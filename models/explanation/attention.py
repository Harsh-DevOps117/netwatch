"""Attention activations over the neighbourhood, and an attribution over the detector's input.

Two questions an analyst asks about an alert, and where each is answered:

1. **"Why this host?"** -- the context encoder attends over up to 20 neighbouring events (the latest event per distinct
   peer of each endpoint). Its attention distribution says how much of this event's context came from each of them.
   That is a real activation of the trained model, not a post-hoc surrogate.
2. **"Was it the flow itself or its context?"** -- the detector reads a 132-wide vector: 32 from Block 7's flow
   embedding, 100 from the context encoder. Gradient x input over those two spans says which half carried the decision.

Both are read from the frozen models with no retraining. Attention capture is opt-in (`encoder.explain = True`) so the
training path keeps `need_weights=False` and pays nothing.

Run: uv run python -m models.explanation --context-encoder <ctx>/best.pt --head <head.pt> --day <day> --events 200000
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from models.context_encoder.data import attack_slice, load_day, make_stream
from models.context_encoder.model import LinkIds, make_batch
from models.compressor.latents import frozen_context_encoder


def attention_over_batch(encoder, batch: dict) -> tuple[torch.Tensor, torch.Tensor]:
    """The attention distribution the encoder used for one batch.

    Input:  a ContextEncoder, a batch from make_batch
    Output: (weights (N, neighbours) float, valid (N, neighbours) bool)

    `valid` matters as much as the weights: an event with an empty neighbourhood is made to attend a dummy slot whose
    contribution is then zeroed, so its weights are an artefact. Reporting them as an explanation would be inventing
    one.
    """
    was = encoder.explain
    encoder.explain = True
    try:
        with torch.no_grad():
            encoder(batch)
        return encoder.last_attention.clone(), encoder.last_neighbour_valid.clone()
    finally:
        encoder.explain = was


def top_neighbours(weights: torch.Tensor, valid: torch.Tensor, k: int = 3) -> tuple[torch.Tensor, torch.Tensor]:
    """The k neighbours each event leaned on most.

    Input:  attention weights (N, L), validity (N, L), how many to keep
    Output: (slots (N, k) int64 with -1 where there was nothing, weights (N, k) float, 0 where nothing)

    Invalid slots are pushed below every valid one rather than dropped, so the shape stays rectangular and a row with
    two real neighbours reports two and pads the rest.
    """
    masked = weights.masked_fill(~valid, -1.0)
    best, slots = masked.topk(min(k, weights.shape[1]), dim=1)
    return torch.where(best >= 0, slots, torch.full_like(slots, -1)), best.clamp(min=0.0)


def explain_events(encoder, stream: dict, rows: torch.Tensor, arm: str, links: LinkIds,
                   k: int = 3, device: str = "cpu", window: int = 512) -> pd.DataFrame:
    """A table of what the encoder attended to, for the given stream positions.

    Input:  frozen ContextEncoder, a stream from make_stream, the stream positions to explain, arm, link ids, how many
            neighbours to report, device, events per chunk
    Output: DataFrame, one row per (event, reported neighbour)

    The neighbour columns are what an analyst reads: which peer it was, how long before, whether it was itself an
    attack, and what share of the attention it took.

    **The stream is replayed from its start up to the last requested row.** The attention query is built from link
    memory, so encoding a handful of rows in isolation asks the model a question it never sees in service: memory would
    be empty, and the explanation would be of a different query than the one that produced the alert. Cost is therefore
    proportional to how deep the requested rows sit, which is why an explanation of one late event is not free.
    """
    encoder.begin_day(len(links))
    wanted = {int(r) for r in rows.tolist()}
    stop = max(wanted) + 1
    total = len(stream["sender"])
    out: list[dict] = []
    for start in range(0, min(stop, total), window):
        index = np.arange(start, min(start + window, total))
        chunk = make_batch(stream, index, arm, links, device=device)
        weights, valid = attention_over_batch(encoder, chunk)
        here = [(at, int(row)) for at, row in enumerate(index) if int(row) in wanted]
        if not here:
            continue
        out += _rows_from(stream, chunk, weights, valid, here, k)
    return pd.DataFrame(out)


def _rows_from(stream: dict, batch: dict, weights: torch.Tensor, valid: torch.Tensor,
               here: list[tuple[int, int]], k: int) -> list[dict]:
    """Explanation rows for the wanted events inside one encoded chunk.

    Input:  the stream, the chunk's batch, its attention weights and validity, (position in chunk, stream row) pairs,
            how many neighbours to report
    Output: list of dicts, one per (event, reported neighbour)
    """
    slots, shares = top_neighbours(weights, valid, k)
    positions = batch.get("neighbour_position")
    out = []
    for i, row in here:
        n_valid = int(valid[i].sum())
        for rank in range(slots.shape[1]):
            slot = int(slots[i, rank])
            record = {
                "event_row": row, "event_id": int(stream["event_id"][row]),
                "t_obs": float(stream["t_obs"][row]), "sender": int(stream["sender"][row]),
                "receiver": int(stream["receiver"][row]), "label": str(stream["label"][row]),
                "neighbours_available": n_valid, "rank": rank,
                "attention": float(shares[i, rank]) if slot >= 0 else 0.0,
                "neighbour_slot": slot,
            }
            if slot >= 0:
                record["neighbour_age_s"] = float(batch["neighbour_age"][i, slot])
                record["neighbour_is_receiver_role"] = int(batch["neighbour_role"][i, slot])
                if positions is not None:
                    at = int(positions[i, slot])
                    record["neighbour_row"] = at
                    record["neighbour_label"] = str(stream["label"][at]) if at >= 0 else ""
            out.append(record)
    return out


def input_attribution(head, mean, std, x: torch.Tensor, family: int, embedding_width: int = 32,
                      device: str = "cpu") -> pd.DataFrame:
    """How much of the decision came from the flow itself versus its context.

    Input:  the detector head, its feature scaler, features (N, W), which class to attribute, how many leading columns
            are Block 7's embedding, device
    Output: DataFrame with the signed contribution of each span, per row

    Gradient x input on the standardised features, summed over each span. Signed on purpose: a span can argue *for*
    benign. Attribution is a local linearisation, not a causal claim -- it says what this particular row's score was
    most sensitive to.
    """
    scaled = ((torch.as_tensor(x, dtype=torch.float32) - torch.as_tensor(mean, dtype=torch.float32))
              / torch.as_tensor(std, dtype=torch.float32)).to(device).requires_grad_(True)
    logits = head(scaled)
    logits[:, family].sum().backward()
    contribution = (scaled.grad * scaled).detach()
    flow = contribution[:, :embedding_width].sum(1)
    context = contribution[:, embedding_width:].sum(1)
    probability = logits.softmax(-1)[:, family].detach()
    return pd.DataFrame({
        "probability": probability.cpu(), "from_flow": flow.cpu(), "from_context": context.cpu(),
        "context_share": (context.abs() / (context.abs() + flow.abs() + 1e-12)).cpu(),
    })


def demo() -> None:
    """Self-check on a tiny synthetic encoder: weights are a distribution, and capture does not change the output."""
    from models.context_encoder.model import ContextEncoder

    torch.manual_seed(0)
    encoder = ContextEncoder("split").eval().requires_grad_(False)
    n, neighbours = 6, 4
    # A batch shaped like make_batch's output, with the feature module stubbed to a flat vector so the check exercises
    # the attention path itself rather than the input encoders.
    batch = {
        "t_obs": torch.arange(n, dtype=torch.float64),
        "forward_link": torch.zeros(n, dtype=torch.long),
        "reverse_link": torch.zeros(n, dtype=torch.long),
        "neighbour_age": torch.rand(n, neighbours),          # float32, as make_batch produces
        "neighbour_role": torch.zeros(n, neighbours, dtype=torch.long),
        "neighbour_valid": torch.ones(n, neighbours, dtype=torch.bool),
    }
    batch["neighbour_valid"][-1] = False                       # one event with no neighbourhood at all
    width = encoder.features.width
    # h_split rides along because the encoder's own message path reads it by name, independently of the feature module.
    batch["inputs"] = {"__flat__": torch.randn(n, width), "h_split": torch.randn(n, 32)}
    batch["neighbour_inputs"] = {"__flat__": torch.randn(n, neighbours, width)}

    class Flat(torch.nn.Module):                                # stand in for EventFeatures
        width = encoder.features.width

        def forward(self, inputs):
            return inputs["__flat__"]

    encoder.features = Flat()
    # The encoder is stateful -- a forward updates link memory -- so each comparison starts from a cleared table.
    encoder.begin_day(4)
    plain = encoder(batch)
    encoder.begin_day(4)
    weights, valid = attention_over_batch(encoder, batch)
    encoder.begin_day(4)
    again = encoder(batch)
    assert torch.allclose(plain, again, atol=1e-6), "the encoder is not reproducible from a cleared table"
    encoder.begin_day(4)
    encoder.explain = True
    with torch.no_grad():
        captured = encoder(batch)
    encoder.explain = False
    assert torch.allclose(plain, captured, atol=1e-6), "capturing attention must not change the encoding"
    assert weights.shape == (n, neighbours), weights.shape
    rows_with_neighbours = valid.any(1)
    sums = weights[rows_with_neighbours].sum(1)
    assert torch.allclose(sums, torch.ones_like(sums), atol=1e-4), sums
    slots, shares = top_neighbours(weights, valid, k=2)
    assert slots.shape == (n, 2)
    assert (slots[-1] == -1).all(), "an event with no neighbour must report none"
    assert (shares[-1] == 0).all()
    assert (shares[rows_with_neighbours][:, 0] > 0).all()

    # attribution: shapes, and that the two spans add up to the total
    head = torch.nn.Sequential(torch.nn.Linear(132, 16), torch.nn.ReLU(), torch.nn.Linear(16, 2))
    x = torch.randn(5, 132)
    mean, std = x.mean(0), x.std(0) + 1e-6
    table = input_attribution(head, mean, std, x, family=1)
    assert len(table) == 5 and {"probability", "from_flow", "from_context", "context_share"} <= set(table.columns)
    assert ((table["context_share"] >= 0) & (table["context_share"] <= 1)).all()
    print("demo ok")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--context-encoder", type=Path, default=None, help="a frozen context encoder checkpoint")
    parser.add_argument("--head", type=Path, default=None, help="a detector checkpoint, for input attribution")
    parser.add_argument("--day", default="Friday-02-03-2018")
    parser.add_argument("--family", default="Bot")
    parser.add_argument("--events", type=int, default=None, help="slice this many events, centred on --family")
    parser.add_argument("--explain", type=int, default=25, help="how many events to explain")
    parser.add_argument("--neighbours", type=int, default=3, help="neighbours reported per event")
    parser.add_argument("--window", type=int, default=512,
                        help="events per chunk while replaying the stream; match the value Block 8 was trained with")
    parser.add_argument("--attacks-only", action="store_true", help="explain attack events rather than the first rows")
    parser.add_argument("--out", type=Path, default=Path("data/model_cache/results/explanation.csv"))
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args(argv)
    if args.demo:
        demo()
        return 0
    if args.context_encoder is None:
        parser.error("--context-encoder is required (or pass --demo)")
    device = "cuda" if torch.cuda.is_available() else "cpu"
    encoder, arm = frozen_context_encoder(args.context_encoder, device)
    day = load_day(args.day, arm)
    if args.events:
        keep = attack_slice(day, args.events, args.family)
        day = {k: v[keep] for k, v in day.items() if hasattr(v, "__len__")}
    stream = make_stream(day, np.ones(len(day["sender"]), bool))
    links = LinkIds(stream["sender"], stream["receiver"])
    pool = torch.as_tensor(stream["attack"]).nonzero().flatten() if args.attacks_only \
        else torch.arange(len(stream["sender"]))
    if not len(pool):
        raise SystemExit(f"{args.day}: no rows to explain (attacks_only={args.attacks_only})")
    rows = pool[: args.explain]
    table = explain_events(encoder, stream, rows, arm, links, args.neighbours, device, args.window)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(args.out, index=False)
    pd.set_option("display.width", 220)
    print(f"\nattention over the neighbourhood -- {args.day}, {len(rows)} events\n")
    print(table.to_string(index=False, float_format=lambda v: f"{v:,.4f}"))
    print(f"\nwritten to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
