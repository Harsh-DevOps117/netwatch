"""Why the world model picked a host: Block 10's neighbourhood attention, read out for the forecast's seeds.

A rollout starts from the latest chunk's most surprising events. For each, the world model embedded the initiator by
attending over its neighbourhood -- the nodes it recently exchanged events with -- and that distribution says which of
them shaped the state the forecast rolls forward from. It is the model's own activation, taken from the same forward
pass that scored the event (`Replay.recent_attention`), so nothing is recomputed and nothing is fitted afterwards.

Only layer 1 is reported. In v1 checkpoints (the one served on 2026-09-26) layer 2, the global readout, pooled over
node states that were all zero, so its attention was exactly uniform (measured spread 0.0) and reporting it would be
presenting padding as evidence. v2 fixed the cause (model.FORMAT); its readout attention is real and is written to
`attention_weights.parquet` by `emit`, but it is network-wide rather than about one seed, so it is not added here.

Run: uv run python -m models.explanation --world-model <b10.pt> --latents <day> --node-index <node_index.parquet>
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
import torch

GLOBAL_READOUT_NOTE = ("global readout not reported per seed; for a v1 checkpoint it is uniform and meaningless, for v2 "
                       "it is network-wide and is in attention_weights.parquet")


def seed_explanations(replay, seed_events, names: "dict | None" = None, k: int = 8) -> list[dict]:
    """For each seed event of the latest chunk, the neighbours its initiator attended to most.

    Input:  a Replay that has scored at least one chunk, the seed event ids (rollout rows' `seed_id`), node_id -> IP,
            how many neighbours to report
    Output: one dict per seed found in the latest chunk: the event, its surprise, how many neighbours were available,
            and up to k attended neighbours with their share of the attention

    A seed with no neighbourhood reports an empty list, not the dummy slot's weight.
    """
    if replay.recent_attention is None:
        return []
    names = names or {}
    ip = lambda node: names.get(int(node), str(int(node)))
    wanted = {int(s) for s in seed_events}
    out = []
    for i, (step, day, position, surprise) in enumerate(replay.recent):
        event = int(day.event_id[position])
        if event not in wanted:
            continue
        nodes = torch.as_tensor(step.neighbour_nodes_initiator, dtype=torch.long)
        valid = nodes >= 0
        # A neighbourhood is a list of recent events, so one peer can fill several slots; its share is their sum.
        weights = replay.recent_attention[i].cpu()
        share: dict = {}
        for node, w in zip(nodes[valid].tolist(), weights[valid].tolist()):
            share[node] = share.get(node, 0.0) + w
        attended = [{"node": node, "ip": ip(node), "attention": round(w, 6)}
                    for node, w in sorted(share.items(), key=lambda item: -item[1])[:k]]
        out.append({"seed_event": event, "t": float(day.t[position]),
                    "sender": int(step.initiator), "receiver": int(step.responder),
                    "sender_ip": ip(step.initiator), "receiver_ip": ip(step.responder),
                    "surprise": round(float(surprise), 6), "neighbours_available": int(valid.sum()),
                    "attended": attended})
    return out


def demo() -> None:
    """Self-check on a stub replay: top neighbours in order, padding never reported, unknown seeds skipped."""
    import numpy as np
    from types import SimpleNamespace

    day = SimpleNamespace(event_id=np.array([10, 11]), t=np.array([1.0, 2.0]))
    step = lambda nodes: SimpleNamespace(initiator=1, responder=2, neighbour_nodes_initiator=np.array(nodes))
    replay = SimpleNamespace(recent=[(step([5, 6, 5, -1]), day, 0, 3.0), (step([-1, -1, -1, -1]), day, 1, 1.0)],
                             recent_attention=torch.tensor([[0.2, 0.6, 0.2, 0.0], [1.0, 0.0, 0.0, 0.0]]))
    rows = seed_explanations(replay, [10, 11, 99], names={6: "10.0.0.6"}, k=3)
    assert [r["seed_event"] for r in rows] == [10, 11]
    assert [a["ip"] for a in rows[0]["attended"]] == ["10.0.0.6", "5"], rows[0]
    assert abs(rows[0]["attended"][1]["attention"] - 0.4) < 1e-6, "a peer's repeated slots add up"
    assert rows[0]["neighbours_available"] == 3
    assert rows[1]["attended"] == [], "an empty neighbourhood must report nothing, not the dummy slot"
    print("demo ok")


def main(argv: "list[str] | None" = None) -> int:
    from models.world_model.inference import Replay
    from models.world_model.reception import receive
    from models.world_model.service import node_names

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--world-model", type=Path, required=True, help="a trained Block 10 checkpoint")
    parser.add_argument("--latents", type=Path, nargs="+", required=True, help="Block 9 latent directories")
    parser.add_argument("--node-index", type=Path, default=None, help="node_index.parquet, to name hosts by IP")
    parser.add_argument("--events", type=int, default=20_000, help="events to score before explaining")
    parser.add_argument("--explain", type=int, default=5, help="seeds to explain")
    parser.add_argument("--neighbours", type=int, default=3, help="neighbours reported per seed")
    parser.add_argument("--out", type=Path, default=Path("data/model_cache/results/explanation_world_model.csv"))
    parser.add_argument("--device", default=None)
    args = parser.parse_args(argv)

    replay = Replay(receive(args.latents), args.world_model, split=None, device=args.device, attention=False)
    replay.advance(args.events)
    replay.finish()
    seeds = {row["seed_id"] for row in replay.rollout(1, args.explain)}
    rows = seed_explanations(replay, seeds, node_names(args.node_index), args.neighbours)
    table = pd.DataFrame([{**{k: v for k, v in r.items() if k != "attended"}, "rank": rank, **a}
                          for r in rows for rank, a in enumerate(r["attended"] or [{}])])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(args.out, index=False)
    pd.set_option("display.width", 220)
    print(f"\nworld model neighbourhood attention -- {len(rows)} seed(s) after {replay.scored:,} events\n")
    print(table.to_string(index=False))
    print(f"\n{GLOBAL_READOUT_NOTE}\nwritten to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
