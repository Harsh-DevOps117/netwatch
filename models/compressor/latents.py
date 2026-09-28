"""Block 9, variant B: Block 8 frozen, the event autoencoder trained separately on its output.

Run: uv run python -m models.compressor.latents --encoder mlp --context-encoder data/model_cache/context/split/best.pt \
        --out data/model_cache/compressor/split_mlp
"mlp" reads each event alone -- Block 8 has already folded the link memory and the neighbourhood into s, so nothing
here reads another event. It is what Block 9 uses: the window (graph-transformer) form was disqualified by the
window-boundary check, and a causal-convolution form was built, measured and dropped (design.md, Block 9). s is read
on the benign scale, fitted once on the first day's benign training events before training starts.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

# torch 2.14 routes some backward kernels through Triton, which needs a C compiler this machine does not have.
os.environ.setdefault("TORCH_DISABLE_NATIVE_JIT", "1")

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import torch

from models.compressor.autoencoder import (
    ENCODERS, EventAutoencoder, TARGET_WIDTH, anomaly_score, benign_reference, event_targets, squared_error,
    window_structure,
)
from models.context_encoder.data import DAYS, attack_slice, cache_neighbours, day_cache, load_day, make_stream
from models.context_encoder.record_arm import day_loader
from models.context_encoder.model import ContextEncoder, LinkIds, make_batch

TARGETS = ("s", "x_e")


def frozen_context_encoder(checkpoint: Path, device: str = "cpu") -> tuple[ContextEncoder, str]:
    """Load a trained Block 8 and freeze it (variant B trains the two blocks separately).

    Input:  path to Block 8's best.pt, device
    Output: (encoder in eval mode with gradients off, its arm)
    """
    state = torch.load(checkpoint, map_location=device, weights_only=False)
    # The record encoder's weights are inside state["model"]; its file is only needed to build a trainable copy. Moved
    # or published elsewhere it is absent, and the frozen model is identical without it (eval, no gradients).
    record_encoder = Path(state["record_encoder"]) if state.get("record_encoder") else None
    model = ContextEncoder(state["arm"], flow_messages=state.get("flow_messages", False),
                           flow_records=state.get("flow_records", False),
                           record_encoder=record_encoder if record_encoder and record_encoder.exists() else None,
                           record_split=state.get("record_split", True),
                           capacity=state.get("capacity")).to(device)
    model.load_state_dict(state["model"])
    model.eval().requires_grad_(False)
    return model, state["arm"]

from models.compressor.train import run_compressor
from models.training import Telemetry, add_training_arguments, load_resume, make_schedule, step_schedule


@torch.no_grad()
def context_vectors(model8: ContextEncoder, stream: dict, arm: str, *, window: int = 512,
                    device: str = "cpu") -> np.ndarray:
    """Block 8's s for every event of a stream, in availability order with memory carried across windows.

    Input:  frozen Block 8, stream, arm, events per forward, device
    Output: (N, d_s) float32

    Kept so Block 9 can be re-run over the same contexts: anything that changes then is Block 9's doing alone.
    """
    links = LinkIds(stream["sender"], stream["receiver"])
    model8.begin_day(len(links))
    n = len(stream["sender"])
    out = np.empty((n, model8.out[-1].out_features), np.float32)
    parts, done = [], 0
    for start in range(0, n, window):
        rows = np.arange(start, min(start + window, n))
        parts.append(model8(make_batch(stream, rows, arm, links, device)))
        # Copied back every 64 windows rather than every window: one synchronisation per ~32k events instead of one
        # per 512, while a full day (7.7M x 100 floats, ~3 GB) never has to sit on a 6 GB GPU at once.
        if len(parts) == 64 or rows[-1] == n - 1:
            block = torch.cat(parts).float().cpu().numpy()
            out[done:done + len(block)] = block
            done += len(block)
            parts = []
    return out


@torch.no_grad()
def score_context(ae: EventAutoencoder, context: np.ndarray, stream: dict, *, reference, window: int = 512,
                  offset: int = 0, device: str = "cpu") -> np.ndarray:
    """Block 9 scores from stored contexts, with the windows cut at `offset` (variant B target: s itself).

    Input:  autoencoder, contexts from context_vectors, stream, benign reference, window size, where the first full
            window starts, device
    Output: (N,) scores

    Only the grouping into windows changes with `offset`, so the per-event encoder must return identical scores and
    the window encoder need not.
    """
    n = len(context)
    starts, at = [0], (offset or window)
    while at < n:
        starts.append(at)
        at += window
    scores = np.empty(n, np.float32)
    for start, stop in zip(starts, [*starts[1:], n]):
        rows = np.arange(start, stop)
        s = ae.normalise(torch.from_numpy(context[rows]).to(device))
        structure = None
        if ae.encoder_kind == "window":
            structure = window_structure(stream["sender"][rows], stream["receiver"][rows], stream["t_obs"][rows], device)
        _, reconstruction = ae(s, structure)
        scores[rows] = anomaly_score(squared_error(reconstruction, s).cpu().numpy(), reference)
    return scores


@torch.no_grad()
def export_latents(model8: ContextEncoder, ae: EventAutoencoder, day: dict, arm: str, out_dir: Path,
                   day_name: str, *, window: int = 512, device: str = "cpu", budget_ms: float = 10.0) -> int:
    """Write what Block 10 reads: one row per event, with its latent and how badly it rebuilt.

    Input:  frozen Block 8, trained Block 9, a day dict (already sliced if wanted), arm, output directory, the day's
            name, events per forward, device, the observation budget the events were scored at
    Output: rows written; writes <out_dir>/event_latents.parquet and latents_manifest.json

    `z` is the latent Block 10 consumes and `recon_error` is the same quantity the false-positive gate reads, so a
    consumer can use either without re-running Block 9. Endpoints are exported as **sender / receiver**, keyed on the
    flow's first captured packet, because that is what Block 8's links are keyed on -- not the flow record's src/dst,
    which disagrees on 11.2% of Thursday-15 events.
    """
    import json

    import pyarrow as pa

    stream = cache_neighbours(make_stream(day, np.ones(len(day["sender"]), bool)))
    context = context_vectors(model8, stream, arm, window=window, device=device)
    latents, errors = [], []
    for start in range(0, len(context), window):
        s = ae.normalise(torch.from_numpy(context[start:start + window]).to(device))
        z, rebuilt = ae(s)
        latents.append(z.cpu().numpy())
        errors.append(((rebuilt - s) ** 2).mean(1).cpu().numpy())
    z = np.concatenate(latents) if latents else np.zeros((0, 1), np.float32)
    error = np.concatenate(errors) if errors else np.zeros(0, np.float32)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    table = pa.table({
        "event_id": stream["event_id"], "t": stream["t"], "t_obs": stream["t_obs"],
        "sender_node_id": stream["sender"].astype(np.int32), "receiver_node_id": stream["receiver"].astype(np.int32),
        "dt_src": stream["dt_src"], "dt_dst": stream["dt_dst"], "reversed": stream["reversed"],
        "z": pa.FixedSizeListArray.from_arrays(pa.array(z.ravel().astype(np.float32)), z.shape[1]),
        "recon_error": error.astype(np.float32),
        "split": stream["split"], "label": stream["label"].astype(str),
        "observation_population": stream["population"].astype(str),
        "attack": stream["attack"],
        # Attacker/victim role, from the schedule's named hosts and never from `reversed`. Block 10's ranking head
        # needs it, and `reversed` answers a different question: on the Bot day it agrees with the true direction for
        # only 4.1% of attack events. EVALUATION AND SUPERVISION ONLY -- it is derived from the schedule, so it is
        # ground truth, not an input.
        "role": _roles_for_stream(day_name, stream),
    })
    pq.write_table(table, out_dir / "event_latents.parquet", compression="zstd")
    manifest = {
        "day": day_name, "n_events": int(len(z)), "event_latent_dim": int(z.shape[1]), "arm": arm,
        "observation_budget_ms": budget_ms,
        "order": "availability order: sorted by (t_obs, event_id), the order Block 8 processed them in",
        "endpoints": "sender_node_id / receiver_node_id are keyed on the flow's FIRST CAPTURED PACKET, not the flow "
                     "record's src/dst",
        "z": "Block 9's latent, the compression of Block 8's context",
        "recon_error": "per-event mean squared reconstruction error of that context, on the benign scale Block 9 was "
                       "fitted with; low means the context looks like benign traffic",
        "label_and_attack": "EVALUATION ONLY -- never an input",
        "role": "attacker/victim role from the schedule: 0 benign, 1 attacker->victim, 2 victim->attacker, "
                "3 in an attack window between hosts the schedule does not pair. GROUND TRUTH -- for supervising a "
                "ranking head and for evaluation, never a model input. Derived from attacker_ips/victim_ips, never "
                "from `reversed`, which on the Bot day agrees with the true direction only 4.1% of the time",
        "columns": [name for name in table.column_names],
    }
    (out_dir / "latents_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return len(z)


def _roles_for_stream(day_name: str, stream: dict) -> "np.ndarray":
    """Role codes for the rows of one export stream.

    Input:  the day, the stream being exported
    Output: (N,) int8 role codes, or all-benign when the day has no schedule entry

    Resolved from the stream's own endpoint ids rather than re-read from disk, so a sliced or reordered export gets the
    role of the rows it actually contains.
    """
    from models.data.roles import BENIGN, node_ips, resolve_roles

    try:
        ips = node_ips(day_name)
    except (FileNotFoundError, OSError):
        return np.full(len(stream["event_id"]), BENIGN, dtype=np.int8)
    sender = ips[np.asarray(stream["sender"], dtype=np.int64)]
    receiver = ips[np.asarray(stream["receiver"], dtype=np.int64)]
    return resolve_roles(day_name, sender, receiver, np.asarray(stream["t"], dtype=float))


def benign_streams(day: dict, split_id: int, limit: int | None = None) -> dict:
    """The day's benign events of one split, as a stream.

    Input:  day dict from load_day, split id (0 train, 1 val, 2 test), optional cap on the number of events
    Output: stream dict
    """
    keep = (~day["attack"]) & (day["split"] == split_id)
    if limit:
        keep &= np.cumsum(keep) <= limit
    # Real events' neighbourhoods looked up once in large GPU blocks; identical to the per-window lookup.
    return cache_neighbours(make_stream(day, keep))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--encoder", choices=ENCODERS, required=True)
    parser.add_argument("--context-encoder", type=Path, required=True, help="Block 8 checkpoint to freeze")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--days", nargs="+", default=DAYS)
    parser.add_argument("--target", choices=TARGETS, default="s", help="variant B rebuilds s; x_e is the fixed event features")
    parser.add_argument("--epochs", type=int, default=6)
    parser.add_argument("--patience", type=int, default=2)
    parser.add_argument("--window", type=int, default=512, help="events per window; also the batch")
    parser.add_argument("--d-z", type=int, default=32)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--normalise-rows", type=int, default=200_000,
                        help="benign training events of the first day fitting the scale of s")
    parser.add_argument("--limit", type=int, default=None, help="first N benign events of each stream (smoke / budget)")
    parser.add_argument("--events", type=int, default=None,
                        help="train on a contiguous slice of this many events, centred on --family")
    parser.add_argument("--family", default=None, help="the family the slice centres on")
    parser.add_argument("--seed", type=int, default=0)
    add_training_arguments(parser, default_epochs=6)
    parser.add_argument("--export", type=Path, default=None,
                        help="instead of training, write event_latents.parquet and latents_manifest.json for each "
                             "day -- what Block 10 reads")
    parser.add_argument("--load", type=Path, default=None, help="the trained Block 9 to export with")
    parser.add_argument("--day-cache", type=Path, default=None,
                        help="keep each loaded day here as .npy and read it back on later epochs and runs (~6 s instead of "
                             "~3 min per day); unset parses the parquet every time")
    parser.add_argument("--embeddings-root", type=Path, default=None,
                        help="where Block 7's exports live, as <root>/<arm export>/<day>/ (default data/flow_embeddings)")
    parser.add_argument("--record-arm", type=Path, default=None,
                        help="run 7: the records-only cascade, matching `models.context_encoder --record-arm`")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    load = day_loader(args.record_arm, device)      # load_day itself when --record-arm is absent
    if args.embeddings_root is not None:
        # A run that exported its own Block 7 embeddings reads those, leaving data/flow_embeddings untouched.
        base_load = load
        load = lambda day, arm, *a, **k: base_load(day, arm, *a, embeddings_root=args.embeddings_root, **k)
    torch.manual_seed(args.seed)
    model8, arm = frozen_context_encoder(args.context_encoder, device)
    # Only the late messages the frozen Block 8 reads; the rest would be loaded, cached and copied for nothing.
    reads, before_prune = set(model8.late.keys()), load
    keep_records = "record" in reads or args.record_arm is not None     # the record arm is built from them
    load = lambda day, arm, *a, **k: before_prune(day, arm, *a, flows="flow" in reads, records=keep_records, **k)
    if args.day_cache is not None:
        load = day_cache(load, args.day_cache, f"f{int('flow' in reads)}r{int(keep_records)}")
    if args.export:
        state = torch.load(args.load or (args.out / "best.pt"), map_location=device, weights_only=False)
        width = model8.out[-1].out_features
        ae = EventAutoencoder(state["encoder"], d_s=width, d_z=state["d_z"], target=width).to(device)
        ae.load_state_dict(state["model"])
        ae.eval().requires_grad_(False)
        for day in args.days:
            data = load(day, arm)
            if args.events:
                keep = attack_slice(data, args.events, args.family)
                data = {name: value[keep] for name, value in data.items() if isinstance(value, np.ndarray)}
            rows = export_latents(model8, ae, data, arm, args.export / day, day, window=args.window, device=device)
            print(f"{day}: {rows:,} events -> {args.export / day / 'event_latents.parquet'}", flush=True)
        return 0
    width = model8.out[-1].out_features if args.target == "s" else TARGET_WIDTH[arm]
    ae = EventAutoencoder(args.encoder, d_s=model8.out[-1].out_features, d_z=args.d_z, target=width).to(device)
    first = load(args.days[0], arm)
    if args.events:
        keep = attack_slice(first, args.events, args.family)
        first = {name: value[keep] for name, value in first.items() if isinstance(value, np.ndarray)}
    fit = benign_streams(first, 0, args.normalise_rows)
    ae.fit_normalisation(context_vectors(model8, fit, arm, window=args.window, device=device))
    del fit
    optimiser = torch.optim.Adam(ae.parameters(), lr=args.lr)
    print(f"Block 9 variant B | encoder {args.encoder} | arm {arm} | target {args.target} ({width} columns) | {device}",
          flush=True)
    history = []
    schedule = make_schedule(optimiser, args.lr_schedule, args.epochs, args.patience)
    state = load_resume(args.resume, ae, optimiser, schedule, higher_is_better=False, device=device)
    board = Telemetry(args.tensorboard, args.run_name)
    history = list(state.history) or history
    for epoch in range(state.epoch, args.epochs):
        validation = []
        for day in args.days:
            data = load(day, arm)
            if args.events:
                keep = attack_slice(data, args.events, args.family)
                data = {name: value[keep] for name, value in data.items() if isinstance(value, np.ndarray)}
            for stage, split_id, step in (("train", 0, optimiser), ("val", 1, None)):
                stream = benign_streams(data, split_id, args.limit)
                started = time.perf_counter()
                out = run_compressor(model8, ae, stream, arm, window=args.window, device=device, optimiser=step,
                                 target=args.target)
                seconds = time.perf_counter() - started
                events = len(stream["sender"])
                history.append({"encoder": args.encoder, "arm": arm, "target": args.target, "epoch": epoch + 1,
                                "day": day, "stage": stage, "events": events, "loss": out["loss"], "seconds": seconds,
                                "events_per_s": events / max(seconds, 1e-9)})
                print(f"  epoch {epoch + 1} {day} {stage}: {events:,} events, loss {out['loss']:.5f}, "
                      f"{events / max(seconds, 1e-9):,.0f} events/s", flush=True)
                if stage == "val":
                    validation.append(out["loss"])
            del data
        pd.DataFrame(history).to_csv(args.out / "history.csv", index=False)
        mean = float(np.mean(validation))
        print(f"epoch {epoch + 1}: mean validation loss {mean:.5f}", flush=True)
        # `epoch/` is what early stopping reads; `day/` is the per-day detail. Distinct scopes so one series never
        # carries two different values for the same step.
        board.log(epoch + 1, prefix="epoch", val_loss=mean, lr=optimiser.param_groups[0]["lr"])
        for row in history[-2:]:
            board.log(epoch + 1, prefix=f"day/{row['stage']}", loss=row["loss"], events_per_s=row["events_per_s"])
        step_schedule(schedule, metric=mean)
        improved = state.improved(mean)
        state.epoch, state.history = epoch + 1, history
        if args.resume is not None:
            state.save(args.resume, ae, optimiser, schedule)
        checkpoint = {"encoder": args.encoder, "arm": arm, "target": args.target, "epoch": epoch + 1,
                      "validation_loss": mean, "d_z": args.d_z, "window": args.window,
                      "model": ae.state_dict(), "context_encoder": str(args.context_encoder)}
        torch.save(checkpoint, args.out / f"epoch_{epoch + 1:02d}.pt")        # every epoch kept; ~0.15 MB each
        if improved:
            torch.save(checkpoint, args.out / "best.pt")
        elif state.stale >= args.patience:
            print(f"early stop: best mean validation loss {state.best:.5f}", flush=True)
            break
    board.close()
    # The best checkpoint on train, validation and -- where a day has one -- test. Train and validation are the best
    # epoch's own rows; test is scored once here with the saved weights, like validation (benign, no gradient), and
    # never used to choose anything.
    best = torch.load(args.out / "best.pt", map_location=device, weights_only=False)
    ae.load_state_dict(best["model"])
    rows = [r for r in history if r["epoch"] == best["epoch"]]
    for day in args.days:
        data = load(day, arm)
        if args.events:
            keep = attack_slice(data, args.events, args.family)
            data = {name: value[keep] for name, value in data.items() if isinstance(value, np.ndarray)}
        if not ((~data["attack"]) & (data["split"] == 2)).any():
            print(f"  test: {day} has no benign test events", flush=True)
            continue
        stream = benign_streams(data, 2, args.limit)
        started = time.perf_counter()
        with torch.no_grad():
            out = run_compressor(model8, ae, stream, arm, window=args.window, device=device, target=args.target)
        seconds = time.perf_counter() - started
        events = len(stream["sender"])
        rows.append({"encoder": args.encoder, "arm": arm, "target": args.target, "epoch": best["epoch"], "day": day,
                     "stage": "test", "events": events, "loss": out["loss"], "seconds": seconds,
                     "events_per_s": events / max(seconds, 1e-9)})
        print(f"  test: {day}, {events:,} events, loss {out['loss']:.5f}", flush=True)
        del data
    pd.DataFrame(rows).to_csv(args.out / "best_metrics.csv", index=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
