"""Block 8 variant B: train the context encoder on benign training events by link prediction, then freeze it.

Run: uv run python -m models.context_encoder --arm split --days DAY [DAY ...] --out data/model_cache/context/split
Each epoch walks every day: its benign training stream trains, its benign validation stream is scored by link-prediction
PR-AUC (real links against sampled negatives). The checkpoint with the best mean validation PR-AUC is kept.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

# torch 2.14 routes some backward kernels (GRU / attention outer products) through Triton, which compiles a helper with
# a C compiler this machine does not have. This documented switch keeps the stock CUDA kernels. Set before torch loads.
os.environ.setdefault("TORCH_DISABLE_NATIVE_JIT", "1")

import numpy as np
import pandas as pd
import torch

from models.context_encoder.model import ContextEncoder, LinkIds, make_batch
from models.flow_encoder.metrics import average_precision_tied
from torch import nn
import torch.nn.functional as F
from models.context_encoder.data import ARMS, DAYS, attack_slice, cache_neighbours, day_cache, load_day, make_stream
from models.context_encoder.record_arm import day_loader
from models.context_encoder.model import ContextEncoder

from models.context_encoder.train import LinkPredictor, link_ap, negative_receivers, run_stream
from models.training import Telemetry, add_training_arguments, load_resume, make_schedule, step_schedule

__all__ = ["LinkPredictor", "link_ap", "negative_receivers", "run_stream", "main"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--arm", choices=list(ARMS), required=True, help="split: the split embedding; sides: request and "
                        "response embeddings on their own sender-keyed links")
    parser.add_argument("--days", nargs="+", default=DAYS)
    parser.add_argument("--out", type=Path, required=True, help="directory for best.pt and history.csv")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--patience", type=int, default=2, help="epochs without a better mean validation PR-AUC")
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--seed", type=int, default=0)
    add_training_arguments(parser, default_epochs=10)
    parser.add_argument("--capacity", type=float, default=None,
                        help="cap link memory at this many links, or below 1 at this fraction of the stream's links, "
                             "recycling the least-recently-used slot. Omitted holds a row per link, which no live "
                             "stream can do. Block 10's equivalent table was capped at 25%% of keys with 237,028 "
                             "evictions and identical recall to four decimals")
    parser.add_argument("--record-flat", action="store_true",
                        help="read the flow record as one flat vector instead of keeping its two directions apart: "
                             "the arm the split record encoder is measured against")
    parser.add_argument("--record-encoder", type=Path, default=None,
                        help="a record encoder pre-trained on benign flows (models.context_encoder.records "
                             "--train-encoder): frozen, mirroring how Block 7's packet embedding reaches Block 8")
    parser.add_argument("--events", type=int, default=None,
                        help="train on a contiguous slice of this many events, centred on --family: the quick proxy "
                             "for a full-day run, validated against one at the 1%% budget (docs/dev/validation/experiment-record.md)")
    parser.add_argument("--family", default=None, help="the family the slice centres on")
    parser.add_argument("--flow-records", action="store_true",
                        help="also feed each flow's CICFlowMeter record to link memory, at the earliest time that "
                             "record can exist (design.md, Block 8 *Flow messages*); needs models.context_encoder.records")
    parser.add_argument("--flow-messages", action="store_true",
                        help="also feed each flow's first-K-packet summary to link memory, at the time that summary "
                             "exists (design.md, Block 8 *Flow messages*)")
    parser.add_argument("--limit", type=int, default=None, help="first N events of each stream only (smoke / timing)")
    parser.add_argument("--day-cache", type=Path, default=None,
                        help="keep each loaded day here as .npy and read it back on later epochs and runs (~6 s instead of "
                             "~3 min per day); unset parses the parquet every time")
    parser.add_argument("--embeddings-root", type=Path, default=None,
                        help="where Block 7's exports live, as <root>/<arm export>/<day>/ (default data/flow_embeddings)")
    parser.add_argument("--record-arm", type=Path, default=None,
                        help="run 7: read the flow record as the event's OWN representation instead of Block 7's "
                             "packet embedding, on the records' own availability timeline. Takes a frozen record "
                             "encoder from `models.context_encoder.records --train-encoder`. Leave unset for the packet path")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    torch.manual_seed(args.seed)
    load = day_loader(args.record_arm, device)      # load_day itself when --record-arm is absent
    if args.embeddings_root is not None:
        # A run that exported its own Block 7 embeddings reads those, leaving data/flow_embeddings untouched.
        base_load = load
        load = lambda day, arm, *a, **k: base_load(day, arm, *a, embeddings_root=args.embeddings_root, **k)
    # Only the late messages this encoder is built to read; the rest would be loaded, cached and copied for nothing.
    needs_flows, needs_records, before_prune = args.flow_messages, bool(args.flow_records or args.record_arm), load
    load = lambda day, arm, *a, **k: before_prune(day, arm, *a, flows=needs_flows, records=needs_records, **k)
    if args.day_cache is not None:
        load = day_cache(load, args.day_cache, f"f{int(needs_flows)}r{int(needs_records)}")
    model = ContextEncoder(args.arm, flow_messages=args.flow_messages, flow_records=args.flow_records,
                           record_encoder=args.record_encoder,
                           record_split=not args.record_flat, capacity=args.capacity).to(device)
    head = LinkPredictor().to(device)
    optimiser = torch.optim.Adam([*model.parameters(), *head.parameters()], lr=args.lr)
    schedule = make_schedule(optimiser, args.lr_schedule, args.epochs, args.patience)
    # Link PR-AUC: higher is better, unlike the losses the other trainers watch.
    state = load_resume(args.resume, model, optimiser, schedule, higher_is_better=True, device=device)
    board = Telemetry(args.tensorboard, args.run_name)
    history = list(state.history)
    for epoch in range(state.epoch, args.epochs):
        validation = []
        for day in args.days:
            started = time.perf_counter()
            data = load(day, args.arm)
            if args.events:
                keep = attack_slice(data, args.events, args.family)
                data = {name: value[keep] for name, value in data.items() if isinstance(value, np.ndarray)}
            print(f"epoch {epoch + 1} {day}: {len(data['event_id']):,} events loaded in {time.perf_counter() - started:.0f} s",
                  flush=True)
            benign = ~data["attack"]
            for stage, split_id, step in (("train", 0, optimiser), ("val", 1, None)):
                keep = benign & (data["split"] == split_id)
                if args.limit:
                    keep &= np.cumsum(keep) <= args.limit
                if not keep.any():
                    # A narrow --events slice can land wholly inside one split band, leaving the other empty. Say so:
                    # the alternative is a NaN that travels silently into early stopping and saves no checkpoint.
                    print(f"  {stage}: no benign events of split {split_id} in this slice", flush=True)
                    if stage == "val":
                        validation.append(float("nan"))
                    continue
                # Every real event's neighbourhood looked up once, in large GPU blocks, instead of per batch: the result
                # is identical (measured, same loss to 4 decimals) and it removes a host<->device round trip per batch.
                stream = cache_neighbours(make_stream(data, keep))
                started = time.perf_counter()
                loss, positive, negative = run_stream(model, head, stream, batch_size=args.batch_size, device=device,
                                                      optimiser=step, seed=args.seed + epoch)
                seconds = time.perf_counter() - started
                ap = link_ap(positive, negative)
                history.append({"arm": args.arm, "epoch": epoch + 1, "day": day, "stage": stage, "events": int(keep.sum()),
                                "loss": loss, "link_ap": ap, "seconds": seconds, "events_per_s": keep.sum() / seconds})
                print(f"  {stage}: {int(keep.sum()):,} events, loss {loss:.4f}, link PR-AUC {ap:.4f}, "
                      f"{keep.sum() / seconds:,.0f} events/s", flush=True)
                if stage == "val":
                    validation.append(ap)
            del data
        pd.DataFrame(history).to_csv(args.out / "history.csv", index=False)
        mean = float(np.nanmean(validation)) if not all(np.isnan(validation)) else float("nan")
        if not np.isfinite(mean):
            raise SystemExit(f"no day had benign validation events{' in this --events slice' if args.events else ''}: "
                             "early stopping has nothing to read and no checkpoint would be written. Widen --events, "
                             "or pick a day whose validation band holds benign rows.")
        print(f"epoch {epoch + 1}: mean validation link PR-AUC {mean:.4f}", flush=True)
        # Two scopes, deliberately distinct: `epoch/` is the number early stopping reads, `day/` is the per-day
        # detail behind it. Writing both under one tag put two different values on the same series.
        board.log(epoch + 1, prefix="epoch", val_link_pr_auc=mean, lr=optimiser.param_groups[0]["lr"])
        for row in history[-2:]:
            board.log(epoch + 1, prefix=f"day/{row['stage']}", loss=row["loss"], link_ap=row["link_ap"],
                      events_per_s=row["events_per_s"])
        step_schedule(schedule, metric=-mean)                  # plateau minimises, and higher PR-AUC is better
        improved = state.improved(mean)
        state.epoch, state.history = epoch + 1, history
        if args.resume is not None:
            state.save(args.resume, model, optimiser, schedule)
        checkpoint = {"arm": args.arm, "flow_messages": args.flow_messages,
                      "flow_records": args.flow_records,
                      "record_encoder": str(args.record_encoder) if args.record_encoder else None,
                      "record_split": not args.record_flat,
                      "capacity": args.capacity,
                      "epoch": epoch + 1,
                      "validation_link_ap": mean,
                      "model": model.state_dict(), "head": head.state_dict()}
        torch.save(checkpoint, args.out / f"epoch_{epoch + 1:02d}.pt")        # every epoch kept; ~1 MB each
        if improved:
            torch.save(checkpoint, args.out / "best.pt")
        elif state.stale >= args.patience:
            print(f"early stop: best mean validation link PR-AUC {state.best:.4f}", flush=True)
            break
    board.close()
    best_metrics(args, model, head, load, history, device)
    return 0


def best_metrics(args, model, head, load, history: list[dict], device: str) -> None:
    """The best checkpoint's loss and link PR-AUC on train, validation and -- where a day has one -- test.

    Train and validation are the best epoch's own rows; test is scored once here with the saved weights, the same way
    validation is (benign events, no gradient), and never used to choose anything. Writes best_metrics.csv.
    """
    best = torch.load(args.out / "best.pt", map_location=device, weights_only=False)
    model.load_state_dict(best["model"])
    head.load_state_dict(best["head"])
    rows = [r for r in history if r["epoch"] == best["epoch"]]
    for day in args.days:
        data = load(day, args.arm)
        if args.events:
            keep = attack_slice(data, args.events, args.family)
            data = {name: value[keep] for name, value in data.items() if isinstance(value, np.ndarray)}
        keep = ~data["attack"] & (data["split"] == 2)
        if args.limit:
            keep &= np.cumsum(keep) <= args.limit
        if not keep.any():
            print(f"  test: {day} has no benign test events", flush=True)
            continue
        started = time.perf_counter()
        with torch.no_grad():
            loss, positive, negative = run_stream(model, head, cache_neighbours(make_stream(data, keep)),
                                                  batch_size=args.batch_size, device=device, optimiser=None,
                                                  seed=args.seed)
        seconds = time.perf_counter() - started
        rows.append({"arm": args.arm, "epoch": best["epoch"], "day": day, "stage": "test", "events": int(keep.sum()),
                     "loss": loss, "link_ap": link_ap(positive, negative), "seconds": seconds,
                     "events_per_s": keep.sum() / seconds})
        print(f"  test: {day}, {int(keep.sum()):,} events, loss {loss:.4f}, link PR-AUC {rows[-1]['link_ap']:.4f}",
              flush=True)
        del data
    pd.DataFrame(rows).to_csv(args.out / "best_metrics.csv", index=False)


if __name__ == "__main__":
    raise SystemExit(main())
