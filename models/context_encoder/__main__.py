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
from models.context_encoder.data import ARMS, DAYS, attack_slice, load_day, make_stream
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
                             "for a full-day run, validated against one at the 1%% budget (docs/TESTS.md)")
    parser.add_argument("--family", default=None, help="the family the slice centres on")
    parser.add_argument("--flow-records", action="store_true",
                        help="also feed each flow's CICFlowMeter record to link memory, at the earliest time that "
                             "record can exist (design.md, Block 8 *Flow messages*); needs models.context_encoder.records")
    parser.add_argument("--flow-messages", action="store_true",
                        help="also feed each flow's first-K-packet summary to link memory, at the time that summary "
                             "exists (design.md, Block 8 *Flow messages*)")
    parser.add_argument("--limit", type=int, default=None, help="first N events of each stream only (smoke / timing)")
    parser.add_argument("--record-arm", type=Path, default=None,
                        help="run 7: read the flow record as the event's OWN representation instead of Block 7's "
                             "packet embedding, on the records' own availability timeline. Takes a frozen record "
                             "encoder from `models.context_encoder.records --train-encoder`. Leave unset for the packet path")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    torch.manual_seed(args.seed)
    load = day_loader(args.record_arm, device)      # load_day itself when --record-arm is absent
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
                stream = make_stream(data, keep)
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
        mean = float(np.nanmean(validation))
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
        if improved:
            torch.save({"arm": args.arm, "flow_messages": args.flow_messages,
                        "flow_records": args.flow_records,
                        "record_encoder": str(args.record_encoder) if args.record_encoder else None,
                        "record_split": not args.record_flat,
                        "capacity": args.capacity,
                        "epoch": epoch + 1,
                        "validation_link_ap": mean,
                        "model": model.state_dict(), "head": head.state_dict()}, args.out / "best.pt")
        elif state.stale >= args.patience:
            print(f"early stop: best mean validation link PR-AUC {state.best:.4f}", flush=True)
            break
    board.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
