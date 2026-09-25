"""Block 13: the logistic-regression baseline the problem statement names, on the CICFlowMeter feature tensor.

Run: uv run python tools/measure/baseline.py --day Friday-02-03-2018 --family Bot

Until this exists, every recall number in the project is unanchored: "0.998 recall" means nothing without knowing what
plain logistic regression on the flow CSV already achieves. This is deliberately generous to the baseline -- it reads
the full 68-column CICFlowMeter record, which only exists once the flow has closed, while the system it is being
compared against answers in 10 ms from packets alone. If the pipeline cannot beat a baseline holding strictly more
information, that is worth knowing early.

Same splits and the same calibration rows as the supervised head: fit on the train split, read the threshold on
validation plus a random slice of train, report the test split.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import torch
import torch.nn.functional as F

from models.context_encoder.data import day_split
from models.context_encoder.records import RECORD_COLUMNS
from models.data.inputs import read_events
from models.flow_encoder.metrics import average_precision_tied, pr_threshold


def fit_logistic(x: np.ndarray, y: np.ndarray, *, epochs: int = 400, device: str = "cpu", seed: int = 0):
    """Plain logistic regression with inverse-frequency class weighting.

    Input:  features (N, W), boolean labels, steps, device, seed
    Output: (weights (W,), bias, mean, std) -- the scaler is part of the model

    Weighted because attacks are a fraction of a percent of rows and the objective is recall; an unweighted fit
    answers benign. No hidden layer, no regularisation beyond weight decay: the point is a floor, not a contender.
    """
    mean, std = x.mean(0), x.std(0) + 1e-6
    xs = torch.from_numpy(((x - mean) / std).astype(np.float32)).to(device)
    ys = torch.from_numpy(y.astype(np.float32)).to(device)
    torch.manual_seed(seed)
    w = torch.zeros(x.shape[1], device=device, requires_grad=True)
    b = torch.zeros(1, device=device, requires_grad=True)
    optimiser = torch.optim.Adam([w, b], lr=0.05, weight_decay=1e-4)
    pos_weight = torch.tensor([(~y).sum() / max(y.sum(), 1)], device=device, dtype=torch.float32)
    for _ in range(epochs):
        optimiser.zero_grad()
        F.binary_cross_entropy_with_logits(xs @ w + b, ys, pos_weight=pos_weight).backward()
        optimiser.step()
    return w.detach(), b.detach(), mean, std


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--day", default="Friday-02-03-2018")
    parser.add_argument("--family", default="Bot")
    parser.add_argument("--calibrate", type=float, default=0.2)
    parser.add_argument("--events", type=int, default=None,
                        help="use a contiguous slice of this many events centred on --family, so the baseline is "
                             "scored on the SAME rows as the system it is being compared against. Without it the "
                             "positive rate differs and even PR-AUC is not comparable.")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", type=Path, default=Path("data/model_cache/results/baseline.csv"))
    args = parser.parse_args(argv)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    events_dir = Path("data/events") / args.day
    events = read_events(events_dir, columns=["event_id", "label", "has_packets"])
    records = pq.read_table(Path("data/context_features") / args.day / "flow_records.parquet",
                            columns=["event_id", *RECORD_COLUMNS]).to_pandas()
    if not np.array_equal(records["event_id"].to_numpy(), events["event_id"].to_numpy()):
        raise SystemExit("records do not line up with the event stream")
    split = day_split(events_dir, args.day)
    keep = events["has_packets"].to_numpy()
    if args.events:
        # the same contiguous, family-centred slice models.context_encoder.data.attack_slice cuts, in EVENT order: the
        # baseline reads flow records, which have no availability time of their own to sort by.
        hit = np.flatnonzero(events["label"].to_numpy(str) == args.family)
        centre = int((hit.min() + hit.max()) // 2) if len(hit) else len(keep) // 2
        start = int(np.clip(centre - args.events // 2, 0, max(len(keep) - args.events, 0)))
        window = np.zeros(len(keep), bool)
        window[start:start + args.events] = True
        keep = keep & window
    x = np.nan_to_num(records[RECORD_COLUMNS].to_numpy(np.float32), nan=0.0, posinf=0.0, neginf=0.0)[keep]
    y = (events["label"].to_numpy(str) == args.family)[keep]
    split = split[keep]

    train, val, test = split == 0, split == 1, split == 2
    rng = np.random.default_rng(args.seed)
    train_rows = np.flatnonzero(train)
    rng.shuffle(train_rows)
    held = train_rows[int(len(train_rows) * (1 - args.calibrate)):]
    calib = np.zeros(len(y), bool)
    calib[held] = True
    calib |= val

    w, b, mean, std = fit_logistic(x[train], y[train], device=device, seed=args.seed)
    with torch.no_grad():
        score = (torch.from_numpy(((x - mean) / std).astype(np.float32)).to(device) @ w + b).cpu().numpy()

    rows = []
    for budget in (1e-3, 1e-4, 3e-5):
        threshold = float(np.quantile(score[calib & ~y], 1 - budget))
        alert = (score >= threshold) & test
        tp, fp = int((alert & y).sum()), int((alert & ~y).sum())
        positives = int((test & y).sum())
        recall, precision = tp / max(positives, 1), tp / max(tp + fp, 1)
        rows.append({"rule": f"budget {budget:g}", "recall": recall, "precision": precision,
                     "f1": 2 * recall * precision / max(recall + precision, 1e-9),
                     "false_alarms": fp, "positives": positives, "benign_test": int((test & ~y).sum())})
    cut, p_pr, r_pr = pr_threshold(score[calib], y[calib])
    alert = (score >= cut) & test
    tp, fp = int((alert & y).sum()), int((alert & ~y).sum())
    recall, precision = tp / max(int((test & y).sum()), 1), tp / max(tp + fp, 1)
    rows.append({"rule": "PR best-F1", "recall": recall, "precision": precision,
                 "f1": 2 * recall * precision / max(recall + precision, 1e-9), "false_alarms": fp,
                 "positives": int((test & y).sum()), "benign_test": int((test & ~y).sum())})

    table = pd.DataFrame(rows)
    table.insert(0, "day", args.day)
    table.insert(1, "family", args.family)
    table["pr_auc"] = average_precision_tied(score[test], y[test])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(args.out, index=False)
    pd.set_option("display.width", 200)
    print(f"Block 13 baseline — logistic regression on {len(RECORD_COLUMNS)} CICFlowMeter columns\n"
          f"{args.day} / {args.family} | train {int(train.sum()):,} | test {int(test.sum()):,} "
          f"({int((test & y).sum()):,} attacks)\n")
    print(table.drop(columns=["day", "family"]).to_string(index=False, float_format=lambda v: f"{v:,.4f}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
