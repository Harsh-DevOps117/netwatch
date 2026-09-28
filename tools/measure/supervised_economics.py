"""The supervised head on the same axes as Block 10: alerts per hour, and incidents rather than events.

Run: uv run python tools/measure/supervised_economics.py --day Friday-02-03-2018 --family Bot --events 3000000 \
         --context-encoder data/model_cache/context/f_norec_s0/best.pt

`run_day` reports recall and precision at fixed false-positive budgets, which cannot be compared with Block 10's
numbers: a budget says nothing about how often the alarm actually rings. This sweeps the same head by alert rate and
collapses alerts on one host within `--gap` seconds into one incident, so the detection and anticipation paths can be
read side by side.

The protocol matches `run_day`: fit on 80% of the train split, calibrate the threshold on rows the head never saw
(the remaining 20% plus validation), report the test split.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

from models.data.splits import band_hours
import pandas as pd
import torch

sys.path.insert(0, str(Path(__file__).parent))
from models.evaluation.thresholds import incidents
from models.detector.features import load_features
from models.detector.model import class_scores, family_codes, train_head


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--day", default="Friday-02-03-2018")
    parser.add_argument("--family", default="Bot")
    parser.add_argument("--events", type=int, default=3_000_000)
    parser.add_argument("--context-encoder", type=Path, default=None)
    parser.add_argument("--gap", type=float, default=60.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", type=Path, default=Path("data/model_cache/results/supervised_economics.csv"))
    args = parser.parse_args(argv)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    data, name = load_features(args.day, args.context_encoder, device, args.events, args.family)
    # load_features already concatenates Block 8's context into "h" (32 + 100 = 132 wide); "context" is returned
    # separately only for the gate, so using both would count it twice.
    x = data["h"]
    code, families = family_codes(data["label"])
    target = families.index(args.family) + 1          # class 0 is benign, so family k is column k + 1
    split = data["split"]
    rng = np.random.default_rng(args.seed)
    train_rows = np.flatnonzero(split == 0)
    rng.shuffle(train_rows)
    cut = int(0.8 * len(train_rows))
    fit_rows, calib_rows = train_rows[:cut], np.r_[train_rows[cut:], np.flatnonzero(split == 1)]
    test_rows = np.flatnonzero(split == 2)

    head, mean, std = train_head(x[fit_rows], code[fit_rows], len(families) + 1, device=device, seed=args.seed)
    score = class_scores(head, mean, std, x, device=device)[:, target]
    attack = data["label"] == args.family
    hours = band_hours(data["t_obs"], split)                  # the test bands' own duration, not first-to-last
    sender = torch.as_tensor(data["sender"].astype(np.int64))
    t_obs = torch.as_tensor(data["t_obs"])
    calib_benign = score[calib_rows][~attack[calib_rows]]

    rows = []
    for budget in (1e-2, 3e-3, 1e-3, 3e-4, 1e-4, 6e-5, 3e-5, 2e-5, 1e-5, 3e-6):
        threshold = float(np.quantile(calib_benign, 1.0 - budget))
        alert = np.zeros(len(score), bool)
        alert[test_rows] = score[test_rows] >= threshold
        tp = int((alert & attack).sum()); fp = int((alert & ~attack).sum())
        positives = int(attack[test_rows].sum())
        ti, fi = incidents(sender, t_obs, torch.as_tensor(alert), torch.as_tensor(attack), args.gap)
        rows.append({"budget": budget, "threshold": threshold,
                     "realised_fpr": fp / max(int((~attack[test_rows]).sum()), 1),
                     "overshoot_vs_budget": (fp / max(int((~attack[test_rows]).sum()), 1)) / budget,
                     "recall": tp / max(positives, 1),
                     "precision": tp / max(tp + fp, 1), "false_alarms": fp, "fa_per_hour": fp / hours,
                     "false_incidents_per_hour": fi / hours, "true_incidents": ti,
                     "positives": positives, "benign_test": int((~attack[test_rows]).sum())})
    table = pd.DataFrame(rows)
    table.insert(0, "family", args.family)
    table.insert(1, "input", name)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(args.out, index=False)
    pd.set_option("display.width", 220)
    print(f"{args.family} | input {name} | test {hours:.2f} h | {rows[0]['positives']:,} attacks, "
          f"{rows[0]['benign_test']:,} benign | incidents collapse alerts on a host within {args.gap:.0f} s\n")
    print(table.drop(columns=["family", "input"]).to_string(index=False, float_format=lambda v: f"{v:,.4f}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
