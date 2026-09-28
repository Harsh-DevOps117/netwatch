"""Turn a false-positive budget into a threshold, and show what each one costs -- no model, no GPU, no refit.

The decision this tool exists for is not "which threshold is best" but which point on the curve is acceptable, and
that is a judgement about alert volume, not a number the fit can produce. So the fit writes its score distributions
once (`models/detector/head.py --save-scores`) and this reads them, which means the whole tradeoff can be swept in
seconds and re-swept whenever the acceptable alarm rate changes.

The threshold is read from the **calibration benign** scores and applied to the test rows, never the other way round.
Reading it from the rows being reported is the oracle mistake: it produces a number like "two false alarms at 99%
recall" that no live system can reproduce, because live has no test labels to look at.

Where the chosen number goes: `--write <head checkpoint>` stores it in that checkpoint's `serve_threshold`, which is
the field a serving process reads. Nothing else writes that field.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch

BUDGETS = (0.01, 0.003, 0.001, 3e-4, 1e-4, 6e-5, 3e-5, 2e-5, 1e-5, 3e-6)


def incidents(t, key, gap: float) -> int:
    """How many incidents a set of alerts collapses into.

    Input:  observation times and keys of the alerting rows, the quiet gap in seconds that ends an incident
    Output: incident count

    An operator does not read events, they read incidents: one host alerting for a minute is one thing to look at, not
    four hundred. Counted per key, so two hosts alerting at once are two incidents.

    Torch throughout, and on whatever device the inputs are on: this runs once per (family, budget) over every alerting
    row, so on a full day it is millions of elements per call.
    """
    t = torch.as_tensor(t)
    key = torch.as_tensor(key)
    if not t.numel():
        return 0
    # Lexsort by (key, t): sort by the minor key first, then a STABLE sort by the major one preserves it.
    order = t.argsort()
    order = order[key[order].argsort(stable=True)]
    k, ts = key[order], t[order]
    starts = torch.ones(len(ts), dtype=torch.bool, device=ts.device)
    if len(ts) > 1:
        starts[1:] = (k[1:] != k[:-1]) | ((ts[1:] - ts[:-1]) > gap)
    return int(starts.sum())


def test_hours(blob: dict) -> float:
    """How long the test rows cover, in hours: what every per-hour rate is divided by.

    Input:  a scores blob
    Output: hours

    The test split is a set of bands spread through the day (models.data.splits.band_hours), so the first-to-last span
    of its rows is about three times too long. A blob written since 2026-09-27 carries the exact figure; for an older one
    the bands are recovered from the rows themselves: consecutive test rows more than the 120 s embargo apart belong to
    different bands. That reproduced the exact figure on all five days to the second.
    """
    if "test_hours" in blob:
        return max(float(blob["test_hours"]), 1e-9)
    gaps = np.diff(np.sort(np.asarray(blob["t_obs"], dtype=float)))
    return max(float(gaps[gaps <= 120.0].sum()) / 3600.0, 1e-9)


def sweep(blob: dict, budgets=BUDGETS, gap: float = 60.0, device: str | None = None) -> pd.DataFrame:
    """Every budget's threshold and what it costs, per family.

    Input:  a scores blob from models/detector/head.py --save-scores, the budgets to try, the incident gap in seconds, the
            device to compute on (None picks cuda when available)
    Output: DataFrame, one row per (family, budget)

    `overshoot_vs_budget` is the column to watch: the threshold is a quantile of one sample of benign traffic, so the
    realised rate on other rows is never exactly the budget. A stable ratio across budgets is what makes the rule
    trustworthy; a ratio that explodes at the tight end means the calibration sample has run out of resolution.

    All budgets are evaluated in **one** pass per family: a single `torch.quantile` over every requested quantile at
    once, then one broadcast comparison of (rows x budgets). That turns a Python loop over budgets into two kernels,
    which is what makes a full day affordable on the GPU.
    """
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    families = blob["families"]
    calib = torch.as_tensor(blob["calib_benign"], device=device)
    test = torch.as_tensor(blob["test"], device=device)
    code = torch.as_tensor(blob["test_code"], device=device)
    attack = torch.as_tensor(blob["test_attack"], device=device)
    t_obs = torch.as_tensor(blob["t_obs"], device=device)
    sender = torch.as_tensor(blob["sender"], device=device)
    hours = test_hours(blob)
    benign = ~attack
    qs = torch.tensor([1.0 - b for b in budgets], device=device, dtype=torch.float32)
    rows = []
    for k, name in enumerate(families, start=1):
        positive, score = code == k, test[:, k]
        n_pos, n_benign = int(positive.sum()), int(benign.sum())
        if not n_pos or not n_benign:
            continue
        # One quantile call for every budget. "higher" so the realised rate never undershoots by rounding onto a tie.
        thresholds = torch.quantile(calib[:, k].float(), qs, interpolation="higher")
        fires = score[:, None] >= thresholds[None, :]              # (rows, budgets), one kernel
        tp = (fires & positive[:, None]).sum(0)
        fp = (fires & benign[:, None]).sum(0)
        for i, budget in enumerate(budgets):
            false_alerts = fires[:, i] & benign
            tp_i, fp_i = int(tp[i]), int(fp[i])
            rows.append({
                "family": name, "budget": budget, "threshold": float(thresholds[i]),
                "recall": tp_i / n_pos, "precision": tp_i / max(tp_i + fp_i, 1),
                "realised_fpr": fp_i / n_benign, "overshoot_vs_budget": (fp_i / n_benign) / budget,
                "false_alarms": fp_i, "fa_per_hour": fp_i / hours,
                "false_incidents_per_hour": incidents(t_obs[false_alerts], sender[false_alerts], gap) / hours,
                "true_positives": tp_i, "positives": n_pos, "benign_test": n_benign, "hours": hours,
            })
    return pd.DataFrame(rows)


def pick(table: pd.DataFrame, floor: float) -> pd.DataFrame:
    """The cheapest operating point per family that still meets a recall floor.

    Input:  a sweep table, the minimum acceptable recall
    Output: one row per family, or an empty frame when no budget reaches the floor

    Cheapest means fewest false alarms, which is the tightest budget, so this is the row an operator wants: everything
    above the floor, nothing spent above it.
    """
    ok = table[table["recall"] >= floor]
    return ok.loc[ok.groupby("family")["fa_per_hour"].idxmin()] if len(ok) else ok.head(0)


def write_threshold(checkpoint: Path, chosen: pd.DataFrame) -> None:
    """Store chosen thresholds in the head checkpoint a serving process loads.

    Input:  a checkpoint written by models.detector.head.save_head, the rows to commit (family, threshold, budget)
    Output: none; rewrites the checkpoint with serve_threshold filled in

    Written into the same file as the weights on purpose: a threshold in a separate config drifts away from the model
    it belongs to, and a threshold from a different fit is meaningless rather than merely wrong.
    """
    state = torch.load(checkpoint, map_location="cpu", weights_only=False)
    if state.get("format") != "supervised-head-v1":
        raise SystemExit(f"{checkpoint}: not a supervised head checkpoint")
    state["serve_threshold"] = {
        row.family: {"threshold": float(row.threshold), "budget": float(row.budget),
                     "recall": float(row.recall), "fa_per_hour": float(row.fa_per_hour)}
        for row in chosen.itertuples()
    }
    torch.save(state, checkpoint)
    for name, value in state["serve_threshold"].items():
        print(f"  {name}: threshold {value['threshold']:.6f} -> recall {value['recall']:.4f}, "
              f"{value['fa_per_hour']:.1f} alarms/hour", flush=True)
    print(f"serve_threshold written into {checkpoint}", flush=True)


def demo() -> None:
    """Self-check on synthetic scores, so the arithmetic is exercised without a trained model."""
    rng = np.random.default_rng(0)
    n = 20_000
    calib = np.c_[rng.uniform(0, 1, n), rng.uniform(0, 0.5, n)].astype(np.float32)
    score = np.c_[rng.uniform(0, 1, n), np.r_[rng.uniform(0.5, 1.0, 200), rng.uniform(0, 0.5, n - 200)]]
    blob = {"families": ["X"], "calib_benign": calib, "test": score.astype(np.float32),
            "test_code": np.r_[np.ones(200, np.int64), np.zeros(n - 200, np.int64)],
            "test_attack": np.r_[np.ones(200, bool), np.zeros(n - 200, bool)],
            "t_obs": np.sort(rng.uniform(0, 3600, n)), "sender": rng.integers(0, 50, n)}
    table = sweep(blob, budgets=(0.01, 0.001), device="cpu")
    assert len(table) == 2, table
    assert table["threshold"].is_monotonic_increasing, "a tighter budget must not lower the threshold"
    assert (table["recall"] > 0.9).all(), table          # the planted family sits above every benign score
    # incidents can never exceed the alerts they collapse
    assert (table["false_incidents_per_hour"] <= table["fa_per_hour"] + 1e-9).all(), table
    assert incidents(np.array([0.0, 1.0, 500.0]), np.array([1, 1, 1]), gap=60) == 2
    assert incidents(np.array([0.0, 1.0]), np.array([1, 2]), gap=60) == 2, "different keys are different incidents"
    assert len(pick(table, floor=0.9)) == 1
    assert len(pick(table, floor=1.01)) == 0, "an unreachable floor selects nothing"
    print("demo ok")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--scores", type=Path, help="a blob from models/detector/head.py --save-scores")
    parser.add_argument("--budgets", type=float, nargs="+", default=list(BUDGETS))
    parser.add_argument("--gap", type=float, default=60.0, help="quiet seconds that end an incident")
    parser.add_argument("--recall-floor", type=float, default=None,
                        help="report, and with --write commit, the cheapest budget still reaching this recall")
    parser.add_argument("--write", type=Path, default=None,
                        help="a head checkpoint to store the chosen thresholds in (needs --recall-floor)")
    parser.add_argument("--out", type=Path, default=None, help="write the sweep here as CSV")
    parser.add_argument("--device", default=None, help="cuda or cpu; default picks cuda when available")
    parser.add_argument("--demo", action="store_true", help="run the self-check and exit")
    args = parser.parse_args(argv)
    if args.demo:
        demo()
        return 0
    if args.scores is None:
        parser.error("--scores is required (or pass --demo)")
    blob = torch.load(args.scores, map_location="cpu", weights_only=False)
    if blob.get("format") != "supervised-scores-v1":
        raise SystemExit(f"{args.scores}: not a scores blob from models/detector/head.py --save-scores")
    table = sweep(blob, tuple(args.budgets), args.gap, args.device)
    if not len(table):
        raise SystemExit("no family has both positives and benign rows in the test split")
    show = ["family", "budget", "threshold", "realised_fpr", "overshoot_vs_budget", "recall", "precision",
            "fa_per_hour", "false_incidents_per_hour"]
    pd.set_option("display.width", 220)
    print(f"\n{blob['day']}: budget -> threshold -> what it costs "
          f"({table['benign_test'].iloc[0]:,} benign test rows over {table['hours'].iloc[0]:.2f} h)\n")
    print(table[show].to_string(index=False, float_format=lambda v: f"{v:,.6g}"))
    if args.recall_floor is not None:
        chosen = pick(table, args.recall_floor)
        if not len(chosen):
            print(f"\nno budget reaches recall {args.recall_floor}: the highest is "
                  f"{table['recall'].max():.4f} -- loosen the floor or improve the model")
        else:
            print(f"\ncheapest point at recall >= {args.recall_floor}:\n")
            print(chosen[show].to_string(index=False, float_format=lambda v: f"{v:,.6g}"))
            if args.write is not None:
                write_threshold(args.write, chosen)
    elif args.write is not None:
        parser.error("--write needs --recall-floor, so the committed threshold is the one that met a stated floor")
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        table.to_csv(args.out, index=False)
        print(f"\nwritten to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
