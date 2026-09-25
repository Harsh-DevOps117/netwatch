"""One evaluation, every metric, from a saved score blob -- detection, emission, calibration and the baseline gap.

Run: uv run python -m models.evaluation --scores data/model_cache/serve/scores_<day>.pt

Reports, in order:

1. **Ranking quality**, independent of any threshold: tied-rank PR-AUC per family. A threshold-free number, so it cannot
   be flattered by a lucky operating point.
2. **The operating-point sweep**: budget -> threshold -> realised FPR, recall, precision, alarms/hour, incidents/hour.
3. **Calibration**: Brier and expected calibration error on the reported probabilities. A probability shown to an
   analyst has to mean what it says, so this is reported even though nothing optimises it.
4. **The emission funnel**: events -> above threshold -> after persist-3 -> incidents, with the real emitter, because
   the alarm rate an operator feels is the one after all three stages.
5. **Population split**: `early_observation` against `completed_before_budget` when the blob carries it. These must
   never be pooled -- only the first carries any lead-time claim.

Everything is torch and runs on the GPU when one is present.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
import torch

from models.runtime import configure, maybe_compile
from models.serving.emitter import AlertEmitter
from models.evaluation.thresholds import BUDGETS, incidents, sweep


def average_precision(score: torch.Tensor, positive: torch.Tensor) -> float:
    """Area under the precision-recall curve, taking tied scores together.

    Input:  scores (N,), boolean positives (N,)
    Output: average precision, or nan when either class is absent

    Ties are collapsed on purpose, matching models.flow_encoder.metrics.average_precision_tied: at a 10 ms budget most
    of a flood's rows share an identical input vector and therefore an identical score with some benign row, and
    ranking those by array position would invent a separation the model never produced.
    """
    total = int(positive.sum())
    if not total or total == len(positive):
        return float("nan")
    order = torch.argsort(score, descending=True)
    s, p = score[order], positive[order].to(torch.float64)
    # one point per DISTINCT score: the last index of each run of equal scores
    last = torch.ones(len(s), dtype=torch.bool, device=s.device)
    last[:-1] = s[1:] != s[:-1]
    tp = torch.cumsum(p, 0)[last]
    seen = torch.nonzero(last).flatten() + 1
    precision, recall = tp / seen, tp / total
    previous = torch.cat([torch.zeros(1, dtype=recall.dtype, device=recall.device), recall[:-1]])
    return float(((recall - previous) * precision).sum())


def calibration(probability: torch.Tensor, truth: torch.Tensor, bins: int = 15) -> dict:
    """Brier score and expected calibration error.

    Input:  predicted probabilities (N,), boolean outcomes (N,), number of equal-width bins
    Output: dict with brier and ece

    ECE is the average gap between confidence and accuracy, weighted by how many rows land in each bin: it answers
    "when this says 0.9, is it right nine times in ten".
    """
    p, y = probability.double(), truth.double()
    brier = float(((p - y) ** 2).mean())
    edges = torch.linspace(0, 1, bins + 1, device=p.device, dtype=p.dtype)
    ece = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        inside = (p > lo) & (p <= hi) if lo > 0 else (p >= lo) & (p <= hi)
        if not bool(inside.any()):
            continue
        ece += float(inside.double().mean()) * abs(float(p[inside].mean()) - float(y[inside].mean()))
    return {"brier": brier, "ece": ece}


def emission_funnel(blob: dict, family: int, threshold: float, persist: int = 3, gap: float = 60.0) -> dict:
    """What each emission stage removes, on real scores.

    Input:  a scores blob, which class column to emit on, the threshold, the run length, the quiet gap
    Output: dict of counts and per-hour rates at each stage, plus the recall that survives

    Run through the actual `AlertEmitter`, not a reimplementation, so what is reported is what would ship.
    """
    score = torch.as_tensor(blob["test"])[:, family]
    key = torch.as_tensor(blob["sender"])
    t = torch.as_tensor(blob["t_obs"])
    truth = torch.as_tensor(blob["test_code"]) == family
    hours = max(float(t.max() - t.min()) / 3600.0, 1e-9)
    order = torch.argsort(t)                                  # emission is order-dependent: availability order
    emitter = AlertEmitter(threshold, persist=persist, gap=gap)
    opened = emitter.push_batch(key[order], score[order], t[order])
    above = int((score >= threshold).sum())
    caught = torch.zeros_like(truth)
    fired_keys = {row["key"] for row in opened}
    if fired_keys:
        caught = truth & torch.isin(key, torch.tensor(sorted(fired_keys)))
    return {
        "events": int(score.numel()), "above_threshold": above,
        "after_persist": emitter.alerts, "incidents": emitter.incidents,
        "above_per_hour": above / hours, "alerts_per_hour": emitter.alerts / hours,
        "incidents_per_hour": emitter.incidents / hours,
        "attack_events_on_alerting_hosts": int(caught.sum()), "attack_events": int(truth.sum()),
        "hosts_alerted": len(fired_keys),
    }


def report(blob: dict, budgets=BUDGETS, gap: float = 60.0, persist: int = 3,
           device: str | None = None) -> dict[str, pd.DataFrame]:
    """Every metric for one saved day.

    Input:  a scores blob from models.detector --save-scores, budgets, incident gap, run length, device
    Output: dict of named tables, ready to print or write
    """
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    families = blob["families"]
    test = torch.as_tensor(blob["test"], device=device)
    code = torch.as_tensor(blob["test_code"], device=device)
    attack = torch.as_tensor(blob["test_attack"], device=device)

    ranking = []
    for k, name in enumerate(families, start=1):
        positive = code == k
        keep = positive | ~attack                      # this family against benign, never against another family
        ranking.append({
            "family": name, "positives": int(positive.sum()), "benign": int((~attack).sum()),
            "pr_auc_tied": average_precision(test[keep, k], positive[keep]),
            **calibration(test[:, k], positive),
        })

    economics = sweep(blob, budgets, gap, device)
    funnels = []
    for k, name in enumerate(families, start=1):
        rows = economics[economics["family"] == name]
        if not len(rows):
            continue
        # the tightest budget that still catches nearly everything, which is the point an operator would pick
        pick = rows[rows["recall"] >= 0.99]
        chosen = pick.iloc[pick["fa_per_hour"].argmin()] if len(pick) else rows.iloc[rows["recall"].argmax()]
        funnels.append({"family": name, "threshold": float(chosen["threshold"]),
                        "budget": float(chosen["budget"]), "recall_at_threshold": float(chosen["recall"]),
                        **emission_funnel(blob, k, float(chosen["threshold"]), persist, gap)})

    tables = {"ranking": pd.DataFrame(ranking), "economics": economics, "emission": pd.DataFrame(funnels)}

    population = blob.get("population")
    if population is not None:
        rows = []
        population = list(population)
        for name in sorted(set(population)):
            mask = torch.tensor([p == name for p in population], device=device)
            for k, family in enumerate(families, start=1):
                positive = (code == k) & mask
                if not bool(positive.any()):
                    continue
                keep = mask & (positive | ~attack)
                rows.append({"population": name, "family": family, "positives": int(positive.sum()),
                             "pr_auc_tied": average_precision(test[keep, k], (code == k)[keep])})
        tables["population"] = pd.DataFrame(rows)
    return tables


def demo() -> None:
    """Self-check: AP against a known case, calibration on a perfect predictor, and the funnel's monotonicity."""
    g = torch.Generator().manual_seed(0)
    # a perfectly separable ranking has AP 1.0; a constant score has AP equal to the positive rate
    score = torch.tensor([0.9, 0.8, 0.2, 0.1])
    positive = torch.tensor([True, True, False, False])
    assert abs(average_precision(score, positive) - 1.0) < 1e-9
    flat = torch.ones(10)
    half = torch.tensor([True] * 5 + [False] * 5)
    assert abs(average_precision(flat, half) - 0.5) < 1e-9, average_precision(flat, half)
    assert average_precision(score, torch.zeros(4, dtype=torch.bool)) != average_precision(score, positive)

    # a perfect, confident predictor is perfectly calibrated
    perfect = calibration(torch.tensor([1.0, 1.0, 0.0, 0.0]), torch.tensor([True, True, False, False]))
    assert perfect["brier"] == 0.0 and perfect["ece"] == 0.0, perfect
    worst = calibration(torch.tensor([1.0, 1.0]), torch.tensor([False, False]))
    assert abs(worst["brier"] - 1.0) < 1e-9 and abs(worst["ece"] - 1.0) < 1e-9, worst

    # the funnel can only shrink: events >= above threshold >= after persist >= incidents
    n = 5_000
    blob = {"families": ["X"],
            "calib_benign": torch.rand(n, 2, generator=g),
            "test": torch.rand(n, 2, generator=g),
            "test_code": (torch.rand(n, generator=g) > 0.98).long(),
            "test_attack": (torch.rand(n, generator=g) > 0.98),
            "t_obs": torch.sort(torch.rand(n, generator=g) * 3600).values,
            "sender": torch.randint(0, 30, (n,), generator=g)}
    funnel = emission_funnel(blob, 1, threshold=0.9)
    assert funnel["events"] >= funnel["above_threshold"] >= funnel["after_persist"] >= funnel["incidents"], funnel

    tables = report(blob, budgets=(0.01, 0.001), device="cpu")
    assert set(tables) >= {"ranking", "economics", "emission"}
    assert len(tables["ranking"]) == 1 and len(tables["economics"]) == 2
    print("demo ok")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--scores", type=Path, help="a blob from models.detector --save-scores")
    parser.add_argument("--budgets", type=float, nargs="+", default=list(BUDGETS))
    parser.add_argument("--gap", type=float, default=60.0)
    parser.add_argument("--persist", type=int, default=3)
    parser.add_argument("--device", default=None)
    parser.add_argument("--fast", action="store_true",
                        help="enable cuDNN autotuning and TF32. Off by default: both change results in the last bits, "
                             "which is not acceptable while measuring a threshold to six significant figures")
    parser.add_argument("--compile", action="store_true",
                        help="compile the scoring kernels. Measured on this path the fusible work was 1.6 ms of a "
                             "105 ms call, so this is provided for completeness and is not expected to help; it falls "
                             "back to eager when no C compiler is present")
    parser.add_argument("--out", type=Path, default=None, help="directory to write one CSV per table")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args(argv)
    if args.demo:
        demo()
        return 0
    backend = configure(fast=args.fast)
    if args.scores is None:
        parser.error("--scores is required (or pass --demo)")
    blob = torch.load(args.scores, map_location="cpu", weights_only=False)
    if blob.get("format") != "supervised-scores-v1":
        raise SystemExit(f"{args.scores}: not a scores blob from models.detector --save-scores")
    run = maybe_compile(report, enabled=args.compile)
    tables = run(blob, tuple(args.budgets), args.gap, args.persist, args.device)
    pd.set_option("display.width", 240)
    print(f"\nbackend: {backend}")
    titles = {"ranking": "1. RANKING AND CALIBRATION (threshold-free)",
              "economics": "2. OPERATING POINTS (budget -> threshold -> cost)",
              "emission": "3. EMISSION FUNNEL (threshold -> persist -> incidents)",
              "population": "4. BY OBSERVATION POPULATION (never pool these)"}
    print(f"\n=== EVALUATION — {blob['day']}")
    for name, table in tables.items():
        print(f"\n{titles.get(name, name)}\n")
        print(table.to_string(index=False, float_format=lambda v: f"{v:,.6g}") if len(table) else "  (empty)")
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        for name, table in tables.items():
            table.to_csv(args.out / f"{name}.csv", index=False)
        print(f"\nwritten to {args.out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
