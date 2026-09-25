"""Fit the detector on a day and report it at each budget."""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from models.context_encoder.data import DAYS
from models.runtime import configure
from models.detector.checkpoint import save_calibration, save_head
from models.detector.features import benign_gate, combine, load_features, standardise
from models.detector.model import (
    BENIGN, FPR_POINTS, HIDDEN, budget_threshold, class_scores, family_codes, train_head,
)
from models.detector.report import multiclass_matrix, report


def run_day(day: str, fprs=FPR_POINTS, device: str = "cpu", seed: int = 0,
            calibrate: float = 0.2, context: Path | None = None, events: int | None = None,
            family: str | None = None, compressor: Path | None = None, save: Path | None = None,
            save_scores: Path | None = None) -> tuple[list[dict], pd.DataFrame]:
    """Fit on a day's train split, calibrate on rows the head never saw, report its test split.

    Input:  day, budgets, device, seed, the share of train held back for calibration
    Output: (report rows, the multi-class matrix at the middle budget)

    The threshold is read on the validation split **plus** a held-back slice of train, and never on the rows being
    reported. Validation alone was not enough: it is one time segment of the day, and a threshold set there overshot
    its budget six-fold on the test segment (benign traffic differs by time of day). The held-back slice is drawn at
    random across the whole training period, so the calibration rows span the day instead of one stretch of it.
    """
    data, feature_name = load_features(day, context, device, events, family)
    code, families = family_codes(data["label"])
    train, val, test = (data["split"] == 0), (data["split"] == 1), (data["split"] == 2)
    # A narrow --events slice can land entirely inside one segment, leaving nothing to report on. Said here rather
    # than as an IndexError from the empty score array three calls later.
    for name, mask in (("train", train), ("validation", val), ("test", test)):
        if not mask.any():
            raise SystemExit(f"{day}: the slice has no {name} rows ({len(mask):,} events). Widen --events, or drop "
                             f"it to use the whole day -- segment_split cuts inside each attack window and benign "
                             f"stretch, so a narrow slice can sit wholly in one split")
    train_rows = np.flatnonzero(train)
    order = np.random.default_rng(seed).permutation(len(train_rows))
    cut = int(len(train_rows) * (1.0 - calibrate))
    fit_rows, held_rows = train_rows[order[:cut]], train_rows[order[cut:]]
    head, mean, std = train_head(data["h"][fit_rows], code[fit_rows], len(families) + 1, device=device, seed=seed)
    calib_rows = np.sort(np.r_[held_rows, np.flatnonzero(val)])
    calib_scores = class_scores(head, mean, std, data["h"][calib_rows], device=device)
    test_scores = class_scores(head, mean, std, data["h"][test], device=device)
    benign_calib = ~data["attack"][calib_rows]
    standardise_reference = calib_scores[benign_calib]
    thresholds = {(name, fpr): budget_threshold(calib_scores[benign_calib, k], fpr)
                  for k, name in enumerate(families, start=1) for fpr in fprs}
    if save is not None:
        save_head(save, head=head, mean=mean, std=std, families=families, thresholds=thresholds,
                  width=data["h"].shape[1], hidden=HIDDEN, feature=feature_name, day=day, seed=seed,
                  context=context, calibrate=calibrate)
    if save_scores is not None:
        save_calibration(save_scores, families=families, day=day, calib_benign=calib_scores[benign_calib],
                         test=test_scores, test_code=code[test], test_attack=data["attack"][test],
                         t_obs=data["t_obs"][test], sender=data["sender"][test])
    gated = None
    if compressor is not None:
        if data["context"] is None:
            raise SystemExit("the gate needs Block 8's context: pass --context-encoder as well")
        raw = benign_gate(compressor, data["context"], device)
        reference = raw[calib_rows][benign_calib]
        calib_gate, test_gate = standardise(raw[calib_rows], reference), standardise(raw[test], reference)
        code_calib = code[calib_rows]
        gated = np.stack([combine(standardise(calib_scores[:, k], standardise_reference[:, k]), calib_gate,
                                 code_calib == k,
                                 standardise(test_scores[:, k], standardise_reference[:, k]), test_gate)
                          for k in range(test_scores.shape[1])], 1)
    held = {name: value[test] for name, value in data.items() if name not in ("h", "context")}
    rows = report(day, held, families, test_scores, thresholds, fprs, gated)
    for row in rows:
        row["input"] = feature_name
        row["width"] = data["h"].shape[1]
    return rows, multiclass_matrix(held, families, test_scores, thresholds, fprs[len(fprs) // 2])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--days", nargs="+", default=DAYS)
    parser.add_argument("--out", type=Path, default=Path("data/model_cache/results/supervised_arm.csv"))
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--events", type=int, default=None,
                        help="use a contiguous slice of this many events, centred on the day's attacks: the quick "
                             "proxy for a full-day run (validated against it -- see docs/TESTS.md)")
    parser.add_argument("--compressor", type=Path, default=None,
                        help="a Block 9 checkpoint: its reconstruction error becomes a second condition on every "
                             "alert, which is Block 9's false-positive job (design.md, Block 9)")
    parser.add_argument("--family", default=None,
                        help="centre the slice on this family; a day's families sit in different stretches of it")
    parser.add_argument("--save", type=Path, default=None,
                        help="write the servable checkpoint here: head weights, the feature scaler, family names and "
                             "the budget thresholds. Without it a run leaves nothing a live system can load")
    parser.add_argument("--save-scores", type=Path, default=None,
                        help="write the calibration and test score distributions here, for models/evaluation/thresholds.py to "
                             "sweep the budget/recall tradeoff without refitting")
    parser.add_argument("--context-encoder", type=Path, default=None,
                        help="a Block 8 checkpoint: puts its context s beside the embedding, which is the only way "
                             "link memory, the neighbourhood and the flow messages reach the supervised arm")
    args = parser.parse_args(argv)
    configure(fast=getattr(args, "fast", False))
    device = "cuda" if torch.cuda.is_available() else "cpu"
    rows = []
    for day in args.days:
        # One day per file: a five-day run would otherwise overwrite one checkpoint five times.
        stem = (lambda p: p.with_name(f"{p.stem}_{day}{p.suffix or '.pt'}") if p else None)
        day_rows, matrix = run_day(day, device=device, seed=args.seed, context=args.context_encoder,
                                   events=args.events, family=args.family, compressor=args.compressor,
                                   save=stem(args.save), save_scores=stem(args.save_scores))
        rows += day_rows
        print(f"\n=== {day}: named family against truth, at the 1% budget (rows true, columns named)")
        print(matrix.to_string())
    table = pd.DataFrame(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(args.out, index=False)
    show = ["day", "input", "population", "family", "fpr_budget", "attacks", "tp", "fp", "fn", "recall",
            "precision", "ideal_precision", "pr_auc", "fp_at_target_oracle", "fpr_at_target_oracle"]
    show += [c for c in ("fp_at_target_gated_oracle", "pr_auc_gated") if c in table.columns]
    print(f"\n=== recall at each budget, with the ceiling precision that budget allows")
    print(table[show].to_string(index=False))
    print(f"\nwritten to {args.out}")
    return 0
