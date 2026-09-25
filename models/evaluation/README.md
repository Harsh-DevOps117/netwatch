# `models/evaluation` — every reported metric, in one place

## Purpose

Produce the complete metric set for a trained model with one command. Previously each number lived in a different
experiment script, and `tools/collect_final.py` could only gather the seven final experiments by index — nothing
produced the whole picture for a given model, which is what has to be presented and re-presented after each full run.

## Function

Reads a score blob written by `models.detector --save-scores` and reports four tables.

1. **Ranking and calibration**, threshold-free — tied-rank PR-AUC, Brier score, expected calibration error.
2. **Operating points** — budget → threshold → realised FPR, recall, precision, alarms/hour, incidents/hour.
3. **The emission funnel** — events → above threshold → after persist-3 → incidents, run through the real
   `AlertEmitter` rather than a reimplementation.
4. **By observation population** — `early_observation` against `completed_before_budget`.

## Files

| file | role |
|---|---|
| `__main__.py` | CLI shim |
| `report.py` | `average_precision`, `calibration`, `emission_funnel`, `report` |
| `thresholds.py` | budget → threshold sweep, and committing a chosen point into a checkpoint |
| `blocks.py` | per-stage evaluation: each block against its own objective |

## Per stage, not only end to end

`python -m models.evaluation.blocks` scores each block on what it was trained against, because an end-to-end number
cannot say which stage moved — and in a frozen cascade every later stage inherits whatever the earlier one produced.

`effective_rank` is the column to watch: a stage can hold a healthy loss while collapsing its output into a few
directions, starving the next stage however good the loss looks. `ratio` is attack error over benign error; at or below
1 the reconstruction carries no signal. Errors are reported **per target**, because the flow encoder's own manifest
warns against combining them unstandardised.

## Running

```bash
uv run python -m models.evaluation --scores data/model_cache/serve/scores_<day>.pt \
  --out data/model_cache/results/evaluation_<day>
```

`--fast` opts into cuDNN autotuning and TF32; off by default, because both change results in the last bits and this is
the code that measures thresholds to six significant figures. `--compile` is accepted and falls back to eager when no C
compiler is present.

## Reference result

Bot day, 3M slice, seed 0 — 574,893 test rows over 0.72 h, **63.7 ms** on the GPU:

| metric | value |
|---|---|
| PR-AUC (tied) | 0.999973 |
| Brier / ECE | 0.000157 / 0.000525 |
| threshold 0.9793 | recall 0.9906, 6 false alarms, 8.4 false alarms/hour |
| emission funnel | 16,241 above threshold → 15,409 after persist-3 → **21 incidents** (29.4/hour) |
| coverage | all 10 attacking hosts alerted; all 16,389 attack events on an alerting host |

The funnel line is the one to show an operator. Raw alerting is 22,708/hour; what a human sees is 29.4 incidents/hour.

## Notes

**Ties are collapsed in PR-AUC.** At a 10 ms budget most of a flood's rows share an identical input vector and therefore
an identical score with some benign row. Ranking those by array position would invent a separation the model never
produced, so precision and recall are taken once per distinct score.

**Populations are never pooled**, for the reason given in `models/data/README.md`.

**Calibration is reported even though nothing optimises it.** A probability shown to an analyst has to mean what it says.
