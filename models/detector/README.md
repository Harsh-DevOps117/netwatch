# `models/detector` — the detection head

## Purpose

Name the attack family behind an event, at a chosen false-positive budget. This is the **main line**: it is the arm
whose numbers are deployable, and the one the system leads with.

## Function

A small classifier over a frozen representation: one hidden layer, one logit per class with benign first. Classes are
weighted by inverse frequency, because an attack family is a fraction of a percent of the rows and the objective is
recall — an unweighted fit learns to answer benign.

The representation is the flow embedding (32-wide), and with `--context-encoder` the context vector beside it (132-wide total).
**Passing a context encoder is not optional for the real system:** it is the only path by which link memory, the
neighbourhood and the flow messages reach this arm.

Thresholds are read from a **calibration** set — the validation split plus a held-back random slice of train — and never
from the rows being reported.

## Files

| file | role |
|---|---|
| `__main__.py` | CLI shim |
| `train.py` | `run_day`: fit, calibrate, report at each budget |
| `model.py` | `Head`, `train_head`, `class_scores`, `family_codes`, `budget_threshold`, and `BENIGN` — the class order every stage numbers against |
| `features.py` | `load_features`, plus the reconstruction-error gate measured against it |
| `checkpoint.py` | `save_head` / `load_head` / `save_calibration` — everything a serving process reads |
| `report.py` | `cost_of_recall`, `confusion`, `report`, `multiclass_matrix` |

Split by concern in 2026-09-21; it was one 510-line `head.py`.

## Inputs and outputs

**In:** `data/flow_embeddings/split/<day>/`, optionally a context encoder checkpoint.
**Out:**
- a report CSV, per family and per observation population, at each budget
- `--save` → a servable checkpoint: head weights, **the feature scaler**, family names, the budget thresholds, and an
  empty `serve_threshold`
- `--save-scores` → the calibration-benign and test score distributions, for threshold sweeps without refitting

Both are suffixed per day, so a multi-day run leaves one checkpoint per day rather than overwriting one.

## Running

```bash
uv run python -m models.detector --days <days...> \
  --context-encoder data/model_cache/block8_10d/best.pt \
  --save data/model_cache/serve/head.pt \
  --save-scores data/model_cache/serve/scores.pt \
  --seed 0
```

Then choose an operating point separately, with `tools/find_threshold.py`, which writes the chosen value into the
checkpoint's `serve_threshold`. Nothing else writes that field.

## Settings that matter

| setting | value | reason |
|---|---|---|
| `--context-encoder` | **required in practice** | Without it the classifier sees flow embeddings alone and no context. |
| `--tensorboard` / `--resume` / `--lr-schedule` | see `models/training.py` | shared by every trainer; `--lr-schedule none` is the default and what every measured result used |
| `--seed` | **0, 1, 2** | Three seeds, always: a nondeterminism bug once masqueraded as roughly 5 points of seed variance. |
| `--compressor` | **leave off** | Adding reconstruction error as a second condition on every alert was measured and rejected — it cost recall without buying false-positive rate. |
| `--events` | omit for a real run | The slice proxy; on the Bot day fewer than ~3M events contain no test rows at all, and the run now says so rather than failing obscurely. |

## Notes

**The feature scaler is part of the model.** `class_scores` standardises with the training mean and standard deviation,
so a process that reloads the weights without them produces scores on a different scale and every threshold becomes
meaningless. `save_head` stores them; `load_head` restores them.

**`fp_at_target` in the report is an oracle.** It selects its threshold using test attack scores, so it cannot be
reproduced by a live system, which has no test labels. Quote only the budget → quantile → realised-FPR path.

**Populations are reported separately.** `early_observation` and `completed_before_budget` are never pooled; only the
first carries a lead-time claim.
