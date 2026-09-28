# `models/detector` — detector

Names the attack family behind an event, with a probability, at a false-alarm budget the operator chooses. Design and
figure: [docs/architecture.md §6](../../docs/architecture.md#6-detector).

## How it works

A small classifier over frozen inputs: `[h, s]` = 32 numbers from the flow encoder and 100 from the detection encoder,
one hidden layer of 64, one output per class (benign first). Classes are weighted by the square root of their inverse
frequency, because each attack family is a small fraction of the rows. One head is trained per day, on that day's
families only, so a head does not know — and should not be served on — another day's attacks.

Thresholds come from **benign scores on calibration rows** (the validation split plus 20% of training kept back) at
each false-alarm budget — 0.01%, 0.1%, 1% and 5% — one per family; test labels are never used to set them.

## Files

| file | role |
|---|---|
| `__main__.py` | command line |
| `train.py` | fit, calibrate and report one day |
| `model.py` | the head, training, class scores, budget thresholds, the class order |
| `features.py` | loads `[h, s]` for a day |
| `checkpoint.py` | saving and loading everything a serving process needs |
| `report.py` | results per family, population and budget; confusion matrices |

## Inputs and outputs

| | path |
|---|---|
| in | `<run>/embeddings/split/<day>/`, `<run>/b8det/best.pt` |
| out | `<run>/detector/head_<day>.pt` — weights, **the feature scaler**, family names, thresholds per budget and the committed operating point `serve_threshold`; `scores_<day>.pt` — calibration and test score distributions; `results.csv` |

## Running

```bash
uv run python -m models.detector --days <days...> --context-encoder <run>/b8det/best.pt \
  --embeddings-root <run>/embeddings --save <run>/detector/head.pt \
  --save-scores <run>/detector/scores.pt --out <run>/detector/results.csv --seed 0
```

Then commit an operating point, the only step that writes `serve_threshold`:
`python -m models.evaluation.thresholds --scores <run>/detector/scores_<day>.pt --recall-floor 0.995 --write <run>/detector/head_<day>.pt`
([docs/training.md §6](../../docs/training.md#6-the-detectors-operating-point)). The training script commits each
family's threshold at the 0.01% budget this way (`SERVE_BUDGET`).

## Settings

| setting | value | why |
|---|---|---|
| `--context-encoder` | the detection encoder | without it the head sees the flow alone, with no context |
| `--seed` | 0 | the training script trains one seed; run 1 and 2 as well before quoting a result's spread |
| `--events`, `--family` | omit | train on a slice of a day, for quick checks only |

## Notes

- **The feature scaler is part of the model**: scores computed without it land on another scale and every threshold
  loses its meaning. `save_head` stores it and `load_head` restores it.
- **Report only budget → threshold → realised false-alarm rate.** The report's `fp_at_target_oracle` column picks its threshold
  with test labels, which no live system has; it is for analysis, not a result.
- The two observation populations (`early_observation`, `completed_before_budget`) are always reported separately.
