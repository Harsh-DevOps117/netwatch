# `models/evaluation` — every reported metric

Produces the full set of detector metrics with one command, so the same picture can be reported after every training
run, and evaluates each stage against its own training objective.

## What it reports

From the score file the detector writes (`--save-scores`):

1. **Ranking and calibration** (no threshold): tie-aware PR-AUC, Brier score, expected calibration error.
2. **Operating points**: budget → threshold → realised false-alarm rate, recall, precision, alarms per hour, incidents
   per hour.
3. **From events to incidents**: events above threshold → after persistence (3 in a row) → incidents, using the same
   `AlertEmitter` as serving.
4. **By observation population**, never pooled — when the score file carries each row's population (detector score
   files written from 2026-09-27 on); older files have none, and tables 1–3 then pool the two.

## Files

| file | role |
|---|---|
| `__main__.py` | command line |
| `report.py` | the four tables |
| `thresholds.py` | the budget → threshold sweep, and committing a chosen operating point into a head checkpoint |
| `blocks.py` | per-stage evaluation: each stage against its own objective |

## Running

```bash
# detector metrics for one day
uv run python -m models.evaluation --scores <run>/detector/scores_<day>.pt --out <report folder>

# commit an operating point into the detector head: the cheapest budget that keeps recall at the floor
uv run python -m models.evaluation.thresholds --scores <run>/detector/scores_<day>.pt --recall-floor 0.995 \
  --write <run>/detector/head_<day>.pt

# each stage against its own objective
uv run python -m models.evaluation.blocks --days <days...> --embeddings-root <run>/embeddings --latents <run>/latents/<day>
```

`--budgets`, `--persist` (default 3) and `--gap` (default 60 s) change the operating points and the incident rules.
Rates per hour are over the test split's own duration — its bands, 2.8–3.7 h per day — not the first-to-last span of its
rows, which covers the whole day and would understate every rate about three times.
`--fast` enables faster GPU arithmetic that changes results in the last digits; it is off by default because this code
measures thresholds precisely.

## Notes

- **Ties are collapsed in PR-AUC.** Within 10 ms many flood events share an identical input, and so an identical score;
  precision and recall are therefore taken once per distinct score rather than by row position.
- **Per-stage evaluation** reports each stage's effective rank alongside its loss: a stage can keep a good loss while
  collapsing its output into a few directions, which starves the next stage.
- Calibration is reported because a probability shown to an analyst has to mean what it says.
