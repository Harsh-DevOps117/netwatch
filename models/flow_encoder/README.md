# `models/flow_encoder` — the per-flow encoder (Block 7)

## Purpose

Produce one fixed-width embedding per network flow from the first packets visible inside a 10 ms observation budget,
without any network context. It is the first learned stage and the input to everything after it.

## Function

An autoencoder over a flow's early packet sequence and its aggregate features. Trained on benign flows only, so its
reconstruction error is meaningful on its own, and frozen afterwards: no gradient from any later stage reaches it.

~65,000 parameters, 32-wide output embedding (`h_split`).

## Files

| file | role |
|---|---|
| `__main__.py` | CLI: fit, score a held-out day, export embeddings |
| `train.py` | the fitting loop, early stopping, `embed()` |
| `encoder.py` | the packet reader and the autoencoder |
| `export.py` | writes `flow_embeddings.parquet` and its manifest |
| `metrics.py` | tied-rank average precision, anomaly score |

## Inputs and outputs

**In:** `data/events/<day>/`, `data/processed/<day>/`
**Out:**
- `data/flow_embeddings/<side>/<day>/flow_embeddings.parquet` — one row per event, `event_id ↔ h` a bijection
- `<save-scores>/<stem>.pt` — weights **and the input scaler**

## Running

```bash
# leave-one-day-out, which is how every reported Block 7 number was produced
uv run python -m models.flow_encoder \
  --fit-day <days...> --cross-day <held-out day> \
  --side split --budget-ms 10 --epochs 30 --patience 5 \
  --save-scores data/model_cache/block7_serve \
  --export data/flow_embeddings/split_serve
```

`--side split` keeps a flow's two directions apart and is what the context encoder and the detector read. `responder`
and `initiator` exist for other arms.

## Settings that matter

| setting | value | reason |
|---|---|---|
| `--budget-ms` | **10** | The design's observation budget. Changing it invalidates every downstream artefact, because `t_obs` and the observation population both move. |
| `--side` | **split** | What the context encoder and detector consume. |
| `--fit-day` | all days, **for serving** | See below. |

## Notes

**A leave-one-day-out checkpoint is not servable.** `--fit-day A B --cross-day C` produces an evaluation artefact: it
has never seen day C. Every checkpoint currently on disk is of that kind. A servable encoder must be fit with every day
in `--fit-day`; the scores from such a run are contaminated, because each day is also a fit day, and must not be quoted.
The checkpoint and the export are the deliverable there.

**The input scaler travels with the weights** (see the IMPORTANT section of `docs/DEPLOYMENT_RUNBOOK.md`). `normalise()` fits its statistics on this run's sampled training rows,
which depend on `--fit-day`, `--sample` and `--seed`. The checkpoint stores them (`format: block7-encoder-v1`) and
`--load-from` restores them; checkpoints written before that change carry none, so loading one recomputes the statistics
from the current invocation's sample and warns. The export manifest records a `normalisation_sha256` so a mismatch is
detectable rather than silent.
