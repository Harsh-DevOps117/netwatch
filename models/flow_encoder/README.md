# `models/flow_encoder` — flow encoder

Turns one network flow, as seen in its first 10 ms, into `h`: 32 numbers. It reads no other traffic. Every later stage
starts from `h`. Design and figure: [docs/architecture.md §4](../../docs/architecture.md#4-flow-encoder).

## How it works

Each flow becomes a small graph: one node per packet seen (up to 20) and one flow node holding the flow's 40-number
summary. Two graph layers (GINEConv over packet-to-packet edges, SAGEConv from the flow node) update the packets; mean
and max pooling plus the summary give `h`. It is trained as an **autoencoder on benign flows**: small decoders must
rebuild the summary, the packets and the flow's full 20-packet summary from `h`. After training it is frozen.

About 65,000 parameters in the encoder, 124,000 with the decoders.

## Files

| file | role |
|---|---|
| `__main__.py` | command line: fit, evaluate, export |
| `train.py` | training loop and `embed()` |
| `encoder.py` | the packet graph, the graph layers and the autoencoder |
| `export.py` | writes `flow_embeddings.parquet` and its manifest |
| `metrics.py` | tie-aware average precision, anomaly score |

## Inputs and outputs

| | path |
|---|---|
| in | `data/events/<day>/`, `data/processed/<day>/` |
| out: model | `<run>/b7/<stem>.pt` (weights **and** the input scaler), `<stem>_epochNN.pt`, `<stem>_history.csv` |
| out: embeddings | `<run>/embeddings/split/<day>/flow_embeddings.parquet` + `flow_embeddings_manifest.json`, one row per event |

`<run>` is a training run folder, `~/netwatch-data/runs/<stamp>/`. Columns: [docs/data.md](../../docs/data.md).

## Running

The training script runs this stage ([docs/training.md](../../docs/training.md)). To run it alone:

```bash
uv run python -m models.flow_encoder --side split --packet-encoder gnn --budget-ms 10 \
  --fit-day <every day> --cross-day <any one day> --sample 320000 --epochs 10 \
  --save-scores <run>/b7 --export <run>/embeddings/split --export-days <every day>
```

## Settings

| setting | value | why |
|---|---|---|
| `--budget-ms` | 10 | the observation budget; changing it changes every event's `t_obs` and every later stage |
| `--side` | `split` | keeps a flow's two directions apart; what the context encoders and the detector read |
| `--fit-day` | every day | a model fitted on some days only is an evaluation run, not one to serve |
| `--sample` | 320,000 | events per day used for fitting; the export still embeds every event |

## Notes

- **The input scaler is part of the model.** It is fitted on the sampled benign training rows and stored in the checkpoint;
  the export manifest records its hash, so a mismatch is detected rather than silent.
- When every day is a fit day, the run's own evaluation scores are not held out and should not be quoted; the
  checkpoint and the export are what such a run is for.
