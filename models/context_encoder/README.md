# `models/context_encoder` — context encoder

Places one event A → B in its network context — what this link has been doing, and what A and B have been doing with
everyone else — and returns `s`: 100 numbers. Design and figures: [docs/architecture.md §5](../../docs/architecture.md#5-context-encoder).

Two copies are trained from the same code:

| copy | messages into link memory | used by |
|---|---|---|
| **detection encoder** (`b8det`) | event, 20-packet summary | the detector, and the `live` tag's compressor and world model |
| **forecasting encoder** (`b8`) | event, 20-packet summary, flow record | the `lag` tag's compressor and world model |

## How it works

- **Link memory** — one GRU state of 100 numbers per link direction, reset after 3,600 s without an update. Each message
  kind has its own slot in the update, and a message is applied only once it exists.
- **Neighbourhood attention** — the event's query attends over up to 20 neighbour events: the latest event with each
  recent distinct peer of A and of B, excluding earlier A → B events.
- **Training** — link prediction on benign events: tell the real receiver from a sampled fake one. The encoder is then
  frozen.

## Files

| file | role |
|---|---|
| `__main__.py` | command line: the day loop, checkpoints, metrics |
| `model.py` | `ContextEncoder`, `LinkMemory`, the message encoders, `make_batch` |
| `train.py` | the link-prediction objective and its metric |
| `stream.py` | `NeighbourIndex` (latest event per distinct peer), availability order |
| `data.py` | loading a day, streams, the day cache |
| `features.py` | per-event side features at `t_obs` (writes `side_features.parquet`) |
| `records.py` | flow records (writes `flow_records.parquet`) and the record encoder |
| `record_arm.py` | a comparison arm (late fusion): the flow record as the event's own representation, on the record's timeline |

## Inputs and outputs

| | path |
|---|---|
| in | `data/events/<day>/`, `data/context_features/<day>/side_features.parquet`, `<run>/embeddings/split/<day>/`; forecasting copy also `data/context_features/<day>/flow_records.parquet` and `<run>/record_encoder.pt` |
| out | `<run>/b8det/` or `<run>/b8/`: `best.pt` (best mean validation link PR-AUC), `epoch_NN.pt`, `resume.pt`, `history.csv`, `best_metrics.csv` |

## Running

The training script runs both copies ([docs/training.md](../../docs/training.md)). To run one alone:

```bash
# side features, once per day
uv run python -m models.context_encoder.features --days <day>

# detection encoder
uv run python -m models.context_encoder --arm split --days <days...> --embeddings-root <run>/embeddings \
  --out <run>/b8det --epochs 5 --batch-size 512 --lr 1e-3 --capacity 0.25 --lr-schedule cosine --flow-messages

# forecasting encoder: add the flow records and the frozen record encoder
uv run python -m models.context_encoder --arm split --days <days...> --embeddings-root <run>/embeddings \
  --out <run>/b8 --epochs 5 --batch-size 512 --lr 1e-3 --capacity 0.25 --lr-schedule cosine \
  --flow-messages --flow-records --record-encoder <run>/record_encoder.pt
```

## Settings

| setting | value | why |
|---|---|---|
| `--batch-size` | 512 | memory is updated once per batch, so the batch size is part of what the model learned; serving uses the same |
| `--capacity` | 0.25 | caps link memory at 25% of a day's links, recycling the least recently used; stored in the checkpoint. The live detector, which has no finished day to count, uses a fixed 250,000 slots (`--capacity`) |
| `--flow-messages` | on | adds the 20-packet summary message |
| `--flow-records`, `--record-encoder` | forecasting copy only | adds the flow-record message; the detector must not see finished-flow information |
| time-to-live | 3,600 s | a model constant, not a flag |

## Notes

- Set `encoder.explain = True` to keep the attention weights for explanations; results are unchanged, and it is off by
  default so training pays nothing ([models/explanation](../explanation/README.md)).
- `--events` and `--family` train on a slice of a day; use them for quick checks only, never for reported numbers.
