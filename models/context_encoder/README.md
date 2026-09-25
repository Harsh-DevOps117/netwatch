# `models/context_encoder` — the context encoder (Block 8)

## Purpose

Give each event the context its flow embedding cannot carry: what this link has been doing, and what the hosts at each
end have been doing with everyone else. Output is a 100-wide context vector `s`.

## Function

Two mechanisms over the availability-ordered event stream:

1. **Link memory** — one GRU state per directed link, reset after a time-to-live of 3600 s without an update.
2. **Neighbourhood attention** — attention over up to 20 neighbouring events, being the latest event per distinct peer
   of each endpoint.

Trained by **link prediction** on benign training events: predict which receiver an event belongs to against sampled
negatives. It is then frozen; the compressor and the detector both read it without passing gradient back.

Optionally, two further message kinds reach link memory at the time they become available: a 20-packet summary, and the
CICFlowMeter record. These are merged into memory as separate message kinds with a presence bit and a per-message time
gap (early fusion, not concatenation).

## Files

| file | role |
|---|---|
| `__main__.py` | CLI: the day loop, checkpoint selection |
| `train.py` | the objective: `LinkPredictor`, `run_stream`, `negative_receivers`, `link_ap` |
| `model.py` | `ContextEncoder`, `LinkMemory`, `LinkIds`, `make_batch`, attention capture |
| `stream.py` | `NeighbourIndex`, `availability_order` |
| `data.py` | `load_day`, `make_stream`, `attack_slice`, the `DAYS` list |
| `features.py` | per-event side features at the observation time |
| `records.py` | the CICFlowMeter record as a message, and its frozen encoder |
| `record_arm.py` | the records-only cascade, on the records' own timeline |

## Inputs and outputs

**In:** `data/events/<day>/`, `data/context_features/<day>/side_features.parquet`, `data/flow_embeddings/split/<day>/`
**Out:** `<out>/best.pt` (selected on mean validation link PR-AUC) and `<out>/history.csv`

## Running

```bash
uv run python -m models.context_encoder --arm split --days <days...> \
  --out data/model_cache/block8_10d \
  --epochs 10 --patience 2 --batch-size 200 --lr 1e-3 --capacity 0.25
```

Add `--flow-records --flow-messages --record-encoder <path>` to enable the extra message kinds, which requires
`models.context_encoder.records` to have produced `flow_records.parquet` for every day being trained on.

## Settings that matter

| setting | value | reason |
|---|---|---|
| `--capacity` | **0.25** for live | Caps link memory and recycles the least-recently-used slot. Omitted, the table holds one row per link, which no live stream can do. Measured: 1,000 distinct links through a 250-slot table produced 750 evictions and validation link PR-AUC 0.9820. The value is stored in the checkpoint, so the compressor and detector honour it with no extra flag. |
| `--events` | omit for a real run | It takes a contiguous slice centred on one family, for quick iteration only — see below. |
| TTL | 3600 s | A constructor default in `model.py`, not a CLI flag. |

## Notes

**`attack_slice` is for comparing arms, not for absolute numbers.** It centres on the attack span, so on the Bot day it
begins 3,446 s *after* the first Bot attack and contains none of that day's 1,239,249 pre-attack rows. It also
calibrates thresholds on fewer benign rows. A slice narrower than about 3M events on the Bot day contains no test rows
at all.

**Attention activations are available for explainability** via `encoder.explain = True`, which is verified to leave the
encoding bit-identical. Default is off, so training pays nothing. See `models/explanation/README.md`.

**The neighbourhood excludes an event's own link.** Link memory already carries that link's history; the neighbourhood
exists to supply the surrounding context. The live implementation reproduces this exactly — see
`models/serving/README.md`.
