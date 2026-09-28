# `models/compressor` — compressor

Compresses each event's context `s` (100 numbers, from a frozen context encoder) into `z` (32 numbers) for the world
model, and reports how unlike benign traffic that context is. Trained twice from the same code: on the forecasting
encoder for the `lag` world model (`b9`), and on the detection encoder for the `live` one (`b9live`). Design and figure:
[docs/architecture.md §7](../../docs/architecture.md#7-compressor).

## How it works

An autoencoder, 100 → 128 → 32 → 128 → 100, trained on benign events only to rebuild `s` (mean squared error). `s` is
first put on a benign scale fitted once on 200,000 benign training events and stored in the checkpoint. Each event is
encoded on its own; the context encoder receives no gradient.

## Files

| file | role |
|---|---|
| `__main__.py` | command line |
| `train.py` | the training loop |
| `autoencoder.py` | the autoencoder and its benign scale |
| `latents.py` | loading the frozen context encoder, scoring, and the `event_latents.parquet` export |

## Inputs and outputs

| | path |
|---|---|
| in | `<run>/b8/best.pt` (`live`: `<run>/b8det/best.pt`) and everything it reads |
| out: model | `<run>/b9/best.pt` (`live`: `b9live/`; best mean validation loss), `epoch_NN.pt`, `resume.pt`, `history.csv`, `best_metrics.csv` |
| out: latents | `<run>/latents/<day>/` (`live`: `latents-live/<day>/`): `event_latents.parquet` + `latents_manifest.json` — one row per event with packets, in availability order |

`label`, `attack`, `role` and `split` in the export are for evaluation only and must never be a model input; neither is
`recon_error`, which is a score. Columns: [docs/data.md](../../docs/data.md).

## Running

```bash
# fit
uv run python -m models.compressor --encoder mlp --target s --context-encoder <run>/b8/best.pt \
  --days <days...> --embeddings-root <run>/embeddings --out <run>/b9 \
  --epochs 5 --window 512 --d-z 32 --lr 1e-3 --normalise-rows 200000 --lr-schedule cosine

# export the latents the world model reads
uv run python -m models.compressor --encoder mlp --target s --context-encoder <run>/b8/best.pt \
  --load <run>/b9/best.pt --out <run>/b9 --export <run>/latents --window 512 \
  --days <days...> --embeddings-root <run>/embeddings
```

For the `live` pair, the same two commands with `--context-encoder <run>/b8det/best.pt`, `--out <run>/b9live` and
`--export <run>/latents-live`.

## Settings

| setting | value | why |
|---|---|---|
| `--d-z` | 32 | the latent width the world model reads |
| `--window` | 512 | events per batch, matching the context encoder; must be the same when fitting and exporting |
| `--target` | `s` | rebuild the context vector |
| `--normalise-rows` | 200,000 | benign training events used to fit the scale of `s` |

## Notes

- `event_latents.parquet` (the compressor's `z`) and `flow_embeddings.parquet` (the flow encoder's `h`) both hold 32
  numbers per event; the names differ so one cannot be loaded in place of the other by mistake.
