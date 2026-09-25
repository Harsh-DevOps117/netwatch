# `models/compressor` — the event compressor (Block 9)

## Purpose

Compress the context encoder's 100-wide context vector into a 32-wide latent `z`, and keep the reconstruction error as
a signal in its own right. `z` is what the world model reads.

## Function

An autoencoder over the frozen context vector, fitted on benign events only. Two outputs per event:

- `z` — the compressed context, 32-wide.
- `recon_error` — the squared reconstruction error on the benign scale the autoencoder was fitted with. Low means the
  context looks like benign traffic.

The context encoder is frozen throughout and never receives a gradient; that separation is the premise of the cascade.

## Files

| file | role |
|---|---|
| `__main__.py` | CLI shim |
| `train.py` | the objective: `run_block9` |
| `latents.py` | `frozen_block8`, `context_vectors`, scoring, and the `event_latents.parquet` export |
| `autoencoder.py` | the autoencoder modules and target construction |

## Inputs and outputs

**In:** a context encoder checkpoint, plus everything that stage read.
**Out:**
- `<out>/best.pt` — selected on mean validation loss
- `data/latents/<run>/<day>/event_latents.parquet` — one row per event, in availability order
- `data/latents/<run>/<day>/latents_manifest.json`

The export is the handoff to Block 10. It carries `event_id`, `t`, `t_obs`, endpoints, `z`, `recon_error`, `split`,
`label`, `observation_population` and `attack`. **`label` and `attack` are evaluation only and must never be used as
input.**

## Running

```bash
# fit
uv run python -m models.compressor --encoder mlp --target s \
  --block8 data/model_cache/block8_10d/best.pt --days <days...> \
  --out data/model_cache/block9_10d \
  --epochs 6 --patience 2 --window 512 --d-z 32 --normalise-rows 200000

# export the latents Block 10 reads
uv run python -m models.compressor --encoder mlp --target s \
  --block8 data/model_cache/block8_10d/best.pt \
  --load data/model_cache/block9_10d/best.pt \
  --out data/model_cache/block9_10d \
  --export data/latents/serve_10d --window 512 --days <days...>
```

`--out` is required by argparse even when exporting, and doubles as the checkpoint location when `--load` is omitted.
`--window` must match the value used to fit.

## Settings that matter

| setting | value | reason |
|---|---|---|
| `--d-z` | **32** | The shipped latent width. |
| `--window` | **512** | Events per window, and also the batch. Matches the context encoder's live batch, so training and serving see the same staleness. |
| `--target` | **s** | Rebuild the context vector. `x_e` rebuilds the fixed event features instead, which is the comparison arm. |
| `--normalise-rows` | **200000** | Benign training rows used to fit the scale of `s`. |

## Notes

**Do not use `recon_error` as a gate on the detector.** Adding it as a second condition on every alert was measured and
rejected: it cost recall without buying false-positive rate. It remains useful as a reported signal.

**Naming.** This package's output is `event_latents.parquet`; the flow encoder's is `flow_embeddings.parquet`. Both have
one row per event and 32 numbers per row, so a loader expecting one would silently accept the other and train on
representations that carry no network context. The names are kept distinct for that reason.
