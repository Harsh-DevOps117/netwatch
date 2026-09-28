"""Block 10 — the world model.

A TGN-family architecture over the event stream: persistent per-node memory, a neighbourhood attention layer, a
network-wide global readout, and two heads — an auxiliary next-event predictor and a primary ranking head that says
which node the campaign reaches next.

Five modules, in the order data moves:

| module | role |
|---|---|
| `reception.py` | load and validate one run's tables against every guarantee the schema claims |
| `dataset.py` | a validated run becomes an ordered stream of `TrainingStep`s: gated neighbours, day markers, negatives |
| `model.py` | the architecture of design section 4 |
| `training.py` | losses, optimiser step, epoch loop — separate so the model is unit-testable without a loop |
| `output.py` | the three Parquet files and the manifest of design section 8 |

Implemented against `docs/dev/design/world-model.md`. Two things that document treats as load-bearing and this code enforces
rather than assumes: labels, `attack`, `recon_error` and `split` never enter the forward pass, and `cross_day_memory`
fails closed with no override.
"""
