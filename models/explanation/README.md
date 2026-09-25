# `models/explanation` — why the system said what it said

## Purpose

Answer, for any alert, the two questions an analyst actually asks. The problem statement requires explainability, and
the context encoder was already computing one half of the answer and discarding it.

## Function

**1. "Why this host?" — attention activations.** The context encoder attends over up to 20 neighbouring events, being
the latest event per distinct peer of each endpoint. Its attention distribution says how much of this event's context
came from each of them. This is a real activation of the trained model, not a post-hoc surrogate fitted afterwards.

The distribution was being thrown away (`need_weights=False`). It is now capturable with `encoder.explain = True`.

**2. "Was it the flow itself, or its context?" — input attribution.** The detector reads a 132-wide vector: 32 columns
from the flow embedding, 100 from the context encoder. Gradient × input over the standardised features, summed across
each span, says which half carried the decision. Signed, because a span can argue *for* benign.

## Files

| file | role |
|---|---|
| `__main__.py` | CLI shim |
| `attention.py` | `attention_over_batch`, `top_neighbours`, `explain_events`, `input_attribution` |

## Running

```bash
uv run python -m models.explanation \
  --block8 data/model_cache/block8_10d/best.pt \
  --day Friday-02-03-2018 --family Bot --events 3000000 \
  --attacks-only --explain 25 --neighbours 3
```

Output is one row per (event, reported neighbour), carrying the neighbour's attention share, its age in seconds, its
role (whether it was reached as sender or receiver) and its label.

## Notes

**Enabling explainability cannot change a verdict.** Capture is opt-in and verified to leave the encoding
bit-identical. The default keeps `need_weights=False`, which lets the fused attention kernel skip materialising the
weights at all, so training pays nothing.

**An empty neighbourhood produces meaningless weights.** An event with no neighbours is made to attend a dummy slot
whose contribution is then zeroed. `valid` is returned alongside the weights and `top_neighbours` reports `-1` for those
slots rather than presenting padding as evidence. Reporting them would be inventing an explanation.

**Attribution is a local linearisation, not a causal claim.** It says what this particular row's score was most
sensitive to, not what would happen under intervention.

**Do not attach a seconds figure to anticipation in any interface.** Detection can be presented with its threshold and
alarm rate. Anticipation should be presented as a ranked "what may be coming" list with no time claim, because the lead
the data contains cannot currently be scored — see `models/data/README.md`.
