# `models/explanation` — why the system said what it said

Answers, for an alert or a forecast, the questions an analyst asks. Every explanation is read from the trained model's
own activations or gradients, not from a separate model fitted afterwards.

| question | answer | source |
|---|---|---|
| which recent events made the context encoder see this event the way it did? | its attention over the event's neighbourhood | `attention.py` |
| did the verdict come from the flow itself or from its context? | gradient × input over the detector's 132 inputs, summed over the flow span (32) and the context span (100), signed | `attention.py` |
| why is the forecast starting from this host? | the world model's neighbourhood attention for each forecast seed, summed per peer host | `world_model.py` |

The world model's explanation is served in `GET /forecast` as `explanation`
([docs/serving.md](../../docs/serving.md#3-the-forecast-api)).

## Files

| file | role |
|---|---|
| `__main__.py` | command line |
| `attention.py` | `attention_over_batch`, `top_neighbours`, `explain_events`, `input_attribution` |
| `world_model.py` | `seed_explanations` |

## Running

```bash
# the context encoder's attention, for attack events of one day
uv run python -m models.explanation --context-encoder <run>/b8det/best.pt --head <run>/detector/head_<day>.pt \
  --day <day> --attacks-only --explain 25 --neighbours 3 --out <folder>

# the world model, on a recorded day
uv run python -m models.explanation --world-model <run>/b10/best.pt --latents <run>/latents/<day> \
  --node-index data/events/<day>/node_index.parquet --events 20000 --explain 5
```

The output has one row per (event, reported neighbour): the neighbour's share of the attention, its age in seconds,
whether it was reached through the sender or the receiver, and its label.

## Notes

- **Explaining never changes a verdict.** Capturing the attention weights leaves the encoding bit-identical; it is off
  by default so training does not pay for it.
- **An event with no neighbours has no attention explanation.** Such rows are marked (`valid`, and `-1` in
  `top_neighbours`) rather than presenting padding as evidence.
- The world model's global readout describes the whole network, not one seed, so it is not reported per seed.
- **Attribution is a local sensitivity, not a causal claim**: it says what this row's score responded to most, not what
  would happen under an intervention.
- Anticipation is presented as a ranked list of what may come next, with no time in seconds attached.
