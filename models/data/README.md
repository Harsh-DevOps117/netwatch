# `models/data` — shared inputs, the 10 ms cut and the splits

Reads the event stream and turns it into arrays, so every stage observes a flow the same way. Nothing here is trained.

## Files

| file | role |
|---|---|
| `inputs.py` | loads packet and aggregate arrays; `normalise()` fits and applies the input scaler; `check_features` refuses forbidden columns |
| `prefix.py` | `observe()`: the 10 ms observation budget, `t_obs` and the observation population |
| `splits.py` | `segment_split()`: train / validation / test, and a per-family coverage report |
| `batching.py` | padded batches of variable-length packet sequences |

## The observation budget

`observe()` sets `t_obs = min(first packet + 10 ms, flow end)` and labels every event with its **observation
population**:

| population | meaning |
|---|---|
| `early_observation` | the flow was still running when the budget ran out: the decision is genuinely early |
| `completed_before_budget` | the flow had already finished: nothing was decided ahead of time |

The two are always reported separately; only the first supports a claim about acting early.

## The split

`segment_split()` cuts 60% / 10% / 30% of **each attack window and each benign stretch separately**, with 120 s left
unused at every boundary, so every split contains every attack family ([docs/data.md](../../docs/data.md#splits)).

Check coverage before training:

```bash
uv run python -m models.data.splits
```

It prints, per day and family, how many rows reach each split, and exits non-zero if a family is missing from one. Very
short attack windows can lose their validation band to the gaps (for example SQL Injection on Friday-23, a 780 s
window).

**Consequence to keep in mind:** because each segment is cut on its own, the splits interleave in wall-clock time. That
is sound for detection, which scores a row that is itself an attack, but not for a question like "will this host attack
later", where training may already have seen the host attack at a later time. Use cross-day evaluation for that.

## Notes

- `normalise()` fits its statistics on the rows the caller passes — the flow encoder passes its benign training rows;
  those statistics are part of the model and are stored in each checkpoint that uses them.
- Labels, attack flags and split codes are never model inputs. `check_features` refuses any identity, label or clock
  column in a feature tensor; the attack flag and the split code stay outside the feature arrays and only select rows.
