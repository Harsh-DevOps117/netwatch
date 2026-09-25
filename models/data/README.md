# `models/data` — shared input plumbing

## Purpose

Everything that reads the event stream and turns it into tensors. Not a pipeline stage: no model lives here, and
nothing in this package trains. It exists so that every stage observes a flow the same way.

## Function

- Load a day's packets, aggregates and flow records into aligned arrays.
- Apply the **observation budget**: restrict every flow to the packets visible within 10 ms of its first packet.
- Assign train / validation / test.
- Batch variable-length packet sequences.

## Files

| file | role |
|---|---|
| `inputs.py` | loads packet and aggregate arrays; `normalise()` fits and applies the input scaler |
| `prefix.py` | `observe()` — the 10 ms budget, `t_obs`, and the observation population |
| `splits.py` | `segment_split()` — the train/val/test cut |
| `batching.py` | padded packet batches |

## The observation budget

`observe()` sets `t_obs = min(first_packet + budget, flow_end)` and records an **observation population** per event:

- `early_observation` — the flow was still running when the budget expired, so the decision is genuinely early.
- `completed_before_budget` — the flow had already finished, so nothing was predicted ahead of time.

**These must never be pooled.** Only `early_observation` supports any lead-time claim. Every report in this repository
splits them.

## Which split mode

`python -m models.data.splits` prints per-family coverage for every ingested day and **exits non-zero if any family is
missing a split**. Run it before training.

| mode | measured on the five ingested days |
|---|---|
| `stratified` | complete: every family reaches train, val and test |
| `segment` | 2 family/day pairs with **no validation rows at all** |
| `chronological` | **all 9** family/day pairs missing a split |

`segment` cuts at a fraction of each segment's clock, which starves a family two ways. A segment under 1,200 s has a
validation band narrower than the 120 s embargo, so Friday-23's 780 s window left SQL Injection with zero validation
rows. And DoS-Hulk's 1,843,441 rows all fall in the first 802 s of a 2,040 s window, so a cut at 60% of the clock put
every one of them in train. `stratified` cuts by **rank within each family**, which fixes both: Hulk's validation went
0 → 184,344, SQL Injection's 0 → 7, Infiltration's 59 → 3,600.

A family missing from a split is invisible in every metric computed afterwards and nothing else notices, which is why
the report returns an exit code rather than only printing.

## How the split works, and its consequence

`segment_split()` cuts 60/10/30 **inside every attack window and every benign stretch separately**. A whole-day time
split puts every attack in train — on both verified days the 60% boundary falls after the last attack window, leaving
validation and test with no attack at all — so the per-segment cut is what gives every split attack rows.

The consequence has to be understood before using it: because each segment is cut independently, **the splits
interleave in wall-clock time**. On the Bot day, 1,677,561 of 1,680,628 test benign rows occur before the latest train
attack. That is harmless for detection, which scores a row that is itself an attack, but it invalidates any
"will this host attack later" target, because training has seen that host attacking at a later real-world time. See
section 8 of `docs/DEPLOYMENT_RUNBOOK.md`.

## Notes

`normalise()` fits its statistics on the sampled training rows, which depend on the caller's day selection, sample size
and seed. Those statistics are part of the model: a checkpoint reloaded beside different statistics scores on a
different scale. `models/flow_encoder` therefore stores them inside its checkpoint.
