<!-- BEGIN GENERATED: front matter and inventory, rewritten by tools/publish/huggingface.py -->
---
license: other
license_name: cse-cic-ids2018
license_link: https://www.unb.ca/cic/datasets/ids-2018.html
gated: true
task_categories:
  - tabular-classification
tags:
  - network-traffic
  - intrusion-detection
  - cybersecurity
configs: []
---

| set | portion | config to load | days | size |
|---|---|---|---|---|
| _empty until staged_ | | | | |
<!-- END GENERATED -->

# NetWatch — CSE-CIC-IDS2018 as an event stream

CSE-CIC-IDS2018 rebuilt as a **continuous-time event stream**: one row per network flow, ordered by the microsecond at
which it became observable, with every flow cut to the first **10 milliseconds** of its life. Time is never binned.

It is published as **two sets, chosen independently**, so nobody downloads six gigabytes of embeddings to read labels.

## Set 1 — `processed`: model-agnostic

The event stream and the per-flow tables. Useful with any model, including one that has nothing to do with this project.

| portion | config | what it is |
|---|---|---|
| `events` | `processed_events` | the labelled event stream: times, endpoints, labels, splits, plus the per-day ip → node id index |
| `flow_records` | `processed_flow_records` | CICFlowMeter's own 69 columns per event, at the earliest time that record could exist |
| `side_features` | `processed_side_features` | per-event request/response features at the observation time, and who sent which side |

## Set 2 — `model`: produced by this cascade

Learned representations. These are only meaningful with the model that produced them — see the companion model
repository.

| portion | config | what it is |
|---|---|---|
| `flow_embeddings` | `model_flow_embeddings` | a 32-wide embedding per flow from its early packets, **no network context** |
| `latents` | `model_latents` | a 32-wide latent `z` summarising each event's network context, plus `recon_error` |

Every table ships with the JSON manifest that records which checkpoint produced it. **Two files whose manifests disagree
are on different scales and must not be mixed**, however similar their configuration looks.

## Loading

Each day is a split, so you can take one day without fetching the rest.

```python
from datasets import load_dataset

events  = load_dataset("<account>/<repo>", "processed_events",  split="Friday_02_03_2018")
latents = load_dataset("<account>/<repo>", "model_latents",     split="Friday_02_03_2018")
```

Or read the parquet directly, which is usually what you want for a table this wide:

```python
import pyarrow.parquet as pq
from huggingface_hub import hf_hub_download

path = hf_hub_download("<account>/<repo>", "model/latents/Friday-02-03-2018/event_latents.parquet",
                       repo_type="dataset")
table = pq.read_table(path)
```

## What one row is

One flow, observed for 10 ms from its first packet. Key columns, shared across sets:

| column | meaning |
|---|---|
| `event_id` | the row's identity; joins every table in both sets |
| `t` | the flow's first packet, epoch seconds |
| `t_obs` | when the decision had to be made: `min(t + 0.010, flow end)` |
| `sender_node_id`, `receiver_node_id` | endpoints, keyed on the flow's **first captured packet**, not the record's src/dst |
| `observation_population` | `early_observation` or `completed_before_budget` — see below |
| `split` | 0 train, 1 validation, 2 test, -1 inside an embargo gap |
| `label`, `attack` | ground truth. **Evaluation only** |

Set-specific: `flow_embeddings` adds `h`; `latents` adds `z` and `recon_error`.

### Two populations, never pooled

| population | meaning |
|---|---|
| `early_observation` | the flow was still running when the budget expired, so a decision here is genuinely early |
| `completed_before_budget` | the flow had already finished; nothing was predicted ahead of time |

Only the first supports any claim about acting early. Pooling them is the most common way to overstate a result on this
data, which is why the column exists rather than being dropped after slicing.

### Columns that must never be an input

`label` and `attack` are ground truth for scoring. So is anything describing a flow's **full** duration: at 10
milliseconds that information does not exist yet, so using it is leakage rather than a feature. The `flow_records`
portion is the place to be careful — it carries CICFlowMeter's complete-flow statistics, and it is included so the
10 ms-budget setting can be compared against the conventional one, not so both can be fed to the same model.

## Splits interleave in wall-clock time

Train, validation and test are cut **inside every attack window and every benign stretch separately**, so each split
contains attack rows; a whole-day cut leaves validation and test with none.

The consequence has to be understood before using them. Because each segment is cut independently, the splits interleave
in real time: on one measured day, **1,677,561 of 1,680,628 test benign rows occur before the latest train attack**. That
is harmless for detection, which scores a row that is itself an attack. It makes any "will this host attack later"
target unsound, because training has already seen that host attacking at a later real-world time. Use cross-day holdout
for that question.

## Node ids are per day

`sender_node_id` and `receiver_node_id` are assigned by first appearance **within a single day**, so the same host is a
different integer on another day. Do not join them across days, and do not carry per-host state between days without
remapping through each day's `node_index`.

## Licence and attribution

Derived from **CSE-CIC-IDS2018**, distributed by the Canadian Institute for Cybersecurity, whose terms govern
redistribution and require attribution. This repository is gated for that reason. Cite the original dataset in any work
that uses these files.
