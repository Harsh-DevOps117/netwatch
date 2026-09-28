---
license: mit
library_name: pytorch
pipeline_tag: tabular-classification
tags:
  - netwatch-v1.0.0
  - network-intrusion-detection
  - anomaly-detection
  - cybersecurity
  - graph-neural-network
---

# NetWatch Flow Cascade — v1.0.0

| version | released | training run | contents |
|---|---|---|---|
| **v1.0.0** | 2026-09-28 | `20260926-2337` | detector (5 day heads, 0.01% false-alarm budget per family), flow, detection, forecasting and record encoders, compressor, world model epoch 5 (`lag` serving tag) |

The world model is under revision (see [The world model](#the-world-model)); its replacement will ship as v1.1.0 in this
repository, under the same file names. Pin a version with `revision="v1.0.0"`.

Names the attack family behind a network flow from the packets visible in its **first 10 milliseconds**, rather than
after the flow has finished and its full statistics are known.

Trained on CSE-CIC-IDS2018. Each stage is frozen before the next reads it; gradients never cross a stage boundary.

| file | stage | what it does |
|---|---|---|
| `flow_encoder.safetensors` | flow encoder | 32-wide embedding of a flow's early packets, no network context |
| `context_encoder.safetensors` | detection encoder | context encoder for the detector: per-link GRU memory + attention over each endpoint's recent distinct peers |
| `world_model_context_encoder.safetensors` | forecasting encoder | the same design, trained separately, whose link memory also reads flow records |
| `record_encoder.safetensors` | record encoder | frozen encoder that turns a flow record into the forecasting encoder's record message |
| `compressor.safetensors` | compressor | squeezes the forecasting encoder's context to 32 dimensions, keeps the reconstruction error |
| `detector.safetensors` | detector | names the family; **holds the feature scaler**. The head the inference endpoint serves |
| `detector_<day>.safetensors` | detector | every head, one per training day; each knows only its own day's families |
| `world_model.safetensors` | world model | per-host memory over the latent stream; forecasts which host a campaign reaches next |
| `live_compressor.safetensors`, `live_world_model.safetensors` | compressor, world model | when present: the same pair trained on the detection encoder's context, for forecasts seconds behind the traffic rather than ~150 s |
| `<stage>.config.json` | — | class order, layer widths, and the operating point — everything that is not a tensor |

**Weights are safetensors, not `.pt`.** `torch.load` executes arbitrary code while unpickling, so a public model
published as a pickle asks every consumer to trust the uploader. safetensors stores tensors and nothing else and
memory-maps them. The consequence is that a stage is **two files**: the tensors, and the `config.json` carrying the class
order, widths and threshold. They are useless apart — the config names the shapes the tensors must have, and the tensors
mean nothing without the scaler and the class order. Upload both.

## Serving

`handler.py` is a Hugging Face Inference Endpoints handler. It scores **pre-extracted features**: the 132-wide vector
formed by the flow embedding (columns 0–31) followed by the context vector (columns 32–131).

```python
from inference import Detector

detector = Detector(".")
detector.decide(features)      # -> predicted class, per-class probabilities, and the alert verdict
detector.info()                # -> families, feature width, the committed threshold
```

Request shape for the endpoint:

```json
{"inputs": [[0.12, -0.4, ...]]}     // one row per event, 132 floats each
{"inputs": "info"}                   // what this checkpoint is
```

Feature extraction is **not** in the endpoint: it needs packet capture and a stream of every flow's history. The
repository runs the whole chain on live traffic, from packets to verdict about 31 ms after a flow's first packet:
`python -m models.serving.detect_live --interface <iface>`.

## The world model

`world_model.safetensors` is a TGN-style temporal graph model that reads the compressor's 32-wide latent per event. It
keeps a memory vector per host, attends over each host's recent peers, and has two heads: **next-event** (does this pair
interact next; its error is the surprise score) and **ranking** (which active host a campaign reaches next). Rolled
forward without observations, it produces the forecast graph `S[t] → S[t+k]`.

**It is not served by `handler.py`.** It is stateful: memory advances with every event in stream order and resets per
day, so it cannot score an event on its own. Run it with the repository's code, which reads the same weights:

```bash
# the repository's loaders read .pt; rebuild it locally from the downloaded safetensors (bit-exact)
uv run python tools/publish/to_safetensors.py world_model.pt --to-pt world_model
uv run python -m models.world_model.service --load world_model.pt --latents <day latents> --node-index <node_index.parquet>
# GET http://localhost:8900/forecast   -- observed links, predicted links with alternatives, threshold, explanation
```
`model.memory` and `model.last_seen` in the file are per-day runtime state, not weights; they are reset before scoring.

**Calibration, honestly.** `world_model.config.json` carries `score`, `direction`, `budget`, `thresholds` and
`serve_threshold`, fitted on benign validation traffic at a 1e-4 budget, with the recall measured there on test data
(`serve_threshold.recall`). The published checkpoint (epoch 5) serves `target_probability` at threshold 0.99148:
on test it catches **0.78%** of attack events with 1,070 false alarms (0.016%, 65 an hour, 3.8 false incidents an
hour). Use the detector for alerts and the world model for forecasting and explanation.

**Status: under revision.** The forecasts' path probabilities are not calibrated (paths shown at 70–100% came true
about 24% of the time), so show forecasts as a ranked list of hosts. A corrected world model (time handling, memory
update, next-new-victim ranking) is being trained; it will replace this file under the same name and format of use.

**Explanation.** For each forecast seed, the peers the model attended to most (its own neighbourhood attention, not a
surrogate) are returned as `explanation`. The global readout describes the whole network and is not reported per seed.

**Match the stages.** Each stage was trained on the frozen output of the one before. The world model is only valid
behind the exact flow encoder, forecasting encoder, record encoder and compressor published beside it; the live pair
only behind the flow encoder and the detection encoder (`context_encoder`).

## Two things that will silently produce wrong scores

**The scaler is part of the model.** `detector.safetensors` carries the training mean and standard deviation, and
`inference.py` applies them. Standardise differently and every score lands on another scale, which makes every threshold
meaningless.

**A threshold belongs to one trained model.** The operating point lives in `detector.config.json` under
`serve_threshold`: one threshold per family, at a 0.01% false-alarm budget on benign calibration rows. Retrain and it is void, not merely stale. `decide()` returns `alert: null` rather than guessing when
no threshold has been committed.

## Decisions the caller still owns

The endpoint scores one event. Alert volume is governed by two rules applied across events on the same host, and they
matter more than the model:

1. **Persistence** — require 3 consecutive events above threshold on one host. Halves false alarms at no cost to recall.
2. **Incidents** — collapse alerts on one host with no quiet gap longer than 60 s into a single incident.

Measured together: thousands of alerts an hour become tens of incidents an hour.

## What it does not claim

- **Not cross-day, and not unseen attackers.** Reported numbers are within-day: train and test come from the same day's
  traffic.
- **No anticipation claim in seconds.** The data contains lead before a host's first attack, but it cannot be scored
  with the split used, which interleaves in wall-clock time.
- **Alarm rates are conditioned on the slice they were measured on.**
- **The world model is not a detector** unless its calibrated `serve_threshold.recall` says so, and it predicts no
  MITRE stage.

## Licence and attribution

Code MIT. Trained on CSE-CIC-IDS2018 from the Canadian Institute for Cybersecurity, whose terms require attribution and
govern redistribution of anything derived from it. Cite the dataset in any work using this model.
