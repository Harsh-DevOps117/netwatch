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
datasets:
  - kaustuk000/netwatch-ids2018-events
metrics:
  - precision
  - recall
  - f1
---

# NetWatch Flow Cascade

**Release v1.0.0** · 2026-09-28 · MIT licence ·
[code](https://github.com/Harsh-DevOps117/netwatch) ·
[dataset](https://huggingface.co/datasets/kaustuk000/netwatch-ids2018-events)

NetWatch names the attack family behind a network flow from the packets visible in its **first 10 milliseconds**, while
the connection is still open, and forecasts which hosts an attack campaign is likely to reach next. This repository
holds the complete model cascade of release v1.0.0: the detector, its encoders, and the world model that produces the
forecast.

Trained on CSE-CIC-IDS2018. Each stage is trained separately and frozen before the next one reads it; gradients never
cross a stage boundary.

## Quick start

The model is open: no account or access request is needed. You need `git`, `uv` and a JDK 8 on the machine.

**1. Install.** This is the step that downloads from Hugging Face.

```bash
git clone https://github.com/Harsh-DevOps117/netwatch && cd netwatch
tools/setup.sh --dataset none
```

| command | what it does | what it downloads from Hugging Face |
|---|---|---|
| `git clone …` | fetches the code from GitHub | nothing |
| `tools/setup.sh --dataset none` | builds the Python environment and CICFlowMeter, fetches this model, rebuilds its checkpoints as `.pt` (bit-exact) and points `artifacts/current` at them | this repository at `v1.0.0`: 30 files, 4.5 MB (the safetensors weights, their configs and the serving code), into `artifacts/huggingface/download/netwatch-flow-cascade/` |

`--dataset none` skips the dataset. With `--dataset processed`, `model` or `both`, the same command also downloads
[kaustuk000/netwatch-ids2018-events](https://huggingface.co/datasets/kaustuk000/netwatch-ids2018-events): about 5 GB,
8 GB or 13 GB. That repository is gated, so accept its terms on its page first and log in when the command asks.

**2. Run.**

```bash
./start-netwatch.sh
```

Starts packet capture, the detection service and the forecast service on the active network interface, then opens the
CLI. After step 1 it downloads nothing from Hugging Face. Run on its own, without step 1, it fetches the same 4.5 MB
model first. It never downloads the dataset.

To fetch only the weights, without the code:

```python
from huggingface_hub import snapshot_download

folder = snapshot_download("kaustuk000/netwatch-flow-cascade", revision="v1.0.0")
```

## Results

Detector, training run `20260926-2337`: one head per day, scored on that day's own test split, on the flows still open
10 ms after their first packet. Each family has its own threshold, set for a **0.01% false-alarm budget** on benign
calibration traffic (validation plus 20% of training, never test).

| family | day | test attacks | precision | recall | F1 | false alarms | false-alarm rate |
|---|---|---|---|---|---|---|---|
| DoS-Hulk | Friday-16-02-2018 | 256,734 | 0.9998 | 0.9986 | 0.9992 | 45 of 736,520 | 0.0061% |
| DoS-GoldenEye | Thursday-15-02-2018 | 7,938 | 0.9935 | 0.9999 | 0.9967 | 52 of 330,656 | 0.0157% |
| Bot | Friday-02-03-2018 | 46,463 | 0.9978 | 0.9905 | 0.9941 | 103 of 1,115,611 | 0.0092% |
| DoS-Slowloris | Thursday-15-02-2018 | 2,653 | 0.9433 | 0.8839 | 0.9126 | 141 of 330,656 | 0.0426% |
| Infiltration | Thursday-01-03-2018 | 2,139 | 0.9533 | 0.7737 | 0.8542 | 81 of 1,145,074 | 0.0071% |

- **Alert volume.** With the alert rules below (three events in a row per host, grouped into incidents), every family
  comes to 1.3 to 6.3 incidents per hour, and the alerting hosts carry 99.7 to 100% of the attack events above.
- **Live.** On live traffic the verdict arrives a median of 31 ms after a flow's first packet (47 ms at the 99th
  percentile). One CPU core tracks and scores about 7,800 flows a second.

## What is in the repository

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
| `<stage>.config.json` | all | class order, layer widths, and the operating point: everything that is not a tensor |

**Weights are safetensors, not `.pt`.** safetensors stores tensors and nothing else, so loading them runs no code. A
stage is therefore **two files**: the tensors, and the `config.json` carrying the class order, widths and threshold.
Keep them together: the config names the shapes the tensors must have, and the tensors mean nothing without the scaler
and the class order.

## Intended use

- Early detection of the attack families above on a network's own traffic, from a PCAP file or a live interface.
- Forecasting and explanation: which hosts a campaign is likely to reach next, and which peers drove that forecast.
- Research on CSE-CIC-IDS2018 with a model that reads the first packets of a flow rather than its final statistics.

Thresholds belong to the traffic they were calibrated on. Before alerting on another network, recalibrate them on that
network's benign traffic.

## Serving the detector

`handler.py` is a Hugging Face Inference Endpoints handler. It scores **pre-extracted features**: the 132-wide vector
formed by the flow embedding (columns 0–31) followed by the context vector (columns 32–131).

```python
from inference import Detector       # run inside the downloaded folder

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
repository ([github.com/Harsh-DevOps117/netwatch](https://github.com/Harsh-DevOps117/netwatch)) runs the whole chain,
from packets to a verdict.

## The world model

`world_model.safetensors` is a TGN-style temporal graph model that reads the compressor's 32-wide latent per event. It
keeps a memory vector per host, attends over each host's recent peers, and has two heads: **next-event** (does this pair
interact next; its error is the surprise score) and **ranking** (which active host a campaign reaches next). Rolled
forward without observations, it produces the forecast graph `S[t] → S[t+k]`.

**How to run it.** It is stateful: memory advances with every event in stream order and resets per day, so it cannot
score an event on its own and is not served by `handler.py`. Run it with the repository's code, which reads the same
weights: `tools/setup.sh` fetches this model (rebuilt as `.pt`, bit-exact) and, if asked, the dataset
([kaustuk000/netwatch-ids2018-events](https://huggingface.co/datasets/kaustuk000/netwatch-ids2018-events)).
`model.memory` and `model.last_seen` in the file are per-day runtime state, not weights; they are reset before scoring.

**Role and operating point.** The world model supplies the forecast and its explanation; alerts come from the detector.
`world_model.config.json` carries `score`, `direction`, `budget`, `thresholds` and `serve_threshold`, fitted on benign
validation traffic at a 1e-4 budget. The published checkpoint (epoch 5) serves `target_probability` at threshold
0.99148; on the test split that operating point flags 0.78% of attack events with 1,070 false alarms (0.016%, 65 an
hour, 3.8 false incidents an hour).

**Explanation.** For each forecast seed, the peers the model attended to most (its own neighbourhood attention, not a
surrogate) are returned as `explanation`. The global readout describes the whole network and is not reported per seed.

**Match the stages.** Each stage was trained on the frozen output of the one before. The world model is only valid
behind the exact flow encoder, forecasting encoder, record encoder and compressor published beside it; the live pair
only behind the flow encoder and the detection encoder (`context_encoder`).

## Integration requirements

**The scaler is part of the model.** `detector.safetensors` carries the training mean and standard deviation, and
`inference.py` applies them. Standardise differently and every score lands on another scale, which makes every threshold
meaningless.

**A threshold belongs to one trained model.** The operating point lives in `detector.config.json` under
`serve_threshold`: one threshold per family, at a 0.01% false-alarm budget on benign calibration rows. After a retrain
it no longer applies. `decide()` returns `alert: null` rather than guessing when no threshold has been committed.

## Recommended alert rules

The endpoint scores one event. Alert volume is governed by two rules applied across events on the same host:

1. **Persistence**: require 3 consecutive events above threshold on one host. Halves false alarms at no cost to recall.
2. **Incidents**: collapse alerts on one host with no quiet gap longer than 60 s into a single incident.

Measured together: thousands of alerts an hour become tens of incidents an hour.

## Limitations

- **Within-day evaluation.** Reported numbers are within-day: train and test come from the same day's traffic. They do
  not measure other days, other networks or attackers the training data does not contain.
- **Forecast scores are not probabilities.** Present a forecast as a ranked list of hosts; in testing, paths scored at
  70 to 100% came true about 24% of the time. The forecast carries no lead time in seconds and no MITRE stage.
- **Alarm rates are conditioned on the slice they were measured on.**
- **Web attacks.** The `Friday-23-02-2018` head is published for completeness; its test split has 11 to 34 attack
  events per family, too few to support a claim.

## Versions

| version | released | training run | contents |
|---|---|---|---|
| **v1.0.0** | 2026-09-28 | `20260926-2337` | detector (5 day heads, 0.01% false-alarm budget per family), flow, detection, forecasting and record encoders, compressor, world model epoch 5 (`lag` serving tag) |

Pin a version with `revision="v1.0.0"`.

## Licence and attribution

Code MIT. Trained on CSE-CIC-IDS2018 from the Canadian Institute for Cybersecurity, whose terms require attribution and
govern redistribution of anything derived from it. Cite the dataset in any work using this model.
