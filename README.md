# NetWatch — early network intrusion detection and forecasting

NetWatch reads network traffic and answers two questions:

- **Detection:** is this flow an attack, and which kind? Decided **10 milliseconds** after the flow's first packet,
  while the connection is still open — not after it has finished and its full statistics are known.
- **Forecasting:** given what the network is doing, which host is a campaign likely to reach next? A world model keeps a
  running state of every host and rolls it forward.

It is built and evaluated on CSE-CIC-IDS2018, from the raw packet captures.

## How it works

![NetWatch architecture: ingest, the flow encoder, the detection encoder with the detector, the forecasting encoder (which also reads flow records), the compressor and the world model, each drawn as its layers; the compressor and world model are trained a second time on the detection encoder's output for the live serving tag](docs/diagrams/overview.svg)

Each stage is trained separately and frozen before the next one is trained on its output. Time is never cut into fixed
windows: one event per flow, processed in the order its information became available, so no decision ever uses
information that did not exist yet. The full design, stage by stage, is in [docs/architecture.md](docs/architecture.md).

## Results so far, and their limits

**Detector** — training run of 2026-09-26: one head per day, scored on that day's own test split, at a **0.01%
false-alarm budget**. Each family has its own threshold: the 99.99th percentile of its scores on benign calibration rows
(validation plus 20% of training, never test). The rows below are the flows still open at 10 ms (`early_observation`);
false alarms are benign test flows of that population above the family's threshold, and the rate per hour is over the
test split's own duration (2.8–3.7 h per day).

| day | family | threshold | test attacks | recall | precision | false alarms | false-alarm rate | per hour |
|---|---|---|---|---|---|---|---|---|
| Friday-16-02-2018 | DoS-Hulk | 0.787 | 256,734 | 0.9986 | 0.9998 | 45 of 736,520 | 0.0061% | 16.2 |
| Friday-02-03-2018 | Bot | 0.440 | 46,463 | 0.9905 | 0.9978 | 103 of 1,115,611 | 0.0092% | 29.7 |
| Thursday-15-02-2018 | DoS-GoldenEye | 0.125 | 7,938 | 0.9999 | 0.9935 | 52 of 330,656 | 0.0157% | 14.1 |
| Thursday-15-02-2018 | DoS-Slowloris | 0.750 | 2,653 | 0.8839 | 0.9433 | 141 of 330,656 | 0.0426% | 38.2 |
| Thursday-01-03-2018 | Infiltration | 0.793 | 2,139 | 0.7737 | 0.9533 | 81 of 1,145,074 | 0.0071% | 24.9 |
| Friday-23-02-2018 | Brute Force -Web | 0.672 | 34 | 0.9412 | 0.1928 | 134 of 896,078 | 0.0150% | 41.5 |
| Friday-23-02-2018 | Brute Force -XSS | 0.321 | 19 | 0.8421 | 0.1684 | 79 of 896,078 | 0.0088% | 24.5 |
| Friday-23-02-2018 | SQL Injection | 0.203 | 11 | 0.4545 | 0.0685 | 68 of 896,078 | 0.0076% | 21.1 |

The budget is met on calibration rows; on test rows the realised rate ranges from 0.006% to 0.043%. DoS-SlowHTTPTest
flows all end within 10 ms, so it has no early rows (on the completed ones, threshold 0.266: recall 1.0000, 66 false
alarms of 501,778, 0.0132%). The web attacks have too few test events to support a claim. After the alert rules
(3 events in a row per host, 60 s incidents), every family comes to 1.3–6.3 incidents per hour over all test rows, and
the alerting hosts carry 99.7–100% of the DoS, Bot and Infiltration attack events (`python -m models.evaluation`).

**Live.** The detector runs on live traffic and gives a verdict about 31 ms after a flow's first packet (median; 47 ms
at the 99th percentile), reproducing training's inputs and verdicts ([docs/serving.md](docs/serving.md#5-serving-the-detector)).

**World model** — the checkpoint calibrated on 2026-09-25 caught no test attacks at its operating point (recall 0); it
serves forecasts and explanations, not detections. It is being retrained, together with a second world model on the
detection stream that serves forecasts seconds, rather than ~150 s, behind the traffic.

**Not claimed:** every result is within-day (train and test from the same day's traffic); each head knows only its own
day's families and does not transfer to other days' traffic; forecasts carry no time. The data does contain lead — an
attacking host reaches its next new target a median of 32 s (Infiltration) to 80 min (Bot) later
([docs/serving.md §4](docs/serving.md#4-serving-tags)) — but that a world model predicts those targets is not yet shown.

## Quick start

Requirements: Python 3.12 via [uv](https://docs.astral.sh/uv/); for ingest and live serving also `tshark`
(`apt install tshark`) and a JDK 8 for CICFlowMeter. A CUDA GPU is optional.

`tools/setup.sh` does the whole setup once after cloning: `uv sync`; CICFlowMeter, a git submodule pinned at the commit
ingest used, fetched, patched and built by `tools/setup_cicflowmeter.sh`; the published model (release `v1.0.0`) from
Hugging Face into `artifacts/huggingface/download/netwatch-flow-cascade/`, with `artifacts/current` pointed at it so
every serving command serves it. It then asks whether to download the dataset, and which set (`processed`, `model` or
both) and which days; `--dataset none|processed|model|both` answers without asking. The dataset is gated: accept its
terms on Hugging Face and log in first.

```bash
git clone --recurse-submodules https://github.com/Harsh-DevOps117/netwatch && cd netwatch
tools/setup.sh

# self-checks: no dataset and no GPU needed
uv run python -m models.serving.graph
uv run python -m models.serving.emitter
uv run python -m models.serving.cascade
uv run python -m models.serving.registry
uv run python -m models.serving.parity --demo
uv run python -m models.evaluation --demo
uv run python -m models.explanation --demo
uv run python -m tools.repo.verify_contracts
```

Then:

| step | guide |
|---|---|
| prepare the data and train every stage (`tools/train_all.sh`) | [docs/training.md](docs/training.md) |
| run live detection and the forecast services, and read the API | [docs/serving.md](docs/serving.md) |
| publish the models and data to Hugging Face | [docs/publishing.md](docs/publishing.md) |

## Repository layout

| folder | contents |
|---|---|
| [`ingest/`](ingest/README.md) | captures → packets, flows, labels, event stream |
| [`models/data/`](models/data/README.md) | shared inputs, the 10 ms cut, the splits |
| [`models/flow_encoder/`](models/flow_encoder/README.md) | flow encoder |
| [`models/context_encoder/`](models/context_encoder/README.md) | context encoder, side features, flow records |
| [`models/detector/`](models/detector/README.md) | the detector |
| [`models/compressor/`](models/compressor/README.md) | compressor |
| `models/world_model/` | world model (package docstrings; design in [docs/architecture.md §8](docs/architecture.md#8-world-model)) |
| [`models/explanation/`](models/explanation/README.md) | attention and attribution explanations |
| [`models/serving/`](models/serving/README.md) | live detection, forecast services and their tags, tolerance test, online graph, alert rules |
| [`models/evaluation/`](models/evaluation/README.md) | every reported metric |
| [`tools/`](tools/README.md) | training script, publishing, measurement |
| `huggingface/` | the Hugging Face model and dataset cards and endpoint |
| `artifacts/` | git-ignored: every trained model the project serves or publishes (`current/`, `previous/`, `huggingface/`) |
| [`docs/`](docs/README.md) | architecture, data, training, serving, publishing |

## Licence

The code is MIT — see [LICENSE](LICENSE).

**The dataset is not.** CSE-CIC-IDS2018 is distributed by the Canadian Institute for Cybersecurity under its own terms,
which require attribution and govern redistribution. Event streams, embeddings and latents produced here are derived
works of it; check those terms before publishing any of them.
