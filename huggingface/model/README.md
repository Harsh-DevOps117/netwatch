---
license: mit
library_name: pytorch
pipeline_tag: tabular-classification
tags:
  - network-intrusion-detection
  - anomaly-detection
  - cybersecurity
  - graph-neural-network
---

# NetWatch — flow cascade

Names the attack family behind a network flow from the packets visible in its **first 10 milliseconds**, rather than
after the flow has finished and its full statistics are known.

Trained on CSE-CIC-IDS2018. Each stage is frozen before the next reads it; gradients never cross a stage boundary.

| file | stage | what it does |
|---|---|---|
| `flow_encoder.safetensors` | flow encoder | 32-wide embedding of a flow's early packets, no network context |
| `context_encoder.safetensors` | context encoder | per-link GRU memory + attention over each endpoint's recent distinct peers |
| `compressor.safetensors` | compressor | squeezes the context to 32 dimensions, keeps the reconstruction error |
| `detector.safetensors` | detector | names the family; **holds the feature scaler** |
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

Feature extraction is deliberately **not** in the endpoint: it needs packet capture and CICFlowMeter, which belong in
the sensor.

## Two things that will silently produce wrong scores

**The scaler is part of the model.** `detector.safetensors` carries the training mean and standard deviation, and
`inference.py` applies them. Standardise differently and every score lands on another scale, which makes every threshold
meaningless.

**A threshold belongs to one trained model.** The operating point lives in `detector.config.json` under
`serve_threshold`. Retrain and it is void, not merely stale. `decide()` returns `alert: null` rather than guessing when
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

## Licence and attribution

Code MIT. Trained on CSE-CIC-IDS2018 from the Canadian Institute for Cybersecurity, whose terms require attribution and
govern redistribution of anything derived from it. Cite the dataset in any work using this model.
