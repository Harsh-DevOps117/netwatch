# `models/serving` — running the models on traffic

What a live process needs beyond the offline pipeline: live detection, the graph built incrementally, every stage chained
in memory, the alert rules, and the world model's forecast services with their serving tags. Nothing here is trained. How the services work
and how to run them: [docs/serving.md](../../docs/serving.md).

## Files

| file | role |
|---|---|
| `graph.py` | `NodeRegistry`, `LinkRegistry`, `OnlineNeighbours`, `LastSeen`, `ReorderBuffer` — the online versions of the offline graph structures |
| `detect_live.py` | fast live detection: packets → CICFlowMeter's flows → each flow scored 10 ms after its first packet by the flow encoder, the streamed detection encoder and every detector head → persistence and operator-facing incidents in `GET /detections`; with `--forecast`, the world model on the same stream → `GET /forecast` (tag `live`, seconds behind); checked by `tools/live/detect_check.py` |
| `cascade.py` | the detection encoder and detector (optionally the compressor) loaded once and chained in memory: an event's features in, a verdict out |
| `emitter.py` | `AlertEmitter` (threshold → persistence → incidents) and `Recalibrator` |
| `live.py` | the world model on this machine's traffic: capture files → complete flows → encoders → world model → `GET /forecast` (tag `lag`, ~150 s behind the wire) |
| `registry.py` | `serving.json`: which models serve each world-model tag, and whether that tag may serve |
| `parity.py` | the tolerance test: a serving path compared stage by stage with the training ingest |

## Online graph structures

Live detection and lag forecasting default to one CPU inference thread each;
`--threads N` overrides this when benchmarking a larger machine. This keeps
small detection calls from competing with forecasting for every CPU core.
Detection batches completed-flow aggregates and all families' incident writes,
and capped link memory uses a reverse residency map to avoid allocating a
matrix across all historical links when new attack sources arrive. Model
weights, thresholds, observation windows and persistence rules are unchanged.

Measure throughput locally without transmitting traffic:

```bash
uv run python -m tools.measure.detection_latency --events 4096 --unique-hosts --force-alerts
```

The benchmark uses temporary databases and reports batch-processing p50/p90,
not live capture latency. `/detections` reports capture-to-verdict `p50`, `p90`
and `p99` (and the existing `median`), queue depth and `inference_threads`.
Restart running model services after updating these files. Under sustained
traffic above the machine's processing capacity, the lossless packet queue
can still grow; compare queue depth and live latency with this measured
throughput when sizing the deployment.

The offline pipeline builds its graph structures from a finished day. A live stream needs incremental equivalents:

| offline | online |
|---|---|
| node ids by first appearance within a day | `NodeRegistry` |
| link ids from the whole day's pairs | `LinkRegistry` |
| `NeighbourIndex` over the whole stream | `OnlineNeighbours` (matches it event for event) |
| time since last seen, per host | `LastSeen` |
| sorting a finished day by `(t_obs, event_id)` | `ReorderBuffer` |

## The cascade

```python
from models.serving.cascade import Cascade

cascade = Cascade(detector="<run>/detector/head_<day>.pt", context_encoder="<run>/b8det/best.pt", capacity=0.25)
cascade.reset(links=n_links)
verdict = cascade.decide(features, keys=senders, times=t_obs)
```

A folder holding `detector.pt` and `context_encoder.pt` can be passed instead of the paths. The compressor is optional
and only adds `z` for the world model; the detector never reads it, and it must be paired with the forecasting encoder
it was trained on (`<run>/b8/best.pt`), not the detection encoder.
The cascade takes precomputed features (the flow encoder's `h` and the event inputs). The context encoder keeps link memory and neighbourhoods across calls, so one instance serves one stream; `reset()`
starts another.

## Alert rules

```python
from models.serving.emitter import AlertEmitter

emitter = AlertEmitter(threshold, persist=3, gap=120.0)
for incident in emitter.push_batch(keys, scores, times):
    publish(incident)
emitter.rates(hours)          # events, alerts and incidents, and their rates per hour
```

1. **Threshold** — the family's own committed threshold (`serve_threshold` in the detector head, 0.01% budget), or,
   with the live detector's `--budget`, its stored threshold at that budget.
2. **Persistence** — 3 consecutive events above threshold on the same host; any event below resets the count.
3. **Incidents** — alerts on one host with no quiet gap longer than 120 s form one incident.

Windows live detection defaults to Npcap immediate capture (`--capture-mode auto`), streaming the original packet
bytes and timestamps through the same tshark dissectors and ingest parser. This avoids quiet-link driver buffering;
it does not sample traffic or shorten the trained 10 ms observation window. If Npcap cannot initialize, `auto`
falls back to tshark and reports the reason in `/detections.capture`; `--capture-mode immediate` requires it,
and `--capture-mode tshark` selects the legacy path. File replay is unchanged. The API exposes capture counters
and `latency_stages_s.packet_delivery` / `scoring_batch` alongside end-to-end latency. Quantiles cover the last
10,000 samples; batch-scoring quantiles are per batch, while end-to-end quantiles are per flow.

The CLI/dashboard applies a separate operator suppression layer **after** the model heads and persistence.
Infiltration's internal-service rule is retained; web-request families now also recognize routine internal DNS
questions and established internal registered TCP services other than HTTP/HTTPS, plus corroborated HTTPS
server responses to local ephemeral client sockets. OS TCP evidence is sampled once a second outside inference
and expires after three seconds; bare SYNs cannot be treated as responses. DNS evidence requires a parsed ordinary
question (TXT/ANY, fragments and truncated questions remain visible). This does not declare all private traffic
benign: missing evidence, mixed peers/services, service fanout, source buckets exceeding 250 packets in a second,
or more than 20 crossings within one second retain the incident. Bot and external Infiltration remain visible even
on established HTTPS connections. Ephemeral response ports do not count as service-port scans. Active decisions
are rechecked every two seconds as evidence grows. Raw incidents, scores and linked evidence remain available
separately, and neither checkpoint calibration nor the three-event / 120-second emitter settings changes.
Low-rate GigE Vision discovery is also recognized: only a validated eight-byte `DISCOVERY_CMD` from a private
IPv4 host to `255.255.255.255:3956` qualifies, with a tighter maximum of ten source packets in a one-second bucket.
Arbitrary port-3956 payloads, camera control commands, unicast requests and discovery floods remain visible.
These rules reduce specific operational false alerts; they are not a measured improvement in labeled model FPR.

Live capture may opt into `--adaptive-thresholds`. Each family then learns a live score quantile after a 128-event
warm-up while keeping the checkpoint threshold as a hard floor. The effective threshold, baseline, sample count and
effective budget are returned by `GET /detections`. This assumes the learning window is mostly benign; do not enable
it for attack-heavy replays because an unsupervised live quantile cannot distinguish drift from a sustained attack.

For a persistent four-hour live threshold operating point, start both `models.serving.detect_live` and `models.serving.live`
with `--live-calibration-hours 4 --calibration-db <service-specific SQLite path>`; `tools/run_windows.ps1` enables
this for both services. Each scored flow is stored once across overlapping world-model rebuilds. A gap longer than
ten minutes restarts the continuous observation window; a checkpoint change invalidates stored scores. Until the
window and the per-model sample minimum are complete, the world model retains its checkpoint threshold and the
detector retains its checkpoint threshold. Do not combine fast-adaptive thresholds with the gated live window.
Afterwards, each family and the world model use
their own live score-tail quantile, with the checkpoint threshold as a floor. The API exposes readiness, elapsed
time, sample counts, baseline, served threshold and target score-exceedance budget. There are no labels in this
traffic: score exceedance is **not** a measured false-positive rate, and test recall/FPR are checkpoint results,
not validation of the live threshold. Review any incident-volume changes and use labeled review before claiming
an improved false-alarm rate. A sustained attack can contaminate an unsupervised quantile. This process does not fit
probabilities; the checkpoint weights, scaler, and score mapping remain unchanged.

The dashboard's detector and world-model operating-point selectors default to **Original checkpoint**. They keep
collecting live scores in the background, but a four-hour live threshold is only selectable once the complete window
is ready (all detector families for detection). The selection is stored locally in separate mode files and survives
service restarts. If collection loses readiness, the effective threshold safely falls back to the checkpoint even
when the saved preference is live. `POST /threshold-mode` on each local model service accepts
`{"mode":"checkpoint"}` or `{"mode":"live"}`; `GET /threshold-mode` reports requested/effective mode and readiness.
Changing the mode affects subsequent detector events or the next world-model forecast cycle, not historical alerts.

On the Bot day's test split (run of 2026-09-26, 0.01% budget) these rules turn 14,709 events per hour above threshold
into 6.3 incidents per hour, with all 13 attacking hosts alerted (`python -m models.evaluation`).

## Notes

### Offline PCAP dashboard

The local dashboard serves `/offline` (PCAP analysis in the sidebar). Upload a completed `.pcap` or `.pcapng` file, up to 128 MiB. `POST /api/offline/jobs` accepts multipart field `file` and returns a job ID; `GET /api/offline/jobs/{id}` reports progress and the final result. Jobs run one at a time with a 30-minute limit. Input, stage outputs, log, and result remain under `artifacts/runtime/offline/{id}` until removed by the operator. The server is bound to localhost; treat captures and results as sensitive.

The detector uses `detect_live --pcap --once` with original checkpoint thresholds and includes only incident-linked event details. The world model uses the `lag` registry checkpoints on all complete flows in the file and reports observed incidents separately from hypothetical `S[t+k]` event-step links. Both paths are unlabeled, use separate job files, and never update live calibration or live incident history. A short capture or one without packet-backed flows may yield a detector result but no world-model result; the page reports each failure independently. Offline forecast scores are not calibrated probabilities, and an event step is not a time ETA.

Windows CICFlowMeter can emit naive local-clock timestamps while tshark emits packet epochs. Offline analysis corrects the meter timestamp only when matching flow keys consistently establish a timezone-sized offset; the reported source includes `meter_clock_offset_corrected_s`.

- **Push events in availability order.** Persistence counts consecutive events, so any other order changes the answer.
- **Persist the registries.** Node and link ids are identity; a restarted process that loses them renumbers every host
  and starts every link memory cold. `save()` and `load()` exist for this. A host evicted and seen again gets a fresh
  id, never another host's.
- **`ReorderBuffer(delay)`** must be larger than the longest gap between a packet arriving and its event's `t_obs`;
  releasing earlier feeds the context encoder an out-of-order stream without raising an error.
- **`Recalibrator`** keeps a reservoir sample across everything seen plus the most recent rows, and reads the threshold
  quantile from both, so a threshold is not fitted to one recent stretch of traffic.
