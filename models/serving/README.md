# `models/serving` — running the models on traffic

What a live process needs beyond the offline pipeline: live detection, the graph built incrementally, every stage chained
in memory, the alert rules, and the world model's forecast services with their serving tags. Nothing here is trained. How the services work
and how to run them: [docs/serving.md](../../docs/serving.md).

## Files

| file | role |
|---|---|
| `graph.py` | `NodeRegistry`, `LinkRegistry`, `OnlineNeighbours`, `LastSeen`, `ReorderBuffer` — the online versions of the offline graph structures |
| `detect_live.py` | fast live detection: packets → CICFlowMeter's flows → each flow scored 10 ms after its first packet by the flow encoder, the streamed detection encoder and every detector head → `GET /detections`; with `--forecast`, the world model on the same stream → `GET /forecast` (tag `live`, seconds behind); checked by `tools/live/detect_check.py` |
| `cascade.py` | the detection encoder and detector (optionally the compressor) loaded once and chained in memory: an event's features in, a verdict out |
| `emitter.py` | `AlertEmitter` (threshold → persistence → incidents) and `Recalibrator` |
| `live.py` | the world model on this machine's traffic: capture files → complete flows → encoders → world model → `GET /forecast` (tag `lag`, ~150 s behind the wire) |
| `registry.py` | `serving.json`: which models serve each world-model tag, and whether that tag may serve |
| `parity.py` | the tolerance test: a serving path compared stage by stage with the training ingest |

## Online graph structures

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

emitter = AlertEmitter(threshold, persist=3, gap=60.0)
for incident in emitter.push_batch(keys, scores, times):
    publish(incident)
emitter.rates(hours)          # events, alerts and incidents, and their rates per hour
```

1. **Threshold** — the family's own committed threshold (`serve_threshold` in the detector head, 0.01% budget), or,
   with the live detector's `--budget`, its stored threshold at that budget.
2. **Persistence** — 3 consecutive events above threshold on the same host; any event below resets the count.
3. **Incidents** — alerts on one host with no quiet gap longer than 60 s form one incident.

On the Bot day's test split (run of 2026-09-26, 0.01% budget) these rules turn 14,709 events per hour above threshold
into 6.3 incidents per hour, with all 13 attacking hosts alerted (`python -m models.evaluation`).

## Notes

- **Push events in availability order.** Persistence counts consecutive events, so any other order changes the answer.
- **Persist the registries.** Node and link ids are identity; a restarted process that loses them renumbers every host
  and starts every link memory cold. `save()` and `load()` exist for this. A host evicted and seen again gets a fresh
  id, never another host's.
- **`ReorderBuffer(delay)`** must be larger than the longest gap between a packet arriving and its event's `t_obs`;
  releasing earlier feeds the context encoder an out-of-order stream without raising an error.
- **`Recalibrator`** keeps a reservoir sample across everything seen plus the most recent rows, and reads the threshold
  quantile from both, so a threshold is not fitted to one recent stretch of traffic.
