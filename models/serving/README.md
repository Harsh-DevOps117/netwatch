# `models/serving` — live traffic

## Purpose

The pieces a live process needs that the offline pipeline gets for free by holding a whole day in memory. Nothing here
is trained.

Two halves: building the **graph** incrementally, and making the **alert decision** incrementally.

## Why it exists

Every graph structure the trained cascade reads is built by a whole-array pass over a finished day, and none of it can
serve:

| offline | why it cannot serve | online |
|---|---|---|
| `ingest.events` node index | ids are assigned by first appearance **within one day**, so a host is a different id tomorrow | `NodeRegistry` |
| `LinkIds` | sorts the whole stream's pairs; a link id is an index into that table, and link id **is** the memory slot | `LinkRegistry` |
| `NeighbourIndex` | lexsorts the entire stream, queried by absolute stream position | `OnlineNeighbours` |
| time-since-last-seen | a groupby over the whole day, for `dt_src` / `dt_dst` | `LastSeen` |
| `availability_order` | sorts the finished day by `(t_obs, event_id)` | `ReorderBuffer` |

## Files

| file | role |
|---|---|
| `graph.py` | `NodeRegistry`, `LinkRegistry`, `OnlineNeighbours`, `LastSeen`, `ReorderBuffer` |
| `emitter.py` | `AlertEmitter`, `Recalibrator` |
| `cascade.py` | every stage loaded once and chained in memory, no file round-trip per event |

## The chain, in memory

Training writes a file per stage and the next reads it back — right for training, wrong for serving.

```python
from models.serving.cascade import Cascade
cascade = Cascade("data/model_cache/serve", capacity=0.25)
cascade.reset(links=n_links)
verdict = cascade.decide(features, keys=senders, times=t_obs)
```

**The context encoder is stateful; the others are not.** Link memory and the neighbourhood accumulate across calls, so
an instance belongs to one stream — `reset()` starts another, and reusing one without it mixes two hosts' histories.
**The emitter is kept across calls**, because persistence is a run of consecutive events and an incident spans them;
rebuilding it per batch would reset both and inflate the incident count.

## The alert decision

Three stages, in this order:

1. **Threshold** — compare to the family's threshold, taken from the head checkpoint's `serve_threshold`.
2. **Persistence** — require 3 consecutive events above threshold on the same key. The counter resets on *any* event
   below threshold, which makes it a run test rather than a count: an attack holds the score up across consecutive
   events, benign noise does not. Measured: halves false alarms at no cost to early recall.
3. **Incident de-duplication** — alerts on one key with no quiet gap longer than 60 s are one incident. Measured: 30
   alerts became 8 incidents.

Together these took 8,544 alerts/hour to **41.9 alerts/hour and 11.2 incidents/hour** — measured on the **world model
arm**; the detection arm's equivalent is 22,708/hour → 29.4 incidents/hour. None of it touches the model, which makes it
the cheapest large improvement available anywhere in the system, and the mechanisms apply to either arm even though the
absolute rates do not transfer.

```python
from models.serving.emitter import AlertEmitter
emitter = AlertEmitter(threshold, persist=3, gap=60.0)
for incident in emitter.push_batch(keys, scores, times):
    publish(incident)
emitter.rates(hours)          # events, alerts, incidents and both per-hour rates
```

## Notes

**Push order is availability order.** A run of three means three *consecutive* events on that key, so a batch sorted by
anything else changes the answer.

**The registries must be persisted.** Node and link ids are identity. Lose them and a restarted process renumbers every
host, the world model's state table then points at the wrong hosts, and link memory starts cold for every link at once.
`save()` / `load()` exist for this. An evicted host that returns is given a **fresh** id rather than inheriting a
stranger's, because silent id reuse corrupts state instead of merely losing it.

**The neighbourhood matches the offline index exactly**, verified event-for-event against `recent_neighbours`. Two
properties are easy to get wrong and both silently degrade the model rather than raising: the two roles are **separate**
tables (events whose sender also sent, plus those whose receiver also received — not everything either endpoint
touched), and an event's **own link is excluded entirely**, at any recency, because link memory already carries it.

**`ReorderBuffer(delay)` needs a measured delay** (see the IMPORTANT section of `docs/DEPLOYMENT_RUNBOOK.md`). It must exceed the worst-case spread between a packet arriving and
its event's `t_obs`. Releasing too early feeds the context encoder an out-of-order stream, which changes link memory,
the neighbourhood and any run test, with no error raised.

**Recalibration keeps two samples.** A threshold read from one contiguous recent stretch overshot its budget six-fold on
another segment of the same day, so `Recalibrator` holds a reservoir sample spanning everything seen plus a FIFO of the
most recent rows, and reads the quantile off their union. Feed it scores of rows that did not alert: circular but
conservative, since an attack slipping under the threshold drags it down, never up.
