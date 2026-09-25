# For the dev team — frontend, backend, CLI, and the demo (Block 14)

> **Updated 2026-09-20 — one wording change matters.** Do not put a seconds figure on *anticipation* anywhere in the
> UI yet. The previous "~2 s lead" was an artefact of the analysis slice, and the lead the data really contains cannot
> currently be scored (the train/test split interleaves in time). Show **detection** confidently, with its threshold
> and alarm rate; show **anticipation** as a ranked "what may be coming" list with no time claim attached. See §4.
>
> Each verdict's `threshold_id` now has a real source: the `serve_threshold` field of the head checkpoint, chosen by an
> operator with `models/evaluation/thresholds.py` and stored beside the weights. Show the budget, the realised FPR and the
> alarms-per-hour that point was measured at — all three are in that field.

*Written 2026-09-20. Your API contract is [dev.json](dev.json).*

You own everything a person touches: the API, the interface, the CLI, and the Block 14 demo the problem statement asks
for ("design and develop a software prototype"). The model side is built and measured; the serving side is being built
by Yug ([yug.md](yug.md)). This file is what you need to know to design against it without reading the model code.

## Ownership boundary

| scope | owner |
|---|---|
| modelling, Blocks 0–9 and the detection head | Kaustuk |
| modelling, Block 10 and above | Vedant |
| live pipeline and serving engineering | Yug |
| **frontend, backend, CLI, Block 14 demo** | **you** |

---

## 1. The system produces two different answers

Do not present them as one feed. They answer different questions and an operator uses them differently.

| | **Detection** | **Anticipation** |
|---|---|---|
| says | "this flow is Bot" | "this host is about to attack" |
| unit | one flow | one host |
| arrives | **10 ms after the flow's first packet** | continuously |
| names a family | yes | yes |
| use in the UI | a row in a flow table, blockable | a host-level warning, investigable |

A second detection verdict arrives later for the same flow, once its CICFlowMeter record exists — a **median 106
seconds** after the first. It is a *separate observation*, not a correction. Show both with their own timestamps;
never overwrite the first with the second.

## 2. Alerts are not events — show incidents

The system emits far more alert *events* than an operator should ever see. Alerts on one host within 60 seconds are one
**incident**. Measured: 30 alert events collapsed to **8 incidents** for anticipation and **27** for detection.

Design the primary view around incidents (host + time window + family + peak probability), with the raw events
available underneath. A feed of raw alerts would show ~42 per hour; incidents show ~11 per hour.

## 3. Every alert carries a probability, and it means what it says

The model is **calibrated** — measured ECE 0.0005–0.0036, meaning when it says 3% it happens about 3% of the time. So
a probability is safe to display as a number and to sort by. Do not re-bucket it into "high/medium/low" without saying
what the thresholds are.

Every alert also carries the **operating point** it was raised at (`threshold_id`). Two alerts from different operating
points are not comparable — show it.

## 4. Lead time: be careful how you word it

The anticipation path flags a host **before its first attack packet** — 275 of 291 campaign starts in our measurement.
But the median lead is **one event, about 2 seconds**. That is enough for an automated response and **not** enough for
a human to act.

So: "flagged before the attack began" is accurate. "Minutes of warning" is not. If the UI shows a countdown or a
"time to impact", it will be wrong most of the time — show the measured lead per alert instead, in seconds, and let it
be small.

## 5. The CLI and the demo

Block 14 in the design is: **PCAP or CIC CSV in → timeline, flagged flows, stages out.** That is your deliverable and
nothing upstream blocks it, provided you go through the API rather than the model code.

What the demo should be able to show, because the measurements support it:
* a timeline of one day with attack campaigns marked
* per-flow detection verdicts at 10 ms, with family and probability
* host-level anticipation warnings, with the lead in seconds
* the incident view, and the raw events behind each incident
* the operating point in use, and what changing it costs (we can supply the recall/alert-rate curve)

What it should **not** claim yet: MITRE kill-chain stages (Block 12 does not exist), per-feature explanations
(Block 11 does not exist), or anything about attacks we have not tested (one day, one family, see §7).

## 6. Performance you can design against

| | measured |
|---|---|
| model throughput | 18–20k events/s |
| peak load in the data | ~3,200 events/s |
| live parameters | 1.09 MB |
| alert rate at the recommended operating point | ~42 events/hour, ~11 incidents/hour |
| detection latency | 10 ms after a flow's first packet |

These exclude ingest and I/O, which are Yug's path. Assume the API is not the bottleneck; the UI will not be flooded.

## 7. What is honestly not proven yet

Say this plainly in any demo narration rather than letting the numbers imply more:

* measured on **one day, one attack family (Bot), one 3M-event slice, two seeds**
* cross-day and cross-family generalisation **untested**
* the anticipation signal may be partly a **volume** effect — attacking hosts emit 2,582 events/hour against a median
  of 1.9
* the lead is **~2 seconds**, not minutes
* Blocks 11 (explainability), 12 (MITRE stages) and 13 (baseline) **do not exist**; the problem statement asks for all
  three
