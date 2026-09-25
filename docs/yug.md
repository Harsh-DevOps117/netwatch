# For Yug — the live pipeline and alert emission

> **Updated 2026-09-20.** Two items previously listed as yours are now written and are not your work: the Block 8 LRU cap (Kaustuk's, inside Block 8) and the alert emitter + recalibrator (`models/serving/emitter.py`). What remains yours is the runner itself, the ordering guarantees, and the recalibration *policy*. See §4.

*Written 2026-09-20. Numbers here are measured, not estimated; each one says where it came from so you can re-check it.*

You own the part that does not exist yet: a process that takes traffic as it arrives and drives the model, plus the
logic that turns scores into alerts a person sees. Everything upstream (Blocks 0–9) and the model itself are built and
measured — but **every "live" number we have is an offline replay of a parquet file with live rules imposed.** There is
no streaming service. That is the gap.

Your input contract is `docs/yug_live_contract.json`.

---

## Ownership boundary

| scope | owner |
|---|---|
| modelling, Blocks 0–9 and the detection head | Kaustuk |
| modelling, **Block 10 and above** (10, 11, 12, 13) | **Vedant** |
| live pipeline and serving engineering | **Yug** |
| frontend, backend, CLI, Block 14 demo | dev team |

The line is **modelling versus dev**, and inside modelling it is **Block 10**. Two exceptions, both deliberate:
Block 13's logistic baseline needs only Block 7's feature tensor — no world model — so Kaustuk is doing it; and the
Block 10 calibration fix and incident-gap sweep stay with Kaustuk because they correct the **baseline handed to
Vedant**, not the model he will build.

## 1. The one hard deadline: 10 ms

A flow is scored **10 ms after its first packet**, or at flow end if the flow finishes sooner. That is the observation
budget and the whole architecture is built around it. Two consequences:

* You must emit an event at 10 ms with only the packets seen by then. Do not wait for the flow.
* Events split into two populations we always report separately — `early_observation` (the flow was still running at
  10 ms) and `completed_before_budget` (it finished first). Never pool them; they behave differently (detection needs
  1–2 false alarms on the first and 13–15 on the second at the same recall).

## 2. Three messages per flow, at three different times

| kind | exists at | what it carries |
|---|---|---|
| ① the event itself | **10 ms** | Block 7's embedding of the first packets |
| ② 20-packet summary | when the 20th packet lands | the flow's own aggregate over its first 20 packets |
| ③ CICFlowMeter record | **at flow close** | the full 68-column record |

**Kind ③ arrives a median 106 seconds after the verdict** (measured on Thursday-15; 91.3% of DoS-Slowloris flows arrive
late). So:

* **Never let ③ influence the 10 ms verdict on its own flow.** That is reading the future. It only enriches the link's
  context for *later* flows.
* Stamp every message with its own availability time and deliver it in that order. If ② or ③ is late, it is applied
  late — that is correct behaviour, not an error.
* Emit two verdict rows per flow: `stage = "observation"` at 10 ms and `stage = "flow_close"` when ③ lands. They are
  separate observations with separate times. Never fold the second back into the first.

## 3. Ordering and batching — do not change these

* **Availability order.** Process events sorted by `(t_obs, event_id)`, never by flow start. An event does not exist
  for the model until its observation time.
* **Batch 512.** This is not a tuning knob. Block 8's link memory updates once per batch, so the batch size *is* how
  stale the memory is when it answers. The models were trained at 512; serving at a different size is a train/serve
  mismatch. Measured: widening it to 4096 dropped one key's recall from 0.930 to 0.108.
* **Memory TTL 3600 s.** A link untouched for an hour resets.

## 4. What you must add that nobody has written

**~~An LRU cap on Block 8's link memory.~~ DONE, and it was never yours — it is Kaustuk's, inside Block 8.**
Pass `--capacity 0.25` to `models.context_encoder` (below 1 = a fraction of the stream's links), or set it at serving time with
`begin_day(n_links, capacity=N)`. The value is stored in the Block 8 checkpoint, so `frozen_block8` and
`models/detector/head.py --block8` honour it with no extra flag, and the default (`None`) still keeps one row per link so
existing checkpoints are provably unaffected. Measured: 1,000 distinct links through a 250-slot table produced 750
evictions, and a capped fit reached validation link PR-AUC 0.9820. **You do not need to build this.**

**The alert emitter — now written for you: `models/serving/emitter.py`, class `AlertEmitter`.** It was previously only in
whole-file offline scripts (`tools/world_model/fpr_levers.py`, `tools/world_model/alert_economics.py`); it is now incremental, which is what a
live process needs. Use it rather than reimplementing:

```python
from models.serving.emitter import AlertEmitter
emitter = AlertEmitter(threshold, persist=3, gap=60.0)
for incident in emitter.push_batch(keys, scores, times):   # push order IS availability order
    publish(incident)
emitter.rates(hours)      # events, alerts, incidents + per-hour rates -- what GET /health should expose
```

**Push order is availability order.** A run of three means three *consecutive* events on that key, so feeding a batch
sorted by anything else changes the answer. The emitter prunes keys whose incident closed more than one gap ago, so the
table stays bounded without losing an open incident. The three stages it implements, in this order:

1. **Threshold** — compare the score to the family's threshold.
2. **Persistence: require 3 consecutive events above threshold on the same key before alerting.** Keep a per-key
   counter, reset it on any event below threshold. Measured: this halves false alarms (58 → 30) at **zero** cost to
   early recall or campaign onsets. It is the cheapest win available to you.
3. **Incident de-duplication** — collapse alerts on one host with no quiet gap longer than 60 s into a single incident.
   Keep an open-incident timer per host. Measured: 30 alerts became 8 incidents.

Together these took the alert rate from 8,544/hour to **41.9/hour (11.2 incidents/hour)** while keeping 99.7% early
recall. **Those are world-model numbers** — "early recall" only exists in that arm. The detection arm, which is the one
shipping first, goes from 22,708/hour to **29.4 incidents/hour**. Your emitter serves both: the rules are identical, the
thresholds and the resulting rates are per arm. Getting this right matters more than anything in the model.

**A recalibration procedure — the mechanism is now written: `models/serving/emitter.py`, class `Recalibrator`.**
Thresholds are points on one trained model's score scale; retrain and they are void, not merely stale. And benign
traffic drifts: we measured a **six-fold** budget overshoot just between time segments of the same day, which is why a
recent window alone is a biased sample of "normal". `Recalibrator` keeps a reservoir sample spanning everything seen
**plus** a FIFO of the most recent rows and reads the quantile off their union — the arrangement that measured best.

```python
from models.serving.emitter import Recalibrator
calib = Recalibrator(budget=3e-05)
calib.observe(scores_of_rows_that_did_not_alert)    # believed benign; conservative, never raises FPR silently
if calib.drifted(realised_rate):                    # outside 3x of budget either way
    threshold = calib.threshold()
```

What is still **yours to decide and write down**: the cadence (how often you call `threshold()` on schedule), the
window size for measuring `realised_rate`, who is told when a recalibration happens, and what the system does while a
recalibration is in flight. The offline rule never left 1.0–2.4× of its budget, so anything beyond 3× means the score
scale has moved and an automatic recalibration is not enough on its own — a human should know.

## 5. Budget you have to hit

| | measured | note |
|---|---|---|
| model throughput | **18–20k events/s** | offline, fed from disk — excludes your ingest and event construction |
| peak load seen in the data | ~3,200 events/s | so about **6× headroom**, before your overhead |
| live parameters | 272,301 (**1.09 MB**) | the whole hot path |
| Block 8 state | ~67 MB | plus Block 10's capped table |
| CPU-only throughput | **unmeasured** | an earlier attempt silently ran on the GPU; do not assume |

## 6. Things that will silently corrupt results

* Reordering events by anything other than availability time.
* Letting a flow-close message reach the 10 ms verdict of its own flow.
* Pooling the two observation populations.
* Changing the batch size without retraining.
* Carrying a threshold across a model version.

---

<!-- FIELD REFERENCE: generated by tools/repo/render_field_reference.py -- do not edit by hand -->

## Field reference

*Generated from [yug.json](yug.json). Every field you send or emit, with its meaning and the mistake it invites.*


### Message kind 1 — `event`

**Available at:** t_first_packet + 0.010 s, or flow end if earlier · **Required:** ALWAYS. Without it the flow is never scored.

the 10 ms verdict. Carries only packets seen by then.

| field | what it is |
|---|---|
| `event_id` | int64, unique within the day, monotonic in t |
| `t` | float64 epoch seconds, the flow's first packet |
| `t_obs` | float64 epoch seconds, == available_at |
| `observation_population` | string enum: early_observation \| completed_before_budget |
| `sender_ip` | string, the host that sent the flow's FIRST packet |
| `receiver_ip` | string |
| `sender_node_id` | int32, stable id from node_index |
| `receiver_node_id` | int32 |
| `reversed` | bool, true when the flow record's src/dst disagree with first-packet direction |
| `dt_src` | float32 seconds since this sender's previous event, -1 if none |
| `dt_dst` | float32 seconds since this receiver's previous event, -1 if none |
| `port_delta` | float32, destination port minus the sender's previous destination port |
| `dst_port_new` | float32 in {0,1}, 1 if this sender has not used this destination port before |
| `has_packets` | bool; a flow with no captured packets is dropped, not scored |
| `n_pkt` | int16, packets seen by t_obs, capped at 20 |
| `pkt` | float32[20][13] per-packet features in this exact order: ['length', 'ttl', 'tcp_window', 'tcp_flag_syn', 'tcp_flag_ack', 'tcp_flag_fin', 'tcp_flag_rst', 'tcp_flag_psh', 'tcp_flag_urg', 'payload_len', 'tcp_retransmission', 'frag', 'direction'] |
| `dt` | float32[20] seconds since the flow's previous packet, zero-padded after n_pkt |
| `side.request_packets` | int32 |
| `side.response_packets` | int32 |
| `side.reply_latency_s` | float32, -1 if no reply yet |
| `side.direction_changes` | int32 |
| `side.no_reply` | bool |
| `node_id_warning` | sender_node_id/receiver_node_id are keyed on the flow's FIRST CAPTURED PACKET. events.parquet also carries src_node_id/dst_node_id keyed on the flow RECORD, and the two disagree on 11.2-33.5% of rows depending on the day. Block 8's links use sender/receiver. Never mix them. |

### Message kind 2 — `packet_summary`

**Available at:** time of the flow's 20th captured packet · **Required:** CONDITIONAL: required whenever the served Block 8 checkpoint has flow_messages=True - which every checkpoint we have trained does. Omitting it does not crash, but it is a TRAIN/SERVE MISMATCH: in training the summary arrived for essentially every flow (98.6% of Bot events, after the verdict), so 'no summary ever arrived' is a state the model never saw.

the flow's own aggregate over its first 20 packets. Arrives after the verdict for most flows: measured 98.6% of Bot events (median 2 ms later) and 97.0% of DoS-Hulk (median 127 ms).

| field | what it is |
|---|---|
| `event_id` | int64, the event this belongs to |
| `available_at` | float64 epoch seconds |
| `summary` | float32[20] in this exact order: ['pkt_n', 'pkt_len_mean', 'pkt_len_std', 'ttl_mean', 'ttl_std', 'win_mean', 'win_std', 'iat_mean', 'iat_std', 'iat_max', 'syn_n', 'ack_n', 'fin_n', 'rst_n', 'psh_n', 'urg_n', 'payload_bytes', 'payload_frac', 'retrans_n', 'frag_n'] |
| `summary_note` | 20 columns, not 15. Derived from the flow's first 20 packets. iat_mean is the mean of the K-1 gaps, so the summary's own availability time is t + iat_mean * max(pkt_n - 1, 0). |

### Message kind 3 — `flow_record`

**Available at:** flow close · **Required:** CONDITIONAL: required whenever the served Block 8 checkpoint has flow_records=True. With flow_records=False it is ignored entirely and computing it is wasted work.

the full CICFlowMeter record. Measured median 106 s AFTER the verdict (91.3% of DoS-Slowloris flows late). Must never reach the 10 ms verdict of its own flow. Three data faults to handle: direction is keyed to the record's own Src IP and disagrees with first-packet direction on 11.2-33.5% of rows depending on the day (swap the 22 Fwd/Bwd pairs and set record_reversed); Active/Idle columns hold epoch timestamps, not durations, and are excluded; rate columns contain infinities and must be sanitised.

| field | what it is |
|---|---|
| `event_id` | int64 |
| `available_at` | float64 epoch seconds, the flow's close |
| `record` | float32[69] = the 68 CICFlowMeter columns minus Active/Idle, plus record_reversed. Exact order in models.context_encoder.records.RECORD_COLUMNS. |
| `record_reversed` | bool, true if the Fwd/Bwd pairs were swapped to match first-packet direction |

### Output — Detection verdicts


**`stage = observation`** — emitted at t_obs

| field | see dev.json |
|---|---|
| `event_id` | see dev.json |
| `t_obs` | see dev.json |
| `family` | see dev.json |
| `family_probability` | see dev.json |
| `alerted` | see dev.json |
| `threshold_id` | see dev.json |

**`stage = flow_close`** — emitted at the flow_record's available_at

| field | see dev.json |
|---|---|
| `event_id` | see dev.json |
| `available_at` | see dev.json |
| `family` | see dev.json |
| `family_probability` | see dev.json |
| `alerted` | see dev.json |
| `threshold_id` | see dev.json |

> a SEPARATE observation with its own time. Never fold it back into the observation stage.


### Output — anticipation

| field | what it is |
|---|---|
| `keyed_on` | sender_node_id |
| `emitted` | per event, continuously |
| `fields` | key; t_obs; horizon_events; probability; family; alerted |
| `note` | horizon is in EVENTS, not seconds: 20 events on a sender key spans a median 16 s but 0.36 s at the 10th percentile. Report the wall-clock lead beside it. |

### Output — incidents

| field | what it is |
|---|---|
| `rule` | alerts on one key with no quiet gap longer than gap_seconds collapse into one incident |
| `gap_seconds` | 60 |
| `note` | this is what an operator counts. Measured: 30 alert events became 8 incidents on the world model, 27 on the detection head. |

### Alert emission

| field | what it is |
|---|---|
| `order` | threshold; persistence; incident_dedup |
| `threshold.per` | family, and per observation_population |
| `threshold.source` | quantile of calibration benign scores, or a precision floor |
| `threshold.note` | thresholds do not survive retraining; they are model-version scoped. Carry threshold_id in every verdict. |
| `persistence.consecutive_above_threshold` | 3 |
| `persistence.per` | key |
| `persistence.reset_on` | any event on that key below threshold |
| `persistence.measured` | halves false alarms (58 -> 30) at zero cost to early recall or campaign onsets |
| `operating_point.recommended_budget` | 0.0001 |
| `operating_point.measured_at_that_point.recall_early` | 0.9969 |
| `operating_point.measured_at_that_point.onsets_caught_early` | 275 of 291 |
| `operating_point.measured_at_that_point.false_alarms_per_hour` | 41.9 |
| `operating_point.measured_at_that_point.false_incidents_per_hour` | 11.2 |
| `operating_point.measured_at_that_point.precision` | 0.9982 |

### State limits

| field | what it is |
|---|---|
| `link_memory_ttl_seconds` | 3600 |
| `lru_cap_required` | True |
| `lru_note` | Block 8 has no cap yet and needs one. Measured on Block 10: capping at 25% of keys with 237,028 evictions left recall identical to four decimals, because the median sender host has 7 lifetime events. |
| `live_parameters` | 272301 |
| `live_parameter_bytes` | 1090000 |
| `block8_state_bytes_approx` | 67000000 |

### Throughput

| field | what it is |
|---|---|
| `model_events_per_second_measured` | 18000; 20000 |
| `measurement_note` | offline, fed from parquet; excludes ingest and event construction |
| `peak_load_in_data_events_per_second` | 3200 |
| `cpu_only` | UNMEASURED - an earlier benchmark silently used the GPU |

### Ordering and batching

| field | what it is |
|---|---|
| `sort_by` | available_at; event_id |
| `rule` | strictly non-decreasing available_at within a stream |
| `batch_size` | 512 |
| `batch_note` | fixed: Block 8's link memory updates once per batch, so batch size IS the memory staleness the models were trained with. Changing it is a train/serve mismatch. |

### Timing and availability — exact definitions

| field | what it is |
|---|---|
| `definitions_from_code.t` | the flow's first packet |
| `definitions_from_code.end` | t + Flow Duration, i.e. the flow's LAST packet |
| `definitions_from_code.t_obs` | min(t + 0.010, end) - models/data/prefix.py. The verdict moment. A flow that finishes inside the budget is scored when it finishes, not at t+10 ms. |
| `definitions_from_code.observation_population` | COMPLETED if end <= t + 0.010, else EARLY - same file, same line |
| `definitions_from_code.flow_time (kind 2)` | t + iat_mean * max(pkt_n - 1, 0) - models/context_encoder/data.py. The moment the K-th packet lands, derived because exporting exact per-packet times would mean re-reading every packet of every day. Checked against real packet times on 200,000 events: median difference 0.2 ns, worst 8.3 us, which is float32 in the stored aggregates. |
| `definitions_from_code.record_time (kind 3)` | t + Flow Duration - models/context_encoder/records.py. This is the EARLIEST the record can exist, not when it is emitted. |
| `CORRECTION_records_are_not_always_late.the_error` | earlier versions of this contract said the record arrives 'a median 106 s after the verdict' as if always. It does not. |
| `CORRECTION_records_are_not_always_late.why` | record_time == end, and for a COMPLETED_BEFORE_BUDGET flow t_obs == end too - so the record's earliest existence time EQUALS the verdict time for those flows. |
| `CORRECTION_records_are_not_always_late.measured_on_Thursday_15.Benign` | 54.9% of records land after the verdict, median lag 2.2 s, p90 115.9 s |
| `CORRECTION_records_are_not_always_late.measured_on_Thursday_15.DoS-GoldenEye` | 100% later, median 6.8 s, p90 23.0 s |
| `CORRECTION_records_are_not_always_late.measured_on_Thursday_15.DoS-Slowloris` | 91.3% later, median 106.3 s, p90 108.3 s |
| `CORRECTION_records_are_not_always_late.so` | roughly 45% of benign records are available at the verdict moment. The 106 s figure is the median lag among SLOWLORIS records that are late - the worst case, not the typical one. |
| `LIVE_emission_time` | record_time is a floor. CICFlowMeter emits at flow close or at its idle/active timeout, which is at or after t + Flow Duration. Stamp kind 3 with YOUR ACTUAL emission time and deliver in that order. Do not back-date it to t + Flow Duration - that would claim the record existed before you had it. |
| `the_rule_that_still_holds` | a flow's own kind-3 record must never inform that flow's own 10 ms verdict. Block 8 queues messages and applies them at the START of the next batch, so a record whose availability time equals t_obs reaches memory one batch later and cannot affect its own event. Preserve that: queue, then apply on the next batch boundary. |
| `two_verdicts` | stage='observation' at t_obs, and stage='flow_close' when the record lands. For a completed_before_budget flow these can be close together or simultaneous in time, but they are still two separate rows with their own timestamps. |

### Which block consumes which message

| field | what it is |
|---|---|
| `note` | Both optional message kinds ARE consumed - just in different blocks, at different times, and in the 20-packet case with different CONTENT each time. This is the part most likely to be implemented wrongly. |
| `the_20_packet_aggregate.columns` | ingest.build.events.AGG_COLUMNS, 20 values |
| `the_20_packet_aggregate.consumer_1.who` | Block 7, as a DIRECT INPUT |
| `the_20_packet_aggregate.consumer_1.code` | models/flow_encoder/encoder.py, FlowEncoder.forward: head(cat([batch['a'], packets(...)])) |
| `the_20_packet_aggregate.consumer_1.when` | at the 10 ms verdict |
| `the_20_packet_aggregate.consumer_1.CONTENT` | the aggregate over packets available BY 10 ms - a PREFIX, not the full 20. Same 20 columns, different numbers. |
| `the_20_packet_aggregate.consumer_1.also` | it is one of Block 7's reconstruction targets (recon_targets: a, pkt, a_future) |
| `the_20_packet_aggregate.consumer_2.who` | Block 8 link memory, as MESSAGE KIND 2 |
| `the_20_packet_aggregate.consumer_2.code` | models/context_encoder/model.py, FlowMessages in ContextEncoder.late['flow'] -> LinkMemory |
| `the_20_packet_aggregate.consumer_2.when` | at flow_time = t + iat_mean * max(pkt_n - 1, 0), i.e. when the 20th packet lands |
| `the_20_packet_aggregate.consumer_2.CONTENT` | the FULL 20-packet aggregate |
| `the_20_packet_aggregate.consumer_2.why_it_is_new_information` | Block 7 only saw the prefix, so the completed aggregate carries something it could not have known. Measured: it lands after the verdict for 98.6% of Bot events (median 2 ms later) and 97.0% of DoS-Hulk (median 127 ms), but 0.0% of DoS-SlowHTTPTest, whose packets all fall inside the budget. |
| `the_20_packet_aggregate.so` | you must send it as its own timestamped message even though Block 7 already consumed a version of it. They are not the same data. |
| `the_cicflowmeter_record.columns` | models.data.inputs.X_COLUMNS (68) -> models.context_encoder.records.RECORD_COLUMNS (69, adds record_reversed) |
| `the_cicflowmeter_record.consumer_1.who` | population tagging - NOT a model input |
| `the_cicflowmeter_record.consumer_1.code` | models/data/inputs.py: 'x_f is never a model input; observe() reads its Flow Duration only to tag the population'; models/data/prefix.py reads X_COLUMNS.index('Flow Duration') |
| `the_cicflowmeter_record.consumer_1.what_for` | deciding early_observation vs completed_before_budget |
| `the_cicflowmeter_record.consumer_1.LIVE NOTE` | offline this is derived from the record's Flow Duration. LIVE you do not need the record for it - you already know whether the flow was still open at t+10 ms. Same semantics, cheaper source. Tag the population directly and do not wait on the record. |
| `the_cicflowmeter_record.consumer_2.who` | Block 8 link memory, as MESSAGE KIND 3 |
| `the_cicflowmeter_record.consumer_2.code` | models/context_encoder/model.py, RecordMessages in ContextEncoder.late['record'] -> LinkMemory |
| `the_cicflowmeter_record.consumer_2.when` | at record_time, the flow's close - a median 106 s after the verdict |
| `the_cicflowmeter_record.consumer_2.only_if` | the Block 8 checkpoint has flow_records=True |
| `the_cicflowmeter_record.consumer_3.who` | Block 13 baseline - offline only |
| `the_cicflowmeter_record.consumer_3.code` | tools/measure/baseline.py |
| `the_cicflowmeter_record.consumer_3.what_for` | logistic regression on all 69 columns, the floor the system is measured against. Not part of serving. |
| `the_cicflowmeter_record.consumer_4.who` | the records-only cascade - experiment only |
| `the_cicflowmeter_record.consumer_4.code` | models/context_encoder/record_arm.py |
| `the_cicflowmeter_record.consumer_4.what_for` | run 7's late-fusion arm, which lost. Not part of serving. |
| `the_cicflowmeter_record.WHO_BENEFITS.note` | The record enters at ONE point - Block 8, message kind 3 - but Block 8's context feeds BOTH arms. So it reaches the world model through Block 8, not separately. What differs is who benefits. |
| `the_cicflowmeter_record.WHO_BENEFITS.world model / anticipation` | HELPS. Sender-key false alarms 6,111-8,200 -> 5,686-5,702 (disjoint across seeds), next-state skill 0.276-0.290 -> 0.300-0.303, and the seed-to-seed spread collapses from 2,089 false alarms to 16. |
| `the_cicflowmeter_record.WHO_BENEFITS.supervised / detection` | HURTS. False alarms at 99% recall 1-2 -> 2-4; PR-AUC on completed_before_budget 0.9995 -> 0.9986-0.9991. |
| `the_cicflowmeter_record.WHO_BENEFITS.THE DECISION` | one Block 8 serves both arms, so you cannot have records for anticipation and not for detection without running TWO Block 8 instances - doubling link-memory state and compute. Three options: (a) two instances, (b) one WITH records and accept slightly worse detection, (c) one WITHOUT and accept slightly worse anticipation. This is Kaustuk's call, not a serving default. |
| `summary_table` | AGG_COLUMNS prefix   -> Block 7 input            -> at 10 ms; AGG_COLUMNS full     -> Block 8 message kind 2   -> at the 20th packet; record Flow Duration -> population tag           -> live: derive it yourself, do not wait for the record; record 69 columns    -> Block 8 message kind 3   -> at flow close, +106 s median, only if flow_records=True |

### What 'required' means

| field | what it is |
|---|---|
| `the_field_answers` | is this message needed for the system to behave AS MEASURED - not merely whether it crashes without it. Those are different questions and conflating them was an error in v1.0 of this contract. |
| `will_it_crash_without_it` | No, for kinds 2 and 3. Block 8's link memory merges kinds by UNION: each kind has its own slot and a PRESENCE BIT, so 'nothing of this kind arrived' is representable. Nothing errors. |
| `will_it_be_correct_without_it` | NO, if the served checkpoint expects that kind. Every Block 8 we trained has flow_messages=True, and in training the summary arrived for essentially every flow. Serving without kind 2 means every link permanently reads a state that never occurred during training, and results will drift from the measured numbers with nothing to signal it. |
| `HOW TO DECIDE` | read the flags off the checkpoint, do not choose: s = torch.load('<block8>/best.pt', map_location='cpu', weights_only=False); send kind 2 iff s['flow_messages'], send kind 3 iff s['flow_records']. Current checkpoints: f_norec_s0 = {flow_messages: True, flow_records: False}; f_rec_s0 = {flow_messages: True, flow_records: True}. |
| `absent_vs_late` | a LATE message is normal and correct - apply it at its availability time, never before. A PERMANENTLY ABSENT kind that the checkpoint expects is a configuration error, not a tolerated condition. |
| `what_optional_really_meant` | only that the wire protocol tolerates absence without erroring. It never meant you may choose not to send it. |

### Statistics you must report

| field | what it is |
|---|---|
| `why` | these are the numbers that tell us whether the live path matches the measured system. Report them per run. |
| `throughput_events_per_second` | count events processed / wall seconds. Ours offline is 18,000-20,000/s EXCLUDING ingest and event construction. Yours includes them, so expect lower - report both your end-to-end figure and, if you can, the model-only figure. |
| `peak_load_handled` | the highest sustained events/s before the queue grows. Peak in the data is ~3,200/s. |
| `per_event_latency_ms` | t_emit - t_obs, median and p99. The budget is 10 ms to the verdict; anything you add on top is lead time lost. |
| `state_keys_resident` | rows currently held in Block 8's link memory and Block 10's table. |
| `evictions_total` | cumulative LRU evictions. Ours: 237,028 at a 25% cap with recall unchanged to four decimals. A far higher rate than that is a sign the cap is too small. |
| `messages_dropped_or_late` | count kind-2 and kind-3 messages that arrived after their link had already been evicted, or that you could not deliver. This is the number that silently degrades results, and nothing else will reveal it. |
| `alerts_and_incidents_per_hour` | false alarms / test hours, and false INCIDENTS / test hours after collapsing by key with gap_seconds. Target at the recommended operating point: ~42 alerts/hour and ~11 incidents/hour. |
| `population_split` | fraction of flows tagged early_observation vs completed_before_budget. Ours on the Bot slice: 370,705 vs 187,799 benign. A large drift here means your budget or flow-end detection differs from ours. |
| `cpu_only_throughput` | run once with the GPU disabled. NEVER VALIDLY MEASURED on our side - an earlier benchmark silently used the GPU, so there is no number to compare against yet. |

### How to calculate every statistic

| field | what it is |
|---|---|
| `test_window_hours` | hours = (max(t_obs[test]) - min(t_obs[test])) / 3600. On the Bot 3M slice this is 0.715 h. Every per-hour figure divides by it, so quote it beside any rate. |
| `recall` | TP / (TP + FN) over TEST rows only, where a positive is an event whose target is true. |
| `recall_early` | TP_early / P_early, where P_early = TEST rows that are BENIGN and have an attack coming on their key within H. This is the anticipation number. On the Bot sender key P_early = 320. |
| `recall_ongoing` | TP_ongoing / P_ongoing over TEST rows that are THEMSELVES attacks with more attack following. P_ongoing = 16,379, so pooled recall is 98% this number - never report recall alone. |
| `precision` | TP / (TP + FP) over TEST rows. |
| `fpr` | FP / N_negatives over TEST rows. N_negatives = 558,522 on the Bot 3M slice. |
| `false_alarms_per_hour` | FP / test_window_hours. Example: 30 / 0.715 = 41.9/hour. |
| `false_incidents_per_hour` | collapse alerts first, then divide. Collapse = group alerts by key, sort by time, and start a new incident whenever the gap to the previous alert on that key exceeds gap_seconds. An incident is TRUE if ANY alert inside it was a true positive, FALSE otherwise. Example: 30 alerts -> 8 false incidents -> 8 / 0.715 = 11.2/hour. The gap is a choice with a real cost: 1.81x collapse at 10 s, 3.42x at 60 s, 5.91x at 300 s. |
| `onsets_caught_early` | count of campaign ONSETS in test that had an alert fire strictly before them. An onset is the first attack event of a campaign on a key - its first attack, or the first after a benign gap. Each campaign contributes exactly one, so unlike recall_early this cannot be inflated by one long campaign. Bot sender key: 291 onsets in test. |
| `lead_events / lead_seconds` | for each alert that precedes an attack on its key: lead_events = the number of events between them; lead_seconds = t_obs(attack) - t_obs(alert). Report the MEDIAN and p90 of both. Measured: 1 event and 2.02 s at BOTH median and p90. |
| `probability_within_H` | from the rollout, per family f: P(f within H) = 1 - prod over k=1..H of (1 - p_k[f]), where p_k = softmax(head(state after k imagined steps)). Compute in log space: 1 - exp(sum_k log(1 - p_k[f])) - the direct product underflows. |
| `ece` | Expected Calibration Error. Bin predictions by predicted probability (15 bins). In each bin b compute \|mean(predicted) - fraction(actually happened)\|. ECE = sum_b (n_b / N) * that gap. 0 is perfect. Read it as: at ECE 0.002, a stated 3% happens 3% +/- 0.2 percentage points of the time. |
| `brier` | mean((predicted probability - outcome)^2) over TEST rows. Lower is better; it penalises both miscalibration and poor discrimination, where ECE sees only miscalibration. |
| `next_state_skill_vs_persistence` | 1 - MSE(model) / MSE(persistence), where persistence predicts z_next = z_now on the same key. 0 = no better than assuming nothing changes; 1 = perfect; NEGATIVE = worse than doing nothing, which is what a broken design looks like. Always report the persistence MSE beside it - a raw MSE means nothing alone. |
| `persistence_rule (persist-k)` | alert only when k CONSECUTIVE events on the same key exceed the threshold. Keep a counter per key; increment on an event above threshold, RESET TO ZERO on any event below it; fire when the counter reaches k. Measured at k=3: false alarms 58 -> 30 with recall_early and onsets unchanged. |
| `threshold_from_budget` | threshold = quantile(scores of CALIBRATION rows that are negative, 1 - budget). Calibration rows are validation only by default - measured better than validation+train on this data (1.112% vs 1.300% realised against a 1% budget) because splits are time-ordered and validation sits nearest test. |
| `threshold_from_precision_floor` | walk the precision-recall curve on calibration rows and take the HIGHEST-RECALL threshold whose precision reaches the floor. Equivalent in outcome to a budget but stated in terms an operator can agree to. Measured: precision>=0.999 landed on the same point as a 3e-5 budget. |

<!-- END FIELD REFERENCE -->
