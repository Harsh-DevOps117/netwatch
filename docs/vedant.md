# For Vedant — Block 10, the world model

*Written 2026-09-20. Every number is measured on a 3M-event slice of Friday-02-03-2018 centred on Bot, 2 seeds, after a
determinism fix. Full tables in [BLOCK10_PROXY_RESULTS.md](BLOCK10_PROXY_RESULTS.md); your input format is in
[WORLD_MODEL_INPUTS.md](WORLD_MODEL_INPUTS.md).*

You own Block 10. A **proxy** exists — `models/world_model_proxy/model.py`, ~75,000 parameters — built only to prove the input
pipeline feeds a world model well enough to be worth building properly. It works, it is measured, and it has one clear
weakness you should beat. Treat its numbers as the bar, not as a design to copy.

**You are the objective.** Blocks 7, 8 and 9 exist to build your input. The system is judged by how quickly and
correctly you identify attacks and state over your rollout, not by per-flow scores. If a representation change would
help you and hurt per-flow numbers, that is a trade we should make — tell us.

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

# PART 1 — TRAINING

## What you get

One directory per day: `event_latents.parquet` (one row per event, in availability order) plus
`latents_manifest.json`. Read the manifest first. Columns that matter: `z` (32-wide latent), `recon_error`,
`sender_node_id`, `receiver_node_id`, `t`, `t_obs`, `split`, `label`, `attack`, `observation_population`.

`split` is 0 train / 1 val / 2 test / **−1 embargo**. Walk the −1 rows to build state, but never score or train on
them. The three splits are cleanly ordered in time with 120 s gaps, so calibrating on validation uses only the past.

## Five things the proxy settled, with the measurement

* **One state per key, never one over the stream.** A single GRU over the interleaved stream reached recall 0.29; one
  state per key reached 0.83+, beating even a memoryless probe on `z` alone (0.80). ~98,000 keys multiplexed into one
  vector loses every individual progression.
* **Chunk width 512.** A hub node carries thousands of events and a wide chunk answers all of them from one stale
  state: receiver-keyed recall was 0.108 at window 4096 and 0.930 at 512. 512 is also Block 8's live batch, so
  training and serving see the same staleness — do not tune them apart.
* **The rollout must iterate the dynamics.** Feed the model's own predicted observation back in and read the head at
  each imagined step. Separate heads per horizon score the same (0.998 vs 0.9976) while never learning a transition,
  which is the shortcut the problem statement's wording rules out. Train **one step at a time** and roll forward only
  at inference; backpropagating through 50 unrolled steps is expensive and unstable.
* **Key on the sender for anticipation. The link key cannot do it at all.** An attacker/victim link carries *no*
  benign traffic (90,039 events, zero benign), so a link-keyed target has zero early positives by construction. A
  sender host emits 1,945 benign events before it attacks and that precursor is learnable.
* **Report next-state skill against a persistence baseline.** `1 − MSE(model)/MSE(predict z_{t+1} = z_t)`. When the
  window was wrong this went **negative** (−0.058, worse than assuming nothing changes) while the raw MSE looked
  unremarkable. It is the metric that catches a broken design.

## Metrics to report, and why each exists

| metric | why |
|---|---|
| `recall_early` | of benign events with an attack coming on that key — **this is the anticipation number** |
| `onsets_caught_early` | distinct campaign starts flagged before their first attack event; cannot be inflated by one long campaign |
| pooled `recall` | 16,379 of 16,699 positives are ongoing attacks, so this is 98% a detection number — never report it alone |
| next-state skill | whether the dynamics learned anything beyond persistence |
| ECE / Brier | the problem statement asks for **likelihood**; recall and FPR cannot see a model right about ranking and wrong about magnitude |
| lead in events **and** seconds | H is in events; 20 events spans a median 16 s but 0.36 s at p10 |

## The bar to clear

| metric | proxy | target |
|---|---|---|
| `recall_early` at ≤42 false alarms/hour, sender key | 0.9969 | ≥ 0.9969 |
| onsets caught early | 275/291 | ≥ 275 |
| next-state skill vs persistence | 0.300 | > 0.30 |
| ECE | 0.0008–0.0021 | ≤ 0.002 |
| leave-attackers-out `recall_early` | 1.0000 | ≥ 0.99 |
| prefix invariance | exact | exact, no exceptions |
| label permutation control | 0.0000 | ≤ 0.02 |
| **measured lead** | **1 event / 2.02 s** | **materially more — this is the point** |

**The lead is the weakness.** `lead_events_median` is 1.0 and `lead_seconds_median` 2.02 at both median and p90, in
every configuration. Nothing in the objective rewards firing earlier inside the window, so the head learns to fire at
the last possible moment. A model that improves recall and leaves the lead at one event has not improved the thing the
problem statement asks for.

## Traps — each cost us a wrong conclusion

* **`scatter_` with duplicate indices has no defined winner.** It masqueraded as ~5 points of seed variance and
  produced three findings that collapsed once fixed. Use `scatter_reduce_(..., reduce="amax")`. Test determinism
  directly: score a prefix of the stream, compare to the same rows inside the full run, require bit-identical.
* **Effective sample size is hosts, not events.** The 320 early positives sit on 9 hosts.
* **The signal may be intensity, not structure.** Attacking hosts emit 2,582 events/hour against a median of 1.9 — a
  1,400× outlier — and normalising scores within each key was **40× worse**, which says the signal lives in a host's
  score *level*. Your generalisation may be generalisation of "very busy host".
* **Calibrate on validation plus a random slice of train**, not validation alone. The detection arm measured a
  six-fold budget overshoot from validation-only calibration. The proxy still has this defect.
* **`load_latents` densifies sender and receiver separately** — a host has different ids in the two roles. Read raw
  node ids for anything cross-role.
* **Seed agreement does not validate anything.** Both seeds shared the `scatter_` bug and agreed with disjoint ranges.
* **Block 9's reconstruction-error gate does nothing here** — 4 fewer false alarms, 8 fewer early positives.
* **Suspiciously equal numbers are usually the dataset.** Four Infiltration hosts "dwelled" 4.266/4.273/4.254/4.271 h
  before attacking; that is the scenario script, not attacker behaviour.

## Still untested — updated 2026-09-20

**Multi-class family prediction: no longer untested.** Run on Thursday-15 (DoS-GoldenEye 41,508 + DoS-Slowloris
11,111), sender-keyed, window 512, `--calibrate 0`, 1% budget:

| horizon | recall | precision | realised FPR | overshoot vs budget |
|---|---|---|---|---|
| H=5 | 0.7717 | 0.376 | 2.31% | **2.3×** |
| H=20 | 0.7011 | 0.356 | 2.29% | 2.3× |
| H=50 | 0.7008 | 0.357 | 2.28% | 2.3× |

Brier 0.0158, ECE 0.0163, and `next_state_skill_vs_persistence` **+0.185** — the dynamics genuinely beat persistence,
which is the result worth keeping. The two problems: recall is well below the Bot day's 0.818+, and the 2.3× budget
overshoot is loose next to the detection arm's 1.0–1.8×. Tightening that overshoot is the highest-value work you have.

**Cross-day and cross-family generalisation: still none.**

**Anticipation: blocked, and not by your model.** `segment_split` cuts 60/10/30 inside every attack window and benign
stretch *separately*, so the splits interleave in wall-clock time — **1,677,561 of 1,680,628** Bot-day test benign rows
occur before the latest train attack. Any "will this host attack later" score is therefore contaminated by having
trained on that same host attacking, later in real time. The lead is real in the data (Bot: 2,568 test rows across 10
hosts whose first attack is still ahead, ~44 min median; Infiltration: 10,865 across 10 hosts) but the only honest
instruments are cross-day transfer and `tools/world_model/leave_attackers_out.py`. **Do not report an anticipation number from a
single-day run.**

---

# PART 2 — DEPLOYMENT

## Checkpointing — done 2026-09-20

`world_model.py` previously trained and evaluated in one process and wrote only a CSV: there was no checkpoint at all,
so nothing could be served. Now:

```
models/world_model_proxy/model.py --save PATH        # one file per latents directory and key
models/world_model_proxy/model.py --load PATH        # evaluate saved weights, train nothing
```

It stores the dynamics weights, the **latent scaler** (`z_mean`/`z_std` from the train split), family names, the key,
window, budget, the per-horizon thresholds, and the warm per-key state table. The scaler is not optional: `run()`
standardises `z` with the training split's statistics, so a checkpoint reloaded without it scores on a different scale
and every threshold is void. Verified on Thursday-15 — a reload reproduced recall, precision, FPR, Brier, ECE and
next-state MSE *identically*, in 47 s against 81 s to fit.

**The state table is per-day and `restore_state` defaults to `False` because of it.** Node ids come from
`data/events/<day>/node_index.parquet`, which is built one day at a time, so slot *i* is a different host on a
different day. Restoring a table against a different stream silently attributes one host's history to another. A live
deployment needs its own stable ip → id map before a warm restart means anything.

Yug owns the live runner and alert emission ([FOR_YUG_LIVE_PIPELINE.md](FOR_YUG_LIVE_PIPELINE.md)). What your model
must satisfy to drop into it:

* **Strict causality.** A score may depend only on events at or before its own `t_obs`. The test is mechanical: score a
  prefix, compare to the full run, require bit-identical. The proxy passes at max difference 0.000e+00.
* **A bounded state table with LRU eviction.** You cannot hold a row per key seen. Measured: capping at 25% of keys
  with 237,028 evictions left recall identical to four decimals, because the median host has 7 lifetime events. A
  returning key must restart from the initial state, same as an unseen one.
* **Chunked, not per-event.** Serve at batch 512 — the same staleness you trained with.
* **Emit probabilities, not decisions.** Yug applies threshold, then a 3-event persistence requirement, then per-host
  incident de-duplication. Give him a calibrated probability per family per horizon and let him choose the operating
  point; that choice was worth 200× more than any model change we made.
* **Carry the model version with every score.** Thresholds are points on your score scale and do not survive
  retraining.
* **Budget.** The proxy runs at 18–20k events/s against a peak load of ~3,200/s, in 1.09 MB of live parameters. CPU-only
  throughput is **unmeasured** — an earlier benchmark silently used the GPU.

## Deployment-time metrics to expose

`probability` per family per horizon, `lead_events` and `lead_seconds`, the key and its state age, and whether the key
was evicted since last seen. The last one matters: an alert on a cold-started key is weaker evidence than one on a warm
key, and nothing currently distinguishes them.

---

---

## The ~2 second lead — corrected 2026-09-20

Earlier versions of this document called the lead "the biggest capability gap" and framed it as an objective to fix.
**That was wrong.** Measured as ground truth, with no model involved: for every benign test event on a host that ever
attacks, the *unbounded* time until that host's next attack is

| p10 | p25 | median | p75 | p90 | p99 | max |
|---|---|---|---|---|---|---|
| 0.1 s | 0.4 s | **0.8 s** | 1.4 s | 1.7 s | 2.0 s | **2.0 s** |

**Zero** of the 320 events have even 60 s of warning available. So the maximum lead anywhere in this data on the sender
key is 2.0 seconds, and no training objective can produce lead the data does not contain.

The cause is traffic rate: an attacking host emits 2,582 events/hour against a median host's 1.9, so its benign traffic
is interleaved with its attack traffic at sub-second spacing. A target phrased as "attack within H **events** on this
key" cannot span more than a couple of seconds on a busy host.

A lead-rewarding objective was implemented and tested (`--lead-steps`), then abandoned once this measurement showed
there was nothing for it to learn. The flag remains and is harmless; it simply cannot help on this target.

**What would create lead.** The rollout predicts **state → next state**: a step is one more event on the key, not a
tick of a clock. So *predict* in state transitions and *report* in seconds — reporting `lead_seconds` beside
`lead_events` is right for an operator, but phrasing the **target** in seconds would force the rollout to additionally
predict inter-event gaps, which is a different model and breaks the transition framing.

* ~~time-based horizon~~ — **withdrawn.** "Attack within T seconds" asks the rollout to answer in units it does not
  operate in. The horizon stays in events.
* **campaign-level** — "will this host attack at all": the state of a host *before it has ever attacked*. Still
  per-event, still "what comes next"; only the label changes. The lead it could offer is whatever traffic precedes the
  **first** attack, which is a different population from the one the 2.0 s ceiling was measured on.
* **cross-host** — "A is attacking, is B next": a **graph** rollout, the state of A conditioning the state of B.
  Block 8 already carries that structure (per-link memory plus neighbourhood attention). A star topology does **not**
  rule this out — that conflates topology with timing. If the hosts start at staggered times, the stagger is real lead
  however they are connected.

The 2.0 s ceiling is not a units problem. On an attacking host, benign traffic simply does not precede attacks by much,
so re-expressing the same target cannot create positives that do not exist. The lead has to come from a **different
key** or a **different point in the campaign**. `tools/lead_ceiling.py` measures both ceilings before anything is built.

---

## "Campaign onsets" are attack resumptions — corrected 2026-09-20

`models.world_model_proxy.model.onsets` marks an attack event whose **previous event on that key was not an attack**. On a host
whose benign and attack traffic interleave at sub-second spacing, that fires constantly. Measured on Bot:

| | |
|---|---|
| onsets reported | **1,565** on 11 hosts |
| that follow an earlier attack on the same host | **1,554 (99.3%)** |
| **genuine first-ever attacks** | **11 — one per host** |
| separated from the previous attack by ≤2 events / 2.02 s | **92%** |
| separated by more than 60 s | **0** |

Requiring K consecutive non-attack events before the attack:

| K | onsets | in test |
|---|---|---|
| 1 *(current)* | 1,565 | 291 |
| 2 | 135 | 22 |
| 5 | 27 | 1 |
| 10 | 15 | **0** |
| 20 | 11 | **0** |

And the 11 real starts fall between t=1520003454.1 and t=1520003455.0 — **within 0.9 seconds of each other, a scripted
simultaneous launch — and all 11 are in the train split.** There is no genuine campaign onset in the Bot test split.

**Consequences.** "275/291 onsets caught early" and "1,565/1,565 campaigns alerted" are real counts of attack
**resumption**, not of campaign anticipation — relabel them. `recall_early` 0.9969 stays literally true, on 320 benign
events whose attack is at most 2.0 s away. Cross-host lead on Bot is ~0.9 s because every host launches at once, and
campaign-level lead is unmeasurable there because all 11 real starts are in train.

**Detection is untouched** — 99% recall at 1–2 false alarms, PR-AUC 1.0000 against the baseline's 0.9259. That is a
per-event claim and none of this bears on it.

**How to report it.** Both: resumption-level onsets under K=1, labelled as resumptions; and genuine campaign starts
requiring K≥H non-attack events, with the per-split counts stated. On Bot the second is zero in test, and saying so is
the result. Whether another day differs is measured by `tools/measure/lead_ceiling_days.py`.

<!-- FIELD REFERENCE: generated by tools/repo/render_field_reference.py -- do not edit by hand -->

## Field reference

*Generated from [vedant.json](vedant.json). Every column you read and every field you emit.*


### Input — `event_latents.parquet`

| field | what it is |
|---|---|
| `event_id` | int64 |
| `t` | float64 epoch seconds, the flow's first packet |
| `t_obs` | float64 epoch seconds, when the verdict was available (10 ms after t, or flow end if sooner) |
| `sender_node_id` | int32, host that sent the flow's FIRST packet |
| `receiver_node_id` | int32 |
| `dt_src` | float32 seconds since that sender's previous event |
| `dt_dst` | float32 seconds since that receiver's previous event |
| `reversed` | bool, the flow record's src/dst disagree with first-packet direction |
| `z` | float32[32] Block 9's latent - the compression of Block 8's context. YOUR INPUT. |
| `recon_error` | float32, Block 9's reconstruction error on the benign scale. Available, unused by the proxy. |
| `split` | int8: 0 train, 1 val, 2 test, -1 embargo |
| `label` | string family name, or Benign |
| `observation_population` | string: early_observation \| completed_before_budget |
| `attack` | bool |

**Warnings on this input**

* split == -1 are 120 s embargo rows between segments. WALK them to build state, never score or train on them.
* Splits are ordered in time: train < val < test. Calibrating on validation therefore uses only the past.
* label and attack are EVALUATION ONLY. Never an input.
* Endpoints are keyed on the flow's FIRST CAPTURED PACKET, not the flow record's src/dst, which disagree on 11.2-33.5% of rows depending on the day.

### Target definitions

| field | what it is |
|---|---|
| `key.options` | link; sender; receiver |
| `key.link` | directed pair sender->receiver. 237,293 keys on the Bot 3M slice. Detection only: an attacker/victim link carries NO benign traffic (90,039 events, zero benign), so there are zero early positives BY CONSTRUCTION and anticipation cannot be measured on it. |
| `key.sender` | source host. 15,174 keys. THE ANTICIPATION KEY - a host emits benign traffic before it attacks and that precursor is learnable. |
| `key.receiver` | destination host. 9,733 keys. Rejected: recall_early 0.14-0.31 and unstable across seeds. Being attacked is not a property of the victim's own traffic. |
| `horizon` | H is in EVENTS, not seconds. H=20 on a sender key spans a median 16 s but 0.36 s at p10 and 289 s at p90. Always report wall-clock lead beside it. |
| `coming_attack` | for each event: is any of the next H events on the same key an attack |
| `onset` | the first attack event of a campaign on a key - its first attack, or the first after a benign gap |
| `early_positive` | a BENIGN event that has an attack coming on its key within H. This is what recall_early is measured on. |

### What you must emit

| field | what it is |
|---|---|
| `per_event` | key; t_obs; horizon_events; probability_per_family; lead_events; lead_seconds |
| `per_family` | one calibrated probability per family per horizon, benign first, matching models.detector.head.family_codes so both arms name families identically |
| `never` | a binary attack/no-attack decision. Block 12 maps your output to kill-chain stages and cannot do that without a family. Emit probabilities and let the serving path threshold them. |
| `state_metadata` | state_age_events; evicted_since_last_seen |
| `state_metadata_why` | an alert on a cold-started key is weaker evidence than one on a warm key, and nothing currently distinguishes them |

### Acceptance criteria

| field | what it is |
|---|---|
| `measured_on` | 3M-event slice of Friday-02-03-2018 centred on Bot, sender key, 2 seeds, deterministic |
| `recall_early_at_42_false_alarms_per_hour.proxy` | 0.9969 |
| `recall_early_at_42_false_alarms_per_hour.bar` | >= 0.9969 |
| `onsets_caught_early.proxy` | 275/291 |
| `onsets_caught_early.bar` | >= 275, BUT read onsets_are_resumptions_not_campaigns first. Under the current K=1 definition these are attack RESUMPTIONS about 2 s after a benign blip, not campaign starts. Matching 275/291 says your model detects resumption as well as the proxy does; it says nothing about anticipating a campaign. Report the stricter K>=H definition alongside it - on Bot that count is ZERO in test, which is the honest number. |
| `next_state_skill_vs_persistence.proxy` | 0.3 |
| `next_state_skill_vs_persistence.bar` | > 0.30 |
| `next_state_skill_vs_persistence.definition` | 1 - MSE(model)/MSE(predict z_next = z_now) |
| `ece.proxy` | 0.0008; 0.0021 |
| `ece.bar` | <= 0.002 |
| `leave_attackers_out_recall_early.proxy` | 1.0 |
| `leave_attackers_out_recall_early.bar` | >= 0.99 |
| `prefix_invariance.proxy` | exact, max diff 0.000e+00 |
| `prefix_invariance.bar` | exact - no exceptions |
| `label_permutation_control.proxy` | 0.0 |
| `label_permutation_control.bar` | <= 0.02 |
| `measured_lead.proxy` | 1 event / 2.02 s |
| `measured_lead.bar` | NOT a bar on this target - the data contains at most 2.0 s of lead on the sender key (see lead_time_the_truth). Do not try to beat it by changing the objective. If you want lead, propose a different TARGET - time-based horizon or campaign-level - and say so before building. |

### Settled by measurement

| field | what it is |
|---|---|
| `state` | one per key, never one over the stream - global reached recall 0.29 where per-key reached 0.83+ |
| `chunk_width` | 512 |
| `chunk_width_why` | a hub node carries thousands of events and a wide chunk answers all of them from one stale state: receiver-keyed recall 0.108 at window 4096 against 0.930 at 512. 512 is also Block 8's live batch, so training and serving see the same staleness. Do not tune them apart. |
| `rollout` | iterate the dynamics, feeding the model's own predicted observation back in. Separate heads per horizon score the same (0.998 vs 0.9976) while never learning a transition. |
| `training` | one step at a time, roll forward only at inference. Backpropagating through 50 unrolled steps is expensive and unstable. |
| `fusion` | flow records enter at Block 8 as their own message kind, union-merged with a presence bit. Late concatenation of separately trained latents was worse on false alarms, calibration and skill. |

### Traps

| field | what it is |
|---|---|
| `scatter_nondeterminism` | scatter_ with duplicate indices has no defined winner - 16 distinct results in 200 repeats on one real chunk. It masqueraded as ~5 points of seed variance and produced three findings that collapsed once fixed. Use scatter_reduce_(reduce='amax'). Test by scoring a prefix and requiring bit-identical results. |
| `effective_sample_size` | the 320 early positives sit on 9 hosts. n is hosts, not events. |
| `intensity_confound` | attacking hosts emit 2,582 events/hour against a median of 1.9 - a 1,400x outlier - and per-key score normalisation was 40x WORSE, which says the signal lives in a host's score level. Your generalisation may be generalisation of 'very busy host'. |
| `calibration_source` | validation alone beat validation+train on this slice (1.112% vs 1.300% realised against a 1% budget) because splits are time-ordered and validation sits nearest test. The detection arm measured the opposite on its subsets. Re-measure per arm, do not inherit. |
| `densified_ids` | If you write your own loader: densify sender and receiver ids TOGETHER or keep them raw. The proxy's load_latents densifies them separately, so a host ends up with different ids in the two roles and cross-role comparisons silently break. It cost us a wrong 'no chain exists' result. |
| `seed_agreement` | does not validate anything - both seeds shared the scatter_ bug and agreed with disjoint ranges. |
| `dataset_artefacts` | four Infiltration hosts 'dwelled' 4.266/4.273/4.254/4.271 h before attacking. That is the scenario script, not behaviour. Suspiciously equal numbers are usually the dataset. |

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

### Statistics you must report

| field | what it is |
|---|---|
| `why` | report these and the comparison to the proxy is direct. Omit one and it is not. |
| `required_per_run` | recall; recall_early; recall_ongoing; precision; false_alarms; fpr; onsets_caught_early / onsets; lead_events_median; lead_seconds_median; lead_seconds_p90; ece; brier; next_state_mse; next_state_mse_persistence; next_state_skill_vs_persistence; next_state_cosine |
| `required_per_key` | report link, sender AND receiver. They answer different questions and dropping one hides a regression - link cannot measure anticipation at all, and receiver is where records look unstable. |
| `required_per_horizon` | H = 5, 20 and 50. Reporting one horizon hides whether the rollout is doing anything. |
| `required_seeds` | at least 2 full runs, and report the RANGE not the mean. Three of our findings died to a second seed. |
| `must_also_report.prefix_invariance` | score a prefix of the stream, compare to the same rows in the full run, report the max absolute difference. Must be exactly 0. |
| `must_also_report.label_permutation` | permute the training labels, retrain, report recall and recall_early on true test labels. Must collapse to about 0. |
| `must_also_report.leave_attackers_out` | 3 folds over the attacking hosts, report recall_early and onsets on HELD-OUT hosts only. |
| `must_also_report.persistence_baseline` | always report next_state_mse_persistence beside next_state_mse. A raw MSE means nothing alone, and the skill score went NEGATIVE when our design was broken. |
| `do_not_report_alone` | pooled recall. 16,379 of 16,699 positives are ongoing attacks, so it is 98% a detection number and says almost nothing about anticipation. |

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
