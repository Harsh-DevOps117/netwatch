# Block 10 — proxy results, acceptance criteria, and a diagnostic checklist

What `models/world_model_proxy/model.py` measured, so the real Block 10 can be checked against it rather than judged on its own
terms. Every number below is from the deterministic re-score of 2026-09-20 (after the `scatter_` fix), 2 seeds, on a
3M-event slice of **Friday-02-03-2018 centred on Bot**. Ranges span the seeds.

Reproduce with:

```
uv run python -m models.world_model_proxy.model --latents data/latents/f_norec_s0/Friday-02-03-2018 \
    --window 512 --seed 0 --key link sender receiver
uv run python tools/world_model/alert_economics.py --latents data/latents/f_norec_s0/Friday-02-03-2018 --key sender
uv run python tools/world_model/fpr_levers.py     --latents data/latents/f_norec_s0/Friday-02-03-2018 --key sender
uv run python tools/world_model/leave_attackers_out.py --latents data/latents/f_norec_s0/Friday-02-03-2018 --key sender
```

The proxy: ~75,000 parameters — one `GRUCell(32 -> 128)` of dynamics, a `Linear(128 -> 32)` next-observation head, an
`MLP(128 -> 64 -> classes)` class head. One state per key. Trained one step at a time, rolled forward at inference.

## 1. Baseline, at the 1% budget on validation negatives

Test split: 18,037 positives, 558,522 negatives, 0.715 h.

| key | records | recall | precision | false alarms | recall_early | onsets early | ECE | next-state skill |
|---|---|---|---|---|---|---|---|---|
| sender | no | 0.9998–1.0000 | 0.671–0.732 | 6,111–8,200 | **1.0000** | **291/291** | 0.0024–0.0036 | 0.276–0.290 |
| sender | yes (early fusion) | 0.9999 | 0.745–0.746 | **5,686–5,702** | **1.0000** | **291/291** | **0.0008–0.0021** | **0.300–0.303** |
| link | no | 1.0000 | 0.721–0.732 | 6,005–6,323 | n/a | n/a (0 in test) | **0.0005–0.0008** | **0.373–0.386** |
| receiver | no | 0.926–0.927 | 0.730–0.737 | 5,978–6,186 | 0.262–0.279 | 118–121/167 | 0.037–0.070 | 0.393–0.395 |

`recall_early` counts benign events with an attack coming on that key; `onsets early` counts distinct campaign starts
flagged before their first attack event. Pooled `recall` is 98% ongoing attacks and hides whether there is foresight.

## 2. The recall / alert-rate curve — sender key, packets only

This is the result that matters operationally, **for this arm**. Every figure in this document is the world model; the detection arm's own alert economics are in docs/TESTS.md §5b and are not interchangeable with these.

A 1% budget is 8,544 false alarms an hour on a 217-events/second
stream; the model was never the problem.

| budget | recall | recall_early | onsets early | false alarms | per hour | false **incidents**/hour |
|---|---|---|---|---|---|---|
| 1e-2 | 0.9998 | 1.0000 | 288/291 | 6,111 | 8,544 | 989 |
| 1e-3 | 0.9996 | 1.0000 | 285/291 | 643 | 899 | 308 |
| 3e-4 | 0.9987 | 1.0000 | 284/291 | 207 | 289 | 95 |
| **1e-4** | 0.9874 | **0.9969** | **275/291** | 58 | 81 | 22 |
| 3e-5 | 0.9829 | 0.9812 | 233/291 | 28 | 39 | 13 |
| 1e-6 | 0.9732 | 0.9781 | 182/291 | 17 | 24 | 7 |

## 3. Emission levers, at 1e-4 (all free of model changes)

| lever | false alarms | per hour | false incidents/hour | recall_early | onsets early |
|---|---|---|---|---|---|
| none | 58 | 81.1 | 22.4 | 0.9969 | 275/291 |
| Block 9 gate | 54 | 75.5 | 22.4 | **0.9719** | 275/291 |
| persist-2 | 41 | 57.3 | 18.2 | 0.9969 | 275/291 |
| **persist-3** | **30** | **41.9** | **11.2** | **0.9969** | **275/291** |
| per-key normalisation | **2,345** | 3,278.7 | 535.5 | 1.0000 | 283/291 |

**Headline operating point: 1e-4 + persist-3 — `recall_early` 0.9969, 275/291 onsets, 30 false alarms
(41.9/hour, 11.2 incidents/hour), precision 0.9982.**

## 4. Generalisation and timing

| test | result |
|---|---|
| leave-attackers-out (3 folds, all 11 attacking hosts held out in turn) | `recall_early` **1.0000** on 320 held-out early positives; **288/291** onsets |
| prefix invariance (no lookahead) | bit-identical, max difference 0.000e+00 |
| label permutation control | recall and `recall_early` both **0.0000** |
| live constraints (25% LRU cap, 237,028 evictions) | recall identical to 4 decimals; 18–20k events/s |
| **measured lead** | **1 event, 2.02 s at both median and p90** |

## 5. Acceptance criteria for the real Block 10

Run it on the same slice and key. It should **beat** these, and the last row is where the proxy is weakest and the real
model should win outright:

| metric | proxy | the bar |
|---|---|---|
| `recall_early` at <= 42 false alarms/hour, sender key | 0.9969 | >= 0.9969 |
| onsets caught early | 275/291 | >= 275 |
| next-state skill vs persistence | 0.300 | > 0.30 |
| ECE | 0.0008–0.0021 | <= 0.002 |
| leave-attackers-out `recall_early` | 1.0000 | >= 0.99 |
| prefix invariance | exact | exact — no exceptions |
| label permutation | 0.0000 | <= 0.02 |
| **measured lead** | **1 event / 2.02 s** | **materially more — this is the point of a better model** |

A model that improves recall while leaving the lead at one event has not improved the thing the problem statement
asks for.

## 6. Diagnostic checklist — symptom to cause

Every row here is something that actually happened on 2026-09-19/20, with the check that found it.

| symptom | most likely cause | check |
|---|---|---|
| recall collapses on one key but not others | chunk width too wide — hub nodes answer from one stale state | re-run at `--window 512`; receiver recall went 0.108 -> 0.930 |
| same config, same seed, different numbers | a non-deterministic index op (`scatter_` with duplicate indices) | score a prefix, compare to the same rows in the full run; must be bit-identical |
| `recall_early` is exactly 0 | link-keyed target, and attack links carry no benign traffic | count benign events on keys that ever attack — it was 0 of 90,039 |
| `onsets` is 0/0 | all campaign onsets fell in the train split | not a failure; check `campaigns_onset_in_train` |
| realised FPR is several times the budget | calibrating on validation alone (one time segment) | calibrate on validation **plus a random slice of train**; the supervised arm measured a six-fold overshoot |
| next-state MSE looks reasonable but nothing works | no baseline — persistence may be better | report `next_state_skill_vs_persistence`; it went **negative** when the window was wrong |
| suspiciously perfect `recall_early` | attacking hosts appear in both train and test, and state is per host | `tools/world_model/leave_attackers_out.py`; ours cleared it, but it must be run |
| enormous false-alarm counts | wrong operating point, not a wrong model | sweep the threshold; 1e-2 -> 1e-4 was 105x for 0.3% of early recall |
| per-key normalisation makes things worse | the signal is in a host's score **level**, not its shape | expected here — it was 40x worse; treat as evidence the signal is intensity-driven |
| dwell times suspiciously equal across hosts | a dataset schedule artefact, not attacker behaviour | four Infiltration hosts "dwelled" 4.266/4.273/4.254/4.271 h — that is the scenario script |
| a claim holds across seeds then collapses | seeds share systematic bugs; agreement is not validation | fix the bug, then re-score; three findings died this way |

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
