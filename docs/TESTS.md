# Experiment record

*Last updated 2026-09-20. The evidence behind every claim the system makes, including the claims that failed.*

This is the document to read before trusting a number. It states what was measured, how, on what, and what was
rejected. Block 7's three design experiments are kept in full at
[TESTS_block7_detail.md](TESTS_block7_detail.md); everything from Block 8 onward is below.

---

## How every result was measured

| | |
|---|---|
| data | CSE-CIC-IDS2018, 5 days ingested from raw PCAP, our own flow extraction |
| main slice | 3,000,000 events of Friday-02-03-2018 centred on Bot — 1.85M benign training rows, 544k–558k test |
| splits | cut inside every attack window and benign stretch, **ordered in time** (train < val < test) with 120 s embargo gaps; embargo rows are walked to build state and scored nowhere |
| seeds | 2 full cascades (Block 8 + Block 9 + head), ranges reported throughout |
| thresholds | read on validation negatives, never on the rows being reported |
| determinism | verified bit-identical under stream truncation after a `scatter_` fix |

**Observation budget.** Every flow is scored **10 ms** after its first packet, or at flow end if sooner. Results are
split into `early_observation` (still running at 10 ms) and `completed_before_budget` and never pooled.

---

## 1. Does it detect attacks? — and is that better than a baseline?

**Block 13 baseline**, the comparison the problem statement names: logistic regression on all 69 CICFlowMeter columns,
same slice, same splits.

| system | PR-AUC | at its best point | false alarms |
|---|---|---|---|
| logistic regression on the flow record | **0.9259** | recall 0.978, precision 0.982 | 288 |
| **our detection arm** | **1.0000** | recall 0.9977, precision 0.998 | **30** |

The baseline was given **strictly more information** — the full record exists only at flow close, a median **106 s**
after our verdict — and still lost. More telling is the cliff:

| budget | baseline recall | ours |
|---|---|---|
| 10⁻³ | 0.9884 | ~1.0 |
| 10⁻⁴ | **0.0003** | 0.9991 |
| 3×10⁻⁵ | **0.0003** | 0.9977 |

Logistic regression works only at loose thresholds. At 53 false alarms it catches 5 attacks out of 15,826. **The
baseline cannot operate in the deployable regime at all.**

**Headline detection result:** 99% recall at **1–2 false alarms** out of 370,705 benign events.

## 2. Does it anticipate? — the problem statement's actual question

Measured on the **sender** key (the attacking host), horizon 20 events.

| metric | value | meaning |
|---|---|---|
| `recall_early` | **0.9969** | of benign events with an attack coming on that host, 99.69% flagged |
| onsets caught early | **275 / 291** | distinct campaign starts flagged **before their first attack packet** |
| false alarms | 30 → **41.9/hour** → **11.2 incidents/hour** | |
| ECE | 0.0008–0.0021 | stated 3% happens ≈3% of the time |
| next-state skill | 0.300–0.303 | dynamics beat "nothing changes" by 30% |

**This is not memorisation.** Holding all 11 attacking hosts out of training in 3 folds, `recall_early` stayed
**1.0000** on 320 held-out early positives and **288 of 291** onsets were still caught.

**But the lead is ~2 seconds.** `lead_events_median` is 1.0 and `lead_seconds_median` 2.02 at both median *and* p90.
The alert fires on the event immediately before the attack. "Flagged before the attack began" is accurate; "minutes of
warning" is not.

## 3. Leakage audit

| test | result | rules out |
|---|---|---|
| prefix invariance | **bit-identical, max diff 0.000e+00** | any lookahead |
| label permutation control | recall **0.0000** | label leakage |
| leave-attackers-out | `recall_early` 1.0000 on held-out hosts | host memorisation |
| split hygiene | train < val < test, 120 s embargoes | calibrating on the future |
| Block 8 training rows | exactly 1,848,132 = the benign-train count | attack, val or test rows reaching training |

## 4. What we rejected, and why

Negative results are reported because they constrain the design as much as the positive ones.

| rejected | evidence |
|---|---|
| **Block 9's false-positive gate** | 7 of 8 supervised cells unchanged; on the world model it buys 4 false alarms and costs 8 early positives |
| **Per-key score normalisation** | **40× worse** (58 → 2,345 false alarms) |
| **Receiver key for anticipation** | `recall_early` 0.14–0.31, unstable; only 206–321 of 928 campaigns alerted |
| **Late fusion** of flow records | worse on false alarms, calibration and skill; on the link key worse than no records at all |
| **PR best-F1 thresholding** | 174 false alarms against a quantile's 50–69 |
| **A 1% FPR budget as an operating point** | 8,544 false alarms/hour — 2.4 per second |

## 5. The false-alarm result — **world model arm**

Measured on the **world model (Block 10)**, keyed on the sender, Bot day slice. The giveaway is the cost column:
`recall_early` and campaign onsets are world-model metrics, so this table cannot be read as a detector result. The
detector's own numbers are in §5b.

A 1% budget on a 217-events/second stream is an alarm that never stops. Three levers, none of which touch the model:

| lever | gain | cost |
|---|---|---|
| threshold 10⁻² → 10⁻⁴ | **105×** | 0.3% of early recall |
| per-host incident aggregation | **1.81–3.42×** (10 s–60 s gap) | none; the gap is a stated choice |
| 3-event persistence requirement | **2×** | **none** — early recall and onsets unchanged |

**8,544 → 41.9 false alarms/hour**, or **11.2 incidents/hour**, at `recall_early` 0.9969.

### 5b. The same question for the **detection arm**

Different arm, different rows, different numbers — and this is the arm that is deployable, so these are the figures to
quote for detection. Bot day, 558,504 benign test rows over 0.72 h, thresholds from calibration benign only:

| budget | threshold | recall | false alarms/hour |
|---|---|---|---|
| 0.1% | 0.0615 | 1.0000 | 919 |
| 0.003% | 0.9338 | 0.9959 | 26.6 |
| 0.001% | 0.9793 | 0.9906 | **8.4** |

Emission funnel at the tightest point: 16,240 above threshold → 15,406 after persist-3 → **21 incidents, 29.4/hour**,
all 10 attacking hosts alerted.

**What transfers between the two arms and what does not.** The *levers* are arm-agnostic mechanisms — persistence and
incident aggregation are decision rules over a score stream, so their multipliers should hold for either. The *absolute
rates* do not transfer: they depend on the score distribution, the threshold and the benign population, all of which
differ between the arms. Never quote 41.9/hour as a detector figure or 8.4/hour as a world-model one.

## 6. Flow records: measured, and not a free win

| where | verdict |
|---|---|
| Block 8 representation | **nothing** (+0.0004, sign flips between seeds) |
| detection | **hurts** (1–2 → 2–4 false alarms at 99% recall) |
| anticipation, sender key | **helps** (false alarms 6,111–8,200 → 5,686–5,702; seed spread 2,089 → **16**) |

Records enter once, at Block 8, whose context feeds both arms — so the benefit and the harm cannot be separated
without running two Block 8 instances. That is an open design decision, not a default.

## 7. Known limitations

* **One day, one attack family, one 3M slice, two seeds.** Cross-day and cross-family generalisation untested.
* **The lead is ~2 s**, not minutes.
* **The anticipation signal may be partly a volume effect** — attacking hosts emit 2,582 events/hour against a median
  of 1.9, and per-key normalisation failing by 40× says the signal lives in score *level*.
* **No live runner exists.** Every "live" number is an offline replay with live rules imposed.
* **Blocks 11, 12 and 14 do not exist** — explainability, MITRE staging, and the demo. The problem statement asks for
  all three.

## 8. Claims that failed during this work

Recorded because a result set with no failures has not been examined hard enough.

| claim | what it turned out to be |
|---|---|
| records cut false alarms 18%, calibration 20× | **−7% and 1.8×** — two-thirds was a `scatter_` non-determinism bug |
| late fusion loses on all four axes | much smaller, and it *preserves* receiver-key early warning that early fusion halves |
| records halve receiver early recall | seed 0 only; seed 1 showed the opposite. No effect. |
| `recall_early` 1.0 proves anticipation | every early positive was on a host already seen attacking — needed leave-attackers-out to settle (it passed) |
| the false-positive rate is unusable | an artefact of a 1% budget, not the model |
| compromise → dwell → callback chain | the dataset's schedule: four hosts "dwelled" 4.266/4.273/4.254/4.271 h |
| widening calibration rows fixes the overshoot | **made it worse** (1.112% → 1.300%); the finding was inherited from another arm and did not transfer |

Each fell to a second seed, a fixed bug, or one more check.

---

## Reproduce

```
uv run python tools/measure/baseline.py --day Friday-02-03-2018 --family Bot --events 3000000
uv run python -m models.world_model_proxy.model --latents data/latents/f_norec_s0/Friday-02-03-2018 --window 512 --key sender
uv run python tools/world_model/alert_economics.py     --latents data/latents/f_norec_s0/Friday-02-03-2018 --key sender
uv run python tools/world_model/fpr_levers.py          --latents data/latents/f_norec_s0/Friday-02-03-2018 --key sender
uv run python tools/world_model/leave_attackers_out.py --latents data/latents/f_norec_s0/Friday-02-03-2018 --key sender
uv run python -m pytest tests/models/ -q
```

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
