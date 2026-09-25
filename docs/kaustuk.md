# Kaustuk — modelling up to Block 9, the detection head, and Block 13

*Written 2026-09-20. Machine-readable companion: [kaustuk.json](kaustuk.json). Full measured position:
[STATUS_2026-09-20.md](STATUS_2026-09-20.md).*

Everything you own, what is done, what is left, and the things that will bite if you forget them. This is the file to
re-read before starting the full 5-day run.

## Ownership boundary

| scope | owner |
|---|---|
| **modelling, Blocks 0–9, the detection head, Block 13** | **you** |
| modelling, Block 10 and above | Vedant — [vedant.md](vedant.md) |
| live pipeline and serving | Yug — [yug.md](yug.md) |
| frontend, backend, CLI, Block 14 demo | dev team — [dev.md](dev.md) |

---

## 1. What you have built and measured

| block | state | key number |
|---|---|---|
| 0–6 ingest | done, 5 days | — |
| 7 per-flow encoder | trained, frozen, exported | 65,000 parameters, 32-wide `h_split`, 10 ms budget |
| 8 context encoder | trained; **LRU cap added 2026-09-20** | val link PR-AUC 0.99392 / 0.99452 (2 seeds) |
| 9 autoencoder | trained, exports `z` + `recon_error` | val loss 0.00396 / 0.01081 |
| detection head | trained, per-family thresholds | **1–2 false alarms at 99% recall** |
| 13 baseline | **done 2026-09-20** | PR-AUC 0.9259 vs your 1.0000 |

**The single most quotable result:** the detection head holds 99% recall at **1–2 false alarms** out of 370,705 benign
events, while logistic regression on the full CICFlowMeter record — strictly more information, available 106 s later —
manages PR-AUC 0.9259 and **collapses to recall 0.0003** at the same alert rate.

## 2. Your remaining work

**Code work is finished as of 2026-09-20** — see *Deployment code, done* below. What is left is runs and one
measurement.

| # | item | cost | note |
|---|---|---|---|
| 3 | seed-2 cascades, both arms | 2.2 h | Block 9 for `f_rec_s2` was lost; needs a refit then the supervised run |
| 9 | CPU-only throughput | 20 min | never validly measured; the old benchmark silently used the GPU |
| — | cross-day transfer + host holdout | ~1.5 h | the **only** honest route to an anticipation number (see §"The ~2 second lead") |
| **10** | **full training, Blocks 7–9, all days** | 8–10 h | **yours, deliberately held back.** Follow `docs/DEPLOYMENT_RUNBOOK.md` |

### Deployment code, done 2026-09-20

Training previously produced nothing a live system could load. All of it now persists:

| what | how |
|---|---|
| Supervised head + **feature scaler** + families + budget thresholds | `models/detector/head.py --save`, reload with `load_head()` |
| Score distributions for threshold sweeps | `models.detector --save-scores` |
| The threshold decision, as its own testable step | `models/evaluation/thresholds.py` → writes `serve_threshold` into the head checkpoint |
| Block 10 weights + **latent scaler** + warm state table + thresholds | `models/world_model_proxy/model.py --save` / `--load` |
| Block 8 LRU cap, wired to the CLI and carried in the checkpoint | `models.context_encoder --capacity 0.25` |
| Incremental alert emitter (threshold → persist-3 → incident dedup) | `models/serving/emitter.py`, `AlertEmitter` |
| Recalibration mechanism (two-sample, drift detection) | `models/serving/emitter.py`, `Recalibrator` |

Verified: reloads score identically for both models; the Bot-day sweep gives threshold 0.932321 → recall 0.9961 at 28.0
alarms/hour, overshoot 1.07–2.39× across ten budgets; 234 tests pass.

Removed as dead or superseded: `models/context_encoder/joint.py` (unreachable — its documented entry point never existed),
`tools/lead_ceiling.py` (superseded, and its headline was void), `tools/fuse_latents.py` + its test (late fusion,
rejected), `tools/attack_chain.py` (its finding collapsed as a dataset artefact). `data/model_cache/snapshots/` holds
7 MB of dated copies of this repo — excluded from pytest, **not deleted**, because the repo has no commits yet and they
may be the only historical copies. Delete them once you have committed.

### The 5-day run is a dependency, not a finale

It is the only thing that produces a **servable Block 7**. Every Block 7 checkpoint on disk is a leave-one-day-out
experiment artefact (`<train days>__<held-out day>__a_pkt__gnn__relu__s<seed>.pt`); none is trained on all days, so
none is defensible to serve. Yug is blocked on this, not just waiting for better numbers.

## 3. Decisions only you can make

**Records: one Block 8 or two?** Flow records enter at Block 8 and its context feeds *both* arms. They **help**
anticipation (sender false alarms 6,111–8,200 → 5,686–5,702, seed spread 2,089 → 16) and **hurt** detection (1–2 → 2–4
false alarms at 99% recall). You cannot have both without running two Block 8 instances, doubling link-memory state.
Three options: two instances, one with records and accept worse detection, or one without and accept worse
anticipation.

**Per-family budgets across 9 families.** Each family currently gets its own budget, so with 9 families across 5 days
the aggregate is 9× whatever you set. For a 0.1% total, each family needs ≈0.011%.

**Threshold recalibration policy.** Thresholds die on retraining and benign traffic drifts. Yug implements it; the
policy — cadence, calibration window, drift response — is yours.

## 4. Things that will bite

* **Checkpoints and code drift.** Three 5-day cascades became unloadable after a refactor (`late.flow.*` renames,
  message width 148 → 216). Land code changes *before* long training runs, never after.
* **Calibration source is data-dependent.** Validation alone beat validation+train here (1.112% vs 1.300% realised
  against a 1% budget) because splits are time-ordered. The detection arm measured the opposite on its subsets.
  Re-measure per arm; do not inherit.
* **Seed agreement is not validation.** Both seeds shared the `scatter_` bug and agreed with disjoint ranges. Three
  findings collapsed when it was fixed.
* **`scatter_` with duplicate indices** has no defined winner. Use `scatter_reduce_(reduce="amax")`.
* **Never use pattern-based `pkill`/`pgrep`** to stop a job — the pattern matches your own shell and kills it. Kill by
  explicit PID. This cost three interruptions in one day.
* **Sender/receiver vs src/dst.** `events.parquet` has `src_node_id`/`dst_node_id` from the flow record;
  `side_features.parquet` has `sender_node_id`/`receiver_node_id` from the first captured packet. They disagree on
  11.2–33.5% of rows. Block 8's links use sender/receiver.

## 5. Reproduce anything

```
uv run python -m models.context_encoder --arm split --days <day> --events 3000000 --family <fam> \
    --flow-messages [--flow-records] --batch-size 512 --epochs 10 --patience 3 --seed <s> --out <b8>
uv run python -m models.compressor --encoder mlp --block8 <b8>/best.pt --days <day> ... --out <b9>
uv run python -m models.compressor ... --load <b9>/best.pt --export data/latents/<run>
uv run python -m models.detector.head --days <day> ... --block8 <b8>/best.pt --block9 <b9>/best.pt --out <csv>
uv run python tools/measure/baseline.py --day <day> --family <fam> --events 3000000
```

All self-checks: `uv run python -m tests.models.test_world_model` (14),
`uv run python -m pytest tests/models/ -q`.

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
