# Block 7 — the design choices and the experiments behind them

> **Read this first (2026-09-19).** These three experiments decided Block 7 and they stand. Two things about them
> are no longer how the system is judged:
>
> 1. **The unsupervised arm they measure is dropped from the live system.** Experiment 3's anomaly arm (A25) needs the
>    response *and* direction-aware models on top of the split model — 195,856 extra encoder parameters on the
>    per-flow hot path. Its numbers are kept here as a real record of what a benign-only per-flow score achieves; they
>    are not the product. The live detection arm is a **multi-class family classifier** on the split embedding
>    (`models/detector/head.py`). Its code is snapshotted at
>    `data/model_cache/snapshots/2026-09-19_unsupervised_arm/`.
> 2. **The objective is recall at a low false-positive rate, and the consumer is the world model.** PR-AUC below is a
>    ranking diagnostic; it is not the target. Suppressing the false positives a recall-first threshold admits is
>    Block 9's job, and a family with high recall and poor precision is work handed to Block 9, not a failure. See
>    *The supervised arm's protocol* at the end of this file, and design.md's *What the system is optimised for*.
>
> Unseen-family results (leave-one-day-out) are kept because they are informative, but detecting attacks outside the
> label vocabulary is a **bonus, never a requirement**.

Three experiments decided how Block 7 (the per-flow encoder) is built. Each states the question, how it was tested,
the result, and the choice it forced. The full experiment log — every run, rejected idea and record id cited in code
comments (R01–R79, A/O/W/X) — is kept in [TESTS_full_2026-09-15.md](TESTS_full_2026-09-15.md). The design itself is in
[design.md](design.md).

## How every result was measured

| | |
|---|---|
| Data | CSE-CIC-IDS2018, three days: Friday-16-02 (DoS-Hulk, DoS-SlowHTTPTest), Friday-02-03 (Bot), Friday-23-02 (Brute Force -Web, -XSS, SQL Injection). The choices were made on these three days; experiments 2 and 3 were then re-run on five days, adding Thursday-15-02 (DoS-GoldenEye, DoS-Slowloris) and Thursday-01-03 (Infiltration) — see each experiment's *Five-day confirmation* |
| Five-day runs | fit on four days (200,000 training events per day, 1.2 M rows in all, as in the three-day runs), score the fifth; Friday-23-02 held out scores all its 456 attacks plus a 200,000-flow benign sample, every other day a uniform 200,000-flow sample. Results: `data/model_cache/results/five_day*.csv` |
| Unseen-attack test | **leave-one-day-out**: models fit on two days, scored on the third, whose attack family they never saw |
| Seeds | two per configuration; results shown seed 0 / seed 1 |
| When a flow is scored | **10 ms** after it starts (or at its end, if earlier) |
| Two populations, never pooled | `early` = flow still running at 10 ms (early warning possible) · `completed` = flow already over (detection only) |
| Training | autoencoders on benign flows only; normalisation fitted on benign training rows only |
| Metric | PR-AUC, tie-aware, with 100-sample bootstrap intervals; positive class = attack |
| Verdict | "better" / "worse" only when the intervals do not overlap; otherwise a tie |

---

## 1. When to score a flow: 10 ms or 100 ms

**Question.** Waiting longer gives the model more packets, but less warning. Which observation time detects better
on attacks never seen in training?

**Test.** The same models and days scored at 10 ms and at 100 ms. Anomaly score: distance to the nearest of 8 benign
k-means centres. PR-AUC ranges over seeds and the two encoder variants.

| Held out | Population | PR-AUC at 10 ms | PR-AUC at 100 ms | Recall at a 1% alert budget, 10 → 100 ms |
|---|---|---|---|---|
| Fri16 (DoS) | early | **0.870–0.925** | 0.836–0.872 | 0.027 → 0.017–0.024 |
| Bot | early | **0.735–0.793** | 0.001 | 0.29–0.33 → 0.14–0.18 |
| Web | early | **0.231–0.244** | 0.002–0.004 | 0.743 → 0.000 |
| Fri16 (DoS) | completed | **0.643–0.825** | 0.442–0.619 | 0.002–0.003 → 0.021–0.066 |
| Bot | completed | **0.901–0.937** | 0.184–0.315 | 0.92 → 0.004–0.005 |
| Web | completed | **0.020–0.051** | 0.007–0.028 | 0.14–0.38 → 0.00–0.31 |

**Result.** 10 ms is better in **22 of 24** comparisons (3 held-out days × 2 populations × 2 seeds × 2 variants),
tied in 2, worse in none. Bot finishes almost every flow before 100 ms, so its early warning window is gone by then.

**Choice.** Every flow is scored once, **10 ms** after it starts.

---

## 2. Which side of the flow the model reads

**Question.** A flow has two directions: the initiator's requests and the responder's replies. Which should the
encoder read — one side, both mixed into one sequence, or both kept apart?

**Test (unseen attacks).** The same packet-graph autoencoder trained on each input form, scored by distance to the
nearest benign mode, early population, PR-AUC seed 0 / seed 1:

| Held out | Response side | Request side | Both, mixed | Both, kept apart (split) |
|---|---|---|---|---|
| Bot | **0.793 / 0.776** | 0.357 / 0.399 | 0.120 / 0.164 | 0.466 / 0.524 |
| Fri16 (DoS) | **0.887 / 0.872** | 0.772 / 0.858 | 0.768 / 0.714 | 0.743 / 0.754 |
| Web | **0.233 / 0.234** | 0.087 / 0.061 | 0.019 / 0.011 | 0.158 / 0.164 |

Request side vs response side: worse on 6 of 6. Split vs response side: 0 better, 2 tie, 4 worse.

**Test (known attacks).** A supervised classifier (MLP, 64 hidden units) on each embedding, trained on labelled flows
of every family, scored on each day's held-out test rows (point estimates):

| | Response-side embedding | Split embedding |
|---|---|---|
| All known families, early (pooled PR-AUC) | 0.983 / 0.982 | **0.999 / 0.999** |
| DoS-Hulk, early | 0.968 / 0.963 | **0.999 / 0.999** |
| DoS-SlowHTTPTest, completed | 0.988 / 0.988 | **1.000 / 1.000** |

**Result.** For attacks never seen, the response side carries the most signal (a likely reason, not tested: an
attacker controls its requests, but not how the server has to answer). Mixing both directions into one sequence
loses information; keeping them apart recovers part of it. For attacks seen in training, the split embedding holds
the most.

**Choice.** The **unsupervised** anomaly score reads the **response side**. The **supervised** classifier reads the
**split** embedding, which is also Block 8's input (with one comparison run on the response embedding).

**Five-day confirmation.** The same comparison with each of the five days held out in turn (k-means PR-AUC, seed 0 /
seed 1):

| Held out | Early: response | Early: split | Completed: response | Completed: split |
|---|---|---|---|---|
| Fri16 (DoS) | **0.847 / 0.877** | 0.704 / 0.703 | **0.813 / 0.797** | 0.683 / 0.653 |
| Bot | **0.717 / 0.797** | 0.451 / 0.516 | **0.857** / 0.891 | 0.769 / 0.890 |
| Web | **0.383** / 0.365 | 0.243 / 0.264 | **0.099** / 0.034 | 0.046 / **0.092** |
| Thu15 (GoldenEye, Slowloris) | **0.288 / 0.279** | 0.249 / 0.160 | 0.003 / 0.003 | 0.013 / 0.003 |
| Thu01 (Infiltration) | 0.003 / 0.004 | 0.006 / **0.015** | 0.314 / 0.315 | **0.477 / 0.451** |

Bold marks the better side where the intervals do not overlap. Split vs response over the 20 comparisons: **11 worse,
5 tie, 4 better** — three of the four on Infiltration, which a response-side view sees poorly (experiment 3). Thu15
completed holds 27 attacks, too few to separate anything. On known families (classifier trained on the fit days'
labelled rows, scored on their test rows) split beats response in **20 of 20**: early 0.963–0.997 against
0.799–0.959, completed 0.917–0.979 against 0.650–0.833. **The choice stands.**

---

## 3. How alerts are raised: a classifier for known attacks, an anomaly score for unknown ones

**Question.** Can one system name known attacks and still flag attacks it has never seen — with a threshold that is
not read from the day being scored?

**Test.** On each held-out day (family unseen by both):

- **classifier**: MLP on the split embedding, trained on the other days' labelled flows, threshold from their PR curve;
- **anomaly score (A25)**: the average of four benign tail ranks — response-side k-means distance, response-side
  decoder error, |iat_mean|, direction-aware decoder error — alerting when it is in the top 1% of **benign training**
  traffic;
- **hybrid**: alert if either alerts.

Early flows (seed 0 / seed 1):

| Held out | Classifier recall | Anomaly recall | Anomaly benign alert rate | Hybrid recall | Hybrid precision |
|---|---|---|---|---|---|
| Bot | 0.166 / 0.065 | **0.988 / 0.988** | 0.84% / 0.91% | 0.988 / 0.988 | 0.730 / 0.727 |
| Fri16 (DoS) | 0.002 / 0.007 | **0.503 / 0.137** | 0.98% / 1.11% | 0.503 / 0.138 | 0.964 / 0.867 |
| Web | 0.270 / 0.257 | **0.996 / 0.765** | 1.34% / 1.33% | 0.996 / 0.765 | 0.059 / 0.046 |

Completed flows (seed 0 / seed 1):

| Held out | Classifier recall | Anomaly recall | Anomaly benign alert rate |
|---|---|---|---|
| Bot | 0.001 / 0.009 | **0.996 / 0.998** | 1.00% / 1.05% |
| Fri16 (DoS) | 0.001 / 0.001 | 0.003 / 0.003 | 1.08% / 1.02% |
| Web | 0.102 / 0.009 | **0.478 / 0.761** | 0.91% / 0.95% |

On known families the same classifier reaches pooled PR-AUC **0.999** (early), and SlowHTTPTest 1.000, Bot
0.994 / 0.989, Hulk 0.872 / 0.826 (completed) — experiment 2.

**Result.**

- The **threshold holds on unseen days**: aiming for 1% benign alerts gives 0.84–1.34%; aiming for 0.1% gives
  0.08–0.15%. No labels and nothing from the scored day are needed.
- The **classifier recognises known families almost perfectly but not unseen ones**, and it stays quiet on them
  (benign alert rate ≤ 0.35%), so it does not bury the anomaly score's alerts.
- The **anomaly score catches most unseen attacks** — nearly all of Bot, most of Web, and 14–50% of an unseen DoS
  among early flows (seed-dependent).
- **Gap:** an unseen flood of identical, already-finished connections (Fri16 completed, recall 0.003) cannot be
  separated flow by flow; it is left to Block 8, which sees many flows together.

**Choice.** Two alert arms per flow, in both populations: **classifier confident → known attack (with its family);
otherwise anomaly score over the 1% benign threshold → unknown threat; otherwise benign.**

**Five-day confirmation.** Each day held out in turn, its family unseen by both arms; early flows (seed 0 / seed 1):

| Held out | Attacks | Classifier recall | Anomaly recall | Anomaly benign alert rate | Hybrid recall | Hybrid precision |
|---|---|---|---|---|---|---|
| Bot | 3,324 | 0.011 / 0.013 | **0.989 / 0.997** | 0.83% / 0.76% | 0.989 / 0.997 | 0.729 / 0.751 |
| Web | 230 | 0.452 / 0.439 | **0.748 / 0.748** | 1.15% / 1.35% | 0.752 / 0.748 | 0.087 / 0.088 |
| Thu15 (GoldenEye, Slowloris) | 1,691 | 0.446 / 0.394 | 0.537 / 0.575 | 1.11% / 1.16% | **0.587 / 0.575** | 0.435 / 0.422 |
| Fri16 (DoS) | 46,904 | 0.045 / 0.008 | 0.134 / 0.134 | 1.15% / 1.05% | 0.156 / 0.135 | 0.875 / 0.869 |
| Thu01 (Infiltration) | 123 | 0.016 / 0.000 | 0.049 / 0.211 | 0.84% / 0.65% | 0.065 / 0.211 | 0.007 / 0.029 |

Per family, hybrid: GoldenEye 0.629 / 0.615, Slowloris 0.422 / 0.422; Brute Force -Web 0.661 / 0.661, -XSS 0.890 /
0.890, SQL Injection 0.788 / 0.758. Completed flows, anomaly recall: Bot 0.998 / 0.998, Web 0.695 / 0.420, Fri16 0.003 /
0.003, Thu01 0.020 / 0.023 (Thu15: 27 attacks). The classifier's recall on completed Infiltration swings from 0.000
(seed 0) to 0.967 (seed 1) and is not counted on.

- The **threshold holds on all five unseen days**: 0.65–1.35% benign alerts for a 1% target, both populations, both
  seeds. The classifier stays quiet on unseen traffic (≤ 0.31% benign alerts).
- The anomaly score still catches nearly all Bot and most Web, and about half of two DoS families it never saw
  (GoldenEye, Slowloris); the classifier, trained on other DoS families, adds some of them.
- **A fifth anomaly input was tested and rejected.** Adding the direction-aware model's k-means distance raised
  completed-Infiltration PR-AUC (0.287 → 0.383, 0.234 → 0.310) but made 7 of 20 PR-AUCs worse, among them Slowloris
  early recall (0.299 / 0.422 → 0.026 / 0.149) and Web early PR-AUC (0.587 / 0.553 → 0.399 / 0.300). Adding the split
  model's k-means distance made only 2 of 20 worse but left Infiltration recall at the 1% threshold unchanged (0.019 /
  0.023). Neither met the rule fixed before the test (Infiltration better on both seeds, nothing worse anywhere), so
  the anomaly score keeps its four inputs (`data/model_cache/results/five_input.py`).

---

## Known gaps

| Gap | Evidence | Where it is left |
|---|---|---|
| **Infiltration** (internal scans from a compromised host) | anomaly recall 0.049 / 0.211 early, 0.020 / 0.023 completed; the split and direction-aware embeddings separate it better (completed PR-AUC 0.45–0.55) but no single-flow score tested lifts recall without costing other families | Block 8: one internal host reaching many others is a pattern across flows (not tested) |
| **Unseen flood of finished connections** (Fri16 completed) | anomaly recall 0.003 on three and five days | Block 8, which sees many flows together |
| **Unseen DoS, early** | recall 0.134 (Fri16) to 0.575 (Thu15), seed-dependent on three days (0.137–0.503) | open |

---

## The supervised arm's protocol (current)

What replaced the arms above, and how it is measured. Code: `models/detector/head.py`, one row per day, population,
family and budget.

| | |
|---|---|
| Head | **multi-class** — one logit per family plus benign, classes weighted by inverse frequency (attack families are a fraction of a percent of the rows and the objective is recall) |
| Input | Block 7's frozen split embedding; adding Block 8's context `s` is the next arm to measure |
| Fit / calibrate / report | train split fits the head; **validation** split's benign rows set each family's threshold at the budget; test split is reported. A threshold is never read on the rows it scores |
| Budgets | **0.1%, 1%, 5%** false-positive rate, all three always reported |
| Per row | the full confusion matrix (tp, fp, fn, tn), recall, precision, realised FPR, **and the ideal at the same budget** — recall 1.0 spending the same false positives — so the distance to the ceiling is readable rather than inferred |
| Also | a multi-class confusion matrix per day: true family against the family the arm named, or "none" |
| Days | **Thursday-15** (Slowloris, GoldenEye — where the score needs lifting) and **Friday-16** (Hulk completed; also the regression guard at 0.999). The other three add nothing: Bot and Infiltration-completed have no room, Infiltration-early is unreachable at 10 ms, and Friday-23's web families need payload rather than better flow features |
| Populations | never pooled |

### First measurement (Thursday-15, seed 0)

| population | family | attacks | budget | recall | precision | ceiling precision | realised FPR |
|---|---|---|---|---|---|---|---|
| early | DoS-GoldenEye | 7,938 | 0.1% | **0.9999** | 0.944 | 0.944 | 0.0014 |
| early | DoS-GoldenEye | 7,938 | 1% | **1.000** | 0.671 | 0.671 | 0.0118 |
| early | DoS-Slowloris | 2,653 | 0.1% | **0.899** | 0.533 | 0.560 | 0.0063 |
| early | DoS-Slowloris | 2,653 | 1% | 0.903 | 0.415 | 0.440 | 0.0102 |
| completed | DoS-Slowloris | 262 | 0.1% | **0.889** | 0.869 | 0.882 | 0.0001 |
| completed | DoS-Slowloris | 262 | 1% | 0.897 | 0.098 | 0.108 | 0.0076 |

**Precision sits essentially on the ceiling in every row** — the false positives are the budget itself, not model
error. Which reframes the earlier picture: Slowloris looked like the worst family at PR-AUC 0.247–0.507 with 0.142
precision, and under the recall-first objective with a multi-class head it recalls **0.89–0.90 at a 0.1% budget**.
GoldenEye is at its ceiling and needs nothing.

The realised FPR exceeds the budget on Slowloris-early (0.0063 against 0.001), which is a **threshold-transfer** gap:
the threshold was calibrated on the validation split's benign rows and the test split's differ. That is the honest
cost of never calibrating on the reported rows, and it is worth its own experiment.
