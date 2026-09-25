# NetWatch — early network intrusion detection from the first 10 milliseconds of a flow

Names the attack family behind a network flow using only the packets visible in its **first 10 milliseconds** — not
after the flow has finished and its full statistics are known.

Most intrusion detection on CSE-CIC-IDS2018 classifies a completed flow record. That is a useful benchmark and a poor
description of the job: by the time a flow has finished, whatever it was going to do has happened. This system commits to
a decision while the flow is still open, and it is built and measured under that constraint throughout.

Two things follow from it, and both shape the design:

- **A flow alone is not enough evidence at 10 ms.** So each event is read together with its context: what this link has
  been doing, and what the hosts at each end have been doing with everyone else.
- **Time is never binned.** One event per flow, ordered by the microsecond timestamp at which it became observable. No
  fixed windows anywhere.

## What it achieves

One run, one held-out split, so the rows are comparable: the Bot day, seed 0, 558,504 benign test rows spanning
0.72 hours. **Every threshold is a quantile of benign calibration scores** — none is chosen using test labels.

You pick a false-positive budget; the threshold and its cost follow:

| budget | threshold | recall | false alarms/hour |
|---|---|---|---|
| 0.1% | 0.0621 | **1.0000** | 916 |
| 0.003% | 0.9323 | **0.9961** | 28.0 |
| 0.001% | 0.9793 | 0.9906 | **8.4** |

Threshold-free, so it cannot be flattered by a lucky operating point: **PR-AUC 0.99997** with ties collapsed.
Calibration: Brier 0.00016, ECE 0.00053 — a probability shown to an analyst means what it says.

Against the logistic-regression baseline the problem statement names, on identical rows: **1.000 vs 0.926** PR-AUC, and
the baseline collapses to 0.0003 at tight thresholds. No leakage: prefix-invariance holds exactly and permuted labels
score 0.0000.

**What an operator sees is not the alarm count.** At the 0.001% point, 16,241 events clear the threshold, 15,409 survive
a three-consecutive-events test on the same host, and those collapse into **21 incidents — 29.4 per hour** — with all 10
attacking hosts alerted and every one of the 16,389 attack events on an alerting host. The two aggregation stages cost
nothing in recall; they are the cheapest large improvement anywhere in the system.

### What it does not claim

Stated plainly, because these are the questions a reviewer should ask:

- **Not cross-day, and not unseen attackers.** Every number above is within-day: train and test come from the same day's
  traffic. Cross-day transfer has not been run.
- **Not anticipation.** The data does contain hours of lead before a host's first attack, but it cannot be scored with
  the current train/test split, which interleaves in wall-clock time. No lead-time claim is made in seconds.
- **Absolute alarm rates are slice-conditioned.** They were measured on a contiguous 3M-event slice, which calibrates on
  fewer benign rows than a full day.

`docs/DEPLOYMENT_RUNBOOK.md` section 8 gives the evidence for each.

## How it works

Five stages. Each is trained separately and frozen before the next reads it — **gradients never cross a stage
boundary**, which keeps every stage's contribution attributable.

```
packet captures
      │  ingest/          one event per flow, labelled, in availability order
      ▼
  flow encoder            32-wide embedding from a flow's first packets, no context
      │
      ▼
 context encoder          per-link GRU memory + attention over each endpoint's recent peers
      │
      ├──────────────►  detector          names the family, at a chosen budget   ◄── the main line
      ▼
   compressor             32-wide latent + reconstruction error
      │
      ▼
   world model            per-key dynamics; what is coming, in events
```

The **detector** is the deployable line today. The world model is developed separately against the compressor's
`event_latents.parquet` contract.

## Quick start

```bash
uv sync                                    # creates .venv here

# Every stage carries an assert-based self-check that needs no dataset and no GPU.
uv run python models/runtime.py
uv run python models/serving/graph.py          # the online graph, checked against the offline index
uv run python models/serving/emitter.py        # the alert rules
uv run python models/serving/cascade.py        # the chain, in memory
uv run python -m models.evaluation --demo
uv run python -m models.evaluation.blocks --demo
uv run python -m models.explanation --demo
uv run python tools/repo/verify_contracts.py   # docs/*.json traced to the code
```

The `pytest` suite is kept out of this repository; the self-checks above are what a clone can run.

Build a day, then audit it:

```bash
uv run python -m ingest.cli    --days <day> --workers 4   # captures -> parquet; a SKIP line per rejected file
uv run python -m ingest.verify <day>                      # audit: offset, labels, captures, packets
uv run python -m ingest.build.events <day>                # the event stream
uv run python -m ingest.verify <day>                      # audit again: now includes the events check
```

Move to the next day only when the second `verify` ends in `RESULT: PASS`. `<day>` is a directory under `data/raw/`,
e.g. `Friday-16-02-2018`.

Train, choose an operating point, and report:

```bash
uv run python -m models.detector --days <days> --block8 <ctx>/best.pt \
    --save data/model_cache/serve/head.pt --save-scores data/model_cache/serve/scores.pt

uv run python -m models.evaluation.thresholds --scores <scores.pt> --recall-floor 0.995 --write <head.pt>
uv run python -m models.evaluation --scores <scores.pt>
```

Full build order for every stage, with the settings to choose and why:
**[`docs/DEPLOYMENT_RUNBOOK.md`](docs/DEPLOYMENT_RUNBOOK.md)** — read its IMPORTANT section first.

## Repository layout

One package per stage, each with its own README covering purpose, files, inputs and outputs, the settings that matter and
the traps specific to it.

| package | stage | what it produces |
|---|---|---|
| [`ingest`](ingest/README.md) | captures → events | the labelled event stream |
| [`models/data`](models/data/README.md) | shared plumbing | the 10 ms observation budget, the splits |
| [`models/flow_encoder`](models/flow_encoder/README.md) | flow encoder | one embedding per flow |
| [`models/context_encoder`](models/context_encoder/README.md) | context encoder | link memory and neighbourhood attention |
| [`models/compressor`](models/compressor/README.md) | compressor | a 32-wide latent and a reconstruction error |
| [`models/detector`](models/detector/README.md) | **detection head** | the family, at a chosen budget |
| [`models/evaluation`](models/evaluation/README.md) | — | every reported metric, one command |
| [`models/explanation`](models/explanation/README.md) | — | attention activations and input attribution |
| [`models/serving`](models/serving/README.md) | — | the incremental graph and the alert decision |
| [`tools`](tools/README.md) | — | measurement, comparison, upkeep, release |

File-by-file map: [`docs/CODE_MAP.md`](docs/CODE_MAP.md).

## Explainability

The problem statement asks for it, and the context encoder was already computing the answer and discarding it: an
attention distribution over each event's neighbourhood. `models/explanation` reads it out, alongside a gradient×input
attribution that separates what came from the flow itself from what came from its context.

Capture is opt-in and verified to leave the encoding **bit-identical**, so enabling explainability cannot change a
verdict.

## Requirements

Python 3.12 via `uv`. Two external tools are not installable from PyPI and must be present for ingest:

| tool | used by | install |
|---|---|---|
| `tshark`, `editcap` | `ingest/sources/packets.py` | `apt install tshark` |
| `java` + CICFlowMeter | `ingest/sources/flows.py` | bundled under `tools/` |

Ingest fails with a clear error if either is missing. Nothing after ingest needs them, and the test suite needs neither.

> `psutil` is a hard dependency and should stay one. Its import is guarded, but without it the check that stops workers
> launching when RAM is short returns `True` unconditionally and the guard disappears silently.

A CUDA GPU is optional. Everything runs on CPU; `models/runtime.py` defaults to the reproducible backend
configuration, and speed options that change results in the last bits are opt-in.

## Documentation

| document | contents |
|---|---|
| [docs/DEPLOYMENT_RUNBOOK.md](docs/DEPLOYMENT_RUNBOOK.md) | Build order, the settings to choose, validation, and what must not be claimed |
| [docs/CODE_MAP.md](docs/CODE_MAP.md) | Which file belongs to which stage |
| [docs/PUBLISHING.md](docs/PUBLISHING.md) | Staging the model and dataset for Hugging Face, and what each release contains |
| [docs/design.md](docs/design.md) | Block-by-block architecture, maths, complexity, per-block verification |
| [docs/data-reference.md](docs/data-reference.md) | Every column of every artefact, and how to join them |
| [docs/TESTS.md](docs/TESTS.md) | The experiment record: what was measured, and what failed |
| [docs/LABELING_VERIFICATION.md](docs/LABELING_VERIFICATION.md) | Label audit and change log |
| [docs/yug.json](docs/yug.json) | Live sensor contract: the three message kinds, their fields, units, availability times |
| [docs/vedant.json](docs/vedant.json) | Compressor → world model handoff: every latent column, and what must never be an input |
| [docs/dev.json](docs/dev.json) | API surface for the frontend, backend and CLI |

## Licence

The code is MIT — see [LICENSE](LICENSE).

**The dataset is not.** CSE-CIC-IDS2018 is distributed by the Canadian Institute for Cybersecurity under its own terms,
which require attribution and govern redistribution. Event streams, embeddings and latents produced here are derived
works of it. Check those terms before publishing any of them; `tools/publish/huggingface.py` marks the dataset card as
gated for this reason.
