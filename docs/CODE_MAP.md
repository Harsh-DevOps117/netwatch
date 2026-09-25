# Code map — one package per stage

Written 2026-09-21. Stage numbers ("Block 8") are how the problem statement refers to them; the **names** below are what
the code uses. No folder or file is named after a block number.

| stage | package | what it does | CLI |
|---|---|---|---|
| Block 7 | `models/flow_encoder/` | one embedding per flow from its first 20 packets inside a 10 ms budget | `-m models.flow_encoder` |
| Block 8 | `models/context_encoder/` | per-link memory + neighbourhood attention → the context vector `s` | `-m models.context_encoder` |
| Block 9 | `models/compressor/` | autoencodes `s` into `z` (32-wide) plus a reconstruction error | `-m models.compressor` |
| Block 10 | `models/world_model_proxy/` *(local only)* | per-key state, learned dynamics, rollout read-out | `-m models.world_model_proxy` |
| — | `models/detector/` | **the main line**: names the attack family at a chosen budget | `-m models.detector` |
| — | `models/evaluation/` | every metric we report, in one place | `-m models.evaluation` |
| — | `models/explanation/` | attention activations + input attribution | `-m models.explanation` |
| — | `models/serving/` | live traffic: incremental graph, incremental alerting | (library) |
| — | `models/runtime.py` | backend flags: determinism by default, opt-in speed | (library) |
| — | `models/training.py` | shared trainer machinery: TensorBoard, LR schedules, resume | (library) |
| — | `models/data/` | shared input plumbing, not a stage | (library) |
| — | `ingest/` | PCAP → events, offline | `-m ingest.cli` |

Every package now has the same shape: `train.py` for the objective, `__main__.py` for the CLI, and its own modules
beside them. Block 8's and Block 9's training loops were previously buried inside their CLI — that is what made them
hard to find — and are now where `models/flow_encoder/train.py` always was.

---

## `ingest/` — PCAP to events

| file | role |
|---|---|
| `cli.py` | entry point |
| `pipeline.py` | per-capture orchestration |
| `sources/packets.py` | PCAP → packet parquet (tshark) |
| `sources/flows.py` | CICFlowMeter records, labels, the UTC offset |
| `sources/schedule.py` | attack schedule, label config version |
| `build/join.py` | joins flows to packets, builds edges |
| `build/events.py` | the event stream, **and the ip → node id map** |
| `build/nodes.py` | per-window host features |
| `verify/checks.py` | post-ingest audits, `python -m ingest.verify <day>` |

Three folders in the order data moves: `sources/` turns raw captures into parquet, `build/` derives the event graph,
`verify/` audits the result.

## `models/data/` — shared plumbing

| file | role |
|---|---|
| `inputs.py` | loads packets and aggregates; `normalise()` is the **input scaler** |
| `prefix.py` | `observe()`: cuts each flow at the 10 ms budget, sets `t_obs` and population |
| `splits.py` | three split modes and a coverage report — see below. Runnable: `python -m models.data.splits` |
| `batching.py` | padded packet batches |

### Splits, and which mode to use

`python -m models.data.splits` prints per-family coverage for every ingested day and exits non-zero if any family is
missing a split.

| mode | guarantees | use for |
|---|---|---|
| `stratified` | every family reaches train, val and test | **the default for detection** |
| `segment` | attack rows in every split, by clock fraction | reproducing earlier results only |
| `chronological` | no wall-clock interleaving | nothing on a single day — it leaves every family with no test rows |

`segment` was the original and it silently starved two families: DoS-Hulk's 1,843,441 rows all fall in the first 802 s
of a 2,040 s window so a 60%-of-clock cut put every one in train, and Friday-23's 780 s window has a validation band
smaller than the 120 s embargo. `stratified` cuts by rank within each family instead, which fixes both.

## `models/flow_encoder/` — Block 7

| file | role |
|---|---|
| `__main__.py` | CLI: fit, score a held-out day, export. Saves the **input scaler** with the weights |
| `train.py` | the fitting loop, early stopping, `embed()` |
| `encoder.py` | the packet reader and the autoencoder |
| `export.py` | writes `flow_embeddings.parquet` + manifest (carries a normalisation fingerprint) |
| `metrics.py` | tied-rank average precision, anomaly score |

## `models/context_encoder/` — Block 8

| file | role |
|---|---|
| `__main__.py` | CLI: the day loop, checkpointing |
| `train.py` | **the objective**: `LinkPredictor`, `run_stream`, `negative_receivers`, `link_ap` |
| `model.py` | `ContextEncoder`, `LinkMemory` (TTL + LRU cap), `LinkIds`, attention capture |
| `stream.py` | `NeighbourIndex`, `availability_order` — the offline graph index |
| `data.py` | `load_day`, `make_stream`, `attack_slice`, `DAYS` |
| `features.py` | per-event side features at the observation time |
| `records.py` | the CICFlowMeter record as a message, and its frozen encoder |
| `record_arm.py` | the records-only cascade on the records' own timeline |

## `models/compressor/` — Block 9

| file | role |
|---|---|
| `__main__.py` | CLI shim |
| `train.py` | **the objective**: `run_block9`, Block 8 frozen throughout |
| `latents.py` | loading (`frozen_block8`, `context_vectors`), scoring, and the `event_latents.parquet` export |
| `autoencoder.py` | the autoencoder modules |

## `models/world_model_proxy/` — Block 10, as a proxy

| file | role |
|---|---|
| `__main__.py` | CLI shim |
| `model.py` | `WorldModel` (state table, `step`, `imagine`), the run loop, `save_world_model` / `load_world_model` |

Named *proxy* deliberately: it settles design questions cheaply (what to key on, chunk width, thresholding) and its
numbers are measured on slices. The real Block 10 is Vedant's.

## `models/detector/` — the main line

Split by concern, as the other packages are. `head.py` used to hold all 510 lines of it.

| file | role |
|---|---|
| `__main__.py` | CLI shim |
| `train.py` | `run_day`: fit on a day, calibrate, report at each budget |
| `model.py` | `Head`, `train_head`, `class_scores`, `family_codes`, `budget_threshold`, and `BENIGN` — the class order |
| `features.py` | `load_features`, and the reconstruction-error gate measured against it |
| `checkpoint.py` | `save_head` / `load_head` / `save_calibration` — everything a serving process reads |
| `report.py` | `cost_of_recall`, `confusion`, `report`, `multiclass_matrix` |

## `models/evaluation/` — every metric, one place

| file | role |
|---|---|
| `report.py` | tied-rank PR-AUC, Brier/ECE, the operating-point sweep, the emission funnel, the population split |
| `thresholds.py` | budget → threshold sweep, and committing the chosen point into a checkpoint |
| `blocks.py` | **per-stage** evaluation: each block against its own objective, so a change can be attributed |

Replaces reading numbers out of a dozen experiment scripts. `tools/collect_final.py` still exists but only knows how to
gather the seven final experiments by number; this one works for any trained model.

## `models/explanation/` — why it said what it said

| file | role |
|---|---|
| `attention.py` | attention activations over the neighbourhood, and gradient×input attribution split into flow vs context |

The context encoder already computed an attention distribution over each event's neighbourhood and threw it away
(`need_weights=False`). It is now capturable via `encoder.explain = True`, which is **verified to leave the encoding
bit-identical** — turning explainability on cannot change a verdict.

## `models/serving/` — live traffic

| file | role |
|---|---|
| `graph.py` | `NodeRegistry`, `LinkRegistry`, `OnlineNeighbours`, `LastSeen`, `ReorderBuffer` |
| `emitter.py` | `AlertEmitter` (threshold → persist-3 → incident), `Recalibrator` |
| `cascade.py` | every stage loaded once and chained in memory — no file round-trip per event |

## `tools/` — measurement, never deployment

| folder | purpose |
|---|---|
| `tools/dataset/` | preparing the raw archives: `extract_zip.py`, `verify_extract.py` |
| `tools/measure/` | one question each: `baseline.py`, `campaign_coverage.py`, `lead_ceiling_days.py`, `supervised_economics.py` |
| `tools/repo/` | upkeep: `verify_contracts.py`, `render_field_reference.py` |
| `tools/publish/` | `huggingface.py` — stages the model and dataset repositories with their cards |
| `tools/world_model/` *(local only)* | the proxy's measurement tools, kept with it |

Removed: `collect_final.py`, which gathered the seven final experiments by index and is superseded by
`models/evaluation` working on any trained model. `find_threshold.py` moved to `models/evaluation/thresholds.py`,
because `report.py` imports its sweep and a shipped module must not depend on a scripts folder.

---

## What moved, and what it was called before

| was | now |
|---|---|
| `ingest/{packets,flows}.py`, `ingest/config/` | `ingest/sources/` |
| `ingest/{derive,events,nodes}.py` | `ingest/build/` |
| `ingest/verify.py` | `ingest/verify/checks.py` |
| `models/context/` | `models/context_encoder/` |
| `models/context/block9.py` | `models/compressor/latents.py` + `models/compressor/train.py` |
| `models/context/autoencoder.py` | `models/compressor/autoencoder.py` |
| `models/supervised.py` | `models/detector/head.py` |
| `models/world_model.py` | `models/world_model_proxy/model.py` |
| `models/emitter.py` | `models/serving/emitter.py` |
| `models/online.py` | `models/serving/graph.py` |
| training loop inside `models/context/__main__.py` | `models/context_encoder/train.py` |

Old CLI paths no longer exist. `python -m models.context`, `python -m models.context.block9` and
`python models/supervised.py` are now `-m models.context_encoder`, `-m models.compressor` and `-m models.detector`.
253 tests, nine module self-checks and 51 contract checks pass after the move.

## Kept out of the repository

`models/world_model_proxy/` is git-ignored, together with its test and the four tools that import it
(`tools/{alert_economics,fpr_levers,threshold_rules,leave_attackers_out}.py`). It is a proxy: it settled the design
questions for Block 10 on slices and is not the deliverable, so publishing it beside the shipped stages would
misrepresent it. The contract it reads — `event_latents.parquet` from the compressor — is documented in
`docs/vedant.json`, and its results are in `docs/world_model.md`.

Tracking those tools without the package would leave a clone that fails on import, which is why they travel together.

## Tests — local only

`/tests/` is git-ignored: the suite is not published. What a clone can run instead is the per-module self-check each
stage carries, plus `tools/repo/verify_contracts.py`; the workflow skips its pytest step when `tests/` is absent.

The layout below is what exists locally.

Ten files, one per package, mirroring the source layout. Consolidated from twenty on 2026-09-21; the test count was
unchanged by that merge (244), because nothing was dropped -- only regrouped.

| file | covers |
|---|---|
| `tests/models/test_data.py` | the observation budget, the splits, batching, array loading |
| `tests/models/test_flow_encoder.py` | Block 7 and its ranking metrics |
| `tests/models/test_context_encoder.py` | Block 8: link memory, attention, the stream index, flow messages |
| `tests/models/test_compressor.py` | Block 9 on a frozen Block 8 |
| `tests/models/test_detector.py` | the detection head |
| `tests/models/test_world_model_proxy.py` *(local only)* | the Block 10 proxy |
| `tests/models/test_serving.py` | the incremental graph, the emitter, the threshold sweep |
| `tests/models/test_reporting.py` | the reported metrics, attention activations, attribution |
| `tests/ingest/test_labels.py` | label matching and the attack schedule |
| `tests/ingest/test_pipeline_e2e.py` | ingest end to end |

A single test root, `tests/`, mirroring the source layout — previously two roots (`models/tests/` and
`ingest/tests/`) with tests importing helpers from one another. Shared fixtures live in `tests/conftest.py`.

The suite is CPU-only and needs no dataset: every test builds its own fixtures, and it runs in about 13 seconds, so
there is no reason to skip it locally. `.github/workflows/tests.yml` runs it when present, then the nine module
self-checks, the contract verifier and a `--help` on every entry point — those three work with or without the suite.

Function names still carrying a block number (`frozen_block8`, `run_block9`, `--block8`, `--block9`) were left alone
deliberately: renaming a CLI flag would silently break every shell script and doc command that passes it. Rename them
in one pass when you next break compatibility, not now.
