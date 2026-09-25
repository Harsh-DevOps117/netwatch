# `tools` — scripts, grouped by what they are for

**Nothing here runs in deployment.** The serving path is `models/serving`; the reported metric set is
`models/evaluation`. These are scripts you run by hand, and they are grouped so it is obvious which ones you need.

```
tools/
  dataset/       one-time preparation of the raw archives
  measure/       answering a specific question about a trained model
  repo/          keeping the repository honest
  publish/       staging artefacts for release
  world_model/   the Block 10 proxy's measurement tools (kept local, see below)
```

## `dataset/` — preparing the archives

| file | role |
|---|---|
| `extract_zip.py` | Extracts a distributed archive without filling memory, safe to stop and resume. Each file streams to `<name>.part`, its CRC-32 is checked as it is written, and it is renamed only when complete, so an interrupted run never leaves a truncated file under a final name. |
| `verify_extract.py` | Reads every extracted file end to end and compares it with the CRC-32 stored in the archive, naming any file that is truncated, missing or altered. |

You need these when adding days. They are not dead: the pipeline is built for ten days and five are ingested.

## `measure/` — one question each

| file | question |
|---|---|
| `baseline.py` | How does the logistic-regression baseline named in the problem statement compare, on the same rows? |
| `campaign_coverage.py` | At a given threshold, are whole campaigns missed, or only scattered flows inside campaigns already caught? |
| `lead_ceiling_days.py` | How much warning does each day contain at all, before any model? Ground truth only, no model, no latents. |
| `supervised_economics.py` | The detection head on operational axes: alerts per hour, and incidents rather than events. |

`baseline.py` **must** receive the same `--events` and `--family` as whatever it is compared against, or the
positive rate differs and even PR-AUC is not comparable.

For choosing an operating point, use `python -m models.evaluation.thresholds`. It lives in the evaluation package rather
than here, because `models/evaluation/report.py` imports its sweep — a shipped module must not depend on a scripts
folder.

## `repo/` — upkeep

| file | role |
|---|---|
| `verify_contracts.py` | Traces every checkable claim in `docs/*.json` to the code and data implementing it. Run after changing a schema, a CLI or a checkpoint format. Reports pass, skip and fail separately: a claim about something kept local or about `data/` is skipped, not failed. |
| `render_field_reference.py` | Regenerates the field-by-field tables in the contract documents from their JSON. |

CI runs `verify_contracts.py` on every push.

## `publish/` — releasing artefacts

| file | role |
|---|---|
| `huggingface.py` | Stages `huggingface/model/` and `huggingface/dataset/`, each with the card Hugging Face renders, and prints the upload command. Finds the artefacts, copies them and lays out the directories itself — nothing is placed by hand. Staging is separate from uploading on purpose, so the contents can be inspected first. `--stage` moves the staging root anywhere, including outside the repository. |
| `to_safetensors.py` | Converts a checkpoint to safetensors plus a JSON config, verifying every tensor is bit-identical first. **Called automatically by `huggingface.py --what model`**; run it directly only for a checkpoint outside the directories that search covers. |

```bash
uv run python tools/publish/huggingface.py --dry-run --user <account>
uv run python tools/publish/huggingface.py --what model --user <account>
uv run python tools/publish/huggingface.py --what dataset --user <account> --days Friday-02-03-2018
```

Full instructions, and what each release contains: [`docs/PUBLISHING.md`](../docs/PUBLISHING.md).

**The dataset is not MIT.** CSE-CIC-IDS2018 carries its own terms from the Canadian Institute for Cybersecurity, and
event streams, embeddings and latents are derived works of it. The generated dataset card is `gated: true` for that
reason. Read those terms before making a dataset repository public.

## `world_model/` — not in this repository

Four tools that import the Block 10 proxy (`models/world_model_proxy`) and are kept local with it: `alert_economics.py`,
`fpr_levers.py`, `threshold_rules.py`, `leave_attackers_out.py`. The proxy settled Block 10's design questions on slices
and is not the deliverable, so it is not published beside the shipped stages; the tools that read its model travel with
it. What they produced is recorded in `docs/TESTS.md` and `docs/world_model.md`.

## Running

Everything takes `--help` and runs through the project environment:

```bash
uv run python tools/repo/verify_contracts.py
uv run python tools/measure/lead_ceiling_days.py --out data/model_cache/results/lead_ceilings.csv
```
