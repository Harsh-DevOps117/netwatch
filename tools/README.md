# `tools` — scripts run by hand

Nothing here runs in deployment: serving is `models/serving`, and the reported metrics come from `models/evaluation`.

```
tools/
  train_all.sh   trains every stage in order (docs/training.md)
  promote.py     copies a finished run's best models into artifacts/current
  dataset/       preparing the raw dataset archives
  measure/       answering one question about a trained model
  publish/       staging models and data for Hugging Face
  live/          StreamMeter.java (the lag service's flow meter) and stream_check.py (its equivalence check),
                 detect_check.py (the live detector against training), pcap_from_packets.py (captures rebuilt from a day)
  setup_cicflowmeter.sh   fetches (git submodule, pinned), patches and builds tools/CICFlowMeter; run once after cloning
  repo/          repository checks
```

## `dataset/`

| file | role |
|---|---|
| `extract_zip.py` | extracts a large archive without filling memory, and can be stopped and resumed: each file is written to `<name>.part`, its CRC-32 checked while writing, and renamed only when complete |
| `verify_extract.py` | reads every extracted file and compares it with the CRC-32 in the archive, naming any file that is truncated, missing or altered |

Needed when adding dataset days.

## `measure/`

| file | question |
|---|---|
| `baseline.py` | how does a logistic-regression baseline compare, on the same rows? |
| `campaign_coverage.py` | at a given threshold, are whole campaigns missed, or only scattered flows inside campaigns that are caught? |
| `lead_ceiling_days.py` | how much warning does each day contain before any model — from the ground truth alone |
| `supervised_economics.py` | the detector in operational terms: alerts and incidents per hour |
| `forecast_lead.py` | are a trained world model's predicted links still in the future when a service with a given lag serves them? |
| `world_model_accuracy.py` | the world model's accuracy on its two training tasks: ranking top-1 / hit@3 / MRR among the quiz's candidates, next-event AUC |
| `forecast_beam.py` | keeping the top 1-3 hosts at every rollout step: is the attacker's real next victim on the list, and are the path probabilities calibrated? |
| `forecast_candidates.py` | the attacker's next new victim ranked by the world model over the served pool, all hosts, a retrieved pool and an address prior, against recency and popularity |
| `average_checkpoints.py` | one world model averaged over several saved epochs of a run, to compare with the single best epoch |

`baseline.py` must receive the same `--events` and `--family` as whatever it is compared with, or the positive rate
differs and not even PR-AUC is comparable. To choose the detector's operating point, use
`python -m models.evaluation.thresholds`.

## `publish/`

| file | role |
|---|---|
| `huggingface.py` | stages `artifacts/huggingface/model/` and `artifacts/huggingface/dataset/` from `artifacts/current` (or `--bundle <run>`), with the cards Hugging Face shows, and prints the upload command; staging is separate from uploading so the contents can be checked first |
| `to_safetensors.py` | converts a checkpoint to safetensors plus a JSON config after checking every tensor is bit-identical; `--to-pt` converts back. Called by `huggingface.py --what model` |
| `download.py` | downloads a published model into `artifacts/huggingface/download/<repo>/` and rebuilds it as servable `.pt` files with a `serving.json` |

```bash
uv run python tools/publish/huggingface.py --what model   --user <account> --detector-day <day> --dry-run
uv run python tools/publish/huggingface.py --what dataset --user <account>
uv run --with huggingface_hub python tools/publish/download.py --repo <account>/netwatch-flow-cascade
```

Full instructions: [docs/publishing.md](../docs/publishing.md). **The dataset is not MIT**: CSE-CIC-IDS2018 has its own
terms, and the event tables, embeddings and latents are derived from it, so the dataset card is gated.

## `repo/`

| file | role |
|---|---|
| `verify_contracts.py` | checks that the modules, functions and settings the pipeline relies on exist; run by CI on every push |
| `verify_docs.py` | checks that every published document's links, repository paths, `python -m` commands and their options exist |
| `render_field_reference.py` | regenerates field tables for internal reference documents; does nothing when they are absent |

Every script takes `--help` and runs through the project environment, for example
`uv run python -m tools.repo.verify_contracts`.
