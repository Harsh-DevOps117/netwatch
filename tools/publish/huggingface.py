"""Stage the dataset and the model for upload to a Hugging Face account.

Run: uv run python tools/publish/huggingface.py --what model --user <account>
     uv run python tools/publish/huggingface.py --what dataset --user <account> --days Friday-02-03-2018
     uv run python tools/publish/huggingface.py --stage ~/hf-staging --user <account>

Builds two self-contained folders under `huggingface/`, each with the card Hugging Face renders as its front page, then
prints the upload command. Nothing is uploaded from here: staging is separated from publishing so the contents can be
inspected, and because pushing derived data has licensing consequences (see LICENSING below).

  huggingface/model/     the servable checkpoints and what is needed to load them
  huggingface/dataset/   the derived per-event tables a model consumer needs

The staging root sits beside the source rather than inside `data/`, because it is a release artefact rather than a
pipeline output. `--stage` moves it anywhere, including outside the repository.

LICENSING. The code in this repository is MIT. **The dataset is not.** CSE-CIC-IDS2018 is distributed by the Canadian
Institute for Cybersecurity under its own terms, which require attribution and govern redistribution. Event streams,
flow embeddings and latents are derived works of it. Check those terms before making a dataset repository public, and
default to private or gated access. This tool writes `gated: true` into the dataset card for that reason.

SIZE. The full derived tree is tens of gigabytes; a single day of latents is a few hundred megabytes. `--days` selects
what to stage and the summary prints the total before anything is copied.
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

BEGIN = "<!-- BEGIN GENERATED: front matter and inventory, rewritten by tools/publish/huggingface.py -->"
END = "<!-- END GENERATED -->"

STAGE = Path("huggingface")          # release staging, not a pipeline output; override with --stage

# Files a consumer needs to load a model, in the order a reader meets them. Each is (source, purpose).
MODEL_PARTS = {
    "detector": ("the family classifier: weights, feature scaler, families, budget thresholds, serve_threshold"),
    "context_encoder": ("Block 8, frozen: link memory and neighbourhood attention"),
    "compressor": ("Block 9, frozen: the 32-wide latent and the reconstruction error"),
    "flow_encoder": ("Block 7, frozen: one embedding per flow, with its input scaler"),
}


def human(size: int) -> str:
    """A byte count as a short human-readable string.

    Input:  size in bytes
    Output: e.g. "1.4 GB"
    """
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:,.1f} {unit}"
        value /= 1024
    return f"{value:,.1f} TB"


def tree_size(path: Path) -> int:
    """Total bytes under a path, following no symlinks.

    Input:  a file or directory
    Output: size in bytes, 0 when absent
    """
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def model_card(user: str, repo: str, parts: dict[str, Path], stage: Path) -> str:
    """The README Hugging Face renders on a model repository.

    Input:  account name, repository name, the staged parts by role, the staging directory
    Output: markdown with YAML front matter

    The front matter is what makes the repository discoverable; the body is what stops it being misused. Both the
    operating point and the fact that thresholds do not survive retraining belong on the front page, not three clicks
    away.
    """
    listed = "\n".join(f"| `{name}.safetensors` | {MODEL_PARTS.get(name, 'part of the cascade')} |"
                       for name in parts)
    return f"""---
license: mit
library_name: pytorch
tags:
  - network-intrusion-detection
  - anomaly-detection
  - graph-neural-network
  - cybersecurity
---

# {repo}

A frozen cascade that names the attack family behind a network flow, from the packets visible in the
**first 10 milliseconds** of that flow.

Each stage is trained separately and frozen before the next one reads it; gradients never cross a stage boundary.

| file | what it is |
|---|---|
{listed}

## How it is put together

1. **Flow encoder** — one embedding per flow from its early packets, no network context.
2. **Context encoder** — per-link GRU memory plus attention over each endpoint's recent distinct peers.
3. **Compressor** — squeezes that context to 32 dimensions and keeps the reconstruction error.
4. **Detector** — names the family, at a chosen false-positive budget.

## Using it

Scores are only meaningful with the scalers that ship inside each checkpoint. The detector standardises its input with
the training mean and standard deviation; the compressor's latents are standardised with the training split's
statistics. **A checkpoint loaded without its scaler produces scores on a different scale, and every threshold becomes
meaningless.**

The operating point lives in the detector checkpoint's `serve_threshold` field. It is chosen deliberately, as a
judgement about acceptable alert volume, and it is **only valid for the exact model that produced it** — retrain and it
is void, not merely stale.

## What it does and does not claim

It **detects**: given a flow, it names the family. Measured on a held-out split of one day at recall 0.995 with about 14
false alarms an hour, thresholded from benign calibration data only.

It does **not** yet claim to anticipate. The lead time present in the data cannot be scored with the current train/test
split, which interleaves in wall-clock time. Nor does it claim cross-day or unseen-attacker generalisation: every
reported number is within-day.

Alerts should be aggregated before reaching a human: three consecutive events above threshold on one host, then
de-duplicated into incidents with a 60-second quiet gap. That takes the rate from thousands of alerts an hour to tens of
incidents an hour at no cost to recall.

## Training data

Derived from CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity). That dataset carries its own licence and
attribution requirements, which apply to anything derived from it.

## Upload

```bash
huggingface-cli upload {user}/{repo} {stage} . --repo-type model
```
"""


# The dataset repository is two selectable sets. A consumer picks a set, then a portion inside it, so nobody has to
# download six gigabytes of embeddings to read the event stream.
#
#   processed/  model-agnostic: the event stream and the per-flow tables. Useful with any model.
#   model/      produced BY this cascade: Block 7 embeddings and Block 9 latents. Only meaningful with it.
DATASET_SETS = {
    "processed": {
        "events": (Path("data/events"), "*.parquet",
                   "the labelled event stream, one row per flow, in availability order"),
        "flow_records": (Path("data/context_features"), "flow_records.parquet",
                         "CICFlowMeter's own columns per event, at the time the record can exist"),
        "side_features": (Path("data/context_features"), "side_features.parquet",
                          "per-event request/response features at the observation time, and who sent which side"),
    },
    "model": {
        "flow_embeddings": (Path("data/flow_embeddings"), "flow_embeddings.parquet",
                            "Block 7's 32-wide per-flow embedding; no network context"),
        "latents": (Path("data/latents"), "event_latents.parquet",
                    "Block 9's 32-wide latent z and its reconstruction error; what the world model reads"),
    },
}


def split_name(day: str) -> str:
    """A day as a Hugging Face split name.

    Input:  a day directory name, e.g. Friday-02-03-2018
    Output: the same with hyphens replaced, e.g. Friday_02_03_2018

    Split names must be word characters, so the hyphens in the dataset's day names cannot be used directly.
    """
    return day.replace("-", "_")


def dataset_front_matter(staged: dict) -> str:
    """The YAML block Hugging Face reads to expose each portion as a selectable config.

    Input:  {set: {portion: {day: [paths]}}} for what was actually staged
    Output: the front matter, as a string

    Generated rather than hand-written because it has to name the files that exist: a config pointing at absent data
    fails at load time, in the consumer's notebook, which is the worst place to find out.
    """
    lines = ["---",
             "license: other",
             "license_name: cse-cic-ids2018",
             "license_link: https://www.unb.ca/cic/datasets/ids-2018.html",
             "gated: true",
             "task_categories:",
             "  - tabular-classification",
             "tags:",
             "  - network-traffic",
             "  - intrusion-detection",
             "  - cybersecurity",
             "configs:"]
    for set_name, portions in staged.items():
        for portion, days in portions.items():
            if not days:
                continue
            lines.append(f"  - config_name: {set_name}_{portion}")
            lines.append("    data_files:")
            for day in sorted(days):
                lines.append(f"      - split: {split_name(day)}")
                lines.append(f'        path: "{set_name}/{portion}/{day}/**/*.parquet"')
    lines.append("---")
    return "\n".join(lines)


def dataset_inventory(staged: dict, sizes: dict) -> str:
    """The table of what is in the repository, by set and portion.

    Input:  the staged plan, and byte sizes keyed (set, portion)
    Output: markdown
    """
    rows = ["| set | portion | config to load | days | size |", "|---|---|---|---|---|"]
    for set_name, portions in staged.items():
        for portion, days in portions.items():
            if not days:
                continue
            rows.append(f"| `{set_name}` | `{portion}` | `{set_name}_{portion}` | {len(days)} | "
                        f"{human(sizes.get((set_name, portion), 0))} |")
    return "\n".join(rows)


def stage_model(user: str, repo: str, serve: Path, dry_run: bool, stage: Path = STAGE) -> None:
    """Copy the servable checkpoints into the staging folder and write the model card.

    Input:  account, repository name, the directory holding serving checkpoints, whether to only report, the
            staging root
    Output: none; writes <stage>/model/
    """
    out = stage / "model"
    # Each role is looked for first in the serving directory, then in the layouts the training runs actually write.
    # The newest match wins, so a fresh run is picked up without arguments.
    cache = Path("data/model_cache")
    patterns = {
        "detector": ["head*.pt", "serve/head*.pt"],
        # Both spellings: the directories written before the stages were renamed still hold real checkpoints.
        "context_encoder": ["context_encoder*/best.pt", "context/*/best.pt", "block8*/best.pt"],
        "compressor": ["compressor*/best.pt", "compressor/*/best.pt", "block9*/best.pt", "block9/*/best.pt"],
        "flow_encoder": ["flow_encoder*/*.pt", "scores/*/*.pt", "block7*/*.pt"],
    }
    found: dict[str, Path] = {}
    for role, globs in patterns.items():
        hits: list[Path] = []
        for pattern in globs:
            hits += sorted(serve.glob(pattern)) + sorted(cache.glob(pattern))
        if hits:
            found[role] = max(hits, key=lambda p: p.stat().st_mtime)
    missing = [role for role in patterns if role not in found]
    if not found:
        raise SystemExit(f"no checkpoints found under {serve} or {cache} -- run the training first "
                         f"(docs/DEPLOYMENT_RUNBOOK.md)")
    if missing:
        print("\nincomplete cascade, these roles have no checkpoint yet:", ", ".join(missing))
        print("a consumer cannot run the cascade without all four; stage anyway only to share a partial result")
    total = sum(tree_size(p) for p in found.values())
    print(f"\nmodel staging -> {out}  ({human(total)})")
    for role, path in found.items():
        print(f"  {role:18s} {human(tree_size(path)):>10s}  {path}")
    if dry_run:
        print("\ndry run: nothing copied")
        return
    out.mkdir(parents=True, exist_ok=True)
    from tools.publish.to_safetensors import convert, verify
    for role, path in found.items():
        staged_pt = out / f"{role}.pt"
        shutil.copy2(path, staged_pt)
        # Published as safetensors, not pickle: torch.load executes code while unpickling, and a public model should
        # not ask its consumers to trust the uploader. The non-tensor fields go to <role>.config.json beside it.
        convert(staged_pt, out / role)
        verify(out / role, staged_pt)
        staged_pt.unlink()
    card = out / "README.md"
    if card.exists():
        print(f"  keeping the existing card at {card}")        # hand-written; do not clobber it
    else:
        card.write_text(model_card(user, repo, found, out))
        print(f"\nwrote {card}")
    print(f"upload with:\n  huggingface-cli upload {user}/{repo} {out} . --repo-type model")


def stage_dataset(user: str, repo: str, days: list[str], include: list[str], dry_run: bool,
                  stage: Path = STAGE) -> None:
    """Lay the derived tables out as two selectable sets and refresh the card's generated block.

    Input:  account, repository name, days to stage (empty means every day found), which sets or portions to include,
            whether to only report, the staging root
    Output: none; writes <stage>/dataset/{processed,model}/<portion>/<day>/

    Copied into a per-day directory rather than flat, because Hugging Face exposes each day as a split and a consumer
    almost always wants one day rather than all of them.
    """
    out = stage / "dataset"
    wanted = set(include) if include else set(DATASET_SETS)
    staged: dict[str, dict[str, dict[str, list[Path]]]] = {}
    sizes: dict[tuple, int] = {}
    for set_name, portions in DATASET_SETS.items():
        for portion, (root, pattern, _) in portions.items():
            if wanted and set_name not in wanted and portion not in wanted and f"{set_name}/{portion}" not in wanted:
                continue
            if not root.exists():
                continue
            by_day: dict[str, list[Path]] = {}
            for path in sorted(root.rglob(pattern)):
                day = next((part for part in path.parts if part.count("-") == 3), None)
                if day is None or (days and day not in days):
                    continue
                by_day.setdefault(day, []).append(path)
                # the manifest beside a table says what produced it; tiny, and useless to omit
                for manifest in path.parent.glob("*manifest*.json"):
                    if manifest not in by_day[day]:
                        by_day[day].append(manifest)
            if by_day:
                staged.setdefault(set_name, {})[portion] = by_day
                sizes[(set_name, portion)] = sum(tree_size(f) for fs in by_day.values() for f in fs)
    if not staged:
        raise SystemExit("nothing to stage: no derived tables matched. Run the pipeline, or widen --include/--days")

    print(f"\ndataset staging -> {out}  ({human(sum(sizes.values()))})")
    for set_name, portions in staged.items():
        for portion, by_day in portions.items():
            files = sum(len(v) for v in by_day.values())
            print(f"  {set_name}/{portion:16s} {human(sizes[(set_name, portion)]):>10s}  "
                  f"{files} files across {len(by_day)} day(s) -> config {set_name}_{portion}")
    if dry_run:
        print("\ndry run: nothing copied")
        return

    for set_name, portions in staged.items():
        for portion, by_day in portions.items():
            for day, files in by_day.items():
                for src in files:
                    target = out / set_name / portion / day / src.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if src.suffix == ".json" and target.exists():
                        continue
                    shutil.copy2(src, target)
    refresh_dataset_card(out, {s: {p: list(d) for p, d in ps.items()} for s, ps in staged.items()}, sizes)
    print(f"upload with:\n  huggingface-cli upload {user}/{repo} {out} . --repo-type dataset --private")


def refresh_dataset_card(out: Path, staged: dict, sizes: dict) -> None:
    """Rewrite only the generated part of the dataset card, leaving the written explanation alone.

    Input:  the dataset staging directory, the staged plan, sizes by (set, portion)
    Output: none; rewrites <out>/README.md between its markers

    The front matter and the inventory must match the files present, so they are generated. Everything else -- what a
    row is, which columns are evaluation only, why the splits interleave -- is prose that a tool should never touch.
    """
    card = out / "README.md"
    generated = dataset_front_matter(staged) + "\n\n" + dataset_inventory(staged, sizes) + "\n"
    if not card.exists():
        card.write_text(f"{BEGIN}\n{generated}{END}\n")
        print(f"  wrote a new card at {card}; add the explanation below the markers")
        return
    text = card.read_text()
    if BEGIN not in text or END not in text:
        print(f"  {card} has no generated block; leaving it untouched")
        return
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    card.write_text(f"{head}{BEGIN}\n{generated}{END}{tail}")
    print(f"  refreshed the generated block in {card}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--what", choices=("model", "dataset", "both"), default="both")
    parser.add_argument("--user", default="<your-account>", help="Hugging Face account, for the printed commands")
    parser.add_argument("--model-repo", default="netwatch-flow-cascade")
    parser.add_argument("--dataset-repo", default="netwatch-ids2018-events")
    parser.add_argument("--serve", type=Path, default=Path("data/model_cache/serve"),
                        help="directory holding the checkpoints written by the --save flags")
    parser.add_argument("--days", nargs="*", default=[], help="limit the dataset to these days (default: all found)")
    parser.add_argument("--include", nargs="+", default=[],
                        choices=["processed", "model", "events", "flow_records", "side_features",
                                 "flow_embeddings", "latents"],
                        help="a whole set (processed, model) or single portions. Default: everything found. "
                             "flow_embeddings is the largest portion by far")
    parser.add_argument("--stage", type=Path, default=STAGE,
                        help="where to build the upload folders. Defaults to huggingface/ beside the source; it may "
                             "point outside the repository")
    parser.add_argument("--dry-run", action="store_true", help="report what would be staged, copy nothing")
    args = parser.parse_args(argv)
    args.stage.mkdir(parents=True, exist_ok=True)
    if args.what in ("model", "both"):
        stage_model(args.user, args.model_repo, args.serve, args.dry_run, args.stage)
    if args.what in ("dataset", "both"):
        stage_dataset(args.user, args.dataset_repo, args.days, args.include, args.dry_run, args.stage)
    print("\nReminder: the dataset is a derived work of CSE-CIC-IDS2018 and carries its terms, not this repo's MIT "
          "licence. The dataset card is gated by default.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
