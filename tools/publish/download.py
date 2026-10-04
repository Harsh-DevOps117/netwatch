"""Download the published model, and optionally the dataset, from Hugging Face into artifacts/huggingface/download/.

Usage:  uv run --with huggingface_hub python tools/publish/download.py --repo <account>/netwatch-flow-cascade
        uv run --with huggingface_hub python tools/publish/download.py --dataset <account>/netwatch-ids2018-events \
            --sets processed model [--days Friday-02-03-2018 ...] [--revision v1.0.0]

The dataset is fetched set by set (`processed`, `model`, as its card describes) and day by day, into
artifacts/huggingface/download/<dataset name>/ in the repository's own layout: <set>/<portion>/<day>/*.parquet.

Before either download, the repository's access is checked. A public, ungated repository is pulled as it is. A gated or
private one needs a Hugging Face login: if this machine has none, the tool asks for it (or, when it cannot ask, says how
to log in) instead of failing with a traceback, and it says so when the account has not accepted the repository's terms.

artifacts/huggingface/download/<repo name>/ after a download:
    *.safetensors, *.config.json, README.md, ...   the repository exactly as published
    flow_encoder.pt  detection_encoder.pt  forecasting_encoder.pt  record_encoder.pt  compressor.pt  world_model.pt
    live_compressor.pt  live_world_model.pt        when the repository has the live tag's pair
    detector/head_<day>.pt                         every published head, as artifacts/current names them
    detector.pt                                    the head the inference endpoint serves
    serving.json                                   paths relative to this folder, like artifacts/current (lag, and live
                                                   when its pair is there)

The .pt files are rebuilt locally from the safetensors (bit-exact), because the repository's loaders read .pt. To serve
the download instead of a local training run:
    uv run python -m models.serving.live --registry artifacts/huggingface/download/<repo name>/serving.json ...
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from models.serving.registry import write  # noqa: E402
from tools.publish.to_safetensors import unflatten  # noqa: E402

DOWNLOADS = ROOT / "artifacts" / "huggingface" / "download"
# published role -> the file name artifacts/current uses for it
NAMES = {"flow_encoder": "flow_encoder.pt", "context_encoder": "detection_encoder.pt",
         "world_model_context_encoder": "forecasting_encoder.pt", "record_encoder": "record_encoder.pt",
         "compressor": "compressor.pt", "world_model": "world_model.pt", "detector": "detector.pt",
         "live_compressor": "live_compressor.pt", "live_world_model": "live_world_model.pt"}


LOGIN = "uvx --from huggingface_hub hf auth login"


def ensure_access(repo: str, repo_type: str = "model") -> None:
    """Make sure this machine may fetch `repo` before a download starts.

    Input:  <account>/<name>, "model" or "dataset"
    Output: None when the download can go ahead; otherwise the process exits with what to do, not a traceback

    A public, ungated repository needs nothing. A gated or private one needs a login: without one the user is asked to
    log in here when there is a terminal to ask on, and told the command when there is not.
    """
    from huggingface_hub import HfApi, get_token, login
    from huggingface_hub.errors import GatedRepoError, HfHubHTTPError, RepositoryNotFoundError

    api = HfApi()
    page = f"https://huggingface.co/{'datasets/' if repo_type == 'dataset' else ''}{repo}"
    try:
        if not api.repo_info(repo, repo_type=repo_type, token=False).gated:
            return                                        # public and ungated: anyone may pull it
        why = "gated"
    except RepositoryNotFoundError:                       # what an anonymous request to a private repository gets
        why = "private, or does not exist"
    if get_token() is None:
        print(f"{repo} is {why}: downloading it needs a Hugging Face login.", flush=True)
        if not sys.stdin.isatty():
            raise SystemExit(f"Log in with:  {LOGIN}\nthen run this again.")
        login()
    try:
        api.auth_check(repo, repo_type=repo_type)
    except GatedRepoError:
        raise SystemExit(f"Your Hugging Face account has no access to {repo} yet. Accept its terms at {page} and run "
                         f"this again.") from None
    except RepositoryNotFoundError:
        raise SystemExit(f"{repo} is not visible to your Hugging Face account: check the name, or ask its owner for "
                         f"access ({page}).") from None
    except HfHubHTTPError as error:                       # an expired or revoked token
        raise SystemExit(f"Hugging Face rejected the saved login ({error}). Log in again:  {LOGIN}") from None


def download(repo: str, revision: "str | None" = None, root: Path = DOWNLOADS) -> Path:
    """Fetch `repo` and rebuild its checkpoints as .pt beside the published files.

    Input:  <account>/<name>, an optional revision (branch, tag or commit), the downloads root
    Output: the download folder
    """
    from huggingface_hub import snapshot_download        # only needed here: run with `uv run --with huggingface_hub`

    ensure_access(repo)
    folder = Path(snapshot_download(repo_id=repo, revision=revision, local_dir=root / repo.split("/")[-1]))
    rebuilt = []
    # Every per-day head, under the name artifacts/current gives it.
    names = {**NAMES, **{p.stem: f"detector/head_{p.stem.removeprefix('detector_')}.pt"
                         for p in folder.glob("detector_*.safetensors")}}
    for role, name in names.items():
        if (folder / f"{role}.safetensors").exists():
            target = folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            torch.save(unflatten(folder / role), target)
            rebuilt.append(name)
    if all(NAMES[r] in rebuilt for r in ("flow_encoder", "world_model_context_encoder", "compressor", "world_model")):
        live = all(NAMES[r] in rebuilt for r in ("context_encoder", "live_compressor", "live_world_model"))
        write(folder / "serving.json", {"block7": "flow_encoder.pt", "block8": "forecasting_encoder.pt",
                                        "block9": "compressor.pt", "block10": "world_model.pt"},
              live={"block7": "flow_encoder.pt", "block8": "detection_encoder.pt", "block9": "live_compressor.pt",
                    "block10": "live_world_model.pt"} if live else None)
    print(f"{repo} -> {folder}\n  rebuilt: {', '.join(rebuilt) or 'nothing (no safetensors found)'}")
    return folder


SETS = ("processed", "model")


def dataset_patterns(sets: "list[str]", days: "list[str] | None") -> list[str]:
    """The files to fetch: the card, plus every portion of the chosen sets, for the chosen days or all of them."""
    unknown = sorted(set(sets) - set(SETS))
    if unknown or not sets:
        raise ValueError(f"sets must be among {SETS}, got {sets}")
    return ["README.md"] + [f"{s}/*/{day}/**" for s in sets for day in (days or ["*"])]


def download_dataset(repo: str, sets: "list[str]", days: "list[str] | None" = None, revision: "str | None" = None,
                     root: Path = DOWNLOADS) -> Path:
    """Fetch the chosen sets (and days) of the dataset repository, in its own layout."""
    from huggingface_hub import snapshot_download

    ensure_access(repo, "dataset")
    folder = Path(snapshot_download(repo_id=repo, repo_type="dataset", revision=revision,
                                    allow_patterns=dataset_patterns(sets, days), local_dir=root / repo.split("/")[-1]))
    files = [p for p in folder.rglob("*.parquet")]
    print(f"{repo} -> {folder}\n  {len(files)} parquet files, {sum(p.stat().st_size for p in files) / 1e9:.1f} GB "
          f"({', '.join(sets)}; days: {', '.join(days) if days else 'all'})")
    return folder


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repo", default=None, help="<account>/<name> of the Hugging Face model repository")
    parser.add_argument("--dataset", default=None, help="<account>/<name> of the Hugging Face dataset repository")
    parser.add_argument("--sets", nargs="+", default=list(SETS), choices=SETS,
                        help="dataset sets to fetch: processed (model-agnostic tables), model (flow embeddings and "
                             "latents of the published model); default both")
    parser.add_argument("--days", nargs="+", default=None, help="dataset days to fetch (default: all)")
    parser.add_argument("--revision", default=None, help="a branch, tag or commit (default: the latest)")
    parser.add_argument("--out", type=Path, default=DOWNLOADS, help="downloads root (default: artifacts/huggingface/download)")
    args = parser.parse_args(argv)
    if not args.repo and not args.dataset:
        parser.error("give --repo, --dataset, or both")
    if args.repo:
        download(args.repo, args.revision, args.out)
    if args.dataset:
        download_dataset(args.dataset, args.sets, args.days, args.revision, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
