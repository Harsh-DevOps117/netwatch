"""Copy a finished training run's best models into artifacts/current, the one folder serving and publishing read.

Usage:  uv run python tools/promote.py <run folder>          (tools/train_all.sh runs this when a run finishes)
        uv run python tools/promote.py --demo                 (self-check on a fake run)

artifacts/current/ after promotion:
    flow_encoder.pt  detection_encoder.pt  forecasting_encoder.pt  record_encoder.pt  compressor.pt  world_model.pt
    live_compressor.pt  live_world_model.pt     the `live` tag's pair, when the run has its stages (b9live, b10live)
    detector/head_<day>.pt
    serving.json      the models behind each world-model tag (lag, live); paths relative to this folder
    manifest.json     the source run, its days, epochs and calibration, and what was copied
    metrics/          each stage's history and best metrics, the detector's results, calibration and tolerance reports
    latents  latents-live  embeddings    links to the run's per-event outputs (tens of GB, not copied); the replay
                      service reads one day of latents, and publishing stages them with the models

The folder is built beside the old one and swapped in at the end; the old one is kept as artifacts/previous/, so a bad
promotion is undone by swapping the two back.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from models.serving.registry import write  # noqa: E402

ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts"
MODELS = {"detection_encoder.pt": "b8det/best.pt", "forecasting_encoder.pt": "b8/best.pt",
          "record_encoder.pt": "record_encoder.pt", "compressor.pt": "b9/best.pt", "world_model.pt": "b10/best.pt"}
# The `live` tag's compressor and world model, trained on the detection encoder's output; optional (a run without the
# live stages promotes with `live` left untrained).
LIVE_MODELS = {"live_compressor.pt": "b9live/best.pt", "live_world_model.pt": "b10live/best.pt"}
METRICS = ["b9live/history.csv", "b9live/best_metrics.csv", "b10live/history.csv", "b10live/best_metrics.csv",
           "calibration_live/report.txt", "b7/*_history.csv", "b7/results.csv", "b8det/history.csv", "b8det/best_metrics.csv", "b8/history.csv",
           "b8/best_metrics.csv", "b9/history.csv", "b9/best_metrics.csv", "b10/history.csv", "b10/best_metrics.csv",
           "detector/results.csv", "calibration/report.txt", "parity/*.json"]


def flow_encoder(run: Path) -> Path:
    """The flow encoder checkpoint of a run: the one the manifest names, else the only kept model in b7/."""
    manifest = run / "manifest.json"
    if manifest.exists():
        named = json.loads(manifest.read_text()).get("checkpoints", {}).get("block7")
        if named and Path(named).exists():
            return Path(named)
    kept = [p for p in (run / "b7").glob("*.pt")
            if "_epoch" not in p.stem and p.name not in ("resume.pt", "current.pt")]
    if len(kept) != 1:
        raise SystemExit(f"{run}/b7: expected one kept flow encoder, found {[p.name for p in kept]}")
    return kept[0]


def promote(run: Path, artifacts: Path = ARTIFACTS) -> Path:
    """Build artifacts/current from `run`, keeping the old one as artifacts/previous.

    Input:  a finished training run folder, the artifacts root
    Output: the path of artifacts/current
    """
    run = run.expanduser().resolve()
    sources = {"flow_encoder.pt": flow_encoder(run), **{name: run / rel for name, rel in MODELS.items()}}
    heads = sorted((run / "detector").glob("head_*.pt"))
    missing = [str(p) for p in sources.values() if not p.exists()] + ([] if heads else [f"{run}/detector/head_*.pt"])
    if missing:
        raise SystemExit("not a finished run, missing: " + ", ".join(missing))

    staging = artifacts / ".current.tmp"
    shutil.rmtree(staging, ignore_errors=True)
    (staging / "detector").mkdir(parents=True)
    live = {name: run / rel for name, rel in LIVE_MODELS.items() if (run / rel).exists()}
    live = live if len(live) == len(LIVE_MODELS) else {}
    for name, source in {**sources, **live}.items():
        shutil.copy2(source, staging / name)
    for head in heads:
        shutil.copy2(head, staging / "detector" / head.name)
    copied = []
    for pattern in METRICS:
        for source in sorted(run.glob(pattern)):
            target = staging / "metrics" / source.relative_to(run)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            copied.append(str(target.relative_to(staging)))
    lag_report = next((f"metrics/parity/{n}.json" for n in ("lag", "delay") if (staging / f"metrics/parity/{n}.json").exists()),
                      None)
    write(staging / "serving.json",
          {"block7": "flow_encoder.pt", "block8": "forecasting_encoder.pt", "block9": "compressor.pt",
           "block10": "world_model.pt"},
          parity={"lag": lag_report} if lag_report else None,
          live={"block7": "flow_encoder.pt", "block8": "detection_encoder.pt", "block9": "live_compressor.pt",
                "block10": "live_world_model.pt"} if live else None)
    for folder in ("latents", "latents-live", "embeddings"):          # per-event outputs: tens of GB, linked not copied
        if (run / folder).is_dir():
            (staging / folder).symlink_to(run / folder, target_is_directory=True)
    source_manifest = json.loads((run / "manifest.json").read_text()) if (run / "manifest.json").exists() else {}
    manifest = {"source_run": str(run), "promoted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "models": {name: str(source) for name, source in {**sources, **live}.items()},
                "detector_heads": [h.name for h in heads], "metrics": copied,
                **{k: source_manifest[k] for k in ("commit", "days", "epochs", "seed", "calibration") if k in source_manifest}}
    (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    current, previous = artifacts / "current", artifacts / "previous"
    if current.exists():
        shutil.rmtree(previous, ignore_errors=True)
        current.rename(previous)
    staging.rename(current)
    return current


def demo() -> None:
    """Self-check: a fake finished run promotes, serving.json resolves inside it, and a second promotion keeps a previous."""
    import tempfile
    from models.serving.registry import resolve

    with tempfile.TemporaryDirectory() as tmp:
        run, artifacts = Path(tmp) / "run", Path(tmp) / "artifacts"
        for rel in ["b7/a__b__s0.pt", "b7/a__b__s0_epoch01.pt", "b7/resume.pt", *MODELS.values(),
                    "detector/head_Friday.pt", "b8/best_metrics.csv", "parity/delay.json"]:
            (run / rel).parent.mkdir(parents=True, exist_ok=True)
            (run / rel).write_text(rel)
        (run / "latents" / "Friday").mkdir(parents=True)
        current = promote(run, artifacts)
        assert (current / "flow_encoder.pt").read_text() == "b7/a__b__s0.pt"
        assert (current / "detector" / "head_Friday.pt").exists() and (current / "metrics/b8/best_metrics.csv").exists()
        assert resolve(current / "serving.json", "lag")["block10"] == current / "world_model.pt"
        assert (current / "latents" / "Friday").is_dir()
        try:
            resolve(current / "serving.json", "live")
            raise AssertionError("live must be refused before its models are trained")
        except PermissionError:
            pass
        for rel in LIVE_MODELS.values():
            (run / rel).parent.mkdir(parents=True, exist_ok=True)
            (run / rel).write_text(rel)
        promote(run, artifacts)
        assert resolve(artifacts / "current" / "serving.json", "live")["block10"].read_text() == "b10live/best.pt"
        assert (artifacts / "previous" / "world_model.pt").exists() and not (artifacts / ".current.tmp").exists()
    print("demo ok")


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("run", type=Path, nargs="?", help="a finished training run, ~/netwatch-data/runs/<stamp>")
    parser.add_argument("--artifacts", type=Path, default=ARTIFACTS, help="the artifacts root (default: <repo>/artifacts)")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args(argv)
    if args.demo:
        demo()
        return 0
    if args.run is None:
        parser.error("give a run folder, or --demo")
    current = promote(args.run, args.artifacts)
    print(f"promoted {args.run} -> {current}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
