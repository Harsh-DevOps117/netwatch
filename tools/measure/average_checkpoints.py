"""Average a world model's weights over several saved epochs into one checkpoint (stochastic weight averaging, post hoc).

Run: uv run python -m tools.measure.average_checkpoints <run>/b10/epoch_06.pt ... <run>/b10/epoch_10.pt --out swa.pt

Every epoch's weights are kept by training (b10/epoch_NN.pt). Averaging the last few gives one model that sits nearer
the middle of the region those epochs explored -- in the link-prediction literature this generalises and calibrates
better than any single checkpoint, at the serving cost of one model and with no retraining (Sapkota et al., 2025:
parameter averaging for link prediction; Izmailov et al., 2018: SWA).

The average is written in the world model's own checkpoint format. It carries no calibrated threshold: a threshold
belongs to one set of weights, so an averaged model must be calibrated (models.world_model.calibration) before it
alerts. Forecast quality can be measured without one (tools.measure.forecast_beam).
"""
from __future__ import annotations

import argparse
from pathlib import Path

import torch


def average(paths: "list[Path]") -> dict:
    states = [torch.load(p, map_location="cpu", weights_only=False) for p in paths]
    formats = {s.get("format") for s in states}
    if len(formats) != 1:
        raise SystemExit(f"checkpoints of different formats: {sorted(map(str, formats))}")
    keys = set(states[0]["model"])
    if any(set(s["model"]) != keys for s in states):
        raise SystemExit("checkpoints hold different weights; they must come from one training run")
    averaged = {k: sum(s["model"][k].float() for s in states) / len(states) for k in keys}
    out = {k: v for k, v in states[-1].items() if k not in ("model", "serve_threshold", "thresholds", "calibration")}
    out.update(model={k: v.to(states[-1]["model"][k].dtype) for k, v in averaged.items()},
               averaged_from=[str(p) for p in paths], averaged_epochs=[s.get("epoch") for s in states])
    return out


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("checkpoints", type=Path, nargs="+")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    state = average(args.checkpoints)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    torch.save(state, args.out)
    print(f"averaged epochs {state['averaged_epochs']} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
