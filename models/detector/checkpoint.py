"""Everything a serving process needs on disk: the head, its scaler, its thresholds, and the score distributions."""
from __future__ import annotations

from pathlib import Path

import numpy as np
import torch

from models.detector.model import HIDDEN, Head


def save_head(path: Path, *, head: Head, mean: np.ndarray, std: np.ndarray, families: list[str],
              thresholds: dict, width: int, hidden: int, feature: str, day: str, seed: int,
              context: Path | None, calibrate: float) -> None:
    """Persist everything a serving process needs to score one event and decide.

    Input:  destination, the fitted head, the scaler it was fitted with, family names, the budget thresholds, feature
            width, hidden width, the feature name, day, seed, the Block 8 checkpoint used, the calibration share
    Output: none; writes a torch checkpoint

    The scaler is part of the model: `class_scores` standardises with the training mean and std, so a process that
    reloads the weights without them produces scores on a different scale and every threshold is meaningless.
    `serve_threshold` is left empty on purpose -- `models/evaluation/thresholds.py` writes the chosen operating point into it,
    so the tradeoff is inspected on its own before anything is committed to a number.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save({
        "format": "supervised-head-v1",
        "head": head.state_dict(), "mean": mean, "std": std,
        "width": int(width), "hidden": int(hidden), "classes": len(families) + 1, "families": list(families),
        # keys are "<family>@<budget>"; tuple keys survive torch.save but are awkward to read back from anything else
        "thresholds": {f"{name}@{fpr}": float(value) for (name, fpr), value in thresholds.items()},
        "serve_threshold": {},
        "day": day, "seed": int(seed), "input": feature, "calibrate": float(calibrate),
        "context_encoder": str(context) if context is not None else None,
    }, path)
    print(f"head -> {path}", flush=True)


def load_head(path: Path, device: str = "cpu") -> tuple[Head, np.ndarray, np.ndarray, list[str], dict]:
    """Rebuild a saved head, its scaler and its thresholds.

    Input:  a checkpoint written by save_head, device
    Output: (head in eval mode, feature mean, feature std, family names, the checkpoint dict itself)

    The mirror of save_head: the shape comes from the checkpoint rather than from the caller, so a serving process
    never has to know how the head was configured.
    """
    state = torch.load(path, map_location=device, weights_only=False)
    if state.get("format") != "supervised-head-v1":
        raise ValueError(f"{path}: not a supervised head checkpoint")
    head = Head(state["width"], state["classes"], state["hidden"]).to(device)
    head.load_state_dict(state["head"])
    return head.eval(), state["mean"], state["std"], state["families"], state


def save_calibration(path: Path, *, families: list[str], day: str, calib_benign: np.ndarray, test: np.ndarray,
                     test_code: np.ndarray, test_attack: np.ndarray, t_obs: np.ndarray, sender: np.ndarray) -> None:
    """Persist the score distributions a threshold sweep needs, so the sweep never refits the head.

    Input:  destination, family names, day, per-class scores on the calibration benign rows and on the test rows,
            test class codes, test attack flag, test observation times, test sender ids
    Output: none; writes a torch checkpoint

    Calibration benign scores set the threshold; the test arrays turn a threshold into recall, realised FPR, alarms
    per hour and incidents per hour. Keeping both means the whole budget-versus-recall tradeoff can be explored in
    seconds without touching the GPU, which is the point of separating the decision from the fit.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save({
        "format": "supervised-scores-v1", "families": list(families), "day": day,
        "calib_benign": np.asarray(calib_benign, np.float32), "test": np.asarray(test, np.float32),
        "test_code": np.asarray(test_code, np.int64), "test_attack": np.asarray(test_attack, bool),
        "t_obs": np.asarray(t_obs, np.float64), "sender": np.asarray(sender, np.int64),
    }, path)
    print(f"scores -> {path}", flush=True)
