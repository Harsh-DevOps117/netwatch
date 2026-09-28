"""Training the compressor: rebuild the frozen context vector, and keep the error as a signal.

Split out of latents.py so the objective is separable from the loading and export paths, matching
models/flow_encoder/train.py and models/context_encoder/train.py. Block 8 is frozen here and never receives a
gradient -- that is the whole premise of the cascade, so it lives in one readable place.
"""
from __future__ import annotations

import numpy as np
import torch

from models.compressor.autoencoder import EventAutoencoder, anomaly_score, event_targets, squared_error, \
    window_structure
from models.context_encoder.model import ContextEncoder, LinkIds, make_batch


def run_compressor(model8: ContextEncoder, ae: EventAutoencoder, stream: dict, arm: str, *, window: int = 512,
               device: str = "cpu", optimiser: torch.optim.Optimizer | None = None, target: str = "s",
               reference: tuple[np.ndarray, np.ndarray] | None = None, collect: int = 0) -> dict:
    """One pass over a stream: frozen Block 8 produces s, Block 9 rebuilds the target from z.

    Input:  frozen Block 8, autoencoder, stream (make_stream), arm, window size (also the batch), device, optimiser
            or None, target ("s" for variant B, "x_e" for the fixed event features), benign reference to turn errors
            into scores, how many rows of per-column error to keep when there is no reference
    Output: dict with loss, and either scores (N,) when a reference is given or errors (<= collect, W) to fit one

    Windows are consecutive in availability order, so the window encoder only ever sees earlier events.
    """
    train = optimiser is not None
    ae.train(train)
    links = LinkIds(stream["sender"], stream["receiver"])
    model8.begin_day(len(links))
    n = len(stream["sender"])
    # The loss stays on the device, and a window's per-column error is read back only while it is still wanted:
    # reading both every window forced a CPU<->GPU synchronisation per window.
    total = torch.zeros((), device=device, dtype=torch.float64)
    scores, errors, kept = (np.empty(n, np.float32) if reference is not None else None), [], 0
    for start in range(0, n, window):
        rows = np.arange(start, min(start + window, n))
        with torch.no_grad():
            batch = make_batch(stream, rows, arm, links, device)
            s = ae.normalise(model8(batch))                    # frozen: no gradient reaches Block 8
        structure = None
        if ae.encoder_kind == "window":
            structure = window_structure(stream["sender"][rows], stream["receiver"][rows], stream["t_obs"][rows], device)
        goal = s if target == "s" else event_targets(batch["inputs"], arm)
        with torch.set_grad_enabled(train):
            _, reconstruction = ae(s, structure)
            error = squared_error(reconstruction, goal)
            loss = error.mean()
            if train:
                optimiser.zero_grad()
                loss.backward()
                optimiser.step()
        total += loss.detach().double() * len(rows)
        if reference is not None:
            scores[rows] = anomaly_score(error.detach().cpu().numpy(), reference)
        elif kept < collect:
            errors.append(error.detach().cpu().numpy())
            kept += len(rows)
    out = {"loss": float(total) / max(n, 1)}
    if reference is not None:
        out["scores"] = scores
    else:
        out["errors"] = np.concatenate(errors) if errors else np.zeros((0, 1), np.float32)
    return out
