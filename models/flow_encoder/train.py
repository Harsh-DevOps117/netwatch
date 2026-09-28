"""Training and inference for the Block 7 autoencoder, benign rows only."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import torch

from models.flow_encoder.encoder import FlowAutoencoder
from models.training import load_resume, make_schedule, step_schedule
from models.data.batching import FlowDataset, flow_loader, to_device


def best_epoch(history: list[float]) -> int:
    """Index of the best validation error so far.

    Input:  validation error per epoch
    Output: index of the best epoch; ties keep the earlier one
    """
    return int(np.argmin(history))


def early_stop_epoch(history: list[float], patience: int) -> int | None:
    """Whether patience has run out, and which epoch to keep.

    Input:  validation error per epoch, epochs tolerated without improvement
    Output: index of the best epoch once patience is exhausted, else None
    """
    if patience <= 0 or not history:
        return None
    best = best_epoch(history)
    return best if len(history) - 1 - best >= patience else None


def train_autoencoder(
    model: FlowAutoencoder, data: dict, rows: np.ndarray, val_rows: np.ndarray,
    *, epochs: int = 5, batch_size: int = 1024, lr: float = 1e-3, device: str = "cpu",
    seed: int = 0, workers: int = 0, patience: int = 0,
    schedule: str = "none", board=None, resume: "Path | None" = None, on_epoch=None,
) -> list[tuple[float, float]]:
    """Fit the autoencoder on benign rows only.

    Input:  model, normalised arrays, train rows, validation rows, epochs, batch size,
            learning rate, device, seed, loader workers, early-stopping patience
    Output: (train error, validation error) per epoch, mean reconstruction error

    With patience > 0 the run stops once the benign validation error has not improved for
    that many epochs, and the best epoch's weights are restored. Validation selects the
    model, so its rows must not also be scored.
    """
    if data["attack"][rows].any() or data["attack"][val_rows].any():
        raise ValueError("autoencoder rows must be benign only")
    loader = flow_loader(
        FlowDataset(data, rows), batch_size=batch_size, shuffle=True,
        workers=workers, seed=seed, pin=device == "cuda",
    )
    optimiser = torch.optim.Adam(model.parameters(), lr=lr)
    scheduler = make_schedule(optimiser, schedule, epochs, max(patience, 1))
    state = load_resume(resume, model, optimiser, scheduler, higher_is_better=False, device=device)
    history: list[tuple[float, float]] = [tuple(h) for h in state.history]
    validation: list[float] = [h[1] for h in history]
    best_state, best_index = None, -1
    for epoch in range(state.epoch, epochs):
        model.train()
        total = 0.0
        for batch in loader:
            _, errors = model(to_device(batch, device))
            loss = errors.mean()
            optimiser.zero_grad()
            loss.backward()
            optimiser.step()
            total += float(loss.detach()) * len(batch["row"])
        val = (
            float(embed(model, data, val_rows, device=device, workers=workers)[1].mean())
            if len(val_rows) else float("nan")
        )
        history.append((total / len(rows), val))
        print(f"  epoch {epoch + 1}/{epochs}  train {history[-1][0]:.4f}  val benign {val:.4f}", flush=True)
        if board is not None:
            board.log(epoch + 1, prefix="flow_encoder", train_loss=history[-1][0], val_benign=val,
                      lr=optimiser.param_groups[0]["lr"])
        step_schedule(scheduler, metric=val if val == val else None)
        state.epoch, state.history = epoch + 1, [list(h) for h in history]
        if on_epoch is not None:
            on_epoch(epoch + 1, model)                   # e.g. keep this epoch's weights on disk
        if resume is not None:
            state.improved(val if val == val else float("inf"))
            state.save(resume, model, optimiser, scheduler)

        if patience > 0 and np.isfinite(val):
            validation.append(val)
            if best_epoch(validation) == epoch:
                best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
                best_index = epoch
            if early_stop_epoch(validation, patience) is not None:
                print(f"  early stop: keeping epoch {best_index + 1} (val {validation[best_index]:.4f})", flush=True)
                break

    if best_state is not None and best_index != len(history) - 1:
        model.load_state_dict(best_state)
    return history


@torch.no_grad()
def embed(
    model: FlowAutoencoder, data: dict, rows: np.ndarray,
    *, batch_size: int = 4096, device: str = "cpu", workers: int = 0,
):
    """Embeddings and reconstruction errors of the given rows, in row order.

    Input:  model, normalised arrays, rows, batch size, device, loader workers
    Output: (h (N, d_h), error per target (N, len(targets))) as numpy arrays
    """
    model.eval()
    if len(rows) == 0:
        return np.zeros((0, 0), np.float32), np.zeros((0, len(model.targets)), np.float32)
    loader = flow_loader(
        FlowDataset(data, rows), batch_size=batch_size, workers=workers, pin=device == "cuda",
    )
    hs, errors = [], []
    for batch in loader:
        h, error = model(to_device(batch, device))
        hs.append(h.cpu())
        errors.append(error.cpu())
    return torch.cat(hs).numpy(), torch.cat(errors).numpy()
