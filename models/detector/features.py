"""What the classifier reads: the frozen representation, and the reconstruction-error gate measured against it."""
from __future__ import annotations

from pathlib import Path

import numpy as np
import torch

from models.compressor.autoencoder import ENCODERS, EventAutoencoder
from models.compressor.latents import context_vectors, frozen_context_encoder
from models.context_encoder.data import attack_slice, load_day, make_stream


def load_features(day: str, context: Path | None = None, device: str = "cpu",
                  events: int | None = None, family: str | None = None) -> tuple[dict, str]:
    """What the classifier reads: Block 7's split embedding, optionally with Block 8's context beside it.

    Input:  day, a Block 8 checkpoint to take context from (None for the embedding alone), device
    Output: (dict with h (N, W), label, population, split, attack -- all in availability order; a name for the report)

    The classifier reading `h_split` alone is the whole reason Block 8 cannot reach the supervised arm: link memory,
    the neighbourhood and the flow messages all live in `s`. Passing a checkpoint here is what puts them in front of
    it, and the name in the report says which was measured.
    """
    data = load_day(day, "split")
    if events:
        keep = attack_slice(data, events, family)
        data = {k: v[keep] for k, v in data.items() if isinstance(v, np.ndarray)}
    x, name = data["h_split"], "h_split"
    context = None
    if context is not None:
        model8, arm = frozen_context_encoder(context, device)
        stream = make_stream(data, np.ones(len(data["sender"]), bool))
        context = context_vectors(model8, stream, arm, device=device)
        x = np.concatenate([x, context], 1)
        name = "h_split+s"
    # sender / t_obs ride along so a consumer can group alerts by host and convert counts into a rate: the score
    # alone cannot say whether 6,000 false alarms are 6,000 incidents or six noisy hosts.
    return {"h": x, "sender": data["sender"], "receiver": data["receiver"], "t_obs": data["t_obs"],
            "label": data["label"], "population": data["population"], "split": data["split"],
            "attack": data["attack"], "context": context}, name


def benign_gate(compressor: Path, context: np.ndarray, device: str = "cpu", chunk: int = 4096) -> np.ndarray:
    """How unlike benign traffic each event's context is, according to Block 9.

    Input:  a Block 9 checkpoint, Block 8's context per event (N, d_s), device, rows per block
    Output: (N,) per-event mean squared reconstruction error; higher is less like the benign traffic it was fitted on

    Block 9's autoencoder is trained on benign contexts only, so an alert whose context rebuilds *well* looks like
    normal traffic and is most likely a false positive. That is the whole of its false-positive job: a second, almost
    independent condition on the same event, where the classifier's threshold alone cannot go (the ceiling columns say
    no threshold can -- the class ratio caps precision).
    """
    from models.compressor.autoencoder import EventAutoencoder

    state = torch.load(compressor, map_location=device, weights_only=False)
    model = EventAutoencoder(state["encoder"], d_s=context.shape[1], d_z=state["d_z"],
                             target=context.shape[1]).to(device)
    model.load_state_dict(state["model"])
    model.eval().requires_grad_(False)
    errors = []
    with torch.no_grad():
        for i in range(0, len(context), chunk):
            s = model.normalise(torch.from_numpy(context[i:i + chunk]).to(device))
            rebuilt = model(s)[1]
            errors.append(((rebuilt - s) ** 2).mean(1).cpu().numpy())
    return np.concatenate(errors) if errors else np.zeros(0, np.float32)


def combine(clf_calib: np.ndarray, gate_calib: np.ndarray, positive: np.ndarray,
            clf_test: np.ndarray, gate_test: np.ndarray, *, steps: int = 400, seed: int = 0) -> np.ndarray:
    """Learn how much Block 9's verdict is worth beside the classifier's, on rows neither was scored on.

    Input:  the two scores on the calibration rows, whether each is the family, the two scores on the reported rows,
            gradient steps, seed
    Output: (N,) combined score for the reported rows

    Adding the two scores with equal weight was wrong: Block 9's reconstruction error is a far weaker signal than the
    classifier's (PR-AUC ~0.1-0.2 against ~0.93), so an even sum drags the strong score down -- measured, it pushed
    false alarms from 5,632 to 6,905 and completed PR-AUC from 0.905 to 0.519. A weight fitted on the calibration rows
    can set the gate's contribution to zero, so the combination cannot be worse than the classifier alone except by
    fitting noise. That makes "does Block 9 reduce false positives" answerable rather than assumed.
    """
    x = torch.from_numpy(np.stack([clf_calib, gate_calib], 1).astype(np.float32))
    y = torch.from_numpy(positive.astype(np.float32))
    torch.manual_seed(seed)
    head = nn.Linear(2, 1)
    optimiser = torch.optim.Adam(head.parameters(), lr=0.05)
    weight = torch.tensor([(len(y) - y.sum()) / max(float(y.sum()), 1.0)])
    for _ in range(steps):
        optimiser.zero_grad()
        F.binary_cross_entropy_with_logits(head(x).squeeze(1), y, pos_weight=weight).backward()
        optimiser.step()
    with torch.no_grad():
        test = torch.from_numpy(np.stack([clf_test, gate_test], 1).astype(np.float32))
        return head(test).squeeze(1).numpy()


def standardise(score: np.ndarray, reference: np.ndarray) -> np.ndarray:
    """Put a score on the scale of the benign rows it is read against.

    Input:  scores to convert (N,), the benign reference scores
    Output: (N,) standardised
    """
    mean, std = float(reference.mean()), float(reference.std())
    return (score - mean) / (std if std > 1e-12 else 1.0)
