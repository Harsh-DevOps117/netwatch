"""Block 9: compress each contextual event into z and score it by how badly it is reconstructed.

Two encoders are built and compared (design.md, Block 9 *Transformation*):

  "mlp"     per event: z depends on this event's s alone. Block 8 has already folded in the link memory and the
            attention over earlier available neighbours, so nothing here can read another event.
  "window"  the graph-transformer form: events attend to *earlier* events of the same window, biased by shared
            endpoints and by how long ago they happened.

The window encoder departs from design.md in one way, forced by the availability rule: design.md asks for Laplacian
positional encodings, which are computed from a whole window's graph -- including events later than the one being
scored. A strictly causal version needs one eigendecomposition per event (measured: ~0.8 ms at 128 events, ~100 h per
pass over five days), so the structure reaches the model as causal features instead: how many earlier events in the
window share this event's sender or receiver, and per-pair attention biases for a shared sender, receiver or link.
"""

from __future__ import annotations

import numpy as np
import torch
from torch import nn

from models.context_encoder.model import D_H, GapCode, _slog

# What variant A rebuilds: the event's own input features, every one of them fixed (Block 7 frozen, Block 6 columns).
TARGET_WIDTH = {"split": D_H + 7, "sides": 2 * D_H + 7}
ENCODERS = ("mlp", "window")


def event_targets(inputs: dict[str, torch.Tensor], arm: str) -> torch.Tensor:
    """x_e: the event's input features, the fixed target of variant A (design.md, Block 9).

    Input:  the tensors event_inputs builds for a batch, arm
    Output: (N, TARGET_WIDTH[arm]): the arm's Block 7 embedding(s), log(1 + dt_src), log(1 + dt_dst), a flag per gap
            for "first appearance" (gap -1, log set to 0), signed-log port_delta, dst_port_new, reversed
    """
    gaps = []
    for name in ("dt_src", "dt_dst"):
        first = inputs[name] < 0
        gaps += [torch.log1p(torch.where(first, torch.zeros_like(inputs[name]), inputs[name]))[:, None],
                 first.to(inputs[name].dtype)[:, None]]
    embeddings = [inputs["h_split"]] if arm == "split" else [inputs["h_request"], inputs["h_response"]]
    return torch.cat([*embeddings, *gaps, _slog(inputs["port_delta"])[:, None],
                      inputs["dst_port_new"][:, None], inputs["reversed"][:, None]], 1)


def window_structure(sender: np.ndarray, receiver: np.ndarray, t_obs: np.ndarray, device: str = "cpu") -> dict:
    """The causal structure of one window: who may attend to whom, what they share, and how far apart they are.

    Input:  sender, receiver and observation time of the window's events, in availability order (W,), device
    Output: dict with causal (W, W) bool (row i may read column j only if j < i), same_sender / same_receiver /
            same_link (W, W) float and age (W, W) seconds since the earlier event, zero where not readable
    """
    s = torch.from_numpy(np.ascontiguousarray(sender)).to(device)
    r = torch.from_numpy(np.ascontiguousarray(receiver)).to(device)
    t = torch.from_numpy(np.ascontiguousarray(t_obs, dtype=np.float64)).to(device)
    causal = torch.tril(torch.ones(len(s), len(s), dtype=torch.bool, device=device), diagonal=-1)
    same_sender = (s[:, None] == s[None, :]) & causal
    same_receiver = (r[:, None] == r[None, :]) & causal
    return {"causal": causal, "same_sender": same_sender.float(), "same_receiver": same_receiver.float(),
            "same_link": (same_sender & same_receiver).float(),
            "age": torch.where(causal, (t[:, None] - t[None, :]).clamp(min=0), torch.zeros_like(t[:, None])).float()}


class WindowEncoder(nn.Module):
    """Graph-transformer encoder over a window of events, reading only earlier ones.

    Input:  context width d_s, model width, heads, layers, latent width
    Output: module; forward(s, structure) returns z (W, d_z)

    Each layer is multi-head attention over the window's earlier events -- biased by a shared sender, receiver or
    link and by the gap since the earlier event -- then a feed-forward block, both with residual and LayerNorm.
    Each event also reads how many earlier events in the window share its sender or its receiver.
    """

    def __init__(self, d_s: int = 100, d_model: int = 128, heads: int = 4, layers: int = 2, d_z: int = 32):
        super().__init__()
        self.heads = heads
        self.gap = GapCode()
        self.inp = nn.Linear(d_s + 2, d_model)          # + the two causal degrees
        self.bias = nn.Linear(3 + self.gap.time.omega.numel() * 2, heads)
        self.qkv = nn.ModuleList(nn.Linear(d_model, 3 * d_model) for _ in range(layers))
        self.attention_norm = nn.ModuleList(nn.LayerNorm(d_model) for _ in range(layers))
        self.ffn = nn.ModuleList(nn.Sequential(nn.Linear(d_model, d_model), nn.ReLU(), nn.Linear(d_model, d_model))
                                 for _ in range(layers))
        self.ffn_norm = nn.ModuleList(nn.LayerNorm(d_model) for _ in range(layers))
        self.out = nn.Linear(d_model, d_z)

    def forward(self, s: torch.Tensor, structure: dict) -> torch.Tensor:
        causal = structure["causal"]
        degrees = torch.stack([torch.log1p(structure["same_sender"].sum(1)), torch.log1p(structure["same_receiver"].sum(1))], 1)
        x = self.inp(torch.cat([s, degrees], 1))
        pair = torch.cat([structure["same_sender"][..., None], structure["same_receiver"][..., None],
                          structure["same_link"][..., None], self.gap(structure["age"])], -1)
        bias = self.bias(pair).permute(2, 0, 1)                    # (heads, W, W)
        blocked = ~causal
        # An event with no earlier event in its window attends to itself only; its attention output is zeroed below.
        alone = blocked.all(1)
        mask = blocked.clone()
        mask[alone, 0] = False
        head_dim = x.shape[1] // self.heads
        for qkv, norm, ffn, ffn_norm in zip(self.qkv, self.attention_norm, self.ffn, self.ffn_norm):
            q, k, v = qkv(x).chunk(3, dim=-1)
            shape = (len(x), self.heads, head_dim)
            q, k, v = (t.view(*shape).transpose(0, 1) for t in (q, k, v))
            scores = q @ k.transpose(-2, -1) / head_dim ** 0.5 + bias
            attended = (scores.masked_fill(mask, float("-inf")).softmax(-1) @ v).transpose(0, 1).reshape(len(x), -1)
            attended = attended * (~alone)[:, None].to(attended.dtype)
            x = norm(x + attended)
            x = ffn_norm(x + ffn(x))
        return self.out(x)


class EventAutoencoder(nn.Module):
    """s_{u,v}(t) -> z -> the variant's target, with the per-column error the anomaly score reads.

    Input:  encoder ("mlp" or "window"), context width d_s, latent width d_z, hidden width, target width
            (x_e for variant A, d_s for variant B), window encoder heads and layers
    Output: module; forward(s, structure=None) returns (z (N, d_z), reconstruction (N, target width))
    """

    def __init__(self, encoder: str = "mlp", d_s: int = 100, d_z: int = 32, hidden: int = 128, target: int = 39,
                 heads: int = 4, layers: int = 2):
        super().__init__()
        if encoder not in ENCODERS:
            raise ValueError(f"encoder must be one of {ENCODERS}")
        self.encoder_kind = encoder
        if encoder == "mlp":
            self.encoder = nn.Sequential(nn.LayerNorm(d_s), nn.Linear(d_s, hidden), nn.ReLU(), nn.Linear(hidden, d_z))
        else:
            self.encoder = WindowEncoder(d_s, hidden, heads, layers, d_z)
        self.decoder = nn.Sequential(nn.Linear(d_z, hidden), nn.ReLU(), nn.Linear(hidden, target))
        # The scale s is read on, fitted on benign contexts (design.md, Block 9). Buffers, so a checkpoint carries it
        # and scoring later cannot use a different scale than training did.
        self.register_buffer("s_mean", torch.zeros(d_s))
        self.register_buffer("s_std", torch.ones(d_s))

    def fit_normalisation(self, context: np.ndarray) -> None:
        """Fit the benign scale of s, once, before training.

        Input:  Block 8 contexts of benign training events (N, d_s)
        Output: none; sets the s_mean / s_std buffers
        """
        mean, std = benign_reference(context)
        self.s_mean.copy_(torch.from_numpy(mean))
        self.s_std.copy_(torch.from_numpy(std))

    def normalise(self, s: torch.Tensor) -> torch.Tensor:
        """s on the benign scale, the form both the encoder and the variant B target read.

        Input:  Block 8 contexts (N, d_s)
        Output: (N, d_s); the identity until fit_normalisation has been called
        """
        return (s - self.s_mean) / self.s_std

    def forward(self, s: torch.Tensor, structure: dict | None = None) -> tuple[torch.Tensor, torch.Tensor]:
        if self.encoder_kind == "window":
            if structure is None:
                raise ValueError("the window encoder needs the window's structure")
            z = self.encoder(s, structure)
        else:
            z = self.encoder(s)
        return z, self.decoder(z)


def squared_error(reconstruction: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
    """Per-column squared error of each event.

    Input:  reconstruction and target (N, W)
    Output: (N, W)
    """
    return (reconstruction - target) ** 2


def benign_reference(error: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Column mean and spread of the benign training errors, the scale the score is read against.

    Input:  per-column errors of benign training events (N, W)
    Output: (mean (W,), std (W,) with zeros replaced by 1)
    """
    mean, std = error.mean(0), error.std(0)
    return mean.astype(np.float32), np.where(std < 1e-12, 1.0, std).astype(np.float32)


def anomaly_score(error: np.ndarray, reference: tuple[np.ndarray, np.ndarray]) -> np.ndarray:
    """One score per event: the reconstruction error standardised on benign training events, then averaged.

    Input:  per-column errors (N, W), the benign reference from benign_reference
    Output: (N,) score; higher is less like benign traffic

    Standardising first stops whichever column reconstructs worst from deciding the score, as in Block 7.
    """
    mean, std = reference
    return ((error - mean) / std).mean(1)
