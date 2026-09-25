"""Training the context encoder: link prediction over the availability-ordered benign stream.

Split out of the CLI so the objective can be read, tested and reused without going through argparse -- the same
shape as models/flow_encoder/train.py. The CLI in __main__.py owns argument parsing, the day loop and
checkpointing; everything that defines *how* Block 8 learns is here.
"""
from __future__ import annotations

from __future__ import annotations
import argparse
import os
import time
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from models.context_encoder.model import ContextEncoder, LinkIds, make_batch
from models.flow_encoder.metrics import average_precision_tied
from torch import nn
import torch.nn.functional as F
from models.context_encoder.data import ARMS, DAYS, attack_slice, load_day, make_stream
from models.context_encoder.record_arm import day_loader
from models.context_encoder.model import ContextEncoder


class LinkPredictor(nn.Module):
    """Scores how likely an event's context is real: a logit from s_{u,v}(t).

    Input:  context width
    Output: module; forward(s (N, d_s)) returns (N,) logits
    """

    def __init__(self, d_s: int = 100):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(d_s, d_s), nn.ReLU(), nn.Linear(d_s, 1))

    def forward(self, s: torch.Tensor) -> torch.Tensor:
        return self.net(s)[:, 0]


def negative_receivers(receiver: np.ndarray, rng: np.random.Generator, tries: int = 4) -> tuple[np.ndarray, np.ndarray]:
    """In-batch negatives: each event read as if it went to another event's receiver.

    Input:  the batch's receivers (N,), generator, how many shuffles to try before giving up on a row
    Output: (fake receiver per row, whether it differs from the real one); rows that stay equal are left out of the loss
    """
    fake = receiver.copy()
    same = np.ones(len(receiver), bool)
    for _ in range(tries):
        if not same.any():
            break
        draw = receiver[rng.integers(0, len(receiver), int(same.sum()))]
        fake[same] = draw
        same = fake == receiver
    return fake, ~same


def run_stream(model: ContextEncoder, head: LinkPredictor, stream: dict, *, batch_size: int = 200,
               device: str = "cpu", optimiser: torch.optim.Optimizer | None = None, seed: int = 0):
    """One pass over a stream in availability order; trains when an optimiser is given.

    Input:  encoder, link predictor, stream dict (make_stream), batch size, device, optimiser or None, seed
    Output: (mean loss, positive logits, negative logits) -- the logits give link-prediction PR-AUC

    Memory starts empty for the stream and carries across its batches, detached between them.
    """
    train = optimiser is not None
    model.train(train)
    head.train(train)
    links = LinkIds(stream["sender"], stream["receiver"])
    model.begin_day(len(links))
    rng = np.random.default_rng(seed)
    n = len(stream["sender"])
    total, seen, positives, negatives = 0.0, 0, [], []
    for start in range(0, n, batch_size):
        rows = np.arange(start, min(start + batch_size, n))
        fake, usable = negative_receivers(stream["receiver"][rows], rng)
        batch = make_batch(stream, rows, model.arm, links, device)
        negative = make_batch(stream, rows, model.arm, links, device, receiver=fake)
        with torch.set_grad_enabled(train):
            s, s_negative = model(batch, negative)
            pos = head(s)
            neg = head(s_negative)[torch.from_numpy(usable).to(device)]
            loss = F.binary_cross_entropy_with_logits(torch.cat([pos, neg]), torch.cat(
                [torch.ones_like(pos), torch.zeros_like(neg)]))
            if train:
                optimiser.zero_grad()
                loss.backward()
                optimiser.step()
        total += float(loss.detach()) * len(rows)
        seen += len(rows)
        positives.append(pos.detach().cpu().numpy())
        negatives.append(neg.detach().cpu().numpy())
    return total / max(seen, 1), np.concatenate(positives), np.concatenate(negatives)


def link_ap(positives: np.ndarray, negatives: np.ndarray) -> float:
    """Tie-aware PR-AUC of real links against sampled negatives.

    Input:  positive logits, negative logits
    Output: PR-AUC, nan when either is empty
    """
    score = np.concatenate([positives, negatives])
    truth = np.r_[np.ones(len(positives), bool), np.zeros(len(negatives), bool)]
    return average_precision_tied(score, truth)
