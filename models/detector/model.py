"""The classifier: one hidden layer over a frozen representation, how it is fitted, and how a score becomes a decision."""
from __future__ import annotations

import numpy as np
import torch
import torch.nn.functional as F
from torch import nn

from ingest.sources.flows import BENIGN_LABEL

BENIGN = BENIGN_LABEL["Label"]          # class 0 everywhere: the order families are numbered against
FPR_POINTS = (0.0001, 0.001, 0.01, 0.05)
HIDDEN = 64          # the head's hidden width; saved in the checkpoint so a serving process rebuilds the same shape


def family_codes(label: np.ndarray) -> tuple[np.ndarray, list[str]]:
    """Labels as class indices, benign first.

    Input:  label per event (N,)
    Output: (code (N,) int64 with 0 for benign, families sorted) -- so class k > 0 is families[k - 1]
    """
    families = sorted(set(label) - {BENIGN})
    code = np.zeros(len(label), np.int64)
    for k, name in enumerate(families, start=1):
        code[label == name] = k
    return code, families


class Head(nn.Module):
    """One hidden layer over a frozen representation, one logit per class.

    Input:  feature width, number of classes (benign + families), hidden width
    Output: module; forward(x) returns logits (N, classes)
    """

    def __init__(self, width: int, classes: int, hidden: int = 64):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(width, hidden), nn.ReLU(), nn.Linear(hidden, classes))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def train_head(x: np.ndarray, y: np.ndarray, classes: int, *, hidden: int = HIDDEN, epochs: int = 300,
               chunk: int = 65_536, device: str = "cpu", seed: int = 0) -> tuple[Head, np.ndarray, np.ndarray]:
    """Fit the family classifier on the training split.

    Input:  features (N, W), class codes (N,), number of classes, hidden width, steps, rows per step, device, seed
    Output: (head in eval mode, feature mean, feature std) -- the scaler is part of the model

    Classes are weighted by the inverse of their frequency: attack families are a fraction of a percent of the rows,
    and the objective is recall, so an unweighted fit would learn to answer benign.
    """
    mean, std = x.mean(0), x.std(0) + 1e-6
    features = torch.from_numpy(((x - mean) / std).astype(np.float32)).to(device)
    target = torch.from_numpy(y).to(device)
    counts = np.bincount(y, minlength=classes).astype(np.float64)
    weight = torch.from_numpy((counts.sum() / np.maximum(counts, 1)) ** 0.5).float().to(device)
    torch.manual_seed(seed)
    head = Head(x.shape[1], classes, hidden).to(device)
    optimiser = torch.optim.Adam(head.parameters(), lr=1e-2)
    rng = torch.Generator().manual_seed(seed)
    for _ in range(epochs):
        if len(features) > chunk:
            rows = torch.randint(len(features), (chunk,), generator=rng).to(device)
            batch, labels = features[rows], target[rows]
        else:
            batch, labels = features, target
        optimiser.zero_grad()
        decay = sum(m.weight.square().sum() for m in head.modules() if isinstance(m, nn.Linear))
        (F.cross_entropy(head(batch), labels, weight=weight) + 1e-4 * decay).backward()
        optimiser.step()
    return head.eval(), mean, std


@torch.no_grad()
def class_scores(head: Head, mean: np.ndarray, std: np.ndarray, x: np.ndarray, *, chunk: int = 65_536,
                 device: str = "cpu") -> np.ndarray:
    """Per-class probability of every row.

    Input:  head, the scaler it was fitted with, features (N, W), rows per block, device
    Output: (N, classes) softmax probabilities
    """
    out = [head(torch.from_numpy(((x[i:i + chunk] - mean) / std).astype(np.float32)).to(device)).softmax(-1).cpu()
           for i in range(0, len(x), chunk)]
    return torch.cat(out).numpy() if out else np.zeros((0, 1), np.float32)


def budget_threshold(benign_score: np.ndarray, fpr: float) -> float:
    """The lowest threshold whose false-positive rate on these rows does not exceed the budget.

    Input:  a family's scores on benign rows, the budget
    Output: threshold; alert when score >= threshold

    Read on the validation split, never on the rows being reported.
    """
    if not len(benign_score):
        return np.inf
    return float(np.quantile(benign_score, 1.0 - fpr, method="higher"))
