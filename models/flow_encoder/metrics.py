"""Scoring and evaluation: k-means anomaly score, PR-AUC, the PR-curve threshold, rates and the supervised probe."""

from __future__ import annotations

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from torch import nn


def pr_threshold(score: np.ndarray, y: np.ndarray, min_precision: float | None = None) -> tuple[float, float, float]:
    """Alert threshold read off the precision-recall curve; alert when score >= threshold.

    Input:  scores, boolean attack labels, optional precision floor
    Output: (threshold, precision, recall) at the highest-F1 threshold, or, with min_precision, at the
            highest-recall threshold whose precision reaches the floor (the highest-precision one if none does)

    Tied scores alert together, so every candidate threshold is a distinct score value.
    """
    order = np.argsort(-score, kind="stable")
    s, t = score[order], np.asarray(y, bool)[order]
    last = np.r_[np.flatnonzero(s[1:] != s[:-1]), len(s) - 1]
    tp = np.cumsum(t)[last]
    precision, recall = tp / (last + 1), tp / max(int(t.sum()), 1)
    if min_precision is None:
        total = precision + recall
        best = int(np.argmax(np.divide(2 * precision * recall, total, out=np.zeros_like(total), where=total > 0)))
    else:
        ok = np.flatnonzero(precision >= min_precision)
        best = int(ok[np.argmax(recall[ok])]) if len(ok) else int(np.argmax(precision))
    return float(s[last[best]]), float(precision[best]), float(recall[best])


def average_precision_tied(score: np.ndarray, positive: np.ndarray) -> float:
    """Area under the precision-recall curve, taking tied scores together.

    Input:  scores, boolean positives
    Output: average precision, or nan when either class is absent

    Rows sharing a score are not ranked by where they sit in the array: at 10 ms most of a
    flood's rows share an identical input vector, hence an identical score, with a benign row.
    Precision and recall are taken once per distinct score, as scikit-learn does.
    """
    total = int(positive.sum())
    if not total or total == len(positive):
        return float("nan")
    order = np.argsort(-score, kind="mergesort")
    ranked, hit = score[order], positive[order]
    tp, fp = np.cumsum(hit), np.cumsum(~hit)
    last = np.r_[np.flatnonzero(np.diff(ranked) != 0), len(ranked) - 1]
    tp, fp = tp[last], fp[last]
    return float(np.sum(np.diff(np.r_[0.0, tp / total]) * tp / (tp + fp)))


def bootstrap_ci(metric, *arrays, samples: int = 100, seed: int = 0, level: float = 0.95):
    """Monte Carlo interval for a metric, resampling rows with replacement.

    Input:  metric function, the arrays it takes, resamples, seed, level
    Output: (low, high)
    """
    rng = np.random.default_rng(seed)
    n = len(arrays[0])
    values = []
    for _ in range(samples):
        idx = rng.integers(0, n, n)
        values.append(metric(*(a[idx] for a in arrays)))
    low, high = np.nanpercentile(values, [(1 - level) / 2 * 100, (1 + level) / 2 * 100])
    return float(low), float(high)


def auroc(score: np.ndarray, positive: np.ndarray) -> float:
    """Area under the ROC curve from the Mann-Whitney rank statistic.

    Input:  scores, boolean positives
    Output: AUROC, or nan when either class is absent
    """
    n_pos = int(positive.sum())
    n_neg = len(positive) - n_pos
    if not n_pos or not n_neg:
        return float("nan")
    ranks = pd.Series(score).rank().to_numpy()
    return float((ranks[positive].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def rates(pred: np.ndarray, truth: np.ndarray) -> dict[str, float]:
    """F1, precision, recall and false positive rate of boolean predictions.

    Input:  predicted and true boolean labels
    Output: dict of the four rates (nan on a zero denominator) and the confusion counts
    """
    tp = int((pred & truth).sum())
    fp = int((pred & ~truth).sum())
    fn = int((~pred & truth).sum())
    tn = int((~pred & ~truth).sum())

    def ratio(a: int, b: int) -> float:
        return a / b if b else float("nan")

    return {
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "fpr": ratio(fp, fp + tn),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def probe(
    h_train: np.ndarray, y_train: np.ndarray, h_test: np.ndarray, y_test: np.ndarray,
    *, device: str = "cpu", hidden: int = 64,
    epochs: int = 200, chunk: int = 65_536, return_scores: bool = False,
) -> dict[str, float] | tuple[dict[str, float], np.ndarray]:
    """Supervised classifier (MLP, one hidden layer) on frozen embeddings.

    Input:  train and test embeddings with boolean attack labels, device, hidden width, epochs
    Output: rates on the test rows at the best-F1 point of the PR curve, AUROC and tie-aware PR-AUC;
            with return_scores, also the per-row test scores

    The threshold is chosen on 20% of the fitting rows, which fitted no weights -- never on the test rows.
    """
    cut = int(len(h_train) * 0.8)
    order = np.random.default_rng(0).permutation(len(h_train))
    h_thr, y_thr = h_train[order[cut:]], y_train[order[cut:]]
    h_train, y_train = h_train[order[:cut]], y_train[order[:cut]]

    mean, std = h_train.mean(0), h_train.std(0) + 1e-6
    features = torch.from_numpy((h_train - mean) / std).to(device)
    target = torch.from_numpy(y_train.astype(np.float32)).to(device)
    torch.manual_seed(0)
    net = nn.Sequential(nn.Linear(features.shape[1], hidden), nn.ReLU(), nn.Linear(hidden, 1)).to(device)
    rng = torch.Generator(device="cpu").manual_seed(0)
    optimiser = torch.optim.Adam(net.parameters(), lr=1e-2)
    for _ in range(epochs):
        optimiser.zero_grad()
        decay = sum(m.weight.square().sum() for m in net.modules() if isinstance(m, nn.Linear))
        # A random chunk per step, so the step count stays the same whatever the training-set size.
        if len(features) > chunk:
            rows = torch.randint(len(features), (chunk,), generator=rng).to(device)
            x, y = features[rows], target[rows]
        else:
            x, y = features, target
        loss = F.binary_cross_entropy_with_logits(net(x).squeeze(1), y) + 1e-4 * decay
        loss.backward()
        optimiser.step()

    def score(h):
        with torch.no_grad():
            out = [
                net(torch.from_numpy((h[i:i + chunk] - mean) / std).to(device)).squeeze(1).cpu()
                for i in range(0, len(h), chunk)
            ]
        return torch.cat(out).numpy() if out else np.zeros(0, np.float32)

    threshold = pr_threshold(score(h_thr), y_thr)[0] if y_thr.any() else 0.0
    scores = score(h_test)
    out = {
        **rates(scores >= threshold, y_test),
        "auroc": auroc(scores, y_test),
        "ap_tied": average_precision_tied(scores, y_test),
    }
    return (out, scores) if return_scores else out
