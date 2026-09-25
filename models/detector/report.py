"""Scoring a fitted head: what a recall target costs, the confusion at a threshold, and the reported tables."""
from __future__ import annotations

import numpy as np
import pandas as pd

from models.flow_encoder.metrics import average_precision_tied
from models.detector.model import BENIGN, FPR_POINTS, family_codes


def cost_of_recall(score: np.ndarray, is_family: np.ndarray, is_benign: np.ndarray,
                   target: float = 0.99, gate: np.ndarray | None = None) -> dict:
    """How many false alarms it takes to catch `target` of the family, and the ranking quality behind that.

    Input:  the family's score per row, family mask, benign mask, the recall to reach
    Output: dict with pr_auc, fp_at_target_oracle, fpr_at_target_oracle, reached

    Recall at a fixed budget saturates -- once an arm reaches 0.997 the next arm cannot show an improvement, and the
    comparison stops being informative. Holding recall fixed and counting the false alarms needed does not saturate,
    and PR-AUC ranks without any threshold at all. Both read the same scores, so they cost nothing extra.

    **The `_oracle` suffix is load-bearing.** Reaching `target` recall requires knowing where the attack scores lie, so
    the threshold behind these two columns is chosen using test labels. No live system can reproduce them: it has no
    test labels. They are valid only for ranking one arm against another on identical rows, and must never be quoted as
    an achievable operating point. For that, use the budget -> quantile -> realised-FPR path in
    models/evaluation/thresholds.py, which never looks at a label.
    """
    family, benign = score[is_family], score[is_benign]
    if not len(family) or not len(benign):
        return {"pr_auc": float("nan"), "fp_at_target_oracle": -1, "fpr_at_target_oracle": float("nan"),
                "reached": False}
    truth = np.r_[np.ones(len(family), bool), np.zeros(len(benign), bool)]
    pr_auc = average_precision_tied(np.r_[family, benign], truth)
    # The threshold that catches `target` of the family is its (1 - target) quantile, taken low so recall is met.
    cut = float(np.quantile(family, 1.0 - target, method="lower"))
    fp = int((benign >= cut).sum())
    out = {"pr_auc": pr_auc, "fp_at_target_oracle": fp, "fpr_at_target_oracle": fp / len(benign),
           "reached": bool((family >= cut).mean() >= target - 1e-9)}
    if gate is not None:
        # `gate` is already the combined score: one ranking, so 99% recall stays reachable and there is no second knob.
        jf, jb = gate[is_family], gate[is_benign]
        jcut = float(np.quantile(jf, 1.0 - target, method="lower"))
        out["fp_at_target_gated_oracle"] = int((jb >= jcut).sum())
        out["pr_auc_gated"] = average_precision_tied(np.r_[jf, jb], truth)
    return out


def confusion(score: np.ndarray, is_family: np.ndarray, is_benign: np.ndarray, threshold: float) -> dict:
    """One family against benign at one threshold, and the best any detector could do there.

    Input:  the family's score per row, family mask, benign mask, threshold
    Output: dict with tp, fp, fn, tn, recall, precision, fpr, alerts, and the ideal_* counterparts

    Rows of *other* families are left out: this answers "does this family's alert fire", not how families separate
    from each other (the multi-class matrix answers that). The ideal spends the same false-positive budget while
    missing nothing, so ideal_precision is the ceiling precision at this budget.
    """
    alert = score >= threshold
    tp = int((alert & is_family).sum())
    fn = int((~alert & is_family).sum())
    fp = int((alert & is_benign).sum())
    tn = int((~alert & is_benign).sum())
    n_family, n_benign = int(is_family.sum()), int(is_benign.sum())
    budget = fp                                        # the ideal is allowed the false positives actually spent
    return {"attacks": n_family, "benign": n_benign, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": tp / n_family if n_family else float("nan"),
            "precision": tp / (tp + fp) if tp + fp else float("nan"),
            "fpr": fp / n_benign if n_benign else float("nan"),
            "alerts": tp + fp,
            "ideal_tp": n_family, "ideal_fn": 0, "ideal_fp": budget, "ideal_tn": n_benign - budget,
            "ideal_recall": 1.0 if n_family else float("nan"),
            "ideal_precision": n_family / (n_family + budget) if n_family + budget else float("nan")}


def report(day: str, data: dict, families: list[str], scores: np.ndarray, thresholds: dict,
           fprs=FPR_POINTS, gated: np.ndarray | None = None) -> list[dict]:
    """Every family, population and budget as one row of confusion counts.

    Input:  day, the day's arrays, family names, per-class scores on the reported rows, thresholds per (family, fpr),
            the budgets
    Output: list of dicts
    """
    rows = []
    for population in ("early_observation", "completed_before_budget"):
        here = data["population"] == population
        is_benign = here & ~data["attack"]
        for k, name in enumerate(families, start=1):
            is_family = here & (data["label"] == name)
            if not is_family.any():
                continue
            cost = cost_of_recall(scores[:, k], is_family, is_benign,
                                  gate=None if gated is None else gated[:, k])
            for fpr in fprs:
                counts = confusion(scores[:, k], is_family, is_benign, thresholds[(name, fpr)])
                rows.append({"day": day, "population": population, "family": name, "fpr_budget": fpr,
                             "threshold": thresholds[(name, fpr)], **counts, **cost})
    return rows


def multiclass_matrix(data: dict, families: list[str], scores: np.ndarray, thresholds: dict,
                      fpr: float) -> pd.DataFrame:
    """True family against what the arm named, at one budget.

    Input:  the day's arrays, family names, per-class scores, thresholds, the budget to use
    Output: DataFrame, rows true class (benign first), columns "none" then each family

    A row is named for the family with the highest score among those over their own threshold; "none" when no family
    clears its threshold.
    """
    over = np.stack([scores[:, k] >= thresholds[(name, fpr)] for k, name in enumerate(families, start=1)], 1)
    masked = np.where(over, scores[:, 1:], -np.inf)
    named = np.where(over.any(1), masked.argmax(1) + 1, 0)
    truth = np.where(data["attack"], 0, 0)
    code, _ = family_codes(data["label"])
    index = [BENIGN, *families]
    matrix = pd.DataFrame(0, index=index, columns=["none", *families], dtype=int)
    for true_k, true_name in enumerate(index):
        rows = code == true_k
        if not rows.any():
            continue
        for pred_k, pred_name in enumerate(["none", *families]):
            matrix.loc[true_name, pred_name] = int((named[rows] == pred_k).sum())
    return matrix
