"""Turn a false-positive budget into a threshold on Block 10's surprise, the way the proxy does it.

Run: uv run python -m models.world_model.calibration --load <best.pt> --latents <dir> [--budget 1e-4]

The score is `next_event_pred_error`, the auxiliary head's surprise -- the per-event signal the design's "surprise
separates" check is about, and the only per-event score this model emits. The threshold is the `1 - budget` quantile of
the **validation benign** scores and is then applied to test, never read from the rows being reported (the oracle
mistake the proxy and `models/evaluation/thresholds.py` both avoid).

**Which tail alerts is measured, not assumed.** The design expects attacks to be surprising. Measured on Thursday-15 the
opposite held -- test ROC-AUC 0.243, zero recall at every budget from the high tail -- because a flood repeats one
attacker/victim pair and is the *most* predictable traffic on the day. So the direction is chosen on **validation**
labels (the split that exists for model decisions) and stored as `direction`: +1 alerts on high surprise, -1 on low.
The served score is `direction * surprise`, and every threshold lives on that signed scale.

Memory walks the whole stream in order, embargo rows included, exactly as a live system would; only the scoring is
masked by split. Every budget's threshold is written into the checkpoint as `thresholds` with the chosen one as
`serve_threshold`, the same fields the proxy stores: a threshold is a point on this model's score scale and dies on
retraining, so it lives beside the weights it was measured with.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import torch

from models.world_model.dataset import Neighbourhoods, steps
from models.world_model.inference import load_model, target_probability
from models.serving.emitter import GAP, PERSIST, AlertEmitter
from models.world_model.reception import SPLIT_TEST, SPLIT_TRAIN, SPLIT_VAL, receive

# The proxy's curve (docs/dev/design/world-model-proxy-results.md section 2), so the two read side by side.
BUDGETS = (1e-2, 1e-3, 3e-4, 1e-4, 3e-5, 1e-6)


@torch.no_grad()
def surprise(run, model, *, window: int = 256, neighbours: int = 20, device: str = "cpu", limit: int | None = None):
    """Per-event surprise over the whole stream, in order.

    Input:  a received run, a loaded model, chunk width, neighbourhood size, device, optional cap on events per day
    Output: dict of arrays: score (surprise), target, split, attack, t_obs, sender

    `target` is the primary head's reading of the same event: the ranking probability that the event's sender or
    receiver is the node the campaign reaches next, from the state before the chunk (so it stays causal).
    """
    out = {k: [] for k in ("score", "target", "split", "attack", "t_obs", "sender")}
    chunk: list = []
    indexes: dict = {}

    def flush(batch):
        day = run.days[batch[0].day_index]
        at = np.fromiter((s.position for s in batch), int, len(batch))
        if day.day not in indexes:
            indexes[day.day] = Neighbourhoods(day.sender, day.receiver, day.t_obs, neighbours)
        probability = target_probability(model, indexes[day.day], day, int(at[0]), device=device)
        out["target"].append(np.maximum(np.vectorize(lambda n: probability.get(int(n), 0.0))(day.sender[at]),
                                        np.vectorize(lambda n: probability.get(int(n), 0.0))(day.receiver[at])))
        as_t = lambda v, d: torch.as_tensor(np.asarray(v), dtype=d, device=device)
        init, resp = as_t([s.initiator for s in batch], torch.long), as_t([s.responder for s in batch], torch.long)
        t_obs = as_t(day.t_obs[at], torch.float32)
        h_i, _ = model.embed(init, as_t(np.stack([s.neighbour_nodes_initiator for s in batch]), torch.long), t_obs)
        h_r, _ = model.embed(resp, as_t(np.stack([s.neighbour_nodes_responder for s in batch]), torch.long), t_obs)
        logit = model.next_event(h_i, h_r)
        out["score"].append(torch.nn.functional.softplus(-logit).cpu().numpy())    # == BCE(logit, 1), as emit writes
        out["split"].append(day.split[at]); out["attack"].append(day.attack[at].astype(bool))
        out["t_obs"].append(day.t_obs[at]); out["sender"].append(day.sender[at])
        model.observe(init, resp, as_t(day.z[at], torch.float32), as_t(day.dt_src[at], torch.float32),
                      as_t(day.dt_dst[at], torch.float32), t_obs)

    for step in steps(run, size=neighbours, negatives=0, limit_per_day=limit):
        if step.starts_day:
            if chunk:
                flush(chunk); chunk = []
            model.reset(run.days[step.day_index].node_count)
        chunk.append(step)
        if len(chunk) >= window:
            flush(chunk); chunk = []
    if chunk:
        flush(chunk)
    return {k: np.concatenate(v) for k, v in out.items()}


def table(scored: dict, budgets=BUDGETS, direction: int = 1, *, calibrate: float = 0.0, seed: int = 0,
          persist: int = PERSIST, gap: float = GAP) -> list[dict]:
    """Threshold per budget from validation benign, and what it costs on test -- raw and after persistence.

    Input:  the output of `surprise`, the budgets, which tail alerts (+1 high, -1 low), the share of train benign to add
            to the calibration rows, a seed for that draw, the persistence run length and incident gap
    Output: one dict per budget, thresholds on the signed scale `direction * surprise`

    `overshoot_vs_budget` is the number to watch, as for the proxy: realised test FPR over the budget. `calibrate` is the
    proxy's `--calibrate`, the remedy its checklist gives for an overshoot; which one wins is measured, not assumed.
    The `persist_*` columns run the test rows through `models.serving.emitter.AlertEmitter` keyed on the sender -- the
    one implementation of the run test -- because the proxy's operating point is a budget *plus* persist-3, and a raw
    threshold alone is not what would be served.
    """
    score, split, attack = direction * scored["score"], scored["split"], scored["attack"]
    calib_rows = (split == SPLIT_VAL) & ~attack
    if calibrate > 0:
        train = np.flatnonzero((split == SPLIT_TRAIN) & ~attack)
        pick = np.random.default_rng(seed).choice(train, size=int(len(train) * calibrate), replace=False)
        calib_rows = calib_rows.copy()
        calib_rows[pick] = True
    calib = score[calib_rows]
    test = split == SPLIT_TEST
    # The test bands' own duration, not the first-to-last span: over several days that span counted the nights and the
    # days between them (371 h for 16.4 h of test on the five days) and understated every rate twenty times.
    from models.evaluation.thresholds import test_hours
    hours = test_hours({"t_obs": scored["t_obs"][test]}) if test.any() else 1e-9
    at = np.flatnonzero(test)
    rows = []
    for budget in budgets:
        threshold = float(np.quantile(calib, 1.0 - budget)) if len(calib) else float("inf")
        alert = score >= threshold
        fp = int((alert & test & ~attack).sum())
        negatives = int((test & ~attack).sum())
        positives = int((test & attack).sum())
        emitter, kept, false_incidents = AlertEmitter(threshold, persist=persist, gap=gap), np.zeros(len(at), bool), 0
        for i, row in enumerate(at):
            before = emitter.alerts
            incident = emitter.push(int(scored["sender"][row]), float(score[row]), float(scored["t_obs"][row]))
            kept[i] = emitter.alerts > before
            false_incidents += incident is not None and not attack[row]
        persist_fp = int((kept & ~attack[at]).sum())
        rows.append({"budget": budget, "threshold": threshold,
                     "fpr": fp / max(negatives, 1), "overshoot_vs_budget": fp / max(negatives, 1) / budget,
                     "recall": int((alert & test & attack).sum()) / max(positives, 1),
                     "false_alarms": fp, "false_alarms_per_hour": fp / hours,
                     "persist_recall": int((kept & attack[at]).sum()) / max(positives, 1),
                     "persist_false_alarms": persist_fp, "persist_false_alarms_per_hour": persist_fp / hours,
                     "false_incidents_per_hour": false_incidents / hours,
                     "calib_benign": int(len(calib)), "test_benign": negatives, "test_attack": positives,
                     "test_hours": hours})
    return rows


def prefix_invariant(run, model_factory, *, prefix: int, window: int, device: str) -> float:
    """Max |difference| between scoring a prefix and the same rows inside a longer run. Must be exactly 0.

    Input:  the run, a callable returning a freshly loaded model, the prefix length, chunk width, device
    Output: the largest absolute difference

    The proxy's causality check, applied here: if any score depended on a later event, truncating the stream would move
    it. The prefix is rounded to whole chunks: a partial last chunk is a different batch shape, and GPU kernels round
    differently by shape (measured ~3e-7), which is float noise rather than lookahead and would hide a real failure.
    """
    prefix = max(window, prefix - prefix % window)
    short = surprise(run, model_factory(), window=window, device=device, limit=prefix)["score"]
    long = surprise(run, model_factory(), window=window, device=device, limit=prefix + 4 * window)["score"]
    # The limit is per day, so the two outputs are laid out day by day with different lengths; compare each day's rows
    # with the same day's rows. Comparing position by position lined one day up against the previous day's later
    # events and reported a failure on a causal model (7.8 on the five-day calibration; 0.0 on any single day).
    worst, at_short, at_long = 0.0, 0, 0
    for day in run.days:
        n = len(day.t_obs)
        a, b = min(prefix, n), min(prefix + 4 * window, n)
        if a:
            worst = max(worst, float(np.abs(short[at_short:at_short + a] - long[at_long:at_long + a]).max()))
        at_short, at_long = at_short + a, at_long + b
    return worst


def auc(scored: dict, split: int = SPLIT_TEST) -> float:
    """ROC-AUC of surprise against the attack label on one split: does surprise separate at all, threshold-free."""
    rows = scored["split"] == split
    s, y = scored["score"][rows], scored["attack"][rows]
    if y.all() or not y.any():
        return float("nan")
    ranks = s.argsort().argsort() + 1.0
    return float((ranks[y].sum() - y.sum() * (y.sum() + 1) / 2) / (y.sum() * (~y).sum()))


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--load", type=Path, required=True, help="a trained Block 10 checkpoint; thresholds go into it")
    parser.add_argument("--latents", type=Path, nargs="+", required=True)
    parser.add_argument("--budget", type=float, default=1e-4, help="the operating point to serve, as for the proxy")
    parser.add_argument("--window", type=int, default=256)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--device", default=None)
    parser.add_argument("--dry-run", action="store_true", help="report only, leave the checkpoint untouched")
    parser.add_argument("--calibrate", type=float, default=0.0,
                        help="share of train benign joining validation to calibrate, as the proxy's flag. The proxy's "
                             "checklist names it as the remedy for a budget overshoot; the table says which is better")
    parser.add_argument("--prefix-check", type=int, default=0,
                        help="also verify prefix invariance on this many events (exact equality required)")
    parser.add_argument("--cache", type=Path, default=None,
                        help="keep the scored stream here and reuse it when present: scoring is the slow part, "
                             "re-choosing a budget should not repeat it")
    parser.add_argument("--score", choices=("auto", "next_event_pred_error", "target_probability"), default="auto",
                        help="the score to serve; auto takes the one with the higher validation recall at --budget")
    args = parser.parse_args(argv)
    device = args.device or ("cuda" if torch.cuda.is_available() else "cpu")

    cached = args.cache is not None and args.cache.is_file()
    # With cached scores the events are only needed for the prefix check: loading every day costs ~8 GB and minutes.
    run = receive(args.latents) if not cached or args.prefix_check else None
    if cached:
        scored = dict(np.load(args.cache))
        print(f"reusing scores from {args.cache}")
    else:
        model = load_model(args.load, max(day.node_count for day in run.days), device)
        scored = surprise(run, model, window=args.window, device=device, limit=args.limit)
        if args.cache is not None:
            np.savez(args.cache, **scored)
    if args.prefix_check:
        factory = lambda: load_model(args.load, max(day.node_count for day in run.days), device)
        drift = prefix_invariant(run, factory, prefix=args.prefix_check, window=args.window, device=device)
        print(f"prefix invariance over {args.prefix_check:,} events: max difference {drift:.3e} "
              f"({'PASS' if drift == 0.0 else 'FAIL -- a score depends on a later event'})")
    budgets = tuple(sorted(set(BUDGETS) | {args.budget}, reverse=True))
    # Two candidate scores, one decision, made on VALIDATION: the tail from its ROC-AUC, the score from its recall at
    # the serving budget. Test is only reported. Choosing the score by ROC-AUC served the surprise at epoch 5 (validation
    # separation 0.85 against 0.77) with zero recall at 0.01%: AUC weighs the whole curve, an alert is only the far tail.
    val, attack = scored["split"] == SPLIT_VAL, scored["attack"].astype(bool)
    candidates = {}
    for name, column in (("next_event_pred_error", "score"), ("target_probability", "target")):
        view = dict(scored, score=scored[column])
        val_auc, test_auc = auc(view, SPLIT_VAL), auc(view)
        direction = -1 if val_auc < 0.5 else 1
        signed = direction * view["score"]
        val_recall = float((signed[val & attack] >= np.quantile(signed[val & ~attack], 1.0 - args.budget)).mean())
        candidates[name] = {"view": view, "val_auc": val_auc, "test_auc": test_auc, "direction": direction,
                            "separation": max(val_auc, 1 - val_auc), "val_recall": val_recall}
        print(f"{name}: ROC-AUC validation {val_auc:.4f}, test {test_auc:.4f}; alerts on the "
              f"{'high' if direction > 0 else 'LOW'} tail; served test ROC-AUC "
              f"{test_auc if direction > 0 else 1 - test_auc:.4f}; validation recall at {args.budget:g} {val_recall:.4%}")
    name = (max(candidates, key=lambda k: (candidates[k]["val_recall"], candidates[k]["separation"]))
            if args.score == "auto" else args.score)
    chosen_score = candidates[name]
    direction, val_auc, separation = chosen_score["direction"], chosen_score["val_auc"], chosen_score["test_auc"]
    print(f"serving {name} ({'chosen on validation' if args.score == 'auto' else 'chosen by --score'}), "
          f"direction {direction:+d}")
    rows = table(chosen_score["view"], budgets, direction, calibrate=args.calibrate)
    for row in rows:
        print("  ".join(f"{k}={v:.6g}" if isinstance(v, float) else f"{k}={v}" for k, v in row.items()))
    if args.dry_run:
        return 0
    state = torch.load(args.load, map_location="cpu", weights_only=False)
    chosen = next(row for row in rows if row["budget"] == args.budget)
    state["score"] = name
    state["direction"] = direction
    state["budget"] = args.budget
    state["thresholds"] = {row["budget"]: row["threshold"] for row in rows}
    state["serve_threshold"] = chosen
    state["calibration"] = {"rows": rows, "val_auc": val_auc, "test_auc": separation, "direction": direction,
                            "candidates": {k: {f: v[f] for f in ("val_auc", "test_auc", "direction", "val_recall")}
                                           for k, v in candidates.items()},
                            "calibrated_on": "validation benign" + (f" + {args.calibrate:g} of train benign"
                                                                    if args.calibrate else "")
                                             + ", direction from validation labels", "persist": PERSIST, "gap": GAP,
                            "days": [p.name for p in args.latents]}
    torch.save(state, args.load)
    print(f"wrote thresholds to {args.load}; serving budget {args.budget} -> threshold {chosen['threshold']:.6g}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
