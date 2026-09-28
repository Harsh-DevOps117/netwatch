"""The world model's accuracy on its two tasks, scored the way training scores its validation and test splits.

Run: uv run python -m tools.measure.world_model_accuracy --latents <latents>/<day> ... --checkpoint <world model .pt> \\
         [--split 2] [--device cuda]

Walks the chosen split's events day by day in chunks, exactly as `training.run_epoch` does (memory reset per day,
updated after each chunk), and reports what the losses stand for:

  ranking (the forecasting task): for each attacker event with a resolved victim, the true victim against the five
      negative candidates training uses -- top-1 accuracy, hit@3 and mean reciprocal rank (chance: 1/6, 1/2, 0.41)
  next-event (the surprise task): each real host pair against the same initiator paired with another event's
      responder -- ROC-AUC, pairwise accuracy (the real pair scored higher) and accuracy at probability 0.5

Six candidates is training's quiz, easier than a live network: tools/measure/forecast_candidates.py and
forecast_beam.py measure the ranking among every recently active host and against what the attacker really did.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch

from models.world_model.dataset import steps
from models.world_model.inference import load_model
from models.world_model.reception import SPLIT_TEST, receive
from models.world_model.training import collate


@torch.no_grad()
def score(model, run, *, split: int, window: int, device: str, neighbours: int = 20, negatives: int = 5) -> dict:
    out = defaultdict(list)
    chunk = []

    def flush(batch):
        h_i, _ = model.embed(batch.initiator, batch.neighbours_initiator, batch.t_obs)
        h_r, _ = model.embed(batch.responder, batch.neighbours_responder, batch.t_obs)
        out["positive"].append(model.next_event(h_i, h_r).cpu())
        out["negative"].append(model.next_event(h_i, torch.roll(h_r, shifts=1, dims=0)).cpu())
        resolved = batch.resolved
        if resolved is not None:
            candidates = torch.cat([batch.true_target[resolved].unsqueeze(1), batch.negatives[resolved]], dim=1)
            valid = candidates >= 0
            safe = candidates.clamp(min=0)
            times = batch.t_obs[resolved].repeat_interleave(safe.shape[1])
            hoods = batch.neighbour_nodes_candidates[resolved].reshape(safe.numel(), -1)
            embedded, _ = model.embed(safe.reshape(-1), hoods, times)
            state, _ = model.global_state(candidates, batch.t_obs[resolved])
            scores, _ = model.rank(embedded.reshape(*safe.shape, -1), state, valid)
            # rank of the true target (column 0): how many valid candidates score strictly higher
            out["rank"].append(((scores[:, 1:] > scores[:, :1]) & valid[:, 1:]).sum(1).cpu())
            out["candidates"].append(valid.sum(1).cpu())
        model.observe(batch.initiator, batch.responder, batch.z, batch.dt_init, batch.dt_resp, batch.t_obs)

    for step in steps(run, size=neighbours, negatives=negatives, seed=0, splits=(split,)):
        if step.starts_day:
            if chunk:
                flush(collate(chunk, run, device))
                chunk = []
            model.reset(run.days[step.day_index].node_count)
        chunk.append(step)
        if len(chunk) >= window:
            flush(collate(chunk, run, device))
            chunk = []
    if chunk:
        flush(collate(chunk, run, device))
    return {k: torch.cat(v).double().numpy() for k, v in out.items()}


def auc(positive: np.ndarray, negative: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(np.r_[np.ones(len(positive)), np.zeros(len(negative))], np.r_[positive, negative]))


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--latents", type=Path, nargs="+", required=True)
    parser.add_argument("--checkpoint", type=Path, nargs="+", required=True)
    parser.add_argument("--split", type=int, default=SPLIT_TEST, help="0 train, 1 validation, 2 test")
    parser.add_argument("--window", type=int, default=512)
    parser.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = parser.parse_args(argv)
    run = receive(args.latents)
    print(f"{', '.join(d.day for d in run.days)}: split {args.split}")
    print(f"{'checkpoint':34s} {'events':>9s} {'next-event AUC':>15s} {'pairwise acc':>13s} {'acc@0.5':>8s} "
          f"{'ranked':>7s} {'top-1':>7s} {'hit@3':>7s} {'MRR':>6s}")
    for checkpoint in args.checkpoint:
        model = load_model(checkpoint, max(d.node_count for d in run.days), args.device)
        s = score(model, run, split=args.split, window=args.window, device=args.device)
        pos, neg = s["positive"], s["negative"]
        rank = s.get("rank", np.zeros(0))
        label = f"{checkpoint.parent.name}/{checkpoint.name}"
        print(f"{label[-34:]:34s} {len(pos):9,d} {auc(pos, neg):15.4f} {np.mean(pos > neg):13.1%} "
              f"{np.mean(np.r_[pos > 0, neg <= 0]):8.1%} {len(rank):7,d} "
              + (f"{np.mean(rank == 0):7.1%} {np.mean(rank < 3):7.1%} {np.mean(1 / (rank + 1)):6.3f}"
                 if len(rank) else f"{'-':>7s} {'-':>7s} {'-':>6s}"))
    print("chance: next-event AUC 0.5; ranking among 6 candidates top-1 16.7%, hit@3 50.0%, MRR 0.408")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
