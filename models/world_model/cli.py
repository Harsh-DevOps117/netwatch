"""Command line for Block 10: receive, train, and write the output contract.

Run: uv run python -m models.world_model --latents data/latents/<run>/<day> ... --out data/model_cache/world_model

Kept separate from `training.py` so the trainer stays importable without argparse, and separate from `model.py` so the
model can be exercised with no CLI at all.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from models.runtime import configure
from models.training import add_training_arguments
from models.world_model.dataset import NEIGHBOURS, ranking_supervision_available
from models.world_model.reception import receive
from models.world_model.inference import emit
from models.world_model.training import train


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--latents", type=Path, nargs="+", required=False,
                        help="one directory per day, each holding event_latents.parquet and its manifest")
    parser.add_argument("--out", type=Path, default=Path("data/model_cache/world_model"))
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--window", type=int, default=256, help="events per chunk; the memory update is sequential")
    parser.add_argument("--neighbours", type=int, default=NEIGHBOURS,
                        help="fixed-recency neighbourhood size, the design's phase-1 default")
    parser.add_argument("--negatives", type=int, default=5, help="hard negatives per ranking step")
    parser.add_argument("--rank-weight", type=float, default=1.0,
                        help="weight on the ranking loss against the auxiliary one. The two tasks differ in density by "
                             "orders of magnitude and the right value is unmeasured; 1.0 is a starting point. 0 trains "
                             "the auxiliary head alone, which is the only option when no day carries role supervision")
    parser.add_argument("--cross-day-memory", action="store_true",
                        help="carry memory across day boundaries. Refused under this schema: node ids are re-derived "
                             "per day, so carried memory would address a different host. There is no override")
    parser.add_argument("--limit", type=int, default=None, help="cap events per split and per day, for a smoke or budgeted run; every day still contributes")
    parser.add_argument("--patience", type=int, default=2)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--select", choices=("auxiliary", "ranking"), default="auxiliary",
                        help="the validation loss that chooses best.pt: auxiliary (next-event) or ranking, the loss of "
                             "the score calibration serves")
    parser.add_argument("--restart-schedule", action="store_true",
                        help="when resuming to more epochs, start a fresh learning-rate schedule from --lr over the "
                             "remaining epochs instead of continuing the finished one")
    parser.add_argument("--emit", type=Path, default=None,
                        help="after training (or with --load alone), run inference over the test split and write the "
                             "three output files and manifest of design section 8 here")
    parser.add_argument("--load", type=Path, default=None,
                        help="score with these saved weights instead of training")
    parser.add_argument("--emit-limit", type=int, default=20_000, help="events to score when emitting")
    parser.add_argument("--rollout-steps", type=int, default=8, help="imagined steps per seed")
    parser.add_argument("--check", action="store_true",
                        help="receive and report the run, then stop: what loaded, and whether ranking supervision "
                             "exists. Costs one pass over the manifests and none over the model")
    add_training_arguments(parser, default_epochs=3)
    args = parser.parse_args(argv)
    configure(fast=False)

    if not args.latents:
        parser.error("--latents needs at least one day directory")
    run = receive(args.latents, cross_day_memory=args.cross_day_memory)
    print(f"received {len(run.days)} day(s), {len(run):,} events, cross_day_memory={run.cross_day_memory}")
    for day in run.days:
        supervised = ranking_supervision_available(day)
        print(f"  {day.day:22s} {len(day):>10,} events  nodes {day.node_count:>7,}  "
              f"ranking supervision: {'yes' if supervised else 'NO (role column absent or all zero)'}")
    if args.check:
        return 0

    checkpoint = args.load
    if checkpoint is None:
        train(run, epochs=args.epochs, lr=args.lr, window=args.window, rank_weight=args.rank_weight,
              out=args.out, tensorboard=args.tensorboard, run_name=args.run_name, resume=args.resume,
              schedule=args.lr_schedule, patience=args.patience, limit=args.limit, seed=args.seed,
              select=args.select, restart_schedule=args.restart_schedule)
        checkpoint = Path(args.out) / "best.pt"
    if args.emit is not None:
        emit(run, checkpoint, args.emit, limit=args.emit_limit, rollout_steps=args.rollout_steps,
             neighbours=args.neighbours, window=args.window)
    return 0
