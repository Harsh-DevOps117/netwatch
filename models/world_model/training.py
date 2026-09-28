"""Module 4 — losses, the optimiser step and the epoch loop, kept out of the model.

Separated deliberately: the model can then be unit-tested as synthetic-event-in, shape-checked-output, with no training
loop involved, and a training bug cannot hide behind a forward-pass bug or the reverse.

Two heads, two losses, and the weighting between them is the open question the design parks rather than settles:

**Auxiliary — next-event prediction.** Dense: every event supplies a positive pair and a sampled negative one. This is
the loss that makes the state model ordinary traffic, which is what lets a deviation register as surprise.

**Primary — ranking.** Sparse: only an event with a resolved attacker/victim role supplies a target. Every day in the
ingested set except Bot and Infiltration supplies almost none, so the ranking loss sees orders of magnitude fewer
examples than the auxiliary one. `--rank-weight` exists because of that imbalance and its right value is unmeasured;
the default of 1.0 is a starting point, not a finding.

The loop refuses to train a ranking head against absent supervision rather than reporting a loss that falls anyway —
see `ranking_supervision_available`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

from models.training import Telemetry, load_resume, make_schedule, step_schedule
from models.world_model.dataset import TrainingStep, ranking_supervision_available, steps
from models.world_model.model import FORMAT, WorldModel
from models.world_model.reception import SPLIT_TEST, SPLIT_TRAIN, SPLIT_VAL, ReceivedRun


@dataclass
class Batch:
    """One chunk of steps as tensors on the model's device."""

    initiator: torch.Tensor
    responder: torch.Tensor
    z: torch.Tensor
    dt_init: torch.Tensor
    dt_resp: torch.Tensor
    t_obs: torch.Tensor
    neighbours_initiator: torch.Tensor
    neighbours_responder: torch.Tensor
    true_target: torch.Tensor
    negatives: torch.Tensor
    neighbour_nodes_candidates: torch.Tensor
    positions: np.ndarray
    starts_day: bool
    # Rows with a resolved target, as device indices computed on the CPU from the steps. Asking the device instead
    # (`(true_target >= 0).any()` and a boolean mask) cost a CPU<->GPU synchronisation every chunk.
    resolved: "torch.Tensor | None" = None


def collate(chunk: "list[TrainingStep]", run: ReceivedRun, device: str) -> Batch:
    """Turn a list of steps into one batch of tensors.

    Input:  the steps, the run they index into, the device
    Output: a Batch

    `z` and the `dt` values are read from the day's arrays by position rather than copied into each step, which is why a
    step stays small enough to stream millions of them.
    """
    day = run.days[chunk[0].day_index]
    positions = np.fromiter((step.position for step in chunk), int, len(chunk))
    as_tensor = lambda values, dtype: torch.as_tensor(np.asarray(values), dtype=dtype, device=device)
    return Batch(
        initiator=as_tensor([s.initiator for s in chunk], torch.long),
        responder=as_tensor([s.responder for s in chunk], torch.long),
        z=as_tensor(day.z[positions], torch.float32),
        dt_init=as_tensor(day.dt_src[positions], torch.float32),
        dt_resp=as_tensor(day.dt_dst[positions], torch.float32),
        t_obs=as_tensor(day.t_obs[positions], torch.float32),
        # Node ids, not stream positions: the attention layer indexes the memory table with these.
        neighbours_initiator=as_tensor(np.stack([s.neighbour_nodes_initiator for s in chunk]), torch.long),
        neighbours_responder=as_tensor(np.stack([s.neighbour_nodes_responder for s in chunk]), torch.long),
        true_target=as_tensor([s.true_target for s in chunk], torch.long),
        negatives=as_tensor(np.stack([s.negatives for s in chunk]), torch.long),
        # (B, 1 + negatives, S): each ranking candidate's own gated neighbourhood.
        neighbour_nodes_candidates=as_tensor(np.stack([s.neighbour_nodes_candidates for s in chunk]), torch.long),
        positions=positions, starts_day=chunk[0].starts_day,
        resolved=(as_tensor(np.flatnonzero([s.true_target >= 0 for s in chunk]), torch.long)
                  if any(s.true_target >= 0 for s in chunk) else None),
    )


def auxiliary_loss(model: WorldModel, batch: Batch) -> torch.Tensor:
    """Next-event prediction: the observed pair against a shuffled one.

    Input:  the model, a batch
    Output: a scalar loss

    The negative pair is the batch's own responders rolled by one, which keeps the negatives on the same traffic
    distribution as the positives. Drawing them uniformly from the address space would make the task trivially easy and
    teach the state nothing about ordinary traffic.
    """
    h_init, _ = model.embed(batch.initiator, batch.neighbours_initiator, batch.t_obs)
    h_resp, _ = model.embed(batch.responder, batch.neighbours_responder, batch.t_obs)
    positive = model.next_event(h_init, h_resp)
    shuffled = torch.roll(h_resp, shifts=1, dims=0)
    negative = model.next_event(h_init, shuffled)
    logits = torch.cat([positive, negative])
    target = torch.cat([torch.ones_like(positive), torch.zeros_like(negative)])
    return F.binary_cross_entropy_with_logits(logits, target)


def ranking_loss(model: WorldModel, batch: Batch) -> "torch.Tensor | None":
    """Cross-entropy over candidates, with the true victim as the positive.

    Input:  the model, a batch
    Output: a scalar loss, or None when no step in the batch has a resolved target

    None rather than zero: a zero would average into the epoch's loss and read as "the ranking head is doing well on a
    batch it never saw", which is the kind of number that survives into a report.
    """
    resolved = batch.resolved
    if resolved is None:
        return None
    candidates = torch.cat([batch.true_target[resolved].unsqueeze(1), batch.negatives[resolved]], dim=1)
    valid = candidates >= 0
    safe = candidates.clamp(min=0)
    flat_positions = safe.reshape(-1)
    times = batch.t_obs[resolved].repeat_interleave(safe.shape[1])
    # Each candidate is embedded over its own gated neighbourhood (section 4.6). Passing no neighbours here instead
    # returns the zero vector for every candidate -- layer 1 zeroes an empty neighbourhood and the node's own memory
    # only enters as the attention query -- so the scores were identical and the loss sat at ln(candidates) forever.
    neighbourhoods = batch.neighbour_nodes_candidates[resolved].reshape(flat_positions.numel(), -1)
    embedded, _ = model.embed(flat_positions, neighbourhoods, times)
    embedded = embedded.reshape(*safe.shape, -1)
    state, _ = model.global_state(candidates, batch.t_obs[resolved])
    scores, _ = model.rank(embedded, state, valid)
    # The true target is column 0 by construction, so the label is 0 for every row.
    target = torch.zeros(scores.shape[0], dtype=torch.long, device=scores.device)
    return F.cross_entropy(scores, target)


def run_epoch(model: WorldModel, run: ReceivedRun, *, split: int, optimiser=None, window: int = 256,
              rank_weight: float = 1.0, device: str = "cpu", limit: int | None = None,
              neighbours: int = 20, negatives: int = 5, seed: int = 0) -> dict:
    """One pass over the run, training when an optimiser is given.

    Input:  the model, the run, which split, the optimiser or None, events per chunk, the ranking loss weight, device,
            an optional cap on events, the neighbourhood size, negatives per step, seed
    Output: dict of mean losses and counts

    Memory is reset at every day boundary, because node ids are re-derived per day. Chunks are processed in stream
    order, never shuffled: the memory update is sequential and shuffling would feed a node's later event before its
    earlier one.
    """
    training = optimiser is not None
    model.train(training)
    totals = {"auxiliary": 0.0, "ranking": 0.0, "events": 0, "batches": 0, "ranking_batches": 0}
    chunk: list[TrainingStep] = []
    for step in steps(run, size=neighbours, negatives=negatives, seed=seed, splits=(split,), limit_per_day=limit):
        if step.starts_day:
            # The previous day's last chunk trains against the previous day's memory, and only then does memory reset.
            # The other order scored that chunk against the next day's empty table.
            if chunk:
                _apply(model, collate(chunk, run, device), optimiser, rank_weight, totals, training)
                chunk = []
            model.reset(run.days[step.day_index].node_count)
        chunk.append(step)
        if len(chunk) >= window:
            _apply(model, collate(chunk, run, device), optimiser, rank_weight, totals, training)
            chunk = []
    if chunk:
        _apply(model, collate(chunk, run, device), optimiser, rank_weight, totals, training)
    batches = max(totals["batches"], 1)
    return {"auxiliary_loss": float(totals["auxiliary"]) / batches,
            "ranking_loss": float(totals["ranking"]) / max(totals["ranking_batches"], 1),
            "events": totals["events"], "batches": totals["batches"],
            "ranking_batches": totals["ranking_batches"]}


def _apply(model, batch, optimiser, rank_weight, totals, training) -> None:
    """One chunk: forward, loss, and the memory update.

    The memory update runs under `no_grad` after the optimiser step. Memory is state carried between events, not a
    parameter, so backpropagating through the whole day's updates would both explode the graph and train the wrong
    thing.
    """
    context = torch.enable_grad() if training else torch.no_grad()
    with context:
        auxiliary = auxiliary_loss(model, batch)
        ranking = ranking_loss(model, batch)
        loss = auxiliary if ranking is None else auxiliary + rank_weight * ranking
        if training:
            optimiser.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimiser.step()
    # Accumulated on the device; run_epoch reads them back once, at the end of the pass.
    totals["auxiliary"] = totals["auxiliary"] + auxiliary.detach().double()
    if ranking is not None:
        totals["ranking"] = totals["ranking"] + ranking.detach().double()
        totals["ranking_batches"] += 1
    totals["events"] += len(batch.positions)
    totals["batches"] += 1
    with torch.no_grad():
        model.observe(batch.initiator, batch.responder, batch.z, batch.dt_init, batch.dt_resp, batch.t_obs)


def train(run: ReceivedRun, *, epochs: int = 3, lr: float = 1e-3, window: int = 256, rank_weight: float = 1.0,
          device: str | None = None, out: "Path | None" = None, tensorboard: "Path | None" = None,
          run_name: str = "", resume: "Path | None" = None, schedule: str = "none", patience: int = 2,
          limit: int | None = None, seed: int = 0, select: str = "auxiliary", restart_schedule: bool = False) -> list:
    """Fit the world model over a received run.

    Input:  the run, epochs, learning rate, chunk width, the ranking weight, device, where to save, telemetry options,
            resume file, LR schedule, early-stopping patience, an event cap for smoke runs, seed, which validation loss
            chooses best.pt ("auxiliary" or "ranking"), whether a resumed run restarts its schedule
    Output: the per-epoch history

    Extending a finished run: `epochs` above the resumed epoch continues it. A cosine schedule restored from the file
    has already annealed over the old epoch count and would climb back to `lr` if simply continued, so
    `restart_schedule` starts a fresh one from `lr` over the remaining epochs. `select` may change on resume; best.pt
    is then re-pointed at the best epoch trained so far under the new choice.

    Refuses to start when no day carries ranking supervision **and** a non-zero ranking weight is asked for: the head
    would train against a constant and report a loss that falls, which is worse than an error.
    """
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    supervised = [day.day for day in run.days if ranking_supervision_available(day)]
    if rank_weight and not supervised:
        raise SystemExit(
            "no day in this run carries attacker/victim supervision, so the ranking head cannot be trained. The "
            "`role` column comes from models.data.roles and is written by the compressor's export; re-export, or pass "
            "rank_weight=0 to train the auxiliary head alone")
    if supervised:
        print(f"ranking supervision from: {', '.join(supervised)}", flush=True)

    torch.manual_seed(seed)
    nodes = max(day.node_count for day in run.days)
    model = WorldModel(nodes=nodes).to(device)
    optimiser = torch.optim.Adam(model.parameters(), lr=lr)
    scheduler = make_schedule(optimiser, schedule, epochs, patience)
    # memory and last_seen are per-day state sized to the day last run, reset before every epoch: never restored.
    state = load_resume(resume, model, optimiser, scheduler, higher_is_better=False, device=device,
                        runtime=("memory", "last_seen"))
    if select not in ("auxiliary", "ranking"):
        raise ValueError("select must be 'auxiliary' or 'ranking'")
    watch = f"val_{select}_loss"
    if restart_schedule and state.epoch:
        for group in optimiser.param_groups:
            group["lr"] = group["initial_lr"] = lr
        scheduler = make_schedule(optimiser, schedule, max(epochs - state.epoch, 1), patience)
    if state.history and out is not None:
        # The best so far under the chosen loss, so a changed choice does not keep a best.pt picked by the other one.
        best_row = min(state.history, key=lambda row: row[watch])
        if best_row[watch] != state.best:
            state.best, state.stale = best_row[watch], 0
            source = Path(out) / f"epoch_{best_row['epoch']:02d}.pt"
            if source.exists():
                import shutil
                shutil.copy2(source, Path(out) / "best.pt")
                print(f"best.pt -> epoch {best_row['epoch']} (best validation {select} loss {state.best:.5f})", flush=True)
    board = Telemetry(tensorboard, run_name)
    history = list(state.history)
    for epoch in range(state.epoch, epochs):
        model.reset(nodes)
        train_metrics = run_epoch(model, run, split=SPLIT_TRAIN, optimiser=optimiser, window=window,
                                 rank_weight=rank_weight, device=device, limit=limit, seed=seed + epoch)
        model.reset(nodes)
        with torch.no_grad():
            val_metrics = run_epoch(model, run, split=SPLIT_VAL, window=window, rank_weight=rank_weight,
                                    device=device, limit=limit, seed=seed + epoch)
        row = {"epoch": epoch + 1,
               **{f"train_{k}": v for k, v in train_metrics.items()},
               **{f"val_{k}": v for k, v in val_metrics.items()}}
        history.append(row)
        print(f"epoch {epoch + 1}: train aux {train_metrics['auxiliary_loss']:.5f} "
              f"rank {train_metrics['ranking_loss']:.5f} | val aux {val_metrics['auxiliary_loss']:.5f} "
              f"rank {val_metrics['ranking_loss']:.5f}", flush=True)
        board.log(epoch + 1, prefix="epoch", **{k: v for k, v in row.items() if k != "epoch"})
        board.log(epoch + 1, prefix="epoch", lr=optimiser.param_groups[0]["lr"])
        watched = val_metrics[f"{select}_loss"]
        step_schedule(scheduler, metric=watched)
        improved = state.improved(watched)
        state.epoch, state.history = epoch + 1, history
        if resume is not None:
            state.save(resume, model, optimiser, scheduler)
        if out is not None:
            Path(out).mkdir(parents=True, exist_ok=True)
            # Weights only: memory and last_seen are per-day state that load_model never restores, and on five days
            # they were most of the file (7.1 MB of 8.6 on one day's 17,657 nodes, growing with the host count).
            checkpoint = {"format": FORMAT, "nodes": nodes, "window": window,
                          "model": {k: v for k, v in model.state_dict().items() if k not in ("memory", "last_seen")},
                          "epoch": epoch + 1, "val_auxiliary_loss": val_metrics["auxiliary_loss"],
                          "val_ranking_loss": val_metrics["ranking_loss"], "selected_on": select,
                          "rank_weight": rank_weight,
                          "days": [day.day for day in run.days]}
            torch.save(checkpoint, Path(out) / f"epoch_{epoch + 1:02d}.pt")   # every epoch kept; ~1.5 MB each
            if improved:
                torch.save(checkpoint, Path(out) / "best.pt")
        if not improved and state.stale >= patience:
            print(f"early stop: best validation {select} loss {state.best:.5f}", flush=True)
            break
    board.close()
    if out is not None:
        import pandas as pd
        Path(out).mkdir(parents=True, exist_ok=True)
        pd.DataFrame(history).to_csv(Path(out) / "history.csv", index=False)
        if (Path(out) / "best.pt").exists():
            best_metrics(model, run, Path(out), history, window=window, rank_weight=rank_weight, device=device,
                         limit=limit, seed=seed)
    return history


def best_metrics(model: WorldModel, run: ReceivedRun, out: Path, history: list[dict], *, window: int,
                 rank_weight: float, device: str, limit: int | None, seed: int) -> None:
    """The best checkpoint's losses on train, validation and -- where the run has one -- test. Writes best_metrics.csv.

    Train and validation are the best epoch's own rows; test is scored once here with the saved weights, the same way
    validation is, and never used to choose anything. Calibration (models.world_model.calibration) adds the served
    score's AUC and recall per split on top.
    """
    import pandas as pd

    best = torch.load(out / "best.pt", map_location=device, weights_only=False)
    model.load_state_dict({k: v for k, v in best["model"].items() if k not in ("memory", "last_seen")}, strict=False)
    row = next(r for r in history if r["epoch"] == best["epoch"])
    rows = [{"stage": stage, "epoch": best["epoch"],
             **{k[len(stage) + 1:]: v for k, v in row.items() if k.startswith(f"{stage}_")}} for stage in ("train", "val")]
    if bool((np.concatenate([day.split for day in run.days]) == SPLIT_TEST).any()):
        model.reset(model.nodes)
        with torch.no_grad():
            test = run_epoch(model, run, split=SPLIT_TEST, window=window, rank_weight=rank_weight, device=device,
                             limit=limit, seed=seed)
        rows.append({"stage": "test", "epoch": best["epoch"], **test})
        print(f"test: aux {test['auxiliary_loss']:.5f} rank {test['ranking_loss']:.5f}", flush=True)
    else:
        print("test: the run has no test split", flush=True)
    pd.DataFrame(rows).to_csv(out / "best_metrics.csv", index=False)
