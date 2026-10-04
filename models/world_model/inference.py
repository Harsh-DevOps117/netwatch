"""Scoring a trained world model, and writing the output contract of design section 8.

Separate from `training.py` because it is a different job with different rules: no gradients, no negative sampling for a
loss, and memory advancing over the split being scored rather than the one being fitted.

Three artefacts come out, per the contract: the per-event risk scores, the rollout trajectories, and the attention
weights that are the explainability record. The attention weights are taken from the model's own forward pass, not
recomputed afterwards, so what is written is what drove the score.
"""
from __future__ import annotations

import subprocess
from collections import deque
from pathlib import Path

import numpy as np
import torch

from models.world_model.dataset import Neighbourhoods, neighbour_nodes, steps
from models.world_model.model import DT_COLD, FORMAT, FORMAT_V1, WorldModel
from models.world_model.output import (LAYER_GLOBAL, LAYER_NEIGHBOURHOOD, write_attention, write_manifest,
                                       write_risk_scores, write_rollouts)
from models.world_model.reception import SPLIT_TEST, ReceivedRun

# Buffers that are per-day state rather than weights; never restored from a checkpoint.
RUNTIME_STATE = {"memory", "last_seen"}


def _commit() -> str:
    """The producing commit, for the manifest. 'unknown' rather than a guess when git is unavailable."""
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def load_model(checkpoint: "str | Path", nodes: int, device: str = "cpu") -> WorldModel:
    """Rebuild a trained world model.

    Input:  the checkpoint, how many nodes the run has, device
    Output: the model in eval mode with gradients off

    The memory table is sized for this run rather than restored from the checkpoint: memory is per-day state, and the
    day being scored is not necessarily the day that was trained on. Restoring it also failed outright on a run with
    more nodes than the checkpoint, since the saved table has the training run's shape.

    A v1 checkpoint is rebuilt with v1's arithmetic (no memory residual), so its calibrated threshold still holds.
    """
    state = torch.load(checkpoint, map_location=device, weights_only=False)
    if state.get("format") not in (FORMAT, FORMAT_V1):
        raise ValueError(f"{checkpoint}: not a Block 10 checkpoint (format {state.get('format')!r})")
    model = WorldModel(nodes=nodes, residual=state["format"] == FORMAT).to(device)
    weights = {k: v for k, v in state["model"].items() if k not in RUNTIME_STATE}
    missing, unexpected = model.load_state_dict(weights, strict=False)
    if set(missing) - RUNTIME_STATE or unexpected:
        raise ValueError(f"{checkpoint}: weights do not match the model: missing {missing}, unexpected {unexpected}")
    return model.eval().requires_grad_(False)


def recently_active(day, last: int, window: int, cap: int) -> np.ndarray:
    """The `cap` nodes most recently seen at or before position `last`, most recent first.

    Input:  the day, the last position, how many events back to look, how many nodes to keep
    Output: node ids

    Recency, not id order: `np.unique(...)[-cap:]` keeps the highest node ids, which are simply the hosts first seen
    latest in the day, and routinely dropped the very node the campaign was hitting.
    """
    span = slice(max(0, last - window), last + 1)
    both = np.stack([day.sender[span], day.receiver[span]], axis=1)[::-1].ravel()
    _, first = np.unique(both, return_index=True)
    return both[np.sort(first)][:cap]


@torch.no_grad()
def target_probability(model: WorldModel, index: Neighbourhoods, day, first: int, *, active_window: int = 4096,
                       cap: int = 64, device: str = "cpu") -> dict:
    """The ranking head's distribution over which active node the campaign reaches next, before position `first`.

    Input:  the model (memory as of just before `first`), the day's causal neighbour index, the day, the chunk's first
            position, how far back "active" looks, how many candidates, device
    Output: {node id: probability}

    Each candidate is embedded over its gated neighbourhood at the chunk's first observation time, the same way the
    head was trained; with no neighbours `embed` returns the zero vector and every candidate scores alike. Everything
    read is strictly before the chunk, so every row of the chunk can use it without lookahead.
    """
    if first <= 0:
        return {}
    cand = recently_active(day, first - 1, active_window, cap)
    at = float(day.t_obs[first])
    hoods = torch.as_tensor(np.stack([neighbour_nodes(day, int(n), index.before(int(n), at)) for n in cand]),
                            dtype=torch.long, device=device)
    nodes = torch.as_tensor(cand, dtype=torch.long, device=device)
    when = torch.full((len(cand),), at, device=device)
    embedded, _ = model.embed(nodes, hoods, when)
    state, _ = model.global_state(nodes.unsqueeze(0), when[:1])
    scores, _ = model.rank(embedded.unsqueeze(0), state)
    return dict(zip(cand.tolist(), torch.softmax(scores[0], dim=0).tolist()))


@torch.no_grad()
def rollout_graph(model: WorldModel, index: Neighbourhoods, day, attacker: int, target: int, z: torch.Tensor,
                  t_obs: float, active: torch.Tensor, *, steps: int, top: int = 3, gap: float = 1.0) -> list[dict]:
    """Roll the campaign forward, letting the ranking head choose each step's next target.

    Input:  the model (memory at the observed state), the day's causal neighbour index, the day, the seed's attacker
            and target node ids, its z, its observation time, the active node ids, steps, how many candidates to keep,
            the assumed gap between imagined events
    Output: one dict per step: step, chosen target, that link's surprise, and the leading candidates with their ranking
            probability and surprise

    The imagined event (attacker -> current target) advances memory, then the ranking head scores every active node
    against the new state and the top one becomes the next target. So the predicted graph can move to new hosts, which
    re-scoring one fixed link never could. Every node is embedded over its real gated neighbourhood plus the imagined
    events: with no neighbours `embed` returns the zero vector, and every pair scored identically.

    Surprise is `softplus(-pair_logit)`, the exact function `models.world_model.calibration` thresholds, so a predicted
    link can be compared with the served threshold directly.
    """
    device = active.device
    size = index.size
    imagined: dict[int, list[int]] = {}

    def hoods(nodes: np.ndarray, at: float) -> torch.Tensor:
        rows = []
        for node in nodes.tolist():
            seen = neighbour_nodes(day, node, index.before(node, t_obs + 1e-9))
            merged = (imagined.get(node, [])[::-1] + [p for p in seen.tolist() if p >= 0])[:size]
            rows.append(merged + [-1] * (size - len(merged)))
        return torch.as_tensor(rows, dtype=torch.long, device=device)

    def dt(node: int, at: float) -> float:
        last = float(model.last_seen[node])
        return DT_COLD if np.isnan(last) else max(at - last, 0.0)

    candidates = active[active != attacker]
    if not len(candidates):
        return []
    cand = candidates.cpu().numpy()
    time, out = float(t_obs), []
    for step in range(steps):
        pair = torch.as_tensor([attacker], device=device), torch.as_tensor([target], device=device)
        model.observe(*pair, z, torch.tensor([dt(attacker, time)], device=device),
                      torch.tensor([dt(target, time)], device=device), torch.tensor([time], device=device))
        imagined.setdefault(attacker, []).append(target)
        imagined.setdefault(target, []).append(attacker)
        time += gap
        when = torch.full((len(cand),), time, device=device)
        embedded, _ = model.embed(candidates, hoods(cand, time), when)
        state, _ = model.global_state(candidates.unsqueeze(0), when[:1])
        scores, _ = model.rank(embedded.unsqueeze(0), state)
        probability = torch.softmax(scores[0], dim=0)
        order = probability.argsort(descending=True)[:top]
        h_attacker, _ = model.embed(pair[0], hoods(np.array([attacker]), time), when[:1])
        surprise = torch.nn.functional.softplus(-model.next_event(h_attacker.expand(len(order), -1), embedded[order]))
        ranked = [{"node": int(cand[i]), "probability": float(probability[i]), "surprise": float(s)}
                  for i, s in zip(order.tolist(), surprise.tolist())]
        target = ranked[0]["node"]
        out.append({"step": step, "target": target, "surprise": ranked[0]["surprise"], "candidates": ranked})
    return out


# ponytail: a fixed chunk count, so a short run costs at most this many forward passes; tune if a window is slow.
MIN_CHUNKS = 64


def chunking(events: int, trained: int) -> "tuple[int, int]":
    """Chunk width and seed span for a run of `events` events and a checkpoint trained at width `trained`.

    A run shorter than one chunk (a live window: tens to hundreds of events against a trained width of 512) was scored
    whole against the empty memory: every surprise one of a few constants, the target probability zero, the
    neighbourhood attention uniform over its slots. Narrower chunks let the run's earlier events build the state its
    later ones are scored against. A run of MIN_CHUNKS full chunks or more keeps the trained width.

    A narrowed run still starts cold, and its first events are surprising for that alone, so only its later half
    seeds a rollout.
    """
    window = min(trained, max(1, -(-events // MIN_CHUNKS)))
    return window, (trained if window == trained else max(1, events // 2))


class Replay:
    """Scores a run chunk by chunk and keeps the model's memory between calls, so a caller can advance it in place.

    Input:  the received run, a trained checkpoint, neighbourhood size, chunk width, which split codes to walk (None
            walks every event in stream order, as a live sensor would), device, how far back "active" looks, the
            candidate cap, whether to keep attention rows, and how many scored rows to keep (None keeps all)
    Output: object; `advance(n)` scores at least n more events, `finish()` scores a trailing partial chunk,
            `rollout(k, seeds)` rolls the current state forward

    One implementation behind both `emit`, which scores a slice and writes the contract files, and the forecast service,
    which advances a few chunks at a time so its input keeps moving instead of being re-scored from the day's start.
    """

    def __init__(self, run: ReceivedRun, checkpoint: "str | Path", *, neighbours: int = 20, window: "int | None" = None,
                 split: "tuple[int, ...] | None" = (SPLIT_TEST,), device: str | None = None,
                 active_window: int = 4096, max_candidates: int = 64, attention: bool = True,
                 keep: int | None = None):
        # The chunk width the checkpoint was trained with, unless the caller insists: serving at another width reads a
        # different staleness than training saw. Checkpoints from before the width was recorded were trained at 256.
        # `span` is how many of the latest events seed a rollout: one chunk, unless the chunks were narrowed.
        self.span = window
        if window is None:
            trained = int(torch.load(checkpoint, map_location="cpu", weights_only=False).get("window", 256))
            window, self.span = chunking(len(run), trained)
        self.run, self.neighbours, self.window = run, neighbours, window
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.active_window, self.max_candidates, self.attention = active_window, max_candidates, attention
        self.model = load_model(checkpoint, max(day.node_count for day in run.days), self.device)
        self.stream = steps(run, size=neighbours, negatives=5, splits=split)
        self.rows = {k: deque(maxlen=keep) for k in ("event_id", "t", "surprise", "ranking", "population",
                                                      "sender", "receiver")}
        self.attention_rows: list[dict] = []
        self.indexes: dict = {}
        self.chunk: list = []
        self.recent: list = []
        self.recent_attention = None
        self.scored = 0
        self.exhausted = False
        self.day = None

    def index(self, day) -> Neighbourhoods:
        if day.day not in self.indexes:
            self.indexes[day.day] = Neighbourhoods(day.sender, day.receiver, day.t_obs, self.neighbours)
        return self.indexes[day.day]

    def advance(self, events: int) -> int:
        """Score whole chunks until at least `events` more events are scored or the run ends.

        Input:  how many events to add
        Output: how many were scored by this call
        """
        done = 0
        while done < events:
            step = next(self.stream, None)
            if step is None:
                self.exhausted = True
                done += self.finish()
                break
            if step.starts_day:
                # The previous day's last chunk is scored against the previous day's memory, then memory resets.
                done += self.finish()
                self.model.reset(self.run.days[step.day_index].node_count)
            self.chunk.append(step)
            if len(self.chunk) >= self.window:
                done += self.finish()
        return done

    def finish(self) -> int:
        """Score whatever partial chunk is pending. Output: its size."""
        if not self.chunk:
            return 0
        batch, self.chunk = self.chunk, []
        self._flush(batch)
        return len(batch)

    @torch.no_grad()
    def _flush(self, batch) -> None:
        """Score one chunk, record its rows, then advance memory."""
        model, device = self.model, self.device
        day = self.run.days[batch[0].day_index]
        self.day = day
        positions = np.fromiter((s.position for s in batch), int, len(batch))
        to_tensor = lambda v, d: torch.as_tensor(np.asarray(v), dtype=d, device=device)
        initiator = to_tensor([s.initiator for s in batch], torch.long)
        responder = to_tensor([s.responder for s in batch], torch.long)
        t_obs = to_tensor(day.t_obs[positions], torch.float32)
        near_init = to_tensor(np.stack([s.neighbour_nodes_initiator for s in batch]), torch.long)
        near_resp = to_tensor(np.stack([s.neighbour_nodes_responder for s in batch]), torch.long)

        h_init, weights_init = model.embed(initiator, near_init, t_obs)
        h_resp, _ = model.embed(responder, near_resp, t_obs)
        # The auxiliary head's error is the surprise signal: how wrong it was that these two would interact.
        logit = model.next_event(h_init, h_resp)
        surprise = torch.nn.functional.binary_cross_entropy_with_logits(
            logit, torch.ones_like(logit), reduction="none")
        # The ranking is the chunk's causal distribution: candidates embedded over their gated neighbourhoods, from the
        # state before the chunk. Embedding them with no neighbours made every candidate the same zero vector.
        probability = target_probability(model, self.index(day), day, int(positions[0]),
                                         active_window=self.active_window, cap=self.max_candidates, device=device)
        ranked_chunk = sorted(probability.items(), key=lambda item: -item[1])

        if self.attention:
            # The candidate set for the explainability record is every currently-active node, per the design.
            active = recently_active(day, int(positions[-1]), int(positions[-1]) - int(positions[0])
                                     + self.active_window, self.max_candidates)
            pool = to_tensor(np.tile(active, (len(batch), 1)), torch.long)
            _, global_weights = model.global_state(pool, t_obs)
        for row, position in enumerate(positions):
            self.rows["event_id"].append(int(day.event_id[position]))
            self.rows["t"].append(float(day.t[position]))
            self.rows["surprise"].append(float(surprise[row]))
            self.rows["ranking"].append(ranked_chunk)
            self.rows["population"].append(str(day.population[position]))
            self.rows["sender"].append(int(day.sender[position]))
            self.rows["receiver"].append(int(day.receiver[position]))
            if not self.attention:
                continue
            for slot in range(near_init.shape[1]):
                node = int(near_init[row, slot])
                if node >= 0:
                    self.attention_rows.append({"event_id": int(day.event_id[position]),
                                                "layer": LAYER_NEIGHBOURHOOD, "source_node_id": node,
                                                "weight": float(weights_init[row, slot])})
            for query in range(global_weights.shape[1]):
                for slot in range(global_weights.shape[2]):
                    node = int(pool[row, slot])
                    if node >= 0:
                        self.attention_rows.append({"event_id": int(day.event_id[position]), "layer": LAYER_GLOBAL,
                                                    "source_node_id": node,
                                                    "weight": float(global_weights[row, query, slot]),
                                                    "query_index": query})
        self.scored += len(batch)
        model.observe(initiator, responder, to_tensor(day.z[positions], torch.float32),
                      to_tensor(day.dt_src[positions], torch.float32),
                      to_tensor(day.dt_dst[positions], torch.float32), t_obs)
        # The whole batch, with its surprise: the rollout seeds from several distinct hosts, and one event per chunk
        # would only ever offer one.
        recent = [(batch[i], day, positions[i], float(surprise[i])) for i in range(len(batch))]
        # With narrowed chunks the seeds still come from the day's latest `span` events, not only the last chunk.
        keep = self.span - len(recent) if self.window < self.span and self.recent and self.recent[-1][1] is day else 0
        self.recent = self.recent[-keep:] + recent if keep > 0 else recent
        # Aligned with `recent`: each event's initiator-side neighbourhood attention, for models.explanation.
        self.recent_attention = torch.cat([self.recent_attention[-keep:], weights_init]) if keep > 0 else weights_init

    @torch.no_grad()
    def rollout(self, rollout_steps: int = 8, rollout_seeds: int = 1) -> list[dict]:
        """Roll the current state forward from the latest chunk's most surprising events.

        Input:  imagined steps, how many distinct seed hosts
        Output: rollout rows in the contract's shape, plus surprise and candidates

        The latest chunk is where memory is warm -- the state a live system would be in -- and its most surprising
        events are what the current input would alert on. Every seed starts from the same observed state, and the
        observed state is restored afterwards, so a rollout never leaks into what is scored next.
        """
        seeds, seen = [], set()
        for step, day, position, _ in sorted(self.recent, key=lambda item: -item[3]):
            if step.initiator in seen:
                continue
            seen.add(step.initiator)
            seeds.append((step, day, position))
            if len(seeds) >= max(1, rollout_seeds):
                break
        model, device, rows = self.model, self.device, []
        observed = (model.memory.clone(), model.last_seen.clone())
        for step, day, position in seeds:
            model.memory, model.last_seen = observed[0].clone(), observed[1].clone()
            active = recently_active(day, int(position), self.active_window, self.max_candidates)
            z = torch.as_tensor(day.z[position: position + 1], dtype=torch.float32, device=device)
            trajectory = rollout_graph(model, self.index(day), day, step.initiator, step.responder, z,
                                       float(day.t_obs[position]),
                                       torch.as_tensor(active, dtype=torch.long, device=device), steps=rollout_steps)
            risk = 0.0
            for entry in trajectory:
                risk += entry["surprise"]
                rows.append({
                    "seed_id": int(day.event_id[position]), "rollout_step": int(entry["step"]),
                    "sender": int(step.initiator), "receiver": int(entry["target"]),
                    "z": z.cpu().numpy().ravel(), "cumulative_risk": risk,
                    "surprise": entry["surprise"], "candidates": entry["candidates"],
                    # The z fed back is the seed's, so the trajectory stays on the observed manifold by construction. A
                    # learned observation decoder would make this a real check rather than a true-by-definition one.
                    "stays_on_manifold": True,
                })
        model.memory, model.last_seen = observed
        return rows


def emit(run: ReceivedRun, checkpoint: "str | Path", out_dir: "str | Path", *, limit: int = 20_000,
         rollout_steps: int = 8, neighbours: int = 20, window: "int | None" = None, split: int = SPLIT_TEST,
         device: str | None = None, active_window: int = 4096, max_candidates: int = 64,
         rollout_seeds: int = 1) -> dict:
    """Score the split and write the three output files plus the manifest.

    Input:  the received run, a trained checkpoint, the destination, how many events to score, rollout depth, the
            neighbourhood size, the chunk width, which split, device
    Output: dict of row counts per file

    `max_candidates` is a practical cap on file size, not a modelling choice: the design wants no top-N truncation of
    the candidate set, so raising it changes only how much is written, and the most recently active nodes are kept when
    it bites.

    `observation_population` is passed through from the input, never recomputed: every downstream comparison stratifies
    on it, and a recomputed value could disagree with the one the metrics were built from.
    """
    replay = Replay(run, checkpoint, neighbours=neighbours, window=window, split=(split,), device=device,
                    active_window=active_window, max_candidates=max_candidates)
    replay.advance(limit)
    replay.finish()
    rollout_rows = replay.rollout(rollout_steps, rollout_seeds)
    rows = replay.rows
    counts = {
        "risk_scores": write_risk_scores(out_dir, event_id=list(rows["event_id"]), t=list(rows["t"]),
                                         next_event_pred_error=list(rows["surprise"]),
                                         ranking_scores=list(rows["ranking"]),
                                         observation_population=list(rows["population"])),
        "rollout_trajectories": write_rollouts(out_dir, rollout_rows) if rollout_rows else 0,
        "attention_weights": write_attention(out_dir, replay.attention_rows) if replay.attention_rows else 0,
    }
    write_manifest(out_dir, commit=_commit(), days=[day.day for day in run.days], counts=counts)
    print(f"wrote {counts} to {out_dir}", flush=True)
    return counts
