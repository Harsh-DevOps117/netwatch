"""Module 2 — a validated run becomes an ordered stream of training steps.

Three jobs: build each event's neighbourhood under a strict causal gate, mark day boundaries so memory can be reset,
and draw negatives for the ranking head.

**Gate then sample, never the reverse.** Admit only events already observable at the query's `t_obs`, *then* take the S
most recent survivors. Sampling first and gating afterwards biases the neighbourhood toward stale events, because the
recent ones get filtered out after they have already consumed the sample budget.

**The querying event is not its own neighbour.** The gate uses `bisect_left`, which excludes everything at or after the
query's own `t_obs`. `bisect_right` would admit events sharing that timestamp — including the query itself — and the
design records this as a bug that was caught by an explicit leakage check rather than by anything crashing. Ties are
therefore excluded wholesale, which is the conservative reading: two events with identical `t_obs` have no defined order
between them, so neither may inform the other.

**True targets come from `role`, not `reversed`.** The schedule-derived role field (`models.data.roles`) says which
endpoint is the attacker. `reversed` records packet order and answers a different question — on the Bot day it agrees
with the true direction for only 4.1% of attack events. A run whose `role` is entirely zero predates that field, and
`ranking_supervision_available` reports False rather than letting a ranking head train on a constant.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from models.world_model.reception import ReceivedDay, ReceivedRun

# Fixed-recency neighbourhood size. The design's phase-1 default is S in [10, 20]; 20 matches the upstream
# neighbourhood width so the two stages see comparable context.
NEIGHBOURS = 20

ATTACKER_TO_VICTIM, VICTIM_TO_ATTACKER = 1, 2


@dataclass
class TrainingStep:
    """One event, with everything a forward pass and a loss need for it.

    Input:  built by `steps`
    Output: dataclass; `neighbours_*` hold stream positions, -1 padded

    Positions rather than copies: the model indexes the day's arrays, so a step stays small however wide the
    neighbourhood is.
    """

    position: int
    event_id: int
    day_index: int
    starts_day: bool
    t: float
    t_obs: float
    sender: int
    receiver: int
    initiator: int
    responder: int
    unresolved_direction: bool
    neighbours_initiator: np.ndarray
    neighbours_responder: np.ndarray
    # Peer node ids for those positions. Kept beside them rather than instead of them: the positions are what an
    # explainability row cites, the node ids are what the attention layer indexes.
    neighbour_nodes_initiator: np.ndarray
    neighbour_nodes_responder: np.ndarray
    true_target: int
    negatives: np.ndarray
    # The gated neighbourhood of each ranking candidate -- the true target first, then the negatives -- as peer node
    # ids, (1 + negatives, size) and -1 padded. Section 4.6 defines h_v(t) over v's own gated neighbourhood, and the
    # ranking head scores candidates by that h_v(t); embedding them with no neighbours makes every candidate the same
    # zero vector, which pins the ranking loss at ln(candidates) whatever the weights do. All -1 when this step has no
    # resolved target, so the rows stack.
    neighbour_nodes_candidates: np.ndarray


class Neighbourhoods:
    """Per-node history, queried under the causal gate.

    Input:  the day's endpoints and observation times, the neighbourhood size
    Output: object; `before(node, t_obs)` returns the S most recent admissible positions

    Built once per day as a sorted list of positions per node. `before` binary-searches that list, so a query costs
    log(history) rather than a scan of the day.
    """

    def __init__(self, sender: np.ndarray, receiver: np.ndarray, t_obs: np.ndarray, size: int = NEIGHBOURS):
        self.size = size
        self.t_obs = np.asarray(t_obs, dtype=float)
        self.history: dict[int, list[int]] = {}
        self._arrays: dict[int, tuple[np.ndarray, np.ndarray]] = {}
        for position, (u, v) in enumerate(zip(sender.tolist(), receiver.tolist())):
            self.history.setdefault(int(u), []).append(position)
            if int(v) != int(u):
                self.history.setdefault(int(v), []).append(position)

    def before(self, node: int, t_obs: float) -> np.ndarray:
        """The node's S most recent events strictly before `t_obs`, most recent first.

        Input:  a node id, the query's observation time
        Output: (size,) positions, -1 padded

        `bisect_left` over the node's own observation times excludes the boundary, so an event can never appear in its
        own neighbourhood, nor can a simultaneous one inform it.
        """
        out = np.full(self.size, -1, dtype=np.int64)
        # Each node's positions and their observation times are materialised once and cached. Rebuilding the times on
        # every query made a query cost O(history) -- 85% of Block 10's data time, measured, on busy hosts -- where the
        # binary search itself is O(log history). searchsorted(side="left") is exactly bisect_left.
        cached = self._arrays.get(int(node))
        if cached is None:
            positions = self.history.get(int(node))
            if not positions:
                return out
            positions = np.asarray(positions, dtype=np.int64)
            cached = self._arrays[int(node)] = (positions, self.t_obs[positions])
        positions, times = cached
        cut = int(np.searchsorted(times, t_obs, side="left"))
        if cut <= 0:
            return out
        admissible = positions[max(0, cut - self.size):cut][::-1]
        out[:len(admissible)] = admissible
        return out


def neighbour_nodes(day: ReceivedDay, node: int, positions: np.ndarray) -> np.ndarray:
    """The peer node at each neighbouring event.

    Input:  the day, the node whose neighbourhood this is, the neighbour stream positions (-1 padded)
    Output: (S,) node ids, -1 where the slot is padding

    A neighbour position says "this node took part in event p". What the attention layer needs is *whose* memory to
    read, which is the **other** endpoint of that event — the peer. Passing the position itself would index the memory
    table with a stream offset, which is out of range as soon as a day has more events than nodes.
    """
    out = np.full(len(positions), -1, dtype=np.int64)
    real = positions >= 0
    if not real.any():
        return out
    at = positions[real]
    sender, receiver = day.sender[at], day.receiver[at]
    # The peer is whichever endpoint is not this node; a self-loop keeps the node itself.
    out[real] = np.where(sender == node, receiver, sender)
    return out


def ranking_supervision_available(day: ReceivedDay) -> bool:
    """Whether this day carries usable attacker/victim supervision.

    Input:  a received day
    Output: True when `role` distinguishes at least one direction

    An export written before the role field exists loads as all-zero. Training a ranking head against a constant
    teaches it nothing and reports a loss that falls anyway, so the caller must check this rather than discover it in a
    metric.
    """
    return bool(np.isin(day.role, (ATTACKER_TO_VICTIM, VICTIM_TO_ATTACKER)).any())


def resolve_true_target(day: ReceivedDay, position: int) -> int:
    """Which node the ranking head should score highest for this event, or -1 when there is none.

    Input:  a received day, a stream position
    Output: a node id, or -1

    The target is the **victim** of an attack event: for an attacker-to-victim event that is the receiver, and for the
    victim's reply it is the sender. A benign event has no target, and an in-window event between hosts the schedule
    does not pair (`role == 3`) is left unresolved rather than guessed.

    This replaces the interim stub the design flagged under Blocker 1. That stub used `reversed`, which encodes packet
    order; measured on the Bot day it matches the true direction for 4.1% of attack events, so a head trained on it was
    being taught the wrong endpoint for almost every positive.
    """
    role = int(day.role[position])
    if role == ATTACKER_TO_VICTIM:
        return int(day.receiver[position])
    if role == VICTIM_TO_ATTACKER:
        return int(day.sender[position])
    return -1


def sample_negatives(day: ReceivedDay, position: int, true_target: int, count: int,
                     rng: np.random.Generator, active: np.ndarray | None = None) -> np.ndarray:
    """Nodes the campaign did *not* reach at this event.

    Input:  the day, the position, the true target, how many to draw, a generator, the currently-active node ids
    Output: (count,) node ids, -1 padded when the pool is too small

    Drawn from the **active** nodes when they are known, which makes them hard negatives: a node that is currently
    exchanging traffic and still was not the target is a far more informative counterexample than one drawn from the
    whole address space, most of which is idle.
    """
    out = np.full(count, -1, dtype=np.int64)
    if true_target < 0:
        return out
    pool = np.asarray(active, dtype=np.int64) if active is not None and len(active) else None
    if pool is None:
        pool = np.arange(day.node_count, dtype=np.int64)
    pool = pool[(pool != true_target) & (pool != int(day.sender[position]))]
    if not len(pool):
        return out
    drawn = rng.choice(pool, size=min(count, len(pool)), replace=False)
    out[: len(drawn)] = drawn
    return out


def steps(run: ReceivedRun, *, size: int = NEIGHBOURS, negatives: int = 5, seed: int = 0,
          splits: "tuple[int, ...] | None" = None, active_window: int = 4096, limit_per_day: "int | None" = None):
    """Every event of the run as a `TrainingStep`, in order.

    Input:  a received run, the neighbourhood size, how many negatives per step, a seed, which split codes to yield,
            how many recent events define the "currently active" node set, an optional cap on steps yielded per day
            (per day, so a capped multi-day run still sees every day rather than only the first)
    Output: generator of TrainingStep

    A generator, not a list: a day is millions of events and a step holds two neighbourhood arrays, so materialising
    the run would cost more memory than the model.

    `starts_day` marks the first step of each day. With `cross_day_memory` False — which is the only value this schema
    permits — that is where the caller resets memory.
    """
    rng = np.random.default_rng(seed)
    for day_index, day in enumerate(run.days):
        index = Neighbourhoods(day.sender, day.receiver, day.t_obs, size)
        first = True
        yielded = 0
        for position in range(len(day)):
            if limit_per_day is not None and yielded >= limit_per_day:
                break
            if splits is not None and int(day.split[position]) not in splits:
                continue
            yielded += 1
            reversal = int(day.reversed_[position])
            u, v = int(day.sender[position]), int(day.receiver[position])
            # Packet-level direction only. This is not attacker/victim: that is `role`, resolved separately.
            initiator, responder = (v, u) if reversal == 1 else (u, v)
            target = resolve_true_target(day, position)
            # The active set only feeds negative sampling, which only happens for the ~1% of events with a resolved
            # target; computing it for every event was the next-largest cost once neighbourhood lookups were cached.
            active = None
            if target >= 0 and position:
                window = slice(max(0, position - active_window), position)
                active = np.unique(np.concatenate([day.sender[window], day.receiver[window]]))
            near_init = index.before(initiator, float(day.t_obs[position]))
            near_resp = index.before(responder, float(day.t_obs[position]))
            sampled = sample_negatives(day, position, target, negatives, rng, active)
            # Only looked up where the ranking head can actually train. Role supervision covers about 1% of events, and
            # a neighbourhood lookup per candidate on every event would cost six times the index work for nothing.
            candidate_neighbours = np.full((1 + negatives, size), -1, np.int64)
            if target >= 0:
                for column, candidate in enumerate((target, *sampled)):
                    if int(candidate) >= 0:
                        near = index.before(int(candidate), float(day.t_obs[position]))
                        candidate_neighbours[column] = neighbour_nodes(day, int(candidate), near)
            yield TrainingStep(
                position=position, event_id=int(day.event_id[position]), day_index=day_index,
                starts_day=first, t=float(day.t[position]), t_obs=float(day.t_obs[position]),
                sender=u, receiver=v, initiator=initiator, responder=responder,
                unresolved_direction=reversal not in (0, 1),
                neighbours_initiator=near_init, neighbours_responder=near_resp,
                neighbour_nodes_initiator=neighbour_nodes(day, initiator, near_init),
                neighbour_nodes_responder=neighbour_nodes(day, responder, near_resp),
                true_target=target,
                negatives=sampled,
                neighbour_nodes_candidates=candidate_neighbours,
            )
            first = False
