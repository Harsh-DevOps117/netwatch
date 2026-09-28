"""The forecast rollout, branched: keep the top k hosts at every step and roll every branch forward, in one GPU batch.

`inference.rollout_graph` follows one path: at each of its steps the ranking head's top host becomes the next target.
Here every path keeps its top k, so S steps give k^S paths -- 64 for k=2, 729 for k=3 over six steps -- and the analyst
is shown the hosts on all of them, ranked by path probability. With k=1 it is `rollout_graph`, number for number
(checked by `demo_against`).

Two things make the batch cheap:
- **Memory per path is a handful of overrides.** An imagined event rewrites only its two endpoints, and the attacker is
  the same on every path, so a path differs from the observed state in at most S+1 hosts. Each path carries those rows
  (`slots`) instead of a copy of the whole memory table; every read gathers the base table and replaces the overridden
  rows.
- **Neighbourhoods are built once, in parallel.** A candidate's real history before the forecast's time does not change
  along a rollout; only the imagined links do. `CausalNeighbours` answers every host's "last S events before t" in one
  vectorised search, and each step merges the paths' imagined links into those rows as tensor operations.
"""
from __future__ import annotations

import numpy as np
import torch

from models.world_model.model import DT_COLD, WorldModel

SHIFT = 37                      # microseconds of one day fit in 2^37; node ids above it


class CausalNeighbours:
    """Every host's most recent S events strictly before a time, for many hosts at once.

    Input:  the day's sender, receiver and observation times, the neighbourhood size
    Output: object; peers(nodes, t) returns (N, S) peer node ids, most recent first, -1 padded

    The same answer as `dataset.Neighbourhoods.before` + `neighbour_nodes`, queried per node there: here every
    (node, event) entry is sorted once by one int64 key -- node, then time in microseconds -- so a whole batch of
    queries is one `searchsorted`.
    """

    def __init__(self, sender: np.ndarray, receiver: np.ndarray, t_obs: np.ndarray, size: int = 20):
        self.size = size
        self.sender, self.receiver = np.asarray(sender, np.int64), np.asarray(receiver, np.int64)
        positions = np.arange(len(sender), dtype=np.int64)
        loop = self.sender == self.receiver
        node = np.r_[self.sender, self.receiver[~loop]]
        position = np.r_[positions, positions[~loop]]
        self.t0 = float(np.min(t_obs)) if len(t_obs) else 0.0
        micros = np.round((np.asarray(t_obs, float)[position] - self.t0) * 1e6).astype(np.int64)
        key = (node << SHIFT) | micros
        # events in the same microsecond keep stream order, as the per-node lists of dataset.Neighbourhoods do
        order = np.lexsort((position, key))
        self.key, self.position = key[order], position[order]

    def peers(self, nodes: np.ndarray, t: float, inclusive: bool = False) -> np.ndarray:
        """Each node's last S peers before t (at or before t when `inclusive`), most recent first, -1 padded."""
        nodes = np.asarray(nodes, np.int64)
        at = np.round((t - self.t0) * 1e6).astype(np.int64)
        cut = np.searchsorted(self.key, (nodes << SHIFT) | at, side="right" if inclusive else "left")
        start = np.searchsorted(self.key, nodes << SHIFT, side="left")
        back = cut[:, None] - 1 - np.arange(self.size)[None, :]                    # most recent first
        valid = back >= start[:, None]
        position = self.position[np.where(valid, back, 0)]
        sender, receiver = self.sender[position], self.receiver[position]
        peer = np.where(sender == nodes[:, None], receiver, sender)
        return np.where(valid, peer, -1)


class _Paths:
    """Every path's overridden memory rows over one shared base table."""

    def __init__(self, model: WorldModel, paths: int, slots: int):
        self.model, device = model, model.memory.device
        self.nodes = torch.full((paths, slots), -1, dtype=torch.long, device=device)
        self.memory = torch.zeros(paths, slots, model.memory_width, device=device)
        # float64 holding float32-rounded times: the model keeps last_seen in float32 (see `write`)
        self.seen = torch.full((paths, slots), float("nan"), dtype=torch.float64, device=device)

    def read(self, nodes: torch.Tensor):
        """(memory, last seen) of `nodes` (P, ...) on each path."""
        flat = nodes.reshape(nodes.shape[0], -1)
        safe = flat.clamp(min=0)
        memory, seen = self.model.memory[safe], self.model.last_seen[safe].to(self.seen.dtype)
        match = flat[:, :, None] == self.nodes[:, None, :]                           # (P, X, slots)
        hit = match.any(-1)
        slot = match.float().argmax(-1)
        memory = torch.where(hit[..., None], torch.gather(self.memory, 1, slot[..., None].expand(-1, -1, memory.shape[-1])),
                             memory)
        seen = torch.where(hit, torch.gather(self.seen, 1, slot), seen)
        return memory.reshape(*nodes.shape, -1), seen.reshape(nodes.shape)

    def write(self, node: torch.Tensor, memory: torch.Tensor, seen: float, free: int) -> None:
        """Override `node` (P,) on each path: its existing slot, else slot `free`."""
        exists = self.nodes == node[:, None]
        slot = torch.where(exists.any(-1), exists.float().argmax(-1), torch.full_like(node, free))
        rows = torch.arange(len(node), device=node.device)
        self.nodes[rows, slot] = node
        self.memory[rows, slot] = memory
        # `observe` writes the time through a float32 tensor; keep the same rounding so the gaps read back match
        self.seen[rows, slot] = float(np.float32(seen))

    def expand(self, repeats: int) -> None:
        self.nodes = self.nodes.repeat_interleave(repeats, 0)
        self.memory = self.memory.repeat_interleave(repeats, 0)
        self.seen = self.seen.repeat_interleave(repeats, 0)


def _embed(model: WorldModel, paths: _Paths, nodes: torch.Tensor, hoods: torch.Tensor, at: float) -> torch.Tensor:
    """Layer 1 on each path: `WorldModel.embed`, reading the path's memory."""
    P, X, S = hoods.shape
    valid = hoods >= 0
    own, _ = paths.read(nodes)
    peer_memory, peer_seen = paths.read(hoods)
    # as WorldModel.embed: the query time and last-seen are float32 there, and the subtraction happens in float32
    age = torch.tensor(at, dtype=torch.float32, device=hoods.device) - peer_seen.float()
    age = torch.where(torch.isnan(age) | ~valid, torch.full_like(age, DT_COLD), age)
    h, _ = model.layer1(own.reshape(P * X, -1), peer_memory.reshape(P * X, S, -1),
                        model.time_encoder(age).reshape(P * X, S, -1), valid.reshape(P * X, S))
    return h.reshape(P, X, -1)


def _dt(paths: _Paths, node: torch.Tensor, at: float) -> torch.Tensor:
    _, seen = paths.read(node[:, None])
    seen = seen[:, 0]
    return torch.where(torch.isnan(seen), torch.full_like(seen, DT_COLD), (at - seen).clamp(min=0.0)).float()


@torch.no_grad()
def beam_rollout(model: WorldModel, neighbours: CausalNeighbours, attacker: int, target: int, z: torch.Tensor,
                 t_obs: float, active: np.ndarray, *, steps: int, k: int, gap: float = 1.0,
                 pool: "np.ndarray | None" = None, alpha: float = 1.0, address: "np.ndarray | None" = None,
                 recent_targets: "list[int] | None" = None) -> dict:
    """Roll the campaign forward keeping the top k hosts of every path at every step.

    Input:  the model (memory at the observed state; never modified), the day's neighbour index, the seed's attacker
            and target, its z (1, D_Z), its observation time, the active host ids, steps, branching k, the assumed gap
    Output: dict with targets (P, steps) host ids per path and step, log_probability (P,) of each path, probability
            (P, steps) of each step's choice, and timing

    Serving options, none of which changes the model or its state updates:
      pool        the hosts the world model chooses among (default: `active`, as trained). The global state is always
                  read from `active`; a retrieved pool only widens which hosts are scored against it.
      alpha       below 1, each step's choice is p_world_model^alpha * q^(1 - alpha), where q is an address-proximity
                  prior: hosts ranked by IPv4 distance to the path's last three targets (the attacker's real recent
                  targets, then the path's own imagined ones), q ~ 1 / (1 + rank). Needs `address` (node -> IPv4 as a
                  number, NaN when unknown).
    """
    device = model.memory.device
    state_hosts = np.asarray([c for c in active.tolist() if c != attacker], np.int64)
    candidates = state_hosts if pool is None else np.asarray([c for c in np.asarray(pool).tolist() if c != attacker],
                                                            np.int64)
    if not len(candidates):
        return {"targets": np.zeros((0, steps), np.int64), "log_probability": np.zeros(0), "probability": np.zeros((0, steps))}
    size = neighbours.size
    started = torch.cuda.Event(enable_timing=True) if device.type == "cuda" else None
    import time
    clock = time.perf_counter()
    # strictly before the seed's time: rollout_graph asks for `before(node, t_obs + 1e-9)`, but at 1.5e9 s a float64
    # cannot hold the 1e-9 -- t_obs + 1e-9 == t_obs -- so its window is strict too
    real_c = torch.as_tensor(neighbours.peers(candidates, t_obs), device=device)   # (C, S)
    graph_seconds = time.perf_counter() - clock
    cand = torch.as_tensor(candidates, device=device)
    state_t = torch.as_tensor(state_hosts, device=device)
    C, A = len(candidates), len(state_hosts)
    if alpha < 1.0:
        if address is None:
            raise ValueError("alpha below 1 needs `address`")
        cand_ip = torch.as_tensor(address[candidates], dtype=torch.float64, device=device)
        known = [h for h in (recent_targets or []) if np.isfinite(address[h])][-3:]
        seed_ip = torch.as_tensor(address[known] if known else address[[target]], dtype=torch.float64, device=device)
        ip_of = torch.as_tensor(np.nan_to_num(address, nan=-1.0), dtype=torch.float64, device=device)

    paths = _Paths(model, 1, steps + 1)
    history = torch.zeros((1, 0), dtype=torch.long, device=device)                 # chosen targets per path
    current = torch.full((1,), int(target), dtype=torch.long, device=device)
    logp = torch.zeros(1, device=device)
    probs = torch.zeros((1, 0), device=device)
    attacker_t = torch.tensor(attacker, device=device)
    time_now = float(t_obs)
    slot_index = torch.arange(size, device=device)
    for step in range(steps):
        P = len(current)
        # the imagined event attacker -> current target, through the same message and GRU as a real one
        a_nodes = attacker_t.expand(P)
        m_a, _ = paths.read(a_nodes[:, None])
        m_t, _ = paths.read(current[:, None])
        phi_a, phi_t = model.time_encoder(_dt(paths, a_nodes, time_now)), model.time_encoder(_dt(paths, current, time_now))
        message = model.message(m_a[:, 0], m_t[:, 0], z.expand(P, -1), phi_a, phi_t)
        new_a, new_t = model.cell(message, m_a[:, 0]), model.cell(message, m_t[:, 0])
        paths.write(a_nodes, new_a, time_now, 0)
        paths.write(current, new_t, time_now, step + 1)
        history = torch.cat([history, current[:, None]], 1)
        time_now += gap

        # each candidate's neighbourhood: the attacker once per time it was imagined with it, then its real history
        count = (history[:, None, :] == cand[None, :, None]).sum(-1)                              # (P, C)
        shifted = slot_index[None, None, :] - count[..., None]
        hoods = torch.where(shifted < 0, attacker_t,
                            torch.gather(real_c.expand(P, -1, -1), 2, shifted.clamp(min=0)))
        embedded = _embed(model, paths, cand.expand(P, -1), hoods, time_now)
        own, _ = paths.read(state_t.expand(P, -1))
        h_active, _ = model.layer1(own.reshape(P * A, -1), own.reshape(P * A, -1)[:, None, :],
                                   model.time_encoder(torch.full((P * A, 1), DT_COLD, device=device)),
                                   torch.zeros((P * A, 1), dtype=torch.bool, device=device))
        state, _ = model.layer2(h_active.reshape(P, A, -1), torch.ones(P, A, dtype=torch.bool, device=device))
        scores, _ = model.rank(embedded, state)
        probability = torch.softmax(scores, dim=-1)                                                 # (P, C)
        if alpha < 1.0:
            # the path's last three targets: its imagined ones, most recent first, then the real recent ones
            imagined_ip = ip_of[history[:, -3:]]                                                     # (P, <=3)
            anchors = torch.cat([seed_ip.expand(P, -1), imagined_ip], 1)[:, -3:]
            anchors = torch.where(anchors < 0, torch.full_like(anchors, float("nan")), anchors)
            distance = (cand_ip[None, :, None] - anchors[:, None, :]).abs()
            distance = torch.where(torch.isnan(distance), torch.full_like(distance, float("inf")), distance).amin(-1)
            rank = distance.argsort(-1).argsort(-1).to(probability.dtype)                          # 0 = nearest
            prior = 1.0 / (1.0 + rank)
            prior = prior / prior.sum(-1, keepdim=True)
            fused = alpha * torch.log(probability.clamp(min=1e-12)) + (1 - alpha) * torch.log(prior)
            probability = torch.softmax(fused, dim=-1)
        top = probability.topk(min(k, C), dim=-1)
        width = top.indices.shape[1]
        # every path branches into its top `width` hosts
        current = cand[top.indices].reshape(-1)
        logp = (logp[:, None] + torch.log(top.values.clamp(min=1e-12))).reshape(-1)
        probs = torch.cat([probs.repeat_interleave(width, 0), top.values.reshape(-1, 1)], 1)
        history = history.repeat_interleave(width, 0)
        paths.expand(width)
    # `history` holds each path's first target (the seed's) and the targets chosen before the last step; the last
    # step's choice is `current`. The forecast is the chosen targets: drop the seed's, add the last.
    targets = torch.cat([history[:, 1:], current[:, None]], 1)
    return {"targets": targets.cpu().numpy(), "log_probability": logp.cpu().numpy(),
            "probability": probs.cpu().numpy(), "graph_seconds": graph_seconds, "candidates": C}


@torch.no_grad()
def score_hosts(model: WorldModel, neighbours: CausalNeighbours, attacker: int, target: int, z: torch.Tensor,
                t_obs: float, active: np.ndarray, pool: np.ndarray) -> np.ndarray:
    """The rollout's first step over any pool of hosts: the ranking head's probability for each host in `pool`.

    Input:  as beam_rollout, plus the hosts to score (e.g. every host seen so far)
    Output: (len(pool),) probabilities, summing to 1 over the pool

    The global state is read from `active`, the recently active hosts the head was trained with; only the hosts scored
    against it change. With `pool` equal to `active` less the attacker this is beam_rollout's first step. Scoring every
    known host is one batched pass: the hosts' memory rows and last-20 peers are gathers, not rebuilds.
    """
    device = model.memory.device
    pool = np.asarray([h for h in np.asarray(pool).tolist() if h != attacker], np.int64)
    state_hosts = torch.as_tensor([h for h in active.tolist() if h != attacker], device=device)
    paths = _Paths(model, 1, 2)
    a, t = torch.tensor([attacker], device=device), torch.tensor([target], device=device)
    m_a, _ = paths.read(a[:, None])
    m_t, _ = paths.read(t[:, None])
    message = model.message(m_a[:, 0], m_t[:, 0], z, model.time_encoder(_dt(paths, a, t_obs)),
                            model.time_encoder(_dt(paths, t, t_obs)))
    paths.write(a, model.cell(message, m_a[:, 0]), t_obs, 0)
    paths.write(t, model.cell(message, m_t[:, 0]), t_obs, 1)
    at = t_obs + 1.0
    hosts = torch.as_tensor(pool, device=device)
    real = torch.as_tensor(neighbours.peers(pool, t_obs), device=device)[None]      # (1, C, S)
    imagined = (hosts == target)[None, :, None] & (torch.arange(real.shape[-1], device=device) == 0)
    shifted = torch.where((hosts == target)[None, :, None],
                          torch.cat([real[..., :1], real[..., :-1]], -1), real)                   # target: attacker first
    hoods = torch.where(imagined, torch.tensor(attacker, device=device), shifted)
    embedded = _embed(model, paths, hosts[None], hoods, at)
    own, _ = paths.read(state_hosts[None])
    n = len(state_hosts)
    h_active, _ = model.layer1(own.reshape(n, -1), own.reshape(n, -1)[:, None, :],
                               model.time_encoder(torch.full((n, 1), DT_COLD, device=device)),
                               torch.zeros((n, 1), dtype=torch.bool, device=device))
    state, _ = model.layer2(h_active.reshape(1, n, -1), torch.ones(1, n, dtype=torch.bool, device=device))
    scores, _ = model.rank(embedded, state)
    return torch.softmax(scores[0], dim=-1).cpu().numpy()
