"""Module 3 — the architecture of design section 4.

Persistent memory, a neighbourhood attention layer, a network-wide global readout, and two heads. Written so it can be
unit-tested on its own: synthetic event in, shape-checked output, no training loop involved. Losses and the epoch loop
live in `training.py`, which is the point of the separation.

Shapes, once, so the rest reads quickly:

| symbol | width | what |
|---|---|---|
| `m_v` | 100 | per-node memory, zero-initialised |
| `z` | 32 | the compressor's latent, the event's own representation |
| `Phi(dt)` | 100 | time encoding, 50 learned frequencies as sin/cos pairs |
| `msg` | 100 | message, from a 432-wide input through a 128-wide hidden layer |
| `h_v` | 100 | neighbourhood embedding: the node's memory plus what it attended to (v2) |
| `S_global` | 100 x 2 | global readout, one vector per learned query |

Two details the design is explicit about, and this enforces:

**A cold start is a branch, not a small number.** `dt == -1` means the endpoint has never been seen. It is replaced by a
separate learned vector rather than pushed through the sinusoids, because sin/cos of a sentinel is a real value that
looks like a real interval.

**Reorientation is packet-level only.** `reversed` canonicalises initiator/responder so the message function sees a
consistent ordering. It is not attacker/victim — that is `role`, and it never enters the forward pass.
"""
from __future__ import annotations

import torch
from torch import nn

D_MEMORY = 100
D_TIME = 100
D_Z = 32
D_MESSAGE_HIDDEN = 128
HEADS = 2
GLOBAL_QUERIES = 2
DT_COLD = -1.0

# v1 embedded a node as its attended neighbourhood alone, so a node with no neighbours was a zero vector -- and the
# global readout, which embeds every active node that way, pooled zeros: its attention was exactly uniform and the
# ranking head read a constant. v2 adds the node's own memory back. The arithmetic differs, not the parameters, so the
# format says which one a checkpoint was trained (and calibrated) with.
FORMAT = "world-model-block10-v2"
FORMAT_V1 = "world-model-block10-v1"


class TimeEncoder(nn.Module):
    """Phi(dt): 50 learned frequencies as sin/cos pairs, with a separate vector for a cold start.

    Input:  output width (even), the sentinel meaning "never seen"
    Output: module; forward(dt) returns (..., width)

    The cold-start branch is a hard `where`, not a clamp: an unseen endpoint carries no interval at all, and giving it
    one — even zero — states something false about the node's history.
    """

    def __init__(self, width: int = D_TIME, cold: float = DT_COLD):
        super().__init__()
        if width % 2:
            raise ValueError("the time encoding pairs sin with cos, so its width must be even")
        self.cold = cold
        self.frequencies = nn.Parameter(torch.logspace(-4, 1, width // 2))
        self.cold_vector = nn.Parameter(torch.zeros(width))

    def forward(self, dt: torch.Tensor) -> torch.Tensor:
        scaled = dt.clamp(min=0.0).unsqueeze(-1) * self.frequencies
        encoded = torch.cat([torch.sin(scaled), torch.cos(scaled)], dim=-1)
        is_cold = (dt == self.cold).unsqueeze(-1)
        return torch.where(is_cold, self.cold_vector.expand_as(encoded), encoded)


class MessageFunction(nn.Module):
    """g_theta(m_init, m_resp, z, Phi(dt_init), Phi(dt_resp)) -> msg in R^100.

    Input:  memory width, z width, time width, hidden width
    Output: module; forward(...) returns (N, memory)

    Output width matches memory so the GRU consumes it directly, which is what keeps one shared cell able to update
    both endpoints.
    """

    def __init__(self, memory: int = D_MEMORY, z: int = D_Z, time: int = D_TIME, hidden: int = D_MESSAGE_HIDDEN):
        super().__init__()
        self.width = 2 * memory + z + 2 * time
        self.net = nn.Sequential(nn.Linear(self.width, hidden), nn.ReLU(), nn.Linear(hidden, memory))

    def forward(self, m_init, m_resp, z, phi_init, phi_resp) -> torch.Tensor:
        return self.net(torch.cat([m_init, m_resp, z, phi_init, phi_resp], dim=-1))


class NeighbourhoodAttention(nn.Module):
    """Layer 1: h_v(t) = m_v + MultiHeadAttn(query = m_v, keys/values = [m_v' || Phi(t - t_v')]).

    Input:  memory width, time width, heads, whether to add m_v back (False only for v1 checkpoints)
    Output: module; forward(memory, neighbour_memory, neighbour_age, valid) returns (N, memory) and the weights

    Keys carry a node's memory concatenated with how long ago it acted, projected to the attention width. The age is
    part of the key rather than a separate bias because *when* a neighbour acted is as much a part of what it says as
    *what* it was doing.
    """

    def __init__(self, memory: int = D_MEMORY, time: int = D_TIME, heads: int = HEADS, residual: bool = True):
        super().__init__()
        self.residual = residual
        self.key_projection = nn.Linear(memory + time, memory)
        self.attention = nn.MultiheadAttention(memory, heads, batch_first=True)

    def forward(self, memory, neighbour_memory, neighbour_age, valid):
        keys = self.key_projection(torch.cat([neighbour_memory, neighbour_age], dim=-1))
        empty = ~valid.any(dim=1)
        mask = ~valid
        # An event with no admissible neighbour attends to a dummy slot whose contribution is zeroed below. Masking
        # every key instead makes the attention softmax undefined and returns NaN.
        mask[:, 0] = mask[:, 0] & ~empty
        attended, weights = self.attention(memory.unsqueeze(1), keys, keys, key_padding_mask=mask,
                                          need_weights=True, average_attn_weights=True)
        out = attended[:, 0] * (~empty).unsqueeze(-1).to(attended.dtype)
        # Residual: a node with no neighbourhood is still its memory, not a zero vector (see FORMAT).
        return (memory + out if self.residual else out), weights[:, 0]


class GlobalReadout(nn.Module):
    """Layer 2: two learned queries pooling over every currently-active node.

    Input:  memory width, how many queries, heads per query
    Output: module; forward(h, valid) returns (N, queries, memory) and the weights

    Two queries, not one per attack class: one biased toward fast volumetric tempo, one toward slow and quiet. Capped at
    two deliberately — with five days and sparse positives, more queries would fit the days rather than the tempos.
    Variable cardinality by construction: the same pooling works for three active nodes or three hundred.
    """

    def __init__(self, memory: int = D_MEMORY, queries: int = GLOBAL_QUERIES, heads: int = HEADS):
        super().__init__()
        self.queries = nn.Parameter(torch.randn(queries, memory) * 0.02)
        self.attention = nn.MultiheadAttention(memory, heads, batch_first=True)

    def forward(self, h, valid):
        batch = h.shape[0]
        query = self.queries.unsqueeze(0).expand(batch, -1, -1)
        empty = ~valid.any(dim=1)
        mask = ~valid
        mask[:, 0] = mask[:, 0] & ~empty
        pooled, weights = self.attention(query, h, h, key_padding_mask=mask,
                                         need_weights=True, average_attn_weights=True)
        return pooled * (~empty).unsqueeze(-1).unsqueeze(-1).to(pooled.dtype), weights


class RankingHead(nn.Module):
    """Primary head: which active node the campaign reaches next.

    Input:  memory width, how many global queries
    Output: module; forward(candidates, global_state, valid) returns scores and the cross-attention weights

    Each candidate is cross-attended against **each** global query separately, and the results are **concatenated and
    projected**, never summed. Summing would force both tempo signals into one subspace and destroy the distinction the
    two queries exist to hold; concatenating keeps them separate through the attention and lets the scoring layer weigh
    them itself. The design flags this as a reasoned default rather than a literature finding, and so does this comment.

    Cross-attention rather than concatenate-and-MLP because its weights are the explainability artefact: they say which
    part of the global state drove a candidate's score.
    """

    def __init__(self, memory: int = D_MEMORY, queries: int = GLOBAL_QUERIES, heads: int = HEADS):
        super().__init__()
        self.queries = queries
        self.cross = nn.ModuleList([nn.MultiheadAttention(memory, heads, batch_first=True) for _ in range(queries)])
        self.project = nn.Linear(queries * memory, memory)
        self.score = nn.Sequential(nn.Linear(memory, memory), nn.ReLU(), nn.Linear(memory, 1))

    def forward(self, candidates, global_state, valid=None):
        parts, weights = [], []
        for index, attention in enumerate(self.cross):
            state = global_state[:, index: index + 1, :]
            attended, weight = attention(candidates, state, state, need_weights=True, average_attn_weights=True)
            # Residual, and not optional: `state` is a single key, so the attention softmax over it is 1.0 and
            # `attended` comes back as that one value for every candidate -- the candidate's own h_v(t) is discarded
            # and every candidate scores identically, pinning the loss at ln(candidates) with no gradient to escape
            # it. Adding the candidate back keeps section 4.7's "cross-attend each query, concatenate, project"
            # while leaving the candidate able to affect its own score.
            parts.append(attended + candidates)
            weights.append(weight)
        combined = self.project(torch.cat(parts, dim=-1))
        scores = self.score(combined).squeeze(-1)
        if valid is not None:
            scores = scores.masked_fill(~valid, float("-inf"))
        return scores, torch.stack(weights, dim=1)


class NextEventHead(nn.Module):
    """Auxiliary head: does this pair interact next?

    Input:  memory width, hidden width
    Output: module; forward(h_a, h_b) returns a logit per pair

    Pairwise and day-agnostic: it is meaningful on a DoS-only day with no propagation signal at all. Its purpose is not
    link prediction for its own sake but to force the state to model ordinary traffic well enough that a deviation
    registers as surprise — which is what the "surprise separates" verification depends on.
    """

    def __init__(self, memory: int = D_MEMORY, hidden: int = 128):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(2 * memory, hidden), nn.ReLU(), nn.Linear(hidden, 1))

    def forward(self, h_a, h_b) -> torch.Tensor:
        return self.net(torch.cat([h_a, h_b], dim=-1)).squeeze(-1)


class WorldModel(nn.Module):
    """Block 10: memory, dynamics, readout and two heads.

    Input:  how many nodes to hold memory for, the widths
    Output: module; `reset()` clears memory, `observe()` advances it, `embed()` reads a neighbourhood, `rollout()`
            iterates without observations

    Memory is a buffer rather than a parameter: it is state carried between events, not something gradient descent
    should move. `reset()` is called at every day boundary, because node ids are re-derived per day and carried memory
    would address a different host.
    """

    def __init__(self, nodes: int, memory: int = D_MEMORY, z: int = D_Z, time: int = D_TIME,
                 heads: int = HEADS, queries: int = GLOBAL_QUERIES, residual: bool = True):
        super().__init__()
        self.nodes, self.memory_width = nodes, memory
        self.time_encoder = TimeEncoder(time)
        self.message = MessageFunction(memory, z, time)
        self.cell = nn.GRUCell(memory, memory)
        self.layer1 = NeighbourhoodAttention(memory, time, heads, residual)
        self.layer2 = GlobalReadout(memory, queries, heads)
        self.ranking = RankingHead(memory, queries, heads)
        self.next_event = NextEventHead(memory)
        self.register_buffer("memory", torch.zeros(max(nodes, 1), memory))
        self.register_buffer("last_seen", torch.full((max(nodes, 1),), float("nan")))

    def reset(self, nodes: int | None = None) -> None:
        """Clear memory for a new day.

        Input:  how many nodes the new day has, or None to keep the current size
        Output: none

        Zero-init for all nodes, per the design and the TGN lineage: a node with no history is exactly a node whose
        memory says nothing.
        """
        if nodes is not None:
            self.nodes = nodes
        device = self.memory.device
        self.memory = torch.zeros(max(self.nodes, 1), self.memory_width, device=device)
        self.last_seen = torch.full((max(self.nodes, 1),), float("nan"), device=device)

    def observe(self, initiator, responder, z, dt_init, dt_resp, t_obs) -> torch.Tensor:
        """Advance memory on a batch of real events.

        Input:  initiator and responder ids, z, both dt values, the observation times
        Output: the message that was applied, (N, memory)

        Both endpoints receive the same message through the same GRU weights, which is what makes the update symmetric
        in the roles it does not know about: the model is told who initiated at the packet level, never who attacked.
        """
        m_init, m_resp = self.memory[initiator], self.memory[responder]
        message = self.message(m_init, m_resp, z,
                               self.time_encoder(dt_init), self.time_encoder(dt_resp))
        updated_init = self.cell(message, m_init)
        updated_resp = self.cell(message, m_resp)
        # The chunk's last event per node wins, chosen explicitly. `index_copy_` with duplicate indices has no defined
        # winner on CUDA either -- measured: two identical GPU scoring runs differed by up to 2.1 in surprise, while CPU
        # matched exactly. That is the `scatter_` defect class the proxy hit. `scatter_reduce_(amax)` over each write's
        # order picks the winner deterministically, and every write to a node then carries the winner's value.
        nodes = torch.cat([initiator, responder])
        order = torch.arange(len(nodes), device=nodes.device)
        order = torch.cat([2 * order[: len(initiator)], 2 * order[: len(responder)] + 1])   # event order, responder last
        latest = torch.full((self.memory.shape[0],), -1, dtype=order.dtype, device=nodes.device)
        latest.scatter_reduce_(0, nodes, order, reduce="amax")
        # Every write to a node carries that node's winning value, so whichever duplicate lands last writes the same
        # thing. Selecting only the winners with a boolean mask did the same, but a mask forces a CPU<->GPU sync.
        winner = latest[nodes]
        row = winner // 2 + (winner % 2) * len(initiator)          # the winning write's row in cat(init, resp)
        memory = self.memory.clone()
        memory.index_copy_(0, nodes, torch.cat([updated_init, updated_resp])[row])
        self.memory = memory
        seen = self.last_seen.clone()
        seen.index_copy_(0, nodes, torch.cat([t_obs, t_obs]).to(seen.dtype)[row])
        self.last_seen = seen
        return message

    def embed(self, node, neighbours, t_obs):
        """Layer 1 for a batch of nodes.

        Input:  node ids (N,), neighbour node ids (N, S) with -1 padding, the query times (N,)
        Output: (h (N, memory), attention weights (N, S))
        """
        valid = neighbours >= 0
        safe = neighbours.clamp(min=0)
        neighbour_memory = self.memory[safe]
        age = t_obs.unsqueeze(-1) - self.last_seen[safe]
        age = torch.where(torch.isnan(age), torch.full_like(age, DT_COLD), age)
        age = torch.where(valid, age, torch.full_like(age, DT_COLD))
        return self.layer1(self.memory[node], neighbour_memory, self.time_encoder(age), valid)

    def global_state(self, active, t_obs):
        """Layer 2 over the currently-active nodes.

        Input:  active node ids (N, A) with -1 padding, the query times (N,)
        Output: (state (N, queries, memory), weights (N, queries, A))
        """
        valid = active >= 0
        safe = active.clamp(min=0)
        h, _ = self.embed(safe.reshape(-1), torch.full((safe.numel(), 1), -1, device=safe.device,
                                                       dtype=torch.long),
                          t_obs.repeat_interleave(safe.shape[1]))
        return self.layer2(h.reshape(*safe.shape, -1), valid)

    def rank(self, candidates, global_state, valid=None):
        """Score every candidate node against the global state."""
        return self.ranking(candidates, global_state, valid)

    @torch.no_grad()
    def rollout(self, initiator, responder, z, dt_init, dt_resp, t_obs, steps: int, gap: float = 1.0):
        """Iterate the dynamics without any further observation.

        Input:  the seed event's fields, how many steps, the assumed gap between imagined events
        Output: list of per-step dicts with the message and the predicted pair logit

        Memory is the only thing carried forward, at O(1) per node — no history buffer is recomputed per step, which is
        what makes rollout affordable and is the reason a memoryless alternative was rejected.

        The imagined event feeds back through the same path as a real one, and no ground truth re-enters.
        """
        out = []
        current_z = z
        time = t_obs
        for step in range(steps):
            message = self.observe(initiator, responder, current_z, dt_init, dt_resp, time)
            h_init, _ = self.embed(initiator, torch.full((len(initiator), 1), -1, device=initiator.device,
                                                         dtype=torch.long), time)
            h_resp, _ = self.embed(responder, torch.full((len(responder), 1), -1, device=responder.device,
                                                         dtype=torch.long), time)
            out.append({"step": step, "message": message, "pair_logit": self.next_event(h_init, h_resp)})
            # The model's own predicted observation becomes the next input; nothing observed is reintroduced.
            current_z = current_z + 0.0 * message[:, : current_z.shape[1]]
            time = time + gap
            dt_init = torch.full_like(dt_init, gap)
            dt_resp = torch.full_like(dt_resp, gap)
        return out

    def parameter_count(self) -> dict:
        """Parameters per component, for comparison against the design's estimate."""
        groups = {"time_encoder": self.time_encoder, "message": self.message, "gru": self.cell,
                  "layer1": self.layer1, "layer2": self.layer2, "ranking": self.ranking,
                  "next_event": self.next_event}
        out = {name: sum(p.numel() for p in module.parameters()) for name, module in groups.items()}
        out["total"] = sum(out.values())
        return out
