"""Block 8 event stream: the availability order and each event's gated neighbourhood.

The neighbourhood is indexed **per distinct peer**, not per recent event. Scanning a host's last N events fails
badly on a flood: 99.9% of DoS-Hulk events had no neighbour left after same-link events were excluded, because the
attacker's whole recent history is that one link -- its nearest event to a different peer sits a median of 45,449
events back, while benign traffic finds one immediately (median 0). Collapsing each host's consecutive runs to the
same peer into a single entry removes that: a flood is one entry, so the host's other partners stay visible however
long ago they were, and no lookback size decides which attacks look isolated.
"""

from __future__ import annotations

import numpy as np
import torch

NEIGHBOURS = 20
# Below this many queries a block, the search runs on the CPU: the work is small and the GPU's launch overhead
# dominates. Measured per event on Friday-16 (cuda / torch-cpu): batch 1 2873 / 442, 16 148 / 91, 64 110 / 73,
# 256 22 / 35, 512 12 / 31, 4096 4.8 / 24. The crossing is between 64 and 256.
GPU_FROM = 256
# Runs searched per endpoint, not raw events. Measured where each label's neighbourhood stops growing (Friday-02-03,
# 20,000 sampled events, mean of 20): benign 19.69 -> 19.93 -> 19.95 at depths 80 / 320 / 1280, Bot 15.51 -> 18.90 ->
# 20.00. At 80 a Bot event lost 4.5 neighbours it had every right to -- its endpoints do have 20 distinct peers in
# history (measured ceiling 20.00) -- so the depth, not the traffic, was deciding which label looked sparse.
LOOKBACK = 64 * NEIGHBOURS
# The first pass's depth: benign endpoints saturate here (19.93 of 20 at 320, 19.95 at 1,280), so only the rows that
# could still gain from depth pay for it.
SHALLOW = 16 * NEIGHBOURS


def availability_order(observation_time: np.ndarray, event_id: np.ndarray) -> np.ndarray:
    """The order Block 8 processes events in: by observation time, ties by event_id.

    Input:  observation time (N,), event_id (N,)
    Output: (N,) indices into the inputs; position p in this order may read only events at positions < p

    An event's representation exists only from its observation time, so reading in this order is what keeps a
    representation out of memory and attention before it exists. Ties resolve by event_id, identically every run.
    """
    return np.lexsort((event_id, observation_time))


class NeighbourIndex:
    """Each endpoint's history as the latest event per distinct peer.

    Consecutive runs with one peer are collapsed first (a flood becomes a single entry), then a peer revisited after
    an interruption is kept only at its most recent run, so the neighbourhood holds distinct partners.

    Input:  sender and receiver node ids of a stream already in availability order (N,)
    Output: index; query(...) returns neighbourhoods for real events and for sampled negative pairs alike
    """

    def __init__(self, sender: np.ndarray, receiver: np.ndarray):
        n = len(sender)
        positions = np.arange(n)
        self.roles = []
        for key, peer in ((sender, receiver), (receiver, sender)):
            order = np.lexsort((positions, key))                 # grouped by endpoint, stream order inside
            node, partner = key[order], peer[order]
            starts = np.flatnonzero(np.r_[True, (node[1:] != node[:-1]) | (partner[1:] != partner[:-1])])
            ends = np.r_[starts[1:], n] - 1                      # a run ends where the next one starts
            scale = n + 1
            # Two search keys over the same endpoint-ordered entries: one per entry, to find where a query falls in
            # an endpoint's history, and one per run, to find the last run that began before it. A run keeps its
            # member range, so the neighbour taken from it is its latest event *before* the query -- which is what a
            # sampled negative pair needs, since the queried event's own link is a normal peer for that query.
            self.roles.append({"node": node[starts], "peer": partner[starts], "start": starts, "end": ends,
                               "order": order, "scale": scale,
                               "entry_key": node.astype(np.int64) * scale + order,
                               "run_key": node[starts].astype(np.int64) * scale + order[starts]})
        self._cached: dict[str, list[dict]] = {}

    def _on(self, device: str) -> list[dict]:
        """The index as tensors on one device, built once per device.

        Input:  device
        Output: the per-role dicts with tensor values
        """
        if device not in self._cached:
            self._cached[device] = [{name: (value if isinstance(value, int) else
                                            torch.as_tensor(value, device=device))
                                     for name, value in role.items()} for role in self.roles]
        return self._cached[device]

    def _scan(self, role: dict, node, partner, where, lookback: int):
        """One endpoint's candidates: its latest event per distinct peer, over `lookback` runs back.

        Input:  the role's tensors, endpoint and partner node ids (M,), stream position (M,), runs to scan
        Output: (positions (M, lookback) with -1 where nothing, oldest (M,) the oldest position this scan saw,
                 exhausted (M,) whether the scan reached the start of this endpoint's history)

        `oldest` and `exhausted` are what let a shallow scan be trusted: anything a deeper scan could find is older
        than `oldest`, and an exhausted endpoint has nothing deeper at all.
        """
        back = torch.arange(lookback, device=node.device)
        key = node * role["scale"] + where
        entry = torch.searchsorted(role["entry_key"], key) - 1        # this endpoint's latest entry before it
        first = torch.searchsorted(role["run_key"], key) - 1
        at = first[:, None] - back
        deepest = first - (lookback - 1)
        ok = (at >= 0) & (at < len(role["node"]))
        at = torch.where(ok, at, torch.zeros_like(at))
        ok &= role["node"][at] == node[:, None]                       # still this endpoint's own history
        ok &= role["peer"][at] != partner[:, None]                    # not the link being queried
        member = torch.minimum(role["end"][at], entry[:, None])       # the run's latest event before the query
        ok &= member >= role["start"][at]
        # Runs are scanned newest first, so a peer's first appearance is its latest event; drop the rest. The sort
        # must be stable, or a different duplicate would survive and the neighbour would be the wrong one.
        peer = torch.where(ok, role["peer"][at], torch.full_like(at, -1))
        by_peer = torch.argsort(peer, dim=1, stable=True)
        sorted_peer = torch.take_along_dim(peer, by_peer, 1)
        duplicate = torch.zeros_like(ok)
        duplicate.scatter_(1, by_peer[:, 1:], (sorted_peer[:, 1:] == sorted_peer[:, :-1]) & (sorted_peer[:, 1:] >= 0))
        ok &= ~duplicate
        positions = torch.where(ok, role["order"][torch.where(ok, member, torch.zeros_like(member))],
                                torch.full_like(member, -1))
        # The endpoint's history ran out inside this scan: either before run 0, or before its own first run.
        edge = deepest.clamp(min=0)
        exhausted = (deepest <= 0) | (role["node"][edge] != node)
        oldest = torch.where(positions >= 0, positions, torch.full_like(positions, 1 << 62)).min(1).values
        return positions, oldest, exhausted

    def query(self, sender: np.ndarray, receiver: np.ndarray, position: np.ndarray, size: int = NEIGHBOURS,
              lookback: int = LOOKBACK, chunk: int = 50_000, device: str | None = None,
              shallow: int = SHALLOW) -> np.ndarray:
        """The neighbourhood of a link read at a stream position.

        Input:  sender, receiver and stream position of each query (M,), neighbourhood size, runs searched per
                endpoint, queries per block, device the search runs on, runs the first pass scans
        Output: (M, size) stream positions, most recent first, -1 where fewer exist: the latest event of each of the
                sender's other peers and of the receiver's other partners, excluding the sender -> receiver link.
                One entry per distinct peer: a peer revisited after an interruption appears once, at its latest
                event, so a pair of peers alternating within the scanned runs cannot fill the neighbourhood and hide
                a third partner.

        Two passes, because depth is only needed where the traffic is odd: benign endpoints fill the neighbourhood
        within 320 runs while a Bot endpoint needs 1,280 (measured). The first pass scans `shallow` runs; a row is
        redone at full depth only when a deeper event could still enter its neighbourhood -- that is, when its
        size-th neighbour is older than the oldest event either pass has seen on a non-exhausted endpoint. The
        result is identical to scanning every row to full depth.
        """
        # Where the search runs: the caller's choice, else the device that is faster for a block this size.
        if device is None:
            device = "cuda" if torch.cuda.is_available() and min(chunk, len(sender)) >= GPU_FROM else "cpu"
        roles = self._on(device)
        out = np.full((len(sender), size), -1, np.int64)
        for start in range(0, len(sender), chunk):
            part = slice(start, start + chunk)
            nodes = [torch.as_tensor(sender[part].astype(np.int64), device=device),
                     torch.as_tensor(receiver[part].astype(np.int64), device=device)]
            where = torch.as_tensor(np.asarray(position[part], np.int64), device=device)
            rows = torch.arange(len(where), device=device)
            best, redo = self._pass(roles, nodes, where, size, min(shallow, lookback))
            if lookback > shallow and redo.any():
                deep, _ = self._pass(roles, [n[redo] for n in nodes], where[redo], size, lookback, final=True)
                best[rows[redo]] = deep
            out[part] = best.cpu().numpy()
        return out

    def _pass(self, roles, nodes, where, size: int, lookback: int, final: bool = False):
        """One depth of the search over both endpoints.

        Input:  the device tensors, [sender, receiver] node ids, stream positions, neighbourhood size, depth,
                whether this is the full-depth pass
        Output: (neighbourhoods (M, size), rows a deeper pass could still change -- empty when final)
        """
        found, unknown = [], []
        for role, node, partner in zip(roles, nodes, nodes[::-1]):
            positions, oldest, exhausted = self._scan(role, node, partner, where, lookback)
            found.append(positions)
            # A deeper scan of this endpoint could only return positions below `oldest`; an exhausted one, nothing.
            unknown.append(torch.where(exhausted, torch.full_like(oldest, -1), oldest - 1))
        best = torch.sort(torch.cat(found, 1), dim=1, descending=True).values[:, :size]
        if final:
            return best, None
        return best, best[:, size - 1] <= torch.maximum(unknown[0], unknown[1])


def recent_neighbours(sender: np.ndarray, receiver: np.ndarray, size: int = NEIGHBOURS,
                      lookback: int = LOOKBACK) -> np.ndarray:
    """Every event's own neighbourhood, for a stream in availability order.

    Input:  sender and receiver node ids (N,), neighbourhood size, runs searched per endpoint
    Output: (N, size) stream positions, most recent first, -1 padded; every neighbour sits at an earlier position
    """
    return NeighbourIndex(sender, receiver).query(sender, receiver, np.arange(len(sender)), size, lookback)
