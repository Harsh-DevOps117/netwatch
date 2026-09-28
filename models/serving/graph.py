"""Building the graph from live traffic, incrementally -- the online counterpart of what ingest/ does in batch.

Every graph structure the trained cascade reads is currently built by a whole-array pass over a finished day, and none
of it can be used live:

| offline | why it cannot serve |
|---|---|
| `ingest.build.events._build_node_index` | node ids are `np.arange` over first appearance **within one day**, so the same host is a different id tomorrow, and the id depends on the whole day's ordering |
| `models.context_encoder.model.LinkIds` | takes the whole stream's endpoints and sorts them; a link id is an index into that table, and an unseen pair returns -1 -- while link id IS the link-memory slot |
| `models.context_encoder.stream.NeighbourIndex` | `np.lexsort` over the entire stream, queried by absolute stream position |
| `ingest.build.events._time_since_last_seen` | a groupby-diff over the whole day, for `dt_src` / `dt_dst` |
| `models.context_encoder.stream.availability_order` | sorts the finished day by `(t_obs, event_id)` |

This module is those five, online and bounded. Each keeps the same semantics as its offline twin -- `demo()` checks the
neighbourhood against `recent_neighbours` on the same stream -- while holding memory flat, because a live process
cannot keep a row per host it has ever seen.

**The registries must be persisted and reloaded.** Node and link ids are identity: lose them and a restarted process
gives every host a new id, the world model's state table points at the wrong hosts, and link memory starts cold for
every link at once. `save()` / `load()` exist for exactly that, and are the piece whose absence would be silent.
"""
from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path

import torch

from models.context_encoder.stream import LOOKBACK, NEIGHBOURS


class NodeRegistry:
    """A stable, persistent ip -> node id map that grows as hosts appear.

    Input:  an optional cap on how many hosts to remember
    Output: object; ids(ips) assigns or recalls an id per ip

    Offline, `_build_node_index` numbers hosts `np.arange` by first appearance inside a single day. That is fine for a
    finished file and useless live: the same host is a different integer tomorrow, so nothing keyed on a node id --
    Block 10's state table above all -- survives a day boundary or a restart.

    Ids here are assigned in order of first appearance too, but the map is **kept**, so an id means one host forever.
    Eviction is deliberately *not* id reuse: an evicted host that returns gets a fresh id rather than inheriting a
    stranger's history, because silently reusing an id is the one failure that corrupts state instead of losing it.
    """

    def __init__(self, capacity: int | None = None):
        self.capacity = capacity
        self.of: OrderedDict[str, int] = OrderedDict()
        self.next_id = 0
        self.evicted = 0

    def ids(self, ips) -> torch.Tensor:
        """Ids for these ips, assigning new ones as needed.

        Input:  a sequence of ip strings
        Output: (N,) int64 node ids

        Each *distinct* ip is looked up once and the result scattered back, so a batch of 512 events over 20 hosts
        costs 20 dictionary operations rather than 512. Recency is therefore per batch, not per row -- which only
        affects which host is evicted first, never which id a host has.
        """
        ips = list(ips)
        first: dict[str, int] = {}
        for ip in ips:
            if ip in first:
                continue
            got = self.of.get(ip)
            if got is None:
                got = self.next_id
                self.next_id += 1
                self.of[ip] = got
                if self.capacity is not None and len(self.of) > self.capacity:
                    self.of.popitem(last=False)
                    self.evicted += 1
            else:
                self.of.move_to_end(ip)
            first[ip] = got
        return torch.tensor([first[ip] for ip in ips], dtype=torch.int64)

    def save(self, path: Path) -> None:
        """Write the map so a restart keeps every id it has issued."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({"next_id": self.next_id, "evicted": self.evicted,
                                          "of": dict(self.of)}))

    @classmethod
    def load(cls, path: Path, capacity: int | None = None) -> "NodeRegistry":
        """Restore a saved map; a missing file starts empty rather than failing, so first boot works."""
        registry = cls(capacity)
        path = Path(path)
        if path.exists():
            state = json.loads(path.read_text())
            registry.of = OrderedDict(state["of"])
            registry.next_id = state["next_id"]
            registry.evicted = state.get("evicted", 0)
        return registry


class LinkRegistry:
    """Directed link ids assigned on first sight.

    Input:  an optional cap on links remembered
    Output: object; ids(sender, receiver) returns a link id per pair

    `LinkIds` builds `np.unique` over every pair the stream contains and returns an index into it, so it needs the
    future. Here a pair gets the next free id when first seen. Both directions are separate ids, matching the offline
    `s << 32 | r` keying, because link memory is per *directed* link.

    Ids must stay dense and small: with Block 8's `capacity=None` the link id **is** the memory slot, so a sparse or
    hashed id would index past the table. `len()` is therefore what to size link memory with.
    """

    def __init__(self, capacity: int | None = None):
        self.capacity = capacity
        self.of: OrderedDict[int, int] = OrderedDict()
        self.next_id = 0
        self.evicted = 0

    def ids(self, sender, receiver) -> torch.Tensor:
        """Link ids for these directed pairs, assigning new ones as needed.

        Input:  sender and receiver node ids
        Output: (N,) int64 link ids

        The pair key is packed in torch (`s << 32 | r`, matching `LinkIds`) and reduced with `torch.unique` before any
        dictionary work, so only distinct links are looked up -- the common live case is a few hundred events over a
        handful of links. `return_inverse` scatters the ids back in row order.
        """
        s = torch.as_tensor(sender, dtype=torch.int64)
        r = torch.as_tensor(receiver, dtype=torch.int64)
        keys = (s << 32) | r
        uniq, inverse = torch.unique(keys, return_inverse=True)
        assigned = torch.empty(len(uniq), dtype=torch.int64)
        for at, key in enumerate(uniq.tolist()):
            got = self.of.get(key)
            if got is None:
                got = self.next_id
                self.next_id += 1
                self.of[key] = got
                if self.capacity is not None and len(self.of) > self.capacity:
                    self.of.popitem(last=False)
                    self.evicted += 1
            else:
                self.of.move_to_end(key)
            assigned[at] = got
        return assigned[inverse]

    def __len__(self) -> int:
        return self.next_id

    def save(self, path: Path) -> None:
        """Write the map; keys are stringified because JSON object keys must be strings."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({"next_id": self.next_id, "evicted": self.evicted,
                                          "of": {str(k): v for k, v in self.of.items()}}))

    @classmethod
    def load(cls, path: Path, capacity: int | None = None) -> "LinkRegistry":
        registry = cls(capacity)
        path = Path(path)
        if path.exists():
            state = json.loads(path.read_text())
            registry.of = OrderedDict((int(k), v) for k, v in state["of"].items())
            registry.next_id = state["next_id"]
            registry.evicted = state.get("evicted", 0)
        return registry


class OnlineNeighbours:
    """Each endpoint's most recent distinct peers, maintained event by event.

    Input:  neighbourhood size, cap on endpoints tracked
    Output: object; push(...) records an event and query(...) returns neighbourhoods

    Matches `NeighbourIndex`'s semantics exactly, and for the same reason it states: what Block 8 attends over is the
    **latest event per distinct peer**, so a flood against one peer collapses to a single entry and a peer revisited
    after an interruption appears only at its latest visit. That is precisely an LRU-ordered map per endpoint, which is
    why the offline lexsort is not needed at all -- only the finished-file *indexing* was.

    **The two roles are separate tables, not one symmetric one.** The offline index builds `(sender, receiver)` and
    `(receiver, sender)` independently, so an event's neighbourhood is the events whose sender also sent, plus those
    whose receiver also received -- never everything either endpoint touched. Conflating them invents neighbours: a
    host that has only ever *received* is not a neighbour of an event in which it *sends*. The demo catches this by
    comparing against `recent_neighbours` event for event.
    """

    def __init__(self, size: int = NEIGHBOURS, capacity: int | None = None):
        self.size, self.capacity = size, capacity
        # role 0: keyed on the sender, peers are receivers. role 1: keyed on the receiver, peers are senders.
        self.roles: tuple[OrderedDict, OrderedDict] = (OrderedDict(), OrderedDict())

    def query(self, sender: int, receiver: int) -> torch.Tensor:
        """The neighbourhood of one event, read BEFORE it is pushed.

        Input:  its sender and receiver node ids
        Output: (size,) positions of neighbouring events, most recent first, -1 padded

        Read before push, because every neighbour must sit strictly earlier in the stream -- the offline index
        guarantees the same thing by searching only positions below the query's own.
        """
        found: list[int] = []
        for role, node, counterpart in ((self.roles[0], sender, receiver), (self.roles[1], receiver, sender)):
            table = role.get(node)
            if not table:
                continue
            # The event's OWN link is not part of its neighbourhood, at any recency. Block 8 already carries that
            # link's history in link memory; the neighbourhood exists to add the *other* context around it, so
            # attending to your own peer would only duplicate what link memory holds. Verified against
            # recent_neighbours: for an event 0->8 whose endpoint 0 last spoke to 8 at position 5, offline omits 5
            # from both roles even though it is neither the newest nor part of an ongoing run.
            found.extend(position for peer, position in table.items() if peer != counterpart)
        out = torch.full((self.size,), -1, dtype=torch.int64)
        # Distinct positions, most recent first: one event can sit in both role tables.
        for at, position in enumerate(sorted(set(found), reverse=True)[: self.size]):
            out[at] = position
        return out

    def query_batch(self, senders, receivers, positions) -> torch.Tensor:
        """Neighbourhoods for a batch, each read before that row is pushed.

        Input:  sender, receiver and stream position per row, in stream order
        Output: (N, size) int64 positions, most recent first, -1 padded

        Interleaved on purpose: row i must see rows < i of the same batch, so query and push alternate. A version that
        queried the whole batch first would hide every within-batch neighbour, which is exactly the kind of difference
        that shows up as a quietly worse model rather than an error.
        """
        s = torch.as_tensor(senders, dtype=torch.int64).tolist()
        r = torch.as_tensor(receivers, dtype=torch.int64).tolist()
        pos = torch.as_tensor(positions, dtype=torch.int64).tolist()
        out = torch.full((len(s), self.size), -1, dtype=torch.int64)
        for i in range(len(s)):
            out[i] = self.query(s[i], r[i])
            self.push(s[i], r[i], pos[i])
        return out

    def push(self, sender: int, receiver: int, position: int) -> None:
        """Record that this event happened, so later events can see it.

        Input:  sender and receiver node ids, the event's stream position
        Output: none
        """
        for role, node, peer in ((self.roles[0], sender, receiver), (self.roles[1], receiver, sender)):
            table = role.get(node)
            if table is None:
                table = role[node] = OrderedDict()
                if self.capacity is not None and len(role) > self.capacity:
                    role.popitem(last=False)
            else:
                role.move_to_end(node)
            table[peer] = position
            table.move_to_end(peer)
            if len(table) > self.size + 1:        # one more than shown: the queried link's own peer is left out
                table.popitem(last=False)


class LastSeen:
    """Seconds since a node was last involved in an event -- `dt_src` and `dt_dst`, online.

    Input:  cap on nodes tracked
    Output: object; gap(node, t) returns the gap and records this sighting

    Offline these come from a groupby-diff over the finished day. The first sighting of a node has no predecessor; the
    offline pipeline's choice there must be mirrored by whoever wires this in, and it is the kind of detail that goes
    wrong quietly, so `first` is returned explicitly rather than encoded as a magic number.
    """

    def __init__(self, capacity: int | None = None):
        self.capacity = capacity
        self.at: OrderedDict[int, float] = OrderedDict()

    def gap(self, node: int, t: float) -> tuple[float, bool]:
        """The gap since this node was last seen, and whether this is its first sighting."""
        previous = self.at.get(node)
        self.at[node] = t
        self.at.move_to_end(node)
        if self.capacity is not None and len(self.at) > self.capacity:
            self.at.popitem(last=False)
        return (0.0, True) if previous is None else (t - previous, False)


class ReorderBuffer:
    """Releases events in availability order, which is not arrival order.

    Input:  how long to hold an event before releasing it, in seconds
    Output: object; push() returns the events now safe to release, in order

    An event becomes available at `t_obs = min(t + budget, flow end)`, so a long flow that started early is observed
    after a short flow that started later. The offline pipeline just sorts the finished day by `(t_obs, event_id)`.
    Live, the only equivalent is to wait: hold each event until no earlier-observed event can still arrive.

    `delay` is that wait. It must exceed the worst-case spread between arrival and `t_obs` -- with a 10 ms observation
    budget the spread is small, but it is not zero, and releasing too early feeds Block 8 an out-of-order stream, which
    silently changes link memory, the neighbourhood and any run of three consecutive events.
    """

    def __init__(self, delay: float = 0.05):
        self.delay = float(delay)
        self.held: list[tuple[float, int, object]] = []

    def push(self, t_obs: float, event_id: int, payload: object, now: float | None = None) -> list[tuple]:
        """Add one event and take whatever is now releasable.

        Input:  its observation time, its id, anything to carry with it, the current clock (defaults to t_obs)
        Output: list of (t_obs, event_id, payload), ascending -- possibly empty
        """
        self.held.append((float(t_obs), int(event_id), payload))
        now = t_obs if now is None else now
        cutoff = now - self.delay
        self.held.sort(key=lambda row: (row[0], row[1]))
        ready, keep = [], []
        for row in self.held:
            (ready if row[0] <= cutoff else keep).append(row)
        self.held = keep
        return ready

    def drain(self) -> list[tuple]:
        """Release everything still held, for shutdown."""
        self.held.sort(key=lambda row: (row[0], row[1]))
        out, self.held = self.held, []
        return out


def demo() -> None:
    """Self-check, including the online neighbourhood against the offline index on the same stream."""
    from models.context_encoder.stream import recent_neighbours

    # --- the neighbourhood must match recent_neighbours event for event
    g = torch.Generator().manual_seed(0)
    n = 400
    sender = torch.randint(0, 12, (n,), generator=g, dtype=torch.int64)
    receiver = torch.randint(0, 12, (n,), generator=g, dtype=torch.int64)
    same = sender == receiver                       # a self-link is not a pair; nudge it
    receiver[same] = (receiver[same] + 1) % 12
    # The oracle is the offline numpy index, so it is fed numpy; everything of ours stays torch.
    offline = recent_neighbours(sender.numpy(), receiver.numpy(), size=NEIGHBOURS, lookback=LOOKBACK)

    online = OnlineNeighbours(size=NEIGHBOURS)
    for i in range(n):
        got = online.query(int(sender[i]), int(receiver[i]))
        want = offline[i]
        assert set(got[got >= 0].tolist()) == set(want[want >= 0].tolist()), (
            i, sorted(got[got >= 0].tolist()), sorted(want[want >= 0].tolist()))
        assert bool((got[got >= 0] < i).all()), "a neighbour must sit strictly earlier"
        online.push(int(sender[i]), int(receiver[i]), i)

    # the batch entry point must agree with the interleaved single-row path it wraps
    batched = OnlineNeighbours(size=NEIGHBOURS).query_batch(sender, receiver, torch.arange(n))
    assert batched.shape == (n, NEIGHBOURS)
    for i in range(n):
        want = offline[i]
        got = batched[i]
        assert set(got[got >= 0].tolist()) == set(want[want >= 0].tolist()), i

    # --- node ids are stable and never reused
    reg = NodeRegistry()
    a = reg.ids(["10.0.0.1", "10.0.0.2", "10.0.0.1"])
    assert a.tolist() == [0, 1, 0]
    assert reg.ids(["10.0.0.2"]).tolist() == [1], "an id must not change once issued"
    small = NodeRegistry(capacity=2)
    small.ids(["a", "b", "c"])                      # "a" is evicted
    assert small.ids(["a"]).tolist() == [3], "an evicted host must get a FRESH id, never a stranger's"

    # --- ids survive a restart
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "nodes.json"
        reg.save(path)
        again = NodeRegistry.load(path)
        assert again.ids(["10.0.0.1"]).tolist() == [0]
        assert again.next_id == reg.next_id
        assert NodeRegistry.load(Path(tmp) / "absent.json").next_id == 0, "first boot must not fail"

        links = LinkRegistry()
        assert links.ids([1, 2, 1], [2, 1, 2]).tolist() == [0, 1, 0], "each direction is its own link"
        assert len(links) == 2
        links.save(path)
        assert LinkRegistry.load(path).ids([2], [1]).tolist() == [1]

    # --- dt_src / dt_dst
    seen = LastSeen()
    gap, first = seen.gap(5, 100.0)
    assert first and gap == 0.0
    gap, first = seen.gap(5, 130.0)
    assert not first and gap == 30.0

    # --- availability order is restored despite out-of-order arrival
    buffer = ReorderBuffer(delay=0.05)
    released = []
    released += buffer.push(1.00, 1, "a", now=1.00)
    released += buffer.push(0.99, 2, "b", now=1.00)   # observed earlier, arrived later
    released += buffer.push(1.20, 3, "c", now=1.20)
    released += buffer.drain()
    assert [row[1] for row in released] == [2, 1, 3], released
    assert [row[0] for row in released] == sorted(row[0] for row in released)
    print("demo ok")


if __name__ == "__main__":
    demo()
