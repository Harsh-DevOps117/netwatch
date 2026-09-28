"""Block 8 model: gap encoding, link memory and neighbourhood attention over the availability-ordered event stream."""

from __future__ import annotations

import numpy as np
import torch
from torch import nn

from ingest.build.events import AGG_COLUMNS
from models.context_encoder.records import RECORD_COLUMNS, RecordEncoder
from models.flow_encoder.encoder import TimeEncoder, mlp, slog as _slog

D_T = 16          # width of every time code
D_H = 32          # Block 7 embedding width
EVENT_FLAGS = ("port_delta", "dst_port_new", "reversed")
SIDE_COUNTS = ("request_packets", "response_packets", "direction_changes")
ARM_INPUTS = {
    "split": ("h_split", "dt_src", "dt_dst", *EVENT_FLAGS),
    "sides": ("h_request", "h_response", *SIDE_COUNTS, "reply_latency_s", "no_reply", "dt_src", "dt_dst", *EVENT_FLAGS),
}
REQUEST, RESPONSE = 0, 1


class LinkIds:
    """Integer ids for the directed links a stream's events touch, in both directions.

    Input:  sender and receiver node ids of the stream (N,)
    Output: callable (sender, receiver) -> link id per pair, -1 for a pair the stream never saw (a sampled negative);
            len() is the number of links
    """

    def __init__(self, sender: np.ndarray, receiver: np.ndarray):
        s, r = sender.astype(np.int64), receiver.astype(np.int64)
        self.keys = np.unique(np.concatenate([s << 32 | r, r << 32 | s]))

    def __len__(self) -> int:
        return len(self.keys)

    def __call__(self, sender: np.ndarray, receiver: np.ndarray) -> np.ndarray:
        key = sender.astype(np.int64) << 32 | receiver.astype(np.int64)
        at = np.minimum(np.searchsorted(self.keys, key), len(self.keys) - 1)
        return np.where(self.keys[at] == key, at, -1)


def event_inputs(stream: dict, rows: np.ndarray, arm: str) -> dict[str, torch.Tensor]:
    """The numeric inputs an arm reads for the given stream positions, as CPU tensors.

    Input:  stream dict (models.context_encoder.data.make_stream), stream positions of any shape, arm
    Output: name -> tensor (float32; no_reply bool)
    """
    return {name: torch.from_numpy(np.ascontiguousarray(stream[name][rows])) if name == "no_reply"
            else torch.from_numpy(np.ascontiguousarray(stream[name][rows], dtype=np.float32))
            for name in ARM_INPUTS[arm]}


class GapCode(nn.Module):
    """Phi*(dt): the Bochner code of log(1 + dt) for dt >= 0, a learned cold-start vector for dt < 0 (first seen).

    Input:  gaps in seconds, any shape
    Output: (..., D_T)
    """

    def __init__(self, d: int = D_T):
        super().__init__()
        self.time = TimeEncoder(d)
        self.cold = nn.Parameter(torch.zeros(d))

    def forward(self, dt: torch.Tensor) -> torch.Tensor:
        first = dt < 0
        code = self.time(torch.where(first, torch.zeros_like(dt), dt))   # -1 never reaches the encoding
        return torch.where(first[..., None], self.cold.expand_as(code), code)


class EventFeatures(nn.Module):
    """An event's own feature vector for its arm (design.md, Block 8 *Input arms*).

    Input:  arm; forward(inputs) with the tensors event_inputs builds, leading shape (...)
    Output: (..., width)
    """

    def __init__(self, arm: str):
        super().__init__()
        self.arm = arm
        self.gap = GapCode()
        side = 2 * D_T + len(EVENT_FLAGS)
        self.width = D_H + side if arm == "split" else 2 * D_H + len(SIDE_COUNTS) + D_T + 1 + side

    def forward(self, x: dict[str, torch.Tensor]) -> torch.Tensor:
        side = [self.gap(x["dt_src"]), self.gap(x["dt_dst"]), _slog(x["port_delta"])[..., None],
                  x["dst_port_new"][..., None], x["reversed"][..., None]]
        if self.arm == "split":
            return torch.cat([x["h_split"], *side], -1)
        counts = torch.stack([torch.log1p(x[c]) for c in SIDE_COUNTS], -1)
        return torch.cat([x["h_request"], x["h_response"], counts, self.gap(x["reply_latency_s"]),
                          x["no_reply"].to(counts.dtype)[..., None], *side], -1)


class FlowMessages(nn.Module):
    """The flow's first-K-packet summary, encoded as a link message.

    Input:  message width, number of summary columns
    Output: module; forward(summary (N, width)) returns messages (N, d_msg)

    A marker vector is added so link memory can tell this apart from an event message, whose markers are the
    request / response roles.
    """

    def __init__(self, d_msg: int = D_H, width: int = len(AGG_COLUMNS)):
        super().__init__()
        self.norm = nn.LayerNorm(width)
        # The same shape the packet head and the decoders use: these are raw aggregates on unlike scales (counts,
        # bytes, seconds), so unlike a Block 7 embedding they need a non-linearity before they reach memory.
        self.out = mlp(width, d_msg)
        self.marker = nn.Parameter(torch.zeros(d_msg))

    def forward(self, summary: torch.Tensor) -> torch.Tensor:
        return self.out(self.norm(_slog(summary))) + self.marker


class RecordMessages(nn.Module):
    """The flow record as a Block 8 message: Block 7's split encoder for records, plus a marker.

    Input:  message width, an optional checkpoint of a record encoder trained as an autoencoder on benign flows
    Output: module; forward(record (N, W)) returns messages (N, d_msg)

    Mirrors the packet path. There, Block 7's packet encoder is trained on benign flows, frozen, and its embedding is
    what reaches Block 8. Here the same holds when `frozen` is given: the record encoder was pre-trained the same way
    and does not move, so Block 8 receives a representation rather than having to learn one inside its own objective
    from four epochs of link prediction. Without `frozen` the encoder is learned in place, which is what it is
    measured against.
    """

    def __init__(self, d_msg: int = D_H, frozen: "Path | None" = None, split: bool = True):
        super().__init__()
        # `split=False` reads all 69 columns as one flat vector -- the arm the split encoder is measured against, so
        # the question "does keeping the directions apart help, as it did for packets" can be answered.
        self.encoder = RecordEncoder(d_msg) if split else nn.Sequential(
            nn.LayerNorm(len(RECORD_COLUMNS)), mlp(len(RECORD_COLUMNS), d_msg))
        if frozen is not None:
            state = torch.load(frozen, map_location="cpu", weights_only=False)
            self.encoder.load_state_dict(state["encoder"])
            self.encoder.requires_grad_(False)
        self.frozen, self.split = frozen is not None, split
        self.marker = nn.Parameter(torch.zeros(d_msg))

    def forward(self, record: torch.Tensor) -> torch.Tensor:
        # The split encoder takes the signed log itself; the flat one needs it applied here.
        x = record if self.split else _slog(record)
        if self.frozen:
            self.encoder.eval()
            with torch.no_grad():
                return self.encoder(x) + self.marker
        return self.encoder(x) + self.marker


class LinkMemory(nn.Module):
    """One GRU state per directed link, starting at a learned h0 and reset after `ttl` seconds without an update.

    Input:  message width, memory width, time-to-live in seconds, how many kinds of message can arrive
    Output: module; reset(n_links) clears the table; read(links, now) returns states (h0 for link id -1);
            update(links, messages, times, kinds) returns (links touched, new states) without writing; commit() writes

    Messages of different kinds are combined by **union, not by averaging**: each kind keeps its own slot, and a
    presence bit per kind is the maximum over that kind's messages -- an OR, so "an event arrived" and "a flow record
    arrived" are both still readable afterwards. A single blended mean lost that: one event plus one record averaged
    their markers into something that was neither. Counts ride alongside, because an OR cannot say how many. Each
    message also carries **its own** time gap, folded in before aggregation, so a record from 30 s ago is not read as
    though it had just arrived.
    """

    def __init__(self, d_msg: int, d_mem: int = 100, ttl: float = 3600.0, kinds: int = 1):
        super().__init__()
        self.d_mem, self.ttl, self.kinds, self.d_msg = d_mem, ttl, kinds, d_msg
        self.h0 = nn.Parameter(torch.zeros(d_mem))
        self.gap = TimeEncoder(D_T)
        self.slot = d_msg + D_T                                  # a kind's slot: its message and its own gap
        width = d_mem + D_T + kinds * self.slot + 2 * kinds      # + presence and count per kind
        self.message = nn.Sequential(nn.Linear(width, d_mem), nn.ReLU(), nn.Linear(d_mem, d_mem))
        self.cell = nn.GRUCell(d_mem, d_mem)
        self.reset(1)

    def reset(self, n_links: int, capacity: int | None = None) -> None:
        """Clear the table, optionally to a fixed number of live slots.

        Input:  how many links the stream has, or a capacity to cap the table at
        Output: none; state, times, residency and the use clock are cleared

        `capacity` is what makes this deployable: a live stream cannot hold a row for every link it has ever seen, so
        slots are recycled least-recently-used first and a link that returns after eviction starts from h0, exactly as
        an unseen one does. Measured on Block 10's identical table: capping at 25% of keys with 237,028 evictions left
        recall unchanged to four decimals, because the median host carries 7 lifetime events. `None` keeps a row per
        link, which is what offline runs and every checkpoint to date were trained with.
        """
        device = self.h0.device
        slots = max(n_links if capacity is None else min(capacity, n_links), 1)
        self.capacity, self.evictions, self.clock = capacity, 0, 0
        self.state = torch.zeros(slots, self.d_mem, device=device)
        self.last = torch.zeros(slots, dtype=torch.float64, device=device)
        self.used = torch.zeros(slots, dtype=torch.bool, device=device)
        self.used_at = torch.zeros(slots, dtype=torch.long, device=device)
        # link -> slot. Unbounded: the link id *is* the slot, so every existing code path is unchanged.
        self.slot_of = (torch.arange(max(n_links, 1), device=device) if capacity is None
                        else torch.full((max(n_links, 1),), -1, dtype=torch.long, device=device))

    def grow(self, n_links: int) -> None:
        """Extend the link -> slot map to ids below `n_links`, for a live stream whose links keep appearing.

        Only a capped table can grow: its slots are fixed and a new link simply has none yet. Doubling keeps the copies
        rare.
        """
        if self.capacity is None or n_links <= len(self.slot_of):
            return
        extra = max(n_links, 2 * len(self.slot_of)) - len(self.slot_of)
        self.slot_of = torch.cat([self.slot_of, torch.full((extra,), -1, dtype=torch.long, device=self.slot_of.device)])

    def _slots(self, links: torch.Tensor, allocate: bool) -> torch.Tensor:
        """Which row of the table each link occupies; -1 when it is not resident and none is free.

        Input:  link id per row (-1 for a padded slot), whether a missing link may claim a slot
        Output: slot index per row, -1 where unseated

        Only reads allocate. A read of a link with no slot answers from h0, which is what an unseen link gets anyway,
        so a capped table degrades rather than errs.
        """
        if self.capacity is None:
            return links
        self.clock += 1
        at = torch.where(links >= 0, self.slot_of[links.clamp(min=0)], torch.full_like(links, -1))
        if allocate:
            wanted = torch.unique(links[links >= 0])
            resident = wanted[self.slot_of[wanted] >= 0]
            self.used_at[self.slot_of[resident]] = self.clock     # protect this batch's residents from eviction
            missing = wanted[self.slot_of[wanted] < 0]
            room = len(self.state) - len(resident)
            missing = missing[:max(room, 0)]
            if len(missing):
                free = torch.topk(self.used_at, len(missing), largest=False).indices
                stale = torch.nonzero(self.slot_of[:, None] == free[None, :])
                if len(stale):
                    self.slot_of[stale[:, 0]] = -1
                    self.evictions += len(stale)
                self.slot_of[missing] = free
                self.state[free], self.used[free], self.last[free] = 0.0, False, 0.0
            at = torch.where(links >= 0, self.slot_of[links.clamp(min=0)], torch.full_like(links, -1))
        self.used_at[at.clamp(min=0)] = self.clock
        return at

    def read(self, links: torch.Tensor, now: torch.Tensor) -> torch.Tensor:
        seated = self._slots(links, allocate=False)
        at = seated.clamp(min=0)
        live = (seated >= 0) & self.used[at] & (now - self.last[at] <= self.ttl)
        return torch.where(live[:, None], self.state[at], self.h0.expand(len(links), -1))

    def update(self, links: torch.Tensor, messages: torch.Tensor, times: torch.Tensor,
               kinds: torch.Tensor | None = None):
        """Fold one step of messages into the links they touch.

        Input:  link id per message, message per message (M, d_msg), its time, its kind (0 when there is one kind)
        Output: (links touched, their new states); nothing is written until commit()
        """
        kinds = torch.zeros_like(links) if kinds is None else kinds
        seated = self._slots(links, allocate=True)
        keep = seated >= 0                                        # a link with no slot writes nothing this batch
        if not bool(keep.all()):
            links, messages, times, kinds, seated = (links[keep], messages[keep], times[keep], kinds[keep],
                                                     seated[keep])
        uniq, inverse = torch.unique(seated, return_inverse=True)
        # Each message's own gap against the link's last committed update, folded in before anything is pooled.
        own_gap = torch.where(self.used[uniq][inverse], times - self.last[uniq][inverse],
                              torch.zeros_like(times)).clamp(min=0)
        carried = torch.cat([messages, self.gap(own_gap.float())], 1)
        cell = inverse * self.kinds + kinds                       # one bucket per (link, kind)
        buckets = len(uniq) * self.kinds
        pooled = torch.zeros(buckets, self.slot, device=links.device).index_add_(0, cell, carried)
        count = torch.zeros(buckets, device=links.device).index_add_(
            0, cell, torch.ones(len(links), device=links.device))
        pooled = pooled / count.clamp(min=1)[:, None]             # mean inside a kind, never across kinds
        present = (count > 0).to(pooled.dtype)                    # the union: an OR over that kind's messages
        latest = torch.full((len(uniq),), -np.inf, dtype=torch.float64, device=links.device).scatter_reduce(
            0, inverse, times, reduce="amax")
        previous = self.read(uniq, latest)
        since = torch.where(self.used[uniq], latest - self.last[uniq], torch.zeros_like(latest)).clamp(min=0)
        folded = torch.cat([pooled.view(len(uniq), -1), present.view(len(uniq), -1),
                            torch.log1p(count).view(len(uniq), -1)], 1)
        new = self.cell(self.message(torch.cat([previous, self.gap(since.float()), folded], 1)), previous)
        self._pending = (uniq, new, latest)
        return uniq, new

    def commit(self) -> None:
        uniq, new, latest = self._pending
        self.state[uniq], self.last[uniq], self.used[uniq] = new.detach(), latest, True


class ContextEncoder(nn.Module):
    """Block 8: s_{u,v}(t) for each event from its features, both directions' link memory and its gated neighbourhood.

    Input:  arm, memory width, output width, attention heads, link time-to-live
    Output: module; begin_day(n_links) clears link memory; forward(batch, negative=None) returns (N, d_s), or the pair
            (positive, negative) when a batch of sampled negative links is given

    Batches follow TGN: the previous batch's messages are applied (with gradient) at the start of the next forward,
    so a batch reads memory as the batches before it left it and nothing a batch contains reaches its own reads.
    Negative links are read from the same memory and write nothing. Neighbour features are Block 7 embeddings of
    earlier stream positions, available by construction.
    """

    def __init__(self, arm: str, d_mem: int = 100, d_s: int = 100, heads: int = 2, ttl: float = 3600.0,
                 flow_messages: bool = False, flow_records: bool = False,
                 record_encoder: "Path | None" = None, record_split: bool = True,
                 flow_encoder: "nn.Module | None" = None, capacity: "int | float | None" = None):
        super().__init__()
        self.arm = arm
        # Live link-memory cap, honoured by begin_day. None is the offline table, one row per link the day contains.
        self.capacity = capacity
        self.features = EventFeatures(arm)
        self.role = nn.Embedding(2, D_H)                  # message marker: request / response
        self.no_reply = nn.Parameter(torch.zeros(D_H))    # arm 2's response message when nothing was answered
        self.query = nn.Linear(self.features.width + 2 * d_mem, d_s)
        self.key = nn.Linear(self.features.width + D_T, d_s)
        self.neighbour_role = nn.Embedding(2, d_s)       # launched by the sender / received by the receiver
        self.neighbour_gap = TimeEncoder(D_T)
        self.attention = nn.MultiheadAttention(d_s, heads, batch_first=True)
        # Explainability, off by default. On, _encode keeps the attention distribution over the neighbourhood for the
        # batch it just encoded, which is what the problem statement's explainability requirement is served from.
        # Off costs nothing: need_weights=False lets the fused kernel skip materialising the weights at all.
        self.explain = False
        self.last_attention: torch.Tensor | None = None
        self.last_neighbour_valid: torch.Tensor | None = None
        self.out = nn.Sequential(nn.Linear(2 * d_s, d_s), nn.ReLU(), nn.Linear(d_s, d_s))
        # The late kinds, each with its own encoder and marker. Kind 0 is always the event's own message.
        late = {}
        if flow_messages:
            late["flow"] = FlowMessages(D_H, len(AGG_COLUMNS))
        if flow_records:
            # Split by default: the record's two directions read by one shared encoder, as Block 7 reads a flow's
            # two sides. `record_split=False` falls back to one flat vector, which is what it is measured against.
            late["record"] = RecordMessages(D_H, frozen=record_encoder, split=record_split)
        self.late = nn.ModuleDict(late)
        # Trained together with the context encoder when given, instead of reading a frozen embedding from disk. The
        # event's embedding is then shaped by this objective rather than only by rebuilding its own flow.
        self.flow_encoder = flow_encoder
        self.memory = LinkMemory(D_H, d_mem, ttl, kinds=1 + len(late))
        self._previous = None
        self._queued: dict[str, list[tuple[torch.Tensor, torch.Tensor, torch.Tensor]]] = {k: [] for k in late}

    def begin_day(self, n_links: int, capacity: "int | float | None" = None) -> None:
        """Clear link memory for a new stream, capping the table when a capacity is set.

        Input:  how many links the stream has; a capacity overriding the one given at construction -- a count, or
                below 1 a fraction of this stream's links
        Output: none; link memory, the previous batch and the queued late messages are cleared

        A live stream cannot hold a row for every link it has ever seen. `LinkMemory` already recycles the
        least-recently-used slot; this is what turns that on. Measured on Block 10's equivalent table: capped at 25%
        of keys, with 237,028 evictions, recall was identical to four decimals, because the median host has 7 lifetime
        events and evicting it loses nothing.
        """
        cap = self.capacity if capacity is None else capacity
        if cap is not None and cap < 1:
            cap = max(1, int(cap * max(n_links, 1)))
        self.memory.reset(n_links, None if cap is None else int(cap))
        self._previous = None
        self._queued = {kind: [] for kind in self.late}

    def _release(self, now: torch.Tensor) -> list[tuple[torch.Tensor, torch.Tensor, torch.Tensor, int]]:
        """Queued late messages that already existed before this batch reads memory.

        Input:  the batch's observation times
        Output: list of (links, encoded messages, times, kind index); the rest stay queued

        A message is held until every event of a batch is at or after its time, so it is never applied before it
        exists. It can be applied up to one batch late -- the same compromise batching already makes for the event's
        own message.
        """
        ready = []
        earliest = now.min()
        for index, (kind, encoder) in enumerate(self.late.items(), start=1):
            keep = []
            for links, payload, times in self._queued[kind]:
                due = times <= earliest
                if due.all():
                    ready.append((links, encoder(payload), times, index))
                elif due.any():
                    ready.append((links[due], encoder(payload[due]), times[due], index))
                    keep.append((links[~due], payload[~due], times[~due]))
                else:
                    keep.append((links, payload, times))
            # Partial releases would otherwise leave one chunk per batch to rescan; a stream whose messages all fall
            # due later (a stalled clock, a long idle link) made that the dominant cost in a benchmark.
            self._queued[kind] = [tuple(torch.cat(part) for part in zip(*keep))] if len(keep) > 8 else keep
        return ready

    def _messages(self, batch: dict) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """The event's own message: what it tells the links it touches, at its observation time.

        Input:  a batch from make_batch
        Output: (link id per message, message per message (M, D_H), its time)

        Arm 1 sends the split embedding on sender -> receiver. Arm 2 sends the request embedding that way and the
        response the other way, with a learned vector standing in where nothing was answered.
        """
        x = batch["inputs"]
        if self.arm == "split":
            h = batch.get("message_h", x["h_split"])
            return batch["forward_link"], h + self.role.weight[REQUEST], batch["t_obs"]
        response = torch.where(x["no_reply"][:, None], self.no_reply.expand_as(x["h_response"]), x["h_response"])
        links = torch.cat([batch["forward_link"], batch["reverse_link"]])
        messages = torch.cat([x["h_request"] + self.role.weight[REQUEST], response + self.role.weight[RESPONSE]])
        return links, messages, torch.cat([batch["t_obs"], batch["t_obs"]])

    def _read(self, links: torch.Tensor, now: torch.Tensor, fresh) -> torch.Tensor:
        state = self.memory.read(links, now)
        if fresh is None:
            return state
        uniq, new = fresh
        at = torch.searchsorted(uniq, links).clamp(max=len(uniq) - 1)
        hit = uniq[at] == links
        return torch.where(hit[:, None], new[at], state)

    def _encode(self, batch: dict, fresh) -> torch.Tensor:
        now = batch["t_obs"]
        s0 = torch.cat([self.features(batch["inputs"]), self._read(batch["forward_link"], now, fresh),
                        self._read(batch["reverse_link"], now, fresh)], 1)
        query = self.query(s0)[:, None, :]
        valid = batch["neighbour_valid"]
        neighbours = self.features(batch["neighbour_inputs"])
        keys = self.key(torch.cat([neighbours, self.neighbour_gap(batch["neighbour_age"])], -1))
        keys = keys + self.neighbour_role(batch["neighbour_role"])
        empty = ~valid.any(1)
        mask = ~valid
        mask[:, 0] &= ~empty                              # an event with no neighbour attends to a dummy slot, zeroed below
        attended, weights = self.attention(query, keys, keys, key_padding_mask=mask,
                                           need_weights=self.explain, average_attn_weights=True)
        attended = attended[:, 0]
        if self.explain:
            # (N, neighbours): how much of this event's context came from each neighbour, averaged over heads. An
            # event with no neighbour attends a zeroed dummy slot, so its row is meaningless -- `valid` rides along to
            # say which rows those are.
            self.last_attention = weights[:, 0].detach()
            self.last_neighbour_valid = valid.detach()
        attended = attended * (~empty)[:, None].to(attended.dtype)
        return self.out(torch.cat([query[:, 0], attended], 1))

    def _embed(self, batch: dict) -> None:
        """Fill in the event's embedding from Block 7, when Block 7 is being trained here.

        Input:  a batch carrying packet tensors under "packets"
        Output: none; writes "h_split" into batch["inputs"]

        The live tensor is what this batch is encoded from, so gradient reaches Block 7. A detached copy is what the
        *next* forward sends as this batch's message: TGN applies a batch's messages one step later, and by then this
        step's graph has been freed, so a live tensor there would be a second backward through it.
        """
        if self.flow_encoder is None or "packets" not in batch:
            return
        h = self.flow_encoder(batch["packets"])
        batch["inputs"]["h_split"] = h
        batch["message_h"] = h.detach()

    def forward(self, batch: dict, negative: dict | None = None):
        self._embed(batch)
        fresh, updates = None, []
        if self._previous is not None:
            links, messages, times = self._messages(self._previous)
            updates.append((links, messages, times, 0))                  # kind 0: the event's own message
        if self.late:
            updates += self._release(batch["t_obs"])
        if updates:
            # One update for every kind at once: memory unions the kinds per link, so an event message and a flow
            # record landing together are one state change with both still identifiable.
            kinds = torch.cat([torch.full_like(part[0], index) for *part, index in updates])
            fresh = self.memory.update(*(torch.cat(part) for part in zip(*[u[:3] for u in updates])), kinds)
            self.memory.commit()          # the previous batch's states, now part of the table for later batches
        positive = self._encode(batch, fresh)
        self._previous = batch
        for kind in self.late:
            if len(batch[f"{kind}_link"]):
                self._queued[kind].append((batch[f"{kind}_link"], batch[f"{kind}_summary"], batch[f"{kind}_time"]))
        return positive if negative is None else (positive, self._encode(negative, fresh))


def make_batch(stream: dict, rows: np.ndarray, arm: str, links: LinkIds, device: str = "cpu",
               receiver: np.ndarray | None = None) -> dict:
    """One batch of consecutive stream positions with everything ContextEncoder reads.

    Input:  stream dict with its index (and optionally its cached neighbourhoods), stream positions, arm, link ids,
            device, optional receiver per row (a sampled negative link: the same event read as if it went to another
            host, whose neighbourhood is always looked up fresh)
    Output: dict: inputs, forward_link, reverse_link, t_obs, flow_link / flow_summary / flow_time (the rows whose
            first-K-packet summary lands after the event was scored), neighbour_inputs (N, S, ...), neighbour_valid (N, S),
            neighbour_age (N, S) seconds between the neighbour's observation time and this event's, neighbour_role
            (0 launched by the sender, 1 received by the receiver)
    """
    sender = stream["sender"][rows]
    sampled = receiver is not None                    # a negative link: read like a real event, but writes nothing
    receiver = stream["receiver"][rows] if receiver is None else receiver
    cached = stream.get("neighbours")                 # a real event's neighbourhood never changes; see cache_neighbours
    neighbours = cached[rows] if cached is not None and receiver is None else stream["index"].query(sender, receiver, rows)
    valid = neighbours >= 0
    at = np.where(valid, neighbours, 0)
    role = (stream["sender"][at] != sender[:, None]).astype(np.int64)
    age = np.where(valid, stream["t_obs"][rows][:, None] - stream["t_obs"][at], 0.0)

    def move(value):
        return value.to(device) if isinstance(value, torch.Tensor) else {k: v.to(device) for k, v in value.items()}

    forward = torch.from_numpy(links(sender, receiver))
    out = {
        "inputs": event_inputs(stream, rows, arm),
        "forward_link": forward, "reverse_link": torch.from_numpy(links(receiver, sender)),
        "t_obs": torch.from_numpy(stream["t_obs"][rows].astype(np.float64)),
        "neighbour_inputs": event_inputs(stream, at, arm),
        "neighbour_valid": torch.from_numpy(valid), "neighbour_age": torch.from_numpy(age.astype(np.float32)),
        "neighbour_role": torch.from_numpy(role),
    }
    # The late messages this event will send: its 20-packet summary, and its flow record. Each goes only where the
    # stream carries it and only where it lands after the event was scored -- otherwise the event already saw it. They
    # update the same link the event's own message does, taken from the same ids so the two cannot drift apart. A
    # sampled negative link writes nothing, so it carries none.
    for kind in ("flow", "record"):
        later = stream.get(f"{kind}_later")
        chosen = (torch.zeros(0, dtype=torch.int64) if sampled or later is None
                  else torch.from_numpy(np.flatnonzero(later[rows])))
        payload = stream.get(f"{kind}_summary")
        width = payload.shape[1] if payload is not None else 1
        out[f"{kind}_link"] = forward[chosen]
        out[f"{kind}_summary"] = (torch.from_numpy(np.ascontiguousarray(payload[rows][chosen.numpy()], np.float32))
                                  if len(chosen) else torch.zeros(0, width))
        out[f"{kind}_time"] = (torch.from_numpy(stream[f"{kind}_time"][rows][chosen.numpy()].astype(np.float64))
                               if len(chosen) else torch.zeros(0, dtype=torch.float64))
    return {name: move(value) for name, value in out.items()}
