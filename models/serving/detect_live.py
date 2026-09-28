"""Fast live detection: every flow scored 10 ms after its first packet, by the trained detection models, unchanged.

Run (capturing needs capture rights, as for dumpcap):
    uv run python -m models.serving.detect_live --interface eth0 --port 8902        # live
    dumpcap -i eth0 -w - | uv run python -m models.serving.detect_live --pcap -     # the same, fed through a pipe
    uv run python -m models.serving.detect_live --pcap capture.pcap --once          # replay a file, print a summary

Models default to artifacts/current (tools/promote.py): flow_encoder.pt, detection_encoder.pt, detector/head_*.pt.

The detection path was trained on what a flow shows within 10 ms of its first packet (models/data/prefix.py), so it
does not need the flow to finish -- only the forecasting path does (models.serving.live). This runs that path on a
packet stream:

    packets        one tshark process, with ingest's own field list and options (ingest/sources/packets.py), its
                   dissector state reset every 250,000 packets as ingest's chunking does
    flows          CICFlowMeter's rules, in Python: a flow is a 5-tuple in either direction, ends at a FIN, at 120 s
                   after its start, or when the next packet of an expired flow arrives (which then inherits its
                   orientation); IPv4 TCP and UDP only
    the event      at t_obs = min(first packet + 10 ms, FIN): the packets seen by then, the side features and host
                   history ingest computes (dt_src, dt_dst, port_delta, dst_port_new, reversed), sender and receiver
    flow encoder   the training code itself: prepare -> normalise -> embed, on those packets -> h (32)
    detection      the detection encoder over the event stream (StreamingContext: the same 512-event batches, link
      encoder      memory, neighbourhoods and late 20-packet summaries as training) -> s (100)
    detector       every head in the detector folder on [h, s] -> per-family probability -> threshold at the chosen
                   false-positive budget -> 3-in-a-row persistence per sender -> incidents

A verdict therefore exists 10 ms after a flow's first packet plus tshark's output lag and one scoring pass, typically
a few milliseconds. GET /detections returns the recent detections, incidents and counters.

**Where it can differ from training** (measured by tools/live/detect_check.py):
- a flow's 20-packet summary is final at its 20th packet or its FIN; a shorter flow without a FIN is known to be
  finished only at CICFlowMeter's 120 s timeout, so its summary message reaches link memory later than in training;
- a flow whose packets all arrive within 10 ms and that ends without a FIN is observed at first packet + 10 ms, where
  training (which knew the flow's end) observed it at its last packet -- the same packets, a later time;
- host history (dt_src, port_delta, ...) is updated in scoring order, which follows t_obs, where ingest follows the
  first packet; the two differ only for flows closed by a FIN inside the 10 ms;
- every flow is scored at its observation time, as training scored every event; CICFlowMeter (so training) drops a
  flow that never gets a second packet, which cannot be known 10 ms in -- 0.3% of flows on the DoS capture checked;
- training's packet-to-flow assignment is an interval join over the finished capture; here packets are assigned as
  CICFlowMeter assigns them, which is what that join approximates.
"""
from __future__ import annotations

import argparse
import heapq
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import numpy as np
import torch

from ingest.build.events import AGG_COLUMNS, DEFAULT_K_PACKETS
from ingest.sources.packets import (DEFAULT_TSHARK_CHUNK_PACKETS, PACKET_COLUMNS, TSHARK_FIELDS, _make_tshark_command,
                                    _parse_packet_row)
from models.compressor.latents import frozen_context_encoder
from models.context_encoder.model import ContextEncoder
from models.context_encoder.stream import NEIGHBOURS
from models.data.inputs import PACKET_FEATURES, PACKET_SOURCE_COLUMNS, X_COLUMNS, normalise
from models.data.prefix import DEFAULT_BUDGET_MS, _aggregates, prepare
from models.detector.model import Head
from models.flow_encoder.train import embed
from models.serving.emitter import AlertEmitter
from models.serving.graph import LinkRegistry, NodeRegistry, OnlineNeighbours

K = DEFAULT_K_PACKETS
FLOW_TIMEOUT_US = 120_000_000        # CICFlowMeter's flow timeout (ifm/Cmd.java), microseconds
SWEEP_EVERY_S = 1.0                  # expired flows are closed this often, as tools/live/StreamMeter.java does
FORGET_AFTER_S = 3600.0              # an expired flow's orientation is kept this long for its successor
DURATION = X_COLUMNS.index("Flow Duration")
OPEN = 1e15                          # Flow Duration (us) of a flow not yet known to have ended: observe() then cuts at the budget
CURRENT = Path(__file__).resolve().parents[2] / "artifacts" / "current"


def packet_features(p: dict) -> np.ndarray:
    """A packet's model features except direction, in PACKET_FEATURES order (models/data/inputs.py _fill_packets)."""
    frag = float(p["ip_flag_mf"] > 0 or p["ip_frag_offset"] > 0)
    return np.array([*(p[c] for c in PACKET_SOURCE_COLUMNS), frag], np.float32)


class Flow:
    __slots__ = ("id", "start_us", "t", "src", "dst", "sport", "dport", "proto", "times", "senders", "rows",
                 "n", "fin", "event", "summary", "first_port")

    def __init__(self, id_: int, p: dict, start_us: int, orientation: tuple):
        self.id, self.start_us, self.t = id_, start_us, float(p["timestamp"])
        self.src, self.dst, self.sport, self.dport, self.proto = orientation
        self.times, self.senders, self.rows = [], [], []
        self.n, self.fin, self.event, self.summary = 0, None, None, None
        self.first_port = p["src_port"]
        self.add(p)

    def add(self, p: dict) -> None:
        self.n += 1
        if len(self.times) < K:
            self.times.append(float(p["timestamp"]))
            self.senders.append(p["src_ip"])
            self.rows.append(packet_features(p))

    def arrays(self) -> tuple[np.ndarray, np.ndarray, int]:
        """The first K packets as load_inputs lays them out: (pkt (K, F), dt (K,), count)."""
        pkt, dt = np.zeros((K, len(PACKET_FEATURES)), np.float32), np.zeros(K, np.float32)
        n = len(self.rows)
        pkt[:n, :-1] = np.stack(self.rows)
        pkt[:n, -1] = [float(s != self.senders[0]) for s in self.senders]
        dt[1:n] = np.clip(np.diff(self.times), 0.0, None)
        return pkt, dt, n


class Tracker:
    """Packets into CICFlowMeter's flows, and each flow into an event once it can be scored.

    Input:  budget in seconds
    Output: object; add(packet) and advance(clock) move events into `ready`; finish() closes everything
    """

    def __init__(self, budget: float):
        self.budget = budget
        self.current: dict[tuple, Flow] = {}
        self.swept: dict[tuple, tuple] = {}         # id -> (orientation, swept at)
        self.due: list[tuple[float, int, Flow]] = []
        self.ready: list[Flow] = []                  # flows whose event can be scored now
        self.summaries: list[Flow] = []              # flows whose 20-packet summary became final
        self.clock, self.last_sweep, self.next_id, self.packets = float("-inf"), float("-inf"), 0, 0

    def add(self, p: dict) -> None:
        """One packet, as FlowGenerator.addPacket (and tools/live/StreamMeter.java) treats it."""
        if p["is_ipv6"] or p["protocol"] not in (6, 17):
            return                                   # CICFlowMeter reads IPv4 only; others never map to a flow
        self.packets += 1
        now = float(p["timestamp"])
        now_us = round(now * 1e6)
        fwd = (p["src_ip"], p["dst_ip"], p["src_port"], p["dst_port"], p["protocol"])
        bwd = (p["dst_ip"], p["src_ip"], p["dst_port"], p["src_port"], p["protocol"])
        key = fwd if fwd in self.current else bwd if bwd in self.current else None
        if key is not None:
            flow = self.current[key]
            if now_us - flow.start_us > FLOW_TIMEOUT_US:                  # flow timeout: a successor, same direction
                self.close(flow)
                self.current[key] = self.open(p, now_us, (flow.src, flow.dst, flow.sport, flow.dport, flow.proto))
            elif p["tcp_flag_fin"]:                                        # FIN ends a TCP flow
                flow.add(p)
                flow.fin = now
                self.grew(flow)
                del self.current[key]
                self.close(flow)
            else:
                flow.add(p)
                self.grew(flow)
        else:
            key = fwd if fwd in self.swept else bwd if bwd in self.swept else None
            if key is not None:                                           # successor of a swept flow
                self.current[key] = self.open(p, now_us, self.swept.pop(key)[0])
            else:
                self.current[fwd] = self.open(p, now_us, fwd)
        self.advance(now)

    def open(self, p: dict, now_us: int, orientation: tuple) -> Flow:
        flow = Flow(self.next_id, p, now_us, orientation)
        self.next_id += 1
        heapq.heappush(self.due, (flow.t + self.budget, flow.id, flow))
        return flow

    def grew(self, flow: Flow) -> None:
        if flow.n == K:
            self.final(flow)

    def emit(self, flow: Flow) -> None:
        flow.event = "ready"
        self.ready.append(flow)

    def final(self, flow: Flow) -> None:
        """The first K packets will not change: the flow's summary message exists."""
        if flow.summary is None and flow.event is not None:
            flow.summary = True
            self.summaries.append(flow)

    def close(self, flow: Flow) -> None:
        if flow.event is None:
            self.emit(flow)                                               # ended by a FIN inside the budget
        self.final(flow)

    def advance(self, clock: float) -> None:
        """Move the clock: flows past their observation time become events, expired flows close."""
        self.clock = max(self.clock, clock)
        while self.due and self.due[0][0] <= self.clock:
            _, _, flow = heapq.heappop(self.due)
            if flow.event is None:
                self.emit(flow)
        if self.clock - self.last_sweep >= SWEEP_EVERY_S:
            self.sweep()

    def sweep(self) -> None:
        self.last_sweep = now = self.clock
        limit = round(now * 1e6) - FLOW_TIMEOUT_US
        for key, flow in [(k, f) for k, f in self.current.items() if f.start_us < limit]:
            del self.current[key]
            self.close(flow)
            self.swept[key] = ((flow.src, flow.dst, flow.sport, flow.dport, flow.proto), now)
        if len(self.swept) > 100_000 or int(now) % 60 == 0:
            self.swept = {k: v for k, v in self.swept.items() if now - v[1] <= FORGET_AFTER_S}

    def finish(self) -> None:
        """End of input: every open flow is final (CICFlowMeter's own end-of-input dump)."""
        while self.due:
            flow = heapq.heappop(self.due)[2]
            if flow.event is None:
                self.emit(flow)
        for flow in list(self.current.values()):
            self.close(flow)
        self.current.clear()


class History:
    """ingest.build.events' cross-flow columns, online: dt_src, dt_dst, port_delta, dst_port_new.

    Each reads only earlier events, keyed on host addresses. Tables are LRU-capped.
    # ponytail: updated in scoring order (t_obs) where ingest uses first-packet order; see the module notes.
    """

    def __init__(self, capacity: int = 1_000_000):
        self.capacity = capacity
        self.as_src, self.as_dst, self.port, self.dialled = OrderedDict(), OrderedDict(), OrderedDict(), OrderedDict()

    def _put(self, table: OrderedDict, key, value) -> None:
        table[key] = value
        table.move_to_end(key)
        if len(table) > self.capacity:
            table.popitem(last=False)

    def features(self, flow: Flow, reversed_: float) -> tuple[float, float, float, float]:
        # Scoring order can put a flow a few ms before an earlier-started one of the same host (a FIN inside the budget):
        # the gap is then 0, never negative -- ingest's gaps never are, and -1 means "first sighting" only.
        dt_src = max(flow.t - self.as_src[flow.src], 0.0) if flow.src in self.as_src else -1.0
        dt_dst = max(flow.t - self.as_dst[flow.dst], 0.0) if flow.dst in self.as_dst else -1.0
        self._put(self.as_src, flow.src, max(flow.t, self.as_src.get(flow.src, flow.t)))
        self._put(self.as_dst, flow.dst, max(flow.t, self.as_dst.get(flow.dst, flow.t)))
        client, port = (flow.dst, flow.sport) if reversed_ == 1 else (flow.src, flow.dport)
        delta = float(port - self.port[client]) if client in self.port else 0.0
        new = 0.0 if (client, port) in self.dialled else 1.0
        self._put(self.port, client, port)
        self._put(self.dialled, (client, port), True)
        return dt_src, dt_dst, delta, new


class StreamingContext:
    """The detection encoder over a live stream, with training's batching reproduced exactly.

    Input:  a frozen ContextEncoder, link-memory slots, events per batch, neighbour-history rows, device
    Output: object; encode(...) returns s for events in stream order; queue_summary(...) adds late messages

    Training (models.compressor.latents.context_vectors) cuts the availability-ordered stream into batches of 512; a
    batch reads memory as the batches before it left it, and the queued 20-packet summaries due by its first event
    are applied at its start. Events here arrive in that same order, so when event p arrives every batch before
    p // 512 is complete: its messages are applied the moment the next batch opens, and each event is encoded on
    arrival rather than when its batch fills. The numbers are those of ContextEncoder.forward (checked by
    tools/live/detect_check.py).
    """

    def __init__(self, model: ContextEncoder, capacity: int, batch: int = 512, ring: int = 1 << 19,
                 device: str = "cpu"):
        if set(model.late) - {"flow"}:
            raise ValueError("the detection encoder must be trained without flow records: a record exists only once "
                             "its flow has closed")
        self.model, self.batch, self.ring, self.device = model, batch, ring, device
        model.begin_day(capacity, capacity=capacity)
        self.links, self.neighbours = LinkRegistry(), OnlineNeighbours(NEIGHBOURS)
        self.position, self.open = 0, []
        self.store = {"h_split": np.zeros((ring, 32), np.float32), "t_obs": np.zeros(ring),
                      "sender": np.zeros(ring, np.int64),
                      **{c: np.zeros(ring, np.float32) for c in ("dt_src", "dt_dst", "port_delta", "dst_port_new",
                                                                  "reversed")}}

    def queue_summary(self, links: np.ndarray, summaries: np.ndarray, times: np.ndarray) -> None:
        """Late 20-packet summaries, each applied at the first batch opening at or after its time."""
        if len(links):
            self.model._queued["flow"].append((torch.as_tensor(links, dtype=torch.int64, device=self.device),
                                               torch.as_tensor(summaries, dtype=torch.float32, device=self.device),
                                               torch.as_tensor(times, dtype=torch.float64, device=self.device)))

    @torch.no_grad()
    def encode(self, inputs: dict, sender: np.ndarray, receiver: np.ndarray, t_obs: np.ndarray,
               late: "tuple | None" = None) -> tuple[np.ndarray, np.ndarray]:
        """s for events in stream order.

        Input:  inputs {h_split (N, 32), dt_src, dt_dst, port_delta, dst_port_new, reversed (N,)}, sender and
                receiver node ids, t_obs, optionally late summaries already known (summary (N, 20), time (N,), send
                (N,) bool), queued straight after their event as training queues them after its batch
        Output: (s (N, d_s), forward link id per event)
        """
        n = len(sender)
        forward = self.links.ids(sender, receiver).numpy()
        reverse = self.links.ids(receiver, sender).numpy()
        self.model.memory.grow(len(self.links))
        out, at = [], 0
        while at < n:
            if self.position % self.batch == 0:
                self._open_batch(float(t_obs[at]))
            take = min(n - at, self.batch - self.position % self.batch)
            rows = np.arange(at, at + take)
            out.append(self._encode(inputs, sender[rows], receiver[rows], t_obs[rows], forward[rows], reverse[rows],
                                    rows))
            if late is not None:
                send = rows[late[2][rows]]
                self.queue_summary(forward[send], late[0][send], late[1][send])
            at += take
        return torch.cat(out).cpu().numpy() if out else np.zeros((0, self.model.out[-1].out_features), np.float32), forward

    def _open_batch(self, first: float) -> None:
        """ContextEncoder.forward's opening: the closed batch's own messages and the summaries now due."""
        model, updates = self.model, []
        if self.open:
            links, h, times = (torch.cat(part) for part in zip(*self.open))
            updates.append((*model._messages({"inputs": {"h_split": h}, "forward_link": links, "t_obs": times}), 0))
        updates += model._release(torch.tensor([first], dtype=torch.float64, device=self.device))
        if updates:
            kinds = torch.cat([torch.full_like(part[0], index) for *part, index in updates])
            model.memory.update(*(torch.cat(part) for part in zip(*[u[:3] for u in updates])), kinds)
            model.memory.commit()
        self.open = []

    def _encode(self, inputs, sender, receiver, t_obs, forward, reverse, rows) -> torch.Tensor:
        n, size = len(sender), NEIGHBOURS
        found = np.full((n, size), -1, np.int64)
        for i in range(n):          # read before push: a row sees earlier rows of its own batch, as offline
            got = self.neighbours.query(int(sender[i]), int(receiver[i])).numpy()
            found[i] = np.where(got > self.position - self.ring, got, -1)   # older than the ring: forgotten
            slot = self.position % self.ring
            for name, store in self.store.items():
                store[slot] = (inputs[name][rows[i]] if name in inputs else
                               t_obs[i] if name == "t_obs" else sender[i])
            self.neighbours.push(int(sender[i]), int(receiver[i]), self.position)
            self.position += 1
        valid = found >= 0
        at = np.where(valid, found, 0) % self.ring
        age = np.where(valid, np.maximum(t_obs[:, None] - self.store["t_obs"][at], 0.0), 0.0)   # never from the future
        names = ("h_split", "dt_src", "dt_dst", "port_delta", "dst_port_new", "reversed")
        dev = self.device
        batch = {
            "inputs": {c: torch.as_tensor(np.asarray(inputs[c][rows], np.float32), device=dev) for c in names},
            "forward_link": torch.as_tensor(forward, device=dev), "reverse_link": torch.as_tensor(reverse, device=dev),
            "t_obs": torch.as_tensor(t_obs, dtype=torch.float64, device=dev),
            "neighbour_inputs": {c: torch.as_tensor(self.store[c][at], dtype=torch.float32, device=dev) for c in names},
            "neighbour_valid": torch.as_tensor(valid, device=dev),
            "neighbour_age": torch.as_tensor(age, dtype=torch.float32, device=dev),
            "neighbour_role": torch.as_tensor((self.store["sender"][at] != sender[:, None]).astype(np.int64), device=dev),
        }
        s = self.model._encode(batch, None)
        self.open.append((batch["forward_link"], batch["inputs"]["h_split"], batch["t_obs"]))
        return s


class Heads:
    """Every detector head, each on its own day's families, each family with its own threshold.

    A family's threshold is its head's committed operating point (`serve_threshold`, written by
    models.evaluation.thresholds --write) unless a budget is given, in which case it is the threshold the head stored at
    that false-positive budget. A family with neither serves no alerts rather than a guessed threshold.
    """

    def __init__(self, paths: "list[Path]", budget: "float | None", device: str):
        self.heads, self.device, self.budgets = [], device, {}
        for path in paths:
            state = torch.load(path, map_location="cpu", weights_only=False)
            if state.get("format") != "supervised-head-v1":
                raise ValueError(f"{path}: not a detector head")
            head = Head(int(state["width"]), int(state["classes"]), int(state["hidden"]))
            head.load_state_dict(state["head"])
            head.to(device).eval().requires_grad_(False)
            scale = (torch.as_tensor(state["mean"], dtype=torch.float32, device=device),
                     torch.as_tensor(state["std"], dtype=torch.float32, device=device))
            committed = state.get("serve_threshold") or {}
            thresholds, budgets = {}, {}
            for f in state["families"]:
                if budget is None and f in committed:
                    thresholds[f], budgets[f] = float(committed[f]["threshold"]), float(committed[f]["budget"])
                else:
                    stored = state["thresholds"].get(f"{f}@{budget:g}") if budget is not None else None
                    thresholds[f], budgets[f] = stored, (budget if stored is not None else None)
            self.heads.append((head, scale, list(state["families"]), thresholds))
            self.budgets.update(budgets)
        if not self.heads:
            raise FileNotFoundError("no detector heads given")
        self.families = [f for _, _, families, _ in self.heads for f in families]
        self.thresholds = {f: t for *_, th in self.heads for f, t in th.items()}

    @torch.no_grad()
    def __call__(self, x: np.ndarray) -> np.ndarray:
        """(N, families) probability of each family, in self.families order."""
        x = torch.as_tensor(x, dtype=torch.float32, device=self.device)
        out = [head((x - mean) / std).softmax(-1)[:, 1:] for head, (mean, std), _, _ in self.heads]
        return torch.cat(out, 1).cpu().numpy()


class Forecaster:
    """The `live` world-model tag: the world model on the detection stream, rebuilt over a recent window each cycle.

    Input:  the live tag's compressor and world model (trained on the detection encoder's output), a work folder, the
            window in seconds and in events, rollout steps and seeds, device
    Output: object; add(...) takes every scored event, cycle() returns the forecast payload (the `lag` tag's format)

    Each cycle takes the window's events as they stand -- no flow has to finish -- and runs exactly what the `lag` tag
    runs on its window (models.serving.live.Live.forecast): the world model from empty memory over the window, then
    the rollout. The state is therefore as of the newest scored event, a few seconds behind the wire, where the `lag`
    tag's is ~150 s behind.
    """

    def __init__(self, compressor: Path, world_model: Path, work: Path, *, width: int, window_s: float = 300.0,
                 max_events: int = 50_000, steps: int = 6, seeds: int = 4, device: str = "cpu"):
        from models.serving.live import load_block9
        from models.world_model.service import served_threshold
        self.ae = load_block9(compressor, width, device)
        self.world_model, self.threshold = world_model, served_threshold(world_model)
        self.work, self.window_s, self.max_events, self.steps, self.seeds = Path(work), window_s, max_events, steps, seeds
        self.device, self.cycles, self.lock = device, 0, threading.Lock()
        self.events: deque = deque()
        self.payload: dict = {"status": "NOT_CONNECTED", "reason": "no forecast yet: the first cycle has not run",
                              "source": {"mode": "live", "tag": "live"}}

    @torch.no_grad()
    def add(self, ids, t, t_obs, senders, receivers, dt_src, dt_dst, reversed_, s) -> None:
        """Compress the scored events' context to z and keep them for the next cycle."""
        x = self.ae.normalise(torch.as_tensor(s, dtype=torch.float32, device=self.device))
        z, rebuilt = self.ae(x)
        error = ((rebuilt - x) ** 2).mean(1).cpu().numpy()
        z = z.cpu().numpy()
        with self.lock:
            self.events.extend(zip(ids, t, t_obs, senders, receivers, dt_src, dt_dst, reversed_, z, error))
            newest = float(np.max(t_obs))
            while self.events and (len(self.events) > self.max_events or self.events[0][2] < newest - self.window_s):
                self.events.popleft()

    def cycle(self) -> dict:
        """Write the window as a latents day and forecast from it, as the `lag` tag does from its window."""
        import pyarrow as pa
        import pyarrow.parquet as pq

        from models.explanation.world_model import seed_explanations
        from models.serving.live import local_addresses
        from models.world_model.inference import Replay
        from models.world_model.reception import SPLIT_TEST, receive
        from models.world_model.service import STAGE_UNAVAILABLE, forecast_payload, node_names

        started = time.monotonic()
        with self.lock:
            rows = sorted(self.events, key=lambda r: (r[2], r[0]))
        if len(rows) < 2:
            return {**self.payload, "reason": "too few events in the window yet"}
        self.cycles += 1
        ids, t, t_obs, senders, receivers, dt_src, dt_dst, reversed_, z, error = map(list, zip(*rows))
        hosts = list(dict.fromkeys(ip for pair in zip(senders, receivers) for ip in pair))   # first appearance
        node = {ip: i for i, ip in enumerate(hosts)}
        folder = self.work / "latents" / "live"
        folder.mkdir(parents=True, exist_ok=True)
        n = len(rows)
        z = np.stack(z).astype(np.float32)
        pq.write_table(pa.table({
            "event_id": np.array(ids, np.int64), "t": np.array(t), "t_obs": np.array(t_obs),
            "sender_node_id": np.array([node[ip] for ip in senders], np.int32),
            "receiver_node_id": np.array([node[ip] for ip in receivers], np.int32),
            "dt_src": np.array(dt_src, np.float32), "dt_dst": np.array(dt_dst, np.float32),
            "reversed": np.array(reversed_, np.float32),
            "z": pa.FixedSizeListArray.from_arrays(pa.array(z.ravel()), z.shape[1]),
            "recon_error": np.array(error, np.float32), "split": np.full(n, SPLIT_TEST, np.int8),
            "label": np.full(n, "Benign"), "observation_population": np.full(n, "live"),
            "attack": np.zeros(n, bool), "role": np.zeros(n, np.int8)}), folder / "event_latents.parquet")
        (folder / "latents_manifest.json").write_text(json.dumps({"day": "live", "n_events": n,
                                                                  "event_latent_dim": int(z.shape[1])}))
        pq.write_table(pa.table({"node_id": np.arange(len(hosts), dtype=np.int32), "ip": hosts}),
                       self.work / "node_index.parquet")

        run = receive([folder])
        replay = Replay(run, self.world_model, split=None, device=self.device, attention=False)
        replay.advance(len(run))
        replay.finish()
        rollouts = replay.rollout(self.steps, self.seeds)
        newest = float(t_obs[-1])
        source = {"mode": "live", "tag": "live", "day": "this machine", "position": replay.scored, "total": n,
                  "t": newest, "cycle": self.cycles, "build_seconds": round(time.monotonic() - started, 2),
                  "state_as_of": newest, "window_seconds": self.window_s,
                  "lag_seconds": round(time.time() - newest, 1), "local_ips": local_addresses()}
        if not rollouts:
            return {"status": "NOT_CONNECTED", "reason": "the window has events but too few for a rollout yet",
                    "current_state": "S[t]", "future_states": [], "predicted_stage": STAGE_UNAVAILABLE,
                    "source": source}
        caveats = [
            f"live: the last {n:,} events ({self.window_s:.0f} s at most) of the detection stream, every flow taken "
            f"10 ms after its first packet; the state is as of {source['lag_seconds']:.0f} s ago",
            "the world model's memory is rebuilt over the window each cycle, as the lag tag's is",
            "each step's target is the ranking head's choice; a predicted link has not happened",
        ]
        names = node_names(self.work / "node_index.parquet")
        return forecast_payload(rollouts, replay.rows, caveats=caveats, names=names, threshold=self.threshold,
                                source=source,
                                explanation=seed_explanations(replay, {r["seed_id"] for r in rollouts}, names))


class Detector:
    """Packets in, verdicts out: tracker -> features -> flow encoder -> detection encoder -> heads -> alerts."""

    def __init__(self, flow_encoder: Path, detection_encoder: Path, heads: "list[Path]", *, budget: "float | None" = None,
                 capacity: int = 250_000, device: str = "cpu", keep: bool = False, oracle: "dict | None" = None,
                 forecaster: "Forecaster | None" = None):
        from models.serving.live import load_block7
        self.device = device
        self.flow_model, self.stats, self.side = load_block7(flow_encoder, device)
        saved = torch.load(flow_encoder, map_location="cpu", weights_only=False)
        self.budget = float(saved.get("budget_ms", DEFAULT_BUDGET_MS)) / 1000
        model8, arm = frozen_context_encoder(detection_encoder, device)
        if arm != "split":
            raise ValueError(f"{detection_encoder}: arm {arm!r}; this service builds the split arm's inputs")
        self.context = StreamingContext(model8, capacity, device=device)
        self.heads = Heads(heads, budget, device)
        self.emitters = {f: AlertEmitter(t) for f, t in self.heads.thresholds.items() if t is not None}
        self.tracker, self.history, self.nodes = Tracker(self.budget), History(), NodeRegistry(capacity=1_000_000)
        self.scored, self.single, self.started = 0, 0, time.time()
        self.detections, self.incidents = deque(maxlen=200), deque(maxlen=200)
        self.counts = {f: 0 for f in self.heads.families}
        self.lag = deque(maxlen=10_000)
        self.log: "list[dict] | None" = [] if keep else None       # every scored event, for the parity check
        self.pending_summaries: dict[int, tuple] = {}              # flow id -> (link, t_obs) of scored events
        # tools/live/detect_check.py only: {(flow_key, t): (summary, time)} known in advance, queued as training queues
        # them, to measure what the live summaries' lateness costs
        self.oracle = oracle
        self.forecaster = forecaster                               # the `live` world-model tag, when served

    def add(self, packet: dict) -> None:
        self.tracker.add(packet)

    def score(self, wall: "float | None" = None) -> int:
        """Score every event that has become ready. Returns how many."""
        flows = sorted(self.tracker.ready, key=lambda f: (self._t_obs(f), f.id))
        self.tracker.ready = []
        if flows:
            self._score(flows, wall)
        self._summaries()
        return len(flows)

    def _t_obs(self, flow: Flow) -> float:
        return min(flow.t + self.budget, flow.fin) if flow.fin is not None else flow.t + self.budget

    def _score(self, flows: "list[Flow]", wall: "float | None") -> None:
        n = len(flows)
        pkt, dt = np.zeros((n, K, len(PACKET_FEATURES)), np.float32), np.zeros((n, K), np.float32)
        n_pkt, x = np.zeros(n, np.int16), np.zeros((n, len(X_COLUMNS)), np.float32)
        for i, flow in enumerate(flows):
            pkt[i], dt[i], n_pkt[i] = flow.arrays()
            x[i, DURATION] = (flow.fin - flow.t) * 1e6 if flow.fin is not None else OPEN
        data = {"event_id": np.array([f.id for f in flows]), "t": np.array([f.t for f in flows]),
                "attack": np.zeros(n, bool), "x": x, "a": np.zeros((n, len(AGG_COLUMNS)), np.float32),
                "pkt": pkt, "dt": dt, "n_pkt": n_pkt}
        data = prepare(data, self.budget, self.side)
        h, _ = embed(self.flow_model, normalise(data, self.stats)[0], np.arange(n), device=self.device)
        t_obs = np.array([self._t_obs(f) for f in flows])

        inputs = {"h_split": h, **{c: np.zeros(n, np.float32) for c in ("dt_src", "dt_dst", "port_delta",
                                                                        "dst_port_new", "reversed")}}
        senders, receivers = [], []
        for i, flow in enumerate(flows):
            inputs["reversed"][i] = rev = reversed_of_flow(flow)
            (inputs["dt_src"][i], inputs["dt_dst"][i], inputs["port_delta"][i],
             inputs["dst_port_new"][i]) = self.history.features(flow, rev)
            sender = flow.senders[0]
            senders.append(sender)
            receivers.append(flow.dst if sender == flow.src else flow.src)
        ids = self.nodes.ids(senders + receivers).numpy()
        sender, receiver = ids[:n], ids[n:]
        late = None
        if self.oracle is not None:
            known = [self.oracle.get((flow_key(f), round(f.t, 6))) for f in flows]
            late = (np.stack([k[0] if k else np.zeros(len(AGG_COLUMNS), np.float32) for k in known]),
                    np.array([k[1] if k else 0.0 for k in known]),
                    np.array([bool(k) and k[1] > t_obs[i] + 1e-6 for i, k in enumerate(known)]))
        s, links = self.context.encode(inputs, sender, receiver, t_obs, late)
        probability = self.heads(np.concatenate([h, s], 1))

        for i, flow in enumerate(flows):
            flow.event = "scored"
            self.pending_summaries[flow.id] = (int(links[i]), float(t_obs[i]))
        self.scored += n
        self.single += int((data["packets_seen"] == 1).sum())
        if wall is not None:
            self.lag.extend((wall - t_obs).tolist())
        self._alerts(flows, sender, t_obs, probability)
        if self.forecaster is not None:
            self.forecaster.add([f.id for f in flows], [f.t for f in flows], t_obs, senders, receivers,
                                inputs["dt_src"], inputs["dt_dst"], inputs["reversed"], s)
        if self.log is not None:
            for i, flow in enumerate(flows):
                self.log.append({"flow_key": flow_key(flow), "t": flow.t, "t_obs": float(t_obs[i]),
                                 "sender_ip": senders[i], "h": h[i], "s": s[i],
                                 "probability": probability[i],
                                 **{c: float(inputs[c][i]) for c in ("dt_src", "dt_dst", "port_delta",
                                                                     "dst_port_new", "reversed")},
                                 "sender": int(sender[i]), "receiver": int(receiver[i]), "link": int(links[i])})

    def _summaries(self) -> None:
        """Queue the 20-packet summaries that have become final, for events already scored."""
        keep, links, rows, times = [], [], [], []
        for flow in self.tracker.summaries:
            if flow.id not in self.pending_summaries:
                keep.append(flow)                    # its event is not scored yet
                continue
            link, t_obs = self.pending_summaries.pop(flow.id)
            pkt, dt, count = flow.arrays()
            valid = (np.arange(K) < count)[None]
            summary = _aggregates(pkt[None], dt[None], valid)[0]
            flow_time = flow.t + float(summary[AGG_COLUMNS.index("iat_mean")]) * max(count - 1, 0)
            if self.log is not None:
                self.log.append({"summary_of": flow_key(flow), "t": flow.t, "summary": summary,
                                 "flow_time": flow_time, "known_at": self.tracker.clock})
            if flow_time > t_obs + 1e-6 and self.oracle is None:            # load_day's flow_later: only a summary the event did not see
                links.append(link), rows.append(summary), times.append(flow_time)
        self.tracker.summaries = keep
        if links:
            self.context.queue_summary(np.array(links), np.stack(rows), np.array(times))
        if len(self.pending_summaries) > 2_000_000:              # ponytail: flows that never finalise are dropped
            self.pending_summaries = dict(list(self.pending_summaries.items())[-1_000_000:])

    def _alerts(self, flows, sender, t_obs, probability) -> None:
        for j, family in enumerate(self.heads.families):
            threshold = self.heads.thresholds.get(family)
            if threshold is None:
                continue
            hit = np.flatnonzero(probability[:, j] >= threshold)
            self.counts[family] += len(hit)
            for i in hit[-20:]:
                flow = flows[i]
                self.detections.append({"family": family, "probability": round(float(probability[i, j]), 5),
                                        "threshold": threshold, "t_obs": float(t_obs[i]), "src": flow.src,
                                        "dst": flow.dst, "src_port": flow.sport, "dst_port": flow.dport,
                                        "protocol": flow.proto, "sender": flow.senders[0] if flow.senders else None})
            for incident in self.emitters[family].push_batch(torch.as_tensor(sender), torch.as_tensor(probability[:, j]),
                                                             torch.as_tensor(t_obs)):
                incident["family"] = family
                self.incidents.append(incident)
                print(json.dumps({"incident": incident}, default=str), flush=True)

    def status(self) -> dict:
        lag = np.array(self.lag) if self.lag else None
        return {"status": "RUNNING", "clock": self.tracker.clock, "packets": self.tracker.packets,
                "open_flows": len(self.tracker.current), "events_scored": self.scored,
                "scored_with_one_packet": self.single,
                "uptime_s": round(time.time() - self.started, 1),
                "latency_after_t_obs_s": None if lag is None else {
                    "median": round(float(np.median(lag)), 4), "p99": round(float(np.quantile(lag, 0.99)), 4)},
                "budget_s": self.budget,
                "thresholds": {f: {"threshold": t, "false_alarm_budget": self.heads.budgets.get(f)}
                               for f, t in self.heads.thresholds.items()},
                "detections_by_family": self.counts,
                "recent_detections": list(self.detections), "incidents": list(self.incidents)}


def reversed_of_flow(flow: Flow) -> float:
    """ingest.build.events._mark_reversed for one flow: 1 when the record runs server -> client, -1 when unknown."""
    first = flow.rows[0]
    if first[PACKET_FEATURES.index("tcp_flag_syn")] == 1 and first[PACKET_FEATURES.index("tcp_flag_ack")] == 0:
        return 0.0 if flow.senders[0] == flow.src and flow.first_port == flow.sport else 1.0
    return 1.0 if flow.sport < flow.dport else 0.0 if flow.sport > flow.dport else -1.0


def flow_key(flow: Flow) -> str:
    from ingest.sources.flows import canonical_flow_key
    return canonical_flow_key(flow.src, flow.sport, flow.dst, flow.dport, flow.proto)


def tshark_command(source: str, interface: bool) -> list[str]:
    """ingest's tshark command, on a live interface or a file ('-' is stdin), line-buffered, state reset per chunk."""
    command = _make_tshark_command(Path(source))
    at = command.index("-r")
    command[at:at + 2] = ["-i", source] if interface else ["-r", source]
    return [*command, "-l", "-M", str(DEFAULT_TSHARK_CHUNK_PACKETS)]


def read_packets(command: list[str], out: "queue.Queue") -> None:
    """tshark's lines as packet dicts, parsed exactly as ingest parses them; None at the end."""
    env = {**os.environ, "MALLOC_ARENA_MAX": "1"}
    errors = tempfile.TemporaryFile("w+")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, text=True, env=env)
    for line in process.stdout:
        values = line.rstrip("\r\n").split("\t")
        if len(values) != len(TSHARK_FIELDS):
            continue
        raw = dict(zip(TSHARK_FIELDS, values))
        if not ((raw.get("ip.src") and raw.get("ip.dst")) or (raw.get("ipv6.src") and raw.get("ipv6.dst"))):
            continue
        row = _parse_packet_row(raw)
        if row is not None:
            out.put(dict(zip(PACKET_COLUMNS, row)))
    if process.wait() != 0:
        errors.seek(0)
        print(f"tshark exited with {process.returncode}: {errors.read()[-2000:]}", file=sys.stderr, flush=True)
    out.put(None)


def run(detector: Detector, packets: "queue.Queue", live: bool, grace: float) -> None:
    """Feed packets, score whatever is ready, until the input ends."""
    while True:
        started, ended = time.monotonic(), False
        while time.monotonic() - started < 0.005:
            try:
                packet = packets.get(timeout=0.002)
            except queue.Empty:
                break
            if packet is None:
                ended = True
                break
            detector.add(packet)
        if live:                                   # a quiet wire still moves the clock; grace covers tshark's lag
            detector.tracker.advance(time.time() - grace)
        if ended:
            detector.tracker.finish()
        detector.score(time.time() if live else None)
        if ended:
            return


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", help="capture from this interface (needs capture rights)")
    source.add_argument("--pcap", help="read this capture file, or - for a pcap stream on stdin")
    parser.add_argument("--flow-encoder", type=Path, default=CURRENT / "flow_encoder.pt")
    parser.add_argument("--detection-encoder", type=Path, default=CURRENT / "detection_encoder.pt")
    parser.add_argument("--detector", type=Path, default=CURRENT / "detector",
                        help="a folder of head_*.pt, or one head file")
    parser.add_argument("--budget", type=float, default=None,
                        help="serve the threshold each head stored at this false-positive budget instead of its "
                             "committed operating point (serve_threshold); heads store 0.0001, 0.001, 0.01 and 0.05")
    parser.add_argument("--capacity", type=int, default=250_000, help="link-memory slots")
    parser.add_argument("--grace", type=float, default=0.02,
                        help="seconds a quiet wire waits for tshark's output before closing an observation window")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--port", type=int, default=8902)
    parser.add_argument("--once", action="store_true", help="process the file, print the status, and exit")
    forecast = parser.add_argument_group("the `live` world-model tag (GET /forecast)")
    forecast.add_argument("--forecast", action="store_true",
                          help="also serve the world model on this stream; models from the registry's `live` tag")
    forecast.add_argument("--registry", type=Path, default=CURRENT / "serving.json")
    forecast.add_argument("--compressor", type=Path, default=None, help="instead of the registry's")
    forecast.add_argument("--world-model", type=Path, default=None, help="instead of the registry's")
    forecast.add_argument("--forecast-every", type=float, default=5.0, help="seconds between forecast cycles")
    forecast.add_argument("--forecast-window", type=float, default=300.0, help="seconds of events per cycle")
    forecast.add_argument("--forecast-events", type=int, default=50_000, help="events per cycle at most")
    forecast.add_argument("--rollout-steps", type=int, default=6)
    forecast.add_argument("--rollout-seeds", type=int, default=4)
    forecast.add_argument("--work", type=Path, default=Path(tempfile.gettempdir()) / "netwatch-forecast")
    args = parser.parse_args(argv)
    if args.forecast and (args.compressor is None or args.world_model is None):
        from models.serving.registry import resolve
        models = resolve(args.registry, "live")              # refuses, with the reason, until the live pair is trained
        args.flow_encoder, args.detection_encoder = models["block7"], models["block8"]
        args.compressor, args.world_model = args.compressor or models["block9"], args.world_model or models["block10"]
    heads = sorted(args.detector.glob("head_*.pt")) if args.detector.is_dir() else [args.detector]
    for path in (args.flow_encoder, args.detection_encoder, *heads):
        if not Path(path).is_file():
            parser.error(f"{path} is missing -- promote a run (tools/promote.py) or name the models")
    forecaster = None
    if args.forecast:
        width = int(torch.load(args.detection_encoder, map_location="cpu", weights_only=False)["model"]
                    ["out.2.weight"].shape[0])
        forecaster = Forecaster(args.compressor, args.world_model, args.work, width=width,
                                window_s=args.forecast_window, max_events=args.forecast_events,
                                steps=args.rollout_steps, seeds=args.rollout_seeds, device=args.device)
    detector = Detector(args.flow_encoder, args.detection_encoder, heads, budget=args.budget, capacity=args.capacity,
                        device=args.device, forecaster=forecaster)
    packets: queue.Queue = queue.Queue(maxsize=200_000)
    live = args.interface is not None or args.pcap == "-"     # a pipe from dumpcap is the wire too
    command = tshark_command(args.interface or args.pcap, args.interface is not None)
    threading.Thread(target=read_packets, args=(command, packets), daemon=True).start()
    served = ", ".join(f"{f} {t:.4g} (budget {detector.heads.budgets[f]:g})" if t is not None else f"{f} none"
                       for f, t in detector.heads.thresholds.items())
    print(f"detection: {len(heads)} heads; thresholds: {served}", flush=True)
    if args.once:
        run(detector, packets, live, args.grace)
        status = detector.status()
        status["recent_detections"] = status["recent_detections"][-5:]
        print(json.dumps(status, indent=1, default=str))
        if forecaster is not None:
            payload = forecaster.cycle()
            print(json.dumps({"forecast": payload.get("status"), "reason": payload.get("reason"),
                              "source": payload.get("source"),
                              "predicted_links": len(payload.get("predicted_edges", []))}, indent=1, default=str))
        return 0

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.rstrip("/")
            if path == "/forecast" and forecaster is not None:
                body = json.dumps(forecaster.payload, default=str).encode()
            elif path in ("/detections", "/health"):
                body = json.dumps(detector.status(), default=str).encode()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    threading.Thread(target=run, args=(detector, packets, live, args.grace), daemon=True).start()
    if forecaster is not None:
        def forecasting() -> None:
            while True:
                time.sleep(args.forecast_every)
                try:
                    forecaster.payload = forecaster.cycle()
                except Exception:                  # a failed cycle must not stop detection
                    import traceback
                    traceback.print_exc()
        threading.Thread(target=forecasting, daemon=True).start()
        print(f"live forecast on http://127.0.0.1:{args.port}/forecast", flush=True)
    print(f"detections on http://127.0.0.1:{args.port}/detections", flush=True)
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
