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
a few milliseconds. GET /detections exposes raw threshold crossings for diagnostics, but operator-facing consumers
report only incidents that pass persistence and quiet-gap aggregation.

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
import io
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from operator import itemgetter
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import numpy as np
import torch

from ingest.build.events import AGG_COLUMNS, DEFAULT_K_PACKETS
from ingest.sources.flows import BENIGN_LABEL, canonical_flow_key
from ingest.sources.packets import (DEFAULT_TSHARK_CHUNK_PACKETS, PACKET_LABEL_COLUMNS, PAYLOAD_BYTES, TSHARK_FIELDS,
                                    _make_tshark_command)
from models.compressor.latents import frozen_context_encoder
from models.context_encoder.model import ContextEncoder
from models.context_encoder.stream import NEIGHBOURS
from models.data.inputs import PACKET_FEATURES, PACKET_SOURCE_COLUMNS, X_COLUMNS, normalise
from models.data.batching import TENSOR_FIELDS
from models.data.prefix import DEFAULT_BUDGET_MS, _aggregates, prepare
from models.detector.model import Head
from models.serving.emitter import AdaptiveThreshold, AlertEmitter
from models.serving.graph import LinkRegistry, NodeRegistry, OnlineNeighbours
from models.serving.incident_history import IncidentHistory, MAX_RETURNED, WINDOW_S
from models.serving.live_calibration import LiveScoreCalibration, checkpoint_signature
from models.serving.threshold_mode import ThresholdMode
from models.serving.service_evidence import ServiceEvidence, normal_dns_query, normal_gvcp_discovery

K = DEFAULT_K_PACKETS
FLOW_TIMEOUT_US = 120_000_000        # CICFlowMeter's flow timeout (ifm/Cmd.java), microseconds
SWEEP_EVERY_S = 1.0                  # expired flows are closed this often, as tools/live/StreamMeter.java does
FORGET_AFTER_S = 3600.0              # an expired flow's orientation is kept this long for its successor
DURATION = X_COLUMNS.index("Flow Duration")
OPEN = 1e15                          # Flow Duration (us) of a flow not yet known to have ended: observe() then cuts at the budget
LATENCY_WINDOW_S = 60.0              # the status reports the latency of verdicts given in this many recent seconds
BATCH_PACKETS = 2048                 # packets taken before a scoring pass; four times as many once that many wait
SIDE = ("dt_src", "dt_dst", "port_delta", "dst_port_new", "reversed")     # an event's host-history features
CONTEXT_INPUTS = ("h_split", *SIDE)                                         # what the detection encoder reads per event
CURRENT = Path(__file__).resolve().parents[2] / "artifacts" / "current"

(_TIME, _SRC4, _SRC6, _DST4, _DST6, _TCP_SPORT, _UDP_SPORT, _TCP_DPORT, _UDP_DPORT, _PROTO4, _PROTO6, _LENGTH, _FRAME,
 _TTL4, _TTL6, _WINDOW, _SYN, _ACK, _FIN, _RST, _PSH, _URG, _DF, _MF, _FRAG, _RETRANSMISSION, _TCP_PAYLOAD,
 _UDP_PAYLOAD) = (TSHARK_FIELDS.index(name) for name in (
     "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "udp.srcport", "tcp.dstport",
     "udp.dstport", "ip.proto", "ipv6.nxt", "frame.len", "frame.number", "ip.ttl", "ipv6.hlim", "tcp.window_size",
     "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset", "tcp.flags.push", "tcp.flags.urg",
     "ip.flags.df", "ip.flags.mf", "ip.frag_offset", "tcp.analysis.retransmission", "tcp.payload", "udp.payload"))
_SET = ("1", "true")                 # how tshark prints a set boolean, across releases
_UNLABELLED = {column: BENIGN_LABEL[column] for column in PACKET_LABEL_COLUMNS}
_SOURCE = itemgetter(*PACKET_SOURCE_COLUMNS)


def _first_int(first: str, second: str = "") -> int:
    """ingest's _optional_int: the first non-empty field as an int; 0 when both are empty or it will not parse."""
    value = first or second
    try:
        return int(value) if value else 0
    except ValueError:
        return 0


def live_packet(v: "list[str]") -> "dict | None":
    """One tshark line as ingest's packet row, or None where ingest drops the packet.

    Input:  the line's fields, in TSHARK_FIELDS order
    Output: dict(zip(PACKET_COLUMNS, _parse_packet_row(...))) for an unlabelled packet

    ingest walks PACKET_FIELDS through a closure and a try per field; at a flood's packet rate that cost as much
    as scoring the flows. This is the same table written out, and test_live_input_contract holds the two equal.
    """
    if not ((v[_SRC4] and v[_DST4]) or (v[_SRC6] and v[_DST6])):
        return None
    try:
        timestamp, length, frame_no = float(v[_TIME]), int(v[_LENGTH]), int(v[_FRAME])
    except ValueError:
        return None                                                   # a required field: the packet is dropped
    src, dst = v[_SRC4] or v[_SRC6], v[_DST4] or v[_DST6]
    src_port, dst_port = _first_int(v[_TCP_SPORT], v[_UDP_SPORT]), _first_int(v[_TCP_DPORT], v[_UDP_DPORT])
    protocol = _first_int(v[_PROTO4], v[_PROTO6])
    hexed = (v[_TCP_PAYLOAD] or v[_UDP_PAYLOAD]).replace(":", "")
    try:
        payload = bytes.fromhex(hexed)[:PAYLOAD_BYTES]
    except ValueError:
        payload = b""
    return {"timestamp": timestamp, "src_ip": src, "dst_ip": dst, "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol, "length": length, "frame_no": frame_no, "ttl": _first_int(v[_TTL4], v[_TTL6]),
            "is_ipv6": 1 if v[_SRC6] else 0, "tcp_window": _first_int(v[_WINDOW]),
            "tcp_flag_syn": 1 if v[_SYN].strip().lower() in _SET else 0,
            "tcp_flag_ack": 1 if v[_ACK].strip().lower() in _SET else 0,
            "tcp_flag_fin": 1 if v[_FIN].strip().lower() in _SET else 0,
            "tcp_flag_rst": 1 if v[_RST].strip().lower() in _SET else 0,
            "tcp_flag_psh": 1 if v[_PSH].strip().lower() in _SET else 0,
            "tcp_flag_urg": 1 if v[_URG].strip().lower() in _SET else 0,
            "ip_flag_df": 1 if v[_DF].strip().lower() in _SET else 0,
            "ip_flag_mf": 1 if v[_MF].strip().lower() in _SET else 0,
            "ip_frag_offset": _first_int(v[_FRAG]), "tcp_retransmission": 1 if v[_RETRANSMISSION] else 0,
            "payload_len": len(hexed) // 2, "payload": payload,
            "flow_key": canonical_flow_key(src, src_port, dst, dst_port, protocol), **_UNLABELLED}


@torch.no_grad()
def flow_embedding_tensor(model, data: dict, device: str, batch_size: int = 4096) -> torch.Tensor:
    """h for prepared flows, left on the device: the detection encoder and the heads read it there."""
    return torch.cat([model.encoder({name: torch.as_tensor(data[name][start:start + batch_size], device=device)
                                     for name in TENSOR_FIELDS})
                      for start in range(0, len(data["n_pkt"]), batch_size)])


def flow_embeddings(model, data: dict, device: str, batch_size: int = 4096) -> np.ndarray:
    """Use the trained encoder directly; detection never consumes reconstruction errors."""
    return flow_embedding_tensor(model, data, device, batch_size).cpu().numpy()


def packet_row(p: dict) -> tuple:
    """A packet's model features except direction, in PACKET_FEATURES order (models/data/inputs.py _fill_packets)."""
    return (*_SOURCE(p), float(p["ip_flag_mf"] > 0 or p["ip_frag_offset"] > 0))


def latency_samples(verdict_wall: float, observed: np.ndarray, first_packet: np.ndarray) -> tuple[np.ndarray, np.ndarray, int]:
    """Nonnegative wall-clock durations and an explicit future-timestamp count."""
    raw_capture = verdict_wall - first_packet
    return (np.maximum(verdict_wall - observed, 0.0), np.maximum(raw_capture, 0.0),
            int((raw_capture < 0).sum()))


class RecentDurations:
    """Durations measured in the last `window` seconds of wall time, so a status describes the service as it is now.

    A history bounded only by count kept a flood's latency on display for hours after a quiet link had caught up.
    """

    def __init__(self, window: float = LATENCY_WINDOW_S, limit: int = 10_000):
        self.window, self.rows = window, deque(maxlen=limit)

    def extend(self, wall: float, values) -> None:
        self.rows.extend((wall, value) for value in values)

    def values(self, now: float) -> np.ndarray:
        return np.array([value for wall, value in list(self.rows) if wall >= now - self.window])


class Flow:
    __slots__ = ("id", "start_us", "t", "src", "dst", "sport", "dport", "proto", "times", "senders", "rows",
                 "n", "fin", "event", "summary", "first_port", "received_wall", "initial_syn",
                 "normal_dns_query", "normal_gvcp_discovery", "service_evidence")

    def __init__(self, id_: int, p: dict, start_us: int, orientation: tuple):
        self.id, self.start_us, self.t = id_, start_us, float(p["timestamp"])
        self.src, self.dst, self.sport, self.dport, self.proto = orientation
        self.times, self.senders, self.rows = [], [], []
        self.n, self.fin, self.event, self.summary = 0, None, None, None
        self.first_port = p["src_port"]
        self.received_wall = p.get("_received_wall")
        self.initial_syn = bool(p.get("tcp_flag_syn") and not p.get("tcp_flag_ack"))
        self.normal_dns_query = normal_dns_query(p)
        self.normal_gvcp_discovery = normal_gvcp_discovery(p)
        self.service_evidence = {}
        self.add(p)

    def add(self, p: dict) -> None:
        self.n += 1
        if len(self.times) < K:
            self.times.append(float(p["timestamp"]))
            self.senders.append(p["src_ip"])
            self.rows.append(packet_row(p))

    def arrays(self) -> tuple[np.ndarray, np.ndarray, int]:
        """The first K packets as load_inputs lays them out: (pkt (K, F), dt (K,), count)."""
        pkt, dt = np.zeros((K, len(PACKET_FEATURES)), np.float32), np.zeros(K, np.float32)
        n = len(self.rows)
        pkt[:n, :-1] = np.array(self.rows, np.float32)
        pkt[:n, -1] = [float(s != self.senders[0]) for s in self.senders]
        dt[1:n] = np.clip(np.diff(self.times), 0.0, None)
        return pkt, dt, n


def flow_arrays(flows: "list[Flow]") -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Flow.arrays() for many flows in one pass: (pkt (N, K, F), dt (N, K), packets held (N,)).

    Per flow that is two allocations, a stack, a diff and a clip, and a flow needs it twice: when it is scored and
    when its summary becomes final.
    """
    n = len(flows)
    counts = np.fromiter((len(flow.rows) for flow in flows), np.int64, n)
    flow_at = np.repeat(np.arange(n), counts)
    packet_at = np.arange(len(flow_at)) - np.repeat(np.cumsum(counts) - counts, counts)
    pkt, times = np.zeros((n, K, len(PACKET_FEATURES)), np.float32), np.zeros((n, K))
    pkt[flow_at, packet_at, :-1] = np.array([row for flow in flows for row in flow.rows],
                                            np.float32).reshape(-1, len(PACKET_FEATURES) - 1)
    pkt[flow_at, packet_at, -1] = [sender != flow.senders[0] for flow in flows for sender in flow.senders]
    times[flow_at, packet_at] = [t for flow in flows for t in flow.times]
    dt = np.zeros((n, K), np.float32)
    dt[:, 1:] = np.clip(np.diff(times, axis=1), 0.0, None)     # the gap into the zero padding is negative: clipped
    return pkt, dt, counts


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
        self.total_packets = self.ipv6_skipped = self.other_protocol_skipped = self.timestamp_reversals = 0
        self.last_packet_time = None

    def add(self, p: dict) -> None:
        """One packet, as FlowGenerator.addPacket (and tools/live/StreamMeter.java) treats it."""
        self.total_packets += 1
        now = float(p["timestamp"])
        self.timestamp_reversals += int(self.last_packet_time is not None and now < self.last_packet_time)
        self.last_packet_time = now
        if p["is_ipv6"]:
            self.ipv6_skipped += 1
            return                                   # CICFlowMeter reads IPv4 only; no validated IPv6 feature contract
        if p["protocol"] not in (6, 17):
            self.other_protocol_skipped += 1
            return
        self.packets += 1
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
        # Retain the exact, head-averaged weights used by the encoder.  This only asks
        # MultiheadAttention to return its already-computed softmax; it does not change s.
        self.model.explain = True
        model.begin_day(capacity, capacity=capacity)
        self.links, self.neighbours = LinkRegistry(), OnlineNeighbours(NEIGHBOURS)
        self.position, self.open = 0, []
        # The ring of earlier events a neighbourhood reads. Their features stay on the model's device, where they
        # are gathered and attended; only what the host itself reads (who, when) is kept in numpy.
        self.features = {"h_split": torch.zeros((ring, 32), device=device),
                         **{c: torch.zeros(ring, device=device) for c in SIDE}}
        self.store = {"t_obs": np.zeros(ring), "sender": np.zeros(ring, np.int64), "receiver": np.zeros(ring, np.int64)}

    def queue_summary(self, links: np.ndarray, summaries: np.ndarray, times: np.ndarray) -> None:
        """Late 20-packet summaries, each applied at the first batch opening at or after its time."""
        if len(links):
            self.model._queued["flow"].append((torch.as_tensor(links, dtype=torch.int64, device=self.device),
                                               torch.as_tensor(summaries, dtype=torch.float32, device=self.device),
                                               torch.as_tensor(times, dtype=torch.float64, device=self.device)))

    def encode(self, inputs: dict, sender: np.ndarray, receiver: np.ndarray, t_obs: np.ndarray,
               late: "tuple | None" = None, explanation_limit: "int | None" = None
               ) -> tuple[np.ndarray, np.ndarray, list[dict]]:
        """encode_tensor(), with s brought to the host."""
        s, forward, attention = self.encode_tensor(inputs, sender, receiver, t_obs, late, explanation_limit)
        return s.cpu().numpy(), forward, attention

    @torch.no_grad()
    def encode_tensor(self, inputs: dict, sender: np.ndarray, receiver: np.ndarray, t_obs: np.ndarray,
                      late: "tuple | None" = None, explanation_limit: "int | None" = None
                      ) -> tuple[torch.Tensor, np.ndarray, list[dict]]:
        """s for events in stream order, left on the device for the heads.

        Input:  inputs {h_split (N, 32), dt_src, dt_dst, port_delta, dst_port_new, reversed (N,)}, sender and
                receiver node ids, t_obs, optionally late summaries already known (summary (N, 20), time (N,), send
                (N,) bool), queued straight after their event as training queues them after its batch; how many of
                the last events' attention rows to report (all when None)
        Output: (s (N, d_s), forward link id per event, the real neighbourhood-attention rows)
        """
        n = len(sender)
        # One upload per input; h_split normally arrives on the device already, straight from the flow encoder.
        inputs = {c: torch.as_tensor(inputs[c], dtype=torch.float32, device=self.device) for c in CONTEXT_INPUTS}
        forward = self.links.ids(sender, receiver).numpy()
        reverse = self.links.ids(receiver, sender).numpy()
        self.model.memory.grow(len(self.links))
        out, attention, at = [], [], 0
        while at < n:
            if self.position % self.batch == 0:
                self._open_batch(float(t_obs[at]))
            take = min(n - at, self.batch - self.position % self.batch)
            rows = slice(at, at + take)
            # Only the reported rows' weights leave the device: those of this chunk among the call's last few.
            explain = take if explanation_limit is None else max(0, min(take, explanation_limit - (n - at - take)))
            encoded, explained = self._encode(inputs, sender[rows], receiver[rows], t_obs[rows], forward[rows],
                                               reverse[rows], rows, explain)
            out.append(encoded)
            attention.extend(explained)
            if late is not None:
                send = np.arange(at, at + take)[late[2][rows]]
                self.queue_summary(forward[send], late[0][send], late[1][send])
            at += take
        encoded = torch.cat(out) if out else torch.zeros((0, self.model.out[-1].out_features), device=self.device)
        return encoded, forward, attention

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

    def _encode(self, inputs, sender, receiver, t_obs, forward, reverse, rows, explain) -> tuple[torch.Tensor, list[dict]]:
        """One chunk of a batch: `rows` of the device inputs, whose last `explain` attention rows are reported."""
        n, first, dev = len(sender), self.position, self.device
        found = np.full((n, NEIGHBOURS), -1, np.int64)
        senders, receivers = sender.tolist(), receiver.tolist()
        for i in range(n):          # read before push: a row sees earlier rows of its own batch, as offline
            got = self.neighbours.positions(senders[i], receivers[i])
            found[i, :len(got)] = got
            self.neighbours.push(senders[i], receivers[i], first + i)
        self.position = first + n
        positions = first + np.arange(n)
        found = np.where(found > (positions - self.ring)[:, None], found, -1)   # older than the ring: forgotten
        # The chunk enters the ring before any of it is read back, as when each event was stored on its own turn.
        slots = positions % self.ring
        self.store["t_obs"][slots], self.store["sender"][slots], self.store["receiver"][slots] = t_obs, sender, receiver
        placed = torch.as_tensor(slots, device=dev)
        for name in CONTEXT_INPUTS:
            self.features[name][placed] = inputs[name][rows]
        valid = found >= 0
        at = np.where(valid, found, 0) % self.ring
        age = np.where(valid, np.maximum(t_obs[:, None] - self.store["t_obs"][at], 0.0), 0.0)   # never from the future
        gathered = torch.as_tensor(at, device=dev)
        batch = {
            "inputs": {c: inputs[c][rows] for c in CONTEXT_INPUTS},
            "forward_link": torch.as_tensor(forward, device=dev), "reverse_link": torch.as_tensor(reverse, device=dev),
            "t_obs": torch.as_tensor(t_obs, dtype=torch.float64, device=dev),
            "neighbour_inputs": {c: self.features[c][gathered] for c in CONTEXT_INPUTS},
            "neighbour_valid": torch.as_tensor(valid, device=dev),
            "neighbour_age": torch.as_tensor(age, dtype=torch.float32, device=dev),
            "neighbour_role": torch.as_tensor((self.store["sender"][at] != sender[:, None]).astype(np.int64), device=dev),
        }
        s = self.model._encode(batch, None)
        explained = []
        if explain:
            weights = self.model.last_attention[n - explain:].cpu().numpy()
            for i in range(n - explain, n):
                share: dict[tuple[int, int], float] = {}
                for j in np.flatnonzero(valid[i]):
                    edge = (int(self.store["sender"][at[i, j]]), int(self.store["receiver"][at[i, j]]))
                    share[edge] = share.get(edge, 0.0) + float(weights[i - n + explain, j])
                explained.append({"sender": senders[i], "receiver": receivers[i],
                                  "attended": [{"sender": edge[0], "receiver": edge[1],
                                                "attention": round(value, 6)}
                                               for edge, value in sorted(share.items(), key=lambda item: -item[1])[:8]]})
        self.open.append((batch["forward_link"], batch["inputs"]["h_split"], batch["t_obs"]))
        return s, explained


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
                 forecaster: "Forecaster | None" = None, adaptive_thresholds: bool = False,
                 adaptive_warmup: int = 128, live_calibration_hours: float = 0.0,
                 calibration_db: "Path | None" = None, incident_db: "Path | None" = None,
                 incident_import_log: "Path | None" = None):
        if adaptive_thresholds and live_calibration_hours > 0:
            raise ValueError("fast adaptive thresholds cannot be combined with a gated live calibration window")
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
        self.adaptive = ({f: AdaptiveThreshold(t, self.heads.budgets[f], warmup=adaptive_warmup, seed=i)
                          for i, (f, t) in enumerate(self.heads.thresholds.items())
                          if t is not None and self.heads.budgets.get(f) is not None}
                         if adaptive_thresholds else {})
        calibrated = {f: t for f, t in self.heads.thresholds.items()
                      if t is not None and self.heads.budgets.get(f) is not None}
        self.live_calibration = (LiveScoreCalibration(
            calibration_db or CURRENT.parent / "runtime" / "calibration" / "detection.sqlite",
            calibrated, {f: self.heads.budgets[f] for f in calibrated},
            signature=checkpoint_signature([flow_encoder, detection_encoder, *heads]),
            duration_s=live_calibration_hours * 3600)
            if live_calibration_hours > 0 and calibrated else None)
        mode_path = (calibration_db or CURRENT.parent / "runtime" / "calibration" / "detection.sqlite").with_name(
            "detection-threshold-mode.json")
        self.threshold_mode = ThresholdMode(mode_path)
        self.incident_history = IncidentHistory(incident_db) if incident_db is not None else None
        if self.incident_history is not None and incident_import_log is not None:
            self.incident_history.import_log(incident_import_log)
        self.tracker, self.history, self.nodes = Tracker(self.budget), History(), NodeRegistry(capacity=1_000_000)
        self.scored, self.single, self.started = 0, 0, time.time()
        self.rate_lock = threading.Lock()
        self.rate_samples = deque()
        self.packet_queue: "queue.Queue | None" = None
        self.detections, self.incidents = deque(maxlen=200), deque(maxlen=MAX_RETURNED)
        self.pending_incident_flags = {family: {} for family in self.heads.families}
        self.incident_event_cache: dict[tuple[str, int, float], list[dict]] = {}
        self.attention = deque(maxlen=8)
        self.counts = {f: 0 for f in self.heads.families}
        self.lag, self.capture_lag = RecentDurations(), RecentDurations()
        self.delivery_lag, self.scoring_lag = RecentDurations(), RecentDurations()
        self.capture_state = {"mode": "tshark"}
        self.service_evidence = None
        self.future_timestamp_events = 0
        self.log: "list[dict] | None" = [] if keep else None       # every scored event, for the parity check
        self.pending_summaries: dict[int, tuple] = {}              # flow id -> (link, t_obs) of scored events
        # tools/live/detect_check.py only: {(flow_key, t): (summary, time)} known in advance, queued as training queues
        # them, to measure what the live summaries' lateness costs
        self.oracle = oracle
        self.forecaster = forecaster                               # the `live` world-model tag, when served

    def add(self, packet: dict) -> None:
        if self.service_evidence is not None:
            self.service_evidence.observe(packet)
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
        started = time.perf_counter()
        n = len(flows)
        pkt, dt, counts = flow_arrays(flows)
        x = np.zeros((n, len(X_COLUMNS)), np.float32)
        x[:, DURATION] = [(flow.fin - flow.t) * 1e6 if flow.fin is not None else OPEN for flow in flows]
        data = {"event_id": np.array([f.id for f in flows]), "t": np.array([f.t for f in flows]),
                "attack": np.zeros(n, bool), "x": x, "a": np.zeros((n, len(AGG_COLUMNS)), np.float32),
                "pkt": pkt, "dt": dt, "n_pkt": counts.astype(np.int16)}
        data = prepare(data, self.budget, self.side)
        # h and s stay on the model's device from here to the heads; only the probabilities come back to the host.
        h = flow_embedding_tensor(self.flow_model, normalise(data, self.stats)[0], self.device)
        t_obs = np.array([self._t_obs(f) for f in flows])

        inputs = {"h_split": h, **{c: np.zeros(n, np.float32) for c in SIDE}}
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
        s, links, attention = self.context.encode_tensor(inputs, sender, receiver, t_obs, late, explanation_limit=8)
        probability = self.heads(torch.cat([h, s], 1))

        names = self.nodes.ip_of
        for i, row in enumerate(attention, start=n - len(attention)):
            self.attention.append({"event_id": int(flows[i].id), "t_obs": float(t_obs[i]),
                                   "sender": int(row["sender"]), "receiver": int(row["receiver"]),
                                   "sender_ip": senders[i], "receiver_ip": receivers[i],
                                   "attended": [{**peer,
                                                 "edge": (names.get(peer["sender"], str(peer["sender"])) + " -> " +
                                                          names.get(peer["receiver"], str(peer["receiver"]))) }
                                                for peer in row["attended"]]})

        for i, flow in enumerate(flows):
            flow.event = "scored"
            self.pending_summaries[flow.id] = (int(links[i]), float(t_obs[i]))
        self.scored += n
        with self.rate_lock:
            now = time.time()
            self.rate_samples.append((now, n))
            while self.rate_samples and self.rate_samples[0][0] < now - 30:
                self.rate_samples.popleft()
        self.single += int((data["packets_seen"] == 1).sum())
        if self.service_evidence is not None:
            for flow in flows:
                flow.service_evidence = self.service_evidence.for_flow(flow)
        self._alerts(flows, sender, t_obs, probability)
        if wall is not None:
            # Packet timestamps can be ahead of the serving host's wall clock.
            # Never present a negative duration as processing latency; report
            # the skew separately so the clock problem remains visible.
            verdict_wall = time.time()
            observed_lag, capture_lag, skewed = latency_samples(
                verdict_wall, t_obs, np.array([flow.t for flow in flows]))
            self.future_timestamp_events += skewed
            self.lag.extend(verdict_wall, observed_lag.tolist())
            self.capture_lag.extend(verdict_wall, capture_lag.tolist())
            self.delivery_lag.extend(verdict_wall, [max(0.0, f.received_wall - f.t) for f in flows
                                                    if f.received_wall is not None])
            self.scoring_lag.extend(verdict_wall, [time.perf_counter() - started])
        if self.forecaster is not None:
            self.forecaster.add([f.id for f in flows], [f.t for f in flows], t_obs, senders, receivers,
                                inputs["dt_src"], inputs["dt_dst"], inputs["reversed"], s)
        if self.log is not None:
            h_rows, s_rows = h.cpu().numpy(), s.cpu().numpy()
            for i, flow in enumerate(flows):
                self.log.append({"flow_key": flow_key(flow), "t": flow.t, "t_obs": float(t_obs[i]),
                                 "sender_ip": senders[i], "h": h_rows[i], "s": s_rows[i],
                                 "probability": probability[i],
                                 **{c: float(inputs[c][i]) for c in SIDE},
                                 "sender": int(sender[i]), "receiver": int(receiver[i]), "link": int(links[i])})

    def _summaries(self) -> None:
        """Queue the 20-packet summaries that have become final, for events already scored."""
        keep, final, links, rows, times = [], [], [], [], []
        for flow in self.tracker.summaries:
            if flow.id not in self.pending_summaries:
                keep.append(flow)                    # its event is not scored yet
                continue
            final.append(flow)
        # One NumPy reduction per bounded chunk, rather than all aggregate
        # kernels once per completed flow (a large cost during a connection flood).
        for start in range(0, len(final), 512):
            chunk = final[start:start + 512]
            pkt, dt, counts = flow_arrays(chunk)
            summaries = _aggregates(pkt, dt, np.arange(K) < counts[:, None])
            for flow, count, summary in zip(chunk, counts.tolist(), summaries):
                link, t_obs = self.pending_summaries.pop(flow.id)
                flow_time = flow.t + float(summary[AGG_COLUMNS.index("iat_mean")]) * max(count - 1, 0)
                if self.log is not None:
                    self.log.append({"summary_of": flow_key(flow), "t": flow.t, "summary": summary,
                                     "flow_time": flow_time, "known_at": self.tracker.clock})
                if flow_time > t_obs + 1e-6 and self.oracle is None:
                    links.append(link), rows.append(summary), times.append(flow_time)
        self.tracker.summaries = keep
        if links:
            self.context.queue_summary(np.array(links), np.stack(rows), np.array(times))
        if len(self.pending_summaries) > 2_000_000:              # ponytail: flows that never finalise are dropped
            self.pending_summaries = dict(list(self.pending_summaries.items())[-1_000_000:])

    def _alerts(self, flows, sender, t_obs, probability) -> None:
        use_live = self.threshold_mode.status(self._live_ready())["effective"] == "live"
        opened_incidents, batch_events = [], []
        batch_keys = np.unique(sender).tolist()
        for j, family in enumerate(self.heads.families):
            adaptive = self.adaptive.get(family)
            threshold = adaptive.threshold() if adaptive is not None else self.heads.thresholds.get(family)
            if use_live and self.live_calibration is not None and family in self.live_calibration.baselines and \
                    self.live_calibration.status(family)["ready"]:
                threshold = self.live_calibration.threshold(family)
            if threshold is None:
                continue
            self.emitters[family].threshold = threshold
            hit = np.flatnonzero(probability[:, j] >= threshold)
            self.counts[family] += len(hit)
            for i in hit[-20:]:
                flow = flows[i]
                self.detections.append({"family": family, "probability": round(float(probability[i, j]), 5),
                                        "threshold": threshold, "t_obs": float(t_obs[i]), "src": flow.src,
                                        "dst": flow.dst, "src_port": flow.sport, "dst_port": flow.dport,
                                        "protocol": flow.proto, "sender": flow.senders[0] if flow.senders else None})
            pending = self.pending_incident_flags[family]
            linked_events: list[dict] = []

            def on_step(index, key, value, observed_at, incident_id, opened_at):
                if value < threshold:
                    pending.pop(key, None)
                    return
                flow = flows[index]
                row = {"family": family, "event_id": int(flow.id), "t_obs": observed_at,
                       "src": flow.src, "dst": flow.dst, "src_port": flow.sport, "dst_port": flow.dport,
                       "protocol": flow.proto, "sender_ip": flow.senders[0] if flow.senders else flow.src,
                       "score": value, "threshold": float(threshold),
                       **getattr(flow, "service_evidence", {})}
                if incident_id is None:
                    pending.setdefault(key, deque(maxlen=2)).append(row)
                    return
                for related in [*pending.pop(key, ()), row]:
                    linked_events.append({**related, "incident": incident_id, "opened_at": opened_at})

            emitter = self.emitters[family]
            prunes_before = emitter.prunes
            for incident in emitter.push_batch(torch.as_tensor(sender), torch.as_tensor(probability[:, j]),
                                               torch.as_tensor(t_obs), on_step=on_step):
                incident["family"] = family
                self.incidents.append(incident)
                opened_incidents.append(incident)
                print(json.dumps({"incident": incident}, default=str), flush=True)
            # Only this batch's senders can have interrupted a run. Scan the
            # full pending table only when the emitter actually evicted keys.
            for key in list(pending) if emitter.prunes != prunes_before else batch_keys:
                if key not in emitter.run:
                    pending.pop(key, None)
            if linked_events:
                if self.incident_history is not None:
                    batch_events.extend(linked_events)
                else:
                    for row in linked_events:
                        key = (family, row["incident"], row["opened_at"])
                        self.incident_event_cache.setdefault(key, []).append(row)
            if adaptive is not None:
                adaptive.observe(probability[:, j])       # affects the next batch; never judge a row against itself
        if self.incident_history is not None:
            self.incident_history.record_batch(opened_incidents, batch_events)
        if self.live_calibration is not None:
            # Written by the calibration's own thread: its database is no part of a verdict's latency.
            scores, times = probability.tolist(), np.asarray(t_obs, np.float64).tolist()
            self.live_calibration.submit([
                (f"{flow.t:.6f}|{flow_key(flow)}", times[i], dict(zip(self.heads.families, scores[i])))
                for i, flow in enumerate(flows)])

    def incident_events(self, family: str, incident: int, opened_at: float) -> list[dict]:
        if self.incident_history is not None:
            return self.incident_history.events(family, incident, opened_at)
        return self.incident_event_cache.get((family, incident, opened_at), [])

    def incident_events_body(self, family: str, incident: int, opened_at: float) -> bytes:
        """GET /incident-events: the linked events, bounded (IncidentHistory.events_json)."""
        if self.incident_history is not None:
            return self.incident_history.events_json(family, incident, opened_at).encode()
        events = self.incident_event_cache.get((family, incident, opened_at), [])
        return json.dumps({"events": events, "total": len(events), "truncated": False}).encode()

    def _live_ready(self) -> bool:
        return self.live_calibration is not None and bool(self.live_calibration.baselines) and all(
            self.live_calibration.status(family)["ready"] for family in self.live_calibration.baselines)

    def _threshold_status(self, family: str, checkpoint: float) -> dict:
        adaptive = self.adaptive.get(family)
        result = (adaptive.status() if adaptive is not None else
                  {"threshold": checkpoint, "baseline_threshold": checkpoint, "adaptive": False,
                   "false_alarm_budget": self.heads.budgets.get(family)})
        result["threshold_source"] = "fast_adaptive" if adaptive is not None and result.get("adaptive_ready") else "checkpoint_validation"
        result["probability_calibration"] = "checkpoint_unchanged"
        if self.live_calibration is not None and family in self.live_calibration.baselines:
            live = self.live_calibration.status(family)
            result["live_calibration"] = live
            if live["ready"] and self.threshold_mode.requested() == "live" and self._live_ready():
                result["threshold"] = self.live_calibration.threshold(family)
                result["threshold_source"] = "live_unlabeled_score_tail"
        return result

    def status(self) -> dict:
        measured = time.time()
        lag, capture_lag, delivery_lag, scoring_lag = (samples.values(measured) for samples in (
            self.lag, self.capture_lag, self.delivery_lag, self.scoring_lag))
        now = self.tracker.clock
        opened = list(self.incidents)
        active = [incident for incident in opened
                  if self.emitters[incident["family"]].open_until.get(incident["key"], float("-inf")) >= now]
        recent = (self.incident_history.recent() if self.incident_history is not None else
                  [incident for incident in opened if incident["t"] >= now - WINDOW_S])
        active_by_family = {f: sum(until >= now for until in emitter.open_until.values())
                            for f, emitter in self.emitters.items()}
        with self.rate_lock:
            wall = time.time()
            while self.rate_samples and self.rate_samples[0][0] < wall - 30:
                self.rate_samples.popleft()
            events_per_second = sum(count for _, count in self.rate_samples) / max(1.0, min(30.0, wall - self.started))
        return {"status": "RUNNING", "clock": self.tracker.clock, "packets": self.tracker.packets,
                "total_ip_packets": self.tracker.total_packets,
                "ipv6_packets_excluded": self.tracker.ipv6_skipped,
                "other_ipv4_protocol_packets_excluded": self.tracker.other_protocol_skipped,
                "packet_timestamp_reversals": self.tracker.timestamp_reversals,
                "open_flows": len(self.tracker.current), "events_scored": self.scored,
                "events_per_second": round(events_per_second, 3),
                "packet_queue_depth": self.packet_queue.qsize() if self.packet_queue is not None else 0,
                "inference_threads": torch.get_num_threads(), "device": str(self.device),
                "capture": dict(self.capture_state),
                "latency_window_s": LATENCY_WINDOW_S,
                "latency_stages_s": {name: {"median": round(float(np.quantile(values, .5)), 4),
                                            "p50": round(float(np.quantile(values, .5)), 4),
                                            "p90": round(float(np.quantile(values, .9)), 4),
                                            "p99": round(float(np.quantile(values, .99)), 4)}
                                     for name, values in (("packet_delivery", delivery_lag),
                                                          ("scoring_batch", scoring_lag)) if len(values)},
                "scored_with_one_packet": self.single,
                "uptime_s": round(time.time() - self.started, 1),
                "latency_after_t_obs_s": None if not len(lag) else {
                    "median": round(float(np.median(lag)), 4), "p50": round(float(np.median(lag)), 4),
                    "p90": round(float(np.quantile(lag, 0.9)), 4), "p99": round(float(np.quantile(lag, 0.99)), 4)},
                "latency_from_first_packet_s": None if not len(capture_lag) else {
                    "median": round(float(np.median(capture_lag)), 4),
                    "p50": round(float(np.median(capture_lag)), 4),
                    "p90": round(float(np.quantile(capture_lag, 0.9)), 4),
                    "p99": round(float(np.quantile(capture_lag, 0.99)), 4)},
                "future_timestamp_events": self.future_timestamp_events,
                "budget_s": self.budget,
                "threshold_mode": self.threshold_mode.status(self._live_ready()),
                "thresholds": {f: self._threshold_status(f, t) for f, t in self.heads.thresholds.items()},
                "detections_by_family": self.counts,
                # Human-facing reporting is incident based. Raw detections are retained for diagnostics and API
                # compatibility, but only an emitter incident has passed threshold, persist-3 and the quiet-gap rule.
                "incidents_by_family": active_by_family,
                "incidents_opened_by_family": {f: emitter.incidents for f, emitter in self.emitters.items()},
                "recent_detections": list(self.detections), "incidents": active,
                "recent_incidents": recent, "incident_history_window_s": WINDOW_S,
                "incident_history_limit": MAX_RETURNED,
                "attention": list(self.attention)}


def reversed_of_flow(flow: Flow) -> float:
    """ingest.build.events._mark_reversed for one flow: 1 when the record runs server -> client, -1 when unknown."""
    first = flow.rows[0]
    if first[PACKET_FEATURES.index("tcp_flag_syn")] == 1 and first[PACKET_FEATURES.index("tcp_flag_ack")] == 0:
        return 0.0 if flow.senders[0] == flow.src and flow.first_port == flow.sport else 1.0
    return 1.0 if flow.sport < flow.dport else 0.0 if flow.sport > flow.dport else -1.0


def flow_key(flow: Flow) -> str:
    return canonical_flow_key(flow.src, flow.sport, flow.dst, flow.dport, flow.proto)


def tshark_command(source: str, interface: bool) -> list[str]:
    """ingest's tshark command, on a live interface or a file ('-' is stdin), line-buffered, state reset per chunk."""
    command = _make_tshark_command(Path(source))
    at = command.index("-r")
    command[at:at + 2] = ["-i", source] if interface else ["-r", source]
    return [*command, "-l", "-M", str(DEFAULT_TSHARK_CHUNK_PACKETS)]


def read_packets(command: list[str], out: "queue.Queue", capture=None) -> None:
    """tshark's lines as packet dicts, parsed exactly as ingest parses them; None at the end."""
    env = {**os.environ, "MALLOC_ARENA_MAX": "1"}
    errors = tempfile.TemporaryFile("w+")
    if capture is not None:
        command = list(command)
        at = command.index("-i")
        command[at:at + 2] = ["-r", "-"]
    process = subprocess.Popen(command, stdin=subprocess.PIPE if capture else None,
                               stdout=subprocess.PIPE, stderr=errors, env=env)
    stop = threading.Event()
    def pump():
        try:
            capture.pump(process.stdin, stop)
        except (OSError, BrokenPipeError) as exc:
            capture.state["error"] = str(exc)
            print(f"immediate capture stopped: {exc}", file=sys.stderr, flush=True)
        finally:
            process.stdin.close()
            capture.close()
    if capture:
        threading.Thread(target=pump, daemon=True).start()
    with io.TextIOWrapper(process.stdout) as lines:
        for line in lines:
            received = time.time()
            values = line.rstrip("\r\n").split("\t")
            if len(values) != len(TSHARK_FIELDS):
                continue
            packet = live_packet(values)
            if packet is not None:
                packet["_received_wall"] = received
                out.put(packet)
    stop.set()
    if process.wait() != 0:
        errors.seek(0)
        print(f"tshark exited with {process.returncode}: {errors.read()[-2000:]}", file=sys.stderr, flush=True)
    out.put(None)
    errors.close()


def run(detector: Detector, packets: "queue.Queue", live: bool, grace: float) -> None:
    """Feed packets, score whatever is ready, until the input ends."""
    while True:
        started, ended = time.monotonic(), False
        # Amortize model calls when capture is ahead, without imposing a large
        # wait on a quiet link. Keep the batch bounded so the HTTP status stays responsive.
        # A scoring pass has a fixed cost whatever it scores, so the further behind, the more one pass takes.
        backlog = packets.qsize()
        batch_seconds = 0.1 if backlog > BATCH_PACKETS else 0.02 if backlog > 256 else 0.005
        limit = 4 * BATCH_PACKETS if backlog > BATCH_PACKETS else BATCH_PACKETS
        processed = 0
        while processed < limit and time.monotonic() - started < batch_seconds:
            try:
                packet = packets.get(timeout=0.002)
            except queue.Empty:
                break
            if packet is None:
                ended = True
                break
            detector.add(packet)
            processed += 1
        if live and packets.empty():               # do not score a flow ahead of packets still waiting in the queue
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
    parser.add_argument("--adaptive-thresholds", action="store_true",
                        help="learn a higher per-family live quantile after warm-up; incompatible with --live-calibration-hours")
    parser.add_argument("--adaptive-warmup", type=int, default=128,
                        help="events per family collected before adaptive thresholds activate")
    parser.add_argument("--live-calibration-hours", type=float, default=0.0,
                        help="collect this many continuous hours of unlabeled traffic before serving threshold-only live quantiles; checkpoint scores stay unchanged")
    parser.add_argument("--calibration-db", type=Path, default=None,
                        help="persistent live score database; defaults to artifacts/runtime/calibration/detection.sqlite")
    parser.add_argument("--incident-db", type=Path, default=None,
                        help="persist the last three hours of opened incidents across detector restarts")
    parser.add_argument("--incident-import-log", type=Path, default=None,
                        help="one-time backfill from an earlier JSON-lines incident log")
    parser.add_argument("--capacity", type=int, default=250_000, help="link-memory slots")
    parser.add_argument("--grace", type=float, default=0.02,
                        help="seconds a quiet wire waits for tshark's output before closing an observation window")
    parser.add_argument("--device", default="cuda", help="Model device (default: cuda; explicit cpu override)")
    parser.add_argument("--threads", type=int, default=1,
                        help="CPU inference threads (default: 1 to avoid small-call contention with forecasting)")
    parser.add_argument("--port", type=int, default=8902)
    parser.add_argument("--capture-mode", choices=("auto", "tshark", "immediate"), default="auto",
                        help="Windows auto uses Npcap immediate delivery; tshark selects the legacy capture path")
    parser.add_argument("--once", action="store_true", help="process the file, print the status, and exit")
    parser.add_argument("--json-out", type=Path, default=None,
                        help="with --once, write the full offline status and incident-linked events to this JSON file")
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
    from models.serving.device import checked_device, device_description
    try:
        args.device = checked_device(args.device)
    except (ValueError, RuntimeError) as error:
        parser.error(str(error))
    if args.threads < 1:
        parser.error("--threads must be positive")
    torch.set_num_threads(args.threads)
    if args.json_out is not None and not args.once:
        parser.error("--json-out requires --once")
    if args.adaptive_thresholds and args.live_calibration_hours > 0:
        parser.error("--adaptive-thresholds cannot be combined with --live-calibration-hours")
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
                        device=args.device, forecaster=forecaster, adaptive_thresholds=args.adaptive_thresholds,
                        adaptive_warmup=args.adaptive_warmup, live_calibration_hours=args.live_calibration_hours,
                        calibration_db=args.calibration_db, incident_db=args.incident_db,
                        incident_import_log=args.incident_import_log)
    packets: queue.Queue = queue.Queue(maxsize=200_000)
    detector.packet_queue = packets
    print(f"Detection: Running in {device_description(detector.device)}", flush=True)
    live = args.interface is not None or args.pcap == "-"     # a pipe from dumpcap is the wire too
    command = tshark_command(args.interface or args.pcap, args.interface is not None)
    if shutil.which(command[0]) is None:
        parser.error(f"{command[0]} is required to read the capture")
    capture = None
    if args.interface and args.capture_mode != "tshark" and (os.name == "nt" or args.capture_mode == "immediate"):
        try:
            from models.serving.npcap_capture import NpcapCapture
            capture = NpcapCapture(args.interface, command[0])
            detector.capture_state = capture.state
        except (OSError, AttributeError) as exc:
            if args.capture_mode == "immediate":
                parser.error(f"immediate capture unavailable: {exc}")
            detector.capture_state["fallback_reason"] = str(exc)
            print(f"immediate capture unavailable; using tshark: {exc}", file=sys.stderr, flush=True)
    if args.interface:
        detector.service_evidence = ServiceEvidence()
        detector.service_evidence.start()
    threading.Thread(target=read_packets, args=(command, packets, capture), daemon=True).start()
    served = ", ".join(f"{f} {t:.4g} (budget {detector.heads.budgets[f]:g})" if t is not None else f"{f} none"
                       for f, t in detector.heads.thresholds.items())
    print(f"detection: {len(heads)} heads; thresholds: {served}", flush=True)
    if detector.adaptive:
        print(f"adaptive thresholds: enabled; {args.adaptive_warmup:,} event warm-up; committed thresholds are floors",
              flush=True)
    if args.once:
        run(detector, packets, live, args.grace)
        if detector.live_calibration is not None:
            detector.live_calibration.flush()
        status = detector.status()
        if args.json_out is not None:
            status["offline_incidents"] = [
                {**incident, "related_events": detector.incident_events(
                    incident["family"], incident["incident"], incident["t"])}
                for incident in status["recent_incidents"]
            ]
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(status, default=str), encoding="utf-8")
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
            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/")
            if path == "/forecast" and forecaster is not None:
                body = json.dumps(forecaster.payload, default=str).encode()
            elif path in ("/detections", "/health"):
                body = json.dumps(detector.status(), default=str).encode()
            elif path == "/incident-events":
                try:
                    args = parse_qs(parsed.query)
                    family = args["family"][0]
                    incident = int(args["incident"][0])
                    opened_at = float(args["opened_at"][0])
                    if not family or incident < 1 or not np.isfinite(opened_at):
                        raise ValueError("invalid incident identity")
                except (KeyError, IndexError, ValueError):
                    self.send_error(400, "family, incident and opened_at are required")
                    return
                body = detector.incident_events_body(family, incident, opened_at)
            elif path == "/threshold-mode":
                body = json.dumps(detector.threshold_mode.status(detector._live_ready())).encode()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path.rstrip("/") != "/threshold-mode":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 128:
                    raise ValueError("invalid request size")
                mode = json.loads(self.rfile.read(length))["mode"]
                result = detector.threshold_mode.set(mode, detector._live_ready())
                status = 200
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                result, status = {"error": str(error)}, 409
            body = json.dumps(result).encode()
            self.send_response(status)
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
