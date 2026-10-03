"""Capture-only service context; never used as a model feature or threshold.

An OS socket snapshot corroborates TCP responses. A bounded per-source packet
counter makes suppression ineligible during bursts. Missing/stale evidence fails open.
"""
from __future__ import annotations

import struct
import ipaddress
import threading
import time
from collections import OrderedDict

import psutil


def normal_gvcp_discovery(packet: dict) -> bool:
    """Only the observed eight-byte DISCOVERY_CMD to limited LAN broadcast."""
    if packet.get("protocol") != 17 or packet.get("dst_port") != 3956:
        return False
    try:
        source = ipaddress.ip_address(packet.get("src_ip", ""))
    except ValueError:
        return False
    payload = packet.get("payload", b"")
    return (packet.get("protocol") == 17 and packet.get("dst_port") == 3956 and
            packet.get("dst_ip") == "255.255.255.255" and source.version == 4 and source.is_private and
            not source.is_loopback and not packet.get("ip_flag_mf") and not packet.get("ip_frag_offset") and
            packet.get("payload_len", len(payload)) == 8 and len(payload) == 8 and
            payload[:6] == b"\x42\x01\x00\x02\x00\x00" and payload[6:] != b"\x00\x00")


def normal_dns_query(packet: dict) -> bool:
    if packet.get("protocol") != 17 or packet.get("dst_port") != 53:
        return False
    payload = packet.get("payload", b"")
    if len(payload) < 12 or not 12 <= packet.get("payload_len", len(payload)) <= 512:
        return False
    _, flags, questions, answers, authority, additional = struct.unpack("!6H", payload[:12])
    if flags & 0xfa0f or questions != 1 or answers or authority or additional > 2 or \
            packet.get("ip_flag_mf") or packet.get("ip_frag_offset"):
        return False
    # Parse a complete, uncompressed question. TXT/ANY and truncated questions
    # remain visible rather than being treated as routine resolution.
    at = 12
    while at < len(payload) and payload[at]:
        width = payload[at]
        if width > 63 or at + 1 + width >= len(payload):
            return False
        at += 1 + width
    if at + 5 > len(payload):
        return False
    kind, cls = struct.unpack("!HH", payload[at + 1:at + 5])
    return cls == 1 and kind in (1, 5, 12, 28, 33, 64, 65)


class ServiceEvidence:
    def __init__(self):
        self.connections = frozenset()
        self.sampled_at = float("-inf")
        self.sources = OrderedDict()

    def refresh(self, connections=None, now=None):
        # Build a new immutable snapshot; readers never wait for OS enumeration.
        connections = psutil.net_connections(kind="tcp") if connections is None else connections
        listening = {c.laddr.port for c in connections if c.status == psutil.CONN_LISTEN and c.laddr}
        snapshot = frozenset((c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
                             for c in connections if c.status == psutil.CONN_ESTABLISHED and c.laddr and c.raddr
                             and c.laddr.port not in listening)
        self.connections, self.sampled_at = snapshot, time.time() if now is None else now

    def start(self):
        def sample():
            while True:
                try:
                    self.refresh()
                except (psutil.Error, OSError):
                    self.connections, self.sampled_at = frozenset(), float("-inf")
                time.sleep(1)
        threading.Thread(target=sample, daemon=True).start()

    def observe(self, packet):
        second = int(packet["timestamp"])
        src = packet["src_ip"]
        buckets = self.sources.pop(src, {})
        buckets = {t: n for t, n in buckets.items() if t >= second - 1}
        buckets[second] = buckets.get(second, 0) + 1
        self.sources[src] = buckets
        if len(self.sources) > 100_000:
            self.sources.popitem(last=False)

    def for_flow(self, flow):
        now = time.time()
        valid = 0 <= now - self.sampled_at <= 3
        forward = (flow.src, flow.sport, flow.dst, flow.dport)
        reverse = (flow.dst, flow.dport, flow.src, flow.sport)
        established = flow.proto == 6 and valid and (forward in self.connections or reverse in self.connections)
        # A bare SYN starts a connection and cannot be an established response.
        established = established and not flow.initial_syn
        source = flow.senders[0]
        buckets = self.sources.get(source, {})
        peak = max((n for t, n in buckets.items() if t >= int(flow.t) - 1), default=0)
        return {"established_connection": bool(established),
                "normal_dns_query": flow.normal_dns_query,
                "normal_gvcp_discovery": bool(getattr(flow, "normal_gvcp_discovery", False)),
                "source_packets_per_second": peak, "service_evidence_version": 1}
