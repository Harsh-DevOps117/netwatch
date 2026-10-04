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


def flow_evidence(flows, packets, packet_map, wanted=None) -> dict:
    """Service context for the complete flows of a capture window, keyed by flow_uid.

    Input:  the window's flows, packets and flow-packet map as pandas frames (the layout Chain.ingest writes), and
            optionally the flow_uids to report
    Output: flow_uid -> the flow's endpoints, plus the fields `ServiceEvidence.for_flow` gives a live flow when the
            flow's packets are in the window

    A live flow is corroborated against the OS socket table. A complete flow is older than its socket, so here a TCP
    flow counts as established only when both of its endpoints sent payload: a bare SYN, a refused connection or a
    handshake that carried nothing does not. A flow with no packets in the window gets no evidence and fails open.
    """
    ends = flows.drop_duplicates("flow_uid").set_index("flow_uid")[["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol"]]
    if wanted is not None:
        ends = ends[ends.index.isin(set(wanted))]
    out = {uid: {"src": str(src), "dst": str(dst), "src_port": int(sport), "dst_port": int(dport), "protocol": int(proto)}
           for uid, (src, sport, dst, dport, proto) in zip(ends.index, ends.fillna(0).to_numpy())}
    if "flow_uid" not in packets.columns:
        packets = packets.merge(packet_map[["frame_no", "flow_uid"]], on="frame_no")
    # Packets per source per second over the whole window, as `ServiceEvidence.observe` counts them on the wire.
    rate = packets.groupby(["src_ip", packets["timestamp"].astype("int64")]).size().to_dict()
    mapped = packets[packets["flow_uid"].isin(out.keys())].sort_values("timestamp", kind="stable")
    for uid, group in mapped.groupby("flow_uid", sort=False):
        flow, first = out[uid], group.iloc[0].to_dict()
        payload = group.groupby("src_ip")["payload_len"].sum()
        second = int(first["timestamp"])
        flow.update({
            "established_connection": bool(flow["protocol"] == 6 and payload.get(flow["src"], 0) > 0
                                           and payload.get(flow["dst"], 0) > 0),
            "normal_dns_query": normal_dns_query(first),
            "normal_gvcp_discovery": normal_gvcp_discovery(first),
            "source_packets_per_second": int(max(rate.get((first["src_ip"], at), 0) for at in (second - 1, second))),
            "service_evidence_version": 1})
    return out
