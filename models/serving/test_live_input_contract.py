"""Small regressions for live input order, direction and latency reporting."""
import unittest

import numpy as np

from ingest.sources.packets import PACKET_COLUMNS, TSHARK_FIELDS, _parse_packet_row
from models.data.inputs import PACKET_FEATURES, PACKET_SOURCE_COLUMNS
from models.serving.detect_live import (K, Flow, Tracker, flow_arrays, latency_samples, live_packet,
                                        reversed_of_flow)


def packet(src, dst, sport, dport, timestamp, syn=0, ack=0):
    value = {name: 0 for name in PACKET_SOURCE_COLUMNS}
    value.update(src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol=6,
                 timestamp=timestamp, is_ipv6=False, ip_flag_mf=0, ip_frag_offset=0,
                 tcp_flag_syn=syn, tcp_flag_ack=ack)
    return value


def tshark_line(**fields):
    """One tshark output line's values: a TCP packet, with the named fields replaced."""
    line = {"frame.time_epoch": "1791043218.671878", "ip.src": "10.0.0.2", "ip.dst": "10.0.0.9",
            "tcp.srcport": "50123", "tcp.dstport": "443", "ip.proto": "6", "frame.len": "74", "frame.number": "17",
            "ip.ttl": "64", "tcp.window_size": "64240", "tcp.flags.syn": "True", "tcp.flags.ack": "False",
            "tcp.flags.fin": "False", "tcp.flags.reset": "False", "tcp.flags.push": "False",
            "tcp.flags.urg": "False", "ip.flags.df": "True", "ip.flags.mf": "False", "ip.frag_offset": "0",
            "tcp.payload": "474554202f20485454502f312e31", **fields}
    return [line.get(name, "") for name in TSHARK_FIELDS]


def ingest_packet(values):
    """What the live reader built before live_packet: ingest's own parser on the line."""
    raw = dict(zip(TSHARK_FIELDS, values))
    if not ((raw.get("ip.src") and raw.get("ip.dst")) or (raw.get("ipv6.src") and raw.get("ipv6.dst"))):
        return None
    row = _parse_packet_row(raw)
    return None if row is None else dict(zip(PACKET_COLUMNS, row))


class LiveInputContractTest(unittest.TestCase):
    def test_live_packet_is_ingests_packet_row(self):
        udp = {"tcp.srcport": "", "tcp.dstport": "", "udp.srcport": "5353", "udp.dstport": "53", "ip.proto": "17",
               "tcp.window_size": "", "tcp.payload": "", "udp.payload": "12:34:01:00:00:01"}
        ipv6 = {"ip.src": "", "ip.dst": "", "ipv6.src": "2001:db8::1", "ipv6.dst": "2001:db8::2", "ip.proto": "",
                "ipv6.nxt": "6", "ip.ttl": "", "ipv6.hlim": "57"}
        lines = [tshark_line(), tshark_line(**udp), tshark_line(**ipv6),
                 tshark_line(**{"tcp.flags.syn": "1", "tcp.flags.ack": "0", "tcp.flags.fin": " TRUE ",
                                "ip.flags.mf": "1", "ip.frag_offset": "185",
                                "tcp.analysis.retransmission": "1"}),          # older tshark; fragment; flag present
                 tshark_line(**{"tcp.srcport": "http", "ip.ttl": "x", "tcp.window_size": "",
                                "ip.frag_offset": ""}),                        # optional fields that will not parse
                 tshark_line(**{"tcp.payload": "4g", "udp.payload": "ff"}),       # hex that will not parse
                 tshark_line(**{"tcp.payload": "ab" * 400}),                      # longer than the kept bytes
                 tshark_line(**{"ip.src": "", "ipv6.src": "2001:db8::1", "ipv6.dst": "2001:db8::2"}),
                 tshark_line(**{"ip.dst": ""}), tshark_line(**{"ip.src": "", "ip.dst": ""}),   # no endpoint pair
                 tshark_line(**{"frame.len": ""}), tshark_line(**{"frame.number": "x"}),       # required fields
                 tshark_line(**{"frame.time_epoch": ""})]
        dropped = 0
        for values in lines:
            got, want = live_packet(values), ingest_packet(values)
            self.assertEqual(got, want, values)
            dropped += got is None
            if got is not None:
                self.assertEqual(list(got), PACKET_COLUMNS)
                self.assertEqual({name: type(got[name]) for name in got}, {name: type(want[name]) for name in want})
        self.assertEqual(dropped, 5)

    def test_batched_arrays_are_each_flows_own(self):
        flows = []
        for i in range(K + 3):
            first = packet("192.0.2.10", "198.51.100.5", 50000 + i, 443, 100.0 + i, syn=1)
            flow = Flow(i, first, 0, (first["src_ip"], first["dst_ip"], first["src_port"], 443, 6))
            for j in range(i):                           # one packet up to more than the K a flow keeps
                reply = packet("198.51.100.5", "192.0.2.10", 443, 50000 + i, 100.0 + i + (j + 1) * .003, ack=j % 2)
                reply["length"], reply["ip_frag_offset"] = 60 + j, j % 3
                flow.add(reply)
            flows.append(flow)
        pkt, dt, counts = flow_arrays(flows)
        for i, flow in enumerate(flows):
            values, gaps, count = flow.arrays()
            np.testing.assert_array_equal(pkt[i], values)
            np.testing.assert_array_equal(dt[i], gaps)
            self.assertEqual(counts[i], count)
        self.assertEqual(flow_arrays([])[0].shape, (0, K, len(PACKET_FEATURES)))

    def test_packet_order_and_forward_backward_direction(self):
        client = packet("192.0.2.10", "198.51.100.5", 50000, 443, 100.0, syn=1)
        server = packet("198.51.100.5", "192.0.2.10", 443, 50000, 100.001, ack=1)
        orientation = (client["src_ip"], client["dst_ip"], client["src_port"], client["dst_port"], 6)
        flow = Flow(0, client, 100_000_000, orientation)
        flow.add(server)
        values, gaps, count = flow.arrays()
        self.assertEqual(count, 2)
        self.assertEqual(PACKET_FEATURES[-1], "direction")
        self.assertEqual(values[:2, PACKET_FEATURES.index("direction")].tolist(), [0.0, 1.0])
        self.assertEqual(values[:2, PACKET_FEATURES.index("tcp_flag_syn")].tolist(), [1.0, 0.0])
        self.assertAlmostEqual(float(gaps[1]), 0.001, places=5)
        self.assertEqual(reversed_of_flow(flow), 0.0)
        reverse_record = Flow(1, client, 100_000_000,
                              (server["src_ip"], server["dst_ip"], server["src_port"], server["dst_port"], 6))
        self.assertEqual(reversed_of_flow(reverse_record), 1.0)

    def test_future_packet_timestamp_is_counted_not_negative_latency(self):
        observed, capture, skewed = latency_samples(100.0, np.array([100.08, 99.9]),
                                                      np.array([100.07, 99.8]))
        self.assertEqual(observed[0], 0.0)
        self.assertAlmostEqual(observed[1], 0.1)
        self.assertEqual(capture[0], 0.0)
        self.assertEqual(skewed, 1)

    def test_excluded_packets_and_timestamp_order_are_visible(self):
        tracker = Tracker(0.01)
        ipv6 = packet("2001:db8::1", "2001:db8::2", 1234, 443, 100.1)
        ipv6["is_ipv6"] = True
        other = packet("192.0.2.10", "198.51.100.5", 0, 0, 100.0)
        other["protocol"] = 1
        eligible = packet("192.0.2.10", "198.51.100.5", 1234, 443, 100.2)
        for value in (ipv6, other, eligible):
            tracker.add(value)
        self.assertEqual((tracker.total_packets, tracker.ipv6_skipped,
                          tracker.other_protocol_skipped, tracker.packets,
                          tracker.timestamp_reversals), (3, 1, 1, 1, 1))


if __name__ == "__main__":
    unittest.main()
