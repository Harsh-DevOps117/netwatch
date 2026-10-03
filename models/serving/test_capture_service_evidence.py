"""Capture framing and adversarial regressions for operator-only evidence."""
import struct
import queue
import shutil
import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from models.serving.npcap_capture import pcap_header, pcap_record, resolve_interface
from models.serving.service_evidence import ServiceEvidence, normal_dns_query, normal_gvcp_discovery


class CaptureEvidenceTest(unittest.TestCase):
    def test_gvcp_discovery_does_not_allow_control_commands_or_unicast(self):
        packet = {"src_ip": "192.168.0.152", "dst_ip": "255.255.255.255", "protocol": 17,
                  "dst_port": 3956, "payload": bytes.fromhex("4201000200000001"), "payload_len": 8}
        self.assertTrue(normal_gvcp_discovery(packet))
        for payload in (bytes.fromhex("4201008200000001"), bytes.fromhex("4201000400000001"), b"arbitrary"):
            self.assertFalse(normal_gvcp_discovery({**packet, "payload": payload}))
        self.assertFalse(normal_gvcp_discovery({**packet, "src_ip": "8.8.8.8"}))
        self.assertFalse(normal_gvcp_discovery({**packet, "dst_ip": "192.168.0.153"}))

    @unittest.skipUnless(shutil.which("tshark"), "tshark is required for parser parity")
    def test_streamed_pcap_matches_ingest_file_features(self):
        from models.serving.detect_live import read_packets, tshark_command
        dns = struct.pack("!6H", 1, 0x100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        udp = struct.pack("!4H", 51000, 53, 8 + len(dns), 0) + dns
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                         socket.inet_aton("192.0.2.10"), socket.inet_aton("192.0.2.1"))
        checksum = sum(struct.unpack("!10H", ip))
        checksum = (checksum & 65535) + (checksum >> 16)
        checksum = (checksum & 65535) + (checksum >> 16)
        ip = ip[:10] + struct.pack("!H", (~checksum) & 65535) + ip[12:]
        packet = b"\x00" * 12 + b"\x08\x00" + ip + udp
        pcap = pcap_header(1) + pcap_record(100, 12345, packet, len(packet))
        class Capture:
            state = {}
            def pump(self, output, stop):
                output.write(pcap)
                output.flush()
            def close(self):
                pass
        def rows(command, capture=None):
            output = queue.Queue()
            read_packets(command, output, capture)
            values = []
            while True:
                row = output.get_nowait()
                if row is None:
                    return values
                row.pop("_received_wall")
                values.append(row)
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "capture.pcap"
            file.write_bytes(pcap)
            expected = rows(tshark_command(str(file), False))
            actual = rows(tshark_command("test-interface", True), Capture())
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 1)
        self.assertEqual(actual[0]["src_port"], 51000)
        self.assertEqual(actual[0]["payload"], dns)

    def test_pcap_preserves_timestamp_bytes_and_original_length(self):
        header = pcap_header(1)
        self.assertEqual(struct.unpack("<IHHIIII", header), (0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        record = pcap_record(100, 12345, b"packet", 600)
        self.assertEqual(struct.unpack("<IIII", record[:16]), (100, 12345, 6, 600))
        self.assertEqual(record[16:], b"packet")

    def test_interface_alias_and_index_cannot_select_another_adapter(self):
        listing = "1. \\Device\\NPF_{a} (Ethernet)\n2. \\Device\\NPF_{b} (Wi-Fi)"
        for interface in ("2", "Wi-Fi", "\\Device\\NPF_{b}"):
            self.assertEqual(resolve_interface(interface, listing), "\\Device\\NPF_{b}")
        with self.assertRaises(OSError):
            resolve_interface("Wi", listing)

    def test_dns_context_requires_an_actual_routine_question(self):
        query = struct.pack("!6H", 1, 0x100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        packet = {"protocol": 17, "dst_port": 53, "payload": query, "payload_len": len(query)}
        self.assertTrue(normal_dns_query(packet))
        for payload in (b"garbage", query[:15], query[:2] + b"\x81\x00" + query[4:],
                        query[:-4] + struct.pack("!HH", 16, 1)):
            self.assertFalse(normal_dns_query({**packet, "payload": payload}))
        self.assertFalse(normal_dns_query({**packet, "ip_flag_mf": 1}))

    def test_connection_evidence_expires_and_syns_are_not_responses(self):
        evidence = ServiceEvidence()
        addr = lambda ip, port: SimpleNamespace(ip=ip, port=port)
        connection = SimpleNamespace(status="ESTABLISHED", laddr=addr("192.168.0.2", 51000),
                                     raddr=addr("198.51.100.5", 443))
        import time
        evidence.refresh([connection])
        flow = SimpleNamespace(src="198.51.100.5", dst="192.168.0.2", sport=443, dport=51000,
                               proto=6, initial_syn=False, normal_dns_query=False,
                               senders=["198.51.100.5"], t=time.time())
        self.assertTrue(evidence.for_flow(flow)["established_connection"])
        listener = SimpleNamespace(status="LISTEN", laddr=addr("0.0.0.0", 51000), raddr=None)
        evidence.refresh([connection, listener])
        self.assertFalse(evidence.for_flow(flow)["established_connection"])
        evidence.refresh([connection])
        flow.initial_syn = True
        self.assertFalse(evidence.for_flow(flow)["established_connection"])
        flow.initial_syn = False
        evidence.sampled_at -= 4
        self.assertFalse(evidence.for_flow(flow)["established_connection"])

    def test_packet_bursts_are_measured_independently_of_model_crossings(self):
        evidence = ServiceEvidence()
        for i in range(300):
            evidence.observe({"src_ip": "192.168.0.2", "timestamp": 100.0 + i / 1000})
        flow = SimpleNamespace(src="192.168.0.2", dst="198.51.100.5", sport=51000, dport=443,
                               proto=6, initial_syn=False, normal_dns_query=False,
                               senders=["192.168.0.2"], t=100.0)
        self.assertEqual(evidence.for_flow(flow)["source_packets_per_second"], 300)


if __name__ == "__main__":
    unittest.main()
