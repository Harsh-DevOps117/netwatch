"""Rebuild a capture file from ingested packet records, to exercise the live runner without capture rights.

Run: uv run python -m tools.live.pcap_from_packets --day Thursday-15-02-2018 --start 1518707112 --seconds 60 \
        --captures UCAP172.31.69.25 capPC1-172.31.65.25 --out /tmp/live-in --files 2

Live capture needs root, and a quiet WSL interface carries almost nothing. This writes the recorded traffic of a slice
of a dataset day as ordinary pcap files -- the same thing dumpcap's ring buffer would drop into the live runner's
input folder -- so the whole chain from capture to forecast can be run and checked, attack traffic included.

The frames are rebuilt from the stored header fields (addresses, ports, protocol, TTL, TCP window and flags, IP flags,
lengths) and the stored payload bytes, padded to their recorded length. Sequence numbers are regenerated per direction
so a protocol analyser does not see false retransmissions. Only IPv4 TCP/UDP is written; other rows are skipped.
"""
from __future__ import annotations

import argparse
import socket
import struct
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

COLUMNS = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "ttl", "is_ipv6",
           "tcp_window", "tcp_flag_syn", "tcp_flag_ack", "tcp_flag_fin", "tcp_flag_rst", "tcp_flag_psh",
           "tcp_flag_urg", "ip_flag_df", "payload_len", "payload"]


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def frame(row: dict, seq: dict) -> "bytes | None":
    """One Ethernet frame from one packet record, or None when it is not IPv4 TCP/UDP."""
    if row["is_ipv6"] or row["protocol"] not in (6, 17):
        return None
    payload = bytes(row["payload"] or b"")[: row["payload_len"]].ljust(row["payload_len"], b"\0")
    src, dst = socket.inet_aton(row["src_ip"]), socket.inet_aton(row["dst_ip"])
    if row["protocol"] == 6:
        key = (row["src_ip"], row["dst_ip"], row["src_port"], row["dst_port"])
        number = seq.get(key, 1000)
        seq[key] = number + len(payload) + (1 if row["tcp_flag_syn"] or row["tcp_flag_fin"] else 0)
        flags = (row["tcp_flag_fin"] | row["tcp_flag_syn"] << 1 | row["tcp_flag_rst"] << 2 | row["tcp_flag_psh"] << 3
                 | row["tcp_flag_ack"] << 4 | row["tcp_flag_urg"] << 5)
        reverse = seq.get((row["dst_ip"], row["src_ip"], row["dst_port"], row["src_port"]), 0)
        header = struct.pack("!HHIIBBHHH", row["src_port"], row["dst_port"], number,
                             reverse if row["tcp_flag_ack"] else 0, 5 << 4, flags,
                             max(0, min(int(row["tcp_window"]), 65535)), 0, 0)
    else:
        header = struct.pack("!HHHH", row["src_port"], row["dst_port"], 8 + len(payload), 0)
    segment = header + payload
    pseudo = src + dst + struct.pack("!BBH", 0, row["protocol"], len(segment))
    check = _checksum(pseudo + segment)
    segment = segment[:16] + struct.pack("!H", check) + segment[18:] if row["protocol"] == 6 else \
        segment[:6] + struct.pack("!H", check) + segment[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0x4000 if row["ip_flag_df"] else 0,
                     max(1, int(row["ttl"])), row["protocol"], 0, src, dst)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip + segment


def write(path: Path, rows: list) -> int:
    """A classic pcap file (microsecond timestamps, Ethernet), which tshark and CICFlowMeter both read."""
    seq, written = {}, 0
    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for row in rows:
            data = frame(row, seq)
            if data is None:
                continue
            seconds = int(row["timestamp"])
            micros = int(round((row["timestamp"] - seconds) * 1e6))
            out.write(struct.pack("<IIII", seconds, micros, len(data), len(data)) + data)
            written += 1
    return written


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--day", required=True)
    parser.add_argument("--start", type=float, required=True, help="epoch seconds")
    parser.add_argument("--seconds", type=float, default=60.0)
    parser.add_argument("--captures", nargs="+", required=True, help="capture folder names under data/processed/<day>")
    parser.add_argument("--processed-root", type=Path, default=Path("data/processed"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--files", type=int, default=1, help="split the slice into this many consecutive files")
    args = parser.parse_args(argv)

    rows = []
    for capture in args.captures:
        table = pq.read_table(args.processed_root / args.day / capture / "packets.parquet", columns=COLUMNS,
                              filters=[("timestamp", ">=", args.start),
                                       ("timestamp", "<", args.start + args.seconds)])
        rows.extend(table.to_pylist())
    rows.sort(key=lambda r: r["timestamp"])
    args.out.mkdir(parents=True, exist_ok=True)
    edges = np.linspace(args.start, args.start + args.seconds, args.files + 1)
    for i in range(args.files):
        part = [r for r in rows if edges[i] <= r["timestamp"] < edges[i + 1]]
        path = args.out / f"replay_{i:05d}.pcap"
        print(f"{path}: {write(path, part):,} packets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
