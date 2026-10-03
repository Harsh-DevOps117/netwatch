"""Measure local detector throughput without sending network traffic.

    uv run python -m tools.measure.detection_latency --events 4096 --unique-hosts

Exercises the actual checkpoints, calibration and durable incident evidence in
temporary databases. --force-alerts lowers thresholds only on this isolated
benchmark instance to measure sustained attack bookkeeping. Reported timings
are processing batches, not capture-to-verdict latency on a real interface.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
import time
from pathlib import Path

import numpy as np
import torch

from models.data.inputs import PACKET_SOURCE_COLUMNS
from models.serving.detect_live import CURRENT, Detector
from models.serving.service_evidence import ServiceEvidence


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--events", type=int, default=4096)
    parser.add_argument("--batch", type=int, default=256)
    parser.add_argument("--unique-hosts", action="store_true", help="simulate many new sources")
    parser.add_argument("--force-alerts", action="store_true", help="exercise incident persistence for every family")
    args = parser.parse_args(argv)
    if min(args.threads, args.events, args.batch) < 1:
        parser.error("threads, events and batch must be positive")
    torch.set_num_threads(args.threads)
    timings, sizes = [], []
    with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
        detector = Detector(CURRENT / "flow_encoder.pt", CURRENT / "detection_encoder.pt",
                            sorted((CURRENT / "detector").glob("head_*.pt")),
                            calibration_db=Path(temp) / "calibration.sqlite", live_calibration_hours=4,
                            incident_db=Path(temp) / "incidents.sqlite")
        detector.service_evidence = ServiceEvidence() # exercise capture-side counters without OS/network probes
        if args.force_alerts:
            for family, threshold in detector.heads.thresholds.items():
                if threshold is not None:
                    detector.heads.thresholds[family] = 0.0
        try:
            # One unmeasured warm-up batch; packet times stay in stream order.
            epoch = time.time()
            for base in range(-args.batch, args.events, args.batch):
                size = args.batch if base < 0 else min(args.batch, args.events - base)
                started = time.perf_counter()
                for i in range(base, base + size):
                    timestamp = epoch + (i + args.batch) * .002
                    src = (f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}"
                           if args.unique_hosts else "192.0.2.10")
                    packet = {name: 0 for name in PACKET_SOURCE_COLUMNS}
                    packet.update(src_ip=src, dst_ip="198.51.100.5", src_port=1024 + i % 60000,
                                  dst_port=443, protocol=6, timestamp=timestamp, is_ipv6=False,
                                  ip_flag_mf=0, ip_frag_offset=0, tcp_flag_syn=1)
                    detector.add(packet)
                    detector.add({**packet, "timestamp": timestamp + .001,
                                  "tcp_flag_syn": 0, "tcp_flag_fin": 1})
                detector.score()
                if base >= 0:
                    timings.append(time.perf_counter() - started)
                    sizes.append(size)
            scored = detector.scored
        finally:
            detector.incident_history.close()
            if detector.live_calibration is not None:
                detector.live_calibration.close()
    print(json.dumps({"threads": args.threads, "events": args.events, "batch": args.batch,
                      "unique_hosts": args.unique_hosts, "forced_alerts": args.force_alerts,
                      "events_scored_including_warmup": scored,
                      "events_per_second": round(sum(sizes) / sum(timings), 2),
                      "batch_p50_s": round(float(np.median(timings)), 6),
                      "batch_p90_s": round(float(np.quantile(timings, .9)), 6)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
