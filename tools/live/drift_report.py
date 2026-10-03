"""Compare live PCAP prefix inputs with the saved training normalisation statistics.

This is an unlabelled input-distribution diagnostic, not a probability or
false-positive calibration. It uses the same packet parser, flow tracker,
prefix preparation, and feature ordering as live detection.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import numpy as np
import torch

from ingest.build.events import AGG_COLUMNS
from ingest.sources.packets import PACKET_COLUMNS, TSHARK_FIELDS, _parse_packet_row
from models.data.inputs import LOG_PACKET_FEATURES, PACKET_FEATURES, X_COLUMNS, signed_log
from models.data.prefix import prepare
from models.serving.detect_live import DURATION, K, OPEN, Flow, Tracker, reversed_of_flow, tshark_command


def collect(path: Path, budget: float, max_packets: int) -> tuple[list[Flow], dict]:
    tracker = Tracker(budget)
    disorder = 0
    previous = None
    count = 0
    ipv6 = 0
    other_protocol = 0
    files = sorted(path.glob("*.pcap")) if path.is_dir() else [path]
    for capture in files:
        process = subprocess.Popen(tshark_command(str(capture), False), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        assert process.stdout is not None
        try:
            for line in process.stdout:
                values = line.rstrip("\r\n").split("\t")
                if len(values) != len(TSHARK_FIELDS):
                    continue
                row = _parse_packet_row(dict(zip(TSHARK_FIELDS, values)))
                if row is None:
                    continue
                packet = dict(zip(PACKET_COLUMNS, row))
                ipv6 += int(bool(packet["is_ipv6"]))
                other_protocol += int(not packet["is_ipv6"] and packet["protocol"] not in (6, 17))
                timestamp = float(packet["timestamp"])
                disorder += int(previous is not None and timestamp < previous)
                previous = timestamp
                tracker.add(packet)
                count += 1
                if count >= max_packets:
                    break
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=10)
        if count >= max_packets:
            break
    tracker.finish()
    flows = sorted(tracker.ready, key=lambda flow: (min(flow.t + budget, flow.fin)
                                                   if flow.fin is not None else flow.t + budget, flow.id))
    return flows, {"parsed_packets": count, "timestamp_reversals": disorder,
                   "ipv6_packets_excluded_from_cic_model": ipv6,
                   "other_ipv4_protocol_packets_excluded": other_protocol,
                   "ipv4_tcp_udp_packets": tracker.packets, "scored_flow_candidates": len(flows)}


def report(path: Path, checkpoint: Path, max_packets: int) -> dict:
    saved = torch.load(checkpoint, map_location="cpu", weights_only=False)
    if saved.get("format") not in ("flow-encoder-v1", "block7-encoder-v1"):
        raise ValueError("checkpoint lacks the training feature contract and normalisation statistics")
    stats = saved["stats"]
    budget = float(saved.get("budget_ms", 10.0)) / 1000.0
    side = saved.get("side", "split")
    flows, summary = collect(path, budget, max_packets)
    if not flows:
        return {"pcap": str(path), "checkpoint": str(checkpoint), **summary, "features": []}
    n = len(flows)
    pkt = np.zeros((n, K, len(PACKET_FEATURES)), np.float32)
    dt = np.zeros((n, K), np.float32)
    n_pkt = np.zeros(n, np.int16)
    x = np.zeros((n, len(X_COLUMNS)), np.float32)
    for index, flow in enumerate(flows):
        pkt[index], dt[index], n_pkt[index] = flow.arrays()
        x[index, DURATION] = (flow.fin - flow.t) * 1e6 if flow.fin is not None else OPEN
    data = prepare({"t": np.array([flow.t for flow in flows]), "pkt": pkt, "dt": dt,
                    "n_pkt": n_pkt, "x": x, "a": np.zeros((n, len(AGG_COLUMNS)), np.float32)},
                   budget, side)
    valid = np.arange(K) < data["n_pkt"][:, None]
    packet_values = data["pkt"][valid].copy()
    for name in LOG_PACKET_FEATURES:
        index = PACKET_FEATURES.index(name)
        packet_values[:, index] = signed_log(packet_values[:, index])
    columns = []
    aggregate_names = (["initiator." + name for name in AGG_COLUMNS] +
                       ["responder." + name for name in AGG_COLUMNS]) if side == "split" else list(AGG_COLUMNS)
    for group, names, values in (("aggregate", aggregate_names, signed_log(data["a"])),
                                 ("packet", PACKET_FEATURES, packet_values)):
        training_mean, training_std = [np.asarray(value) for value in stats["a" if group == "aggregate" else "pkt"]]
        if values.shape[1] != len(names) or len(training_mean) != len(names):
            raise ValueError(f"{group} feature width differs from checkpoint")
        live_mean, live_std = values.mean(0), values.std(0)
        for index, name in enumerate(names):
            columns.append({"feature": group + "." + name,
                            "mean_shift_training_sd": round(float((live_mean[index] - training_mean[index]) /
                                                                    max(training_std[index], 1e-6)), 3),
                            "live_to_training_sd": round(float(live_std[index] /
                                                                max(training_std[index], 1e-6)), 3),
                            "live_mean": round(float(live_mean[index]), 4),
                            "training_mean": round(float(training_mean[index]), 4)})
    summary.update({"pcap": str(path), "checkpoint": str(checkpoint), "observation_budget_ms": budget * 1000,
                    "side": side, "packet_feature_order": PACKET_FEATURES,
                    "forward_packets": int((packet_values[:, PACKET_FEATURES.index("direction")] == 0).sum()),
                    "backward_packets": int((packet_values[:, PACKET_FEATURES.index("direction")] == 1).sum()),
                    "reversed_flows": {str(value): sum(reversed_of_flow(flow) == value for flow in flows)
                                       for value in (-1.0, 0.0, 1.0)},
                    "features": sorted(columns, key=lambda row: abs(row["mean_shift_training_sd"]), reverse=True)})
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--checkpoint", type=Path, default=Path("artifacts/current/flow_encoder.pt"))
    parser.add_argument("--max-packets", type=int, default=100_000)
    parser.add_argument("--top", type=int, default=20)
    args = parser.parse_args()
    result = report(args.pcap, args.checkpoint, args.max_packets)
    top = result.pop("features")
    result["largest_input_shifts"] = top[:args.top]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
