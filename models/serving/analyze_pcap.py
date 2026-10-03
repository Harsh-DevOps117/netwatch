"""Isolated, unlabeled PCAP analysis for the dashboard's offline route.

Detection reuses its normal replay path. The world model uses complete flows
from the whole file (not the live runner's 120-second boundary hold).
Neither path reads or writes live calibration, live incident history, or capture.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from ingest.build.join import build_edges, build_flow_packet_map


def align_meter_clock(folder: Path) -> float:
    """Align CICFlowMeter's wall-clock CSV to packet epochs when its zone differs.

    Windows CICFlowMeter may format a capture's local wall time as a naive CSV
    timestamp, while tshark exports epoch seconds. Only shift when multiple
    matching 5-tuple keys agree on the same 15-minute timezone offset.
    """
    flows_path = folder / "flows.parquet"
    table = pq.read_table(flows_path)
    flows = table.select(["flow_key", "Timestamp"]).to_pandas()
    packet_map = pq.read_table(folder / "flow_packet_map.parquet", columns=["frame_no", "flow_key"]).to_pandas()
    packets = pq.read_table(folder / "packets.parquet", columns=["frame_no", "timestamp"]).to_pandas()
    first_packet = packet_map.merge(packets, on="frame_no").groupby("flow_key")["timestamp"].min()
    dates = pd.to_datetime(flows["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
    seconds = (dates - pd.Timestamp("1970-01-01")).dt.total_seconds()
    first_flow = pd.DataFrame({"flow_key": flows["flow_key"], "seconds": seconds}).groupby("flow_key")["seconds"].min()
    overlap = first_flow.to_frame().join(first_packet, how="inner").dropna()
    if len(overlap) < 2:
        return 0.0
    deltas = (overlap["seconds"] - overlap["timestamp"]).to_numpy()
    shift = round(float(np.median(deltas)) / 900.0) * 900.0
    if abs(shift) < 900 or np.mean(np.abs(deltas - shift) < 120) < .75:
        return 0.0
    corrected = (dates - pd.to_timedelta(shift, unit="s")).dt.strftime("%d/%m/%Y %I:%M:%S %p")
    index = table.schema.get_field_index("Timestamp")
    pq.write_table(table.set_column(index, "Timestamp", pa.array(corrected)), flows_path, compression="zstd")
    build_flow_packet_map(flows_path, folder / "packets.parquet", folder / "flow_packet_map.parquet")
    build_edges(flows_path, folder / "edges.parquet")
    return shift


def analyze(pcap: Path, work: Path, result_path: Path, name: str) -> dict:
    if os.name == "nt":
        wireshark = Path("C:/Program Files/Wireshark")
        if wireshark.is_dir():
            os.environ["PATH"] = str(wireshark) + os.pathsep + os.environ.get("PATH", "")
    from models.serving.live import Chain, DAY
    from models.serving.registry import resolve
    from models.world_model.inference import Replay
    from models.world_model.reception import receive
    from models.world_model.service import forecast_payload, node_names, served_threshold

    work.mkdir(parents=True, exist_ok=True)
    result = {"mode": "offline", "file": name, "started_at": time.time(),
              "detection": None, "world": None, "errors": {}}
    progress = work / "progress.json"

    def stage(value: str) -> None:
        progress.write_text(json.dumps({"stage": value, "updated_at": time.time()}), encoding="utf-8")

    stage("Scoring detector events")
    detection_file = work / "detection.json"
    try:
        subprocess.run([sys.executable, "-m", "models.serving.detect_live", "--pcap", str(pcap),
                        "--once", "--json-out", str(detection_file)], check=True, timeout=1800)
        detection = json.loads(detection_file.read_text(encoding="utf-8"))
        # Incident details are deliberately separate from the rolling live-event feed.
        result["detection"] = {"status": detection["status"], "packets": detection["packets"],
                               "events_scored": detection["events_scored"],
                               "thresholds": detection["thresholds"],
                               "incidents": detection["offline_incidents"],
                               "attention": detection.get("attention", [])}
    except Exception as exc:
        result["errors"]["detection"] = str(exc)
        traceback.print_exc()

    stage("Building complete flows for world model")
    try:
        models = resolve(Path("artifacts/current/serving.json"), "lag")
        chain = Chain(work / "world", block7=models["block7"], block8=models["block8"],
                      block9=models["block9"], cicflowmeter=Path("tools/CICFlowMeter"))
        ingested = chain.ingest(pcap, work / "world" / "ingested")
        if ingested is None:
            raise ValueError("No complete flows could be built from this capture")
        clock_shift = align_meter_clock(ingested)
        times = pq.read_table(ingested / "packets.parquet", columns=["timestamp"]).column(0).to_numpy()
        folder = work / "world" / "cycle" / "capture" / "window"
        shutil.copytree(ingested, folder)
        stage("Scoring world-model events")
        count = chain.build(folder, work / "world" / "cycle", -np.inf, np.inf)
        if count == 0:
            raise ValueError("No complete world-model flows in this capture")
        manifest = json.loads((work / "world" / "cycle" / "latents" / DAY / "latents_manifest.json").read_text())
        if manifest["n_events"] == 0:
            raise ValueError("No packet-backed world-model events in this capture")
        run = receive([work / "world" / "cycle" / "latents" / DAY])
        replay = Replay(run, models["block10"], split=None, device=chain.device, attention=False, keep=2000)
        replay.advance(len(run))
        replay.finish()
        stage("Generating forecast event steps")
        # The offline panel presents a short, event-indexed horizon. Keep all
        # four seed paths, but only imagine the next three events on each path.
        rollouts = replay.rollout(3, 4)
        source = {"mode": "offline", "tag": "lag", "captures": [name],
                  "position": replay.scored, "total": len(run),
                  "t": float(replay.rows["t"][-1]) if replay.rows["t"] else None,
                  "capture_first": float(times.min()), "capture_last": float(times.max()),
                  "meter_clock_offset_corrected_s": clock_shift}
        caveats = ["Offline analysis of a completed PCAP. Live thresholds and incident history are untouched.",
                   "S[t+k] is k imagined model event steps, not k seconds or confirmed future traffic.",
                   "Unlabeled capture: score-tail exceedance is not a measured false-positive rate."]
        result["world"] = forecast_payload(
            rollouts, replay.rows, caveats=caveats,
            names=node_names(work / "world" / "cycle" / "events" / DAY / "node_index.parquet"),
            threshold=served_threshold(models["block10"]), source=source)
    except Exception as exc:
        result["errors"]["world"] = str(exc)
        traceback.print_exc()

    result["finished_at"] = time.time()
    result_path.write_text(json.dumps(result, default=str), encoding="utf-8")
    stage("Complete")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    result = analyze(args.pcap, args.work, args.out, args.name)
    return 0 if result["detection"] is not None or result["world"] is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
