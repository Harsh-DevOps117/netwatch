"""Check that the live service's streaming ingest produces exactly the flows a whole-capture ingest does.

Run: uv run python -m tools.live.pcap_from_packets --day Thursday-15-02-2018 --start 1518707112 --seconds 600 \\
         --captures UCAP172.31.69.25 capPC1-172.31.65.25 --out /tmp/check/files --files 20
     uv run python -m tools.live.stream_check /tmp/check/files --work /tmp/check/work

Two comparisons over the same capture files:
  1. CICFlowMeter's own batch run over the merged capture vs tools/live/StreamMeter: identical rows (order aside).
  2. models.serving.live.Live, fed one file at a time with the models stubbed out, vs one ingest of the merged capture:
     the same complete flows (keyed by 5-tuple and first packet), with identical statistics and packet counts.
Exits non-zero on any difference.
"""
from __future__ import annotations

import argparse
import collections
import os
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from ingest.sources.flows import run_cicflowmeter
from models.context_encoder.records import X_COLUMNS
from models.serving.live import HOLD_S, Chain, FlowStream, Live, complete_flows


def flows_of(folder: Path, start: float, cutoff: float):
    """Complete flows of an ingested folder: (flow_key, first packet) -> statistics and mapped packet count."""
    f = pq.read_table(folder / "flows.parquet").to_pandas()
    m = pq.read_table(folder / "flow_packet_map.parquet", columns=["frame_no", "flow_uid"]).to_pandas()
    p = pq.read_table(folder / "packets.parquet", columns=["frame_no", "timestamp"]).to_pandas()
    mp = m.merge(p, on="frame_no")
    f["first"] = f["flow_uid"].map(mp.groupby("flow_uid")["timestamp"].min()).round(6)
    f["packets_mapped"] = f["flow_uid"].map(mp.groupby("flow_uid").size())
    f = f[(f["first"] >= start) & (f["first"] <= cutoff)]
    cols = [c for c in X_COLUMNS if c in f.columns] + ["packets_mapped"]
    return f[["flow_key", "first"] + cols].sort_values(["flow_key", "first"] + cols).reset_index(drop=True), cols


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("files", type=Path, help="folder of consecutive capture files")
    parser.add_argument("--work", type=Path, required=True, help="scratch folder (emptied)")
    parser.add_argument("--cicflowmeter", type=Path, default=Path("tools/CICFlowMeter"))
    args = parser.parse_args(argv)
    files = sorted(args.files.glob("*.pcap"))
    shutil.rmtree(args.work, ignore_errors=True)
    args.work.mkdir(parents=True)
    ok = True

    # ---- the reference: one ingest of the whole capture
    reference = Chain.__new__(Chain)
    reference.work, reference.cicflowmeter = args.work / "reference", args.cicflowmeter
    merged = args.work / "window.pcap"
    subprocess.run(["mergecap", "-F", "pcap", "-w", str(merged), *map(str, files)], check=True, capture_output=True)
    whole = Chain.ingest(reference, merged, reference.work / "window")

    # ---- 1. meter rows vs CICFlowMeter's batch rows
    run_cicflowmeter(args.cicflowmeter, merged, args.work / "batch")
    batch = (args.work / "batch" / "window.pcap_Flow.csv").read_text().splitlines()[1:]
    stream = FlowStream(args.cicflowmeter, args.work / "stream")
    stream.feed(merged)
    stream.close()
    _, rows = stream.rows()
    with stream.lock:
        rows += stream.pending                                   # the end-of-input dump follows the last sweep
    same = collections.Counter(batch) == collections.Counter(rows)
    ok &= same
    print(f"1. meter vs batch CICFlowMeter: {len(rows):,} vs {len(batch):,} rows, identical: {same}")

    # ---- 2. the live service, one file at a time, vs the whole-capture ingest
    chain = Chain.__new__(Chain)
    chain.work, chain.cicflowmeter = args.work / "live", args.cicflowmeter
    chain.work.mkdir()
    seen = {}

    def build(folder, cycle, start, cutoff):                     # the models are stubbed: capture the window only
        complete_flows(folder, start, cutoff)
        shutil.copytree(folder, args.work / "last_window", dirs_exist_ok=True)
        seen.update(start=start, cutoff=cutoff)
        return 0

    chain.build = build
    live = Live.__new__(Live)
    live.chain, live.inbox, live.window, live.idle, live.hold = chain, args.work / "in", len(files), 0.0, HOLD_S
    live.pcaps, live.seen, live.cycles, live.status = [], set(), 0, {}
    live.packets, live.next_frame, live.next_flow, live.slabs = {}, 0, 0, []
    live.stream = FlowStream(args.cicflowmeter, chain.work / "stream")
    live.inbox.mkdir()
    for i, f in enumerate(files):
        shutil.copy2(f, live.inbox / f.name)
        os.utime(live.inbox / f.name, (1e9 + i, 1e9 + i))
        live.step()
    live.stream.close()
    new, cols = flows_of(args.work / "last_window", seen["start"], seen["cutoff"])
    old, _ = flows_of(whole, seen["start"], seen["cutoff"])
    keys_new = collections.Counter(zip(new.flow_key, new["first"]))
    keys_old = collections.Counter(zip(old.flow_key, old["first"]))
    same_keys = keys_new == keys_old
    same_values = same_keys and bool(np.isclose(new[cols].to_numpy(float), old[cols].to_numpy(float),
                                                equal_nan=True).all())
    ok &= same_values
    print(f"2. live service vs whole-capture ingest: {len(new):,} vs {len(old):,} complete flows, "
          f"same flows: {same_keys}, identical statistics and packet counts: {same_values}")
    if not same_keys:
        print("   only whole-capture:", list((keys_old - keys_new))[:3], "\n   only live:", list((keys_new - keys_old))[:3])
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
