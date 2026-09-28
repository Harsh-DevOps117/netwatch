"""The tolerance test: does a serving path give the models the inputs they were trained on?

Run: uv run python -m models.serving.parity --registry <models>/serving.json --tag lag --pcap <capture.pcap> \
        --out <models>/parity/lag.json

One capture goes through the training-style ingest (every flow, one stream -- a day as the offline ingest builds it) and
through the tag's path, and every stage is compared flow by flow:

| stage | what | kind |
|---|---|---|
| flows | which flows exist | the tag's flows must be a subset, as its rule says |
| event | start time, direction, packet presence | exact / float |
| summary | the 20-packet aggregate (Block 8's kind 2 and Block 7's prefix source) | float |
| side | request/response counts, reply latency; endpoints by IP | exact / float |
| record | the 69 CICFlowMeter record columns | float |
| block7_h | Block 7's embedding: per flow, no state | embedding |
| host_state | dt_src, dt_dst, port_delta, dst_port_new: read earlier events of the host | stateful |
| block9_z | Block 9's latent, through Block 8's link memory | stateful |
| block10 | Block 10's surprise, through its node memory | stateful |

Stateless stages must match for any tag. Stateful ones match only when the stream and its resets match: for `lag`
they differ by design (a window of complete flows starts cold and misses the flows it drops), so they are measured and
reported as the size of that difference rather than failed. `--candidate` compares any other built cycle, and there
every stage must pass. The `live` tag's own check is tools/live/detect_check.py.

The report names the first stage that fails and the retrain it would imply (docs/dev/contracts/live-sensor-schema.json,
parity_2026_09_26). Nothing is retrained here: the report is kept so that decision can be made later.

`--tag self` builds the reference twice and compares it with itself -- the harness's own check, and a determinism check
of the serving path.
"""
from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from ingest.build.events import AGG_COLUMNS
from models.context_encoder.records import RECORD_COLUMNS

DAY = "live"
# (columns, kind) per stage. Kinds: exact equality; float = rtol 1e-5 + atol 1e-6 (float32 arithmetic in a different
# order); embedding = atol 1e-4 (a network's output; the Block 7 re-export matched to 7.6e-6); stateful = atol 1e-4,
# enforced only where the tag's stream is meant to be the same stream.
TOLERANCES = {
    "exact": {"rtol": 0.0, "atol": 0.0},
    "float": {"rtol": 1e-5, "atol": 1e-6},
    "embedding": {"rtol": 0.0, "atol": 1e-4},
    "stateful": {"rtol": 0.0, "atol": 1e-4},
}
STAGES = [
    ("event", ["t", "reversed", "has_packets"], "float"),
    ("summary", list(AGG_COLUMNS), "float"),
    ("side", ["sender_ip", "receiver_ip", "request_packets", "response_packets", "direction_changes", "no_reply"], "exact"),
    ("side_latency", ["reply_latency_s"], "float"),
    ("record", list(RECORD_COLUMNS), "float"),
    ("block7_h", ["h"], "embedding"),
    ("host_state", ["dt_src", "dt_dst", "port_delta", "dst_port_new"], "stateful"),
    ("block9_z", ["z", "latent_recon_error"], "stateful"),
    ("block10", ["surprise"], "stateful"),
]
# What a failing stage would take to fix, if the sensor cannot be made to match (retrain from that block down).
RETRAIN = {
    "flows": "blocks 7-10 and the detector: flow boundaries define the events (needs the original captures)",
    "event": "blocks 7-10 and the detector", "summary": "both Block 8s, Block 9, Block 10, the detector",
    "side": "both Block 8s, Block 9, Block 10, the detector", "side_latency": "both Block 8s, Block 9, Block 10, the detector",
    "record": "the world model's Block 8, Block 9, Block 10", "block7_h": "blocks 7-10 and the detector",
    "host_state": "Block 10 (memory/stream policy), with the world model's Block 8 if its policy changes too",
    "block9_z": "Block 10 (memory/stream policy), with the world model's Block 8 if its policy changes too",
    "block10": "Block 10 only (memory policy)",
}


def build_variant(chain, ingested: Path, cycle: Path, start: float, cutoff: float) -> Path:
    """One serving path's stage outputs for an ingested capture: a copy, filtered by [start, cutoff], built."""
    folder = cycle / "capture" / "window"
    shutil.copytree(ingested, folder)
    if not chain.build(folder, cycle, start, cutoff):
        raise SystemExit(f"{cycle}: no flows in [{start}, {cutoff}]")
    return cycle


def stage_table(cycle: Path, block10: Path) -> pd.DataFrame:
    """Every compared value of one built cycle, one row per flow, indexed by flow_uid."""
    from models.world_model.inference import Replay
    from models.world_model.reception import receive

    events = pq.read_table(cycle / "events" / DAY / "events.parquet").to_pandas()
    ips = pq.read_table(cycle / "events" / DAY / "node_index.parquet").to_pandas().set_index("node_id")["ip"]
    side = pq.read_table(cycle / "context_features" / DAY / "side_features.parquet").to_pandas()
    side["sender_ip"], side["receiver_ip"] = side["sender_node_id"].map(ips), side["receiver_node_id"].map(ips)
    table = events.merge(side.drop(columns=["sender_node_id", "receiver_node_id"]), on="event_id")
    records = cycle / "context_features" / DAY / "flow_records.parquet"
    if records.exists():
        table = table.merge(pq.read_table(records, columns=["event_id", *RECORD_COLUMNS]).to_pandas(), on="event_id")
    h = pq.read_table(next((cycle / "flow_embeddings").glob(f"*/{DAY}/flow_embeddings.parquet")),
                      columns=["event_id", "h"]).to_pandas()
    table = table.merge(h, on="event_id", how="left")
    latents = pq.read_table(cycle / "latents" / DAY / "event_latents.parquet",
                            columns=["event_id", "z", "recon_error"]).to_pandas()
    table = table.merge(latents.rename(columns={"recon_error": "latent_recon_error"}), on="event_id", how="left")
    replay = Replay(receive([cycle / "latents" / DAY]), block10, split=None, attention=False)
    replay.advance(len(latents))
    replay.finish()
    scored = pd.DataFrame({"event_id": list(replay.rows["event_id"]), "surprise": list(replay.rows["surprise"])})
    return table.merge(scored, on="event_id", how="left").set_index("flow_uid")


def _as_matrix(series: pd.Series) -> np.ndarray:
    values = series.to_numpy()
    if len(values) and isinstance(values[0], (list, np.ndarray)):
        return np.stack([np.asarray(v, dtype=np.float64) for v in values])
    return values


def compare(reference: pd.DataFrame, candidate: pd.DataFrame, *, enforce_stateful: bool) -> dict:
    """Stage by stage, on the flows both have. Output: the report dict (see the module docstring)."""
    shared = reference.index.intersection(candidate.index)
    extra = candidate.index.difference(reference.index)
    report = {"flows": {"reference": int(len(reference)), "candidate": int(len(candidate)), "compared": int(len(shared)),
                        "candidate_only": int(len(extra)), "verdict": "pass" if len(extra) == 0 and len(shared) else "fail"},
              "stages": {}}
    ref, cand = reference.loc[shared], candidate.loc[shared]
    for stage, columns, kind in STAGES:
        columns = [c for c in columns if c in ref.columns and c in cand.columns]
        if not columns:
            report["stages"][stage] = {"verdict": "not present"}
            continue
        tol = TOLERANCES[kind]
        worst, within, total = 0.0, 0, 0
        per_column, spread = {}, []
        for column in columns:
            a, b = _as_matrix(ref[column]), _as_matrix(cand[column])
            if a.dtype.kind in "OUS" or b.dtype.kind in "OUS":
                ok = a.astype(str) == b.astype(str)
                diff = np.where(ok, 0.0, np.inf)
            else:
                a, b = a.astype(np.float64), b.astype(np.float64)
                both_nan = np.isnan(a) & np.isnan(b)
                diff = np.where(both_nan, 0.0, np.abs(a - b))
                ok = diff <= tol["atol"] + tol["rtol"] * np.abs(np.nan_to_num(a))
            col_worst = float(np.nanmax(diff)) if diff.size else 0.0
            if np.isfinite(diff).all():
                spread.append(diff.ravel())
            per_column[column] = col_worst
            worst, within, total = max(worst, col_worst), within + int(ok.sum()), total + int(ok.size)
        share = within / max(total, 1)
        if share == 1.0:
            verdict = "pass"
        elif kind == "stateful" and not enforce_stateful:
            verdict = "differs (expected for this tag)"
        else:
            verdict = "fail"
        flat = np.concatenate(spread) if spread else np.zeros(1)
        report["stages"][stage] = {"kind": kind, "tolerance": tol, "max_abs_diff": worst, "share_within": share,
                                   "median_abs_diff": float(np.median(flat)), "p90_abs_diff": float(np.quantile(flat, 0.9)),
                                   "reference_scale": float(np.median(np.abs(np.concatenate(
                                       [_as_matrix(ref[c]).astype(np.float64).ravel() for c in columns
                                        if _as_matrix(ref[c]).dtype.kind not in "OUS"] or [np.zeros(1)])))),
                                   "worst_columns": dict(sorted(per_column.items(), key=lambda kv: -kv[1])[:5]),
                                   "verdict": verdict}
    order = ["flows", *[s for s, _, _ in STAGES]]
    failed = next((s for s in order if (report["flows"] if s == "flows" else report["stages"][s]).get("verdict") == "fail"),
                  None)
    report["first_failure"] = failed
    report["retrain_if_not_fixed"] = RETRAIN.get(failed, "none")
    report["verdict"] = "pass" if failed is None else "fail"
    return report


def main(argv: "list[str] | None" = None) -> int:
    from models.serving.live import HOLD_S, Chain
    from models.serving.registry import resolve

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--registry", type=Path, required=True, help="serving.json naming the tag's checkpoints")
    parser.add_argument("--tag", choices=("lag", "delay", "live", "self"), required=True,
                        help="lag (its old name, delay, still works), live, or self")
    parser.add_argument("--pcap", type=Path, nargs="+", help="the capture(s) both paths read; merged in time order")
    parser.add_argument("--candidate", type=Path, default=None,
                        help="live: a built cycle folder (events/, context_features/, flow_embeddings/, latents/) "
                             "produced from the sensor's messages for the same capture")
    parser.add_argument("--hold", type=float, default=HOLD_S)
    parser.add_argument("--cicflowmeter", type=Path, default=Path("tools/CICFlowMeter"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--device", default=None)
    args = parser.parse_args(argv)
    args.tag = "lag" if args.tag == "delay" else args.tag

    report = {"tag": args.tag, "pcap": [str(p) for p in args.pcap or []], "hold_seconds": args.hold}
    if args.tag == "live" and args.candidate is None:
        report.update(verdict="pending", reason="the live tag reads the detection stream; its inputs are checked "
                      "against training by tools/live/detect_check.py, not here. --candidate compares a built cycle "
                      "folder instead")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        return 0
    if not args.pcap:
        parser.error("--pcap is required")
    models = resolve(args.registry, "lag")           # the trained set; lag never needs parity to be resolved
    chain = Chain(Path(tempfile.mkdtemp(prefix="parity-")), block7=models["block7"], block8=models["block8"],
                  block9=models["block9"], cicflowmeter=args.cicflowmeter, device=args.device)
    work = chain.work
    try:
        merged = work / "capture.pcap"
        import subprocess
        subprocess.run(["mergecap", "-F", "pcap", "-w", str(merged), *map(str, args.pcap)], check=True,
                       capture_output=True)
        ingested = chain.ingest(merged, work / "ingested")
        if ingested is None:
            raise SystemExit("the capture held no flows")
        times = pq.read_table(ingested / "packets.parquet", columns=["timestamp"]).column(0).to_numpy()
        first, newest = float(times.min()), float(times.max())
        reference = stage_table(build_variant(chain, ingested, work / "reference", -np.inf, np.inf), models["block10"])
        if args.tag == "lag":
            start, cutoff = first + args.hold, newest - args.hold
            candidate_cycle = build_variant(chain, ingested, work / "candidate", start, cutoff)
            report["rule"] = f"flows that started in [first packet + {args.hold:.0f} s, newest - {args.hold:.0f} s]"
        elif args.tag == "self":
            candidate_cycle = build_variant(chain, ingested, work / "candidate", -np.inf, np.inf)
        else:
            candidate_cycle = args.candidate
        candidate = stage_table(candidate_cycle, models["block10"])
        report.update(compare(reference, candidate, enforce_stateful=args.tag != "lag"))
        report["capture_seconds"] = newest - first
        report["checkpoints"] = {role: str(path) for role, path in models.items()}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, default=float) + "\n")
    summary = {s: v.get("verdict") for s, v in report["stages"].items()}
    print(json.dumps({"tag": args.tag, "verdict": report["verdict"], "flows": report["flows"], "stages": summary,
                      "first_failure": report["first_failure"], "retrain_if_not_fixed": report["retrain_if_not_fixed"]},
                     indent=2))
    return 0


def demo() -> None:
    """Self-check of the comparison: identical tables pass; a moved stateless value fails and names the retrain."""
    table = pd.DataFrame({"t": [1.0, 2.0], "reversed": [0.0, 1.0], "has_packets": [True, True],
                          "h": [np.zeros(3), np.ones(3)], "surprise": [0.1, 0.2]},
                         index=pd.Index(["a", "b"], name="flow_uid"))
    assert compare(table, table.copy(), enforce_stateful=True)["verdict"] == "pass"
    moved = table.copy()
    moved.loc["b", "t"] = 2.5
    report = compare(table, moved, enforce_stateful=True)
    assert report["first_failure"] == "event" and "blocks 7-10" in report["retrain_if_not_fixed"], report
    drifted = table.copy()
    drifted["surprise"] = [0.1, 0.3]
    assert compare(table, drifted, enforce_stateful=False)["verdict"] == "pass", "lag: stateful drift is reported"
    assert compare(table, drifted, enforce_stateful=True)["first_failure"] == "block10"
    print("demo ok")


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--demo"]:
        demo()
    else:
        raise SystemExit(main())
