"""Check the live detector (models.serving.detect_live) against the training pipeline.

Run: uv run python -m tools.live.detect_check --run ~/netwatch-data/runs/20260926-2337 --day Thursday-15-02-2018 \\
         --capture UCAP172.31.69.25 --start 1518707112 --seconds 300

1. The detection encoder, streamed: a slice of a training day's own stream through StreamingContext, in groups of
   random size, against models.compressor.latents.context_vectors over the same slice. Must agree to float precision.
2. Packets to features: the capture's recorded packets (packets.parquet, the rows tshark gave ingest) through the whole
   detector, against the training events of that capture -- the same flows, their embedding h, observation time, the
   cross-flow columns and the 20-packet summary, plus how late the live summaries reach link memory.
3. Verdicts: the densest benign test hour of the day, replayed from the capture holding most of its test events, against
   the probabilities the detector stage saved for those same events (detector/scores_<day>.pt), at the served thresholds.
   Training's stream merges every capture of the day, so events of hosts also seen by other captures are reported
   separately: one capture alone, like one sensor, gives them less context.
Exits non-zero when check 1 fails, check 2 matches fewer than 95% of flows or embeddings, or check 3's verdicts differ
on more than 1% of events.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import torch

from ingest.build.events import AGG_COLUMNS
from models.compressor.latents import context_vectors, frozen_context_encoder
from models.context_encoder.data import attack_slice, make_stream
from models.serving.detect_live import Detector, StreamingContext

HISTORY = ("dt_src", "dt_dst", "port_delta", "dst_port_new", "reversed")


def encoder_check(run: Path, day: str, events: int, seed: int = 0) -> bool:
    cache = run / "daycache" / f"{day}__split__f1r0"
    data = {p.stem: np.load(p, mmap_mode="r") for p in cache.glob("*.npy")}
    keep = attack_slice(data, events)
    stream = make_stream({k: np.asarray(v) for k, v in data.items()}, keep)
    offline, _ = frozen_context_encoder(run / "b8det" / "best.pt")
    offline.capacity = None                               # one row per link: no evictions on either side
    want = context_vectors(offline, stream, "split")

    model, _ = frozen_context_encoder(run / "b8det" / "best.pt")
    n = len(stream["sender"])
    live = StreamingContext(model, capacity=2 * n + 16)
    rng, got, at = np.random.default_rng(seed), [], 0
    while at < n:
        rows = np.arange(at, min(n, at + int(rng.integers(1, 700))))
        inputs = {c: stream[c][rows] for c in ("h_split", *HISTORY)}
        late = (stream["flow_summary"][rows], stream["flow_time"][rows], stream["flow_later"][rows])
        s, _ = live.encode({c: np.asarray(v) for c, v in inputs.items()}, stream["sender"][rows].astype(np.int64),
                           stream["receiver"][rows].astype(np.int64), stream["t_obs"][rows], late)
        got.append(s)
        at = rows[-1] + 1
    got = np.concatenate(got)
    # Relative: link ids are numbered differently, so memory sums its messages in another order -- float round-off,
    # nothing more (training's own code reproduces itself exactly).
    diff = float(np.abs(got - want).max() / np.abs(want).max())
    cosine = float(((got * want).sum(1) / np.linalg.norm(got, axis=1) / np.linalg.norm(want, axis=1)).min())
    ok = diff < 1e-4 and cosine > 0.9999
    print(f"1. streamed detection encoder vs training's: {n:,} events, max |s difference| {diff:.1e} of the largest "
          f"|s|, lowest cosine {cosine:.7f} -> {'same' if ok else 'DIFFERENT'}")
    return ok


def replay(run: Path, packets: list, oracle: "dict | None" = None) -> Detector:
    b7 = next(p for p in (run / "b7").glob("*.pt") if "epoch" not in p.name and p.name != "resume.pt")
    detector = Detector(b7, run / "b8det" / "best.pt", sorted((run / "detector").glob("head_*.pt")),
                        capacity=500_000, keep=True, oracle=oracle)
    for i, row in enumerate(packets):
        detector.add(row)
        if i % 2048 == 2047:
            detector.score()
    detector.tracker.finish()
    detector.score()
    return detector


def packet_check(run: Path, day: str, capture: str, start: float, seconds: float, warm: float) -> bool:
    folder = Path("data/processed") / day / capture
    packets = pq.read_table(folder / "packets.parquet",
                            filters=[("timestamp", ">=", start), ("timestamp", "<", start + seconds)]).to_pandas()
    packets = packets.sort_values("frame_no").drop(columns=["payload"]).to_dict("records")
    detector = replay(run, packets)
    live = [r for r in detector.log if "h" in r]
    summaries = {(r["summary_of"], round(r["t"], 6)): r for r in detector.log if "summary_of" in r}
    by_key = {(r["flow_key"], round(r["t"], 6)): r for r in live}
    sent = sum(1 for r in detector.log if "summary_of" in r and r["flow_time"] > by_key.get(
        (r["summary_of"], round(r["t"], 6)), {"t_obs": np.inf})["t_obs"] + 1e-6)

    events = pq.read_table(Path("data/events") / day / "events.parquet",
                           columns=["event_id", "t", "flow_uid", "has_packets", *HISTORY, *AGG_COLUMNS],
                           filters=[("capture", "=", capture), ("t", ">=", start + warm),
                                    ("t", "<", start + seconds - 130)]).to_pandas()
    events = events[events["has_packets"]]
    keys = pq.read_table(folder / "flows.parquet", columns=["flow_uid", "flow_key", "Tot Fwd Pkts",
                                                           "Tot Bwd Pkts"]).to_pandas()
    events = events.merge(keys, on="flow_uid")
    emb = pq.read_table(run / "embeddings" / "split" / day / "flow_embeddings.parquet",
                        columns=["event_id", "observation_time", "h"],
                        filters=[("event_id", "in", events["event_id"].tolist())]).to_pandas()
    events = events.merge(emb, on="event_id")
    # A connection already running when the replay starts is cut into 120 s pieces from where the replay first sees it,
    # not from its real start, so its pieces never line up with the whole-day ingest's. A service that keeps running
    # sees connections from their start; only the replay has this edge. Such connections are left out.
    before = pq.read_table(folder / "packets.parquet", columns=["flow_key"],
                           filters=[("timestamp", ">=", start - 3600), ("timestamp", "<", start)])
    running = set(before.column("flow_key").to_pylist())
    print(f"   left out: {int(events['flow_key'].isin(running).sum()):,} events of connections running before the "
          f"replay started")
    events = events[~events["flow_key"].isin(running)].reset_index(drop=True)
    matched = [(row, by_key.get((row.flow_key, round(row.t, 6)))) for row in events.itertuples()]
    found = [(e, r) for e, r in matched if r is not None]
    window = [r for r in live if start + warm <= r["t"] < start + seconds - 130 and r["flow_key"] not in running]
    # The offline packet map is an interval join on CICFlowMeter's second-resolution start times; it sometimes hands a
    # flow more packets than CICFlowMeter itself counted in it (the next connection's). Those events are the join's,
    # not CICFlowMeter's, and the live tracker -- which assigns packets as CICFlowMeter does -- rightly has no twin.
    joined = events["pkt_n"] > np.minimum(events["Tot Fwd Pkts"] + events["Tot Bwd Pkts"], 20)
    lost = [e for e, r in matched if r is None]
    artefacts = sum(bool(joined[e.Index]) for e in lost)
    usable = len(events) - artefacts
    print(f"2. {len(packets):,} packets -> {len(live):,} live events; training has {len(events):,} in the compared "
          f"window, {artefacts:,} of them with more packets from the offline join than CICFlowMeter counted; of the "
          f"other {usable:,} live found {len(found):,} ({len(found) / max(usable, 1):.1%}); live-only in the window: "
          f"{len(window) - len(found):,}")
    if not found:
        return False
    h_diff = np.array([np.abs(np.asarray(e.h) - r["h"]).max() for e, r in found])
    t_diff = np.array([abs(e.observation_time - r["t_obs"]) for e, r in found])
    print(f"   h (32): identical within 1e-4 on {np.mean(h_diff < 1e-4):.1%}, within 1e-2 on {np.mean(h_diff < 1e-2):.1%}"
          f" (median max-diff {np.median(h_diff):.1e})")
    print(f"   observation time: identical on {np.mean(t_diff < 1e-6):.1%}, later by up to 10 ms on the rest "
          f"(median {np.median(t_diff) * 1e3:.2f} ms)")
    for c in HISTORY:
        same = np.mean([np.isclose(getattr(e, c), r[c], atol=1e-3) for e, r in found])
        print(f"   {c}: same on {same:.1%}")
    agg = [(e, summaries.get((e.flow_key, round(e.t, 6)))) for e, _ in found]
    agg = [(e, s) for e, s in agg if s is not None]
    if agg:
        same = np.mean([np.allclose([getattr(e, c) for c in AGG_COLUMNS], s["summary"], rtol=1e-3, atol=1e-3)
                        for e, s in agg])
        late = np.array([s["known_at"] - s["flow_time"] for _, s in agg])
        print(f"   20-packet summary: identical on {same:.1%} of {len(agg):,}; known within 1 s of its time on "
              f"{np.mean(late <= 1):.1%}, median delay {np.median(late):.3f} s, 90th pct {np.quantile(late, 0.9):.1f} s")
    # What the summaries' lateness costs: the same replay with every summary queued the moment training would.
    oracle = {k: (s["summary"], s["flow_time"]) for k, s in summaries.items()}
    exact = {(r["flow_key"], round(r["t"], 6)): r for r in replay(run, packets, oracle).log if "h" in r}
    pairs = [(r, exact[k]) for k, r in by_key.items() if k in exact]
    p_live, p_exact = np.stack([a["probability"] for a, _ in pairs]), np.stack([b["probability"] for _, b in pairs])
    th = np.array([detector.heads.thresholds.get(f) or np.inf for f in detector.heads.families])
    flip = np.mean(((p_live >= th) != (p_exact >= th)).any(1))
    s_change = max(float(np.abs(a["s"] - b["s"]).max()) for a, b in pairs)
    print(f"   late summaries ({sent:,} sent to link memory): largest change in s {s_change:.3f}, in probability "
          f"{np.abs(p_live - p_exact).max():.4f}; verdict changed on {flip:.2%} of {len(pairs):,} events")
    return len(found) >= 0.95 * usable and np.mean(h_diff < 1e-2) >= 0.95


def verdict_check(run: Path, day: str, warmup: float = 600.0) -> bool:
    saved = torch.load(run / "detector" / f"scores_{day}.pt", weights_only=False)
    t_obs, code, probability = (np.asarray(saved[k]) for k in ("t_obs", "test_code", "test"))
    benign = code == 0
    hours = (t_obs[benign] // 3600).astype(int)
    hour = int(np.bincount(hours - hours.min()).argmax() + hours.min())
    events = pq.read_table(Path("data/events") / day / "events.parquet", columns=["capture", "t"],
                           filters=[("t", ">=", hour * 3600.0), ("t", "<", hour * 3600.0 + 3600)]).to_pandas()
    tested = set(np.round(t_obs[benign], 6))
    events = events[[round(t + 0.01, 6) in tested for t in events["t"]]]
    capture = events["capture"].value_counts().index[0]
    start = float(events.loc[events["capture"] == capture, "t"].min())
    packets = pq.read_table(Path("data/processed") / day / capture / "packets.parquet",
                            filters=[("timestamp", ">=", start - warmup), ("timestamp", "<", start + 1200)]).to_pandas()
    detector = replay(run, packets.sort_values("frame_no").drop(columns=["payload"]).to_dict("records"))
    at = {round(t, 6): i for i, t in enumerate(t_obs)}
    pairs = [(r, at[round(r["t_obs"], 6)]) for r in detector.log
             if "h" in r and r["t"] >= start and round(r["t_obs"], 6) in at]
    # Training's stream is every capture of the day merged: a host that talks to several captured machines carries
    # all of that in its context. One capture replayed alone -- like one sensor -- sees only its own share, so an event
    # of such a host is compared only when its hosts appear in no other capture over the replayed span.
    window = pq.read_table(Path("data/events") / day / "events.parquet",
                           columns=["capture", "src_node_id", "dst_node_id"],
                           filters=[("t", ">=", start - warmup), ("t", "<", start + 1200)]).to_pandas()
    ips = pq.read_table(Path("data/events") / day / "node_index.parquet", columns=["node_id", "ip"]).to_pandas()
    ip = dict(zip(ips["node_id"], ips["ip"]))
    other = window[window["capture"] != capture]
    shared = {ip[n] for n in np.r_[other["src_node_id"].to_numpy(), other["dst_node_id"].to_numpy()]}
    endpoints = lambda key: {part.rsplit(":", 1)[0] for part in key.split("|")[:2]}
    local = [(r, i) for r, i in pairs if not endpoints(r["flow_key"]) & shared]
    columns = [detector.heads.families.index(f) for f in saved["families"]]
    threshold = np.array([detector.heads.thresholds[f] for f in saved["families"]])
    everything = np.stack([r["probability"][columns] for r, _ in pairs])
    differs = int(((everything >= threshold) != (probability[[i for _, i in pairs]][:, 1:] >= threshold)).any(1).sum())
    pairs = local
    live = np.stack([r["probability"][columns] for r, _ in pairs])
    offline = probability[[i for _, i in pairs]][:, 1:]
    rate_live, rate_offline = (live >= threshold).mean(0), (offline >= threshold).mean(0)
    print(f"3. {len(pairs):,} benign test events of {capture}, replayed after {warmup / 60:.0f} minutes of warm-up: above threshold "
          + ", ".join(f"{f} {a:.2%} live / {b:.2%} training" for f, a, b in zip(saved["families"], rate_live,
                                                                              rate_offline))
          + f"; median probability difference {np.median(np.abs(live - offline)):.1e}. Left out: "
          f"{len(everything) - len(pairs):,} events with a host also seen by other captures (training's context "
          f"includes them); across all {len(everything):,} events the verdict differs on {differs}")
    # The pass rule is on verdicts, over every event: training batches the whole network's stream 512 events at a time
    # and a replayed capture batches only its own, so link memory is refreshed at other moments, which moves the scores
    # of bursts on one link (measured: one 5-event port probe, 0.37% of events, at the 0.01% thresholds; none at 0.1%).
    return differs <= 0.01 * len(everything)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--day", default="Thursday-15-02-2018")
    parser.add_argument("--capture", default="UCAP172.31.69.25")
    parser.add_argument("--start", type=float, default=1518707112)
    parser.add_argument("--seconds", type=float, default=300)
    parser.add_argument("--warm", type=float, default=60, help="seconds of history before flows are compared")
    parser.add_argument("--events", type=int, default=20_000, help="stream slice for check 1")
    parser.add_argument("--warmup", type=float, default=600.0,
                        help="seconds of traffic replayed before the events check 3 compares, to warm link memory")
    args = parser.parse_args(argv)
    ok = encoder_check(args.run, args.day, args.events)
    ok &= packet_check(args.run, args.day, args.capture, args.start, args.seconds, args.warm)
    ok &= verdict_check(args.run, args.day, args.warmup)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
