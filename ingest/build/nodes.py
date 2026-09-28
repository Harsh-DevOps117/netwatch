"""Per-host features in fixed time windows -- a BASELINE, not the main path.

The pipeline is event-based (see events.py): the model consumes a continuous
stream of interactions, not binned snapshots. This module bins anyway, and is
kept for three narrower purposes:

  * a baseline to compare the event model against,
  * a sanity check that host-level behaviour separates at all,
  * visualisation and reconnaissance features.

Do not put it on the main path. Binning at 10s makes the label distribution
0.04% attack (796 of 2,063,888 rows) because a DoS compresses 3.6M flows into a
handful of windows, and most windows are near-empty. The event stream keeps
every interaction and spends no capacity on silence.

What it does provide, which edges.parquet does not: edges.parquet is an edge
LIST, so hosts carry no features of their own. This derives them.

Aggregation is day-level, across every capture, because one host appears in many
captures and its true degree is the union of all of them.

Output columns, per (window_start, ip):

    window_start    float64  UTC epoch, floor of the window
    ip              string
    out_flows       flows where this host was the source
    in_flows        flows where it was the destination
    out_peers       distinct hosts it contacted
    in_peers        distinct hosts that contacted it
    out_ports       distinct destination ports it dialled   <- port-scan signal
    listen_ports    distinct of its own ports contacted     <- being scanned
    out_packets     packets it sent
    in_packets      packets it received
    out_mean_dur    mean duration of flows it opened, seconds
    label           most severe label touching this host in this window
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

EDGE_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "dst_port",
    "duration", "fwd_packets", "bwd_packets", "label",
]

FEATURE_COLUMNS = [
    "out_flows", "in_flows", "out_peers", "in_peers",
    "out_ports", "listen_ports", "out_packets", "in_packets", "out_mean_dur",
]


def _read_day_edges(day_dir: Path, drop_bad_timestamps: bool) -> pd.DataFrame:
    frames = []
    for path in sorted(day_dir.glob("*/edges.parquet")):
        frames.append(pq.read_table(path, columns=EDGE_COLUMNS).to_pandas())
    if not frames:
        raise FileNotFoundError(f"no edges.parquet under {day_dir}")
    edges = pd.concat(frames, ignore_index=True)

    if drop_bad_timestamps:
        # A small number of flows carry epochs near 0 from malformed captures.
        # Harmless for labels, but they would create phantom windows decades
        # away from the capture.
        median = edges["timestamp"].median()
        keep = (edges["timestamp"] - median).abs() < 86_400
        edges = edges.loc[keep]

    for column in ("src_ip", "dst_ip"):
        edges[column] = edges[column].astype("category")
    return edges


def build_node_table(
    day_dir: Path,
    output: Path,
    *,
    window_seconds: int = 10,
    drop_bad_timestamps: bool = True,
) -> int:
    """Write nodes.parquet for one dataset day. Returns the row count."""
    day_dir = Path(day_dir)
    edges = _read_day_edges(day_dir, drop_bad_timestamps)

    edges["window_start"] = (
        edges["timestamp"] // window_seconds * window_seconds
    )
    edges["duration_s"] = edges["duration"] / 1e6

    # Each edge contributes an OUT row to its source and an IN row to its
    # destination, so one groupby per direction and then a join.
    out = (
        edges.groupby(["window_start", "src_ip"], observed=True)
        .agg(
            out_flows=("dst_ip", "size"),
            out_peers=("dst_ip", "nunique"),
            out_ports=("dst_port", "nunique"),
            out_packets=("fwd_packets", "sum"),
            out_mean_dur=("duration_s", "mean"),
        )
        .rename_axis(["window_start", "ip"])
    )
    inn = (
        edges.groupby(["window_start", "dst_ip"], observed=True)
        .agg(
            in_flows=("src_ip", "size"),
            in_peers=("src_ip", "nunique"),
            listen_ports=("dst_port", "nunique"),
            in_packets=("bwd_packets", "sum"),
        )
        .rename_axis(["window_start", "ip"])
    )

    nodes = out.join(inn, how="outer")
    for column in FEATURE_COLUMNS:
        if column not in nodes.columns:
            nodes[column] = 0.0
    nodes[FEATURE_COLUMNS] = nodes[FEATURE_COLUMNS].fillna(0.0)

    nodes["label"] = _window_host_labels(edges).reindex(nodes.index).fillna("Benign")

    nodes = nodes.reset_index()
    nodes["ip"] = nodes["ip"].astype(str)
    nodes = nodes[["window_start", "ip", *FEATURE_COLUMNS, "label"]]

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(
        pa.Table.from_pandas(nodes, preserve_index=False),
        output,
        compression="zstd",
    )
    return len(nodes)


def _window_host_labels(edges: pd.DataFrame) -> pd.Series:
    """Label for each (window, host).

    Input:  edge frame with window_start and label
    Output: series indexed by (window_start, ip)

    A host is labelled by traffic at either end: a DoS victim is in the attack
    window as much as the attacker. Any non-Benign label wins, unambiguous
    because config.py has no overlapping rules within a day.
    """
    attack = edges.loc[edges["label"] != "Benign"]
    if attack.empty:
        return pd.Series(dtype="object")

    both = pd.concat(
        [
            attack[["window_start", "src_ip", "label"]].rename(columns={"src_ip": "ip"}),
            attack[["window_start", "dst_ip", "label"]].rename(columns={"dst_ip": "ip"}),
        ]
    )
    return both.groupby(["window_start", "ip"], observed=True)["label"].first()


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("day", help="e.g. Friday-16-02-2018")
    parser.add_argument("--processed-root", type=Path, default=Path("data/processed"))
    parser.add_argument("--output-root", type=Path, default=Path("data/nodes"))
    parser.add_argument(
        "--window-seconds", type=int, default=10,
        help="bin width in seconds (default 10)",
    )
    args = parser.parse_args(argv)

    out = args.output_root / args.day / "nodes.parquet"
    n = build_node_table(
        args.processed_root / args.day, out, window_seconds=args.window_seconds
    )
    print(f"{n:,} (window, host) rows -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
