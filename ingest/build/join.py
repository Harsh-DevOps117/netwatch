"""Per-capture artefacts derived from flows and packets.

Two stages of the pipeline live here, both reading what packets.py and flows.py
produced for one capture:

  build_edges()            flows.parquet -> edges.parquet
                           flows reduced to graph shape with an epoch clock

  build_flow_packet_map()  flows + packets -> flow_packet_map.parquet
                           the interval join that resolves the granularity
                           mismatch between the two modalities

Neither bins time. edges.parquet is an edge LIST ordered by event time, and the
"windows" in build_flow_packet_map are per-flow [start, end] intervals, not
fixed time bins -- see docs/design.md Blocks 4 and 5.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from ingest.sources.flows import LABEL_COLUMNS


# ===========================================================================
# Stage 4 -- graph edges
# ===========================================================================

GRAPH_COLUMNS = [
    "Timestamp",
    "flow_key",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    *LABEL_COLUMNS,
]


def build_edges(
    flow_parquet: Path,
    output: Path,
    *,
    batch_size: int = 100_000,
) -> int:
    """
    Reduce flows to graph-shaped edges with an epoch clock.

    Input:  flows.parquet path, output path, batch size
    Output: rows written

    One row per flow. Streams Arrow batches; the flow table is never fully
    resident.
    """
    flow_parquet = Path(flow_parquet)
    output = Path(output)

    if not flow_parquet.is_file():
        raise FileNotFoundError(
            f"Flow Parquet does not exist: {flow_parquet}"
        )

    output.parent.mkdir(parents=True, exist_ok=True)

    parquet = pq.ParquetFile(flow_parquet)

    writer = None
    total = 0

    try:
        for batch in parquet.iter_batches(
            batch_size=batch_size,
            columns=GRAPH_COLUMNS,
        ):
            df = batch.to_pandas()

            if df.empty:
                continue

            required = [
                "Src IP",
                "Dst IP",
                "Src Port",
                "Dst Port",
                "Protocol",
            ]

            df = df.dropna(subset=required)

            if df.empty:
                continue

            df["Src IP"] = df["Src IP"].astype(str)
            df["Dst IP"] = df["Dst IP"].astype(str)

            df["Src Port"] = pd.to_numeric(
                df["Src Port"], errors="coerce"
            )
            df["Dst Port"] = pd.to_numeric(
                df["Dst Port"], errors="coerce"
            )
            df["Protocol"] = pd.to_numeric(
                df["Protocol"], errors="coerce"
            )

            df = df.dropna(
                subset=["Src Port", "Dst Port", "Protocol"]
            )

            if df.empty:
                continue

            df["Src Port"] = df["Src Port"].astype("int32")
            df["Dst Port"] = df["Dst Port"].astype("int32")
            df["Protocol"] = df["Protocol"].astype("int16")

            # The flow Timestamp is UTC but parses naive, so the epoch is
            # subtracted directly. Do not switch to datetime.timestamp():
            # stdlib reads a naive value in the HOST timezone, pandas reads it
            # as UTC, and only the latter matches packets.parquet.
            timestamp_dt = pd.to_datetime(
                df["Timestamp"], format="mixed", dayfirst=True, errors="coerce"
            )
            timestamp_epoch = (
                timestamp_dt - pd.Timestamp("1970-01-01")
            ).dt.total_seconds()

            edges = pd.DataFrame(
                {
                    "timestamp": timestamp_epoch,
                    "flow_key": df["flow_key"],
                    "src_ip": df["Src IP"],
                    "src_port": df["Src Port"],
                    "dst_ip": df["Dst IP"],
                    "dst_port": df["Dst Port"],
                    "protocol": df["Protocol"],
                    "duration": df["Flow Duration"],
                    "fwd_packets": df["Tot Fwd Pkts"],
                    "bwd_packets": df["Tot Bwd Pkts"],
                    "label": df["Label"],
                    "attack_name": df["attack_name"],
                    "label_source": df["label_source"],
                    "label_confidence": df["label_confidence"],
                    "label_direction": df["label_direction"],
                }
            )

            table = pa.Table.from_pandas(
                edges,
                preserve_index=False,
            )

            if writer is None:
                writer = pq.ParquetWriter(
                    output,
                    table.schema,
                    compression="zstd",
                )

            writer.write_table(table)
            total += len(edges)

    finally:
        if writer is not None:
            writer.close()

    return total


# ===========================================================================
# Stage 5 -- flow <-> packet interval join
# ===========================================================================

MAP_FLOW_COLUMNS = ["flow_uid", "flow_key", "Timestamp", "Flow Duration"]
PACKET_COLUMNS = ["frame_no", "flow_key", "timestamp"]

# Bump whenever attribution logic changes. Stored in the file's schema metadata,
# so pipeline.py rebuilds a map written by older logic instead of reusing it.
MAP_VERSION = "3-contain-fallback"

MAP_SCHEMA = pa.schema(
    [
        ("frame_no", pa.int64()),
        ("flow_uid", pa.string()),
        ("flow_key", pa.string()),
    ],
    metadata={b"map_version": MAP_VERSION.encode()},
)


def map_is_current(path: Path) -> bool:
    """Whether a flow_packet_map was written by the current attribution logic.

    Input:  map path
    Output: True when its schema metadata carries MAP_VERSION
    """
    try:
        metadata = pq.read_schema(path).metadata or {}
    except (OSError, pa.ArrowInvalid):
        return False
    return metadata.get(b"map_version") == MAP_VERSION.encode()


def _flow_windows(flow_parquet: Path, slack_seconds: float) -> pd.DataFrame:
    """Load flows as [start, end] epoch-second windows."""
    flows = pq.read_table(flow_parquet, columns=MAP_FLOW_COLUMNS).to_pandas()

    start = pd.to_datetime(
        flows["Timestamp"], format="mixed", dayfirst=True, errors="coerce"
    )
    # Naive value is UTC by construction (CICFlowMeter runs under
    # -Duser.timezone=UTC), so subtracting the epoch is the correct conversion.
    start_epoch = (start - pd.Timestamp("1970-01-01")).dt.total_seconds()

    # "Flow Duration" is microseconds.
    duration = pd.to_numeric(flows["Flow Duration"], errors="coerce").fillna(0) / 1e6

    windows = pd.DataFrame(
        {
            "flow_uid": flows["flow_uid"].astype("string"),
            "flow_key": flows["flow_key"].astype("string"),
            "start": start_epoch,
            "end": start_epoch + duration + slack_seconds,
        }
    )
    # Ties on start are common: CICFlowMeter timestamps are whole seconds, so a
    # connection's forward part and the server's reverse continuation often
    # share one. merge_asof takes the LAST tied row, so order ties by end and
    # the widest window, which covers every packet of that second, wins. An
    # arbitrary pick dropped 581,719 Friday packets.
    return windows.dropna(subset=["start", "flow_key"]).sort_values(["start", "end"], kind="stable")


def build_flow_packet_map(
    flow_parquet: Path,
    packet_parquet: Path,
    output: Path,
    *,
    slack_seconds: float = 1.0,
    batch_size: int = 1_000_000,
) -> int:
    """Write flow_packet_map.parquet. Returns the number of packets mapped.

    MEMORY
    ------
    The first implementation read every packet into one DataFrame and ran a
    single merge_asof. On the Friday attack capture -- 18,888,225 packets
    against 3,622,934 flows -- that died with

        MemoryError: Unable to allocate 144. MiB for an array with
        shape (18888225,) and data type int64

    and it died on the ONE capture that holds all the attack traffic. Packets
    are now streamed in batches while only the flow windows stay resident, and
    the join carries int32 row indices rather than flow_uid strings so
    merge_asof works on numeric columns.
    """
    flow_parquet = Path(flow_parquet)
    packet_parquet = Path(packet_parquet)
    output = Path(output)

    for path in (flow_parquet, packet_parquet):
        if not path.is_file():
            raise FileNotFoundError(f"required input missing: {path}")

    windows = _flow_windows(flow_parquet, slack_seconds)

    # flow_key -> int32 code, shared by both sides. Comparing ints instead of
    # strings inside merge_asof is what keeps the resident set small.
    codes, uniques = pd.factorize(windows["flow_key"], sort=False)
    lookup = pd.Index(uniques)
    flow_uids = windows["flow_uid"].to_numpy()

    right = pd.DataFrame(
        {
            "code": codes.astype("int32"),
            "start": windows["start"].to_numpy(),
            "end": windows["end"].to_numpy(),
            "row": range(len(windows)),
        }
    ).sort_values("start", kind="stable")
    right["row"] = right["row"].astype("int32")

    output.parent.mkdir(parents=True, exist_ok=True)

    writer: pq.ParquetWriter | None = None
    mapped = 0

    try:
        parquet = pq.ParquetFile(packet_parquet)
        for batch in parquet.iter_batches(batch_size=batch_size, columns=PACKET_COLUMNS):
            left = batch.to_pandas()
            if left.empty:
                continue

            key = left["flow_key"].astype("string")
            left["code"] = lookup.get_indexer(key).astype("int32")  # -1 == unknown

            # Packets are written in capture order, so this is already sorted;
            # the sort is cheap insurance because merge_asof requires it.
            left = left.sort_values("timestamp", kind="stable")

            merged = pd.merge_asof(
                left[["frame_no", "flow_key", "timestamp", "code"]],
                right,
                left_on="timestamp",
                right_on="start",
                by="code",
                direction="backward",
                allow_exact_matches=True,
            )

            # merge_asof only enforces start <= t. Drop the attribution when the
            # packet falls past the end of that flow's window -- otherwise a
            # packet in a gap between two flows is charged to the earlier one.
            outside = merged["end"].isna() | (merged["timestamp"] > merged["end"])

            # merge_asof sees only the latest start, so a later, shorter flow of
            # the same key shadows an earlier one that still covers the packet
            # (2,584 Friday packets). Fall back to the latest-starting window that
            # contains it. Only would-be-dropped packets are retried, so no
            # existing attribution changes.
            retry = outside & (merged["code"] >= 0)
            if retry.any():
                lost = merged.loc[retry, ["timestamp", "code"]].reset_index()
                cand = lost.merge(right[right["code"].isin(lost["code"])], on="code")
                cand = cand[(cand["start"] <= cand["timestamp"]) & (cand["timestamp"] <= cand["end"])]
                best = cand.sort_values("start", kind="stable").groupby("index").tail(1).set_index("index")
                merged.loc[best.index, "row"] = best["row"]
                merged.loc[best.index, "end"] = best["end"]
                outside = merged["end"].isna() | (merged["timestamp"] > merged["end"])
            rows = merged["row"].to_numpy(dtype="float64")
            uid = pd.Series(pd.NA, index=merged.index, dtype="string")
            inside = ~outside.to_numpy()
            if inside.any():
                uid.iloc[inside] = flow_uids[rows[inside].astype("int64")]

            result = pd.DataFrame(
                {
                    "frame_no": merged["frame_no"].astype("int64"),
                    "flow_uid": uid,
                    "flow_key": merged["flow_key"].astype("string"),
                }
            ).sort_values("frame_no", kind="stable")

            mapped += int(result["flow_uid"].notna().sum())

            table = pa.Table.from_pandas(result, schema=MAP_SCHEMA, preserve_index=False)
            if writer is None:
                writer = pq.ParquetWriter(output, MAP_SCHEMA, compression="zstd")
            writer.write_table(table)
    except BaseException:
        if writer is not None:
            writer.close()
            writer = None
        output.unlink(missing_ok=True)
        raise
    finally:
        if writer is not None:
            writer.close()

    return mapped


def load_joined(capture_dir: Path, flow_columns: list[str] | None = None):
    """Join packets to their containing flow.

    Input:  capture directory, optional flow columns to attach
    Output: one row per packet, flow columns suffixed _flow on collision

    Packets with no containing flow (ICMP, IGMP, capture-edge fragments) keep a
    null flow_uid rather than being dropped.
    """
    capture_dir = Path(capture_dir)
    mapping = pq.read_table(capture_dir / "flow_packet_map.parquet").to_pandas()
    packets = pq.read_table(capture_dir / "packets.parquet").to_pandas()

    columns = flow_columns or ["flow_uid", "Label", "attack_name", "label_direction"]
    if "flow_uid" not in columns:
        columns = ["flow_uid", *columns]
    flows = pq.read_table(capture_dir / "flows.parquet", columns=columns).to_pandas()

    out = packets.merge(
        mapping[["frame_no", "flow_uid"]], on="frame_no", how="left",
        suffixes=("", "_map"),
    )
    return out.merge(flows, on="flow_uid", how="left", suffixes=("_pkt", "_flow"))
