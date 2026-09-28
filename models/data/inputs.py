"""Model inputs: one row per event holding its flow statistics, packet aggregates and first K packets."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from ingest.build.events import AGG_COLUMNS, DEFAULT_K_PACKETS
from ingest.sources.flows import BENIGN_LABEL

CICFLOWMETER_COLUMNS = [
    "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
    "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
    "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Len", "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s",
    "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
    "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt",
    "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt", "Down/Up Ratio",
    "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg",
    "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts",
    "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

# This CICFlowMeter build writes the flow's absolute epoch time (microseconds)
# into Idle on about half of all flows and zero into Active on every flow.
ACTIVE_IDLE_COLUMNS = CICFLOWMETER_COLUMNS[-8:]

X_COLUMNS = [c for c in CICFLOWMETER_COLUMNS if c not in ACTIVE_IDLE_COLUMNS]

PACKET_FEATURES = [
    "length", "ttl", "tcp_window",
    "tcp_flag_syn", "tcp_flag_ack", "tcp_flag_fin",
    "tcp_flag_rst", "tcp_flag_psh", "tcp_flag_urg",
    "payload_len", "tcp_retransmission", "frag", "direction",
]
LOG_PACKET_FEATURES = ["length", "ttl", "tcp_window", "payload_len"]

# Read straight from packets.parquet; "frag" and "direction" are derived below.
PACKET_SOURCE_COLUMNS = [c for c in PACKET_FEATURES if c not in ("frag", "direction")]

FORBIDDEN_MODEL_COLUMNS = {
    "src_ip", "dst_ip", "src_port", "dst_port", "capture", "flow_uid", "day",
    "Src IP", "Dst IP", "Src Port", "Dst Port", "Flow ID", "flow_key",
    "src_node_id", "dst_node_id", "event_id", "t", "Timestamp",
    "Label", "label", "attack_name", "label_source", "label_confidence", "label_direction",
    *ACTIVE_IDLE_COLUMNS,
}

EVENT_READ_COLUMNS = ["event_id", "t", "flow_uid", "capture", *AGG_COLUMNS, "label"]

# Forecast target: the completed flow's aggregates, kept beside the prefix. Training-only --
# never an input.
FUTURE_FIELDS = ("a_future",)

CACHE_VERSION = "1"

CACHED_ARRAYS = ("event_id", "t", "attack", "x", "a", "pkt", "dt", "n_pkt")


def check_features(columns) -> None:
    """Fail closed when an identity, label or clock column is used as a feature.

    Input:  feature column names
    Output: None; raises ValueError on any forbidden name
    """
    leaked = FORBIDDEN_MODEL_COLUMNS & set(columns)
    if leaked:
        raise ValueError(f"forbidden columns in feature tensor: {sorted(leaked)}")


def read_events(
    day_events_dir: Path, rows: np.ndarray | None = None, columns: list[str] = EVENT_READ_COLUMNS,
) -> pd.DataFrame:
    """Read event columns batch by batch, keeping only the requested rows.

    Input:  events directory of one day, sorted row positions or None for every row, columns
    Output: event frame of those rows in event_id order; label and capture as categoricals
    """
    file = pq.ParquetFile(
        Path(day_events_dir) / "events.parquet",
        read_dictionary=[c for c in ("label", "capture") if c in columns],
    )
    parts, start = [], 0
    for batch in file.iter_batches(batch_size=1_000_000, columns=columns):
        end = start + len(batch)
        if rows is not None:
            batch = batch.take(pa.array(rows[(rows >= start) & (rows < end)] - start))
        parts.append(batch)
        start = end
    return pa.Table.from_batches(parts).to_pandas()


def load_inputs(
    events: pd.DataFrame, day_dir: Path, k: int = DEFAULT_K_PACKETS, readers: int = 4,
) -> dict[str, np.ndarray]:
    """Gather each event's flow statistics and first K packets, aligned to the event rows.

    Input:  event rows from read_events, processed directory of the same day, K,
            captures read concurrently
    Output: dict of arrays: event_id, t, attack, x (L, 68), a (L, 20), pkt (L, K, 13),
            dt (L, K) seconds since the flow's previous packet, n_pkt (L,), first_sender (L,) the IP that sent
            the flow's first packet -- the host whose packets are direction 0 -- or "" for a flow without packets

    x_f is never a model input; observe() reads its Flow Duration only to tag the population.
    Captures are read on threads because the cost is parquet IO, and each capture
    writes its own disjoint rows of the output arrays.
    """
    check_features([*X_COLUMNS, *AGG_COLUMNS, *PACKET_FEATURES])
    events = events.reset_index(drop=True)
    n = len(events)
    uids = events["flow_uid"].to_numpy()
    data = {
        "event_id": events["event_id"].to_numpy(np.int64),
        "t": events["t"].to_numpy(np.float64),
        "attack": (events["label"] != BENIGN_LABEL["Label"]).to_numpy(),
        "x": np.zeros((n, len(X_COLUMNS)), np.float32),
        "a": events[AGG_COLUMNS].to_numpy(np.float32),
        "pkt": np.zeros((n, k, len(PACKET_FEATURES)), np.float32),
        "dt": np.zeros((n, k), np.float32),
        "n_pkt": np.zeros(n, np.int16),
        "first_sender": np.full(n, "", dtype=object),
    }
    groups = events.groupby("capture", sort=False, observed=True).indices.items()
    with ThreadPoolExecutor(max_workers=readers) as pool:
        list(pool.map(
            lambda group: _fill_capture(Path(day_dir) / group[0], uids[group[1]], group[1], k, data),
            groups,
        ))

    # Block 6 counted the same first-K packets; any disagreement is a lost or
    # duplicated packet, or a subgraph spanning two flows.
    expected = np.minimum(events["pkt_n"].to_numpy(), k)
    if not np.array_equal(np.minimum(data["n_pkt"], DEFAULT_K_PACKETS), expected):
        bad = int((np.minimum(data["n_pkt"], DEFAULT_K_PACKETS) != expected).sum())
        raise RuntimeError(f"{bad} events disagree with Block 6 on their packet count")
    return data


def _fill_capture(capture_dir: Path, uids: np.ndarray, rows: np.ndarray, k: int, data: dict) -> None:
    """Write one capture's flow statistics and packets into the output arrays.

    Input:  capture directory, its events' flow_uids, their row positions, K, arrays
    Output: None; fills data["x"] and the packet arrays in place
    """
    file = pq.ParquetFile(capture_dir / "flows.parquet")
    wanted = pa.array(uids.tolist(), file.schema_arrow.field("flow_uid").type)
    flows = pa.Table.from_batches([
        batch.filter(pc.is_in(batch["flow_uid"], wanted))
        for batch in file.iter_batches(batch_size=250_000, columns=["flow_uid", *X_COLUMNS])
    ]).to_pandas().set_index("flow_uid")
    data["x"][rows] = flows.loc[uids, X_COLUMNS].to_numpy(np.float32)
    _fill_packets(capture_dir, uids, rows, k, data)


def _fill_packets(capture_dir: Path, uids: np.ndarray, rows: np.ndarray, k: int, data: dict) -> None:
    """Write the first K packets of the given flows into the packet arrays.

    Input:  capture directory, flow_uids, their row positions, K, arrays from load_inputs
    Output: None; fills data["pkt"], data["dt"], data["n_pkt"], data["first_sender"] in place
    """
    mapping = pq.read_table(
        capture_dir / "flow_packet_map.parquet", columns=["frame_no", "flow_uid"],
        filters=[("flow_uid", "in", list(uids))],
    ).to_pandas()
    if mapping.empty:
        return
    packets = pq.read_table(
        capture_dir / "packets.parquet",
        columns=["frame_no", "timestamp", "src_ip", "ip_flag_mf", "ip_frag_offset", *PACKET_SOURCE_COLUMNS],
        filters=[("frame_no", "in", mapping["frame_no"].tolist())],
    ).to_pandas()

    joined = mapping.merge(packets, on="frame_no", how="inner").sort_values(["flow_uid", "frame_no"])
    joined = joined.groupby("flow_uid", sort=False).head(k)
    grouped = joined.groupby("flow_uid", sort=False)
    joined["direction"] = (
        joined["src_ip"].astype(str) != grouped["src_ip"].transform("first").astype(str)
    ).astype(np.float32)
    joined["frag"] = (
        (joined["ip_flag_mf"] > 0) | (joined["ip_frag_offset"] > 0)
    ).astype(np.float32)
    # Out-of-order capture timestamps would make a negative gap and a NaN log.
    gap = grouped["timestamp"].diff().fillna(0.0).clip(lower=0.0)

    position = pd.Index(uids)
    row = rows[position.get_indexer(joined["flow_uid"])]
    slot = grouped.cumcount().to_numpy()
    data["pkt"][row, slot] = joined[PACKET_FEATURES].to_numpy(np.float32)
    data["dt"][row, slot] = gap.to_numpy(np.float32)
    counts = grouped.size()
    data["n_pkt"][rows[position.get_indexer(counts.index)]] = counts.to_numpy()
    first = grouped["src_ip"].first()
    data["first_sender"][rows[position.get_indexer(first.index)]] = first.astype(str).to_numpy()


def cached_inputs(
    events: pd.DataFrame, day_dir: Path, k: int = DEFAULT_K_PACKETS,
    cache: Path | None = None, readers: int = 4,
) -> dict[str, np.ndarray]:
    """Build the model inputs, reusing an earlier build of the same rows.

    Input:  event rows, processed day directory, K, cache directory or None, readers
    Output: same arrays as load_inputs, memory-mapped when they came from the cache

    Reading the parquet files is minutes per day and does not change between
    runs; the cache is keyed on the exact event ids so a different sample cannot
    silently reuse it.
    """
    if cache is None:
        return load_inputs(events, day_dir, k, readers)
    cache = Path(cache)
    event_ids = events["event_id"].to_numpy(np.int64)
    fingerprint = {
        "version": CACHE_VERSION,
        "day": Path(day_dir).name,
        "k": k,
        "rows": len(event_ids),
        "event_ids_sha256": hashlib.sha256(event_ids.tobytes()).hexdigest()[:16],
        "x_columns": len(X_COLUMNS),
        "packet_features": PACKET_FEATURES,
    }
    meta = cache / "meta.json"
    if meta.is_file() and json.loads(meta.read_text()) == fingerprint:
        return {name: np.load(cache / f"{name}.npy", mmap_mode="r") for name in CACHED_ARRAYS}

    data = load_inputs(events, day_dir, k, readers)
    cache.mkdir(parents=True, exist_ok=True)
    for name in CACHED_ARRAYS:
        np.save(cache / f"{name}.npy", data[name])
    meta.write_text(json.dumps(fingerprint))
    return data


def signed_log(values: np.ndarray) -> np.ndarray:
    """Compress heavy-tailed magnitudes while keeping sign.

    Input:  array
    Output: float32 array of sign(v) * log(1 + |v|), with NaN and infinities set to 0 first
    """
    v = np.nan_to_num(values.astype(np.float64), nan=0.0, posinf=0.0, neginf=0.0)
    return (np.sign(v) * np.log1p(np.abs(v))).astype(np.float32)


def normalise(data: dict, stats: dict | None = None, rows: np.ndarray | None = None) -> tuple[dict, dict]:
    """Signed-log then standardise the aggregate and packet features and the forecast target.

    Input:  arrays from load_inputs; stats from an earlier call, or None with the rows to fit on
    Output: (copy of the arrays with a, pkt (and a_future) normalised and padded packet slots zero, stats)
    """
    out = dict(data)
    k = data["pkt"].shape[1]
    valid = np.arange(k) < data["n_pkt"][:, None]
    a, pkt = signed_log(data["a"]), data["pkt"].copy()
    logged = [PACKET_FEATURES.index(c) for c in LOG_PACKET_FEATURES]
    pkt[..., logged] = signed_log(pkt[..., logged])
    futures = {n: signed_log(data[n]) for n in FUTURE_FIELDS if n in data}
    if stats is None:
        stats = {"a": _moments(a[rows]), "pkt": _moments(pkt[rows][valid[rows]])}
        stats.update({n: _moments(v[rows]) for n, v in futures.items()})
    out["a"] = (a - stats["a"][0]) / stats["a"][1]
    pkt -= stats["pkt"][0]
    pkt /= stats["pkt"][1]
    pkt *= valid[..., None]
    out["pkt"] = pkt
    for name, value in futures.items():
        out[name] = (value - stats[name][0]) / stats[name][1]
    return out, stats


def _moments(values: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Column mean and standard deviation, with constant columns given unit scale.

    Input:  (N, D) array
    Output: (mean, std), each (D,) float32
    """
    mean = values.mean(axis=0)
    std = values.std(axis=0)
    return mean.astype(np.float32), np.where(std < 1e-6, 1.0, std).astype(np.float32)
