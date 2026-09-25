"""Block 8 input: per-event side features at the observation time, and who sent which side.

Run: uv run python -m models.context_encoder.features --days DAY [DAY ...] --out data/context_features
Writes <out>/<day>/side_features.parquet, one row per event in event order.

Block 7's sides are defined by the flow's first captured packet: direction 0 is its sender. Block 6's src / dst is
the flow record's orientation, which disagrees with that sender on part of every day (reversed records), so links
that receive one side's embedding are keyed here on the actual sender and receiver.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from ingest.build.events import DEFAULT_K_PACKETS
from models.data.inputs import EVENT_READ_COLUMNS, PACKET_FEATURES, load_inputs
from models.data.prefix import DEFAULT_BUDGET_MS, observe

DIRECTION = PACKET_FEATURES.index("direction")
SCHEMA = pa.schema([
    ("event_id", pa.int64()),
    ("sender_node_id", pa.int32()),
    ("receiver_node_id", pa.int32()),
    ("request_packets", pa.int16()),
    ("response_packets", pa.int16()),
    ("reply_latency_s", pa.float32()),
    ("direction_changes", pa.int16()),
    ("no_reply", pa.bool_()),
])


def side_features(data: dict) -> dict[str, np.ndarray]:
    """What each side has sent by the observation time, computed without any learned model.

    Input:  arrays after observe(): pkt (N, K, F) with the direction column, dt (N, K), n_pkt (N,)
    Output: request_packets, response_packets (packets of direction 0 / 1 seen), reply_latency_s (seconds from the
            first packet to the first response packet, -1 when none was seen), direction_changes (turns between
            consecutive seen packets), no_reply (no response packet seen)

    These carry what single-side encoders cannot see: how fast and how often the two sides answer each other.
    """
    k = data["dt"].shape[1]
    seen = np.arange(k) < data["n_pkt"][:, None]
    response = (data["pkt"][..., DIRECTION] > 0.5) & seen
    offset = np.cumsum(data["dt"], axis=1)
    has_reply = response.any(1)
    first_reply = response.argmax(1)
    latency = np.where(has_reply, offset[np.arange(len(offset)), first_reply], -1.0)
    turns = (response[:, 1:] != response[:, :-1]) & seen[:, 1:]
    return {
        "request_packets": (seen & ~response).sum(1).astype(np.int16),
        "response_packets": response.sum(1).astype(np.int16),
        "reply_latency_s": latency.astype(np.float32),
        "direction_changes": turns.sum(1).astype(np.int16),
        "no_reply": ~has_reply,
    }


def orient(src_node: np.ndarray, dst_node: np.ndarray, src_ip: np.ndarray, dst_ip: np.ndarray,
           first_sender: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Sender and receiver node of each event: the host that sent the first packet, and the other one.

    Input:  event src / dst node ids and their IPs, first packet sender IP per event ("" for no packets)
    Output: (sender node id, receiver node id); a flow without packets keeps the record's src -> dst
    Raises: ValueError when a first sender is neither endpoint of its event
    """
    first_sender = first_sender.astype(str)
    is_src = first_sender == src_ip.astype(str)
    is_dst = first_sender == dst_ip.astype(str)
    empty = first_sender == ""
    bad = ~(is_src | is_dst | empty)
    if bad.any():
        raise ValueError(f"{int(bad.sum())} events have a first packet sent by neither endpoint")
    flip = is_dst & ~is_src
    return np.where(flip, dst_node, src_node).astype(np.int32), np.where(flip, src_node, dst_node).astype(np.int32)


def export_side_features(day: str, events_root: Path, processed_root: Path, out_dir: Path,
                         budget_ms: float = DEFAULT_BUDGET_MS, chunk: int = 200_000, readers: int = 4,
                         limit: int | None = None) -> int:
    """Stream one day and write its side features, one row per event in event order.

    Input:  day, event and processed roots, output directory, observation budget, events per chunk, capture
            readers, optional row cap
    Output: rows written; writes <out_dir>/side_features.parquet
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    source = Path(events_root) / day
    ips = pq.read_table(source / "node_index.parquet", columns=["node_id", "ip"]).to_pandas().set_index("node_id")["ip"]
    reader = pq.ParquetFile(source / "events.parquet", read_dictionary=["label", "capture"])
    total = min(reader.metadata.num_rows, limit or reader.metadata.num_rows)
    writer, written = None, 0
    for batch in reader.iter_batches(batch_size=chunk, columns=[*EVENT_READ_COLUMNS, "src_node_id", "dst_node_id"]):
        events = batch.to_pandas()
        if written + len(events) > total:
            events = events.iloc[: total - written]
        if events.empty:
            break
        data = load_inputs(events.drop(columns=["src_node_id", "dst_node_id"]), Path(processed_root) / day,
                           DEFAULT_K_PACKETS, readers)
        src, dst = events["src_node_id"].to_numpy(), events["dst_node_id"].to_numpy()
        sender, receiver = orient(src, dst, ips.reindex(src).to_numpy(), ips.reindex(dst).to_numpy(), data["first_sender"])
        table = pa.Table.from_pydict({"event_id": data["event_id"], "sender_node_id": sender,
                                      "receiver_node_id": receiver, **side_features(observe(data, budget_ms / 1000))},
                                     schema=SCHEMA)
        if writer is None:
            writer = pq.ParquetWriter(out_dir / "side_features.parquet", SCHEMA, compression="zstd")
        writer.write_table(table)
        written += len(events)
        print(f"  {day}: {written:,}/{total:,}", flush=True)
        if written >= total:
            break
    if writer is not None:
        writer.close()
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--days", nargs="+", required=True)
    parser.add_argument("--out", type=Path, default=Path("data/context_features"))
    parser.add_argument("--events-root", type=Path, default=Path("data/events"))
    parser.add_argument("--processed-root", type=Path, default=Path("data/processed"))
    parser.add_argument("--budget-ms", type=float, default=DEFAULT_BUDGET_MS)
    parser.add_argument("--readers", type=int, default=4)
    parser.add_argument("--limit", type=int, default=None, help="stop each day after this many events")
    args = parser.parse_args(argv)
    for day in args.days:
        rows = export_side_features(day, args.events_root, args.processed_root, args.out / day, args.budget_ms,
                                    readers=args.readers, limit=args.limit)
        print(f"{day}: wrote {rows:,} rows", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
