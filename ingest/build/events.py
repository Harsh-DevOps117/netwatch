"""Build the continuous-time event stream: one event per flow, globally ordered.

This is the graph representation the encoder consumes. It is deliberately the
last stage before any model code -- nothing here imports torch.

An event is a single flow, i.e. one interaction between two hosts, following the
CTG formulation of Duan et al. (Continuous Temporal Graph, §IV-A): the graph has
no fixed adjacency matrix and no fixed node set, and an interaction is the
quadruple <Src IP, Dst IP, Time, Index>. A host seen for the first time simply
gets a new id; nothing needs retraining.

TIMESTAMPS ARE CORRECTED HERE, AND IT MATTERS
---------------------------------------------
CICFlowMeter writes flow timestamps at one-second resolution. Used directly,
99.7% of consecutive events have dt == 0 and up to 8,568 events share a single
timestamp, which leaves a time encoder nothing to encode. The true start of a
flow is the timestamp of its first packet, available at microsecond resolution
through flow_packet_map. Measured on one capture:

    CICFlowMeter 1s : 5,521 distinct timestamps of 13,845, 60.1% zero dt
    first packet    : 13,841 distinct timestamps of 13,845,  0.0% zero dt
                      median nonzero dt 0.073 s

WHAT IS AND IS NOT IN THE OUTPUT
--------------------------------
events.parquet carries the event index, the inter-event times, the per-source
port access pattern, the flow's orientation, and packet-level aggregates
computed here. It does NOT duplicate the 77 CICFlowMeter columns --
those already exist in flows.parquet and are joined on flow_uid at model time.
Copying them would add ~3 GB per day for no new information.

Packet aggregates summarise the first K packets of each flow. K = 20 follows
Farrukh et al. (XG-NID §3.1.1); the distribution measured here agrees, with 89.5% of flows
holding 20 packets or fewer (p50 = 6, p90 = 21).
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

DEFAULT_K_PACKETS = 20

PACKET_COLUMNS = [
    "frame_no", "timestamp", "src_ip", "src_port",
    "length", "ttl", "tcp_window", "payload_len",
    "tcp_flag_syn", "tcp_flag_ack", "tcp_flag_fin",
    "tcp_flag_rst", "tcp_flag_psh", "tcp_flag_urg",
    "tcp_retransmission", "ip_flag_mf", "ip_frag_offset",
]

# Aggregates over the first K packets. Names are the encoder's input feature
# names; keep them stable, the model contract refers to them.
AGG_COLUMNS = [
    "pkt_n", "pkt_len_mean", "pkt_len_std",
    "ttl_mean", "ttl_std", "win_mean", "win_std",
    "iat_mean", "iat_std", "iat_max",
    "syn_n", "ack_n", "fin_n", "rst_n", "psh_n", "urg_n",
    "payload_bytes", "payload_frac",
    "retrans_n", "frag_n",
]

# Derived per-event context. Computed across events, not within a flow, so they
# are not part of a_f. Each uses only strictly earlier events of the same host.
CONTEXT_COLUMNS = ["dt_src", "dt_dst", "port_delta", "dst_port_new"]

EVENT_COLUMNS = [
    "event_id", "t", "src_node_id", "dst_node_id", *CONTEXT_COLUMNS,
    "flow_uid", "capture", "has_packets", "reversed", *AGG_COLUMNS, "label",
]


def _packet_aggregates(capture_dir: Path, k_packets: int) -> pd.DataFrame:
    """Corrected start time and first-K-packet statistics, per flow_uid."""
    mapping = pq.read_table(
        capture_dir / "flow_packet_map.parquet", columns=["frame_no", "flow_uid"]
    ).to_pandas().dropna(subset=["flow_uid"])

    available = set(pq.read_schema(capture_dir / "packets.parquet").names)
    columns = [c for c in PACKET_COLUMNS if c in available]
    # src_ip as a dictionary: the big capture joins 18.9M packets, and plain
    # strings would cost ~40 B each for a column read only on SYN rows.
    packets = pq.read_table(
        capture_dir / "packets.parquet", columns=columns, read_dictionary=["src_ip"]
    ).to_pandas()

    joined = mapping.merge(packets, on="frame_no", how="inner")
    if joined.empty:
        return pd.DataFrame(columns=["flow_uid", "t", *AGG_COLUMNS, "syn_src_ip", "syn_src_port"])

    # First K packets of each flow, in capture order. frame_no is the original
    # capture index, so sorting on it is the true packet order.
    joined = joined.sort_values(["flow_uid", "frame_no"])
    joined = joined.groupby("flow_uid", sort=False).head(k_packets)

    # Inter-arrival time within a flow. The first packet of each flow has no
    # predecessor, so its gap is undefined rather than zero.
    joined["iat"] = joined.groupby("flow_uid", sort=False)["timestamp"].diff()

    grouped = joined.groupby("flow_uid", sort=False)
    out = pd.DataFrame({
        "t": grouped["timestamp"].min(),
        "pkt_n": grouped["timestamp"].size(),
        "pkt_len_mean": grouped["length"].mean(),
        "pkt_len_std": grouped["length"].std().fillna(0.0),
        "iat_mean": grouped["iat"].mean().fillna(0.0),
        "iat_std": grouped["iat"].std().fillna(0.0),
        "iat_max": grouped["iat"].max().fillna(0.0),
    })
    for name, column in (("ttl", "ttl"), ("win", "tcp_window")):
        if column in joined.columns:
            out[f"{name}_mean"] = grouped[column].mean()
            out[f"{name}_std"] = grouped[column].std().fillna(0.0)
        else:
            out[f"{name}_mean"] = 0.0
            out[f"{name}_std"] = 0.0
    for flag in ("syn", "ack", "fin", "rst", "psh", "urg"):
        column = f"tcp_flag_{flag}"
        out[f"{flag}_n"] = grouped[column].sum() if column in joined.columns else 0.0

    # Retransmissions and fragmentation, both named in the problem statement.
    # Counted over the same first-K window as the other aggregates.
    out["retrans_n"] = (
        grouped["tcp_retransmission"].sum()
        if "tcp_retransmission" in joined.columns else 0.0
    )
    if "ip_flag_mf" in joined.columns:
        joined["_frag"] = (
            (joined["ip_flag_mf"] > 0) | (joined["ip_frag_offset"] > 0)
        ).astype("int8")
        out["frag_n"] = joined.groupby("flow_uid", sort=False)["_frag"].sum()
    else:
        out["frag_n"] = 0.0

    # Payload is absent from output written before it was added to the packet
    # schema; those captures get zeros rather than failing.
    if "payload_len" in joined.columns:
        joined["_has_payload"] = (joined["payload_len"] > 0).astype("float32")
        out["payload_bytes"] = grouped["payload_len"].sum()
        out["payload_frac"] = joined.groupby("flow_uid", sort=False)["_has_payload"].mean()
    else:
        out["payload_bytes"] = 0.0
        out["payload_frac"] = 0.0

    # A flow that opens with a bare SYN (SYN set, ACK clear) names its client:
    # the SYN's sender. Only the first packet is read, so the value exists at
    # the flow's start and needs no observation gate.
    first = joined.groupby("flow_uid", sort=False).head(1)
    syn = first[(first["tcp_flag_syn"] == 1) & (first["tcp_flag_ack"] == 0)].set_index("flow_uid")
    out["syn_src_ip"] = syn["src_ip"].astype("string")
    out["syn_src_port"] = syn["src_port"]

    return out.reset_index()


def _mark_reversed(events: pd.DataFrame) -> pd.DataFrame:
    """Mark records whose source is the responder rather than the initiator.

    Input:  capture event frame with src_ip, src_port, dst_port, syn_src_ip,
            syn_src_port
    Output: the same frame with reversed added and the helper columns dropped

    reversed = 1 when the record runs server -> client, 0 when client -> server,
    -1 when neither rule applies. When the flow's first packet is a bare SYN,
    its sender is the client; otherwise the side on the higher (ephemeral) port
    is. On real Friday captures the port rule agrees with the SYN 95.9% of the
    time.

    Built from packets and ports only, never from labels: this is the
    label-free counterpart of label_direction.
    """
    src_port = pd.to_numeric(events["src_port"], errors="coerce")
    dst_port = pd.to_numeric(events["dst_port"], errors="coerce")
    by_port = np.select([src_port < dst_port, src_port > dst_port], [1.0, 0.0], default=-1.0)
    has_syn = events["syn_src_ip"].notna().to_numpy()
    client_is_src = (
        (events["syn_src_ip"].astype("string") == events["src_ip"].astype("string"))
        & (pd.to_numeric(events["syn_src_port"], errors="coerce") == src_port)
    ).fillna(False).to_numpy(dtype=bool)
    events["reversed"] = np.where(
        has_syn, np.where(client_is_src, 0.0, 1.0), by_port
    ).astype("float32")
    return events.drop(columns=["syn_src_ip", "syn_src_port"])


def _capture_events(capture_dir: Path, k_packets: int) -> pd.DataFrame | None:
    needed = ("flows.parquet", "packets.parquet", "flow_packet_map.parquet")
    if not all((capture_dir / n).is_file() for n in needed):
        return None

    aggregates = _packet_aggregates(capture_dir, k_packets)

    flows = pq.read_table(
        capture_dir / "flows.parquet",
        columns=[
            "flow_uid", "flow_key", "Src IP", "Dst IP",
            "Src Port", "Dst Port", "Timestamp", "Label",
        ],
    ).to_pandas()

    # LEFT join, not inner. A flow whose packets were attributed to its
    # opposite-direction twin gets no aggregates, and dropping it here loses
    # 20,281 conversations outright -- see build_event_stream, which removes
    # only the ones a twin actually represents.
    events = flows.merge(aggregates, on="flow_uid", how="left")
    events = events.rename(
        columns={
            "Src IP": "src_ip", "Dst IP": "dst_ip",
            "Src Port": "src_port", "Dst Port": "dst_port", "Label": "label",
        }
    )
    events["has_packets"] = events["t"].notna()
    events = _mark_reversed(events)

    # Fall back to the CICFlowMeter start time for flows with no packets. It is
    # only second-resolution, which is why has_packets is exported: the encoder
    # can mask these, and the degraded timestamp stays visible.
    fallback = pd.to_datetime(
        events["Timestamp"], format="mixed", dayfirst=True, errors="coerce"
    )
    fallback = (fallback - pd.Timestamp("1970-01-01")).dt.total_seconds()
    events["t"] = events["t"].fillna(fallback)
    events[AGG_COLUMNS] = events[AGG_COLUMNS].fillna(0.0)

    events = events.drop(columns=["Timestamp"])
    events["capture"] = capture_dir.name
    return events.dropna(subset=["t"])


def build_event_stream(
    day_dir: Path,
    output_dir: Path,
    *,
    k_packets: int = DEFAULT_K_PACKETS,
) -> int:
    """Build the day's event stream.

    Input:  day directory of processed captures, output directory, K packets
    Output: number of events; writes events.parquet and node_index.parquet
    """
    day_dir = Path(day_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    frames = []
    for capture_dir in sorted(p for p in day_dir.iterdir() if p.is_dir()):
        events = _capture_events(capture_dir, k_packets)
        if events is not None and not events.empty:
            frames.append(events)
    if not frames:
        raise FileNotFoundError(f"no usable captures under {day_dir}")

    events = pd.concat(frames, ignore_index=True)
    del frames

    # Drop flows whose packets carry epochs from malformed captures; they would
    # sort decades away from the rest of the stream.
    median = events["t"].median()
    events = events.loc[(events["t"] - median).abs() < 86_400]

    # CICFlowMeter emits a forward and a reverse biflow for one conversation.
    # Whichever of the pair the interval join gave the packets to is the record
    # retained; its twin is the same conversation seen from the other side and
    # would double-count it. Measured on Friday: 605,069 of 625,350 packet-less
    # conversations are duplicates like this, and the remaining 20,281 (133,453
    # records, all Benign) exist ONLY as packet-less flows -- those are kept.
    # groupby-transform rather than a Python set of flow_key strings: at 7.7M
    # keys the set alone costs several GB and dominates the run.
    events["flow_key"] = events["flow_key"].astype("category")
    represented = events.groupby("flow_key", observed=True)["has_packets"].transform("max")
    events = events.loc[events["has_packets"] | ~represented]
    events = events.drop(columns=["flow_key"])

    # Global time order. Ties are broken by capture then flow_uid so the stream
    # is reproducible rather than dependent on filesystem ordering.
    events = events.sort_values(["t", "capture", "flow_uid"], kind="stable")
    events = events.reset_index(drop=True)
    events["event_id"] = np.arange(len(events), dtype="int64")

    node_index = _build_node_index(events)
    ids = node_index.set_index("ip")["node_id"]
    events["src_node_id"] = events["src_ip"].map(ids).astype("int32")
    events["dst_node_id"] = events["dst_ip"].map(ids).astype("int32")

    events["dt_src"] = _time_since_last_seen(events, "src_node_id")
    events["dt_dst"] = _time_since_last_seen(events, "dst_node_id")
    events = _port_access_features(events)

    events = events[EVENT_COLUMNS]
    for column in AGG_COLUMNS + CONTEXT_COLUMNS + ["reversed"]:
        events[column] = events[column].astype("float32")

    pq.write_table(
        pa.Table.from_pandas(events, preserve_index=False),
        output_dir / "events.parquet",
        compression="zstd",
    )
    pq.write_table(
        pa.Table.from_pandas(node_index, preserve_index=False),
        output_dir / "node_index.parquet",
        compression="zstd",
    )
    return len(events)


def _build_node_index(events: pd.DataFrame) -> pd.DataFrame:
    """Assign an integer id per host, ordered by first appearance.

    Input:  event frame with t, src_ip, dst_ip
    Output: frame of node_id, ip, first_seen_t, n_events

    First-appearance order means a prefix of the stream uses a prefix of the
    ids, keeping embedding tables dense under truncation.
    """
    endpoints = pd.concat([
        events[["t", "src_ip"]].rename(columns={"src_ip": "ip"}),
        events[["t", "dst_ip"]].rename(columns={"dst_ip": "ip"}),
    ])
    first = endpoints.groupby("ip", sort=False)["t"].agg(["min", "size"])
    first = first.sort_values("min").reset_index()
    first.columns = ["ip", "first_seen_t", "n_events"]
    first["node_id"] = np.arange(len(first), dtype="int32")
    return first[["node_id", "ip", "first_seen_t", "n_events"]]


def _port_access_features(events: pd.DataFrame) -> pd.DataFrame:
    """Port-scan signal for each event, from the initiator's own earlier events.

    Input:  time-sorted event frame with src_node_id, dst_node_id, src_port,
            dst_port and reversed
    Output: the same frame with port_delta and dst_port_new added

    The problem statement asks for "sequential or randomised port access
    patterns". A scan is visible only across flows, so it cannot be an
    aggregate over one flow's packets:

        port_delta    the port this initiator dialled minus its previous one.
                      A sequential sweep holds it at +-1; a randomised sweep
                      spreads it over the port space; a client returning to a
                      service leaves it at 0. Zero on an initiator's first event.
        dst_port_new  1 when this initiator has never dialled this port.
                      Near-constant 1 is fan-out; a scan's defining shape.

    Keyed on the initiator and the port it dialled, not on the record's src:
    when reversed == 1 the src is the responder. Keyed on src, the Friday Hulk
    victim scored as a sequential sweeper of the attacker's ephemeral ports
    (port_delta +2 on 60.7% of 1.75M events). Both features read only earlier
    rows of the time-sorted stream.
    """
    rev = (events["reversed"] == 1).to_numpy()
    client = pd.Series(
        np.where(rev, events["dst_node_id"], events["src_node_id"]), index=events.index
    )
    # One coerced series for both features, so an unparsable port is -1 in both
    # rather than -1 in one and a dropped NaN group in the other.
    port = pd.Series(
        np.where(
            rev,
            pd.to_numeric(events["src_port"], errors="coerce"),
            pd.to_numeric(events["dst_port"], errors="coerce"),
        ),
        index=events.index,
    ).fillna(-1)
    events["port_delta"] = port.groupby(client, sort=False).diff().fillna(0.0)
    seen = pd.DataFrame({"u": client, "p": port}).duplicated()
    events["dst_port_new"] = (~seen).astype("float32")
    return events


def _time_since_last_seen(events: pd.DataFrame, column: str) -> pd.Series:
    """Seconds since this endpoint last appeared.

    Input:  time-sorted event frame, endpoint column name
    Output: float series; -1 on an endpoint's first appearance

    -1 rather than 0 so cold start is distinguishable from two simultaneous
    events; the consumer branches on it.
    """
    gap = events.groupby(column, sort=False)["t"].diff()
    return gap.fillna(-1.0)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("day", help="e.g. Friday-16-02-2018")
    parser.add_argument("--processed-root", type=Path, default=Path("data/processed"))
    parser.add_argument("--output-root", type=Path, default=Path("data/events"))
    parser.add_argument(
        "--k-packets", type=int, default=DEFAULT_K_PACKETS,
        help=f"packets summarised per flow (default {DEFAULT_K_PACKETS})",
    )
    args = parser.parse_args(argv)

    out = args.output_root / args.day
    n = build_event_stream(
        args.processed_root / args.day, out, k_packets=args.k_packets
    )
    print(f"{n:,} events -> {out}/events.parquet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
