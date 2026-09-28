from __future__ import annotations

from pathlib import Path
import os
import tempfile

from ingest.sources.schedule import ATTACKS, label_config_version
from ingest.sources.flows import (
    LabelMatcher,
    csv_to_parquet,
    find_flow_csvs,
    run_cicflowmeter,
)
from ingest.build.join import build_edges, build_flow_packet_map, map_is_current
from ingest.sources.packets import PACKETS_VERSION, pcap_to_parquet



def output_version(day: str) -> str:
    """Fingerprint of everything a capture's outputs depend on.

    Input:  dataset day
    Output: version string stored beside the outputs

    That day's attack rules plus the packet parser: a change to either makes
    existing outputs unsafe to reuse. Per day, so a rule added to one day does
    not force every other day to be rebuilt.
    """
    return f"{label_config_version(day)}+packets-{PACKETS_VERSION}"



def _version_file(output_dir: Path) -> Path:
    return output_dir / ".label_config_version"


def _read_version(output_dir: Path) -> str | None:
    try:
        return _version_file(output_dir).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _write_version(output_dir: Path, day: str) -> None:
    path = _version_file(output_dir)
    fd, tmp_name = tempfile.mkstemp(prefix=".label_config_version.", dir=output_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(output_version(day) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def _invalidate_labeled_outputs(output_dir: Path, day: str) -> None:
    """Remove outputs produced under a different labelling config or packet parser."""
    if _read_version(output_dir) == output_version(day):
        return

    for name in (
        "packets.parquet",
        "flows.parquet",
        "edges.parquet",
        "flow_packet_map.parquet",
    ):
        (output_dir / name).unlink(missing_ok=True)

    # The version marker is written only after the complete capture succeeds.
    _version_file(output_dir).unlink(missing_ok=True)


def process_capture(
    cfm_dir: Path,
    pcap_dir: Path,
    output_dir: Path,
    day: str,
    *,
    pcap: Path,
) -> tuple[int, int]:
    """Process one capture into packets, flows, edges and the flow<->packet map.

    Input:  CICFlowMeter directory, capture directory, output directory, day,
            the capture to process
    Output: (flow rows, edge rows)

    CICFlowMeter is handed the exact capture, not its parent directory: given
    a directory it processes every capture in it, which breaks parallel
    workers. Existing outputs are reused only when their labelling fingerprint
    matches the current attack table and logic.
    """

    cfm_dir = Path(cfm_dir).resolve()
    pcap_dir = Path(pcap_dir).resolve()
    output_dir = Path(output_dir).resolve()
    pcap = Path(pcap).resolve()

    # Validate inputs

    if not cfm_dir.is_dir():
        raise FileNotFoundError(
            f"CICFlowMeter directory not found: {cfm_dir}"
        )

    if not pcap_dir.is_dir():
        raise FileNotFoundError(
            f"PCAP directory not found: {pcap_dir}"
        )

    if not pcap.is_file():
        raise FileNotFoundError(
            f"PCAP does not exist: {pcap}"
        )

    # Prevent accidental processing of a PCAP from another
    # directory when the caller supplies an inconsistent path.
    try:
        pcap.relative_to(pcap_dir)
    except ValueError:
        raise ValueError(
            f"PCAP {pcap} is not inside PCAP directory {pcap_dir}"
        )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Output written under a different attack table, labelling logic or packet
    # parser is unsafe to reuse; the fingerprint check discards it.
    _invalidate_labeled_outputs(output_dir, day)

    day_attacks = [attack for attack in ATTACKS if attack["day"] == day]
    if not day_attacks:
        raise ValueError(f"No attack timeline configured for dataset day {day!r}")
    label_matcher = LabelMatcher(day_attacks, day)

    packet_parquet = output_dir / "packets.parquet"
    flow_dir = output_dir / "csv"
    flow_parquet = output_dir / "flows.parquet"
    edge_parquet = output_dir / "edges.parquet"

    # 1. Packet provenance

    if not _valid_parquet(packet_parquet):
        packet_parquet.unlink(
            missing_ok=True
        )

        packet_rows = pcap_to_parquet(
            pcap,
            packet_parquet,
            label_matcher=label_matcher,
        )

        if packet_rows == 0:
            raise RuntimeError(
                "TShark produced no valid packet records."
            )

    # 2. CICFlowMeter

    csvs = find_flow_csvs(flow_dir, pcap)

    if not csvs:
        flow_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        # The exact PCAP, not pcap_dir: given a directory CICFlowMeter would
        # process every capture in it, breaking parallel workers.
        run_cicflowmeter(
            cfm_dir,
            pcap,
            flow_dir,
        )

        csvs = find_flow_csvs(flow_dir, pcap)

    if not csvs:
        raise RuntimeError(
            "CICFlowMeter completed but produced "
            "no Flow CSV files."
        )

    # 3. Flows

    if not _valid_parquet(flow_parquet):
        flow_parquet.unlink(
            missing_ok=True
        )

        rows = csv_to_parquet(
            csvs,
            flow_parquet,
            day=day,
            matcher=label_matcher,
        )

        if rows == 0:
            raise RuntimeError(
                "Flow conversion produced zero rows."
            )

    else:
        rows = _parquet_rows(
            flow_parquet
        )

    # 4. Graph edges

    if not _valid_parquet(edge_parquet):
        edge_parquet.unlink(
            missing_ok=True
        )

        edges = build_edges(
            flow_parquet,
            edge_parquet,
        )

        if edges == 0:
            raise RuntimeError(
                "Edge generation produced zero rows."
            )

    else:
        edges = _parquet_rows(
            edge_parquet
        )

    # 5. Flow <-> packet mapping
    #
    # flow_key is not unique (CICFlowMeter reopens a flow for the same 5-tuple
    # after FIN/timeout), so this is an interval join, not a merge on the key.
    # See derive.py.

    map_parquet = output_dir / "flow_packet_map.parquet"

    # A map from older attribution logic is rebuilt; packets and flows are kept.
    if not _valid_parquet(map_parquet) or not map_is_current(map_parquet):
        map_parquet.unlink(missing_ok=True)

        mapped = build_flow_packet_map(
            flow_parquet,
            packet_parquet,
            map_parquet,
        )

        print(
            f"[ALIGN] {output_dir.name}: {mapped:,} packets mapped to flows",
            flush=True,
        )

    _write_version(output_dir, day)

    return rows, edges


def _valid_parquet(path: Path) -> bool:
    """Check that a Parquet file is readable and non-empty.

    Input:  path
    Output: True when it opens and holds at least one row and one column
    """

    path = Path(path)

    if not path.is_file():
        return False

    try:
        if path.stat().st_size == 0:
            return False
    except OSError:
        return False

    try:
        import pyarrow.parquet as pq

        metadata = pq.read_metadata(path)

        return (
            metadata.num_rows > 0
            and metadata.num_columns > 0
        )

    except Exception:
        return False


def _parquet_rows(path: Path) -> int:
    """Return Parquet row count without loading the data."""

    import pyarrow.parquet as pq

    return pq.read_metadata(path).num_rows
