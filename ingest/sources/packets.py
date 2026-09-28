from __future__ import annotations

import os
import signal
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from datetime import date, datetime, timezone
from typing import Any, Callable

import pyarrow as pa
import pyarrow.parquet as pq

from ingest.sources.flows import (
    BENIGN_LABEL,
    LABEL_COLUMNS,
    LabelMatcher,
    SCHEDULE_UTC_OFFSET,
    canonical_flow_key,
)


# PACKET_FIELDS is the single source of truth for packets.parquet: the tshark
# command line, PACKET_COLUMNS and PACKET_SCHEMA are all derived from it, so
# adding or removing an entry needs no other change.
#
# required=True drops the whole packet when the field cannot be parsed. Reserve
# it for columns with no sensible fallback (endpoints, timestamp, length).


def _required_str_first(
    *tshark_fields: str,
) -> Callable[[dict[str, str]], str]:
    """First non-empty of several tshark fields, as a string.

    Input:  raw tshark field dict
    Output: the value; raises when every field is empty

    An endpoint address is in ip.src for IPv4 and ipv6.src for IPv6; exactly
    one is populated per packet, never both.
    """

    def _parse(raw: dict[str, str]) -> str:
        for tshark_field in tshark_fields:
            value = raw.get(tshark_field, "")
            if value:
                return value

        raise ValueError(f"none of {tshark_fields} present")

    return _parse


def _required_float(tshark_field: str) -> Callable[[dict[str, str]], float]:
    def _parse(raw: dict[str, str]) -> float:
        return float(raw[tshark_field])  # raises ValueError if empty

    return _parse


def _required_int(tshark_field: str) -> Callable[[dict[str, str]], int]:
    def _parse(raw: dict[str, str]) -> int:
        return int(raw[tshark_field])  # raises ValueError if empty

    return _parse


def _optional_int(
    *tshark_fields: str, default: int = 0
) -> Callable[[dict[str, str]], int]:
    """
    First non-empty of several tshark fields, as an int.

    Input:  raw tshark field dict
    Output: int, or `default` when every field is empty
    """

    def _parse(raw: dict[str, str]) -> int:
        for tshark_field in tshark_fields:
            value = raw.get(tshark_field, "")
            if value:
                return int(value)
        return default

    return _parse


# How many leading payload bytes to keep per packet. Full payload would be
# ~1500 B/packet; at ~98M packets that is >100 GB, so it is truncated. 128 B
# covers an HTTP request line plus Host header, which is where SQL-injection
# and XSS payloads appear in the CIC web-attack days. payload_len records the
# TRUE length, so truncation stays visible.
# Bump whenever extraction or parsing changes what packets.parquet contains.
# pipeline.py folds it into the output fingerprint, so a file written by an
# older parser is rebuilt instead of reused (change log 5m).
PACKETS_VERSION = "2-bool-true-false"

PAYLOAD_BYTES = 128


def _payload_bytes(raw: dict[str, str]) -> bytes:
    """First PAYLOAD_BYTES of transport payload.

    Input:  raw tshark field dict
    Output: bytes, empty when the packet carries no payload

    Reads tcp.payload / udp.payload, not data.data: tshark populates data.data
    only when it cannot dissect the upper layer, so a dissected HTTP request
    returns empty there.
    """
    for field in ("tcp.payload", "udp.payload"):
        value = raw.get(field, "")
        if value:
            return bytes.fromhex(value.replace(":", ""))[:PAYLOAD_BYTES]
    return b""


def payload_vector(payload: bytes, width: int = PAYLOAD_BYTES) -> "np.ndarray":
    """Fixed-width byte-value vector for one payload.

    Input:  payload bytes, target width
    Output: uint8 array of length `width`, zero-padded, truncated if longer

    Storage keeps raw bytes because a padded float vector for ~98M packets
    would cost tens of GB and fix one feature choice; this converts on demand.

    >>> payload_vector(b"GET", width=5)
    array([71, 69, 84,  0,  0], dtype=uint8)
    """
    import numpy as np

    out = np.zeros(width, dtype=np.uint8)
    if payload:
        chunk = np.frombuffer(payload[:width], dtype=np.uint8)
        out[: len(chunk)] = chunk
    return out


def _payload_len(raw: dict[str, str]) -> int:
    """True payload length in bytes, before truncation."""
    for field in ("tcp.payload", "udp.payload"):
        value = raw.get(field, "")
        if value:
            return len(value.replace(":", "")) // 2
    return 0


def _bool_field(tshark_field: str) -> Callable[[dict[str, str]], int]:
    """1 when a boolean field is set, else 0.

    Input:  raw tshark field dict
    Output: 0 or 1

    tshark 4.x prints booleans as "True"/"False"; older releases print "1"/"0".
    Both are accepted: matching only "1" zeroed every TCP flag under 4.6.4.
    """

    def _parse(raw: dict[str, str]) -> int:
        return 1 if raw.get(tshark_field, "").strip().lower() in ("1", "true") else 0

    return _parse


def _present_field(tshark_field: str) -> Callable[[dict[str, str]], int]:
    """1 when tshark emitted the field at all, else 0.

    Input:  raw tshark field dict
    Output: 0 or 1

    Analysis flags such as tcp.analysis.retransmission carry no value; their
    presence is the signal.
    """

    def _parse(raw: dict[str, str]) -> int:
        return 1 if raw.get(tshark_field, "") else 0

    return _parse


@dataclass(frozen=True)
class PacketField:
    name: str  # Column name in packets.parquet
    dtype: Any  # pyarrow dtype
    raw_fields: tuple[str, ...]  # TShark field name(s) this reads, in preference order
    parse: Callable[[dict[str, str]], Any]
    required: bool = False
    default: Any = 0


PACKET_FIELDS: list[PacketField] = [
    # Ports are read from tcp.* and udp.*: CIC-IDS2018 contains UDP attacks
    # (DDoS-LOIC-UDP), and requesting only tcp.* silently zeroes the port
    # signal for every one of them.
    PacketField("timestamp", pa.float64(), ("frame.time_epoch",), _required_float("frame.time_epoch"), required=True),
    PacketField("src_ip", pa.string(), ("ip.src", "ipv6.src"), _required_str_first("ip.src", "ipv6.src"), required=True, default=""),
    PacketField("dst_ip", pa.string(), ("ip.dst", "ipv6.dst"), _required_str_first("ip.dst", "ipv6.dst"), required=True, default=""),
    PacketField("src_port", pa.int32(), ("tcp.srcport", "udp.srcport"), _optional_int("tcp.srcport", "udp.srcport")),
    PacketField("dst_port", pa.int32(), ("tcp.dstport", "udp.dstport"), _optional_int("tcp.dstport", "udp.dstport")),
    # ipv6.nxt is the IPv6 equivalent of ip.proto. With extension headers it
    # names the next header rather than the transport protocol; acceptable
    # here because they are rare in this dataset.
    PacketField("protocol", pa.int32(), ("ip.proto", "ipv6.nxt"), _optional_int("ip.proto", "ipv6.nxt")),
    PacketField("length", pa.int32(), ("frame.len",), _required_int("frame.len"), required=True),

    # 1-based index within the ORIGINAL capture. tshark numbers frames per
    # input file, so _extract_tshark_chunk rebases by the chunk offset;
    # without that every 250k chunk restarts at 1. This is the join key of
    # flow_packet_map.parquet, so it must stay unique.
    PacketField("frame_no", pa.int64(), ("frame.number",), _required_int("frame.number"), required=True),
    # TTL / IPv6 hop limit: spoofing and OS-fingerprint signal.
    PacketField("ttl", pa.int32(), ("ip.ttl", "ipv6.hlim"), _optional_int("ip.ttl", "ipv6.hlim")),
    # Cheaper for a model than inferring the family from the address string.
    PacketField("is_ipv6", pa.int8(), ("ipv6.src",), lambda raw: 1 if raw.get("ipv6.src") else 0),
    # TCP receive window, 0 for non-TCP.
    PacketField("tcp_window", pa.int32(), ("tcp.window_size",), _optional_int("tcp.window_size")),
    # Per-packet, unlike CICFlowMeter's per-flow flag counts: keeps the
    # sequencing that flow-level aggregation discards.
    PacketField("tcp_flag_syn", pa.int8(), ("tcp.flags.syn",), _bool_field("tcp.flags.syn")),
    PacketField("tcp_flag_ack", pa.int8(), ("tcp.flags.ack",), _bool_field("tcp.flags.ack")),
    PacketField("tcp_flag_fin", pa.int8(), ("tcp.flags.fin",), _bool_field("tcp.flags.fin")),
    PacketField("tcp_flag_rst", pa.int8(), ("tcp.flags.reset",), _bool_field("tcp.flags.reset")),
    PacketField("tcp_flag_psh", pa.int8(), ("tcp.flags.push",), _bool_field("tcp.flags.push")),
    PacketField("tcp_flag_urg", pa.int8(), ("tcp.flags.urg",), _bool_field("tcp.flags.urg")),

    # Transport payload. Header features alone cannot see SQL injection or XSS
    # -- those attacks leave flow statistics looking ordinary and live entirely
    # in the bytes. Needed for Thursday/Friday-23-02.
    # PS: "IP fragment flags". Fragmentation is a classic evasion signal and is
    # invisible at flow level.
    PacketField("ip_flag_df", pa.int8(), ("ip.flags.df",), _bool_field("ip.flags.df")),
    PacketField("ip_flag_mf", pa.int8(), ("ip.flags.mf",), _bool_field("ip.flags.mf")),
    PacketField("ip_frag_offset", pa.int32(), ("ip.frag_offset",), _optional_int("ip.frag_offset")),

    # PS: "retransmission counts". Requires tcp.analyze_sequence_numbers, which
    # is enabled in _make_tshark_command for this reason.
    PacketField("tcp_retransmission", pa.int8(), ("tcp.analysis.retransmission",),
                _present_field("tcp.analysis.retransmission")),

    PacketField("payload_len", pa.int32(), ("tcp.payload", "udp.payload"), _payload_len),
    PacketField("payload", pa.binary(), ("tcp.payload", "udp.payload"), _payload_bytes, default=b""),
]

# Computed, not a tshark field. Joins this packet to flows/edges.
_PAYLOAD_COLUMNS = ("payload_len", "payload")

PACKET_DERIVED_COLUMNS = ["flow_key"]

# Computed from the same LabelMatcher the flows use, so a packet cannot
# disagree with the flow containing it.
PACKET_LABEL_COLUMNS = list(LABEL_COLUMNS)

_BASE_PACKET_COLUMNS: list[str] = [f.name for f in PACKET_FIELDS]
PACKET_COLUMNS: list[str] = (
    _BASE_PACKET_COLUMNS + PACKET_DERIVED_COLUMNS + PACKET_LABEL_COLUMNS
)
PACKET_SCHEMA = pa.schema(
    [(f.name, f.dtype) for f in PACKET_FIELDS]
    + [(name, pa.string()) for name in PACKET_DERIVED_COLUMNS]
    + [(name, pa.string()) for name in PACKET_LABEL_COLUMNS]
)

# Deduplicated, order-preserving union of every PacketField's raw_fields: what
# is requested from tshark, and the order each output line is split against.
TSHARK_FIELDS: list[str] = []
_seen_tshark_fields: set[str] = set()
for _pfield in PACKET_FIELDS:
    for _raw_field in _pfield.raw_fields:
        if _raw_field not in _seen_tshark_fields:
            _seen_tshark_fields.add(_raw_field)
            TSHARK_FIELDS.append(_raw_field)


def _parse_packet_row(
    raw: dict[str, str],
    label_matcher: LabelMatcher | None = None,
) -> tuple | None:
    """Build one output row from one tshark line.

    Input:  raw tshark field dict, optional LabelMatcher
    Output: row tuple, or None when a required field will not parse

    A packet is dropped rather than written with a bad value.
    """
    row = []

    for pfield in PACKET_FIELDS:
        try:
            row.append(pfield.parse(raw))
        except (ValueError, TypeError, KeyError):
            if pfield.required:
                return None
            row.append(pfield.default)

    # Already parsed and coalesced, so the join key and the label see the same
    # endpoint representation as the output columns.
    base = dict(zip(_BASE_PACKET_COLUMNS, row))

    row.append(
        canonical_flow_key(
            base["src_ip"],
            base["src_port"],
            base["dst_ip"],
            base["dst_port"],
            base["protocol"],
        )
    )

    if label_matcher is not None:
        # frame.time_epoch is UTC; LabelMatcher shifts to schedule-local.
        label = label_matcher.label_packet(
            datetime.fromtimestamp(float(base["timestamp"]), tz=timezone.utc),
            str(base["src_ip"]),
            str(base["dst_ip"]),
            source_port=int(base["src_port"]),
            destination_port=int(base["dst_port"]),
            protocol=int(base["protocol"]),
        )
    else:
        label = BENIGN_LABEL

    row.extend(label[column] for column in PACKET_LABEL_COLUMNS)

    return tuple(row)


# tshark RSS grows with the capture it is handed: a whole CIC PCAP needed 14+
# GiB in one pass, while 250k packets holds it near 380 MB. Chunking is the
# memory-safety mechanism, so this must stay well below the per-worker ceiling.
DEFAULT_TSHARK_CHUNK_PACKETS = 250_000


def validate_pcap(path: Path) -> None:
    """Cheap validation before passing a PCAP to TShark."""
    path = Path(path)

    if not path.is_file():
        raise FileNotFoundError(
            f"PCAP does not exist: {path}"
        )

    if path.stat().st_size == 0:
        raise ValueError(
            f"PCAP is empty: {path}"
        )


# CIC-IDS2018 captures are named like "capPC1-172.31.64.106", where the
# trailing ".106" is an IP octet, not an extension. Path.stem strips it anyway,
# collapsing 21 distinct captures onto one name -- so only known pcap
# extensions are removed here.
_PCAP_SUFFIXES = (".pcap", ".pcapng", ".cap")


def capture_name(pcap: Path) -> str:
    """Output-directory name for one capture file.

    Input:  path to a capture
    Output: filename with only a genuine pcap extension removed

    Path.stem would strip a trailing IP octet, collapsing distinct captures
    onto one name.
    """
    name = Path(pcap).name
    for suffix in _PCAP_SUFFIXES:
        if name.lower().endswith(suffix):
            return name[: -len(suffix)]
    return name


# pcap magic -> byte order of the record headers that follow. pcapng has no
# fixed first-record offset, so its date is not checked.
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">",
    b"\x0a\x0d\x0d\x0a": None,
}


def capture_problem(path: Path, day: date | None = None) -> str | None:
    """Why a file cannot serve as a capture of `day`.

    Input:  file path, optional dataset day
    Output: the reason, or None when the file is usable

    Decided by content, never by name. Friday-02-03-2018 ships 17
    capture-named files that are entirely zero bytes, valid captures named
    UCAP<ip> or <ip>a that a name rule skipped, and misfiled captures from
    other days that the name rule skipped only by luck.
    """
    with open(path, "rb") as handle:
        head = handle.read(28)
    if head[:4] not in _PCAP_MAGIC:
        return "no pcap header"
    order = _PCAP_MAGIC[head[:4]]
    if day is None or order is None or len(head) < 28:
        return None
    first = datetime.fromtimestamp(struct.unpack(order + "I", head[24:28])[0], timezone.utc)
    local = (first + SCHEDULE_UTC_OFFSET).date()
    if local != day:
        return f"first packet is on {local}, not {day}"
    return None


def find_pcaps(
    root: Path,
    day: date | None = None,
    skipped: list[tuple[Path, str]] | None = None,
) -> list[Path]:
    """Find a day's capture files, recursively.

    Input:  directory to search, optional dataset day, optional list that
            receives (path, reason) for every rejected file
    Output: sorted list of paths

    A file is a capture when capture_problem() finds nothing wrong with it,
    whatever its name.
    """
    root = Path(root)

    if not root.is_dir():
        raise FileNotFoundError(
            f"PCAP root does not exist: {root}"
        )

    pcaps: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        problem = capture_problem(path, day)
        if problem is None:
            pcaps.append(path)
        elif skipped is not None:
            skipped.append((path, problem))
    return pcaps


def _terminate_process(process: subprocess.Popen) -> None:
    """
    Terminate TShark and its complete process group.
    """
    if process.poll() is not None:
        return

    try:
        if os.name != "nt":
            os.killpg(
                os.getpgid(process.pid),
                signal.SIGTERM,
            )
        else:
            process.terminate()

    except (ProcessLookupError, OSError):
        pass

    try:
        process.wait(timeout=5)

    except subprocess.TimeoutExpired:
        try:
            if os.name != "nt":
                os.killpg(
                    os.getpgid(process.pid),
                    signal.SIGKILL,
                )
            else:
                process.kill()

        except (ProcessLookupError, OSError):
            pass

        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def _write_batch(
    writer: pq.ParquetWriter | None,
    batch: list[tuple],
    output: Path,
) -> tuple[pq.ParquetWriter, int]:
    """Append one packet batch to the output file.

    Input:  open writer or None, batch of row tuples, output path
    Output: (writer, rows written); the writer is created on the first batch
    """
    if not batch:
        if writer is None:
            raise RuntimeError(
                "Cannot write an empty batch without a writer."
            )

        return writer, 0

    table = pa.Table.from_pylist(
        [
            dict(zip(PACKET_COLUMNS, row))
            for row in batch
        ],
        schema=PACKET_SCHEMA,
    )

    if writer is None:
        writer = pq.ParquetWriter(
            output,
            PACKET_SCHEMA,
            compression="zstd",
        )

    writer.write_table(table)

    return writer, len(batch)


def _valid_parquet(path: Path) -> bool:
    """
    Check whether a packet Parquet is readable and non-empty.
    """
    path = Path(path)

    if not path.is_file():
        return False

    if path.stat().st_size == 0:
        return False

    try:
        metadata = pq.read_metadata(path)
    except Exception:
        return False

    if metadata.num_rows <= 0:
        return False

    names = list(metadata.schema.names)
    if names == PACKET_COLUMNS:
        return True

    # Accept output written before the payload columns existed. Rebuilding it
    # needs the original PCAPs, which are routinely deleted after processing,
    # so invalidating here would destroy packet data that cannot be recovered.
    return names == [c for c in PACKET_COLUMNS if c not in _PAYLOAD_COLUMNS]


# Many CSE-CIC-IDS2018 PCAPs are cut short or corrupt mid-write. The readable
# prefix still parses cleanly, but the tools signal it differently:
#
#   editcap -c   exit 0,  writes the readable prefix, warns on stderr
#   tshark -r    exit 14, N good packets already written to stdout
#
# Treating any non-zero exit as fatal discards a whole capture over a damaged
# tail. The readable prefix is kept instead.

_TRUNCATION_MARKERS = (
    "appears to be damaged or corrupt",
    "appears to have been cut short",
    "less data than the packet header says",
    "unexpected end of file",
)


def _looks_truncated(diagnostics: str) -> bool:
    lowered = diagnostics.lower()
    return any(marker in lowered for marker in _TRUNCATION_MARKERS)


def _make_tshark_command(pcap: Path) -> list[str]:
    """
    Build the flat-field tshark command for one capture.

    Input:  path to a capture
    Output: argv list

    The -e arguments are generated from TSHARK_FIELDS, so field order here
    matches what _extract_tshark_chunk expects when splitting output lines.
    Reassembly stays off; chunking is the memory-safety mechanism.
    """
    command = [
        "tshark",
        "-r",
        str(pcap),

        "-n",

        "-T",
        "fields",
    ]

    for tshark_field in TSHARK_FIELDS:
        command += ["-e", tshark_field]

    command += [
        "-E",
        "separator=\t",

        "-E",
        "quote=n",

        "-E",
        "occurrence=f",

        # Reassembly is unnecessary for flat per-packet fields and costs memory.
        "-o",
        "tcp.desegment_tcp_streams:FALSE",

        # Required for tcp.analysis.retransmission. Costs memory, which is why
        # the capture is chunked (see DEFAULT_TSHARK_CHUNK_PACKETS).
        "-o",
        "tcp.analyze_sequence_numbers:TRUE",

        "-o",
        "ip.defragment:FALSE",

        "-o",
        "http.desegment_headers:FALSE",

        "-o",
        "http.desegment_body:FALSE",

        "-o",
        "tls.desegment_ssl_records:FALSE",

        "-o",
        "tls.desegment_ssl_application_data:FALSE",

        "-o",
        "smb.trans_reassembly:FALSE",

        "-o",
        "smb.dcerpc_reassembly:FALSE",

        "-o",
        "smb2.pipe_reassembly:FALSE",

        "-o",
        "ssh.desegment_buffers:FALSE",
    ]

    return command


def _extract_tshark_chunk(
    chunk_pcap: Path,
    writer: pq.ParquetWriter | None,
    output: Path,
    *,
    batch_size: int,
    label_matcher: LabelMatcher | None = None,
    frame_offset: int = 0,
) -> tuple[pq.ParquetWriter | None, int]:
    """
    Run one tshark process over one chunk and append its rows.

    Input:  chunk path, open writer or None, batch size, matcher, frame offset
    Output: (writer, rows written)

    tshark is restarted per chunk so its memory tracks the chunk, not the
    capture.
    """
    command = _make_tshark_command(chunk_pcap)

    tshark_env = {
        **os.environ,

        # Keep glibc from accumulating unnecessary arenas.
        "MALLOC_ARENA_MAX": "1",

        # Encourage large allocations to use mmap and be returned
        # to the kernel more readily.
        "MALLOC_MMAP_THRESHOLD_": "131072",

        # Encourage malloc trimming.
        "MALLOC_TRIM_THRESHOLD_": "131072",
    }

    process: subprocess.Popen | None = None
    stderr_tmp = tempfile.NamedTemporaryFile(
        mode="w+",
        prefix="tshark_stderr_",
        suffix=".log",
        delete=False,
    )

    stderr_path = Path(stderr_tmp.name)

    batch: list[tuple] = []
    total = 0

    try:
        if os.name != "nt":
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=stderr_tmp,
                text=True,
                bufsize=1024 * 1024,
                start_new_session=True,
                env=tshark_env,
            )
        else:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=stderr_tmp,
                text=True,
                bufsize=1024 * 1024,
                env=tshark_env,
            )

        stderr_tmp.close()

        assert process.stdout is not None

        for raw_line in process.stdout:
            line = raw_line.rstrip("\r\n")

            if not line:
                continue

            values = line.split("\t")

            # TShark must produce exactly one value per requested
            # field (TSHARK_FIELDS), in the same order.
            #
            # We deliberately do not attempt to repair malformed
            # lines. Silently shifting columns would create exactly
            # the kind of packet/feature misalignment to
            # prevent.
            if len(values) != len(TSHARK_FIELDS):
                continue

            raw = dict(zip(TSHARK_FIELDS, values))

            # tshark numbers frames from 1 within the chunk file it is given,
            # so without this every 250k-packet chunk restarts at 1 and
            # frame_no stops identifying a packet (18,888,225 packets shared
            # only 250,000 distinct values). Rebase onto the original capture.
            if frame_offset:
                try:
                    raw["frame.number"] = str(
                        frame_offset + int(raw["frame.number"])
                    )
                except (TypeError, ValueError):
                    continue

            # Only packets with a usable pair of IP endpoints (IPv4
            # OR IPv6) are part of the graph provenance dataset.
            # (src_ip/dst_ip are `required` PacketFields that
            # coalesce ip.*/ipv6.*, so an empty pair here already
            # makes _parse_packet_row return None -- this is just
            # the cheap early-exit before building the full row.)
            has_v4 = raw.get("ip.src") and raw.get("ip.dst")
            has_v6 = raw.get("ipv6.src") and raw.get("ipv6.dst")

            if not (has_v4 or has_v6):
                continue

            row = _parse_packet_row(raw, label_matcher=label_matcher)

            if row is None:
                # A required field failed to parse -- drop the
                # packet rather than write a shifted/bad value.
                continue

            batch.append(row)

            if len(batch) >= batch_size:
                writer, written = _write_batch(
                    writer,
                    batch,
                    output,
                )

                total += written
                batch.clear()

        return_code = process.wait()

        if return_code != 0:
            diagnostics = ""

            try:
                diagnostics = stderr_path.read_text(
                    errors="replace"
                ).strip()
            except OSError:
                pass

            # TShark streams every good packet to stdout BEFORE reporting that
            # the file is damaged, so by this point `batch`/`total` already
            # hold the readable prefix. Keeping it is strictly better than
            # throwing the chunk away; the packets themselves parsed cleanly.
            if _looks_truncated(diagnostics):
                print(
                    f"[PACKETS] {chunk_pcap.name}: truncated chunk; keeping "
                    f"{total + len(batch):,} packets read before the damage",
                    flush=True,
                )
            else:
                raise RuntimeError(
                    f"TShark failed with exit code "
                    f"{return_code}"
                    + (
                        f":\n{diagnostics}"
                        if diagnostics
                        else ""
                    )
                )

        # Final partial batch from this chunk.
        if batch:
            writer, written = _write_batch(
                writer,
                batch,
                output,
            )

            total += written
            batch.clear()

        return writer, total

    except KeyboardInterrupt:
        if process is not None:
            _terminate_process(process)

        raise

    except BaseException:
        if process is not None:
            _terminate_process(process)

        raise

    finally:
        batch.clear()

        if process is not None:
            if process.poll() is None:
                _terminate_process(process)

            if process.stdout is not None:
                try:
                    process.stdout.close()
                except Exception:
                    pass

        stderr_path.unlink(missing_ok=True)


def _split_capture(source: Path, directory: Path, chunk_packets: int) -> list[Path]:
    """Split a capture into consecutive chunks in one sequential pass.

    Input:  capture path, empty directory for the chunks, packets per chunk
    Output: chunk paths in packet order; every chunk but the last holds exactly
            chunk_packets packets

    One pass rather than one `editcap -r` per chunk: a pcap has no index, so a
    range carve re-reads the file from the start. On the 18.9M-packet Friday
    capture that cost 12.5 s for the first chunk and 147 s for the last.
    """
    result = subprocess.run(
        ["editcap", "-c", str(chunk_packets), str(source), str(directory / "chunk.pcap")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    diagnostics = result.stderr.strip()
    chunks = sorted(directory.glob("chunk_*"))

    if result.returncode != 0 or not chunks:
        raise RuntimeError(
            f"editcap failed to split {source} (exit {result.returncode})"
            + (f":\n{diagnostics}" if diagnostics else "")
        )

    if _looks_truncated(diagnostics):
        print(
            f"[PACKETS] {source.name}: capture is truncated; "
            f"processing the readable prefix",
            flush=True,
        )
    return chunks


def pcap_to_parquet(
    pcap: Path,
    output: Path,
    *,
    label_matcher: LabelMatcher | None = None,
    batch_size: int = 100_000,
    chunk_packets: int = DEFAULT_TSHARK_CHUNK_PACKETS,
) -> int:
    """Extract per-packet features from one capture into Parquet.

    Input:  capture path, output path, optional LabelMatcher, batch size,
            packets per tshark chunk
    Output: rows written

    The capture is never modified. editcap splits it into chunk_packets-sized
    files in one pass and tshark runs once per chunk, so resident memory tracks
    chunk_packets rather than the capture. Disk holds up to one capture's worth
    of chunks, released as each is consumed. Packet order is preserved and a
    partial output is removed.

    Malformed tshark output is dropped, never repaired: a line must carry
    exactly len(TSHARK_FIELDS) values, and a packet whose required field will
    not parse is discarded rather than written with shifted columns.
    """
    pcap = Path(pcap)
    output = Path(output)

    validate_pcap(pcap)

    if batch_size <= 0:
        raise ValueError(
            f"batch_size must be > 0, got {batch_size}"
        )

    if chunk_packets <= 0:
        raise ValueError(
            f"chunk_packets must be > 0, got {chunk_packets}"
        )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Reuse only a valid completed result.
    if _valid_parquet(output):
        return pq.read_metadata(output).num_rows

    # Never append to an old/corrupt result.
    output.unlink(missing_ok=True)

    writer: pq.ParquetWriter | None = None
    total = 0

    try:
        # Chunks sit next to the output, not in /tmp, so a large capture cannot
        # fill a different filesystem. The directory is removed on any exit.
        with tempfile.TemporaryDirectory(
            prefix=f".{output.stem}.chunks_", dir=output.parent
        ) as tmp:
            print(
                f"[PACKETS] {pcap.name}: splitting into "
                f"{chunk_packets:,}-packet chunks",
                flush=True,
            )
            chunks = _split_capture(pcap, Path(tmp), chunk_packets)

            for index, chunk in enumerate(chunks):
                first_packet = index * chunk_packets + 1
                print(
                    f"[PACKETS] chunk {index + 1}/{len(chunks)}: "
                    f"from packet {first_packet:,}",
                    flush=True,
                )
                writer, written = _extract_tshark_chunk(
                    chunk,
                    writer,
                    output,
                    batch_size=batch_size,
                    label_matcher=label_matcher,
                    frame_offset=first_packet - 1,
                )
                total += written
                chunk.unlink()

        if writer is not None:
            writer.close()
            writer = None

        if total == 0:
            output.unlink(missing_ok=True)
            raise RuntimeError(
                f"TShark produced no usable IPv4/IPv6 packets "
                f"for: {pcap}"
            )

    except BaseException:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
        output.unlink(missing_ok=True)
        raise

    # Final integrity validation.
    if not _valid_parquet(output):
        output.unlink(missing_ok=True)

        raise RuntimeError(
            f"Packet extraction completed but produced "
            f"an invalid Parquet file: {output}"
        )

    metadata = pq.read_metadata(output)

    if metadata.num_rows != total:
        output.unlink(missing_ok=True)

        raise RuntimeError(
            f"Packet Parquet row-count mismatch for {output}: "
            f"expected {total}, found {metadata.num_rows}"
        )

    if metadata.schema.names != PACKET_COLUMNS:
        output.unlink(missing_ok=True)

        raise RuntimeError(
            f"Packet Parquet schema mismatch for {output}: "
            f"expected {PACKET_COLUMNS}, "
            f"found {metadata.schema.names}"
        )

    print(
        f"[PACKETS] complete: "
        f"{total:,} usable IPv4/IPv6 packets -> {output}",
        flush=True,
    )

    return total
