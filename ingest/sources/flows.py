from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, time as dt_time, timedelta, timezone
from ipaddress import ip_address

import subprocess
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


FLOW_SUFFIX = "_Flow.csv"


import fcntl

class _CFMFileLock:
    """Serialise CICFlowMeter/Gradle invocations across processes.

    Input:  lock file path
    Output: a context manager held for the duration of one invocation

    flock releases automatically if a worker is killed, so a crashed worker
    cannot leave the lock held.
    """

    def __init__(self, lock_path: Path):
        self.lock_path = Path(lock_path)
        self.fd = None

    def acquire(self, poll_interval: float = 0.5) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.lock_path, os.O_CREAT | os.O_WRONLY)
        # Blocks; the kernel manages the waiting queue.
        fcntl.flock(self.fd, fcntl.LOCK_EX)

    def release(self) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def __enter__(self) -> "_CFMFileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


def run_cicflowmeter(
    cic_dir: Path,
    pcap_path: Path,
    output_dir: Path,
) -> None:
    """
    Run CICFlowMeter over one capture.

    Input:  CICFlowMeter directory, capture path, output directory
    Output: none; writes <output_dir>/<capture>_Flow.csv

    Gradle's task is project-global, so invocations are serialised by a
    cross-process file lock. The capture is never copied.
    """

    cic_dir = Path(cic_dir).resolve()
    pcap_path = Path(pcap_path).resolve()
    output_dir = Path(output_dir).resolve()

    if not cic_dir.is_dir():
        raise FileNotFoundError(
            f"CICFlowMeter directory not found: {cic_dir}"
        )

    if not pcap_path.is_file():
        raise FileNotFoundError(
            f"PCAP file not found: {pcap_path}"
        )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    lock = _CFMFileLock(cic_dir / ".cicflowmeter.lock")

    # A Gradle JVM occasionally exits 1 from transient memory contention with
    # a sibling worker; the same capture then runs clean alone. A larger heap
    # worsens contention, so retry rather than raising -Xmx.
    for attempt in range(2):
        try:
            _run_cicflowmeter_once(cic_dir, pcap_path, output_dir, lock)
            return
        except subprocess.CalledProcessError:
            if attempt == 1:
                raise
            time.sleep(5)


def _run_cicflowmeter_once(
    cic_dir: Path,
    pcap_path: Path,
    output_dir: Path,
    lock: "_CFMFileLock",
) -> None:
    with lock:
        process = subprocess.Popen(
            [
                "./gradlew",
                "--no-daemon",
                # 512 MB is ample for one PCAP and caps swap pressure.
                "-Dorg.gradle.jvmargs=-Xms64m -Xmx512m -Duser.timezone=UTC",
                "exeCMD",
                f"-PpcapDir={pcap_path}",
                f"-PoutputDir={output_dir}",
            ],
            cwd=cic_dir,
            env={
                **os.environ,
                "JAVA_OPTS": "-Xms64m -Xmx512m -Duser.timezone=UTC",
                "GRADLE_OPTS": "-Xms64m -Xmx256m",
            },
        )
        try:
            return_code = process.wait()
            if return_code != 0:
                raise subprocess.CalledProcessError(return_code, process.args)
        except BaseException:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
            raise


def find_flow_csvs(
    flow_dir: Path,
    pcap: Path | None = None,
) -> list[Path]:
    """Locate CICFlowMeter flow CSVs.

    Input:  flow directory, optionally the capture to restrict to
    Output: sorted CSV paths; just that capture's CSV when pcap is given
    """

    flow_dir = Path(flow_dir)

    if not flow_dir.is_dir():
        return []

    if pcap is None:
        return sorted(
            p for p in flow_dir.glob(f"*{FLOW_SUFFIX}")
            if p.is_file()
        )

    pcap = Path(pcap)

    expected = flow_dir / f"{pcap.name}{FLOW_SUFFIX}"

    if expected.is_file():
        return [expected]

    return []


def iter_flow_csv(
    csv_path: Path,
    chunksize: int = 50_000,
) -> Iterator[pd.DataFrame]:
    """Read a CICFlowMeter CSV in chunks.

    Input:  CSV path, rows per chunk
    Output: iterator of frames; the whole CSV is never resident
    """

    yield from pd.read_csv(
        csv_path,
        chunksize=chunksize,
        low_memory=False,
    )


# Every timestamp this pipeline stores is UTC. The CSE-CIC-IDS2018 attack
# schedule copied into config/config.py is not: it is capture-local time at the
# Canadian Institute for Cybersecurity, which sits in the Atlantic zone, so
# February is UTC-4.
#
#   schedule_local_time = stored_utc_time + SCHEDULE_UTC_OFFSET
#
# Confirmed against the official labelled CSV: its first SlowHTTPTest flow is
# 10:12:14 and ours 14:12:14; Hulk 13:45:27 against 17:45:27.
#
# Only LabelMatcher applies the shift, in memory at comparison time. Stored
# timestamps stay UTC so flows, packets and edges share one clock.
SCHEDULE_UTC_OFFSET = timedelta(hours=-4)

# Bump when a labelling-logic change invalidates written labels.
# config.label_config_version(day) mixes this in, so logic changes discard
# stale Parquet exactly as a change to that day's rules does.
LABEL_LOGIC_VERSION = "2-utc-to-ast-plus-port-proto-direction"


@dataclass(frozen=True)
class AttackRule:
    name: str
    day: str
    start: dt_time
    end: dt_time
    attacker_ips: frozenset[str]
    victim_ips: frozenset[str]
    # Service port(s) on the victim, matched direction-aware: attacker->victim
    # carries it as Dst Port, the return flow as Src Port.
    #
    # Empty means unconstrained (time and IP pair only). Leave it empty until a
    # day's ports are verified against real traffic -- a wrong set silently
    # relabels an entire attack as Benign.
    service_ports: frozenset[int] = frozenset()
    # IP protocol number(s): 6 TCP, 17 UDP. Empty means unconstrained.
    protocols: frozenset[int] = frozenset()
    # label_confidence written on a match: how the rule relates to CIC's
    # Table 2. "time_endpoint" for the table's own windows.
    confidence: str = "time_endpoint"


def _normalize_ip(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        return str(ip_address(text))
    except ValueError:
        return text


def _parse_rule_time(value: str) -> dt_time:
    value = str(value).strip()
    for fmt in ("%H:%M:%S", "%H:%M"):
        try:
            return datetime.strptime(value, fmt).time()
        except ValueError:
            pass
    raise ValueError(f"Invalid attack time: {value!r}")


def _make_attack_rules(attacks: Sequence[Mapping[str, Any]]) -> tuple[AttackRule, ...]:
    rules: list[AttackRule] = []
    for attack in attacks:
        attackers = attack.get("attacker_ips")
        victims = attack.get("victim_ips")
        if not isinstance(attackers, (list, tuple, set, frozenset)):
            raise ValueError(f"{attack['name']} must define attacker_ips explicitly")
        if not isinstance(victims, (list, tuple, set, frozenset)):
            raise ValueError(f"{attack['name']} must define victim_ips explicitly")

        attacker_set = frozenset(_normalize_ip(v) for v in attackers if _normalize_ip(v))
        victim_set = frozenset(_normalize_ip(v) for v in victims if _normalize_ip(v))
        if not attacker_set or not victim_set:
            raise ValueError(f"{attack['name']} must have non-empty attacker_ips and victim_ips")

        start_time = _parse_rule_time(str(attack["start"]))
        end_time = _parse_rule_time(str(attack["end"]))
        if start_time > end_time:
            raise ValueError(f"{attack['name']} has start after end")

        rules.append(AttackRule(
            name=str(attack["name"]),
            day=str(attack["day"]),
            start=start_time,
            end=end_time,
            attacker_ips=attacker_set,
            victim_ips=victim_set,
            service_ports=_int_set(attack.get("service_ports"), attack["name"], "service_ports"),
            protocols=_int_set(attack.get("protocols"), attack["name"], "protocols"),
            confidence=str(attack.get("confidence", "time_endpoint")),
        ))
    return tuple(rules)


def _int_set(value: object, attack_name: str, field: str) -> frozenset[int]:
    """Parse an optional list of integers from an attack rule."""
    if value is None:
        return frozenset()
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(f"{attack_name}: {field} must be a list of integers")
    try:
        return frozenset(int(item) for item in value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{attack_name}: {field} must contain integers") from exc


LABEL_COLUMNS = ("Label", "attack_name", "label_source", "label_confidence", "label_direction")

BENIGN_LABEL: dict[str, str] = {
    "Label": "Benign",
    "attack_name": "",
    "label_source": "default",
    "label_confidence": "none",
    "label_direction": "",
}


class LabelMatcher:
    """Authoritative time + endpoint matcher, shared by flows and packets.

    Input:  attack rules for one day, the day name
    Output: label_frame() labels a flow frame; label_packet() labels one packet

    Both paths run the same rules through the same timezone conversion, so a
    flow and the packets inside it cannot disagree. Timestamps passed in are
    UTC; the schedule is capture-local (see SCHEDULE_UTC_OFFSET).
    """

    def __init__(self, attacks: Sequence[Mapping[str, Any]], day: str):
        self.day = str(day)
        self.expected_date = datetime.strptime(self.day, "%A-%d-%m-%Y").date()
        self.rules = tuple(r for r in _make_attack_rules(attacks) if r.day == self.day)
        if not self.rules:
            raise ValueError(f"No attack rules configured for dataset day {self.day!r}")
        self.needs_ports = any(r.service_ports for r in self.rules)
        self.needs_protocol = any(r.protocols for r in self.rules)


    @staticmethod
    def _to_schedule_time(utc: pd.Series) -> pd.Series:
        """Convert a UTC datetime Series to the schedule's local clock."""
        return utc + SCHEDULE_UTC_OFFSET


    def label_frame(
        self,
        frame: pd.DataFrame,
        *,
        source_column: str = "Src IP",
        destination_column: str = "Dst IP",
        timestamp_column: str = "Timestamp",
        source_port_column: str = "Src Port",
        destination_port_column: str = "Dst Port",
        protocol_column: str = "Protocol",
    ) -> pd.DataFrame:
        for column in (source_column, destination_column, timestamp_column):
            if column not in frame.columns:
                raise ValueError(f"Missing {column!r} column")
        if self.needs_ports:
            for column in (source_port_column, destination_port_column):
                if column not in frame.columns:
                    raise ValueError(
                        f"Missing {column!r} column, required because an attack "
                        f"rule for {self.day} constrains service_ports"
                    )
        if self.needs_protocol and protocol_column not in frame.columns:
            raise ValueError(
                f"Missing {protocol_column!r} column, required because an attack "
                f"rule for {self.day} constrains protocols"
            )

        # Stored timestamps are UTC; shift to the schedule's clock BEFORE the
        # date check so an attack that crosses midnight in UTC still lands on
        # the correct dataset day.
        utc = pd.to_datetime(
            frame[timestamp_column],
            format="mixed",
            dayfirst=True,
            errors="coerce",
        )
        local = self._to_schedule_time(utc)

        labels = pd.Series(BENIGN_LABEL["Label"], index=frame.index, dtype="string")
        direction = pd.Series("", index=frame.index, dtype="string")
        confidence = pd.Series("none", index=frame.index, dtype="string")
        valid = local.notna() & (local.dt.date == self.expected_date)

        # Normalize endpoints once for the whole frame rather than once per
        # rule -- this runs over millions of rows per capture.
        src_ip = frame[source_column].astype("string").map(_normalize_ip)
        dst_ip = frame[destination_column].astype("string").map(_normalize_ip)
        src_port = _as_int_series(frame, source_port_column)
        dst_port = _as_int_series(frame, destination_port_column)
        protocol = _as_int_series(frame, protocol_column)

        for rule in self.rules:
            in_window = (
                valid
                & (local.dt.time >= rule.start)
                & (local.dt.time <= rule.end)
            )
            if not bool(in_window.any()):
                continue

            if rule.protocols and protocol is not None:
                in_window &= protocol.isin(rule.protocols).fillna(False)

            # Direction is resolved explicitly. A DoS victim's replies are part
            # of the attack and CICFlowMeter emits them as their own biflows
            # when the forward flow has already been closed, so they are
            # labelled too -- but recorded as "reverse" so a consumer can
            # filter them without relabelling.
            forward = in_window & src_ip.isin(rule.attacker_ips) & dst_ip.isin(rule.victim_ips)
            reverse = in_window & src_ip.isin(rule.victim_ips) & dst_ip.isin(rule.attacker_ips)

            if rule.service_ports:
                # attacker -> victim hits the service port as its destination;
                # the victim -> attacker return flow carries it as its source.
                forward &= (
                    dst_port.isin(rule.service_ports).fillna(False)
                    if dst_port is not None else False
                )
                reverse &= (
                    src_port.isin(rule.service_ports).fillna(False)
                    if src_port is not None else False
                )

            match = forward | reverse
            taken = labels.ne(BENIGN_LABEL["Label"])
            if bool((match & taken & labels.ne(rule.name)).any()):
                raise RuntimeError(
                    f"Ambiguous overlapping attack rules for day {self.day}"
                )
            # Rules of one attack may share a boundary (Bot's gap rule): the
            # earlier rule keeps the row, so a table window keeps its own tag.
            match &= ~taken
            forward &= match
            reverse &= match
            labels.loc[match] = rule.name
            direction.loc[forward] = "forward"
            direction.loc[reverse] = "reverse"
            confidence.loc[match] = rule.confidence

        is_attack = labels.ne(BENIGN_LABEL["Label"])
        frame["Label"] = labels
        frame["attack_name"] = labels.where(is_attack, "")
        frame["label_source"] = pd.Series("default", index=frame.index, dtype="string").mask(
            is_attack, "attack_timeline"
        )
        frame["label_confidence"] = confidence
        frame["label_direction"] = direction
        return frame


    def label_packet(
        self,
        timestamp: datetime,
        source: str,
        destination: str,
        source_port: int | None = None,
        destination_port: int | None = None,
        protocol: int | None = None,
    ) -> dict[str, str]:
        # Refuse to label rather than silently return Benign when the caller
        # omits a field the rules need. Silent under-labeling is exactly the
        # failure this module exists to prevent.
        if self.needs_ports and (source_port is None or destination_port is None):
            raise ValueError(
                f"source_port and destination_port are required: an attack rule "
                f"for {self.day} constrains service_ports"
            )
        if self.needs_protocol and protocol is None:
            raise ValueError(
                f"protocol is required: an attack rule for {self.day} "
                f"constrains protocols"
            )

        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        # Same UTC -> schedule-local shift as label_frame, applied before the
        # date check for the same reason.
        local = timestamp + SCHEDULE_UTC_OFFSET
        if local.date() != self.expected_date:
            return dict(BENIGN_LABEL)

        src = _normalize_ip(source)
        dst = _normalize_ip(destination)
        matched: list[tuple[str, str]] = []

        for rule in self.rules:
            if not (rule.start <= local.time() <= rule.end):
                continue
            if rule.protocols and (protocol is None or int(protocol) not in rule.protocols):
                continue

            forward = src in rule.attacker_ips and dst in rule.victim_ips
            reverse = src in rule.victim_ips and dst in rule.attacker_ips

            if rule.service_ports:
                forward = forward and destination_port is not None and int(destination_port) in rule.service_ports
                reverse = reverse and source_port is not None and int(source_port) in rule.service_ports

            if forward:
                matched.append((rule.name, "forward", rule.confidence))
            elif reverse:
                matched.append((rule.name, "reverse", rule.confidence))

        if len({name for name, _, _ in matched}) > 1:
            raise RuntimeError(f"Ambiguous overlapping attack rules for packet on {self.day}")
        if matched:
            # Rules of one attack may share a boundary: the earlier rule wins.
            name, heading, confidence = matched[0]
            return {
                "Label": name,
                "attack_name": name,
                "label_source": "attack_timeline",
                "label_confidence": confidence,
                "label_direction": heading,
            }
        return dict(BENIGN_LABEL)


def _as_int_series(frame: pd.DataFrame, column: str) -> pd.Series | None:
    """Read a port or protocol column back as nullable ints.

    Input:  flow frame, column name
    Output: Int64 series, or None when the column is absent

    _coerce_numeric_columns has already made these float64 by the time
    labelling runs, and set membership on floats does not match.
    """
    if column not in frame.columns:
        return None
    return pd.to_numeric(frame[column], errors="coerce").astype("Int64")


def assign_labels(
    df: pd.DataFrame,
    day: str,
    *,
    matcher: LabelMatcher | None = None,
) -> pd.DataFrame:
    """Apply the configured CIC-IDS2018 timeline when a matcher is supplied."""
    if "Label" not in df.columns:
        raise ValueError("Missing Label column")
    df["Label"] = df["Label"].astype("string").str.strip()
    if matcher is None:
        # Keep the schema identical either way, so a Parquet written without a
        # matcher still concatenates with one written with it.
        for column in LABEL_COLUMNS[1:]:
            if column not in df.columns:
                df[column] = pd.Series(BENIGN_LABEL[column], index=df.index, dtype="string")
        return df
    return matcher.label_frame(df)


# CICFlowMeter's own "Flow ID" is directional, so it cannot join a flow to its
# packets. flow_key is the canonical bidirectional identity: both (ip, port)
# endpoints in a stable order plus the protocol, written into flows, packets and
# edges alike.
#
# The scalar and vectorized forms below must produce byte-identical strings --
# they are the two halves of one join.


def canonical_flow_key(
    src_ip: object,
    src_port: object,
    dst_ip: object,
    dst_port: object,
    protocol: object,
) -> str:
    """Scalar canonical flow identity (used per-packet)."""
    a = f"{src_ip}:{int(src_port)}"
    b = f"{dst_ip}:{int(dst_port)}"
    lo, hi = (a, b) if a <= b else (b, a)
    return f"{lo}|{hi}|{int(protocol)}"


def canonical_flow_key_series(
    src_ip: pd.Series,
    src_port: pd.Series,
    dst_ip: pd.Series,
    dst_port: pd.Series,
    protocol: pd.Series,
) -> pd.Series:
    """Vectorized canonical flow identity (used per-flow / per-edge)."""

    def _endpoint(ip: pd.Series, port: pd.Series) -> pd.Series:
        return (
            ip.astype("string")
            + ":"
            + pd.to_numeric(port, errors="coerce").astype("Int64").astype("string")
        )

    a = _endpoint(src_ip, src_port)
    b = _endpoint(dst_ip, dst_port)
    swap = (b < a).fillna(False)
    lo = a.where(~swap, b)
    hi = b.where(~swap, a)
    return (
        lo
        + "|"
        + hi
        + "|"
        + pd.to_numeric(protocol, errors="coerce").astype("Int64").astype("string")
    )


# Everything else in a CICFlowMeter Flow CSV is a numeric feature.
_STRING_COLUMNS = {
    "Flow ID",
    "Src IP",
    "Dst IP",
    "Timestamp",
    "flow_key",
    "flow_uid",
    *LABEL_COLUMNS,
}


def _coerce_numeric_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Coerce every non-identifier column to float64.

    Input:  one CSV chunk
    Output: the same frame with numeric columns as float64

    CIC CSVs contain literal "Infinity"/"NaN" strings, so per-chunk dtype
    inference disagrees between chunks of one file. The ParquetWriter is opened
    with the first chunk's schema, so a later mismatch would fail mid-file.
    """

    for col in df.columns:
        if col in _STRING_COLUMNS:
            continue

        df[col] = pd.to_numeric(
            df[col],
            errors="coerce",
        ).astype("float64")

    return df


def _prepare_chunk(
    df: pd.DataFrame,
    *,
    day: str,
    capture: str,
    matcher: LabelMatcher | None = None,
    row_offset: int = 0,
) -> pd.DataFrame:
    """Add dataset metadata to one flow chunk."""

    df = df.dropna(how="all")

    if df.empty:
        return df

    df = _coerce_numeric_columns(df)

    df.insert(0, "capture", capture)
    df.insert(0, "day", day)

    df["flow_key"] = canonical_flow_key_series(
        df["Src IP"], df["Src Port"], df["Dst IP"], df["Dst Port"], df["Protocol"]
    )

    # flow_key is NOT unique: CICFlowMeter closes a flow on FIN or timeout and
    # opens a new one for the same 5-tuple, so one key can name several flows
    # (up to 7 observed in a single capture, and 14,039 of 14,040 keys in the
    # Hulk slice). flow_uid is the per-flow identity that joining actually
    # needs -- see align.build_flow_packet_map.
    df["flow_uid"] = [
        f"{capture}#{row_offset + i}" for i in range(len(df))
    ]

    return assign_labels(df, day, matcher=matcher)


def csv_to_parquet(
    csv_paths,
    output_path,
    *,
    day: str,
    chunksize: int = 50_000,
    matcher: LabelMatcher | None = None,
) -> int:
    """
    Convert CICFlowMeter CSVs into one labelled Parquet file.

    Input:  CSV paths, output path, day, chunk size, optional LabelMatcher
    Output: rows written

    Chunked throughout: a full CIC day does not fit in memory.
    """

    csv_paths = [
        Path(path)
        for path in csv_paths
    ]

    if not csv_paths:
        raise FileNotFoundError(
            "No *_Flow.csv files found"
        )

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    required_columns = {
        "Flow ID",
        "Src IP",
        "Src Port",
        "Dst IP",
        "Dst Port",
        "Protocol",
        "Timestamp",
        "Label",
    }

    writer: pq.ParquetWriter | None = None

    total_rows = 0
    skipped: list[tuple[str, str]] = []

    try:
        for csv_path in csv_paths:

            try:
                if not csv_path.is_file():
                    skipped.append(
                        (str(csv_path), "not a regular file")
                    )
                    continue

                if csv_path.stat().st_size == 0:
                    skipped.append(
                        (str(csv_path), "empty file")
                    )
                    continue

            except OSError as exc:
                skipped.append(
                    (str(csv_path), f"filesystem error: {exc}")
                )
                continue

            capture = csv_path.stem.removesuffix(
                "_Flow"
            )

            try:
                chunks = iter_flow_csv(
                    csv_path,
                    chunksize=chunksize,
                )

                first_chunk = True

                for df in chunks:

                    if df.empty:
                        continue

                    if first_chunk:
                        missing = (
                            required_columns
                            .difference(df.columns)
                        )

                        if missing:
                            skipped.append(
                                (
                                    str(csv_path),
                                    "missing columns: "
                                    + ", ".join(
                                        sorted(missing)
                                    ),
                                )
                            )
                            break

                        first_chunk = False

                    df = _prepare_chunk(
                        df,
                        day=day,
                        capture=capture,
                        matcher=matcher,
                        # Keeps flow_uid unique and monotonic across chunks
                        # and across every CSV in this capture.
                        row_offset=total_rows,
                    )

                    if df.empty:
                        continue

                    table = pa.Table.from_pandas(
                        df,
                        preserve_index=False,
                    )

                    if writer is None:
                        writer = pq.ParquetWriter(
                            output_path,
                            table.schema,
                            compression="zstd",
                        )

                    writer.write_table(table)

                    total_rows += table.num_rows

            except (
                pd.errors.EmptyDataError,
                pd.errors.ParserError,
                UnicodeDecodeError,
                OSError,
            ) as exc:
                skipped.append(
                    (
                        str(csv_path),
                        f"unreadable CSV: {exc}",
                    )
                )

    finally:
        if writer is not None:
            writer.close()

    if total_rows == 0:
        output_path.unlink(missing_ok=True)

        details = "\n".join(
            f"  {path}: {reason}"
            for path, reason in skipped
        )

        raise RuntimeError(
            "No valid flow records were produced.\n"
            + details
        )

    if skipped:
        print(
            f"Warning: skipped {len(skipped)} "
            f"invalid flow CSV(s)."
        )

        for path, reason in skipped:
            print(
                f"  - {path}: {reason}"
            )

    return total_rows
