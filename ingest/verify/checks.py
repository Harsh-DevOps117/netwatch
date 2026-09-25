"""Audit generated labels for one dataset day.

    python -m ingest.verify Friday-16-02-2018

Five things are checked, and the first is the important one:

1. OFFSET DETECTION. The configured schedule is capture-local (UTC-4); stored
   timestamps are UTC. Rather than trusting that constant, this scans candidate
   offsets and reports which one actually aligns this day's attacker<->victim
   traffic with its scheduled window. If the winner is not the configured
   SCHEDULE_UTC_OFFSET, the day is flagged -- that is the check to run before
   trusting labels on a day nobody has verified by hand.

2. LABEL AUDIT. Every configured attack carries a label, no labelled row
   sits outside its windows, and no flow shaped like the attack (endpoints,
   service port, protocol) falls outside all of them.

3. CAPTURES. Every capture find_pcaps() selects from the raw day has complete
   output, and no output belongs to an unselected file.

4. PACKETS, across every capture: maps current, packets attached to the flow
   that covers them, TCP flags parsed, attack packets labelled like their flow.

5. EVENTS, once events.py has run: fresh, complete, finite, and carrying every
   configured attack.

Run it after the CLI and again after events.py; move to the next day only on a
PASS from the second run.

The official CIC CSVs deliberately play no part here. They cannot serve as
ground truth: the Friday file is truncated at Excel's 1,048,576-row limit, has
no Src IP / Dst IP columns at all, writes 13:45:27 as "01:45:27" (12-hour clock
with the AM/PM marker stripped), and duplicates every SlowHTTPTest flow for 24
minutes. See docs/LABELING_VERIFICATION.md.

Exit status is non-zero if any check fails, so this can gate a pipeline run.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from ingest.sources.schedule import ATTACKS
from ingest.build.join import MAP_VERSION, map_is_current
from ingest.build.events import EVENT_COLUMNS
from ingest.sources.flows import SCHEDULE_UTC_OFFSET, AttackRule, _make_attack_rules, _normalize_ip
from ingest.sources.packets import capture_name, find_pcaps

FLOW_COLUMNS = [
    "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
    "Timestamp", "flow_key", "Label", "label_direction", "label_confidence",
]

# Offsets scanned during detection: every quarter hour from -12h to +12h.
_CANDIDATE_OFFSETS = [pd.Timedelta(minutes=15 * n) for n in range(-48, 49)]


def _parse_utc(timestamps: pd.Series) -> pd.Series:
    return pd.to_datetime(timestamps, format="mixed", dayfirst=True, errors="coerce")


def _pair_mask(frame: pd.DataFrame, rule: AttackRule) -> pd.Series:
    """Flows between this rule's attacker and victim, in either direction.

    Input:  flow frame, one attack rule
    Output: boolean mask over the frame

    Deliberately ignores time: offset detection exists to measure the time
    shift, so it cannot assume one.
    """
    src = frame["Src IP"].astype("string").map(_normalize_ip)
    dst = frame["Dst IP"].astype("string").map(_normalize_ip)
    return (
        (src.isin(rule.attacker_ips) & dst.isin(rule.victim_ips))
        | (src.isin(rule.victim_ips) & dst.isin(rule.attacker_ips))
    )


# A connection opened inside a window can be recorded just after it closes.
# CICFlowMeter's flow timeout is the natural bound on that lag.
EDGE_TOLERANCE = pd.Timedelta(seconds=120)


def _window_mask(local: pd.Series, rule: AttackRule, expected_date, tolerance=EDGE_TOLERANCE) -> pd.Series:
    """Rows a scheduled window accounts for, allowing for flows recorded at its edge.

    Input:  local timestamps, one rule, the day's date, edge tolerance
    Output: boolean mask

    Friday-23 has four flows 4 to 28 s past an edge, two of them single-packet
    server-side tails. A genuine gap -- Friday-02-03's Bot heartbeat, hours from
    any edge -- is far outside the tolerance and still escapes.
    """
    start = pd.Timestamp.combine(expected_date, rule.start) - tolerance
    end = pd.Timestamp.combine(expected_date, rule.end) + tolerance
    return local.notna() & (local >= start) & (local <= end)


def _attack_shape(frame: pd.DataFrame, rule: AttackRule) -> pd.Series:
    """Flows that match a rule in everything but time.

    Input:  flow frame, one attack rule
    Output: boolean mask: attacker<->victim, on the rule's service port and
            protocol when it constrains them
    """
    src = frame["Src IP"].astype("string").map(_normalize_ip)
    dst = frame["Dst IP"].astype("string").map(_normalize_ip)
    forward = src.isin(rule.attacker_ips) & dst.isin(rule.victim_ips)
    reverse = src.isin(rule.victim_ips) & dst.isin(rule.attacker_ips)
    if rule.service_ports:
        forward &= frame["Dst Port"].isin(rule.service_ports)
        reverse &= frame["Src Port"].isin(rule.service_ports)
    shape = forward | reverse
    if rule.protocols:
        shape &= frame["Protocol"].isin(rule.protocols)
    return shape


def _detect_offset(
    histograms: dict[str, Counter], rules: list[AttackRule], expected_date
) -> tuple[pd.Timedelta | None, dict[str, int]]:
    """Find the UTC offset that places the most attack traffic inside its windows.

    Input:  per-attack histograms of flows per UTC minute, the day's rules, date
    Output: (best offset or None, flows aligned per attack at that offset)

    A minute counts once per attack, however many of its windows hold it:
    rules of one attack share boundaries, and summing rule by rule counted the
    boundary minutes twice (290,895 "aligned" of 286,191 Bot flows).
    """
    by_name: dict[str, list[AttackRule]] = {}
    for rule in rules:
        by_name.setdefault(rule.name, []).append(rule)

    def aligned(name: str, offset: pd.Timedelta) -> int:
        total = 0
        for minute, count in histograms.get(name, {}).items():
            local = minute + offset
            if local.date() == expected_date and any(
                r.start <= local.time() <= r.end for r in by_name[name]
            ):
                total += count
        return total

    scores = {o: sum(aligned(name, o) for name in by_name) for o in _CANDIDATE_OFFSETS}
    # Sparse traffic can fit several quarter-hour shifts equally well; a tie
    # that includes the configured offset does not contradict it.
    best = max(scores, key=lambda o: (scores[o], o == SCHEDULE_UTC_OFFSET))
    if scores[best] == 0:
        return None, {}
    return best, {name: aligned(name, best) for name in by_name}


def verify_day(
    day: str,
    processed_root: Path,
    raw_root: Path = Path("data/raw"),
    events_root: Path = Path("data/events"),
) -> int:
    """Audit one processed day end to end.

    Input:  day, processed root, raw dataset root, event-stream root
    Output: 0 when every check passes, 1 otherwise
    """
    day_dir = processed_root / day
    if not day_dir.is_dir():
        print(f"FAIL  no processed output at {day_dir}")
        return 1

    rules = [r for r in _make_attack_rules(ATTACKS) if r.day == day]
    if not rules:
        print(f"FAIL  no attack rules configured for {day!r}")
        return 1
    expected_date = pd.to_datetime(day, format="%A-%d-%m-%Y").date()
    # Rules sharing a name (Bot, Infiltration) are one attack in several windows.
    by_name: dict[str, list[AttackRule]] = {}
    for rule in rules:
        by_name.setdefault(rule.name, []).append(rule)

    flow_files = sorted(day_dir.glob("*/flows.parquet"))
    if not flow_files:
        print(f"FAIL  no flows.parquet under {day_dir}")
        return 1

    hours = SCHEDULE_UTC_OFFSET.total_seconds() / 3600
    print(f"day       : {day}")
    print(f"captures  : {len(flow_files)}")
    print(f"configured: schedule local = UTC{hours:+.0f}  (stored timestamps are UTC)")
    print()

    label_counts: Counter[str] = Counter()
    direction_counts: Counter[tuple[str, str]] = Counter()
    spans: dict[str, list[pd.Timestamp]] = {}
    ports: dict[str, Counter[int]] = {}
    out_of_window: Counter[str] = Counter()
    escaped: Counter[str] = Counter()
    escaped_span: dict[str, list[pd.Timestamp]] = {}
    attacker_ports: dict[str, Counter[int]] = {}
    phases: dict[str, Counter[str]] = {}
    captures_with: dict[str, set[str]] = {}
    histograms: dict[str, Counter] = {}
    total_rows = 0

    for path in flow_files:
        available = set(pq.read_schema(path).names)
        missing = [c for c in FLOW_COLUMNS if c not in available]
        if missing:
            print(f"FAIL  {path.parent.name}: missing column(s) {missing}")
            print("      -> regenerate; this output predates the current schema")
            return 1

        frame = pq.read_table(path, columns=FLOW_COLUMNS).to_pandas()
        total_rows += len(frame)
        utc = _parse_utc(frame["Timestamp"])
        local = utc + SCHEDULE_UTC_OFFSET

        label_counts.update(frame["Label"].value_counts().to_dict())
        for (label, heading), n in (
            frame.groupby(["Label", "label_direction"], dropna=False).size().items()
        ):
            direction_counts[(str(label), str(heading))] += int(n)

        # Flows some scheduled window accounts for -- this attack's or another's.
        # Friday-23's three web attacks share one attacker, one victim and port
        # 80, so audited rule by rule each counted the other two as escaped.
        covered = pd.Series(False, index=frame.index)
        for rule in rules:
            covered |= _window_mask(local, rule, expected_date)

        for name, group in by_name.items():
            # -- offset detection input: pair matches, time ignored. One mask
            # per attack, so a flow is counted once however many windows it has.
            pair = pd.Series(False, index=frame.index)
            for rule in group:
                pair |= _pair_mask(frame, rule)
            if bool(pair.any()):
                minutes = utc[pair].dt.floor("min").value_counts()
                histograms.setdefault(name, Counter()).update(minutes.to_dict())

            # -- the attack's windows, and traffic shaped like it outside them --
            in_window = pd.Series(False, index=frame.index)
            shape = pd.Series(False, index=frame.index)
            for rule in group:
                in_window |= (local.dt.time >= rule.start) & (local.dt.time <= rule.end)
                shape |= _attack_shape(frame, rule)
            in_window &= local.notna() & (local.dt.date == expected_date)
            outside = shape & ~covered
            if bool(outside.any()):
                escaped[name] += int(outside.sum())
                lo, hi = local[outside].min(), local[outside].max()
                prev = escaped_span.get(name)
                escaped_span[name] = [lo, hi] if prev is None else [min(prev[0], lo), max(prev[1], hi)]

            # -- label audit, against the union of the attack's windows -------
            hit = frame["Label"] == name
            if not bool(hit.any()):
                continue
            phases.setdefault(name, Counter()).update(
                frame.loc[hit, "label_confidence"].value_counts().to_dict())
            captures_with.setdefault(name, set()).add(path.parent.name)
            lo, hi = local[hit].min(), local[hit].max()
            prev = spans.get(name)
            spans[name] = (
                [lo, hi] if prev is None else [min(prev[0], lo), max(prev[1], hi)]
            )
            counter = ports.setdefault(name, Counter())
            fwd = hit & frame["label_direction"].eq("forward")
            rev = hit & frame["label_direction"].eq("reverse")
            counter.update(frame.loc[fwd, "Dst Port"].dropna().astype(int).tolist())
            counter.update(frame.loc[rev, "Src Port"].dropna().astype(int).tolist())
            theirs = attacker_ports.setdefault(name, Counter())
            theirs.update(frame.loc[fwd, "Src Port"].dropna().astype(int).tolist())
            theirs.update(frame.loc[rev, "Dst Port"].dropna().astype(int).tolist())
            out_of_window[name] += int((hit & ~in_window).sum())

    failures = 0

    # ---------------------------------------------------------------- offset
    print("offset detection")
    print("  which UTC offset places this day's attacker<->victim traffic")
    print("  inside its scheduled window?")
    best, per_rule = _detect_offset(histograms, rules, expected_date)
    if best is None:
        print("  INCONCLUSIVE - no attacker<->victim traffic found in any capture")
        print("                 (nothing to align; check the capture set)")
    else:
        bh = best.total_seconds() / 3600
        print(f"  best offset   : UTC{bh:+.2f}")
        print(f"  configured    : UTC{hours:+.2f}")
        for name, n in per_rule.items():
            print(f"    {name:<26} {n:>10,} flows aligned")
        if best == SCHEDULE_UTC_OFFSET:
            print("  STATUS        : OK - measured offset matches the configured one")
        else:
            print(f"  STATUS        : FAIL - measured UTC{bh:+.2f} != configured "
                  f"UTC{hours:+.2f}")
            print("                  labels on this day are NOT trustworthy")
            failures += 1

    # ----------------------------------------------------------- label audit
    print(f"\ntotal flow rows: {total_rows:,}")
    print("\nlabel distribution")
    for label, n in label_counts.most_common():
        print(f"  {label:<28} {n:>12,}")

    print("\nper-attack detail")
    for name, group in by_name.items():
        rule = group[0]
        n = label_counts.get(name, 0)
        print(f"\n  {name}")
        windows = ", ".join(f"{r.start}-{r.end}" for r in group)
        print(f"    scheduled     : {windows} local")
        print(f"    labelled rows : {n:,}")
        if n == 0:
            print("    STATUS        : FAIL - configured for this day but no flow "
                  "carries its label")
            failures += 1
            continue
        lo, hi = spans[name]
        print(f"    observed      : {lo} .. {hi} local")
        print(f"    captures      : {len(captures_with[name])}")
        fwd = direction_counts.get((name, "forward"), 0)
        rev = direction_counts.get((name, "reverse"), 0)
        print(f"    direction     : forward={fwd:,} reverse={rev:,}")
        top = ", ".join(f"{p}:{c:,}" for p, c in ports[name].most_common(4))
        theirs = ", ".join(f"{p}:{c:,}" for p, c in attacker_ports[name].most_common(4))
        print(f"    victim ports  : {top}")
        print(f"    attacker ports: {theirs}")
        print("    phases        : " + ", ".join(f"{k} {v:,}" for k, v in phases[name].most_common()))
        if rule.service_ports:
            print(f"    constrained to: ports {sorted(rule.service_ports)} "
                  f"proto {sorted(rule.protocols) or 'any'}")
        else:
            print("    constrained to: (unconstrained - ports not yet verified for "
                  "this day)")
        if escaped[name]:
            lo, hi = escaped_span[name]
            print(f"    FAIL  {escaped[name]:,} flows shaped like this attack fall outside its "
                  f"windows ({lo} .. {hi} local); if they are the attack, add a tagged rule")
            failures += 1
        stray = out_of_window[name]
        if stray:
            print(f"    STATUS        : FAIL - {stray:,} rows outside the window")
            failures += 1
        else:
            print("    STATUS        : OK - all labelled rows inside the window")

    failures += _verify_coverage(day, day_dir, raw_root)
    failures += _verify_packets(day_dir, set().union(*captures_with.values()), rules, expected_date)
    failures += _verify_events(day, day_dir, events_root, rules)

    print()
    if failures:
        print(f"RESULT: FAIL ({failures} problem(s))")
        return 1
    print("RESULT: PASS")
    return 0


def _verify_coverage(day: str, day_dir: Path, raw_root: Path) -> int:
    """Check that every capture selected for the day was processed, and nothing else.

    Input:  day, processed day directory, raw dataset root
    Output: number of failed checks

    Selection is find_pcaps() on the raw day, the rule the pipeline itself uses.
    Raw days are often deleted once processed; then this is reported, not failed.
    """
    pcap_dir = raw_root / day / "pcap"
    print("\ncaptures")
    if not pcap_dir.is_dir():
        print(f"  raw captures not at {pcap_dir}: completeness not checked")
        return 0
    skipped: list[tuple[Path, str]] = []
    selected = find_pcaps(pcap_dir, pd.to_datetime(day, format="%A-%d-%m-%Y").date(), skipped)
    print(f"  selected       : {len(selected):,} of {len(selected) + len(skipped):,} files")
    for reason, n in sorted(Counter(r.split(",")[0] for _, r in skipped).items()):
        print(f"  skipped        : {n:,} x {reason}")
    want = {capture_name(p) for p in selected}
    done = {d.name for d in day_dir.iterdir() if (d / "flow_packet_map.parquet").is_file()}
    missing, extra = sorted(want - done), sorted(done - want)
    print(f"  processed      : {len(want & done):,} of {len(want):,}")
    failures = 0
    if missing:
        print(f"  FAIL  {len(missing)} selected capture(s) have no complete output: {missing[:5]}")
        failures += 1
    if extra:
        print(f"  FAIL  {len(extra)} output(s) belong to no selected capture: {extra[:5]}")
        failures += 1
    if not failures:
        print("  STATUS         : OK")
    return failures


def _window_names(local: pd.Series, rules, expected_date) -> np.ndarray:
    """The attack whose scheduled window holds each local time; '' for none.

    Input:  schedule-local timestamps, the day's rules, the day's date
    Output: array of attack names aligned with `local`
    """
    names = np.full(len(local), "", dtype=object)
    on_day = (local.dt.date == expected_date).to_numpy()
    times = local.dt.time
    for rule in rules:
        names[on_day & ((times >= rule.start) & (times <= rule.end)).to_numpy()] = rule.name
    return names


def _verify_packets(
    day_dir: Path,
    attack_captures: set[str],
    rules: list[AttackRule] = (),
    expected_date=None,
) -> int:
    """Check packets, maps and attribution across every capture of the day.

    Input:  processed day directory, names of captures holding attack flows,
            the day's rules and date
    Output: number of failed checks

    Every capture is checked, not a sample: which capture holds the attack
    differs by day, so one sampled capture proves nothing about the rest.

    A flow keeps the label of its start and a packet takes the label of its own
    time, so they differ legitimately where a flow crosses a window edge (200 Bot
    packets on Friday-02-03). Any other difference is an attribution error.
    """
    caps = sorted(p.parent for p in day_dir.glob("*/flows.parquet"))
    print("\npackets")
    ready = [c for c in caps
             if (c / "packets.parquet").is_file() and (c / "flow_packet_map.parquet").is_file()]
    incomplete = sorted({c.name for c in caps} - {c.name for c in ready})
    stale = [c.name for c in ready if not map_is_current(c / "flow_packet_map.parquet")]
    has_flow = lost = tcp = flagged = attack_packets = joined = edge = unexplained = 0
    misaligned: list[str] = []
    flags = ["tcp_flag_syn", "tcp_flag_ack", "tcp_flag_fin", "tcp_flag_rst"]

    for c in ready:
        m = pq.read_table(c / "flow_packet_map.parquet", columns=["frame_no", "flow_key", "flow_uid"])
        keys = pc.unique(pq.read_table(c / "flows.parquet", columns=["flow_key"]).column(0))
        with_flow = pc.is_in(m.column("flow_key"), value_set=keys)
        has_flow += pc.sum(with_flow).as_py() or 0
        lost += pc.sum(pc.and_(with_flow, pc.is_null(m.column("flow_uid")))).as_py() or 0

        is_attack = c.name in attack_captures
        p = pq.read_table(c / "packets.parquet",
                          columns=["frame_no", "protocol", *flags]
                          + (["timestamp", "Label"] if is_attack else []))
        is_tcp = pc.equal(p.column("protocol"), 6)
        any_flag = pc.equal(p.column(flags[0]), 1)
        for name in flags[1:]:
            any_flag = pc.or_(any_flag, pc.equal(p.column(name), 1))
        tcp += pc.sum(is_tcp).as_py() or 0
        flagged += pc.sum(pc.and_(is_tcp, any_flag)).as_py() or 0

        if is_attack:
            attack_packets += pc.sum(pc.not_equal(p.column("Label"), "Benign")).as_py() or 0
            # Map and packets hold one row per packet, so sorted by frame_no they
            # align row for row and each packet's flow label is one lookup: far
            # leaner than joining 18.9M rows on string keys.
            pm = p.take(pc.sort_indices(p.column("frame_no")))
            mm = m.take(pc.sort_indices(m.column("frame_no")))
            if pm.num_rows != mm.num_rows or not pc.all(
                pc.equal(pm.column("frame_no"), mm.column("frame_no"))
            ).as_py():
                misaligned.append(c.name)
                continue
            flows = pq.read_table(c / "flows.parquet", columns=["flow_uid", "Label", "Timestamp"])
            idx = pc.index_in(mm.column("flow_uid"), value_set=flows.column("flow_uid").cast(pa.string()))
            flow_label = pc.take(flows.column("Label").cast(pa.string()), idx)
            attached = pc.is_valid(idx)
            differ = pc.fill_null(pc.and_(attached, pc.not_equal(pm.column("Label"), flow_label)), False)
            joined += pc.sum(attached).as_py() or 0
            if pc.any(differ).as_py():
                packet_local = pd.Series(pd.to_datetime(
                    pc.filter(pm.column("timestamp"), differ).to_numpy(), unit="s")) + SCHEDULE_UTC_OFFSET
                start_local = _parse_utc(pd.Series(
                    pc.take(flows.column("Timestamp"), pc.filter(idx, differ)).to_pylist())) + SCHEDULE_UTC_OFFSET
                crossing = (_window_names(packet_local, rules, expected_date)
                            != _window_names(start_local, rules, expected_date))
                edge += int(crossing.sum())
                unexplained += int((~crossing).sum())

    share = 1 - lost / has_flow if has_flow else 1.0
    tcp_share = flagged / tcp if tcp else 1.0
    agreement = 1 - (edge + unexplained) / joined if joined else 1.0
    print(f"  captures       : {len(caps):,}")
    print(f"  maps current   : {len(ready) - len(stale):,} of {len(ready):,} ({MAP_VERSION})")
    print(f"  attached       : {share:.4%} of packets whose key has a flow ({lost:,} of {has_flow:,} lost)")
    print(f"  TCP flags set  : {tcp_share:.2%} of TCP packets carry SYN, ACK, FIN or RST")
    print(f"  attack packets : {attack_packets:,} in {len(attack_captures)} capture(s); "
          f"label agrees with its flow on {agreement:.4%}")
    if edge or unexplained:
        print(f"  label differs  : {edge:,} from flows crossing a window edge, {unexplained:,} unexplained")

    failures = 0
    for bad, message in (
        (incomplete, f"{len(incomplete)} capture(s) missing packets or map: {incomplete[:5]}"),
        (stale, f"{len(stale)} map(s) from older attribution logic; rerun the CLI: {stale[:5]}"),
        (share < 0.999, "packets whose key has a flow were not attached to one"),
        (tcp and tcp_share < 0.9, "TCP flags look unparsed; check the tshark boolean format"),
        (attack_captures and not attack_packets, "attack flows exist but no packet is labelled attack"),
        (misaligned, f"map and packets disagree on frame numbers: {misaligned[:5]}"),
        (unexplained, f"{unexplained:,} packet(s) labelled unlike their flow with no window edge between"),
    ):
        if bad:
            print(f"  FAIL  {message}")
            failures += 1
    if not failures:
        print("  STATUS         : OK")
    return failures


def _verify_events(day: str, day_dir: Path, events_root: Path, rules: list[AttackRule]) -> int:
    """Check the day's event stream, once events.py has built it.

    Input:  day, processed day directory, event-stream root, the day's rules
    Output: number of failed checks

    events.py runs after the first audit, so an absent stream is reported, not
    failed. A stream older than any map was built from superseded attribution.
    """
    root = events_root / day
    path = root / "events.parquet"
    print("\nevents")
    if not path.is_file():
        print(f"  not built yet  : run  python -m ingest.build.events {day}  then verify again")
        return 0
    maps = list(day_dir.glob("*/flow_packet_map.parquet"))
    if maps and path.stat().st_mtime < max(m.stat().st_mtime for m in maps):
        print("  FAIL  older than the flow<->packet maps; rebuild it with events.py")
        return 1

    table = pq.read_table(path)
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        print(f"  FAIL  {message}")
        failures += 1

    print(f"  events         : {table.num_rows:,}, {table.num_columns} columns")
    if table.column_names != EVENT_COLUMNS:
        fail("columns differ from events.EVENT_COLUMNS; rebuild with the current code")
        return failures
    bad = 0
    for name in table.column_names:
        column = table.column(name)
        bad += column.null_count
        if pa.types.is_floating(column.type):
            bad += (pc.sum(pc.is_nan(column)).as_py() or 0) + (pc.sum(pc.is_inf(column)).as_py() or 0)
    if bad:
        fail(f"{bad:,} null, NaN or inf values")

    e = table.select(["event_id", "t", "src_node_id", "dst_node_id", "has_packets",
                      "reversed", "syn_n", "ack_n", "fin_n", "rst_n", "payload_bytes",
                      "label"]).to_pandas()
    if not e["t"].is_monotonic_increasing:
        fail("not sorted by t")
    if not np.array_equal(e["event_id"].to_numpy(), np.arange(len(e))):
        fail("event_id is not the row order")
    if not set(e["reversed"].unique()) <= {-1.0, 0.0, 1.0}:
        fail("reversed outside {-1, 0, 1}")
    node_index = root / "node_index.parquet"
    if not node_index.is_file():
        fail("node_index.parquet missing")
    elif max(e["src_node_id"].max(), e["dst_node_id"].max()) >= pq.read_metadata(node_index).num_rows:
        fail("a node id falls outside node_index")
    flagged = e[["syn_n", "ack_n", "fin_n", "rst_n"]].ne(0).any(axis=1).mean()
    payload = (e["payload_bytes"] != 0).mean()
    print(f"  TCP flag counts: non-zero on {flagged:.1%} of events")
    print(f"  payload_bytes  : non-zero on {payload:.1%} of events")
    if flagged == 0:
        fail("every TCP flag count is zero; check the tshark boolean format")
    if payload == 0:
        fail("payload_bytes is zero on every event")
    print(f"  no packets     : {(~e['has_packets']).mean():.2%} of events (CICFlowMeter time only)")
    counts = e["label"].value_counts()
    for name in dict.fromkeys(rule.name for rule in rules):
        n = int(counts.get(name, 0))
        reversed_share = (e.loc[e["label"] == name, "reversed"] == 1).mean() if n else 0.0
        print(f"  {name:<26} {n:>10,} events, {reversed_share:.1%} reversed")
        if not n:
            fail(f"no {name} event in the stream")
    if not failures:
        print("  STATUS         : OK")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("day", help="e.g. Friday-16-02-2018")
    parser.add_argument(
        "--processed-root",
        type=Path,
        default=Path("data/processed"),
        help="directory holding one subdirectory per dataset day",
    )
    parser.add_argument(
        "--raw-root",
        type=Path,
        default=Path("data/raw"),
        help="raw dataset root, for the capture-completeness check",
    )
    parser.add_argument(
        "--events-root",
        type=Path,
        default=Path("data/events"),
        help="event-stream root, for the events check",
    )
    args = parser.parse_args(argv)
    return verify_day(args.day, args.processed_root, args.raw_root, args.events_root)


if __name__ == "__main__":
    sys.exit(main())
