"""Evaluation splits: the day's attack windows and the chronological cut inside each segment."""

from __future__ import annotations

from datetime import datetime

import numpy as np
import pandas as pd

from ingest.sources.schedule import ATTACKS
from ingest.sources.flows import BENIGN_LABEL, SCHEDULE_UTC_OFFSET, LabelMatcher

SPLIT_NAMES = {0: "train", 1: "val", 2: "test", -1: "gap"}


def time_split(
    t: np.ndarray, train: float = 0.6, val: float = 0.1, gap: float = 120.0,
    bounds: tuple[float, float] | None = None,
) -> np.ndarray:
    """Assign events to chronological splits with an embargo gap after train and after val.

    Input:  event start times in seconds, train and val fractions of the time span,
            gap in seconds, the span to cut or None to take it from the events
    Output: int8 array, 0 train, 1 val, 2 test, -1 inside a gap
    """
    t0, t1 = bounds if bounds is not None else (float(np.min(t)), float(np.max(t)))
    train_end = t0 + train * (t1 - t0)
    val_end = t0 + (train + val) * (t1 - t0)
    out = np.full(len(t), -1, dtype=np.int8)
    out[t <= train_end] = 0
    out[(t > train_end + gap) & (t <= val_end)] = 1
    out[t > val_end + gap] = 2
    return out


def attack_windows(day: str) -> list[tuple[float, float]]:
    """The day's scheduled attack windows as merged UTC epoch spans.

    Input:  day name, e.g. Friday-16-02-2018
    Output: disjoint (start, end) pairs in epoch seconds, ascending

    Built from the rules LabelMatcher uses, through the same timezone
    conversion, so the splits cannot drift from the labels. Rules that touch or
    overlap — Friday-02-03's three Bot windows — merge into one span.
    """
    matcher = LabelMatcher(ATTACKS, day)
    return _merge(sorted(
        (_epoch(datetime.combine(matcher.expected_date, rule.start)),
         _epoch(datetime.combine(matcher.expected_date, rule.end)))
        for rule in matcher.rules
    ))


def observed_windows(timeline: pd.DataFrame, day: str) -> list[tuple[float, float]]:
    """The span each attack actually occupies, clipped to the day's schedule.

    Input:  frame with t and label covering the whole day, day name
    Output: disjoint (start, end) pairs in epoch seconds, ascending

    A scheduled window can be far longer than the traffic in it: Friday-16's
    DoS-Hulk window runs 34 minutes while its events stop after 13, so cutting
    the window at 60% put all 1,843,441 Hulk events in train. Clipping to the
    schedule keeps a stray label from widening a segment.
    """
    attacks = timeline[timeline["label"] != BENIGN_LABEL["Label"]]
    spans = []
    for _, rows in attacks.groupby("label", observed=True):
        t = rows["t"].to_numpy()
        for start, end in attack_windows(day):
            inside = t[(t >= start) & (t <= end)]
            if inside.size and inside.max() > inside.min():
                spans.append((float(inside.min()), float(inside.max())))
    return _merge(sorted(spans))


def segment_split(
    t: np.ndarray, windows: list[tuple[float, float]],
    train: float = 0.6, val: float = 0.1, gap: float = 120.0,
) -> np.ndarray:
    """Cut train, val and test inside every attack window and every benign stretch.

    Input:  event start times in seconds, merged attack windows, train and val
            fractions, embargo gap in seconds
    Output: int8 array, 0 train, 1 val, 2 test, -1 inside a gap

    A whole-day time split puts every attack in train: on both verified days the
    60% boundary falls after the last attack window, leaving val and test with no
    attack at all. Cutting inside each segment keeps time order within the
    segment and still gives every split rows of every attack.
    """
    t = np.asarray(t, dtype=float)
    out = np.full(len(t), -1, dtype=np.int8)
    segments = _segments(float(t.min()), float(t.max()), windows)
    for index, (start, end) in enumerate(segments):
        last = index + 1 == len(segments)
        inside = (t >= start) & ((t <= end) if last else (t < end))
        if inside.any():
            out[inside] = time_split(t[inside], train, val, gap, bounds=(start, end))
    return out


def _segments(first: float, last: float, windows: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """Split the day into attack windows and the benign stretches between them.

    Input:  first and last event time, merged attack windows
    Output: consecutive (start, end) pairs covering [first, last]
    """
    edges = [first]
    for start, end in windows:
        if end > first and start < last:
            edges += [max(start, first), min(end, last)]
    edges.append(last)
    return [(a, b) for a, b in zip(edges, edges[1:]) if b > a]


def _merge(spans) -> list[tuple[float, float]]:
    """Merge overlapping or touching spans.

    Input:  (start, end) pairs in ascending order
    Output: disjoint (start, end) pairs
    """
    merged: list[list[float]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def _epoch(local: datetime) -> float:
    """Convert a schedule-local wall clock to UTC epoch seconds.

    Input:  naive datetime on the capture-local clock
    Output: epoch seconds
    """
    return (local - SCHEDULE_UTC_OFFSET - datetime(1970, 1, 1)).total_seconds()


def stratified_split(t: np.ndarray, label: np.ndarray, windows: list[tuple[float, float]],
                     train: float = 0.6, val: float = 0.1, gap: float = 120.0,
                     benign: str | None = None) -> np.ndarray:
    """Chronological splits that every attack family is guaranteed to appear in.

    Input:  event start times, per-event labels, merged attack windows, train and val fractions, the embargo in
            seconds, the benign label (taken from the ingest config when None)
    Output: int8 array, 0 train, 1 val, 2 test, -1 embargoed

    `segment_split` cuts each segment at a **fraction of its clock**, which silently starves families in two ways, both
    measured on the ingested days:

    1. **A short window loses validation entirely.** The val band is 10% of the segment, so a segment under 1,200 s has
       a band smaller than the 120 s embargo and nothing survives it. Friday-23's 780 s window left SQL Injection with
       zero validation rows.
    2. **A burst that ends early lands wholly in train.** DoS-Hulk's 1,843,441 rows all fall in the first 802 s of a
       2,040 s window, so a cut at the window's 60% mark put every one of them in train and left val and test with none.

    Cutting by **rank within each family's own rows** removes both: the fractions apply to the family's events rather
    than to the clock, so a family with three rows gets one per split whatever its shape in time. Order within a family
    is still chronological -- every train row of a family precedes its val rows, which precede its test rows -- which is
    what the split is for.

    The embargo is applied as a time gap after each boundary and **skipped for a group it would empty**, because an
    empty split is a worse failure than a short one: it removes the family from the metric entirely, and silently.
    """
    benign = benign if benign is not None else BENIGN_LABEL["Label"]
    t = np.asarray(t, dtype=float)
    label = np.asarray(label, dtype=object)
    out = np.full(len(t), -1, dtype=np.int8)
    segments = _segments(float(t.min()), float(t.max()), windows) if len(t) else []
    for index, (start, end) in enumerate(segments):
        last = index + 1 == len(segments)
        inside = (t >= start) & ((t <= end) if last else (t < end))
        if not inside.any():
            continue
        for name in np.unique(label[inside]):
            rows = np.flatnonzero(inside & (label == name))
            # Benign rows are plentiful and spread through the segment, so the clock cut is fine and keeps the
            # familiar behaviour; only the families need rank cutting.
            if name == benign:
                out[rows] = time_split(t[rows], train, val, gap, bounds=(start, end))
            else:
                out[rows] = _rank_split(t[rows], train, val, gap)
    return out


def _rank_split(t: np.ndarray, train: float, val: float, gap: float) -> np.ndarray:
    """Cut one group at rank fractions of its own events, oldest first.

    Input:  the group's times, train and val fractions, the embargo in seconds
    Output: int8 per row

    Fewer than three events cannot be cut three ways, so they all go to train and the coverage report says the family
    is train-only rather than pretending otherwise. Friday-23 has families with tens of events, so this is reached.
    """
    n = len(t)
    out = np.zeros(n, dtype=np.int8)
    if n < 3:
        return out
    order = np.argsort(t, kind="stable")
    rank = np.empty(n, dtype=np.int64)
    rank[order] = np.arange(n)
    # At least one row each side of both boundaries, whatever the fractions round to.
    first = min(max(1, int(round(n * train))), n - 2)
    second = min(max(first + 1, int(round(n * (train + val)))), n - 1)
    out[rank >= first] = 1
    out[rank >= second] = 2
    for boundary, later in ((first, 1), (second, 2)):
        edge = t[order[boundary - 1]]
        embargoed = (out == later) & (t <= edge + gap)
        # Only embargo if something of this split survives it.
        if embargoed.any() and (out == later).sum() > embargoed.sum():
            out[embargoed] = -1
    return out


def band_hours(t: np.ndarray, split: np.ndarray, code: int = 2) -> float:
    """How long one split's bands last, in hours: the time a per-hour rate on that split's rows must be divided by.

    Input:  event times and split codes, both in time order; the split code (2: test)
    Output: the summed duration of every unbroken run of that code, in hours

    A split is a set of bands, one per segment, so its rows are spread over the whole day while covering only part of
    it (test: 2.8-3.7 of 10-13 hours on the five days). Dividing by the first-to-last span understates every rate about
    three times.
    """
    t, split = np.asarray(t, dtype=float), np.asarray(split, dtype=np.int64)
    if not len(t):
        return 0.0
    edges = np.flatnonzero(np.diff(np.r_[-99, split, -99]) != 0)
    return float(sum(t[b - 1] - t[a] for a, b in zip(edges[:-1], edges[1:]) if split[a] == code)) / 3600.0


def split_report(split: np.ndarray, label: np.ndarray, benign: str | None = None) -> pd.DataFrame:
    """Rows per split per family, and whether any split is empty.

    Input:  a split array, the matching labels, the benign label
    Output: DataFrame with train/val/test counts per family and a `complete` flag

    The point of running this is the `complete` column. A family missing from a split is invisible in every metric
    computed afterwards, and nothing else in the pipeline notices.
    """
    benign = benign if benign is not None else BENIGN_LABEL["Label"]
    label = np.asarray(label, dtype=object)
    rows = []
    for name in sorted(set(label.tolist())):
        mask = label == name
        counts = {SPLIT_NAMES[v]: int((split[mask] == v).sum()) for v in (0, 1, 2, -1)}
        rows.append({"family": name, "is_benign": name == benign, "total": int(mask.sum()), **counts,
                     "complete": all(counts[s] > 0 for s in ("train", "val", "test"))})
    return pd.DataFrame(rows)


def available_days(events_root: "Path | str" = "data/events") -> list[str]:
    """Every ingested day, in chronological order.

    Input:  the events root
    Output: day directory names, oldest first

    Discovered rather than hard-coded, so adding the remaining days needs no code change. Sorted by the date in the
    name -- the directories are `Weekday-DD-MM-YYYY`, which does not sort correctly as text.
    """
    from pathlib import Path as _Path
    root = _Path(events_root)
    if not root.is_dir():
        return []
    days = [p.name for p in root.iterdir() if p.is_dir() and (p / "events.parquet").is_file()]
    def key(day: str):
        try:
            _, d, m, y = day.split("-")
            return (int(y), int(m), int(d))
        except ValueError:
            return (0, 0, 0)
    return sorted(days, key=key)


def main(argv: list[str] | None = None) -> int:
    """Report split coverage per day and family, for the current splitter and the stratified one."""
    import argparse
    from pathlib import Path as _Path

    import pyarrow.parquet as pq

    parser = argparse.ArgumentParser(description="Split coverage: does every family reach every split?")
    parser.add_argument("--days", nargs="*", default=None, help="default: every ingested day")
    parser.add_argument("--events-root", type=_Path, default=_Path("data/events"))
    parser.add_argument("--mode", choices=("stratified", "segment", "chronological", "both"),
                        default="both", help="chronological is the non-interleaving mode, for "
                             "anticipation only; check coverage before trusting it")
    parser.add_argument("--train", type=float, default=0.6)
    parser.add_argument("--val", type=float, default=0.1)
    parser.add_argument("--gap", type=float, default=120.0)
    parser.add_argument("--out", type=_Path, default=None, help="write the report here as CSV")
    args = parser.parse_args(argv)

    days = args.days or available_days(args.events_root)
    if not days:
        raise SystemExit(f"no ingested days under {args.events_root}")
    tables = []
    for day in days:
        events = pq.read_table(args.events_root / day / "events.parquet",
                               columns=["t", "label", "has_packets"]).to_pandas()
        keep = events["has_packets"].to_numpy()
        t, label = events["t"].to_numpy()[keep], events["label"].to_numpy(str)[keep]
        windows = observed_windows(pd.DataFrame({"t": t, "label": label}), day)
        for mode in (("stratified", "segment") if args.mode == "both" else (args.mode,)):
            if mode == "stratified":
                split = stratified_split(t, label, windows, args.train, args.val, args.gap)
            elif mode == "chronological":
                split = chronological_split(t, args.train, args.val, args.gap)
            else:
                split = segment_split(t, windows, args.train, args.val, args.gap)
            report = split_report(split, label)
            report.insert(0, "mode", mode)
            report.insert(0, "day", day)
            tables.append(report)
    table = pd.concat(tables, ignore_index=True)
    attacks = table[~table["is_benign"]]
    pd.set_option("display.width", 200)
    print("\nSPLIT COVERAGE — every attack family must reach train, val and test\n")
    print(attacks.drop(columns=["is_benign"]).to_string(index=False))
    for mode in sorted(attacks["mode"].unique()):
        broken = attacks[(attacks["mode"] == mode) & ~attacks["complete"]]
        verdict = "complete" if not len(broken) else f"{len(broken)} family/day pairs missing a split"
        print(f"\n  {mode:11s} {verdict}")
        for row in broken.itertuples():
            missing = [s for s in ("train", "val", "test") if getattr(row, s) == 0]
            print(f"      {row.day} {row.family}: no {', '.join(missing)}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        table.to_csv(args.out, index=False)
        print(f"\nwritten to {args.out}")
    return 0 if not len(attacks[(attacks["mode"] == "stratified") & ~attacks["complete"]]) else 1



def chronological_split(t: np.ndarray, train: float = 0.6, val: float = 0.1, gap: float = 120.0) -> np.ndarray:
    """One cut across the whole day, so the splits never interleave in wall-clock time.

    Input:  event start times, train and val fractions, the embargo in seconds
    Output: int8 array, 0 train, 1 val, 2 test, -1 embargoed

    **Use this for anticipation, and nothing else.** `segment_split` and `stratified_split` cut inside each segment so
    that every split receives attack rows, and the price is that the splits interleave in real time: on the Bot day,
    1,677,561 of 1,680,628 test benign rows occur before the latest train attack. That is harmless when scoring a row
    that is itself an attack, and fatal for "will this host attack later", because training has already seen that host
    attacking at a later wall-clock time.

    **Measured across all five ingested days: it leaves every one of the nine family/day pairs missing a split.** On
    each day the 60% boundary falls after the last attack window, so every attack row lands in train and validation and
    test contain none. `python -m models.data.splits --mode chronological` reproduces that table.

    So a single-day chronological split is not an alternative for anticipation either: it has no attacks to score. The
    only honest route to an anticipation number is a **cross-day holdout** -- fit on some days, test on a day held out
    entirely -- which is why this function exists to be measured against rather than to be used.
    """
    return time_split(np.asarray(t, dtype=float), train, val, gap)


if __name__ == "__main__":
    raise SystemExit(main())
