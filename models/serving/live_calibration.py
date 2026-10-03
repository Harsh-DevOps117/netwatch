"""Persistent score-tail thresholds for unlabeled live traffic.

This estimates a live score tail, not a measured false-positive rate. Scores
are keyed by stable flow identity so rebuilding an overlapping forecast window
does not count the same flow again. The validated checkpoint threshold is a
hard floor, and no live threshold is served before a full observation window.
"""
from __future__ import annotations

import sqlite3
import threading
import time
import traceback
import json
import math
from functools import wraps
from pathlib import Path


def synchronized(method):
    @wraps(method)
    def inner(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return inner


MAX_PENDING = 200_000    # scored flows waiting for the writer, beyond which submit() leaves new ones out


def checkpoint_signature(paths) -> str:
    """Invalidate saved scores whenever a model input checkpoint changes."""
    return "|".join(f"{Path(path).resolve()}:{Path(path).stat().st_size}:{Path(path).stat().st_mtime_ns}"
                    for path in paths)


class LiveScoreCalibration:
    def __init__(self, path: Path, baselines: dict[str, float], budgets: dict[str, float], *,
                 signature: str, duration_s: float = 7200.0, min_samples: int = 128,
                 tail_samples: int = 4, max_gap_s: float = 600.0):
        if duration_s <= 0 or min_samples < 1 or tail_samples < 1 or max_gap_s <= 0:
            raise ValueError("calibration duration, minimum samples, tail samples and maximum gap must be positive")
        self.baselines = {name: float(value) for name, value in baselines.items()}
        self.budgets = {name: float(budgets[name]) for name in self.baselines}
        if any(not 0 < budget < 1 for budget in self.budgets.values()):
            raise ValueError("calibration budgets must be between zero and one")
        self.duration_s, self.min_samples = float(duration_s), int(min_samples)
        self.tail_samples, self.max_gap_s = int(tail_samples), float(max_gap_s)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # `lock` guards only the in-memory state, so status() and threshold() never wait for a transaction;
        # `db_lock` is held across the database work of one observe().
        self.lock, self.db_lock = threading.RLock(), threading.RLock()
        self.pending, self.pending_rows, self.skipped = [], 0, 0
        self.pending_changed = threading.Condition()
        self.writer, self.closed = None, False
        self.recompute_after = 0.0             # monotonic time before which a slow recompute is not repeated
        self.db = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        # A busy link's window is gigabytes of index. SQLite's default 2 MB cache and 4 MB checkpoint made each
        # small transaction wait on random reads and a checkpoint sync.
        self.db.execute("PRAGMA cache_size=-65536")
        self.db.execute("PRAGMA wal_autocheckpoint=16384")
        self.insert_rows = self.db.getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER) // 4   # four values per row
        self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS scores (name TEXT NOT NULL, event TEXT NOT NULL, "
                        "t REAL NOT NULL, score REAL NOT NULL, PRIMARY KEY (name, event))")
        self.db.execute("CREATE INDEX IF NOT EXISTS scores_time ON scores (t)")
        self.db.execute("CREATE INDEX IF NOT EXISTS scores_name_score ON scores (name, score)")
        policy = json.dumps({"version": 2, "duration_s": self.duration_s,
                             "min_samples": self.min_samples, "tail_samples": self.tail_samples,
                             "max_gap_s": self.max_gap_s, "baselines": self.baselines,
                             "budgets": self.budgets}, sort_keys=True)
        saved = self._meta("signature")
        if saved != signature or self._meta("policy") != policy:
            with self.db:
                self.db.execute("DELETE FROM scores")
                self.db.execute("DELETE FROM metadata")
                self._set_meta("signature", signature)
                self._set_meta("policy", policy)
        self.start_t = float(self._meta("start_t")) if self._meta("start_t") is not None else None
        self.last_t = float(self._meta("last_t")) if self._meta("last_t") is not None else None
        self.counts = {}
        self.current = self.baselines.copy()
        self.effective_budgets = {name: None for name in self.baselines}
        self.last_recompute_t = None
        self._recompute()

    def _meta(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _set_meta(self, key: str, value) -> None:
        self.db.execute("INSERT OR REPLACE INTO metadata VALUES (?, ?)", (key, str(value)))

    def _reset(self) -> None:
        with self.db:
            self.db.execute("DELETE FROM scores")
            self.db.execute("DELETE FROM metadata WHERE key IN ('start_t', 'last_t')")
        with self.lock:
            self.start_t = self.last_t = self.last_recompute_t = None
            self.current = self.baselines.copy()
            self.effective_budgets = {name: None for name in self.baselines}
            self.counts = {}

    def submit(self, events: list[tuple[str, float, dict[str, float]]]) -> None:
        """observe(), on a writer thread: the caller hands its batch over and never waits for the database.

        Batches that arrive during a transaction are written together by the next one. Once the writer is
        MAX_PENDING flows behind, further batches are left out and counted in `skipped`: the window is then a
        sample of the traffic. Making the caller wait instead stopped detection for a minute at a time, with the
        window's database at 7 GB under a flood.
        """
        if not events:
            return
        with self.pending_changed:
            if self.closed:
                return
            if self.pending_rows >= MAX_PENDING:
                self.skipped += len(events)
                return
            self.pending.append(events)
            self.pending_rows += len(events)
            if self.writer is None:
                self.writer = threading.Thread(target=self._write, name="calibration-writer", daemon=True)
                self.writer.start()
            self.pending_changed.notify_all()

    def _write(self) -> None:
        while True:
            with self.pending_changed:
                while not self.pending:
                    if self.closed:
                        return
                    self.pending_changed.wait()
                batches, self.pending = self.pending, []
            events = [event for batch in batches for event in batch]
            try:
                self.observe(events)
            except Exception:                      # a failed write must not end calibration, or its caller
                traceback.print_exc()
            finally:
                with self.pending_changed:
                    self.pending_rows -= len(events)
                    self.pending_changed.notify_all()

    def flush(self) -> None:
        """Wait until every submitted batch has been written."""
        with self.pending_changed:
            while self.pending_rows:
                self.pending_changed.wait()

    def observe(self, events: list[tuple[str, float, dict[str, float]]]) -> None:
        """Ingest each distinct scored flow once, then update the mature window."""
        if not events:
            return
        with self.db_lock:
            self._observe(events)

    def _observe(self, events: list[tuple[str, float, dict[str, float]]]) -> None:
        ordered = sorted(((str(key), float(t), values) for key, t, values in events), key=lambda row: row[1])
        # A long capture interruption cannot be counted as two hours of traffic.
        previous, segment = self.last_t, 0
        for i, (_, t, _) in enumerate(ordered):
            if previous is not None and t - previous > self.max_gap_s:
                segment = i
                self._reset()
            previous = max(previous, t) if previous is not None else t
        ordered = ordered[segment:]
        latest = max(t for _, t, _ in ordered)
        cutoff = latest - self.duration_s
        inserts = [(name, key, t, float(values[name])) for key, t, values in ordered if t >= cutoff
                   for name in self.baselines if name in values and math.isfinite(values[name])]
        with self.db:
            # Thousands of rows per statement: SQLite works through each without the interpreter lock, where
            # executemany() takes the lock back for every row and so queues behind the scoring thread.
            inserted = 0
            for start in range(0, len(inserts), self.insert_rows):
                rows = inserts[start:start + self.insert_rows]
                inserted += self.db.execute(
                    "INSERT OR IGNORE INTO scores VALUES " + ", ".join(["(?, ?, ?, ?)"] * len(rows)),
                    [value for row in rows for value in row]).rowcount
            self.db.execute("DELETE FROM scores WHERE t < ?", (cutoff,))
            if inserted:
                first = min(t for _, _, t, _ in inserts)
                with self.lock:
                    self.start_t = first if self.start_t is None else min(self.start_t, first)
                    self.last_t = latest if self.last_t is None else max(self.last_t, latest)
                self._set_meta("start_t", self.start_t)
                self._set_meta("last_t", self.last_t)
        if self.last_t is not None and time.monotonic() >= self.recompute_after and (
                self.last_recompute_t is None or
                self.last_t - self.last_recompute_t >= (60 if self.ready else 15) or
                (self.ready and all(value is None for value in self.effective_budgets.values()))):
            started = time.monotonic()
            self._recompute()
            # It reads the whole window. Once that takes long, it is given a twentieth of the writer's time at
            # most; counts and thresholds are then that much older, and the scores keep being written.
            spent = time.monotonic() - started
            self.recompute_after = time.monotonic() + 20 * spent if spent > 0.25 else 0.0

    @property
    def ready(self) -> bool:
        return self.start_t is not None and self.last_t is not None and self.last_t - self.start_t >= self.duration_s

    def _recompute(self) -> None:
        # Query into locals and publish at the end, so a reader sees the old state or the new, never between.
        counts = {name: count for name, count in self.db.execute(
            "SELECT name, COUNT(*) FROM scores GROUP BY name")}
        current = self.baselines.copy()
        effective_budgets = {name: None for name in self.baselines}
        if self.ready:
            for name, baseline in self.baselines.items():
                count = counts.get(name, 0)
                if count < self.min_samples:
                    continue
                budget = max(self.budgets[name], self.tail_samples / count)
                effective_budgets[name] = budget
                # A covering SQLite index finds the exact 'higher' quantile without
                # loading every stored score into Python on the scoring thread.
                rank = min(count - 1, math.ceil((1 - budget) * (count - 1)))
                row = self.db.execute(
                    "SELECT score FROM scores WHERE name=? ORDER BY score LIMIT 1 OFFSET ?",
                    (name, rank)).fetchone()
                if row is not None:
                    current[name] = max(baseline, float(row[0]))
        with self.lock:
            self.counts, self.current, self.effective_budgets = counts, current, effective_budgets
            self.last_recompute_t = self.last_t

    @synchronized
    def threshold(self, name: str) -> float:
        return self.current[name]

    @synchronized
    def status(self, name: str) -> dict:
        elapsed = max(0.0, self.last_t - self.start_t) if self.ready or self.start_t is not None else 0.0
        count = self.counts.get(name, 0)
        ready = self.ready and count >= self.min_samples
        return {"ready": ready, "window_s": self.duration_s, "elapsed_s": round(elapsed, 1),
                "remaining_s": round(max(0.0, self.duration_s - elapsed), 1),
                "samples": count, "minimum_samples": self.min_samples, "skipped_flows": self.skipped,
                "first_observed": self.start_t, "last_observed": self.last_t,
                "baseline_threshold": self.baselines[name], "live_threshold": self.current[name] if ready else None,
                "target_exceedance_budget": self.budgets[name],
                "effective_exceedance_budget": self.effective_budgets[name],
                "labels_available": False, "calibration_type": "threshold_only",
                "probability_calibration": "checkpoint_unchanged"}

    def close(self) -> None:
        with self.pending_changed:
            self.closed = True
            self.pending_changed.notify_all()
        if self.writer is not None:
            self.writer.join()                     # it writes what is still pending first
        with self.db_lock:
            self.db.close()


def demo() -> None:
    from tempfile import TemporaryDirectory
    temporary = Path(__file__).resolve().parents[2] / "artifacts" / "runtime"
    temporary.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=temporary) as folder:
        path = Path(folder) / "calibration.sqlite"
        calibration = LiveScoreCalibration(path, {"model": 0.8}, {"model": 0.01}, signature="v1",
                                           duration_s=10, min_samples=3, max_gap_s=20)
        calibration.observe([(str(i), float(i), {"model": score}) for i, score in
                             enumerate([0.2, 0.4, 0.9, 0.95])])
        assert not calibration.status("model")["ready"] and calibration.threshold("model") == 0.8
        calibration.observe([("last", 10.0, {"model": 0.99})])
        assert calibration.status("model")["ready"] and calibration.threshold("model") >= 0.8
        count = calibration.status("model")["samples"]
        calibration.observe([("last", 10.0, {"model": 0.99})])
        assert calibration.status("model")["samples"] == count
        calibration.close()
        resumed = LiveScoreCalibration(path, {"model": 0.8}, {"model": 0.01}, signature="v1",
                                       duration_s=10, min_samples=3, max_gap_s=20)
        assert resumed.status("model")["ready"]
        resumed.observe([("new", 40.0, {"model": 0.1})])
        assert not resumed.status("model")["ready"], "a capture gap must restart the window"
        resumed.close()
