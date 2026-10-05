"""Small durable ledgers of detector incidents and world-model flags for the operator's recent-history view."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

WINDOW_S = 3 * 3600
MAX_RETURNED = 500
EVENT_LIMIT = 30_000     # linked events one answer may carry: about what the dashboard's 16 MiB response bound holds
EVENT_PREVIEW = 1_000    # how many of a larger incident's events are returned instead, marked truncated
SUMMARY_GROUPS = 16      # how many (sender, source, destination) groups a truncated answer summarises


class IncidentHistory:
    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS incidents (family TEXT NOT NULL, incident INTEGER NOT NULL, "
                        "sender_node INTEGER NOT NULL, opened_at REAL NOT NULL, score REAL NOT NULL, "
                        "PRIMARY KEY (family, incident, opened_at))")
        self.db.execute("CREATE INDEX IF NOT EXISTS incidents_opened_at ON incidents(opened_at)")
        self.db.execute("CREATE TABLE IF NOT EXISTS incident_events (family TEXT NOT NULL, "
                        "incident INTEGER NOT NULL, opened_at REAL NOT NULL, event_id INTEGER NOT NULL, "
                        "observed_at REAL NOT NULL, detail TEXT NOT NULL, "
                        "PRIMARY KEY (family, incident, opened_at, event_id))")
        self.db.execute("CREATE INDEX IF NOT EXISTS incident_events_opened_at ON incident_events(opened_at)")
        self.db.commit()
        # History is read on a connection of its own: WAL lets it read during a write, so a flood's evidence
        # query on the HTTP thread never makes the scoring thread wait to record its batch.
        self.read_lock = threading.Lock()
        self.reader = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.last_prune = float("-inf")

    def record(self, incident: dict) -> None:
        self.record_batch([incident], [])

    def record_events(self, rows: list[dict]) -> None:
        """Persist only threshold crossings assigned to a real incident."""
        self.record_batch([], rows)

    def record_batch(self, incidents: list[dict], rows: list[dict]) -> None:
        """Commit all families' incidents and their evidence in one transaction."""
        if not incidents and not rows:
            return
        # Serialize outside the database lock, so HTTP history reads need not
        # wait while a flood's evidence is converted to JSON.
        incident_values = [(str(row["family"]), int(row["incident"]), int(row["key"]),
                            float(row["t"]), float(row["score"])) for row in incidents]
        event_values = [(str(row["family"]), int(row["incident"]), float(row["opened_at"]),
                        int(row["event_id"]), float(row["t_obs"]), json.dumps(row)) for row in rows]
        with self.lock, self.db:
            self.db.executemany("INSERT OR IGNORE INTO incidents VALUES (?, ?, ?, ?, ?)", incident_values)
            self.db.executemany("INSERT OR IGNORE INTO incident_events VALUES (?, ?, ?, ?, ?, ?)", event_values)
            now = time.time()
            if now - self.last_prune >= 60:
                self.db.execute("DELETE FROM incidents WHERE opened_at < ?", (now - WINDOW_S,))
                self.db.execute("DELETE FROM incident_events WHERE opened_at < ?", (now - WINDOW_S,))
                self.last_prune = now

    def events(self, family: str, incident: int, opened_at: float) -> list[dict]:
        with self.read_lock:
            rows = self.reader.execute("SELECT detail FROM incident_events WHERE family=? AND incident=? "
                                       "AND opened_at=? ORDER BY observed_at, event_id",
                                       (str(family), int(incident), float(opened_at))).fetchall()
        return [json.loads(row[0]) for row in rows]

    def events_json(self, family: str, incident: int, opened_at: float, limit: int = EVENT_LIMIT,
                    preview: int = EVENT_PREVIEW) -> str:
        """The /incident-events answer, built from the stored JSON text: nothing is decoded to be encoded again.

        Input:  the incident's identity; how many linked events a complete answer may hold, and how many of a
                larger incident's are returned instead
        Output: '{"events": [...], "total": N, "truncated": bool}', events in observation order; a truncated
                answer also carries "summary", counted over every linked event: its largest groups by
                (sender_ip, src, dst) with their event and distinct destination-port counts, and the most used
                source port. That is what a consumer needs to decide who the incident's traffic is between.

        A flood links over 100,000 events to one incident, more than a consumer reads. Such an answer carries
        the first `preview` and says so: whoever needs the complete evidence must not conclude from it. Those
        are read in key order (event id, which follows observation), so the flood is never sorted to answer.
        """
        key = (str(family), int(incident), float(opened_at))
        with self.read_lock:
            total = self.reader.execute("SELECT COUNT(*) FROM incident_events WHERE family=? AND incident=? "
                                        "AND opened_at=?", key).fetchone()[0]
            order, count = ("observed_at, event_id", total) if total <= limit else ("event_id", preview)
            rows = self.reader.execute("SELECT detail FROM incident_events WHERE family=? AND incident=? "
                                       f"AND opened_at=? ORDER BY {order} LIMIT ?", (*key, count)).fetchall()
            summary = ""
            if total > limit:
                where = "FROM incident_events WHERE family=? AND incident=? AND opened_at=?"
                groups = self.reader.execute(
                    "SELECT json_extract(detail, '$.sender_ip'), json_extract(detail, '$.src'), "
                    "json_extract(detail, '$.dst'), COUNT(*), COUNT(DISTINCT json_extract(detail, '$.dst_port')) "
                    f"{where} GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT ?", (*key, SUMMARY_GROUPS)).fetchall()
                port = self.reader.execute(f"SELECT json_extract(detail, '$.src_port'), COUNT(*) {where} "
                                           "GROUP BY 1 ORDER BY 2 DESC LIMIT 1", key).fetchone()
                summary = ', "summary": ' + json.dumps({
                    "groups": [{"sender_ip": sender, "src": src, "dst": dst, "events": events, "dst_ports": ports}
                               for sender, src, dst, events, ports in groups],
                    "top_src_port": {"port": port[0], "events": port[1]}})
        return ('{"events": [' + ", ".join(row[0] for row in rows) +
                f'], "total": {total}, "truncated": {json.dumps(total > limit)}{summary}}}')

    def import_log(self, path: Path) -> int:
        """Recover incidents logged by an older detector before this ledger existed."""
        try:
            lines = Path(path).open("r", encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return 0
        cutoff = time.time() - WINDOW_S
        rows = []
        with lines:
            for line in lines:
                try:
                    incident = json.loads(line).get("incident")
                    if isinstance(incident, dict) and float(incident["t"]) >= cutoff:
                        rows.append((str(incident["family"]), int(incident["incident"]), int(incident["key"]),
                                     float(incident["t"]), float(incident["score"])))
                except (ValueError, TypeError, KeyError, AttributeError):
                    continue
        with self.lock, self.db:
            inserted = self.db.executemany("INSERT OR IGNORE INTO incidents VALUES (?, ?, ?, ?, ?)", rows).rowcount
            self.db.execute("DELETE FROM incidents WHERE opened_at < ?", (cutoff,))
            return inserted

    def recent(self, now: float | None = None) -> list[dict]:
        cutoff = (time.time() if now is None else float(now)) - WINDOW_S
        with self.read_lock:
            rows = self.reader.execute(
                "SELECT family, incident, sender_node, opened_at, score FROM "
                "(SELECT * FROM incidents WHERE opened_at >= ? ORDER BY opened_at DESC LIMIT ?) "
                "ORDER BY opened_at ASC", (cutoff, MAX_RETURNED)).fetchall()
        return [{"family": family, "incident": incident, "key": key, "t": opened,
                 "score": score} for family, incident, key, opened, score in rows]

    def close(self) -> None:
        with self.read_lock:
            self.reader.close()
        with self.lock:
            self.db.close()


class WorldAlertHistory:
    """The observed events that crossed the world model's threshold, kept for the same three hours.

    The live forecast rebuilds its window every cycle, so a flag is on screen only while its event is in that window.
    An event is identified by its time and link: event ids are renumbered on every rebuild.
    """

    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS world_alerts (t REAL NOT NULL, sender_ip TEXT NOT NULL, "
                        "receiver_ip TEXT NOT NULL, incident INTEGER NOT NULL, detail TEXT NOT NULL, "
                        "PRIMARY KEY (t, sender_ip, receiver_ip))")
        self.db.commit()

    def record(self, events: list[dict], now: "float | None" = None) -> None:
        """Keep these flagged events. One that later joins an incident stays marked as part of it."""
        values = [(float(e["t"]), str(e["sender_ip"]), str(e["receiver_ip"]), int(bool(e.get("incident"))),
                   json.dumps(e)) for e in events]
        with self.lock, self.db:
            self.db.executemany("INSERT INTO world_alerts VALUES (?, ?, ?, ?, ?) ON CONFLICT (t, sender_ip, receiver_ip) "
                                "DO UPDATE SET incident = MAX(incident, excluded.incident), detail = excluded.detail",
                                values)
            self.db.execute("DELETE FROM world_alerts WHERE t < ?", ((time.time() if now is None else now) - WINDOW_S,))

    def remember(self, events: list[dict], incidents: list[dict]) -> list[dict]:
        """Keep one cycle's threshold crossings and return everything kept.

        Input:  the cycle's events (those without a `severity` did not cross and are skipped) and its incidents
        Output: `recent()` after recording them
        """
        in_incident = {(e["t"], e["sender_ip"], e["receiver_ip"]) for incident in incidents
                       for e in incident["related_events"]}
        crossings = {(e["t"], e["sender_ip"], e["receiver_ip"]): e for e in events if e.get("severity")}
        self.record([{**e, "incident": key in in_incident} for key, e in crossings.items()])
        return self.recent()

    def recent(self, now: "float | None" = None) -> list[dict]:
        """The kept events, oldest first, each with `incident`: whether it was ever part of an incident."""
        cutoff = (time.time() if now is None else float(now)) - WINDOW_S
        with self.lock:
            rows = self.db.execute("SELECT incident, detail FROM world_alerts WHERE t >= ? ORDER BY t",
                                   (cutoff,)).fetchall()
        return [{**json.loads(detail), "incident": bool(incident)} for incident, detail in rows]

    def close(self) -> None:
        with self.lock:
            self.db.close()
