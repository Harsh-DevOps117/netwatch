"""Regression tests for the durable three-hour incident history."""
import json
import tempfile
import time
import unittest
from pathlib import Path

from models.serving.incident_history import IncidentHistory, WINDOW_S


class IncidentHistoryTest(unittest.TestCase):
    def test_batch_commits_all_families_and_evidence_together(self):
        with tempfile.TemporaryDirectory() as temp:
            history = IncidentHistory(Path(temp) / "incidents.sqlite")
            opened = time.time()
            incidents = [{"family": family, "incident": 1, "key": 7, "t": opened, "score": .9}
                         for family in ("Bot", "DoS")]
            events = [{"family": row["family"], "incident": 1, "opened_at": opened,
                       "event_id": 22, "t_obs": opened} for row in incidents]
            statements = []
            history.db.set_trace_callback(statements.append)
            history.record_batch(incidents, events)
            self.assertEqual(sum(sql == "COMMIT" for sql in statements), 1)
            self.assertEqual({row["family"] for row in history.recent()}, {"Bot", "DoS"})
            for row in events:
                self.assertEqual(history.events(row["family"], 1, opened), [row])
            history.close()

    def test_closed_incident_remains_recent_across_reopen(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "incidents.sqlite"
            opened = time.time() - 120
            event = {"family": "Bot", "incident": 1, "key": 7,
                     "t": opened, "score": 0.98}
            history = IncidentHistory(path)
            history.record(event)
            self.assertEqual(history.recent(), [event])
            reopened = IncidentHistory(path)
            self.assertEqual(reopened.recent(), [event])
            self.assertEqual(reopened.recent(opened + WINDOW_S + 1), [])
            reopened.close()
            history.close()

    def test_import_log_deduplicates_and_skips_old_or_invalid_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            recent = {"family": "Infiltration", "incident": 2, "key": 11,
                      "t": time.time() - 30, "score": 0.91}
            old = {**recent, "incident": 1, "t": time.time() - WINDOW_S - 30}
            log = path / "detection.log"
            log.write_text("\n".join([json.dumps({"incident": recent}),
                                        json.dumps({"incident": old}), "not json", "{}"]),
                           encoding="utf-8")
            history = IncidentHistory(path / "incidents.sqlite")
            self.assertEqual(history.import_log(log), 1)
            self.assertEqual(history.import_log(log), 0)
            self.assertEqual(history.recent(), [recent])
            history.close()

    def test_related_events_survive_reopen_and_are_scoped_to_incident(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "incidents.sqlite"
            opened = time.time() - 10
            row = {"family": "Bot", "incident": 1, "opened_at": opened, "event_id": 22,
                   "t_obs": opened - 0.01, "src": "192.0.2.10", "dst": "198.51.100.7"}
            history = IncidentHistory(path)
            history.record_events([row, row])
            self.assertEqual(history.events("Bot", 1, opened), [row])
            self.assertEqual(history.events("Bot", 2, opened), [])
            history.close()
            reopened = IncidentHistory(path)
            self.assertEqual(reopened.events("Bot", 1, opened), [row])
            reopened.close()

    def test_event_answer_is_complete_up_to_the_limit_then_a_marked_prefix(self):
        with tempfile.TemporaryDirectory() as temp:
            history = IncidentHistory(Path(temp) / "incidents.sqlite")
            opened = time.time() - 10
            rows = [{"family": "Bot", "incident": 1, "opened_at": opened, "event_id": i,
                     "t_obs": opened + i, "src": "192.0.2.10"} for i in range(5)]
            history.record_events(rows[::-1])
            complete = json.loads(history.events_json("Bot", 1, opened, limit=5, preview=2))
            self.assertEqual(complete, {"events": rows, "total": 5, "truncated": False})
            prefix = json.loads(history.events_json("Bot", 1, opened, limit=4, preview=2))
            self.assertEqual(prefix, {"events": rows[:2], "total": 5, "truncated": True})
            self.assertEqual(json.loads(history.events_json("Bot", 2, opened)),
                             {"events": [], "total": 0, "truncated": False})
            self.assertEqual(history.events("Bot", 1, opened), rows)
            history.close()


if __name__ == "__main__":
    unittest.main()
