"""Regression tests for the durable three-hour incident history."""
import json
import tempfile
import time
import unittest
from pathlib import Path

from models.serving.incident_history import IncidentHistory, WINDOW_S, WorldAlertHistory


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
            self.assertEqual({k: prefix[k] for k in ("events", "total", "truncated")},
                             {"events": rows[:2], "total": 5, "truncated": True})
            self.assertEqual(json.loads(history.events_json("Bot", 2, opened)),
                             {"events": [], "total": 0, "truncated": False})
            self.assertEqual(history.events("Bot", 1, opened), rows)
            history.close()

    def test_truncated_answer_summarises_every_linked_event(self):
        with tempfile.TemporaryDirectory() as temp:
            history = IncidentHistory(Path(temp) / "incidents.sqlite")
            opened = time.time() - 10
            flow = lambda i, dst, sport, dport: {"family": "DoS-Hulk", "incident": 1, "opened_at": opened, "event_id": i,
                                                 "t_obs": opened + i, "sender_ip": "10.0.0.5", "src": "10.0.0.5",
                                                 "dst": dst, "src_port": sport, "dst_port": dport}
            # Replies from this host's port 5173 to one client's changing ports, and one unrelated flow.
            history.record_events([flow(i, "10.0.0.9", 5173, 40000 + i) for i in range(4)] +
                                  [flow(4, "1.1.1.1", 50000, 443)])
            answer = json.loads(history.events_json("DoS-Hulk", 1, opened, limit=3, preview=1))
            self.assertEqual((len(answer["events"]), answer["total"], answer["truncated"]), (1, 5, True))
            self.assertEqual(answer["summary"], {
                "groups": [{"sender_ip": "10.0.0.5", "src": "10.0.0.5", "dst": "10.0.0.9", "events": 4, "dst_ports": 4},
                           {"sender_ip": "10.0.0.5", "src": "10.0.0.5", "dst": "1.1.1.1", "events": 1, "dst_ports": 1}],
                "top_src_port": {"port": 5173, "events": 4}})
            self.assertNotIn("summary", json.loads(history.events_json("DoS-Hulk", 1, opened)))
            history.close()

    def test_world_flags_outlive_the_window_and_keep_their_incident_mark(self):
        with tempfile.TemporaryDirectory() as temp:
            now = time.time()
            flag = {"event_id": 4, "t": now - 60, "sender_ip": "10.0.0.5", "receiver_ip": "10.0.0.9",
                    "value": .999, "severity": "MEDIUM"}
            history = WorldAlertHistory(Path(temp) / "world-alerts.sqlite")
            quiet = {**flag, "t": now - 30, "severity": ""}
            history.record([{**flag, "t": now - WINDOW_S - 5}])
            history.remember([flag, quiet], [{"related_events": [flag]}])
            # The next cycle renumbers the event and no longer sees it inside an incident.
            history.remember([{**flag, "event_id": 9}, quiet], [])
            history.close()
            kept = WorldAlertHistory(Path(temp) / "world-alerts.sqlite").recent()
            self.assertEqual([(row["t"], row["event_id"], row["incident"]) for row in kept], [(now - 60, 9, True)])


if __name__ == "__main__":
    unittest.main()
