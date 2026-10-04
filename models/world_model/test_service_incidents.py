"""Observed world-model incidents are distinct from raw event flags and forecasts."""
import unittest

from models.world_model.service import alert_groups, caveats_for, forecast_payload, observed_incidents, with_live_age


def rows(times, scores):
    count = len(times)
    return {"event_id": list(range(count)), "t": times, "surprise": scores,
            "ranking": [[] for _ in times], "sender": [1] * count, "receiver": [2] * count}


THRESHOLD = {"score": "next_event_pred_error", "direction": 1, "threshold": 0.8, "thresholds": {}}


class WorldIncidentTests(unittest.TestCase):
    def test_observed_recent_events_are_chronological_model_inputs(self):
        payload = forecast_payload([], rows(list(range(15)), [.2] * 15),
                                   caveats=[], names={1: "sender", 2: "receiver"})
        recent = payload["observed"]["recent_events"]
        self.assertEqual([event["event_id"] for event in recent], list(range(3, 15)))
        self.assertEqual(recent[-1]["sender_ip"], "sender")
        self.assertEqual(recent[-1]["receiver_ip"], "receiver")

    def test_rollout_caveat_does_not_promise_wall_clock_eta(self):
        caveats = " ".join(caveats_for(None))
        self.assertIn("seeded rollout", caveats)
        self.assertIn("not k seconds", caveats)
        self.assertIn("does not predict an arrival time", caveats)

    def test_live_state_age_refreshes_without_changing_replay(self):
        live = {"source": {"mode": "live", "state_as_of": 100.0, "lag_seconds": 10.0}}
        self.assertEqual(with_live_age(live, now=225.0)["source"]["lag_seconds"], 125.0)
        self.assertEqual(live["source"]["lag_seconds"], 10.0)
        replay = {"source": {"mode": "replay", "lag_seconds": 10.0}}
        self.assertIs(with_live_age(replay, now=225.0), replay)

    def test_three_consecutive_flags_open_one_incident(self):
        self.assertEqual(observed_incidents(rows([0, 1], [.9, .9]), THRESHOLD, {}), [])
        incidents = observed_incidents(rows([0, 1, 2, 3], [.9, .9, .9, .9]), THRESHOLD, {1: "host"})
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["sender_ip"], "host")
        self.assertEqual(incidents[0]["events"], 4)
        self.assertEqual([event["event_id"] for event in incidents[0]["related_events"]], [0, 1, 2, 3])
        self.assertEqual(incidents[0]["related_events"][0]["sender_ip"], "host")

    def test_non_flag_resets_persistence(self):
        self.assertEqual(observed_incidents(rows([0, 1, 2, 3], [.9, .9, .1, .9]), THRESHOLD, {}), [])

    def test_120_second_quiet_gap_groups_then_starts_new_incident(self):
        together = observed_incidents(rows([0, 1, 2, 100, 101, 102], [.9] * 6), THRESHOLD, {})
        self.assertEqual(len(together), 1)
        self.assertEqual(together[0]["opened"], 2)
        self.assertEqual(together[0]["events"], 6)
        separate = observed_incidents(rows([0, 1, 2, 200, 201, 202], [.9] * 6), THRESHOLD, {})
        self.assertEqual(len(separate), 1)  # the earlier grouping is no longer active
        self.assertEqual(separate[0]["opened"], 202)

    def test_uncalibrated_model_never_reports_incidents(self):
        self.assertEqual(observed_incidents(rows([0, 1, 2], [.9] * 3), None, {}), [])

    def test_low_surprise_uses_signed_checkpoint_threshold(self):
        threshold = {**THRESHOLD, "direction": -1, "threshold": -0.2}
        incidents = observed_incidents(rows([0, 1, 2], [.1, .1, .1]), threshold, {})
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["opening_score"], 0.1)

    def test_stored_flags_become_one_row_per_burst_on_a_link(self):
        flag = lambda t, receiver, **more: {"t": t, "sender_ip": "a", "receiver_ip": receiver, "value": .9,
                                            "severity": "MEDIUM", **more}
        groups = alert_groups([flag(300, "b", severity="HIGH"), flag(10, "b"), flag(100, "b", incident=True),
                               flag(50, "c")])
        self.assertEqual([(g["receiver_ip"], g["opened"], g["last_seen"], g["events"], g["incident"], g["severity"])
                          for g in groups],
                         [("b", 10, 100, 2, True, "MEDIUM"), ("c", 50, 50, 1, False, "MEDIUM"),
                          ("b", 300, 300, 1, False, "HIGH")])


if __name__ == "__main__":
    unittest.main()
