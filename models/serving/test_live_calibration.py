"""Live score-tail calibration changes thresholds only after a complete window."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from models.serving.live_calibration import LiveScoreCalibration


class LiveCalibrationTest(unittest.TestCase):
    def test_four_hour_gate_and_checkpoint_floor(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scores.sqlite"
            cal = LiveScoreCalibration(path, {"Bot": 0.8, "World": 0.7},
                                       {"Bot": 0.1, "World": 0.1}, signature="checkpoint-v1",
                                       duration_s=4 * 3600, min_samples=3, tail_samples=1,
                                       max_gap_s=5 * 3600)
            cal.observe([(str(t), float(t), {"Bot": score, "World": score}) for t, score in
                         [(0, 0.1), (7200, 0.2), (14399, 0.9)]])
            self.assertFalse(cal.status("Bot")["ready"])
            self.assertEqual(cal.threshold("Bot"), 0.8)
            cal.observe([("last", 14400.0, {"Bot": 0.95, "World": 0.95})])
            self.assertTrue(cal.status("Bot")["ready"])
            self.assertEqual(cal.threshold("Bot"), 0.95)
            self.assertEqual(cal.status("World")["probability_calibration"], "checkpoint_unchanged")
            cal.close()
            resumed = LiveScoreCalibration(path, {"Bot": 0.8, "World": 0.7},
                                           {"Bot": 0.1, "World": 0.1}, signature="checkpoint-v1",
                                           duration_s=4 * 3600, min_samples=3, tail_samples=1,
                                           max_gap_s=5 * 3600)
            self.assertTrue(resumed.status("Bot")["ready"])
            resumed.observe([("after-gap", 40000.0, {"Bot": 0.2, "World": 0.2})])
            self.assertFalse(resumed.status("Bot")["ready"])
            self.assertEqual(resumed.threshold("Bot"), 0.8)
            resumed.close()

    def test_new_policy_does_not_reuse_old_window(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scores.sqlite"
            old = LiveScoreCalibration(path, {"Bot": 0.8}, {"Bot": 0.1},
                                       signature="checkpoint-v1", duration_s=7200)
            old.observe([("old", 0.0, {"Bot": 0.9})])
            old.close()
            four_hour = LiveScoreCalibration(path, {"Bot": 0.8}, {"Bot": 0.1},
                                             signature="checkpoint-v1", duration_s=14400)
            self.assertEqual(four_hour.status("Bot")["samples"], 0)
            self.assertFalse(four_hour.status("Bot")["ready"])
            four_hour.close()

    def test_submitted_batches_are_written_once_without_blocking_readers(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "scores.sqlite"
            policy = dict(signature="checkpoint-v1", duration_s=4 * 3600, min_samples=3, tail_samples=1,
                          max_gap_s=5 * 3600)
            cal = LiveScoreCalibration(path, {"Bot": 0.8}, {"Bot": 0.1}, **policy)
            with cal.db_lock:                           # a transaction in progress on the writer
                for t, score in [(0, 0.1), (7200, 0.2), (14399, 0.9)]:
                    cal.submit([(str(t), float(t), {"Bot": score})])
                cal.submit([("0", 0.0, {"Bot": 0.1})])  # the same flow again is not a second sample
                # The caller did not wait for the database: nothing has been written yet.
                self.assertEqual(cal.status("Bot")["samples"], 0)
                self.assertEqual(cal.threshold("Bot"), 0.8)
                # Nor does it wait once the writer is too far behind: that batch is left out, and counted.
                with mock.patch("models.serving.live_calibration.MAX_PENDING", 4):
                    cal.submit([("left out", 7300.0, {"Bot": 0.99})])
                self.assertEqual(cal.status("Bot")["skipped_flows"], 1)
            cal.submit([("last", 14400.0, {"Bot": 0.95})])
            cal.flush()
            self.assertTrue(cal.status("Bot")["ready"])
            self.assertEqual(cal.threshold("Bot"), 0.95)
            cal.submit([("another", 14400.0, {"Bot": 0.5})])
            cal.close()                                 # writes what is still pending
            resumed = LiveScoreCalibration(path, {"Bot": 0.8}, {"Bot": 0.1}, **policy)
            self.assertEqual(resumed.status("Bot")["samples"], 5)
            resumed.close()


if __name__ == "__main__":
    unittest.main()
