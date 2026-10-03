"""Operator threshold selection is safe, gated, and restart-persistent."""
import tempfile
import unittest
from pathlib import Path

from models.serving.threshold_mode import ThresholdMode


class ThresholdModeTest(unittest.TestCase):
    def test_checkpoint_default_and_live_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "mode.json"
            choice = ThresholdMode(path)
            self.assertEqual(choice.status(False)["effective"], "checkpoint")
            with self.assertRaises(ValueError):
                choice.set("live", False)
            self.assertFalse(path.exists())
            self.assertEqual(choice.set("live", True)["effective"], "live")
            self.assertEqual(ThresholdMode(path).status(True)["effective"], "live")
            self.assertEqual(ThresholdMode(path).status(False)["effective"], "checkpoint")
            self.assertEqual(choice.set("checkpoint", False)["effective"], "checkpoint")
            self.assertEqual(ThresholdMode(path).requested(), "checkpoint")


if __name__ == "__main__":
    unittest.main()
