"""Incident event tracing must retain the exact run and incident identity."""
import unittest

import torch

from models.serving.emitter import AlertEmitter


class EmitterTraceTest(unittest.TestCase):
    def test_default_incident_quiet_gap_is_120_seconds(self):
        emitter = AlertEmitter(0.8)
        self.assertEqual(emitter.gap, 120.0)
        for second in (0.0, 1.0):
            self.assertIsNone(emitter.push(7, 0.9, second))
        self.assertIsNotNone(emitter.push(7, 0.9, 2.0))
        self.assertIsNone(emitter.push(7, 0.9, 100.0))
        self.assertIsNotNone(emitter.push(7, 0.9, 221.0))

    def test_callback_identifies_contributing_run_across_batches(self):
        emitter = AlertEmitter(0.8)
        seen = []
        emitter.push_batch(torch.tensor([7, 7]), torch.tensor([0.9, 0.9]),
                           torch.tensor([1.0, 2.0]), on_step=lambda *row: seen.append(row))
        opened = emitter.push_batch(torch.tensor([7, 7]), torch.tensor([0.9, 0.95]),
                                    torch.tensor([3.0, 4.0]), on_step=lambda *row: seen.append(row))
        self.assertEqual(len(opened), 1)
        self.assertEqual([row[4] for row in seen], [None, None, 1, 1])
        self.assertEqual([row[5] for row in seen], [None, None, 3.0, 3.0])


if __name__ == "__main__":
    unittest.main()
