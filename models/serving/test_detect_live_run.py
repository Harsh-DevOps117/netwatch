"""The live runner must not advance past packets waiting to be processed."""
import queue
import unittest

from models.serving.detect_live import BATCH_PACKETS, run


class FakeTracker:
    def __init__(self):
        self.advances = []

    def advance(self, clock):
        self.advances.append(clock)

    def finish(self):
        pass


class FakeDetector:
    def __init__(self, packets):
        self.packets = packets
        self.tracker = FakeTracker()
        self.first_score_advances = None

    def add(self, packet):
        pass

    def score(self, wall):
        if self.first_score_advances is None:
            self.first_score_advances = len(self.tracker.advances)
            self.packets.put(None)


class LiveRunnerTest(unittest.TestCase):
    def test_backlog_does_not_advance_to_wall_clock(self):
        packets = queue.Queue()
        for i in range(4 * BATCH_PACKETS + 1):      # one more than the largest pass takes
            packets.put(i)
        detector = FakeDetector(packets)
        run(detector, packets, live=True, grace=0.02)
        self.assertEqual(detector.first_score_advances, 0)


if __name__ == "__main__":
    unittest.main()
