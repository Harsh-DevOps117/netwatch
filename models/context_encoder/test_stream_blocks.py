"""The neighbour search gives the same answer however few rows it holds in memory at once."""
import unittest
from unittest import mock

import numpy as np

from models.context_encoder import stream


class BoundedSearchTest(unittest.TestCase):
    def test_small_blocks_match_one_pass(self):
        rng = np.random.default_rng(7)
        # A flood on one link, with other hosts' traffic mixed in: the flood's rows need the deep pass.
        sender = np.where(rng.random(3000) < .7, 1, rng.integers(2, 60, 3000))
        receiver = np.where(sender == 1, 2, rng.integers(0, 60, 3000))
        index = stream.NeighbourIndex(sender, receiver)
        whole = index.query(sender, receiver, np.arange(3000), device="cpu")
        with mock.patch.object(stream, "CELLS", stream.LOOKBACK * 7):       # seven rows at a time at full depth
            blocks = index.query(sender, receiver, np.arange(3000), device="cpu")
        self.assertTrue((whole >= 0).any())
        np.testing.assert_array_equal(blocks, whole)


if __name__ == "__main__":
    unittest.main()
