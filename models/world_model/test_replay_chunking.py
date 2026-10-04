import unittest

from models.world_model.inference import MIN_CHUNKS, chunking


class ChunkingTest(unittest.TestCase):
    def test_a_short_run_is_scored_in_many_chunks_and_seeded_from_its_later_half(self):
        self.assertEqual(chunking(13, 512), (1, 6))
        self.assertEqual(chunking(181, 512), (3, 90))
        self.assertEqual(chunking(0, 512), (1, 1))

    def test_a_long_run_keeps_the_trained_width(self):
        self.assertEqual(chunking(MIN_CHUNKS * 512, 512), (512, 512))
        self.assertEqual(chunking(28_000_000, 512), (512, 512))


if __name__ == "__main__":
    unittest.main()
