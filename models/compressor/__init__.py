"""Block 9 -- the compressor: squeezes the context vector into a 32-wide latent plus a reconstruction error.

Reads a frozen context encoder and never trains it. Its output, `event_latents.parquet`, is what the world model reads.
"""
