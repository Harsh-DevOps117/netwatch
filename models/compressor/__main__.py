"""CLI: uv run python -m models.compressor --encoder mlp --context-encoder <ctx>/best.pt --out <dir>"""
from models.compressor.latents import main

raise SystemExit(main())
