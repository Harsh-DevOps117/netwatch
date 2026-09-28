"""CLI: uv run python -m models.world_model --latents data/latents/<run>/<day> --out data/model_cache/world_model"""
from models.world_model.cli import main

raise SystemExit(main())
