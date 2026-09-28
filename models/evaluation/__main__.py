"""CLI: uv run python -m models.evaluation --scores data/model_cache/serve/scores_<day>.pt

The threshold sweep is a separate entry point: uv run python -m models.evaluation.thresholds
"""
from models.evaluation.report import main

raise SystemExit(main())
