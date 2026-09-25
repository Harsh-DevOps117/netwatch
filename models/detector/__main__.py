"""CLI: uv run python -m models.detector --days <days> --context-encoder <ctx>/best.pt --save <head.pt>"""
from models.detector.train import main

raise SystemExit(main())
