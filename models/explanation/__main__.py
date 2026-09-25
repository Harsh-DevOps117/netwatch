"""CLI: uv run python -m models.explanation --context-encoder <ctx>/best.pt --day <day> --events 3000000"""
from models.explanation.attention import main

raise SystemExit(main())
