"""CLI: uv run python -m ingest.verify <day>"""
from ingest.verify.checks import main

raise SystemExit(main())
