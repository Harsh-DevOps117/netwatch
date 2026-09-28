"""CLI: uv run python -m models.explanation --context-encoder <ctx>/best.pt --day <day> --events 3000000
     or: uv run python -m models.explanation --world-model <b10.pt> --latents <day> --node-index <index>"""
import sys

if "--world-model" in sys.argv:
    from models.explanation.world_model import main
else:
    from models.explanation.attention import main

raise SystemExit(main())
