"""Check that the published documentation points at things that exist.

Run: uv run python -m tools.repo.verify_docs

For every published Markdown file (README.md, docs/*.md, each package README, the Hugging Face cards):
- every relative link and image resolves to a file, and every #anchor to a heading of that file;
- every repository path written in backticks (models/..., tools/..., ingest/..., docs/..., huggingface/...) exists;
- every `python -m <module>` names an importable module, and every --flag written after it on the same line is one
  that module's command line accepts (read from its --help).
Exits non-zero on any failure. It checks references, not prose: what a document says a stage does is checked by reading.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md")), *sorted(ROOT.glob("*/README.md")),
        *sorted(ROOT.glob("models/*/README.md")), *sorted(ROOT.glob("huggingface/*/README.md"))]
PREFIXES = ("models/", "tools/", "ingest/", "docs/", "huggingface/")
# Local-only folders are never published, so their notes are not checked here (tools/repo/verify_contracts.py).
LOCAL_ONLY = ("models/world_model_proxy/", "tools/world_model/")
DOCS = [p for p in DOCS if not str(p.relative_to(ROOT)).startswith(LOCAL_ONLY)]


def anchor(heading: str) -> str:
    """GitHub's heading anchor."""
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    return {anchor(m.group(1)) for m in re.finditer(r"^#+\s+(.*)$", path.read_text(), re.M)}


@lru_cache(maxsize=None)
def flags(module: str, dispatch: str = "") -> "set[str] | None":
    """The options a module's command line accepts, or None when it has no --help.

    `dispatch` is a flag the module's entry point switches on (`"--world-model" in sys.argv`) to hand over to another
    command line, whose options are then the ones that count.
    """
    out = subprocess.run([sys.executable, "-m", module, *([dispatch] if dispatch else []), "--help"],
                         capture_output=True, text=True, cwd=ROOT, timeout=300)
    if out.returncode != 0:
        return None
    return set(re.findall(r"(--[a-z0-9][a-z0-9-]*)", out.stdout))


def importable(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def check(path: Path) -> list[str]:
    problems, text = [], path.read_text()
    fenced = re.sub(r"```.*?```", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    for target in re.findall(r"\]\(([^)\s]+)\)", fenced):
        if re.match(r"[a-z]+://|mailto:", target):
            continue
        file, _, frag = target.partition("#")
        dest = (path.parent / file).resolve() if file else path
        if not dest.exists():
            problems.append(f"link to a missing file: {target}")
        elif frag and dest.suffix == ".md" and frag not in anchors(dest):
            problems.append(f"link to a missing heading: {target}")
    for ref in re.findall(r"`([^`\s]+)`", text):
        ref = ref.rstrip(".,:;)")
        if not ref.startswith(PREFIXES) or any(c in ref for c in "<>*{}|$"):
            continue
        name = ref.split("::")[0].split(":")[0]
        if not (ROOT / name).exists():
            problems.append(f"path does not exist: {ref}")
    for line in re.sub(r"\\\n\s*", " ", text).splitlines():          # continued command lines as one
        for module in re.findall(r"python -m ([\w.]+)", line):
            if not importable(module):
                problems.append(f"no module {module}")
                continue
            written = set(re.findall(r"\s(--[a-z0-9][a-z0-9-]*)", line.split(f"-m {module}", 1)[1].split("python -m")[0]))
            source = importlib.util.find_spec(module)
            code = Path(source.origin).read_text() if source and source.origin else ""
            if source and source.submodule_search_locations and (Path(source.origin).parent / "__main__.py").exists():
                code = (Path(source.origin).parent / "__main__.py").read_text()
            switch = next((f for f in re.findall(r'"(--[\w-]+)" in sys\.argv', code) if f in written and f != "--demo"), "")
            known = flags(module, switch)
            if '"--demo"' in code:
                written.discard("--demo")                   # read from sys.argv before the parser, so not in --help
            if known is not None and written - known - {"--help"}:
                problems.append(f"{module} has no option {sorted(written - known)}")
    return problems


def main() -> int:
    import argparse
    argparse.ArgumentParser(description=__doc__.split("\n")[0]).parse_args()
    sys.path.insert(0, str(ROOT))
    failed = 0
    for path in DOCS:
        for problem in check(path):
            print(f"FAIL  {path.relative_to(ROOT)}: {problem}")
            failed += 1
    print(f"{len(DOCS)} documents checked, {failed} problems")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
