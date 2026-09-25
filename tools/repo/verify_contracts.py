"""Check every claim in docs/*.json against the code and data that implement it.

The contracts are what teammates build against, so a stale field name there costs someone a day. This traces the
checkable claims -- referenced modules and callables, declared column lists, declared file paths -- and fails loudly on
any that no longer match. Run it after changing a schema, a CLI or a checkpoint format.

Not checkable here, and deliberately skipped: dev.json's HTTP endpoints, because the backend is not in this repository.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path

DOCS = Path("docs")

# Kept out of the published repository on purpose: the Block 10 proxy is measured on slices and is not the deliverable,
# and the four tools that import it travel with it. Declared here rather than read from .gitignore, because a check
# that shells out to git silently passes everything in an export that has no .git directory.
LOCAL_ONLY_MODULES = ("models.world_model_proxy",)
LOCAL_ONLY_PATHS = ("models/world_model_proxy/", "tools/world_model/")


def checks() -> list[tuple[str, bool, str]]:
    """Every contract claim, as (what was checked, whether it holds, what was found).

    Input:  none; reads docs/*.json and imports the pipeline
    Output: list of (label, ok, detail)
    """
    out: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        out.append((label, bool(ok), detail))

    def skip(label: str, reason: str) -> None:
        """Record a check that cannot run here, distinct from one that failed.

        Two things are legitimately absent from a published clone: the Block 10 proxy, which is kept local, and
        everything under data/, which is never committed. Reporting either as a failure would train people to ignore
        this tool's output.
        """
        out.append((label, None, reason))

    # ---- the JSONs parse at all
    docs = {}
    for name in ("yug", "vedant", "dev", "kaustuk"):
        path = DOCS / f"{name}.json"
        try:
            docs[name] = json.loads(path.read_text())
            check(f"{name}.json parses", True, f"version {docs[name].get('version')}")
        except Exception as exc:                                     # noqa: BLE001 -- report, do not raise
            check(f"{name}.json parses", False, str(exc))

    # ---- callables the contracts promise
    promised = [
        ("models.serving.emitter", "AlertEmitter"), ("models.serving.emitter", "Recalibrator"),
        ("models.detector.checkpoint", "save_head"), ("models.detector.checkpoint", "load_head"),
        ("models.detector.checkpoint", "save_calibration"), ("models.detector.model", "class_scores"),
        ("models.world_model_proxy.model", "save_world_model"), ("models.world_model_proxy.model", "load_world_model"),
        ("models.evaluation.thresholds", "sweep"), ("models.evaluation.thresholds", "write_threshold"),
        ("models.evaluation.thresholds", "incidents"),
        ("models.context_encoder.model", "ContextEncoder"), ("models.context_encoder.model", "LinkMemory"),
        ("models.compressor.latents", "frozen_context_encoder"), ("models.compressor.train", "run_compressor"),
        ("models.context_encoder.train", "run_stream"), ("models.context_encoder.train", "LinkPredictor"),
        ("models.serving.graph", "NodeRegistry"), ("models.serving.graph", "LinkRegistry"),
        ("models.serving.graph", "OnlineNeighbours"), ("models.serving.graph", "ReorderBuffer"),
        ("models.evaluation.report", "report"), ("models.evaluation.report", "average_precision"),
        ("models.explanation.attention", "attention_over_batch"),
        ("models.explanation.attention", "input_attribution"),
    ]
    for module, attr in promised:
        try:
            check(f"{module}.{attr} exists", hasattr(importlib.import_module(module), attr))
        except ModuleNotFoundError as exc:
            label = f"{module}.{attr} exists"
            if module.startswith(LOCAL_ONLY_MODULES):
                skip(label, "kept local, not published in this repository")
            else:
                check(label, False, str(exc))
        except Exception as exc:                                     # noqa: BLE001
            check(f"{module}.{attr} exists", False, str(exc))

    # ---- the LRU cap the contracts now advertise
    from models.context_encoder.model import ContextEncoder
    import inspect
    sig = inspect.signature(ContextEncoder.__init__)
    check("ContextEncoder takes capacity", "capacity" in sig.parameters)
    check("begin_day takes capacity", "capacity" in inspect.signature(ContextEncoder.begin_day).parameters)
    enc = ContextEncoder("split", capacity=0.25)
    enc.begin_day(1000)
    check("capacity 0.25 of 1000 links -> 250 slots", len(enc.memory.state) == 250, f"{len(enc.memory.state)} slots")
    plain = ContextEncoder("split")
    plain.begin_day(1000)
    check("default stays offline (one row per link)", plain.memory.capacity is None and len(plain.memory.state) == 1000)

    # ---- explainability is opt-in and leaves the encoding untouched
    enc = ContextEncoder("split")
    check("attention capture is off by default", enc.explain is False)
    check("encoder exposes last_attention", hasattr(enc, "last_attention"))

    # ---- yug.json: the 20-packet summary width, which a live buffer is sized from
    from ingest.build.events import AGG_COLUMNS
    y = docs.get("yug", {})
    summary = next((m for m in y.get("messages", []) if "summary" in str(m.get("name", "")).lower()
                    or m.get("kind") == 2), None)
    check("yug.json has a 20-packet summary message", summary is not None)
    if summary is not None:
        declared = json.dumps(summary)
        check(f"yug.json states the real AGG width ({len(AGG_COLUMNS)})",
              str(len(AGG_COLUMNS)) in declared, f"AGG_COLUMNS = {len(AGG_COLUMNS)}")

    # ---- yug.json: side features must match SIDE_COLUMNS
    from models.context_encoder.data import SIDE_COLUMNS
    side_fields = set()
    for message in y.get("messages", []):
        side_fields |= set((message.get("fields", {}) or {}).get("side", {}) or {})
    if side_fields:
        real = set(SIDE_COLUMNS) - {"event_id", "sender_node_id", "receiver_node_id"}
        check("yug.json side fields are all real SIDE_COLUMNS", side_fields <= set(SIDE_COLUMNS),
              f"unknown: {sorted(side_fields - set(SIDE_COLUMNS))}")
        check("yug.json covers every side feature", real <= side_fields, f"missing: {sorted(real - side_fields)}")

    # ---- yug.json: the record message width
    from models.context_encoder.records import RECORD_COLUMNS
    record = next((m for m in y.get("messages", []) if "record" in str(m.get("name", "")).lower()), None)
    check("yug.json has a flow record message", record is not None)
    if record is not None:
        check(f"yug.json states the real record width ({len(RECORD_COLUMNS)})",
              str(len(RECORD_COLUMNS)) in json.dumps(record), f"RECORD_COLUMNS = {len(RECORD_COLUMNS)}")

    # ---- vedant.json: latent columns must match what the exporter actually writes
    declared = list((docs.get("vedant", {}).get("input", {}).get("columns", {}) or {}))
    exported = None
    for manifest in sorted(Path("data/latents").glob("*/*/latents_manifest.json")):
        exported = json.loads(manifest.read_text()).get("columns")
        if exported:
            break
    if declared and exported:
        check("vedant.json latent columns match a real export", set(declared) == set(exported),
              f"only in doc: {sorted(set(declared) - set(exported))}; "
              f"only in export: {sorted(set(exported) - set(declared))}")
    elif declared:
        skip("vedant.json latent columns match a real export", "no latents export on disk (data/ is not committed)")
    else:
        check("vedant.json latent columns match a real export", False, "no columns declared in the contract")

    # ---- files documented as removed must actually be absent
    for name, doc in docs.items():
        for section, body in doc.items():
            if not (isinstance(section, str) and section.startswith("removed") and isinstance(body, dict)):
                continue
            for path in body:
                if _is_path(path):
                    check(f"{name}.json: removed file is absent: {path}", not Path(path).exists())

    # ---- every concrete path the JSONs name, that is not a <pattern>, exists
    for name, doc in docs.items():
        for path in sorted(_paths(doc)):
            if "<" in path or "*" in path:
                continue
            if not Path(path).exists():
                if path.startswith("data/"):
                    skip(f"{name}.json path: {path}", "under data/, which is never committed")
                    continue
                if path.startswith(LOCAL_ONLY_PATHS):
                    skip(f"{name}.json path: {path}", "kept local, not published in this repository")
                    continue
            check(f"{name}.json path exists: {path}", Path(path).exists())
    return out





def _paths(node, found=None) -> set[str]:
    """Every string in a JSON tree that looks like a repository path, excluding sections about deleted files.

    Input:  a parsed JSON value
    Output: set of path-like strings

    A key beginning "removed" documents files that were deleted on purpose, so the paths under it are claims that
    something is **absent** -- checking them for existence would invert the test.
    """
    found = set() if found is None else found
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key.startswith("removed"):
                continue
            if isinstance(key, str) and _is_path(key):
                found.add(key)
            _paths(value, found)
    elif isinstance(node, list):
        for value in node:
            _paths(value, found)
    elif isinstance(node, str) and _is_path(node):
        found.add(node)
    return found


def _is_path(text: str) -> bool:
    """Whether a string is a bare repository path rather than prose that mentions one."""
    text = text.strip()
    if " " in text or not text or text.startswith(("http", "-")):
        return False
    return text.startswith(("data/", "models/", "tools/", "ingest/", "docs/")) and "." in text.rsplit("/", 1)[-1]


def main() -> int:
    results = checks()
    width = max(len(label) for label, _, _ in results)
    failed = sum(1 for _, ok, _ in results if ok is False)
    skipped = sum(1 for _, ok, _ in results if ok is None)
    for label, ok, detail in results:
        mark = "skip" if ok is None else ("ok  " if ok else "FAIL")
        print(f"  {mark}  {label.ljust(width)}  {detail}")
    print(f"\n{len(results) - failed - skipped} passed, {skipped} skipped, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
