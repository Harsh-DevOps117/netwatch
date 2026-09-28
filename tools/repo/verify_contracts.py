"""Check every claim in the team's JSON contracts against the code and data that implement it.

The contracts are what teammates build against, so a stale field name there costs someone a day. This traces the
checkable claims -- referenced modules and callables, declared column lists, declared file paths -- and fails loudly on
any that no longer match. Run it after changing a schema, a CLI or a checkpoint format.

Not checkable here, and deliberately skipped: api-schema.json's HTTP endpoints, because the backend is not in this repository.

The contracts live in docs/dev/contracts/, which is kept out of the published repository (it is the development team's
working record). In a clone without it, the contract checks are reported as skipped and only the code checks run.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path

DOCS = Path("docs/dev/contracts")

# Kept out of the published repository on purpose: the Block 10 proxy is measured on slices and is not the deliverable,
# and the four tools that import it travel with it. Declared here rather than read from .gitignore, because a check
# that shells out to git silently passes everything in an export that has no .git directory.
LOCAL_ONLY_MODULES = ("models.world_model_proxy",)
LOCAL_ONLY_PATHS = ("models/world_model_proxy/", "tools/world_model/")


def checks() -> list[tuple[str, bool, str]]:
    """Every contract claim, as (what was checked, whether it holds, what was found).

    Input:  none; reads docs/dev/contracts/*.json when present, and imports the pipeline
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
    # Keyed by subject, matching the file names rather than by whose desk they came from.
    for name in ("live-sensor", "latents", "api", "modelling-notes"):
        path = DOCS / (f"{name}.json" if name.endswith("notes") else f"{name}-schema.json")
        if not path.exists():
            skip(f"{name}.json parses", f"{DOCS} is local-only (not in the published repository)")
            continue
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
        ("models.explanation.world_model", "seed_explanations"),
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

    # ---- live-sensor-schema.json: what the capture side provides must be what models.serving.live reads
    y = docs.get("live-sensor", {})
    if not y:
        return out + _code_only_note()
    from models.serving import live
    provide, reads = y.get("provide", {}), y.get("how_the_model_reads_it", {})
    check("live-sensor-schema.json names the file patterns the live service accepts",
          all(pattern in provide.get("file_names", "") for pattern in live.CAPTURES), f"live.CAPTURES = {live.CAPTURES}")
    window = live.main.__code__.co_consts                                   # the --window default lives in main()
    check("live-sensor-schema.json keeps as many files as one window needs (16)",
          "16" in provide.get("retention", "") and 16 in window, "live.py --window default")
    check(f"live-sensor-schema.json states the {int(live.HOLD_S)} s hold", f"{int(live.HOLD_S)} s" in json.dumps(reads))
    check("live-sensor-schema.json names the registry the live service reads by default",
          "artifacts/current/serving.json" in reads.get("models", "")
          and live.CURRENT.as_posix().endswith("artifacts/current/serving.json"))
    check("live-sensor-schema.json gives a capture folder", bool(y.get("save_to", {}).get("folder")))
    from ingest.sources.packets import PACKET_FIELDS
    listed = [f.get("column") for f in y.get("columns_the_model_side_extracts", {}).get("packet_fields", {}).get("fields", [])]
    check("live-sensor-schema.json lists the packet fields ingest extracts, in order",
          listed == [f.name for f in PACKET_FIELDS], f"contract {len(listed)}, PACKET_FIELDS {len(PACKET_FIELDS)}")

    # ---- latents-schema.json: latent columns must match what the exporter actually writes
    declared = list((docs.get("latents", {}).get("input", {}).get("columns", {}) or {}))
    exported = None
    manifests = sorted([*Path("artifacts/current/latents").glob("*/latents_manifest.json"),
                        *Path("data/latents").glob("*/*/latents_manifest.json")], key=lambda m: m.stat().st_mtime)
    exporter = Path("models/compressor/latents.py").stat().st_mtime
    if manifests and manifests[-1].stat().st_mtime >= exporter:          # an export older than the exporter proves nothing
        exported = json.loads(manifests[-1].read_text()).get("columns")
    if declared and not exported and manifests:
        skip("latents-schema.json latent columns match a real export",
             "every export on disk predates the current exporter (models/compressor/latents.py)")
    elif declared and exported:
        check("latents-schema.json latent columns match a real export", set(declared) == set(exported),
              f"only in doc: {sorted(set(declared) - set(exported))}; "
              f"only in export: {sorted(set(exported) - set(declared))}")
    elif declared:
        skip("latents-schema.json latent columns match a real export", "no latents export on disk (data/ and artifacts/ are not committed)")
    else:
        check("latents-schema.json latent columns match a real export", False, "no columns declared in the contract")

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





def _code_only_note() -> list[tuple[str, bool, str]]:
    """The contract checks that could not run, as one skip line."""
    return [("contract content checks", None, "the JSON contracts are not in this checkout")]


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
    return text.startswith(("data/", "models/", "tools/", "ingest/", "docs/", "huggingface/")) and "." in text.rsplit("/", 1)[-1]


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
