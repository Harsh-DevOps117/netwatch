"""Which models serve which world-model tag, and whether that tag may serve at all.

Two ways to feed the world model from this machine's traffic, each a tag:

| tag | input | state | models |
|---|---|---|---|
| `lag` | capture files, a window of complete flows (`models.serving.live`) | ~150 s behind the wire: the 120 s flow timeout, up to one 30 s file, processing | the forecasting encoder (with flow records), its compressor and world model |
| `live` | the 10 ms detection stream (`models.serving.detect_live --forecast`) | a few seconds behind: the detection stream plus one forecast cycle | the detection encoder (no flow records), and a compressor and world model trained on its output |

The two are served side by side so either can be chosen by what it measures (`tools/measure/forecast_lead.py`:
how many predicted links are still in the future when served). `lag` was called `delay`; that name still resolves.

`serving.json` sits beside the models it names (a promoted training run writes it). A tag may also require a passing
parity report; `resolve` then hands out its checkpoints only when the report says "pass".
"""
from __future__ import annotations

import json
from pathlib import Path

ROLES = ("block7", "block8", "block9", "block10")
ALIASES = {"delay": "lag"}

TAGS = {
    "lag": {"input": "capture-window", "runner": "models.serving.live", "requires_parity": False,
            "description": "complete flows from a window of capture files; the state lags the wire by the flow timeout "
                           "(120 s) plus up to one file plus processing"},
    "live": {"input": "detection-stream", "runner": "models.serving.detect_live", "requires_parity": False,
             "description": "every flow 10 ms after its first packet, through the detection encoder; the compressor "
                            "and world model are trained on that encoder's output; a few seconds behind the wire"},
}


def write(path: "str | Path", checkpoints: dict, parity: "dict | None" = None, live: "dict | None" = None) -> Path:
    """Write serving.json.

    Input:  the registry path, {role: checkpoint} for the `lag` tag, optional {tag: parity report path}, optional
            {role: checkpoint} for the `live` tag (None: its models are not trained yet, and it refuses to serve)
    Output: the path written
    """
    for name, roles in (("lag", checkpoints), ("live", live)):
        missing = [role for role in ROLES if roles is not None and role not in roles]
        if missing:
            raise ValueError(f"serving.json: tag {name!r} needs a checkpoint for every role; missing {missing}")
    path = Path(path)
    parity = {ALIASES.get(tag, tag): report for tag, report in (parity or {}).items()}
    models = {"lag": checkpoints, "live": live}
    registry = {"tags": {tag: {**spec,
                               "checkpoints": ({r: str(models[tag][r]) for r in ROLES} if models[tag] else None),
                               "parity": str(parity[tag]) if tag in parity else None}
                         for tag, spec in TAGS.items()}}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(registry, indent=2) + "\n")
    return path


def resolve(path: "str | Path", tag: str) -> dict:
    """The checkpoints a tag serves with, or an error saying why it may not serve.

    Input:  the registry path, the tag
    Output: {role: Path}

    A tag without trained models, or one that requires parity without a passing report, is refused with the reason --
    never served with a warning.
    """
    path = Path(path)
    registry = json.loads(path.read_text())
    tags = registry.get("tags", {})
    tag = ALIASES.get(tag, tag)
    if tag not in tags and tag == "lag" and "delay" in tags:          # a serving.json written before the rename
        tag = "delay"
    if tag not in tags:
        raise ValueError(f"{path}: no tag {tag!r}; known: {sorted(tags)}")
    entry = tags[tag]
    if not entry.get("checkpoints"):
        raise PermissionError(f"tag {tag!r} has no trained models in {path}: train them (tools/train_all.sh, the "
                              f"live stages) and promote the run")
    if entry.get("requires_parity"):
        report = entry.get("parity")
        if not report:
            raise PermissionError(f"tag {tag!r} needs a passing parity report and has none")
        report = Path(report) if Path(report).is_absolute() else path.parent / report
        verdict = json.loads(report.read_text()).get("verdict") if report.exists() else "missing"
        if verdict != "pass":
            raise PermissionError(f"tag {tag!r} may not serve: its parity report {report} says {verdict!r}")
    # A relative checkpoint path is relative to serving.json, so a promoted folder (artifacts/current) can move as a whole.
    return {role: Path(p) if Path(p).is_absolute() else path.parent / p for role, p in entry["checkpoints"].items()}


def demo() -> None:
    """Self-check: lag resolves (and by its old name); live is refused until its models exist, then resolves."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        models = {role: root / f"{role}.pt" for role in ROLES}
        registry = write(root / "serving.json", models, parity={"delay": "lag.json"})
        assert resolve(registry, "lag")["block10"] == models["block10"]
        assert resolve(registry, "delay")["block10"] == models["block10"], "the old name must still resolve"
        assert json.loads(registry.read_text())["tags"]["lag"]["parity"] == "lag.json"
        try:
            resolve(registry, "live")
            raise AssertionError("live without models must be refused")
        except PermissionError:
            pass
        live = {role: f"live_{role}.pt" for role in ROLES}
        relative = write(root / "moved" / "serving.json", {role: f"{role}.pt" for role in ROLES}, live=live)
        assert resolve(relative, "lag")["block10"] == root / "moved" / "block10.pt"      # relative to serving.json
        assert resolve(relative, "live")["block9"] == root / "moved" / "live_block9.pt"
        old = root / "old.json"                                                         # written before the rename
        old.write_text(json.dumps({"tags": {"delay": {"checkpoints": {r: f"{r}.pt" for r in ROLES}}}}))
        assert resolve(old, "lag")["block7"] == root / "block7.pt"
    print("demo ok")


if __name__ == "__main__":
    demo()
