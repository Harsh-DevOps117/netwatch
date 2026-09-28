"""Module 5 — the three Parquet files and the manifest of design section 8.

Manifest plus Parquet, not one large JSON, matching the upstream contract's own discipline: a consumer that wants only
the risk scores should not have to parse the rollouts to reach them.

| file | one row per | consumed by |
|---|---|---|
| `risk_scores.parquet` | real (non-rollout) event | MITRE-stage mapping, baseline comparison |
| `rollout_trajectories.parquet` | (seed, rollout step) | the demo interface, baseline comparison |
| `attention_weights.parquet` | (event, neighbour or query) | explainability, directly — no post-hoc SHAP pass |

`observation_population` is passed through to `risk_scores.parquet` and never recomputed, because every downstream
comparison is required to stratify on it and a recomputed value could disagree with the one the metrics were built from.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

CONTRACT_VERSION = "1.0-block10"
CONSUMES_SCHEMA = "vedant-2026-09"

RISK_SCORES = "risk_scores.parquet"
ROLLOUTS = "rollout_trajectories.parquet"
ATTENTION = "attention_weights.parquet"
MANIFEST = "world_model_output_schema.json"

LAYER_NEIGHBOURHOOD, LAYER_GLOBAL = "neighborhood", "global_readout"


def write_risk_scores(out_dir: "str | Path", *, event_id, t, next_event_pred_error,
                      ranking_scores, observation_population) -> int:
    """One row per real event: the surprise signal and the ranking output.

    Input:  the directory, per-event ids and times, the auxiliary head's error, the ranking output as a list of
            (node_id, score) per event, the passed-through population
    Output: rows written

    `ranking_scores` is a list column rather than a wide frame because the candidate set is every currently-active node
    and its size changes per event; a fixed-width encoding would need a truncation rule that the design explicitly does
    not want.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pairs = pa.array([[{"node_id": int(n), "score": float(s)} for n, s in row] for row in ranking_scores],
                     type=pa.list_(pa.struct([("node_id", pa.int32()), ("score", pa.float32())])))
    table = pa.table({
        "event_id": pa.array(np.asarray(event_id, dtype=np.int64)),
        "t": pa.array(np.asarray(t, dtype=np.float64)),
        "next_event_pred_error": pa.array(np.asarray(next_event_pred_error, dtype=np.float64)),
        "ranking_scores": pairs,
        "observation_population": pa.array(np.asarray(observation_population, dtype=object).astype(str)),
    })
    pq.write_table(table, out_dir / RISK_SCORES, compression="zstd")
    return table.num_rows


def write_rollouts(out_dir: "str | Path", rows: "list[dict]") -> int:
    """One row per (seed, rollout step).

    Input:  the directory, dicts with seed_id, rollout_step, predicted sender/receiver/z, cumulative_risk,
            stays_on_manifold
    Output: rows written

    `stays_on_manifold` is a claim about the *predicted* feature ranges falling inside the observed training
    distribution. A rollout that leaves it has not necessarily failed, but its later steps are extrapolation and should
    not be read as a forecast.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    predicted = pa.array([{"sender": int(r["sender"]), "receiver": int(r["receiver"]),
                           "z": [float(v) for v in np.asarray(r["z"]).ravel()]} for r in rows],
                         type=pa.struct([("sender", pa.int32()), ("receiver", pa.int32()),
                                         ("z", pa.list_(pa.float32()))]))
    table = pa.table({
        "seed_id": pa.array([int(r["seed_id"]) for r in rows], pa.int64()),
        "rollout_step": pa.array([int(r["rollout_step"]) for r in rows], pa.int32()),
        "predicted_event": predicted,
        "cumulative_risk": pa.array([float(r["cumulative_risk"]) for r in rows], pa.float64()),
        "stays_on_manifold": pa.array([bool(r["stays_on_manifold"]) for r in rows], pa.bool_()),
    })
    # Additive, only when the rollout chose its targets: the chosen link's surprise on the calibrated scale, and the
    # ranking head's leading candidates for that step. Readers of the base contract are unaffected.
    if all("surprise" in r for r in rows):
        table = table.append_column("surprise", pa.array([float(r["surprise"]) for r in rows], pa.float64()))
    if all("candidates" in r for r in rows):
        candidate = pa.struct([("node", pa.int32()), ("probability", pa.float32()), ("surprise", pa.float32())])
        table = table.append_column("candidates", pa.array([r["candidates"] for r in rows], pa.list_(candidate)))
    pq.write_table(table, out_dir / ROLLOUTS, compression="zstd")
    return table.num_rows


def write_attention(out_dir: "str | Path", rows: "list[dict]") -> int:
    """One row per (event, neighbour or query): the explainability artefact.

    Input:  the directory, dicts with event_id, layer, source_node_id, weight, query_index
    Output: rows written

    `query_index` is -1 for neighbourhood rows, where it has no meaning, rather than 0 — which would read as "the first
    global query" and quietly merge two different kinds of row in any group-by.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    table = pa.table({
        "event_id": pa.array([int(r["event_id"]) for r in rows], pa.int64()),
        "layer": pa.array([str(r["layer"]) for r in rows]),
        "source_node_id": pa.array([int(r["source_node_id"]) for r in rows], pa.int32()),
        "weight": pa.array([float(r["weight"]) for r in rows], pa.float32()),
        "query_index": pa.array([int(r.get("query_index", -1)) for r in rows], pa.int32()),
    })
    pq.write_table(table, out_dir / ATTENTION, compression="zstd")
    return table.num_rows


def write_manifest(out_dir: "str | Path", *, commit: str = "unknown", days: "list[str] | None" = None,
                   counts: "dict | None" = None) -> Path:
    """The manifest that names the three files and what produced them.

    Input:  the directory, the producing commit, which days the run covered, row counts per file
    Output: the manifest path
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "contract_version": CONTRACT_VERSION,
        "producer": f"block10_world_model (commit {commit})",
        "consumes_schema": CONSUMES_SCHEMA,
        "files": {"rollout_trajectories": ROLLOUTS, "risk_scores": RISK_SCORES, "attention_weights": ATTENTION},
        "days": list(days or []),
        "rows": dict(counts or {}),
        "notes": [
            "risk_scores.observation_population is passed through from the input, never recomputed: every downstream "
            "comparison stratifies on it and a recomputed value could disagree with the one the metrics used.",
            "attention_weights.query_index is -1 for neighborhood rows, where it has no meaning.",
            "ranking_scores covers every currently-active candidate, with no top-N truncation.",
        ],
    }
    path = out_dir / MANIFEST
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return path


def demo() -> None:
    """Self-check: the three files round-trip with the types the contract states."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        n = write_risk_scores(tmp, event_id=[1, 2], t=[1.0, 2.0], next_event_pred_error=[0.1, 0.2],
                              ranking_scores=[[(7, 0.9), (8, 0.1)], [(7, 0.4)]],
                              observation_population=["early_observation", "completed_before_budget"])
        assert n == 2
        table = pq.read_table(Path(tmp) / RISK_SCORES)
        assert table.column_names == ["event_id", "t", "next_event_pred_error", "ranking_scores",
                                     "observation_population"]
        first = table["ranking_scores"].to_pylist()[0]
        assert first[0]["node_id"] == 7 and abs(first[0]["score"] - 0.9) < 1e-6
        # variable candidate counts must survive: two candidates then one
        assert [len(row) for row in table["ranking_scores"].to_pylist()] == [2, 1]

        assert write_rollouts(tmp, [{"seed_id": 0, "rollout_step": 0, "sender": 1, "receiver": 2,
                                     "z": np.zeros(32), "cumulative_risk": 0.5,
                                     "stays_on_manifold": True}]) == 1
        rollout = pq.read_table(Path(tmp) / ROLLOUTS).to_pylist()[0]
        assert len(rollout["predicted_event"]["z"]) == 32 and rollout["stays_on_manifold"] is True

        assert write_attention(tmp, [
            {"event_id": 1, "layer": LAYER_NEIGHBOURHOOD, "source_node_id": 5, "weight": 0.7},
            {"event_id": 1, "layer": LAYER_GLOBAL, "source_node_id": 6, "weight": 0.3, "query_index": 1},
        ]) == 2
        attention = pq.read_table(Path(tmp) / ATTENTION).to_pylist()
        assert attention[0]["query_index"] == -1, "a neighbourhood row has no query, and -1 says so"
        assert attention[1]["query_index"] == 1

        manifest = json.loads(write_manifest(tmp, commit="abc123", days=["Friday-02-03-2018"],
                                             counts={"risk_scores": 2}).read_text())
        assert manifest["contract_version"] == CONTRACT_VERSION
        assert set(manifest["files"]) == {"rollout_trajectories", "risk_scores", "attention_weights"}
    print("demo ok")


if __name__ == "__main__":
    demo()
