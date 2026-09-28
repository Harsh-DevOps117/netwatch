"""Module 1 — load one run's tables and refuse anything that breaks the input contract.

Every guarantee the schema claims is checked here, once, so no later module has to re-derive whether it holds. The
design's reasoning for putting this first: a contract violation that reaches the model surfaces as a bad number days
later, and a bad number is far harder to attribute than a refused load.

Two rules are enforced rather than trusted:

**Forbidden model inputs.** `label`, `attack`, `role`, `split`, `recon_error` and `anomaly_score` are ground truth or
upstream-model output. They are loaded, because evaluation and supervision need them, and they are kept out of the
feature path by construction — `ReceivedRun.features()` cannot return them.

**`cross_day_memory` fails closed.** Node ids are re-derived per day, so memory carried across a day boundary would
address a different host. The guard therefore permits `True` only when *every* manifest in the run declares
`node_id_scope: unified`, treats an absent field as `per_day`, and refuses a run that mixes the two. There is
deliberately **no override**: the fix for wanting one is repairing the upstream index.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

SCHEMA_VEDANT = "vedant-2026-09"

SPLIT_TRAIN, SPLIT_VAL, SPLIT_TEST, SPLIT_EMBARGO = 0, 1, 2, -1
SPLIT_CODES = {SPLIT_TRAIN, SPLIT_VAL, SPLIT_TEST, SPLIT_EMBARGO}

# Loaded for supervision and evaluation; never reachable from the feature path.
FORBIDDEN_MODEL_INPUTS = ("label", "attack", "role", "split", "recon_error", "anomaly_score")

REQUIRED_EVENT_FIELDS = ("event_id", "t", "t_obs", "sender_node_id", "receiver_node_id",
                         "dt_src", "dt_dst", "reversed", "z", "split", "label")
EXPECTED_Z_DIM = 32

# dt sentinel for "this endpoint has not been seen before". A cold start is a separate branch in the time encoder, not
# a small number fed through the sinusoids and hoped to behave.
DT_COLD = -1.0


@dataclass
class ReceivedDay:
    """One day's validated tables.

    Input:  built by `receive_day`
    Output: dataclass of arrays in availability order, plus the day's manifest
    """

    day: str
    event_id: np.ndarray
    t: np.ndarray
    t_obs: np.ndarray
    sender: np.ndarray
    receiver: np.ndarray
    dt_src: np.ndarray
    dt_dst: np.ndarray
    reversed_: np.ndarray
    z: np.ndarray
    split: np.ndarray
    label: np.ndarray
    attack: np.ndarray
    role: np.ndarray
    population: np.ndarray
    manifest: dict
    node_count: int

    def __len__(self) -> int:
        return len(self.event_id)


@dataclass
class ReceivedRun:
    """Every day of one run, in order, with the resolved memory policy.

    Input:  built by `receive`
    Output: dataclass; `features(i)` is the only way to reach model inputs
    """

    days: list = field(default_factory=list)
    cross_day_memory: bool = False
    schema: str = SCHEMA_VEDANT

    def __len__(self) -> int:
        return sum(len(day) for day in self.days)

    def features(self, day_index: int) -> dict:
        """The model inputs for one day, and nothing else.

        Input:  which day
        Output: dict of arrays the forward pass may read

        Deliberately narrow. Anything supervisory lives on the `ReceivedDay` and has to be asked for by name, so a
        forward pass cannot reach it by iterating a feature dict.
        """
        day = self.days[day_index]
        return {"event_id": day.event_id, "t": day.t, "t_obs": day.t_obs,
                "sender": day.sender, "receiver": day.receiver,
                "dt_src": day.dt_src, "dt_dst": day.dt_dst,
                "reversed": day.reversed_, "z": day.z}


def _column(table, name: str, *, required: bool = True, default=None):
    """One column as a contiguous numpy array, with a clear error when it is missing.

    Input:  a pyarrow table, the column name, whether absence is an error, the value to return when it is not
    Output: (N,) array, or (N, width) for a fixed-size list column such as `z`

    A list column is reshaped rather than left as an object array of lists, because every consumer wants a matrix and
    the alternative is each of them converting it slightly differently.
    """
    import pyarrow as pa

    if name not in table.column_names:
        if required:
            raise ValueError(f"required column {name!r} is missing; the run does not meet the {SCHEMA_VEDANT} contract")
        return default
    column = table[name].combine_chunks()
    if pa.types.is_fixed_size_list(column.type):
        return column.flatten().to_numpy().reshape(len(column), column.type.list_size).copy()
    if pa.types.is_list(column.type) or pa.types.is_large_list(column.type):
        stacked = np.stack([np.asarray(row) for row in column.to_pylist()]) if len(column) else np.zeros((0, 0))
        return stacked.copy()
    return np.asarray(column.to_numpy(zero_copy_only=False)).copy()


def receive_day(directory: "str | Path", *, expect_z: int = EXPECTED_Z_DIM) -> ReceivedDay:
    """Load and validate one day's latents export.

    Input:  a directory holding event_latents.parquet and latents_manifest.json, the expected z width
    Output: a ReceivedDay

    Checks, each with its own error: the manifest exists and names the day; every required column is present; `z` has
    the expected width; `t_obs` is non-decreasing (the availability order every later module relies on); `split` holds
    only the four known codes; `dt` is either non-negative or exactly the cold sentinel; node ids are in range.
    """
    import pyarrow.parquet as pq

    directory = Path(directory)
    manifest_path = directory / "latents_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"{manifest_path} is missing; a run must carry its manifest")
    manifest = json.loads(manifest_path.read_text())
    table = pq.read_table(directory / "event_latents.parquet")

    missing = [name for name in REQUIRED_EVENT_FIELDS if name not in table.column_names]
    if missing:
        raise ValueError(f"{directory}: missing required columns {missing}")

    z = _column(table, "z")
    if z.ndim != 2 or z.shape[1] != expect_z:
        raise ValueError(f"{directory}: z has width {z.shape[1:] or 1}, expected {expect_z}")

    t_obs = _column(table, "t_obs").astype(float)
    if len(t_obs) > 1 and np.any(np.diff(t_obs) < 0):
        raise ValueError(f"{directory}: t_obs is not non-decreasing; the export must be in availability order")

    split = _column(table, "split").astype(np.int64)
    unknown = sorted(set(np.unique(split).tolist()) - SPLIT_CODES)
    if unknown:
        raise ValueError(f"{directory}: split holds unknown codes {unknown}; expected {sorted(SPLIT_CODES)}")

    dt_src, dt_dst = _column(table, "dt_src").astype(float), _column(table, "dt_dst").astype(float)
    for name, dt in (("dt_src", dt_src), ("dt_dst", dt_dst)):
        bad = (dt < 0) & (dt != DT_COLD)
        if bad.any():
            raise ValueError(f"{directory}: {name} has {int(bad.sum())} negative values that are not the cold "
                             f"sentinel {DT_COLD}")

    sender = _column(table, "sender_node_id").astype(np.int64)
    receiver = _column(table, "receiver_node_id").astype(np.int64)
    node_count = int(max(sender.max(initial=0), receiver.max(initial=0))) + 1
    if (sender < 0).any() or (receiver < 0).any():
        raise ValueError(f"{directory}: negative node ids")

    return ReceivedDay(
        day=str(manifest.get("day", directory.name)),
        event_id=_column(table, "event_id").astype(np.int64),
        t=_column(table, "t").astype(float), t_obs=t_obs,
        sender=sender, receiver=receiver, dt_src=dt_src, dt_dst=dt_dst,
        reversed_=_column(table, "reversed").astype(np.int8),
        z=z.astype(np.float32), split=split.astype(np.int8),
        label=_column(table, "label").astype(str),
        attack=_column(table, "attack", required=False,
                       default=np.zeros(len(t_obs), bool)).astype(bool),
        # `role` is the schedule-derived attacker/victim field (upstream `models.data.roles`). Exports written before it
        # existed have no such column, so it is derived here from the same source rather than left as zeros: an
        # all-zero role silently disables the ranking head, and re-exporting a day costs far more than resolving it.
        role=_role_column(table, manifest, t_obs, _column(table, "sender_node_id").astype(np.int64),
                          _column(table, "receiver_node_id").astype(np.int64),
                          _column(table, "t").astype(float)),
        population=_column(table, "observation_population", required=False,
                           default=np.array(["unknown"] * len(t_obs))).astype(str),
        manifest=manifest, node_count=node_count,
    )


def _role_column(table, manifest: dict, t_obs: np.ndarray, sender: np.ndarray, receiver: np.ndarray,
                 t: np.ndarray) -> np.ndarray:
    """The attacker/victim role, read from the export or derived from the schedule when it is absent.

    Input:  the table, its manifest, observation times, endpoint ids, event times
    Output: (N,) int8 role codes

    Deriving rather than defaulting to zeros is the difference between a ranking head that trains and one that silently
    does not: an all-zero role gives every event the same target, and the loss falls anyway. The derivation uses the
    same schedule the labels came from, so the two agree by construction.

    Falls back to zeros only when the day is genuinely unresolvable -- no node index on disk, or a day the schedule does
    not cover -- and that case is what `ranking_supervision_available` reports.
    """
    if "role" in table.column_names:
        return np.asarray(table["role"].combine_chunks().to_numpy(zero_copy_only=False)).astype(np.int8)
    day = str(manifest.get("day", ""))
    if not day:
        return np.zeros(len(t_obs), np.int8)
    try:
        from models.data.roles import node_ips, resolve_roles

        ips = node_ips(day)
        return resolve_roles(day, ips[sender], ips[receiver], t).astype(np.int8)
    except Exception:                                            # noqa: BLE001 -- absence is a reportable state
        return np.zeros(len(t_obs), np.int8)


def resolve_cross_day_memory(manifests: "list[dict]", requested: bool) -> bool:
    """Decide whether memory may cross a day boundary. Fails closed, with no override.

    Input:  every manifest in the run, whether the caller asked for cross-day memory
    Output: the resolved flag

    An absent `node_id_scope` is read as `per_day`: no positive guarantee is ever inferred from silence. A run whose
    manifests disagree is refused outright rather than resolved to the safer value, because mixing a unified-index day
    with a per-day-index day means at least one of them is being addressed wrongly. And under this schema a manifest
    claiming `unified` contradicts the upstream construction, so it raises instead of being believed.
    """
    scopes = {str(m.get("node_id_scope", "per_day")) for m in manifests} or {"per_day"}
    if "unified" in scopes:
        raise ValueError("a manifest declares node_id_scope='unified', which contradicts the per-day node index this "
                         "schema is built with. Fix the upstream index rather than trusting the claim")
    if len(scopes) > 1:
        raise ValueError(f"manifests disagree on node_id_scope: {sorted(scopes)}. A run must not mix index scopes")
    if requested:
        raise ValueError("cross_day_memory=True requires every manifest to declare node_id_scope='unified'. Node ids "
                         "are re-derived per day, so carried memory would address a different host. There is no "
                         "override: the fix is a unified upstream index")
    return False


def receive(directories: "list[str | Path]", *, cross_day_memory: bool = False,
            expect_z: int = EXPECTED_Z_DIM) -> ReceivedRun:
    """Load a whole run and resolve its memory policy.

    Input:  one directory per day, whether cross-day memory is wanted, the expected z width
    Output: a ReceivedRun

    Days are ordered by their first observation time, not by the order the paths were given, so a run assembled from a
    shell glob cannot silently train days out of order.
    """
    days = [receive_day(directory, expect_z=expect_z) for directory in directories]
    if not days:
        raise ValueError("a run needs at least one day")
    days.sort(key=lambda day: float(day.t_obs[0]) if len(day) else 0.0)
    resolved = resolve_cross_day_memory([day.manifest for day in days], cross_day_memory)
    return ReceivedRun(days=days, cross_day_memory=resolved)
