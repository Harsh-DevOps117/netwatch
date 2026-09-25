"""Block 7's deliverable: one flow embedding per event, written where Block 8 reads it.

Named flow_embeddings, never event_latents: that name belongs to Block 9's output in
the Block 9 -> 10 contract. Both files have one row per event and 32 numbers a row, so
a loader expecting Block 9 latents would accept this file silently and train the world
model on embeddings that carry no network context.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from models.data.inputs import EVENT_READ_COLUMNS, load_inputs, normalise
from models.data.prefix import prepare
from models.flow_encoder.encoder import VARIANT
from models.flow_encoder.train import embed

# Was "block7-flow-embeddings-v1" before the stages were named. Readers accept either.
FORMAT = "flow-embeddings-v1"
LEGACY_FORMATS = ("block7-flow-embeddings-v1",)


def latent_schema(d_h: int, n_targets: int) -> pa.Schema:
    """Column layout of flow_embeddings.parquet.

    Input:  embedding width, number of reconstruction targets
    Output: pyarrow schema

    event_id and flow_uid travel with every row because the identity invariant
    e <-> flow_uid <-> h_f is asserted downstream, not assumed.
    """
    return pa.schema([
        ("event_id", pa.int64()),
        ("flow_uid", pa.string()),
        ("t", pa.float64()),
        ("observation_time", pa.float64()),
        ("packets_seen", pa.int16()),
        ("observation_population", pa.string()),
        ("attack", pa.bool_()),
        ("h", pa.list_(pa.float32(), d_h)),
        ("recon_error", pa.list_(pa.float32(), n_targets)),
    ])


def _stats_digest(stats: dict) -> str:
    """A stable fingerprint of the normalisation statistics an export was produced with.

    Input:  the stats dict from models.data.inputs.normalise
    Output: hex sha256 over its keys and moments

    Recorded in the manifest because the stats themselves are not reconstructable from it: they are fitted on the
    sampled train rows of a particular run. The digest at least makes a mismatch detectable instead of silent.
    """
    parts = []
    for name in sorted(stats):
        mean, std = stats[name]
        parts.append(name.encode())
        parts.append(np.asarray(mean, dtype=np.float64).tobytes())
        parts.append(np.asarray(std, dtype=np.float64).tobytes())
    return hashlib.sha256(b"".join(parts)).hexdigest()


def export_latents(
    model, stats: dict, *, day: str, events_root: Path, processed_root: Path, out_dir: Path,
    k: int = 20, budget_ms: float = 10.0, side: str = "responder", device: str = "cpu",
    chunk: int = 200_000, readers: int = 4, limit: int | None = None, model_seed: int = 0,
) -> dict:
    """Stream one whole day through the trained encoder and write its latents.

    Input:  trained FlowAutoencoder, the normalisation stats it was fitted with, day name, event and
            processed roots, output directory, K, budget, side (responder / both / split), device,
            events per chunk, capture readers, optional row cap, model seed for the manifest
    Output: the manifest dict; writes flow_embeddings.parquet and flow_embeddings_manifest.json

    A day is 7.8M events and its packet tensor alone is 8 GB, so the file is read,
    embedded and appended chunk by chunk and never held whole. Chunks follow the
    file's own row order, which is event order, so the output is time-ordered.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    source = Path(events_root) / day / "events.parquet"
    reader = pq.ParquetFile(source, read_dictionary=["label", "capture"])
    total = min(reader.metadata.num_rows, limit or reader.metadata.num_rows)

    writer, written, digest = None, 0, hashlib.sha256()
    for batch in reader.iter_batches(batch_size=chunk, columns=EVENT_READ_COLUMNS):
        events = batch.to_pandas()
        if written + len(events) > total:
            events = events.iloc[: total - written]
        if events.empty:
            break
        data = prepare(load_inputs(events, Path(processed_root) / day, k, readers), budget_ms / 1000, side)
        normalised, _ = normalise(data, stats)
        h, error = embed(model, normalised, np.arange(len(events)), device=device)
        digest.update(h.tobytes())

        table = pa.Table.from_pydict({
            "event_id": data["event_id"],
            "flow_uid": events["flow_uid"].astype(str).to_numpy(),
            "t": data["t"],
            "observation_time": data["observation_time"],
            "packets_seen": data["packets_seen"].astype(np.int16),
            "observation_population": data["population"],
            "attack": data["attack"],
            "h": pa.FixedSizeListArray.from_arrays(h.reshape(-1), h.shape[1]),
            "recon_error": pa.FixedSizeListArray.from_arrays(error.reshape(-1), error.shape[1]),
        }, schema=latent_schema(h.shape[1], error.shape[1]))
        if writer is None:
            writer = pq.ParquetWriter(out_dir / "flow_embeddings.parquet", table.schema,
                                      compression="zstd")
        writer.write_table(table)
        written += len(events)
        print(f"  exported {written:,}/{total:,}", flush=True)
        if written >= total:
            break
    if writer is not None:
        writer.close()

    manifest = {
        "format": FORMAT,
        "day": day,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": "models.flow_encoder (Block 7)",
        "granularity": "flow_event",
        "n_events": written,
        "embedding_dim": int(h.shape[1]),
        "recon_targets": list(model.targets),
        "encoder": {
            "variant": VARIANT, "packet_encoder": model.encoder.packet_encoder, "k_packets": k,
            "mode": "online_prefix", "budget_ms": budget_ms, "side": side, "ttl_blanked": True,
            "model_seed": model_seed,
            "parameters": int(sum(p.numel() for p in model.encoder.parameters())),
            # Fingerprint of the input normalisation these embeddings were produced with. Two exports that disagree
            # here are on different input scales and must not be compared or mixed, however alike their configs look.
            "normalisation_sha256": _stats_digest(stats),
        },
        "embedding_sha256": digest.hexdigest(),
        "files": {"embeddings": "flow_embeddings.parquet"},
        "notes": [
            "One row per event, in event order. event_id <-> flow_uid <-> h is a bijection.",
            "Block 7 output: per-flow, no network context. Not Block 9's event_latents.",
            "observation_population must not be pooled: early_observation carries the lead-time"
            " claim, completed_before_budget does not.",
            "recon_error is per target, unstandardised; the anomaly arm ranks it against benign"
            " training rows (models.flow_encoder.alerts).",
        ],
    }
    (out_dir / "flow_embeddings_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
