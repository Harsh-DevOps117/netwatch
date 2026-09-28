"""Run 7's records-only cascade: the flow record as the event's own representation, on the record's own timeline.

Run: nothing directly -- `models.context_encoder --record-arm <encoder.pt>` and `models.compressor.latents --record-arm ...`

This is the **late fusion** arm, built so the reference papers' argument against it can be tested rather than taken on
faith. XG-NID calls combining separately-encoded modalities at the end "multi-step" and says it "lacks direct fusion";
CTG and TGN both fold a new signal into link memory as `state ‖ Φ(gap) ‖ message` instead. Our own union merge is the
early-fusion form. Measuring the alternative is the only way to know whether that advice holds on this data.

What makes it honest is the **timeline**. A CICFlowMeter record exists only once its flow closes -- measured on
Thursday-15, a median 106 s after the event was scored, 91.3% of Slowloris flows arriving late. Encoding a record and
attaching it to its own event at that event's observation time would read the future. So the stream is re-sorted into
record-availability order and every downstream block sees the record exactly when it could first exist.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import torch

from models.context_encoder.data import load_day
from models.context_encoder.records import RECORD_COLUMNS, RecordEncoder
from models.context_encoder.stream import availability_order


def encode_records(records: np.ndarray, encoder_path: Path, device: str = "cpu", chunk: int = 8192) -> np.ndarray:
    """The frozen record encoder's embedding for every row.

    Input:  record matrix (N, 69), a checkpoint from `models.context_encoder.records --train-encoder`, device, rows per pass
    Output: (N, 32) float32 -- the same width as Block 7's h_split, so it substitutes for it exactly

    Frozen, mirroring how Block 7's packet embedding reaches Block 8: trained to rebuild benign flows and then held
    still, so Block 8 receives a representation rather than learning one inside its own objective.
    """
    state = torch.load(encoder_path, map_location=device, weights_only=False)
    model = RecordEncoder(32).to(device)
    model.load_state_dict(state["encoder"])
    model.eval().requires_grad_(False)
    out = np.zeros((len(records), 32), np.float32)
    with torch.no_grad():
        for start in range(0, len(records), chunk):
            rows = slice(start, min(start + chunk, len(records)))
            out[rows] = model(torch.from_numpy(records[rows]).to(device)).cpu().numpy()
    return out


def load_record_day(day: str, arm: str, *args, encoder: Path, device: str = "cpu", **kwargs) -> dict:
    """A day shaped for Block 8, built from flow records instead of packets, on the records' own timeline.

    Input:  day, arm (must be "split"), the frozen record encoder, device; remaining arguments go to load_day
    Output: the dict load_day returns, with h_split replaced by the record embedding, t_obs by record_time, and every
            array re-sorted into availability order of the records

    Events whose record never arrives are dropped: there is nothing for this cascade to read on them.
    """
    if arm != "split":
        raise ValueError("the record arm substitutes for h_split, so it only makes sense on the split arm")
    data = load_day(day, arm, *args, **kwargs)
    if "record_summary" not in data:
        raise ValueError(f"{day}: no flow_records.parquet -- run `python -m models.context_encoder.records --days {day}`")
    keep = np.isfinite(data["record_time"]) & np.isfinite(data["record_summary"]).all(1)
    data = {name: value[keep] for name, value in data.items() if isinstance(value, np.ndarray)}
    data["h_split"] = encode_records(data["record_summary"], encoder, device)
    data["t_obs"] = data["record_time"]
    order = availability_order(data["t_obs"], data["event_id"])
    return {name: value[order] for name, value in data.items()}


def day_loader(encoder: Path | None, device: str = "cpu"):
    """load_day, or the record-arm version of it, as one callable.

    Input:  a frozen record encoder checkpoint, or None for the ordinary packet path; device
    Output: a callable with load_day's signature

    None returns `load_day` itself, so the packet runs execute byte-for-byte the code they always did.
    """
    if encoder is None:
        return load_day
    return lambda day, arm, *a, **k: load_record_day(day, arm, *a, encoder=Path(encoder), device=device, **k)
