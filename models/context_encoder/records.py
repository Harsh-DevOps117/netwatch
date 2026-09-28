"""The flow record as a Block 8 message: CICFlowMeter's own columns, available when the flow closes.

Run: uv run python -m models.context_encoder.records --days DAY [DAY ...] --out data/context_features

Writes <out>/<day>/flow_records.parquet, one row per event in event order: the 68 CICFlowMeter columns the model is
allowed (`X_COLUMNS` -- the 76 less the 8 Active/Idle, which this build fills with the flow's absolute epoch time on
about half of all flows) and `record_time`, the earliest moment the record can exist.

These are new information, not a restatement of the packet aggregates: ours stop at the flow's first 20 packets, while
these cover the whole flow -- total bytes each way, header lengths, subflow statistics, initial window sizes, active
data packets. They reach the model as a third message type on the link timeline (design.md, Block 8 *Flow messages*),
never as a feature of the 10 ms verdict, because at 10 ms the record does not exist.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pyarrow as pa
import torch
from torch import nn
import pyarrow.compute as pc
import pyarrow.parquet as pq

from models.context_encoder.data import DAYS
from models.data.inputs import X_COLUMNS
from models.flow_encoder.encoder import mlp, slog as _slog

DURATION = "Flow Duration"
# CICFlowMeter's Fwd / Bwd columns are keyed to the record's own Src IP, while Block 7's sides and Block 8's links are
# keyed to the sender of the flow's FIRST CAPTURED PACKET. Those disagree on 11.2% of Thursday-15 events and 33.5% of
# its DoS-GoldenEye flows, so without swapping, 46 of the 68 columns arrive with their directions crossed -- the same
# problem the split model exists to solve, one level up.
PAIRS = [(c, c.replace("Fwd", "Bwd")) for c in X_COLUMNS if "Fwd" in c and c.replace("Fwd", "Bwd") in X_COLUMNS]
# These two have no Bwd twin, so they cannot be swapped; the flag below tells the model when they are the other side's.
UNPAIRED = [c for c in X_COLUMNS if "Fwd" in c and c.replace("Fwd", "Bwd") not in X_COLUMNS]
REVERSED = "record_reversed"
RECORD_COLUMNS = [*X_COLUMNS, REVERSED]


def orient_records(records: np.ndarray, flipped: np.ndarray) -> np.ndarray:
    """Put the record's directions on the link's terms: swap Fwd with Bwd wherever the record is the other way round.

    Input:  (N, 68) columns in X_COLUMNS order, a mask of events whose record src is not the first packet's sender
    Output: (N, 69) with the 22 Fwd/Bwd pairs swapped on the flipped rows, and a flag column marking them

    The flag matters because two Fwd columns have no Bwd twin (Fwd Act Data Pkts, Fwd Seg Size Min): on a flipped row
    they describe the other side and cannot be swapped, so the model is told rather than misled.
    """
    out = records.copy()
    index = {name: i for i, name in enumerate(X_COLUMNS)}
    for fwd, bwd in PAIRS:
        a, b = index[fwd], index[bwd]
        out[flipped, a], out[flipped, b] = records[flipped, b], records[flipped, a]
    return np.concatenate([out, flipped.astype(np.float32)[:, None]], 1)


def capture_records(capture_dir: Path, uids: np.ndarray, chunk: int = 250_000) -> np.ndarray:
    """One capture's flow columns for the given flows, in the order asked for.

    Input:  capture directory, the flow_uids wanted, rows per read
    Output: (len(uids), 68) float32 in X_COLUMNS order
    """
    file = pq.ParquetFile(capture_dir / "flows.parquet")
    wanted = pa.array(uids.tolist(), file.schema_arrow.field("flow_uid").type)
    flows = pa.Table.from_batches([
        batch.filter(pc.is_in(batch["flow_uid"], wanted))
        for batch in file.iter_batches(batch_size=chunk, columns=["flow_uid", *X_COLUMNS])
    ]).to_pandas().set_index("flow_uid")
    return flows.loc[uids, X_COLUMNS].to_numpy(np.float32)


def export_flow_records(day: str, events_root: Path, processed_root: Path, out_dir: Path,
                        chunk: int = 500_000) -> int:
    """Stream one day and write its flow records, one row per event in event order.

    Input:  day, event and processed roots, output directory, events per chunk
    Output: rows written; writes <out_dir>/flow_records.parquet

    `record_time` is `t + Flow Duration`: the flow's last packet, which is the **earliest** the record can exist. The
    meter emits it after that, on a FIN or RST (measured early in 100% of DoS-Hulk and DoS-SlowHTTPTest flows, 66.5%
    of GoldenEye, 46.0% of Slowloris, 37-41% of benign) or else after its 120 s idle timeout. Using the earliest time
    is the optimistic end of that range, and it is recorded here so a later version can tighten it.
    """
    features_root = Path(out_dir)
    out_dir = features_root / day
    out_dir.mkdir(parents=True, exist_ok=True)
    events = pq.read_table(Path(events_root) / day / "events.parquet",
                           columns=["event_id", "t", "flow_uid", "capture", "src_node_id"]).to_pandas()
    side = pq.read_table(features_root / day / "side_features.parquet",
                         columns=["event_id", "sender_node_id"]).to_pandas()
    if not np.array_equal(side["event_id"].to_numpy(), events["event_id"].to_numpy()):
        raise ValueError(f"{day}: side features do not line up with the event stream")
    flipped = events["src_node_id"].to_numpy() != side["sender_node_id"].to_numpy()
    records = np.zeros((len(events), len(X_COLUMNS)), np.float32)
    for capture, part in events.groupby("capture", sort=False):
        records[part.index.to_numpy()] = capture_records(
            Path(processed_root) / day / str(capture), part["flow_uid"].to_numpy())
    duration = records[:, X_COLUMNS.index(DURATION)] / 1e6                      # microseconds in the CSV
    # CICFlowMeter writes infinity into the per-second rates when a flow's duration is zero -- 22,914 rows of
    # Thursday-15 in `Flow Byts/s` and the same in `Flow Pkts/s`. Left in, the signed log stays infinite and the
    # LayerNorm that follows turns the whole row into NaN, which then spreads through link memory. Zero is what the
    # rest of the pipeline already substitutes for an undefined rate (models/data/prefix.py).
    records = np.nan_to_num(records, nan=0.0, posinf=0.0, neginf=0.0)
    oriented = orient_records(records, flipped)
    table = pa.table({"event_id": events["event_id"].to_numpy(),
                      "record_time": events["t"].to_numpy() + np.nan_to_num(duration, nan=0.0, posinf=0.0),
                      **{name: oriented[:, i] for i, name in enumerate(RECORD_COLUMNS)}})
    pq.write_table(table, out_dir / "flow_records.parquet", compression="zstd")
    return len(events)


class RecordEncoder(nn.Module):
    """The flow record read with its two directions kept apart -- Block 7's split, one level up.

    Input:  output width, the record's column names, hidden width
    Output: module; forward(record (N, W)) returns (N, d_out)

    Block 7's split model does not pool a flow's two sides: it keeps the initiator's and the responder's aggregates as
    a tuple and marks every packet with a learned side vector. A flow record has the same shape of problem -- 22 of its
    columns are the sender's direction and 22 the receiver's -- so one **shared** encoder reads either side and a side
    embedding says which it was. "What a side looks like" is learned once and the two sides stay comparable. The
    flow-level columns that belong to neither direction go in separately, with the two Fwd columns that have no Bwd
    twin and the flag that says when those describe the other side.
    """

    def __init__(self, d_out: int = 32, columns: list[str] | None = None, hidden: int = 128):
        super().__init__()
        columns = list(RECORD_COLUMNS if columns is None else columns)
        index = {name: i for i, name in enumerate(columns)}
        pairs = [(c, c.replace("Fwd", "Bwd")) for c in columns if "Fwd" in c and c.replace("Fwd", "Bwd") in index]
        self.register_buffer("sender_at", torch.tensor([index[f] for f, _ in pairs]), persistent=False)
        self.register_buffer("receiver_at", torch.tensor([index[b] for _, b in pairs]), persistent=False)
        rest = sorted(set(range(len(columns))) - {*self.sender_at.tolist(), *self.receiver_at.tolist()})
        self.register_buffer("flow_at", torch.tensor(rest), persistent=False)
        self.side_norm = nn.LayerNorm(len(pairs))
        self.side_in = mlp(len(pairs), d_out, hidden)              # shared: the same function reads either side
        self.side = nn.Embedding(2, d_out)                         # ... and this says which side it was
        self.flow_norm = nn.LayerNorm(len(rest))
        self.flow_in = mlp(len(rest), d_out, hidden)
        self.out = mlp(3 * d_out, d_out, hidden)

    def forward(self, record: torch.Tensor) -> torch.Tensor:
        x = _slog(record)
        sender = self.side_in(self.side_norm(x[:, self.sender_at])) + self.side.weight[0]
        receiver = self.side_in(self.side_norm(x[:, self.receiver_at])) + self.side.weight[1]
        flow = self.flow_in(self.flow_norm(x[:, self.flow_at]))
        return self.out(torch.cat([sender, receiver, flow], 1))


class RecordAutoencoder(nn.Module):
    """The record encoder trained the way Block 7 is: rebuild a benign flow record from its own embedding.

    Input:  embedding width, hidden width
    Output: module; forward(record) returns (embedding, reconstruction)

    Trained on benign flows only, then frozen -- so Block 8 is handed a representation of what a normal flow record
    looks like, exactly as it is handed Block 7's packet embedding, instead of learning one inside link prediction.
    """

    def __init__(self, d_out: int = 32, hidden: int = 128):
        super().__init__()
        self.encoder = RecordEncoder(d_out, hidden=hidden)
        self.decoder = mlp(d_out, len(RECORD_COLUMNS), hidden)

    def forward(self, record: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        h = self.encoder(record)
        return h, self.decoder(h)


def train_encoder(day: str, events: int | None = None, family: str | None = None, d_out: int = 32,
                  epochs: int = 200, chunk: int = 65_536, device: str = "cpu", seed: int = 0) -> dict:
    """Train the record encoder the way Block 7 is trained: rebuild benign flow records, then freeze.

    Input:  day, slice size and family (None for the whole day), embedding width, steps, rows per step, device, seed
    Output: dict to save: the encoder's weights, its width, and the benign scale it was fitted on

    Benign training events only, and the scale is fitted on them alone -- the same discipline as every other
    autoencoder here. What Block 8 then receives is a representation of a normal flow record, not raw columns.
    """
    from models.context_encoder.data import attack_slice, load_day

    data = load_day(day, "split")
    if events:
        keep = attack_slice(data, events, family)
        data = {name: value[keep] for name, value in data.items() if isinstance(value, np.ndarray)}
    if "record_summary" not in data:
        raise SystemExit(f"{day}: no flow records exported; run models.context_encoder.records first")
    benign = (~data["attack"]) & (data["split"] == 0)
    x = data["record_summary"][benign]
    torch.manual_seed(seed)
    model = RecordAutoencoder(d_out).to(device)
    optimiser = torch.optim.Adam(model.parameters(), lr=1e-3)
    features = torch.from_numpy(x).to(device)
    generator = torch.Generator().manual_seed(seed)
    for step in range(epochs):
        rows = (torch.randint(len(features), (chunk,), generator=generator).to(device)
                if len(features) > chunk else torch.arange(len(features), device=device))
        batch = features[rows]
        _, rebuilt = model(batch)
        loss = torch.nn.functional.mse_loss(rebuilt, _slog(batch))       # rebuild on the scale the encoder reads
        optimiser.zero_grad()
        loss.backward()
        optimiser.step()
        if step % 50 == 0:
            print(f"  step {step}: benign reconstruction {float(loss):.5f}", flush=True)
    return {"encoder": model.encoder.state_dict(), "decoder": model.decoder.state_dict(), "d_out": d_out,
            "day": day, "events": events, "family": family, "benign_rows": int(benign.sum())}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--days", nargs="+", default=DAYS)
    parser.add_argument("--events-root", type=Path, default=Path("data/events"))
    parser.add_argument("--processed-root", type=Path, default=Path("data/processed"))
    parser.add_argument("--out", type=Path, default=Path("data/context_features"))
    parser.add_argument("--train-encoder", type=Path, default=None,
                        help="instead of exporting, train the record encoder on benign flows and save it here -- the "
                             "mirror of Block 7: frozen before Block 8 ever sees it")
    parser.add_argument("--events", type=int, default=None, help="train on a slice of this many events")
    parser.add_argument("--family", default=None, help="the family the slice centres on")
    parser.add_argument("--steps", type=int, default=200,
                        help="optimisation steps for --train-encoder, each on 65,536 benign records drawn at random. "
                             "200 left the loss still halving every 50 steps on a full day; watch it level off")
    args = parser.parse_args(argv)
    if args.train_encoder:
        state = train_encoder(args.days[0], args.events, args.family, epochs=args.steps)
        args.train_encoder.parent.mkdir(parents=True, exist_ok=True)
        torch.save(state, args.train_encoder)
        print(f"record encoder trained on {state['benign_rows']:,} benign flows -> {args.train_encoder}")
        return 0
    for day in args.days:
        rows = export_flow_records(day, args.events_root, args.processed_root, args.out)
        print(f"{day}: {rows:,} flow records -> {args.out / day / 'flow_records.parquet'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
