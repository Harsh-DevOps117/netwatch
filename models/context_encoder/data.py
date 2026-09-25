"""Block 8 day loader: events, side features and the arm's Block 7 embeddings, joined and put in availability order."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from ingest.build.events import AGG_COLUMNS
from ingest.sources.flows import BENIGN_LABEL
from models.context_encoder.stream import NeighbourIndex, availability_order
from models.data.inputs import read_events
from models.data.splits import observed_windows, segment_split

# Which Block 7 exports each input arm reads (design.md, Block 8 *Input arms*).
ARMS = {"split": ("split",), "sides": ("request", "response")}

# The five ingested days, in the order the streams are walked.
DAYS = ["Friday-16-02-2018", "Friday-02-03-2018", "Friday-23-02-2018", "Thursday-15-02-2018", "Thursday-01-03-2018"]
EVENT_COLUMNS = ["event_id", "t", "dt_src", "dt_dst", "port_delta", "dst_port_new", "has_packets", "reversed",
                 "label", *AGG_COLUMNS]
SIDE_COLUMNS = ["event_id", "sender_node_id", "receiver_node_id", "request_packets", "response_packets",
                "reply_latency_s", "direction_changes", "no_reply"]


def day_split(events_dir: Path, day: str) -> np.ndarray:
    """The day's train / val / test assignment in event order, cut inside every attack window and benign stretch.

    Input:  events directory of the day, day name
    Output: (N,) int8, 0 train, 1 val, 2 test, -1 inside a 120 s embargo gap -- the same split Block 7 used
    """
    timeline = read_events(events_dir, columns=["t", "label"])
    return segment_split(timeline["t"].to_numpy(), observed_windows(timeline, day))


def _embeddings(path: Path, event_id: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """One Block 7 export's embeddings, observation times and populations, checked row for row against the events.

    Input:  flow_embeddings.parquet path, the day's event_id in event order
    Output: (h (N, d) float32, observation_time (N,) float64, observation_population (N,) str)
    """
    table = pq.read_table(path, columns=["event_id", "observation_time", "observation_population", "h"])
    if not np.array_equal(table["event_id"].to_numpy(), event_id):
        raise ValueError(f"{path}: rows do not line up with the event stream")
    h = table["h"].combine_chunks()
    return (h.flatten().to_numpy().reshape(len(h), -1), table["observation_time"].to_numpy(),
            table["observation_population"].to_numpy(zero_copy_only=False).astype(str))


def load_day(day: str, arm: str, events_root: Path = Path("data/events"),
             features_root: Path = Path("data/context_features"), embeddings_root: Path = Path("data/flow_embeddings"),
             split: np.ndarray | None = None, records: bool = True) -> dict[str, np.ndarray]:
    """Everything Block 8 reads for one day, in availability order.

    Input:  day, arm ("split" or "sides"), roots of the event stream, side features and Block 7 exports, optional
            precomputed split (event order; computed from the day's labels and schedule when None)
    Output: dict of arrays, one row per event with packets, sorted by (observation time, event_id):
            event_id, t, t_obs, sender, receiver, dt_src, dt_dst, port_delta, dst_port_new, reversed, the side
            features, split, population, label and attack (evaluation only), h_<export> per export the arm reads

    Events without packets are dropped: nothing exists for them at an observation time (design.md, online_prefix).
    """
    if arm not in ARMS:
        raise ValueError(f"arm must be one of {list(ARMS)}")
    events_dir = Path(events_root) / day
    events = pq.read_table(events_dir / "events.parquet", columns=EVENT_COLUMNS).to_pandas()
    event_id = events["event_id"].to_numpy()
    side = pq.read_table(Path(features_root) / day / "side_features.parquet", columns=SIDE_COLUMNS).to_pandas()
    if not np.array_equal(side["event_id"].to_numpy(), event_id):
        raise ValueError(f"{day}: side features do not line up with the event stream")
    split = day_split(events_dir, day) if split is None else np.asarray(split)
    data = {
        "event_id": event_id, "t": events["t"].to_numpy(),
        "sender": side["sender_node_id"].to_numpy(), "receiver": side["receiver_node_id"].to_numpy(),
        **{c: events[c].to_numpy(np.float32) for c in ("dt_src", "dt_dst", "port_delta", "dst_port_new", "reversed")},
        **{c: side[c].to_numpy() for c in SIDE_COLUMNS[3:]},
        "split": split, "label": events["label"].astype(str).to_numpy(),
    }
    data["attack"] = data["label"] != BENIGN_LABEL["Label"]
    t_obs = None
    for export in ARMS[arm]:
        data[f"h_{export}"], observed, population = _embeddings(
            Path(embeddings_root) / export / day / "flow_embeddings.parquet", event_id)
        if t_obs is not None and not np.array_equal(observed, t_obs):
            raise ValueError(f"{day}: the arm's exports disagree on observation times")
        t_obs = observed
    data["t_obs"], data["population"] = t_obs, population
    # The flow's own summary over its first K packets (ingest/build/events.py: K = 20) and the moment that summary exists:
    # the last of those packets. iat_mean is the mean of the K - 1 gaps, so the gaps sum to iat_mean * (pkt_n - 1) --
    # checked against the per-packet times on 200,000 events, median difference 0.2 ns and at most 8.3 us, which is
    # float32 in the stored aggregates. Deriving it costs nothing; exporting it exactly would mean re-reading every
    # packet of every day.
    data["flow_summary"] = events[AGG_COLUMNS].to_numpy(np.float32)
    data["flow_time"] = data["t"] + (events["iat_mean"].to_numpy(np.float64)
                                     * np.maximum(events["pkt_n"].to_numpy() - 1, 0))
    # Only a summary that lands after the event was scored carries anything Block 7 did not already see. Measured:
    # 98.6% of Bot events (median 2 ms later), 97.0% of DoS-Hulk (median 127 ms), 0.0% of DoS-SlowHTTPTest, whose
    # packets are all inside the 10 ms budget.
    data["flow_later"] = data["flow_time"] > t_obs + 1e-6
    # The flow's own CICFlowMeter record, and the earliest moment it can exist (models/context_encoder/records.py). Its 68
    # columns cover the whole flow, where the aggregates above stop at the first 20 packets, so they are new
    # information -- and they exist only once the flow has closed, which is why they reach the model as a message on
    # the link timeline and never as a feature of the 10 ms verdict. A day without the export has no record messages.
    record_file = Path(features_root) / day / "flow_records.parquet"
    if record_file.exists():
        from models.context_encoder.records import RECORD_COLUMNS
        table = pq.read_table(record_file, columns=["event_id", "record_time", *RECORD_COLUMNS]).to_pandas()
        if not np.array_equal(table["event_id"].to_numpy(), event_id):
            raise ValueError(f"{day}: the flow records do not line up with the event stream")
        data["record_summary"] = table[RECORD_COLUMNS].to_numpy(np.float32)
        data["record_time"] = table["record_time"].to_numpy(np.float64)
        data["record_later"] = data["record_time"] > t_obs + 1e-6
    keep = events["has_packets"].to_numpy()
    order = availability_order(t_obs[keep], event_id[keep])
    rows = np.flatnonzero(keep)[order]
    return {name: values[rows] for name, values in data.items()}


def make_stream(day: dict, keep: np.ndarray) -> dict:
    """A stream Block 8 runs over: the kept events of a day, still in availability order, with its own index.

    Input:  day dict from load_day, boolean mask (for training: benign events of the train split)
    Output: dict with the kept rows of every array and index (NeighbourIndex over this stream alone), so memory and
            neighbourhoods only ever contain events of the same stream
    """
    # A stream can be narrowed again (the window-shift check does), so the previous index is dropped, not sliced.
    stream = {name: values[keep] for name, values in day.items() if isinstance(values, np.ndarray)}
    stream["index"] = NeighbourIndex(stream["sender"], stream["receiver"])
    return stream


def cache_neighbours(stream: dict) -> dict:
    """Look every real event's neighbourhood up once, for streams that are walked more than once.

    Input:  stream dict from make_stream
    Output: the same dict with "neighbours" (N, S) int32 added

    A real event's neighbourhood depends only on the stream, so scoring it, ablating memory and counting its
    neighbours can share one lookup. Sampled negative links are not cached: their receiver changes per batch.
    """
    n = len(stream["sender"])
    stream["neighbours"] = stream["index"].query(stream["sender"], stream["receiver"], np.arange(n)).astype(np.int32)
    return stream


def attack_slice(day: dict, events: int, family: str | None = None) -> np.ndarray:
    """A contiguous run of the day around its attacks, for quick iteration.

    Input:  day dict from load_day, how many events to keep, a family to centre on (None: all attacks)
    Output: (N,) bool mask, one unbroken run

    Contiguous on purpose: Block 8's link memory, the neighbourhood index and the horizon label all read a stream, so
    a random sample would break them. **Centre on one family**, because a day's families sit in different stretches of
    it -- on Thursday-15 DoS-GoldenEye occupies rows 748,285-1,223,487 and DoS-Slowloris 1,846,334-2,353,575, so a
    slice centred on all attacks lands inside the larger window and loses the smaller family entirely.

    The slice is for **comparing arms**, not for absolute numbers: it calibrates a threshold on fewer benign rows, so
    a 0.1% budget is noisier here than on a whole day.
    """
    n = len(day["attack"])
    if events >= n:
        return np.ones(n, bool)
    hit = np.flatnonzero((day["label"] == family) if family else day["attack"])
    centre = int((hit.min() + hit.max()) // 2) if len(hit) else n // 2
    start = int(np.clip(centre - events // 2, 0, n - events))
    keep = np.zeros(n, bool)
    keep[start:start + events] = True
    return keep
