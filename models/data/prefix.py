"""Online observation: cut every flow at its observation time and recompute what is known by then."""

from __future__ import annotations

import numpy as np

from ingest.build.events import AGG_COLUMNS
from models.data.inputs import PACKET_FEATURES, X_COLUMNS

DEFAULT_BUDGET_MS = 10.0

EARLY, COMPLETED = "early_observation", "completed_before_budget"

# responder: the response side only; initiator: the request side only; both: one arrival chain of both sides;
# split: both sides kept apart.
SIDES = ("responder", "initiator", "both", "split")
INITIATOR, RESPONDER = 0.0, 1.0


def prepare(data: dict, budget_s: float, side: str) -> dict:
    """Everything done to a flow before normalising it, shared by training, scoring and export.

    Input:  raw arrays from load_inputs, budget in seconds, side from SIDES
    Output: arrays observed at the budget, cut to one side's packets for "responder" / "initiator", TTL
            blanked, and for "split" rebuilt with the two sides' aggregates side by side

    TTL reports hop distance, not behaviour. It is blanked before the sides are split, so both
    halves are rebuilt from blanked packets.
    """
    if side not in SIDES:
        raise ValueError(f"side must be one of {SIDES}")
    data = observe(data, budget_s)
    if side in ("responder", "initiator"):
        data = keep_side(data, RESPONDER if side == "responder" else INITIATOR)
    # observe and keep_side return fresh a and pkt arrays, so TTL is blanked in place: no third copy of the packets.
    data["a"][:, [AGG_COLUMNS.index("ttl_mean"), AGG_COLUMNS.index("ttl_std")]] = 0.0
    data["pkt"][..., PACKET_FEATURES.index("ttl")] = 0.0
    return split_sides(data) if side == "split" else data


def observe(data: dict, budget_s: float) -> dict:
    """Restrict every flow to the packets seen within its observation budget.

    Input:  raw arrays from load_inputs (before normalise), budget in seconds
    Output: copy with pkt and dt masked to the budget, n_pkt replaced by the packets
            seen, a recomputed from those packets alone, plus observation_time,
            packets_seen, population and a_future (the uncut aggregates, a forecast target)

    t_obs = min(t* + budget, flow end). The first packet is always seen, so a flow
    never arrives empty. Flow Duration is read only to tag the population — it is
    a terminal column and never reaches a feature tensor.
    """
    k = data["pkt"].shape[1]
    slots = np.arange(k)
    valid = slots < data["n_pkt"][:, None]
    # dt is the gap to the flow's previous packet, so its running sum is each
    # packet's offset from the flow's first packet.
    offset = np.cumsum(data["dt"], axis=1)
    observed = valid & (offset <= budget_s)
    seen = observed.sum(1).astype(np.int16)

    out = dict(data)
    out["pkt"] = data["pkt"] * observed[..., None]
    out["dt"] = data["dt"] * observed
    out["n_pkt"] = seen
    out["a"] = _aggregates(out["pkt"], out["dt"], observed)

    duration = data["x"][:, X_COLUMNS.index("Flow Duration")] / 1e6
    end = data["t"] + np.nan_to_num(duration, nan=0.0, posinf=0.0, neginf=0.0)
    out["observation_time"] = np.minimum(data["t"] + budget_s, end)
    out["packets_seen"] = seen
    out["population"] = np.where(end <= data["t"] + budget_s, COMPLETED, EARLY)
    # What this flow becomes, kept as a prediction target: forecasting the remainder asks
    # what the opening implies.
    out["a_future"] = data["a"]
    return out


def keep_side(data: dict, side: float) -> dict:
    """Keep one side's packets in each flow and rebuild everything that follows.

    Input:  arrays after observe(), 0 for the flow's initiator, 1 for the responder
    Output: copy with the other side removed, packets compacted to the front,
            gaps re-derived, n_pkt/packets_seen and a recomputed

    An attacker paces the packets it sends; it cannot make the victim answer
    differently without abandoning the attack. Gaps become the span between
    surviving packets, so the removed side's time is not lost.
    """
    k = data["pkt"].shape[1]
    slots = np.arange(k)
    valid = slots < data["n_pkt"][:, None]
    direction = data["pkt"][..., PACKET_FEATURES.index("direction")]
    keep = valid & (direction == side)

    # Stable argsort moves the kept slots to the front, in their original order.
    order = np.argsort(~keep, axis=1, kind="stable")
    rows = np.arange(len(keep))[:, None]
    offsets = np.cumsum(data["dt"], axis=1)[rows, order]
    count = keep.sum(1).astype(np.int16)
    kept = slots < count[:, None]

    gaps = np.zeros_like(offsets)
    gaps[:, 1:] = np.diff(offsets, axis=1)
    gaps = np.where(kept, gaps, 0.0).astype(np.float32, copy=False)
    gaps[:, 0] = 0.0
    pkt = np.where(kept[..., None], data["pkt"][rows, order], 0.0).astype(np.float32, copy=False)

    out = dict(data)
    out["pkt"], out["dt"], out["n_pkt"], out["packets_seen"] = pkt, gaps, count, count
    out["a"] = _aggregates(pkt, gaps, kept)
    return out


def split_sides(data: dict) -> dict:
    """Keep both directions, but apart: the input tuple of initiator and responder.

    Input:  arrays after observe()
    Output: copy with a = [initiator aggregates, responder aggregates] (40 columns); packets unchanged

    One pooled set of aggregates mixes the attacker's requests with the victim's replies.
    keep_side already recomputes one side's aggregates with that side's own gaps, so the
    tuple is the two of them side by side.
    """
    out = dict(data)
    out["a"] = np.concatenate([keep_side(data, INITIATOR)["a"], keep_side(data, RESPONDER)["a"]], axis=1).astype(np.float32)
    return out


def _aggregates(pkt: np.ndarray, dt: np.ndarray, observed: np.ndarray) -> np.ndarray:
    """Recompute the 20 packet aggregates over the observed packets only.

    Input:  masked packet features (N, K, F), masked gaps (N, K), observed mask (N, K)
    Output: (N, 20) float32 in AGG_COLUMNS order

    Same definitions as Block 6, so an online row differs from its offline twin
    only by which packets it was allowed to see.
    """
    column = {name: PACKET_FEATURES.index(name) for name in PACKET_FEATURES}
    count = observed.sum(1)
    gaps = observed.copy()
    gaps[:, 0] = False  # the first packet has no predecessor

    out = {"pkt_n": count.astype(np.float32)}
    for name, feature in (
        ("pkt_len", "length"), ("ttl", "ttl"), ("win", "tcp_window"),
    ):
        mean, std = _mean_std(pkt[..., column[feature]], observed, count)
        out[f"{name}_mean"], out[f"{name}_std"] = mean, std
    iat_mean, iat_std = _mean_std(dt, gaps, gaps.sum(1))
    out["iat_mean"], out["iat_std"] = iat_mean, iat_std
    out["iat_max"] = np.where(gaps, dt, 0.0).max(1)
    for flag in ("syn", "ack", "fin", "rst", "psh", "urg"):
        out[f"{flag}_n"] = pkt[..., column[f"tcp_flag_{flag}"]].sum(1)
    payload = pkt[..., column["payload_len"]]
    out["payload_bytes"] = payload.sum(1)
    out["payload_frac"] = np.divide(
        ((payload > 0) & observed).sum(1), count, out=np.zeros(len(count)), where=count > 0,
    )
    out["retrans_n"] = pkt[..., column["tcp_retransmission"]].sum(1)
    out["frag_n"] = pkt[..., column["frag"]].sum(1)
    return np.stack([out[name] for name in AGG_COLUMNS], axis=1).astype(np.float32)


def _mean_std(values: np.ndarray, mask: np.ndarray, count: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Mean and sample standard deviation over the masked entries of each row.

    Input:  values (N, K), mask (N, K), number of masked entries per row
    Output: (mean, std); both 0 where a row has no entries, std 0 where it has one

    Sample standard deviation (n - 1) to match Block 6's pandas aggregation.
    """
    total = np.where(mask, values, 0.0).sum(1)
    mean = np.divide(total, count, out=np.zeros(len(count)), where=count > 0)
    squares = np.where(mask, (values - mean[:, None]) ** 2, 0.0).sum(1)
    var = np.divide(squares, count - 1, out=np.zeros(len(count)), where=count > 1)
    return mean, np.sqrt(var)
