"""Attacker/victim role per event, derived from the schedule and never from `reversed`.

This resolves Blocker 1 of the Block 10 design. The ranking head needs to know which endpoint of an event is the
attacker, and `reversed` cannot answer that: it records whether the flow's first captured packet travelled against the
record's src/dst, which is a capture artefact of the packet order. On a day where the attacker's traffic is mostly
responses, `reversed` is exactly backwards, silently.

The schedule already carries the answer -- every entry names `attacker_ips` and `victim_ips` separately -- so the role
is derived from it and the event's endpoints, with no inference from packet direction anywhere.

Four codes, because "attack event" is not one thing:

| code | meaning |
|---|---|
| `BENIGN` (0) | outside every attack window, or inside one but between hosts the schedule does not name |
| `ATTACKER_TO_VICTIM` (1) | the event's sender is a scheduled attacker and its receiver a scheduled victim |
| `VICTIM_TO_ATTACKER` (2) | the reverse direction of the same pair -- the victim answering |
| `IN_WINDOW_OTHER` (3) | inside a window, one endpoint named, the other not; unresolved rather than guessed |

Code 3 exists so a partially-matching event is never quietly counted as either direction. A ranking head trained on
codes 1 and 2 should exclude it; a report should state how much of it there is.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

from ingest.sources.flows import SCHEDULE_UTC_OFFSET, _make_attack_rules, _normalize_ip
from ingest.sources.schedule import ATTACKS

BENIGN = 0
ATTACKER_TO_VICTIM = 1
VICTIM_TO_ATTACKER = 2
IN_WINDOW_OTHER = 3
ROLE_NAMES = {BENIGN: "benign", ATTACKER_TO_VICTIM: "attacker_to_victim",
              VICTIM_TO_ATTACKER: "victim_to_attacker", IN_WINDOW_OTHER: "in_window_other"}


def node_ips(day: str, events_root: "Path | str" = "data/events") -> np.ndarray:
    """The day's node id to ip map, as an array indexed by node id.

    Input:  day, the events root
    Output: (n_nodes,) array of ip strings

    Node ids are assigned per day, so this map is per day too. Indexing it with an id from another day returns the
    wrong host, which is why the day is a required argument rather than a default.
    """
    import pyarrow.parquet as pq

    table = pq.read_table(Path(events_root) / day / "node_index.parquet", columns=["node_id", "ip"]).to_pandas()
    out = np.empty(int(table["node_id"].max()) + 1, dtype=object)
    out[table["node_id"].to_numpy()] = table["ip"].to_numpy()
    return out


def day_rules(day: str):
    """The schedule's rules for one day, with their windows in UTC epoch seconds.

    Input:  day name
    Output: list of (start_epoch, end_epoch, attacker_ips, victim_ips)

    The schedule is written in capture-local time and the stored timestamps are UTC, so the offset is applied here --
    the same correction `LabelMatcher` makes, and the reason labels and roles agree on which events are in a window.
    """
    _, day_part, month, year = day.split("-")
    date = datetime(int(year), int(month), int(day_part))
    out = []
    for rule in _make_attack_rules(ATTACKS):
        if rule.day != day:
            continue
        for bound, attribute in (("start", rule.start), ("end", rule.end)):
            _ = bound
        start = (datetime.combine(date, rule.start) - SCHEDULE_UTC_OFFSET).timestamp()
        end = (datetime.combine(date, rule.end) - SCHEDULE_UTC_OFFSET).timestamp()
        if end <= start:                                        # a window crossing midnight
            end += timedelta(days=1).total_seconds()
        out.append((start, end, rule.attacker_ips, rule.victim_ips, rule.name))
    return out


def resolve_roles(day: str, sender_ip, receiver_ip, t, events_root: "Path | str" = "data/events") -> np.ndarray:
    """The attacker/victim role of every event.

    Input:  day, per-event sender and receiver ip, per-event time in UTC epoch seconds, the events root
    Output: (N,) int8 of role codes

    Time and endpoints both have to match: an event between the named hosts *outside* the window is benign traffic
    between the same machines, which is exactly the case a role field taken from endpoints alone would mislabel.
    """
    _ = events_root
    sender = np.asarray([_normalize_ip(v) for v in sender_ip], dtype=object)
    receiver = np.asarray([_normalize_ip(v) for v in receiver_ip], dtype=object)
    t = np.asarray(t, dtype=float)
    roles = np.full(len(t), BENIGN, dtype=np.int8)
    for start, end, attackers, victims, _name in day_rules(day):
        inside = (t >= start) & (t <= end)
        if not inside.any():
            continue
        from_attacker = np.fromiter((ip in attackers for ip in sender), bool, len(sender))
        to_victim = np.fromiter((ip in victims for ip in receiver), bool, len(receiver))
        from_victim = np.fromiter((ip in victims for ip in sender), bool, len(sender))
        to_attacker = np.fromiter((ip in attackers for ip in receiver), bool, len(receiver))
        roles[inside & from_attacker & to_victim] = ATTACKER_TO_VICTIM
        roles[inside & from_victim & to_attacker] = VICTIM_TO_ATTACKER
        touched = from_attacker | to_victim | from_victim | to_attacker
        unresolved = inside & touched & (roles == BENIGN)
        roles[unresolved] = IN_WINDOW_OTHER
    return roles


def roles_for_day(day: str, events_root: "Path | str" = "data/events",
                  features_root: "Path | str" = "data/context_features") -> np.ndarray:
    """Role codes for a day's keyed events, in event order.

    Input:  day, the events root, the context-features root (for the endpoint ids)
    Output: (N,) int8, one per event with packets

    Reads the endpoints from `side_features.parquet` because those are keyed on the flow's **first captured packet**,
    which is the same pairing every model input uses. Taking them from the flow record instead would pair the role with
    a different notion of sender.
    """
    import pyarrow.parquet as pq

    events = pq.read_table(Path(events_root) / day / "events.parquet",
                           columns=["t", "has_packets"]).to_pandas()
    sides = pq.read_table(Path(features_root) / day / "side_features.parquet",
                          columns=["sender_node_id", "receiver_node_id"]).to_pandas()
    keep = events["has_packets"].to_numpy()
    ips = node_ips(day, events_root)
    sender = ips[sides["sender_node_id"].to_numpy()[keep]]
    receiver = ips[sides["receiver_node_id"].to_numpy()[keep]]
    return resolve_roles(day, sender, receiver, events["t"].to_numpy()[keep])


def role_report(day: str, roles: np.ndarray, label: np.ndarray) -> "object":
    """Roles against labels, so a disagreement is visible rather than assumed away.

    Input:  day, role codes, per-event labels
    Output: DataFrame of counts per (label, role)

    The row to check is an attack-labelled event with role `benign`: it means the schedule's named hosts do not cover
    that event, and any ranking supervision built from roles would miss it.
    """
    import pandas as pd

    return (pd.DataFrame({"label": np.asarray(label, dtype=object),
                          "role": [ROLE_NAMES[int(r)] for r in roles]})
            .value_counts().rename("events").reset_index().assign(day=day))
