"""How much anticipation lead every ingested day contains, measured from the event stream alone.

Run: uv run python tools/measure/lead_ceiling_days.py

**This tool disproved the claim it was written to generalise.** The earlier "Bot supports no lead beyond ~2 seconds"
came from the 3M-event slice, and `attack_slice` centres on the attack span: on the Bot day it starts 3,446 s after the
first Bot attack and contains none of the day's 1,239,249 pre-attack rows. Measured over whole days instead, Bot has
19,983 benign events on attacking hosts more than 60 s before that host's next attack, up to 15,488 s; Infiltration has
54,483, up to 23,064 s. The lead is real. What is NOT measurable is a model's use of it, because `segment_split`
interleaves the splits in wall-clock time -- see docs/data.md, "Splits".

No model and no latents are needed — the ceiling depends only on labels, times and endpoints, so this reads the event
stream directly and works for days that were never exported.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from ingest.sources.flows import BENIGN_LABEL
from models.context_encoder.data import DAYS, day_split


def measure(day: str, events_root: Path, features_root: Path) -> list[dict]:
    """The three lead ceilings for one day, per attack family.

    Input:  day name, the event and context-feature roots
    Output: one row per (day, family) with the event-based, campaign-level and cross-host ceilings
    """
    events_dir = events_root / day
    ev = pq.read_table(events_dir / "events.parquet", columns=["label", "t", "has_packets"]).to_pandas()
    side = pq.read_table(features_root / day / "side_features.parquet",
                         columns=["sender_node_id", "receiver_node_id"]).to_pandas()
    split = day_split(events_dir, day)
    keep = ev["has_packets"].to_numpy()
    label = ev["label"].to_numpy(str)[keep]
    t = ev["t"].to_numpy()[keep]
    s = side["sender_node_id"].to_numpy()[keep].astype(np.int64)
    split = split[keep]
    rows = []
    for family in sorted(set(label) - {BENIGN_LABEL["Label"]}):
        a = label == family
        hosts = np.unique(s[a])
        # 1. event-based ceiling: for benign events on an attacking host, seconds to that host's next attack
        order = np.lexsort((t, s))
        ks, ts, as_ = s[order], t[order], a[order]
        nxt, seen = np.full(len(ts), np.nan), {}
        for i in range(len(ts) - 1, -1, -1):
            k = int(ks[i])
            if as_[i]:
                seen[k] = ts[i]
            elif k in seen:
                nxt[i] = seen[k]
        gap = np.full(len(ts), np.nan)
        gap[order] = nxt - ts
        on_host = np.isin(s, hosts)
        g = gap[on_host & ~a & np.isfinite(gap)]
        # 2. campaign-level ceiling: time from a host's first appearance to its first attack
        warm = [float(t[s == h][a[s == h]].min() - t[s == h].min()) for h in hosts]
        # 3. cross-host ceiling: the stagger between hosts' first attacks
        firsts = np.sort(np.array([t[(s == h) & a].min() for h in hosts]))
        first_splits = [int(split[(s == h) & a][0]) for h in hosts]
        rows.append({
            "day": day, "family": family, "attack_events": int(a.sum()), "attacking_hosts": len(hosts),
            "event_lead_n": len(g),
            "event_lead_median_s": float(np.median(g)) if len(g) else np.nan,
            "event_lead_max_s": float(g.max()) if len(g) else np.nan,
            "event_lead_n_over_60s": int((g > 60).sum()) if len(g) else 0,
            "campaign_warmup_median_s": float(np.median(warm)) if warm else np.nan,
            "campaign_warmup_max_s": float(np.max(warm)) if warm else np.nan,
            "cross_host_total_stagger_s": float(firsts[-1] - firsts[0]) if len(firsts) > 1 else 0.0,
            "cross_host_median_gap_s": float(np.median(np.diff(firsts))) if len(firsts) > 1 else np.nan,
            "first_attacks_in_train": sum(1 for v in first_splits if v == 0),
            "first_attacks_in_test": sum(1 for v in first_splits if v == 2),
        })
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--days", nargs="+", default=DAYS)
    parser.add_argument("--events-root", type=Path, default=Path("data/events"))
    parser.add_argument("--features-root", type=Path, default=Path("data/context_features"))
    parser.add_argument("--out", type=Path, default=Path("data/model_cache/results/lead_ceiling_all_days.csv"))
    args = parser.parse_args(argv)

    rows: list[dict] = []
    for day in args.days:
        print(f"--- {day}", flush=True)
        rows += measure(day, args.events_root, args.features_root)
    table = pd.DataFrame(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(args.out, index=False)
    pd.set_option("display.width", 250)
    print("\nLEAD CEILINGS — how much warning the data contains, before any model\n")
    print(table[["day", "family", "attacking_hosts", "event_lead_max_s", "event_lead_n_over_60s",
                 "campaign_warmup_max_s", "cross_host_total_stagger_s", "first_attacks_in_test"]]
          .to_string(index=False, float_format=lambda v: f"{v:,.1f}"))
    print(f"\nwritten to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
