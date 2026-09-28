"""Is the world model's forecast ahead of time? When each predicted link really happens, against when it was served.

Run: uv run python -m tools.measure.forecast_lead --latents <latents>/<day> --checkpoint <world model .pt> \\
         [--every 10000] [--lags 150 1]

The day is walked as the live service walks it (every event, in stream order). Every `--every` events a forecast is
rolled out from the current state, at time T (the last scored event's observation time). Each predicted link
(seed host -> predicted target) is then looked up in what really followed: the first event on that link after T.
A forecast served `lag` seconds after T is ahead for a link that happens more than `lag` seconds after T; one that
happened sooner was already in the past when served. Lags: 150 s is the `lag` tag (complete flows: the 120 s flow
timeout, up to a 30 s file, processing); ~1 s is the `live` tag (the 10 ms detection stream plus a world-model step).

Rollout steps are events, not seconds, so no forecast carries a time: this measures what the served ones were worth.

Also reported, as the forecast's recall: hit@k -- for every real attacker -> victim event, whether the victim was among
the ranking head's top k active hosts from the state before it, separately for moves to a victim the attacker had not
contacted before.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

import numpy as np

from models.world_model.inference import Replay
from models.world_model.reception import receive

HORIZON = 3600.0         # a predicted link not seen within this long counts as not happening


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--latents", type=Path, required=True, help="one day's latents folder")
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--every", type=int, default=10_000, help="events between forecasts")
    parser.add_argument("--steps", type=int, default=6)
    parser.add_argument("--seeds", type=int, default=4)
    parser.add_argument("--lags", type=float, nargs="+", default=[150.0, 1.0])
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--limit", type=int, default=None, help="stop after this many events")
    args = parser.parse_args(argv)

    run = receive([args.latents])
    day = run.days[0]
    replay = Replay(run, args.checkpoint, split=None, device=args.device, attention=False, keep=1)
    # Every link's event times, to find the first occurrence after any T.
    key = day.sender.astype(np.int64) << 32 | day.receiver.astype(np.int64)
    order = np.lexsort((day.t_obs, key))
    keys, times = key[order], day.t_obs[order]
    position_of = {int(e): i for i, e in enumerate(day.event_id)}

    predictions = []                     # (seed label, delay after T or inf, the link had happened before T)
    # hit@k: for every real attacker -> victim event, where the victim ranked among the active hosts, from the state
    # before its chunk (the ranking the forecast's first step uses); inf when it was not among the candidates at all.
    ranks: dict[str, list[float]] = {"new victim": [], "every attack event": []}
    seen: set[tuple[int, int]] = set()
    total = len(day.t_obs) if args.limit is None else min(args.limit, len(day.t_obs))
    next_forecast = args.every
    while replay.scored < total and not replay.exhausted:
        replay.advance(replay.window)                    # one chunk: its ranking is the state before it
        if not replay.recent:
            continue
        ranked = replay.rows["ranking"][-1] if replay.rows["ranking"] else []
        place = {int(node): i for i, (node, _) in enumerate(ranked)}
        for _, d, pos, _ in replay.recent:
            pair = (int(d.sender[pos]), int(d.receiver[pos]))
            if d.role[pos] == 1:                         # attacker -> victim, from the schedule
                rank = place.get(pair[1], np.inf)
                ranks["every attack event"].append(rank)
                if pair not in seen:
                    ranks["new victim"].append(rank)
            seen.add(pair)
        if replay.scored < next_forecast:
            continue
        next_forecast += args.every
        now = float(replay.recent[-1][1].t_obs[replay.recent[-1][2]])
        for row in replay.rollout(args.steps, args.seeds):
            link = int(row["sender"]) << 32 | int(row["receiver"])
            lo, hi = np.searchsorted(keys, link, "left"), np.searchsorted(keys, link, "right")
            span = times[lo:hi]
            later = span[span > now]
            delay = float(later[0] - now) if len(later) and later[0] - now <= HORIZON else np.inf
            seed = position_of[int(row["seed_id"])]
            predictions.append((str(day.label[seed]), delay, bool((span <= now).any())))
        print(f"  {replay.scored:,}/{total:,} events, {len(predictions):,} predicted links", flush=True)

    groups = defaultdict(list)
    for label, delay, repeat in predictions:
        groups[label].append((delay, repeat))
    print(f"\n{day.day}: {len(predictions):,} predicted links from forecasts every {args.every:,} events; "
          f"'happens' = the link occurs within {HORIZON:.0f} s after the forecast's state")
    header = f"{'seed':22s} {'links':>7s} {'happens':>8s} {'median wait':>12s} " + " ".join(
        f"{'ahead @' + format(lag, 'g') + ' s':>12s}" for lag in args.lags) + f" {'new link':>9s}"
    print(header)
    for label in sorted(groups, key=lambda g: (g == "Benign", g)):
        delay = np.array([d for d, _ in groups[label]])
        repeat = np.array([r for _, r in groups[label]])
        happens = np.isfinite(delay)
        median = f"{np.median(delay[happens]):.1f} s" if happens.any() else "-"
        ahead = " ".join(f"{np.mean(delay[happens] > lag) if happens.any() else 0:12.1%}" for lag in args.lags)
        print(f"{label[:22]:22s} {len(delay):7,d} {happens.mean():8.1%} {median:>12s} {ahead} {np.mean(~repeat):9.1%}")
    print(f"\nWHERE NEXT (hit@k): the true victim's rank among the active hosts (at most {replay.max_candidates}), "
          f"from the state before its event")
    print(f"{'attacker events':22s} {'events':>8s} {'hit@1':>7s} {'hit@3':>7s} {'hit@10':>7s} {'not a candidate':>16s}")
    for name, values in ranks.items():
        r = np.asarray(values, dtype=float)
        if not len(r):
            print(f"{name:22s} {0:8,d}   (no attacker -> victim events in the replayed span)")
            continue
        print(f"{name:22s} {len(r):8,d} " + " ".join(f"{np.mean(r < k):7.1%}" for k in (1, 3, 10))
              + f" {np.mean(~np.isfinite(r)):16.1%}")
    print("\nahead @ L: of the links that happened, the share that happened more than L seconds after the forecast's "
          "state -- still in the future when a service with that lag serves it. new link: never seen before the state.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
