"""Where does an attacker go next? The world model against simple live-friendly heuristics, and their fusion.

Run: uv run python -m tools.measure.forecast_candidates --latents <latents>/<day> --checkpoint <world model .pt> \\
         [--forecasts 150] [--device cuda]

At real attacker -> victim events (roles from the schedule), from the state just before, every method ranks the hosts
seen so far; the truth is what the attacker did in the next hour:

  model, recent 64            the world model's ranking head over the 64 most recently active hosts -- served today
  model, all hosts            the same head over every host seen so far, in one batched pass
  world model, retrieved 256  retrieval then ranking: cheap signals choose which hosts the world model considers
                              (the recent pool, the 128 hosts nearest in IPv4 address to the attacker's last three
                              targets, the 64 most contacted recently), the world model scores and chooses
  world model x IP prior      the world model's probability times an address-proximity prior, p^a q^(1-a); a = 1
                              is the world model alone
  reference lines             address proximity alone, popularity alone (PopTrack) -- not candidates to replace the
                              world model, which is what estimates the next state; they show what the signals carry

Reported per method and list size N: hit@N (the attacker's next new victim is on the list), recall@N (of its next six
new victims), precision@N (listed hosts it contacted at all within the hour). Then a conformal list size: calibrated on
the first half of the forecasts, the smallest N whose list held the next new victim in 80% / 90% of them, and how
often that N actually did on the second half.

Why these: temporal-graph benchmarks find memorisation, popularity and recency baselines competitive with learned
temporal GNNs (Poursafaei et al., NeurIPS 2022; Daniluk & Dabrowski 2023), and fusing them robust (Base3, 2025).
"""
from __future__ import annotations

import argparse
import ipaddress
import time
from collections import Counter, defaultdict, deque
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import torch

from models.world_model.beam import CausalNeighbours, score_hosts
from models.world_model.inference import Replay, recently_active
from models.world_model.reception import receive

HORIZON = 3600.0
SIZES = (1, 3, 5, 10, 20)
RRF = 60.0
ALPHAS = (0.75, 0.5, 0.25)          # weight on the world model; 1 is the world model alone


def ip_int(ip: str) -> float:
    try:
        return float(int(ipaddress.IPv4Address(ip)))
    except ValueError:
        return np.nan


def ranked(hosts: np.ndarray, score: np.ndarray) -> list[int]:
    """Hosts best first (higher score better), ties broken by host id so every run lists them the same way."""
    order = np.lexsort((hosts, -score))
    return hosts[order].tolist()


def fuse(*lists: list[int]) -> list[int]:
    score = defaultdict(float)
    for items in lists:
        for rank, host in enumerate(items):
            score[host] += 1.0 / (RRF + rank + 1)
    return sorted(score, key=lambda h: (-score[h], h))


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--latents", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--events-root", type=Path, default=Path("data/events"), help="for each day's node index (IPs)")
    parser.add_argument("--forecasts", type=int, default=150)
    parser.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    parser.add_argument("--quick", action="store_true", help="forecast at every attack chunk and stop at --forecasts")
    args = parser.parse_args(argv)

    run = receive([args.latents])
    day = run.days[0]
    index = pq.read_table(args.events_root / day.day / "node_index.parquet", columns=["node_id", "ip"]).to_pandas()
    ip = np.full(day.node_count, np.nan)
    known = index["node_id"].to_numpy() < day.node_count
    ip[index["node_id"].to_numpy()[known]] = [ip_int(a) for a in index["ip"].to_numpy()[known]]

    replay = Replay(run, args.checkpoint, split=None, device=args.device, attention=False, keep=1)
    device = torch.device(args.device)
    neighbours = CausalNeighbours(day.sender, day.receiver, day.t_obs, replay.neighbours)
    by_sender = defaultdict(list)
    for position in np.flatnonzero(np.isin(day.sender, np.unique(day.sender[day.role == 1]))):
        by_sender[int(day.sender[position])].append((float(day.t_obs[position]), int(day.receiver[position])))
    stride = 1 if args.quick else max(1, int(np.ceil((day.role == 1).sum() / replay.window)) // args.forecasts)

    seen = np.zeros(day.node_count, bool)
    recent: deque = deque()
    popularity: Counter = Counter()
    results, timings, chunks = defaultdict(list), defaultdict(list), 0
    while not replay.exhausted:
        if args.quick and len(results["model, recent 64"]) >= args.forecasts:
            break
        replay.advance(replay.window)
        if not replay.recent:
            continue
        positions = np.fromiter((p for _, _, p, _ in replay.recent), int)
        attack = positions[day.role[positions] == 1]
        if len(attack):
            chunks += 1
        if len(attack) and chunks % stride == 0 and len(results["model, recent 64"]) < args.forecasts:
            position = int(attack[-1])
            attacker, target, t0 = int(day.sender[position]), int(day.receiver[position]), float(day.t_obs[position])
            contacts = by_sender[attacker]
            before = [h for t, h in contacts if t <= t0]
            future = {}
            for t, h in contacts:
                if t0 < t <= t0 + HORIZON:
                    future.setdefault(h, t - t0)
            new = [h for h, _ in sorted(future.items(), key=lambda kv: kv[1]) if h not in set(before)][:6]
            if new:
                active = recently_active(day, position, replay.active_window, replay.max_candidates)
                z = torch.as_tensor(day.z[position:position + 1], dtype=torch.float32, device=device)
                universe = np.flatnonzero(seen)
                universe = universe[universe != attacker]
                lists = {}
                clock = time.perf_counter()
                recent_pool = np.asarray([h for h in active.tolist() if h != attacker])
                p = score_hosts(replay.model, neighbours, attacker, target, z, t0, active, recent_pool)
                lists["model, recent 64"] = ranked(recent_pool, p)
                timings["model, recent 64"].append(time.perf_counter() - clock)
                clock = time.perf_counter()
                p = score_hosts(replay.model, neighbours, attacker, target, z, t0, active, universe)
                if device.type == "cuda":
                    torch.cuda.synchronize()
                timings["world model, all hosts"].append(time.perf_counter() - clock)
                timings["hosts known"].append(len(universe))
                lists["model, all hosts"] = ranked(universe, p)
                last = [h for h in before[-3:] if np.isfinite(ip[h])] or [target]
                distance = np.nanmin(np.abs(ip[universe][:, None] - ip[np.asarray(last)][None, :]), axis=1)
                ip_list = ranked(universe, -np.nan_to_num(distance, nan=np.inf))
                pop_list = ranked(universe, np.asarray([popularity[h] for h in universe], float))
                # Retrieval, then the world model ranks: the recent pool, the hosts nearest the attacker's recent
                # targets, and the recently popular ones -- the world model scores and chooses among them.
                retrieved = list(dict.fromkeys(recent_pool.tolist() + ip_list[:128] + pop_list[:64]))
                pool_arr = np.asarray(retrieved, np.int64)
                clock = time.perf_counter()
                p_pool = score_hosts(replay.model, neighbours, attacker, target, z, t0, active, pool_arr)
                timings["world model, retrieved pool"].append(time.perf_counter() - clock)
                timings["hosts retrieved"].append(len(pool_arr))
                lists["world model, retrieved 256"] = ranked(pool_arr, p_pool)
                # The world model's choice with a proximity prior: p ~ p_wm^a * q^(1-a), q from the address rank.
                rank_ip = {h: i for i, h in enumerate(ip_list)}
                q = np.asarray([1.0 / (1 + rank_ip.get(h, len(ip_list))) for h in retrieved])
                q /= q.sum()
                for a in ALPHAS:
                    fused = a * np.log(np.clip(p_pool, 1e-12, None)) + (1 - a) * np.log(q)
                    lists[f"world model x IP prior, a={a}"] = ranked(pool_arr, fused)
                lists["reference: IP proximity alone"] = ip_list
                lists["reference: popular alone"] = pop_list
                pool = set(recent_pool.tolist())
                for name, items in lists.items():
                    place = {h: i for i, h in enumerate(items)}
                    results[name].append({"first": place.get(new[0], np.inf),
                                          "new": [place.get(h, np.inf) for h in new],
                                          "shown": items[:max(SIZES)], "future": future,
                                          "in_recent_pool": new[0] in pool})
        # what later forecasts may know: hosts seen, and who was contacted recently
        seen[day.sender[positions]] = True
        seen[day.receiver[positions]] = True
        chunk_receivers = Counter(day.receiver[positions].tolist())
        recent.append(chunk_receivers)
        popularity.update(chunk_receivers)
        while len(recent) > 20_000 // replay.window:
            popularity.subtract(recent.popleft())

    first = results["model, recent 64"]
    print(f"{day.day}: {len(first)} forecasts at attacker events; truth = the attacker's contacts in the next "
          f"{HORIZON:.0f} s. The next new victim was among the recent-64 pool in "
          f"{np.mean([r['in_recent_pool'] for r in first]):.1%} of forecasts")
    header = f"{'method':30s} " + " ".join(f"{'hit@' + str(n):>7s}" for n in SIZES) + "  " + " ".join(
        f"{'recall@' + str(n):>9s}" for n in (5, 10, 20)) + "  " + " ".join(f"{'prec@' + str(n):>7s}" for n in (3, 10))
    print(header)
    for name, rows in results.items():
        firsts = np.array([r["first"] for r in rows], float)
        recall = {n: np.mean([np.mean(np.array(r["new"]) < n) for r in rows]) for n in (5, 10, 20)}
        precision = {n: np.mean([np.mean([h in r["future"] for h in r["shown"][:n]]) if r["shown"][:n] else 0
                                 for r in rows]) for n in (3, 10)}
        print(f"{name:30s} " + " ".join(f"{np.mean(firsts < n):7.1%}" for n in SIZES) + "  "
              + " ".join(f"{recall[n]:9.1%}" for n in (5, 10, 20)) + "  "
              + " ".join(f"{precision[n]:7.1%}" for n in (3, 10)))

    print("\nconformal list size for the next new victim (first half calibrates, second half checks):")
    for name, rows in results.items():
        firsts = np.array([r["first"] for r in rows], float)
        half = len(firsts) // 2
        calibrate, check = firsts[:half], firsts[half:]
        out = []
        for level in (0.8, 0.9):
            n = np.quantile(calibrate, level, method="higher") + 1 if len(calibrate) else np.inf
            out.append(f"{level:.0%}: N={'inf' if not np.isfinite(n) else int(n):>6} -> {np.mean(check < n):5.1%} held")
        print(f"  {name:30s} " + "   ".join(out))
    print("\nscoring time per forecast, median (95th percentile):")
    for name, values in timings.items():
        if name.startswith("hosts"):
            print(f"  {name:34s} {np.median(values):8,.0f}")
        else:
            print(f"  {name:34s} {1e3 * np.median(values):8.2f} ms ({1e3 * np.quantile(values, 0.95):.2f} ms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
