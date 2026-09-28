"""The world model's forecast, served better: branching, retrieval and a proximity prior, measured against what happened.

Run: uv run python -m tools.measure.forecast_beam --latents <latents>/<day> --checkpoint <world model .pt> \\
         [--k 1 2 3] [--forecasts 150] [--device cuda]

Every forecast is seeded at a real attacker -> victim event (roles from the schedule) and rolled out six steps by the
world model (models.world_model.beam.beam_rollout), which updates its state at every imagined step. Serving variants,
none of which changes the model:

  served                  the 64 most recently active hosts, the world model alone -- what runs today
  retrieved               the hosts the world model chooses among are retrieved first: the recent pool, the 128 hosts
                          nearest in IPv4 address to the attacker's last three targets, the 64 most contacted recently
  retrieved + prior a     as retrieved, each step's choice p_world_model^a * q^(1-a), q an address-proximity prior that
                          follows the path's own targets

each with k = 1, 2, 3 hosts kept per path per step (k^6 paths). The paths are shown as **one ranked list of hosts**: a
path's weight is the product of its steps' probabilities, normalised over the kept paths; a host's score is the summed
weight of the paths that reach it. Scored against the attacker's next hour, for the top N hosts shown:
  precision@N  shown hosts the attacker contacted within the hour
  recall@N     the attacker's next new victims (up to six, never contacted before the forecast) shown
  ahead        of the shown hosts it contacted, those contacted more than 150 s / 1 s after the forecast's state
Also: k=1 of the served variant against `inference.rollout_graph` (ties between equally scored hosts aside), the
reliability of the shown score, and the time per forecast.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import time
from collections import Counter, defaultdict, deque
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import torch

from models.world_model.beam import CausalNeighbours, beam_rollout
from models.world_model.dataset import neighbour_nodes
from models.world_model.inference import Replay, recently_active, rollout_graph
from models.world_model.reception import receive

HORIZON = 3600.0
LAGS = (150.0, 1.0)
VARIANTS = (("served", None), ("retrieved", 1.0), ("retrieved + prior 0.5", 0.5), ("retrieved + prior 0.25", 0.25))


def host_scores(result: dict) -> tuple[np.ndarray, np.ndarray]:
    """The paths as one ranked list: (hosts, reach probability), best first."""
    targets, logp = result["targets"], result["log_probability"]
    if not len(targets):
        return np.zeros(0, np.int64), np.zeros(0)
    weight = np.exp(logp - logp.max())
    weight /= weight.sum()
    reach = defaultdict(float)
    for path, w in zip(targets, weight):
        for host in set(path.tolist()):
            reach[host] += w
    hosts = np.array(sorted(reach, key=lambda h: (-reach[h], h)), np.int64)
    return hosts, np.array([reach[h] for h in hosts])


def platt(p: np.ndarray, y: np.ndarray) -> tuple[float, float]:
    """Fit logit(p') = a logit(p) + b to outcomes y by maximum likelihood."""
    x = torch.as_tensor(np.log(p / (1 - p)), dtype=torch.float64)
    t = torch.as_tensor(y, dtype=torch.float64)
    ab = torch.tensor([1.0, 0.0], dtype=torch.float64, requires_grad=True)
    optimiser = torch.optim.LBFGS([ab], max_iter=200)

    def closure():
        optimiser.zero_grad()
        loss = torch.nn.functional.binary_cross_entropy_with_logits(ab[0] * x + ab[1], t)
        loss.backward()
        return loss
    optimiser.step(closure)
    return float(ab[0].detach()), float(ab[1].detach())


def ece(p: np.ndarray, y: np.ndarray, bins: int = 10) -> float:
    """Expected calibration error: the gap between shown probability and outcome, weighted by bin size."""
    at = np.minimum((p * bins).astype(int), bins - 1)
    return float(sum(abs(p[at == b].mean() - y[at == b].mean()) * (at == b).mean() for b in range(bins) if (at == b).any()))


def ip_int(ip: str) -> float:
    try:
        return float(int(ipaddress.IPv4Address(ip)))
    except ValueError:
        return np.nan


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--latents", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--events-root", type=Path, default=Path("data/events"), help="for each day's node index (IPs)")
    parser.add_argument("--k", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--steps", type=int, default=6)
    parser.add_argument("--forecasts", type=int, default=150, help="forecasts at most, spread over the attack chunks")
    parser.add_argument("--show", type=int, nargs="+", default=[3, 5, 10], help="hosts shown to the analyst")
    parser.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    parser.add_argument("--quick", action="store_true", help="forecast at every attack chunk and stop at --forecasts")
    args = parser.parse_args(argv)

    run = receive([args.latents])
    day = run.days[0]
    replay = Replay(run, args.checkpoint, split=None, device=args.device, attention=False, keep=1)
    model, device = replay.model, torch.device(args.device)
    neighbours = CausalNeighbours(day.sender, day.receiver, day.t_obs, replay.neighbours)
    index = replay.index(day)
    table = pq.read_table(args.events_root / day.day / "node_index.parquet", columns=["node_id", "ip"]).to_pandas()
    address = np.full(day.node_count, np.nan)
    inside = table["node_id"].to_numpy() < day.node_count
    address[table["node_id"].to_numpy()[inside]] = [ip_int(a) for a in table["ip"].to_numpy()[inside]]
    by_sender = defaultdict(list)
    for position in np.flatnonzero(np.isin(day.sender, np.unique(day.sender[day.role == 1]))):
        by_sender[int(day.sender[position])].append((float(day.t_obs[position]), int(day.receiver[position])))
    stride = 1 if args.quick else max(1, int(np.ceil((day.role == 1).sum() / replay.window)) // args.forecasts)

    seen = np.zeros(day.node_count, bool)
    recent: deque = deque()
    popularity: Counter = Counter()
    rows, timing, forecasts, chunks = [], defaultdict(list), 0, 0
    check = {"identical": 0, "tie": 0, "different": 0}
    check_gaps: list[float] = []
    while not replay.exhausted and forecasts < args.forecasts:
        replay.advance(replay.window)
        if not replay.recent:
            continue
        positions = np.fromiter((p for _, _, p, _ in replay.recent), int)
        attack = positions[day.role[positions] == 1]
        chunks += bool(len(attack))
        if len(attack) and chunks % stride == 0:
            position = int(attack[-1])
            attacker, target, t0 = int(day.sender[position]), int(day.receiver[position]), float(day.t_obs[position])
            contacts = by_sender[attacker]
            earlier = [h for t, h in contacts if t <= t0]
            future = {}
            for t, h in contacts:
                if t0 < t <= t0 + HORIZON:
                    future.setdefault(h, t - t0)
            new = [h for h, _ in sorted(future.items(), key=lambda kv: kv[1]) if h not in set(earlier)][:6]
            active = recently_active(day, position, replay.active_window, replay.max_candidates)
            z = torch.as_tensor(day.z[position:position + 1], dtype=torch.float32, device=device)
            served = [c for c in active.tolist() if c != attacker]
            # retrieval: the recent pool, the hosts nearest the attacker's recent targets, the recently popular ones
            universe = np.flatnonzero(seen)
            universe = universe[universe != attacker]
            anchors = [h for h in earlier[-3:] if np.isfinite(address[h])] or [target]
            distance = np.nanmin(np.abs(address[universe][:, None] - address[np.asarray(anchors)][None, :]), axis=1)
            nearest = universe[np.lexsort((universe, np.nan_to_num(distance, nan=np.inf)))][:128].tolist()
            popular = [h for h, _ in popularity.most_common(64)]
            retrieved = np.asarray(list(dict.fromkeys(served + nearest + popular)), np.int64)
            forecasts += 1

            clock = time.perf_counter()
            for node in served + [attacker]:
                neighbour_nodes(day, node, index.before(node, t0 + 1e-9))
            timing["graph, one host at a time"].append(time.perf_counter() - clock)
            clock = time.perf_counter()
            neighbours.peers(np.asarray(served + [attacker]), t0)
            timing["graph, one vectorised query"].append(time.perf_counter() - clock)

            for name, alpha in VARIANTS:
                for k in args.k:
                    if device.type == "cuda":
                        torch.cuda.synchronize()
                    clock = time.perf_counter()
                    result = beam_rollout(model, neighbours, attacker, target, z, t0, active, steps=args.steps, k=k,
                                          pool=None if alpha is None else retrieved, alpha=alpha or 1.0,
                                          address=address, recent_targets=earlier)
                    if device.type == "cuda":
                        torch.cuda.synchronize()
                    timing[f"{name}, k={k} ({k ** args.steps} paths)"].append(time.perf_counter() - clock)
                    hosts, probability = host_scores(result)
                    rows.append({"variant": name, "k": k, "hosts": hosts, "probability": probability,
                                 "future": future, "new": new,
                                 "pool": set(served if alpha is None else retrieved.tolist())})
                    if name == "served" and k == 1 and os.environ.get("BEAM_TRACE") == str(forecasts):
                        print(f"  TRACE forecast {forecasts}: seed {attacker}->{target} first step {result['targets'][0][0]} "
                              f"p {result['probability'][0][0]:.6g}", flush=True)
                    if name == "served" and k == 1 and sum(check.values()) < 30 and not os.environ.get("BEAM_NO_REF"):
                        saved = (model.memory.clone(), model.last_seen.clone())
                        reference = rollout_graph(model, index, day, attacker, target, z, t0,
                                                  torch.as_tensor(active, dtype=torch.long, device=device),
                                                  steps=args.steps)
                        model.memory, model.last_seen = saved
                        mine, theirs = result["targets"][0].tolist(), [r["target"] for r in reference]
                        if mine == theirs:
                            check["identical"] += 1
                        else:
                            step = next(i for i, (a, b) in enumerate(zip(mine, theirs)) if a != b)
                            ranked = {c["node"]: c["probability"] for c in reference[step]["candidates"]}
                            gap = abs(ranked[mine[step]] - ranked[theirs[step]]) if mine[step] in ranked else np.inf
                            # GPU kernels round differently by batch shape (~1e-7 relative): a near-tie can flip
                            check["tie" if gap < 1e-4 else "different"] += 1
                            check_gaps.append(gap)
                            if not gap < 1e-4:
                                print(f"  DIVERGE forecast {forecasts} step {step}: mine {mine} theirs {theirs} seed {attacker}->{target}; "
                                      f"reference step candidates {reference[step]['candidates']}; "
                                      f"my step probabilities {result['probability'][0].round(4).tolist()}", flush=True)
                                full = beam_rollout(model, neighbours, attacker, target, z, t0, active, steps=1,
                                                    k=len(active))
                                dist = dict(zip(full["targets"][:, 0].tolist(), full["probability"][:, 0].tolist()))
                                print(f"    target in active {target in active.tolist()}, pool {len(active)}; mine step0: "
                                      f"{mine[0]}={dist.get(mine[0])}, {theirs[0]}={dist.get(theirs[0])}; "
                                      f"duplicates in active {len(active) - len(set(active.tolist()))}", flush=True)
        seen[day.sender[positions]] = True
        seen[day.receiver[positions]] = True
        chunk_receivers = Counter(day.receiver[positions].tolist())
        recent.append(chunk_receivers)
        popularity.update(chunk_receivers)
        while len(recent) > 20_000 // replay.window:
            popularity.subtract(recent.popleft())

    with_new = [r for r in rows if r["variant"] == "served" and r["k"] == args.k[0] and r["new"]]
    print(f"{day.day}: {forecasts} forecasts seeded at attacker events ({len(with_new)} with a new victim in the next "
          f"hour), {args.steps} steps")
    print(f"served k=1 against the existing rollout: {check['identical']} identical, {check['tie']} differ only by a "
          f"tie or near-tie (probabilities within 1e-4), {check['different']} differ otherwise"
          + (f"; gaps at the first differing step: {', '.join(f'{g:.2e}' for g in check_gaps)}" if check_gaps else ""))
    for name, _ in VARIANTS:
        mine = [r for r in rows if r["variant"] == name and r["k"] == args.k[0] and r["new"]]
        inside = [h in r["pool"] for r in mine for h in r["new"]]
        print(f"  ceiling, {name:24s}: {np.mean(inside) if inside else float('nan'):6.1%} of the next new victims were "
              f"in the pool the world model chooses from")
    print(f"\n{'variant':24s} {'k':>2} {'shown':>6} {'hosts':>6} {'precision':>10} {'recall':>8} "
          + " ".join(f"{'ahead @' + format(lag, 'g') + ' s':>13}" for lag in LAGS))
    for name, _ in VARIANTS:
        for k in args.k:
            mine = [r for r in rows if r["variant"] == name and r["k"] == k]
            for n in args.show:
                shown = [set(r["hosts"][:n].tolist()) for r in mine]
                precision = np.mean([len(s & set(r["future"])) / len(s) for s, r in zip(shown, mine) if s])
                pairs = [(s, r) for s, r in zip(shown, mine) if r["new"]]
                recall = np.mean([len(s & set(r["new"])) / len(r["new"]) for s, r in pairs]) if pairs else float("nan")
                waits = [r["future"][h] for s, r in zip(shown, mine) for h in s & set(r["future"])]
                ahead = " ".join(f"{np.mean(np.asarray(waits) > lag) if waits else float('nan'):13.1%}" for lag in LAGS)
                print(f"{name:24s} {k:>2} {n:>6} {np.mean([len(s) for s in shown]):6.1f} {precision:10.1%} "
                      f"{recall:8.1%} {ahead}")
    print("\nreliability of the shown score (every listed host), largest k:")
    edges = np.array([0, 0.05, 0.1, 0.2, 0.4, 0.7, 1.0001])
    for name, _ in VARIANTS:
        mine = [r for r in rows if r["variant"] == name and r["k"] == max(args.k)]
        if not mine:
            continue
        p = np.concatenate([r["probability"] for r in mine])
        hit = np.concatenate([[h in r["future"] for h in r["hosts"].tolist()] for r in mine])
        cells = [f"{lo:.2f}-{min(hi, 1):.2f}: {hit[(p >= lo) & (p < hi)].mean():5.1%} of "
                 f"{int(((p >= lo) & (p < hi)).sum())}"
                 for lo, hi in zip(edges[:-1], edges[1:]) if ((p >= lo) & (p < hi)).any()]
        print(f"  {name:24s} " + " | ".join(cells))
    # Can the shown number be made a probability? Platt scaling -- logit(p') = a logit(p) + b -- fitted on the first half
    # of the forecasts, judged on the second by expected calibration error (ECE, 10 equal-width bins).
    print("\ncalibrating the shown score (first half fits, second half checks), largest k:")
    for name, _ in VARIANTS:
        mine = [r for r in rows if r["variant"] == name and r["k"] == max(args.k)]
        if len(mine) < 4:
            continue
        half = len(mine) // 2
        def pairs(part):
            p = np.concatenate([r["probability"] for r in part]).clip(1e-6, 1 - 1e-6)
            y = np.concatenate([[h in r["future"] for h in r["hosts"].tolist()] for r in part]).astype(float)
            return p, y
        fit_p, fit_y = pairs(mine[:half])
        test_p, test_y = pairs(mine[half:])
        a_, b_ = platt(fit_p, fit_y)
        calibrated = 1 / (1 + np.exp(-(a_ * np.log(test_p / (1 - test_p)) + b_)))
        from sklearn.isotonic import IsotonicRegression
        isotonic = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(fit_p, fit_y)
        print(f"  {name:24s} ECE raw {ece(test_p, test_y):.3f} | Platt {ece(calibrated, test_y):.3f} "
              f"(a={a_:.2f}, b={b_:.2f}) | isotonic {ece(isotonic.predict(test_p), test_y):.3f}; "
              f"{len(test_p)} listed hosts checked")
    print("\nper forecast, median (95th percentile):")
    for name, values in timing.items():
        print(f"  {name:40s} {1e3 * np.median(values):8.2f} ms ({1e3 * np.quantile(values, 0.95):.2f} ms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
