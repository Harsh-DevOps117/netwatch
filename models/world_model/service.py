"""Serve the world model's forecast over HTTP, for the dashboard's Forecast panel.

The dashboard is a separate process and reads its forecast from a URL. This is what answers that URL: it loads a
trained Block 10 checkpoint once and **streams** a recorded day through it -- memory stays live between ticks, each
tick scores the next few chunks and rolls the new state forward -- so the forecast follows its input the way it would
follow a live sensor, instead of being re-scored from the start of the day on every refresh.

It is a replay, and says so in every payload: there is no live runner from packet capture to Block 10 latents yet
(docs/STATUS: "live runner -- does not exist"), so the hosts on the forecast are the recorded day's, not this machine's.

Nothing here re-implements inference: scoring and rollout are `models.world_model.inference.Replay`, the same path
`emit` writes the contract files with.

Run:
    uv run python -m models.world_model.service --load <checkpoint.pt> --latents <dir> --port 8900
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pyarrow.parquet as pq
import torch

from models.explanation.world_model import seed_explanations
from models.world_model.inference import Replay
from models.world_model.reception import receive

# What the model does not claim. The panel shows an attack stage, and the world model has no stage head: it predicts
# the next event and ranks candidate targets. Reporting a MITRE stage here would be an invention, so the field is
# returned empty and the reason travels with it.
STAGE_UNAVAILABLE = ""

# The ranking head's score, as `models.world_model.calibration` names it when that is the one it serves.
TARGET = "target_probability"
INCIDENT_GAP_S = 120.0


def node_names(index: "Path | None") -> dict:
    """node_id to IP, so the panel names hosts rather than integers.

    Input:  a node_index.parquet from ingest, or None
    Output: {node_id: ip}, empty when there is no index

    Node ids are an internal encoding; an operator reading the panel needs the address. Missing index means the panel
    falls back to the id, which is honest, rather than inventing an address.
    """
    if index is None or not Path(index).is_file():
        return {}
    table = pq.read_table(index, columns=["node_id", "ip"]).to_pandas()
    return {int(row.node_id): str(row.ip) for row in table.itertuples()}


def served_threshold(checkpoint: Path) -> "dict | None":
    """The operating point `models.world_model.calibration` stored beside the weights, or None when uncalibrated.

    Input:  the checkpoint
    Output: the served row (budget, threshold, fpr, recall, counts, test window, persist-3 figures) plus the score, its
            direction, a readable rule, what it was calibrated on, and every budget's threshold -- or None
    """
    state = torch.load(checkpoint, map_location="cpu", weights_only=False)
    if "serve_threshold" not in state:
        return None
    direction = int(state.get("direction", 1))
    value = float(state["serve_threshold"]["threshold"])
    calibration = state.get("calibration", {})
    return {**state["serve_threshold"], "score": state.get("score", "next_event_pred_error"), "direction": direction,
            # The rule in the score's own units, for a reader: thresholds are stored on the signed scale.
            "rule": f"{'target probability' if state.get('score') == TARGET else 'surprise'} "
                    f"{'>=' if direction > 0 else '<='} {direction * value:.4f}",
            "calibrated_on": calibration.get("calibrated_on", "validation benign"),
            "days": calibration.get("days", []),
            "thresholds": {str(k): float(v) for k, v in state.get("thresholds", {}).items()},
            "epoch": state.get("epoch")}


def severity(value: float, threshold: dict) -> str:
    """HIGH past the tightest calibrated threshold, MEDIUM past the served one, else empty.

    Compared on the signed scale `direction * value` that calibration stored the thresholds on.
    """
    signed = threshold.get("direction", 1) * value
    tightest = max([threshold["threshold"], *threshold["thresholds"].values()])
    if signed >= tightest:
        return "HIGH"
    return "MEDIUM" if signed >= threshold["threshold"] else ""


def observed_incidents(rows: dict, threshold: "dict | None", names: dict, *, gap: float = INCIDENT_GAP_S) -> list[dict]:
    """Group observed world-model flags by link, without treating a forecast as an observation.

    Three consecutive scored events on the same link must cross the served threshold.
    A further crossing within ``gap`` seconds extends the same incident. These are
    operational groupings over the current scored window, not validated incident FPR.
    """
    if threshold is None:
        return []
    score_name = threshold["score"]
    direction = int(threshold["direction"])
    cutoff = float(threshold["threshold"])
    runs: dict[tuple[int, int], int] = {}
    pending: dict[tuple[int, int], list[dict]] = {}
    last_flag: dict[tuple[int, int], float] = {}
    active: dict[tuple[int, int], dict] = {}
    incidents: list[dict] = []
    columns = ("event_id", "t", "surprise", "ranking", "sender", "receiver")
    newest = float(rows["t"][-1]) if len(rows["t"]) else 0.0
    for event_id, t, surprise, ranking, sender, receiver in zip(*(rows[c] for c in columns)):
        key = (int(sender), int(receiver))
        value = (max(dict(ranking).get(sender, 0.0), dict(ranking).get(receiver, 0.0))
                 if score_name == TARGET else float(surprise))
        if direction * value < cutoff:
            runs.pop(key, None)
            pending.pop(key, None)
            continue
        event_time = float(t)
        if event_time > last_flag.get(key, float("-inf")) + gap:
            runs.pop(key, None)
            pending.pop(key, None)
        runs[key] = runs.get(key, 0) + 1
        last_flag[key] = event_time
        event = {"event_id": int(event_id), "t": event_time,
                 "sender_ip": names.get(key[0], str(key[0])),
                 "receiver_ip": names.get(key[1], str(key[1])),
                 "value": round(float(value), 6), "severity": severity(float(value), threshold)}
        if runs[key] < 3:
            pending.setdefault(key, []).append(event)
            continue
        incident = active.get(key)
        if incident is None or event_time > incident["last_seen"] + gap:
            incident = {"id": f"{event_time:.6f}:{key[0]}:{key[1]}", "opened": event_time,
                        "last_seen": event_time, "sender_ip": names.get(key[0], str(key[0])),
                        "receiver_ip": names.get(key[1], str(key[1])), "opening_score": round(float(value), 6),
                        "events": 0, "related_events": [], "severity": severity(float(value), threshold)}
            active[key] = incident
            incidents.append(incident)
        incident["last_seen"] = event_time
        incident["related_events"].extend([*pending.pop(key, ()), event])
        incident["events"] = len(incident["related_events"])
        if severity(float(value), threshold) == "HIGH":
            incident["severity"] = "HIGH"
    return [incident for incident in incidents if incident["last_seen"] + gap >= newest][-30:]


def forecast_payload(rollouts: list[dict], rows: dict, *, caveats: list[str], names: "dict | None" = None,
                     threshold: "dict | None" = None, recent: int = 400, source: "dict | None" = None,
                     explanation: "list | None" = None) -> dict:
    """Turn the replay's rows and rollout into the Forecast panel's fields.

    Input:  rollout rows from `Replay.rollout`, the replay's scored rows, caveats, node_id -> IP, the served threshold
            (None when uncalibrated), how many of the latest scored events form the current input, where the input is
            coming from, and per-seed attention from `models.explanation.world_model.seed_explanations`
    Output: the payload dict

    Two graphs, both judged against the one calibrated threshold: `observed` is the latest scored events -- the input
    the forecast starts from -- and `predicted_edges` is the rollout, one row per (seed, step) with the ranking head's
    leading candidates. Every link carries `value`, the served score -- whichever of surprise or the ranking head's
    target probability calibration chose -- so observed and predicted links are judged on one scale. No threshold, no
    alerts: an uncalibrated scale has no operating point to alert at.
    """
    names = names or {}
    ip = lambda node: names.get(int(node), str(int(node)))
    judge = (lambda v: severity(v, threshold)) if threshold else (lambda v: "")
    score = threshold["score"] if threshold else "next_event_pred_error"
    direction = threshold["direction"] if threshold else 1

    columns = ("event_id", "t", "surprise", "ranking", "sender", "receiver")
    latest = list(zip(*(list(rows[c])[-recent:] for c in columns)))
    links: dict = {}
    input_alerts = []
    recent_events = []
    for event_id, t, surprise, ranking, sender, receiver in latest:
        if score == TARGET:
            ranked = dict(ranking)
            value = max(ranked.get(sender, 0.0), ranked.get(receiver, 0.0))
        else:
            value = float(surprise)
        link = links.setdefault((sender, receiver), {"sender_ip": ip(sender), "receiver_ip": ip(receiver),
                                                     "events": 0, "values": [], "severity": ""})
        link["events"] += 1
        link["values"].append(value)
        level = judge(value)
        recent_events.append({"event_id": int(event_id), "t": float(t), "sender_ip": ip(sender),
                              "receiver_ip": ip(receiver), "value": round(value, 6), "severity": level})
        if level:
            if level == "HIGH" or not link["severity"]:
                link["severity"] = level
            input_alerts.append({"event_id": int(event_id), "t": float(t), "sender_ip": ip(sender),
                                 "receiver_ip": ip(receiver), "value": round(value, 6), "severity": level})
    for link in links.values():
        # The link's most alerting event, in the score's units: the highest when high alerts, the lowest when low does.
        link["value"] = round(direction * max(direction * v for v in link.pop("values")), 6)

    predicted_edges = []
    for row in sorted(rollouts, key=lambda r: (r["seed_id"], r["rollout_step"])):
        candidates = []
        for c in row.get("candidates", []):
            value = float(c["probability"] if score == TARGET else c["surprise"])
            candidates.append({"ip": ip(c["node"]), "node": int(c["node"]),
                               "probability": round(float(c["probability"]), 6),
                               "surprise": round(float(c["surprise"]), 6),
                               "value": round(value, 6), "severity": judge(value)})
        surprise = float(row.get("surprise", row["cumulative_risk"]))
        value = candidates[0]["value"] if candidates else surprise
        predicted_edges.append({
            "step": int(row["rollout_step"]) + 1, "seed_event": int(row["seed_id"]),
            "sender": int(row["sender"]), "receiver": int(row["receiver"]),
            "sender_ip": ip(row["sender"]), "receiver_ip": ip(row["receiver"]),
            "surprise": round(surprise, 6), "value": round(value, 6), "severity": judge(value),
            "probability": candidates[0]["probability"] if candidates else None,
            "candidates": candidates,
            "cumulative_risk": round(float(row["cumulative_risk"]), 6),
            "on_manifold": bool(row["stays_on_manifold"]),
        })

    # One alert per predicted link, at the first step it crosses: that step is the lead the forecast offers.
    alerts, seen = [], set()
    for edge in sorted(predicted_edges, key=lambda e: e["step"]):
        key = (edge["sender"], edge["receiver"])
        if edge["severity"] and key not in seen:
            seen.add(key)
            alerts.append({"sender_ip": edge["sender_ip"], "receiver_ip": edge["receiver_ip"],
                           "sender": edge["sender"], "receiver": edge["receiver"],
                           "crosses_at_step": edge["step"], "value": edge["value"],
                           "severity": edge["severity"], "extrapolated": not edge["on_manifold"]})

    steps = sorted({edge["step"] for edge in predicted_edges})
    per_step = [[e for e in predicted_edges if e["step"] == k] for k in steps]
    return {
        "status": "CONNECTED",
        "score": score,
        "threshold": threshold,
        "source": source or {},
        "observed": {"edges": list(links.values()), "alerts": input_alerts[-50:],
                     "recent_events": recent_events[-12:],
                     "incidents": observed_incidents(rows, threshold, names), "events": len(latest)},
        "alerts": alerts,
        "current_state": "S[t]",
        "future_states": [f"S[t+{k}]" for k in steps],
        # Share of the rolled-out links at each step that cross the served threshold. A count, not a probability.
        "alert_share": [round(sum(bool(e["severity"]) for e in rows_) / max(len(rows_), 1), 6) for rows_ in per_step],
        # Per step, the predicted link closest to alerting, in the score's units; the panel draws it against the
        # threshold in the same units.
        "step_value": [round(direction * max((direction * e["value"] for e in rows_), default=0.0), 6)
                       for rows_ in per_step],
        "predicted_stage": STAGE_UNAVAILABLE,
        "predicted_edges": predicted_edges,
        "rollout_steps": len(steps),
        "caveats": caveats + (["observed incidents group three consecutive threshold crossings on a link with a "
                               f"{INCIDENT_GAP_S:g}-second quiet gap; this grouping has no measured incident false-positive rate"]
                              if threshold else []),
        "events_scored": int((source or {}).get("position", len(latest))),
        # Why each seed: the neighbours its initiator attended to. Layer 1 only; the global readout is network-wide.
        "explanation": explanation or [],
    }


def caveats_for(threshold: "dict | None") -> list[str]:
    """What the panel must not let a reader assume."""
    out = [
        "this is a replay of a recorded day, not this machine's traffic: no live runner feeds Block 10 yet",
        "S[t+k] means k imagined event steps on each seeded rollout, not k seconds or the next k actual network events: the rollout assumes a one-second internal gap "
        "but does not predict an arrival time; a predicted link has not been observed or confirmed as an incident",
    ]
    if threshold is None:
        out.append("this checkpoint is uncalibrated, so nothing is alerted: run models.world_model.calibration")
        return out
    out.append(f"alerts when {threshold['rule']}, a {threshold['budget']:g} false-positive budget calibrated on "
               f"{threshold['calibrated_on']}")
    if threshold.get("recall", 0) == 0:
        out.append("at this threshold the model caught none of the test attacks: it is not a working detector yet, "
                   "see docs/dev/guides/world-model.md, 'Block 10 calibration'")
    if threshold["score"] == TARGET:
        out.append("the served score is the ranking head's probability that a link's endpoint is the node the "
                   "campaign reaches next")
    elif threshold["direction"] < 0:
        out.append("low surprise alerts: a flood repeats one link and is the most predictable traffic there is, so "
                   "the model flags links that are unusually regular, not unusual")
    return out


class Stream:
    """A recorded day, replayed through the model a few chunks per tick, with memory kept between ticks.

    Input:  checkpoint, latent directories, node index, warm-up events, events per tick, rollout depth and seeds,
            device
    Output: object; `tick()` advances and returns a fresh payload

    Starts again from the first event when the day runs out, rather than freezing on the last state.
    """

    def __init__(self, checkpoint: Path, latents: list[Path], *, node_index: "Path | None", warmup: int,
                 advance: int, rollout_steps: int, rollout_seeds: int, device: "str | None"):
        self.checkpoint, self.run = checkpoint, receive(latents)
        self.names, self.threshold = node_names(node_index), served_threshold(checkpoint)
        self.warmup, self.advance, self.device = warmup, advance, device
        self.rollout_steps, self.rollout_seeds = rollout_steps, rollout_seeds
        self.total = len(self.run)
        self.replay = self._start()

    def _start(self) -> Replay:
        # Every event in stream order, as a sensor would see it; attention rows are not needed for the panel.
        replay = Replay(self.run, self.checkpoint, split=None, device=self.device, attention=False, keep=2_000)
        replay.advance(self.warmup)
        return replay

    def tick(self) -> dict:
        self.replay.advance(self.advance)
        if self.replay.exhausted:
            self.replay = self._start()
        rollouts = self.replay.rollout(self.rollout_steps, self.rollout_seeds)
        day = self.replay.day
        source = {"mode": "replay", "day": day.day if day is not None else "", "position": self.replay.scored,
                  "total": self.total, "t": float(self.replay.rows["t"][-1]) if self.replay.rows["t"] else None}
        if not rollouts:
            return {"status": "NOT_CONNECTED", "reason": "the model produced no rollout for this slice",
                    "current_state": "S[t]", "future_states": [], "predicted_stage": STAGE_UNAVAILABLE,
                    "source": source}
        explanation = seed_explanations(self.replay, {r["seed_id"] for r in rollouts}, self.names)
        return forecast_payload(rollouts, self.replay.rows, caveats=caveats_for(self.threshold), names=self.names,
                                threshold=self.threshold, source=source, explanation=explanation)


class Handler(BaseHTTPRequestHandler):
    """Answers GET with the latest payload."""

    payload: dict = {}
    mode_controller = None

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/threshold-mode" and self.mode_controller is not None:
            ready = self.mode_controller.live_calibration is not None and self.mode_controller.live_calibration.status("world")["ready"]
            body = json.dumps(self.mode_controller.threshold_mode.status(ready)).encode()
        else:
            body = json.dumps(with_live_age(self.payload)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/threshold-mode" or self.mode_controller is None:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 128:
                raise ValueError("invalid request size")
            mode = json.loads(self.rfile.read(length))["mode"]
            ready = self.mode_controller.live_calibration is not None and self.mode_controller.live_calibration.status("world")["ready"]
            result = self.mode_controller.threshold_mode.set(mode, ready)
            status = 200
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            result, status = {"error": str(error)}, 409
        body = json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        """Silent: the dashboard polls this, and one access line per poll buries the startup output."""


def with_live_age(payload: dict, now: float | None = None) -> dict:
    """Keep the live state age truthful between expensive forecast cycles."""
    source = payload.get("source") or {}
    if source.get("mode") != "live" or source.get("state_as_of") is None:
        return payload
    age = max(0.0, (time.time() if now is None else now) - float(source["state_as_of"]))
    return {**payload, "source": {**source, "lag_seconds": round(age, 1)}}


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--load", type=Path, required=True, help="a trained Block 10 checkpoint")
    parser.add_argument("--latents", type=Path, nargs="+", required=True,
                        help="one directory per day, each holding event_latents.parquet")
    parser.add_argument("--port", type=int, default=8900)
    parser.add_argument("--limit", type=int, default=4000,
                        help="events to score before serving, so memory is warm when the first forecast appears")
    parser.add_argument("--advance", type=int, default=256,
                        help="events the replay moves forward per tick; the forecast follows the input")
    parser.add_argument("--refresh", type=float, default=3.0, help="seconds between ticks")
    parser.add_argument("--rollout-steps", type=int, default=6)
    parser.add_argument("--rollout-seeds", type=int, default=6,
                        help="how many distinct hosts to roll forward; one seed predicts one link, not a graph")
    parser.add_argument("--node-index", type=Path, default=None,
                        help="node_index.parquet from ingest, so hosts are named by IP rather than node id")
    parser.add_argument("--device", default=None)
    args = parser.parse_args(argv)

    print(f"warming up on {args.limit:,} events with {args.load} ...", flush=True)
    stream = Stream(args.load, args.latents, node_index=args.node_index, warmup=args.limit, advance=args.advance,
                    rollout_steps=args.rollout_steps, rollout_seeds=args.rollout_seeds, device=args.device)
    Handler.payload = stream.tick()
    print(f"ready: {Handler.payload.get('status')}, threshold "
          f"{'calibrated' if stream.threshold else 'ABSENT -- no alerts'}; advancing {args.advance} events every "
          f"{args.refresh:g}s", flush=True)

    def run() -> None:
        while True:
            started = time.monotonic()
            try:
                Handler.payload = stream.tick()
            except Exception as error:                      # a failed tick must not take the service down
                print(f"tick failed, serving the previous payload: {error}", flush=True)
            time.sleep(max(0.0, args.refresh - (time.monotonic() - started)))

    threading.Thread(target=run, daemon=True).start()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    print(f"world model service on http://127.0.0.1:{args.port}", flush=True)
    print(f"point the dashboard at it:  netwatch dashboard --forecast-url http://127.0.0.1:{args.port}/forecast",
          flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
