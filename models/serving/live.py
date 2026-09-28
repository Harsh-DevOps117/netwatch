"""The live runner: capture files in, a world-model forecast out, over HTTP.

Run (as the repo's owner; the capture itself is dumpcap's, started by the launcher as root):
    uv run python -m models.serving.live --input ~/netwatch-data/live/in --work ~/netwatch-data/live/work \
        --block7 <v1 flow encoder .pt> --block8 <context encoder best.pt> --block9 <compressor best.pt> \
        --block10 <world model best.pt> --port 8901

Every stage already exists as a function with explicit paths; this composes them, holding the models in memory. Each
time a capture file finishes, one cycle runs over a window of the latest files:

    packets, once per file        the packet parser (tshark) runs on each capture file once, when it closes
    flows, once per packet        one CICFlowMeter process (tools/live/StreamMeter.java) reads every file since the
                                  service started as one continuous capture and writes each flow the moment it is
                                  final -- the rows a whole-capture run writes (tools/live/stream_check.py)
    assemble the window           the cached packets and complete flows of the window's files, and the packet map over
                                  them, laid out exactly as a whole-window ingest writes them
    Blocks 7-9                    side features, flow records, Block 7, Blocks 8 + 9 -> latents
    Block 10                      streamed to the cutoff -> rollout -> the Forecast payload

**Only complete flows, so a fixed delay.** CICFlowMeter writes out every still-open flow when its input ends, as if it
had finished. Run per 30 s file, that cut every flow crossing a file boundary in two: 50-80% of live TCP flows began
without a SYN, against 7-8% in training. Merging the window removes the file boundaries; the hold removes the flows
still open at the window's end. CICFlowMeter closes any flow at most 120 s after it starts (its flow timeout), so a
flow that started 120 s before the newest packet is final -- the same flow, with the same record, that the offline
ingest of a whole day produces. The world model's state is therefore as of `newest packet - hold`, and the flow records
and 20-packet summaries reach Block 8 at their own availability times up to that moment, exactly as in training.

**Why a rolling window, rebuilt each cycle.** Node ids, neighbourhoods and Block 8's link memory are built per event
stream, and Block 10's memory resets per stream (node ids are not stable across streams). Rebuilding the last few minutes
each cycle keeps every stage on the contract it was trained on. Ingest is incremental: every packet goes through tshark
and CICFlowMeter once, so a cycle's ingest cost follows the new traffic rather than the window.

**Unlabelled.** Live traffic has no attack schedule, so ingest runs with no label matcher (every flow "Benign") and the
split column is set to test. Labels were never model inputs, so this changes nothing the models read.

The same timeout bounds the other end: a flow starting in the window's first 120 s may have begun before the window and
be seen only in part, so those are left out too. With 30 s files and 16 per window, the state covers about 4 minutes.

**Honest limits.** The state lags the wire by the hold plus up to one capture file plus the cycle's processing,
about 2.5-3 minutes. A connection longer than the window (long-lived HTTPS) is still cut into 120 s pieces at a different
phase than a whole-day ingest would cut it; both sides see such pieces start without a SYN. The forecast is only as
good as the checkpoint it serves -- see docs/dev/guides/world-model.md.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import threading
import time
import traceback
from http.server import HTTPServer
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
import torch

from ingest.build.events import DEFAULT_K_PACKETS, build_event_stream
from ingest.build.join import build_edges, build_flow_packet_map
from ingest.sources.flows import csv_to_parquet, find_flow_csvs, run_cicflowmeter
from ingest.sources.packets import pcap_to_parquet
from models.compressor.autoencoder import EventAutoencoder
from models.compressor.latents import export_latents as export_event_latents
from models.compressor.latents import frozen_context_encoder
from models.context_encoder.data import load_day
from models.context_encoder.features import export_side_features
from models.context_encoder.records import export_flow_records
from models.flow_encoder.encoder import VARIANT, FlowAutoencoder
from models.flow_encoder.export import export_latents as export_flow_latents
from models.explanation.world_model import seed_explanations
from models.world_model.inference import Replay
from models.world_model.reception import SPLIT_TEST, receive
from models.world_model.service import Handler, STAGE_UNAVAILABLE, forecast_payload, node_names, served_threshold

DAY = "live"                   # the window's stream name; every stage keys its folders on it
# CICFlowMeter's flow timeout (tools/CICFlowMeter .../ifm/Cmd.java: flowTimeout = 120000000 us). A flow that started this
# long before the newest packet has been closed; change it only together with the meter's own setting.
HOLD_S = 120.0
CURRENT = Path(__file__).resolve().parents[2] / "artifacts" / "current" / "serving.json"   # tools/promote.py writes it
TAG = "lag"                    # models.serving.registry: this runner is the `lag` path (complete flows, a lagging state)


def local_addresses() -> list[str]:
    """This machine's own addresses, so the panel can mark it the way the topology map does. Empty if unknown."""
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return out.split()
CAPTURES = ("*.pcap", "*.pcapng")


def load_block7(path: Path, device: str) -> tuple[FlowAutoencoder, dict, str]:
    """The flow encoder with the normalisation stats it was fitted behind -- a v1 checkpoint, or it refuses.

    A checkpoint without stats would re-derive the input scale from whatever it is shown, and every embedding
    downstream would silently move.
    """
    saved = torch.load(path, map_location=device, weights_only=False)
    if not (isinstance(saved, dict) and saved.get("format") in ("flow-encoder-v1", "block7-encoder-v1")):
        raise ValueError(f"{path}: not a v1 flow encoder checkpoint with its normalisation stats")
    stats, side = saved["stats"], saved.get("side", "split")
    model = FlowAutoencoder(VARIANT, k=DEFAULT_K_PACKETS, predict=True,
                            packet_encoder=saved.get("packet_encoder", "gnn"),
                            a_width=len(np.asarray(stats["a"][0]).ravel()), split=side == "split").to(device)
    model.load_state_dict(saved["model"])
    return model.eval().requires_grad_(False), stats, side


def load_block9(path: Path, width: int, device: str) -> EventAutoencoder:
    state = torch.load(path, map_location=device, weights_only=False)
    ae = EventAutoencoder(state["encoder"], d_s=width, d_z=state["d_z"], target=width).to(device)
    ae.load_state_dict(state["model"])
    return ae.eval().requires_grad_(False)


class Chain:
    """Capture files to Block 10 latents, with every model loaded once."""

    def __init__(self, work: Path, *, block7: Path, block8: Path, block9: Path, cicflowmeter: Path,
                 device: "str | None" = None, budget_ms: float = 10.0):
        self.work, self.cicflowmeter, self.budget_ms = Path(work), Path(cicflowmeter), budget_ms
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.block7, self.stats7, self.side7 = load_block7(block7, self.device)
        self.block8, self.arm = frozen_context_encoder(block8, self.device)
        self.block9 = load_block9(block9, self.block8.out[-1].out_features, self.device)
        self.reads = set(self.block8.late)        # the late messages this Block 8 was trained with: flow, record

    def ingest(self, pcap: Path, out: Path) -> "Path | None":
        """One capture through ingest, unlabelled. Output: its folder, or None if it held no packets or no flows."""
        out.mkdir(parents=True, exist_ok=True)
        if not pcap_to_parquet(pcap, out / "packets.parquet", label_matcher=None):
            return None
        run_cicflowmeter(self.cicflowmeter, pcap, out / "csv")
        try:
            csv_to_parquet(find_flow_csvs(out / "csv", pcap), out / "flows.parquet", day=DAY, matcher=None)
        except RuntimeError:                      # CICFlowMeter produced no flow at all
            return None
        build_edges(out / "flows.parquet", out / "edges.parquet")
        build_flow_packet_map(out / "flows.parquet", out / "packets.parquet", out / "flow_packet_map.parquet")
        return out

    def build(self, folder: Path, cycle: Path, start: float, cutoff: float) -> int:
        """Event stream to latents for one ingested window, from the flows that started in [start, cutoff].

        Output: events built (0 means no flow is complete yet, and nothing was built)
        """
        processed, events = cycle / "processed", cycle / "events"
        features, embeddings, latents = cycle / "context_features", cycle / "flow_embeddings", cycle / "latents"
        if not complete_flows(folder, start, cutoff):
            return 0
        (processed / DAY).mkdir(parents=True, exist_ok=True)
        (processed / DAY / folder.name).symlink_to(folder.resolve(), target_is_directory=True)
        n = build_event_stream(processed / DAY, events / DAY)
        export_side_features(DAY, events, processed, features / DAY, self.budget_ms)
        if "record" in self.reads:
            export_flow_records(DAY, events, processed, features)
        export_flow_latents(self.block7, self.stats7, day=DAY, events_root=events, processed_root=processed,
                            out_dir=embeddings / self.side7 / DAY, k=DEFAULT_K_PACKETS, budget_ms=self.budget_ms,
                            side=self.side7, device=self.device)
        # Live traffic has no split; every event is scored as test would be. Labels are evaluation-only either way.
        data = load_day(DAY, self.arm, events_root=events, features_root=features, embeddings_root=embeddings,
                        split=np.full(n, SPLIT_TEST, dtype=np.int8), flows="flow" in self.reads,
                        records="record" in self.reads)
        export_event_latents(self.block8, self.block9, data, self.arm, latents / DAY, DAY, device=self.device,
                             budget_ms=self.budget_ms)
        (cycle / "READY").write_text(json.dumps({"events": int(n), "cutoff": cutoff}))
        return n


def complete_flows(folder: Path, start: float, cutoff: float) -> int:
    """Keep only the flows that started in [start, cutoff], rewriting flows.parquet in place. Output: flows kept.

    Before `start` (the window's first packet + hold) a flow may have begun before the window and be seen only in part;
    after `cutoff` (its newest packet - hold) it may still be open. Filtering here, before the event stream is built,
    lets ingest number events, measure the gaps between them and assign node ids exactly as it does for a training day.
    A flow's start is its first packet, as the event stream defines it; one with no packets falls back to the meter's
    second-resolution timestamp, as the event stream does.
    """
    table = pq.read_table(folder / "flows.parquet")                # filtered as Arrow: the schema stays exactly as written
    flows = table.select(["flow_uid", "Timestamp"]).to_pandas()
    mapping = pq.read_table(folder / "flow_packet_map.parquet", columns=["frame_no", "flow_uid"]).to_pandas()
    packets = pq.read_table(folder / "packets.parquet", columns=["frame_no", "timestamp"]).to_pandas()
    first = mapping.merge(packets, on="frame_no").groupby("flow_uid")["timestamp"].min()
    fallback = pd.to_datetime(flows["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
    began = flows["flow_uid"].map(first).fillna((fallback - pd.Timestamp("1970-01-01")).dt.total_seconds())
    keep = ((began >= start) & (began <= cutoff)).to_numpy()
    pq.write_table(table.filter(keep), folder / "flows.parquet", compression="zstd")
    return int(keep.sum())


class FlowStream:
    """One CICFlowMeter for the whole session (tools/live/StreamMeter.java), fed every capture file in order.

    Output: rows() hands back the flows that became final since the last call; swept is the capture time up to which
    every flow is final (a flow that started before swept - HOLD_S has been written).

    Capture files reach it through a named pipe as one continuous capture, so a flow is never cut at a file boundary and
    long connections are split exactly where a single CICFlowMeter run over the whole capture splits them. The meter's
    rows equal that run's rows (checked by tools/live/stream_check.py); only their timing differs.
    """

    SOURCE = Path(__file__).resolve().parents[2] / "tools" / "live" / "StreamMeter.java"

    def __init__(self, cicflowmeter: Path, folder: Path):
        self.cic, self.folder = Path(cicflowmeter).resolve(), Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.fifo = self.folder / "stream.pcap"
        if self.fifo.exists():
            self.fifo.unlink()
        os.mkfifo(self.fifo)
        classes = self.compile()
        self.proc = subprocess.Popen(
            ["java", f"-Djava.library.path={self.cic / 'jnetpcap' / 'linux' / 'jnetpcap-1.4.r1425'}",
             "-cp", f"{self.classpath()}:{classes}", "StreamMeter", str(self.fifo), "-"],
            cwd=self.cic, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.pipe = open(self.fifo, "wb")             # returns once the meter has opened its end
        self.header: "bytes | None" = None
        self.lock, self.pending, self.ready, self.swept = threading.Lock(), [], [], float("-inf")
        self.columns = None
        threading.Thread(target=self._read, daemon=True).start()

    def classpath(self) -> str:
        """CICFlowMeter's runtime classpath, asked of its Gradle build once and cached beside the meter."""
        cache = self.folder / "classpath.txt"
        if cache.exists() and cache.stat().st_mtime >= (self.cic / "build.gradle").stat().st_mtime:
            return cache.read_text().strip()
        init = self.folder / "classpath.gradle"
        init.write_text('allprojects { afterEvaluate { p -> p.tasks.create("netwatchClasspath") { doLast { '
                        'println "NETWATCH_CP=" + p.sourceSets.main.runtimeClasspath.asPath } } } }\n')
        out = subprocess.run(["./gradlew", "-q", "--offline", "-PpcapDir=-", "-PoutputDir=-", "-I", str(init),
                              "compileJava", "netwatchClasspath"], cwd=self.cic, capture_output=True, text=True, check=True)
        path = next(line[len("NETWATCH_CP="):] for line in out.stdout.splitlines() if line.startswith("NETWATCH_CP="))
        cache.write_text(path + "\n")
        return path

    def compile(self) -> Path:
        """StreamMeter compiled against CICFlowMeter's classes, again only when its source changed."""
        classes = self.folder / "classes"
        built = classes / "StreamMeter.class"
        if not built.exists() or built.stat().st_mtime < self.SOURCE.stat().st_mtime:
            classes.mkdir(parents=True, exist_ok=True)
            subprocess.run(["javac", "-cp", self.classpath(), "-d", str(classes), str(self.SOURCE)], check=True,
                           capture_output=True)
        return classes

    def _read(self) -> None:
        """Rows and sweep markers, in order: the rows before a marker are released together with it."""
        for line in self.proc.stdout:
            line = line.rstrip("\n")
            if line.startswith("NETWATCH_SWEPT "):
                with self.lock:
                    self.ready.extend(self.pending)
                    self.pending = []
                    self.swept = int(line.split()[1]) / 1e6
            elif line.startswith("NETWATCH_"):
                continue
            elif self.columns is None:
                self.columns = line
            else:
                self.pending.append(line)

    def feed(self, pcap: Path) -> bool:
        """Append one finished capture file to the stream. Output: False if it is not an Ethernet capture."""
        data = pcap.read_bytes()
        if data[:4] != b"\xd4\xc3\xb2\xa1":                  # pcapng, nanosecond or big-endian pcap: normalise
            converted = self.folder / "convert.pcap"
            subprocess.run(["editcap", "-F", "pcap", str(pcap), str(converted)], check=True, capture_output=True)
            data = converted.read_bytes()
            converted.unlink()
        if int.from_bytes(data[20:24], "little") != 1:           # DLT_EN10MB: CICFlowMeter decodes from Ethernet
            return False
        if self.header is None:
            self.header = data[:24]
            self.pipe.write(data)
        else:
            self.pipe.write(data[24:])
        self.pipe.flush()
        return True

    def wait(self, until: float, timeout: float = 60.0) -> None:
        """Block until the meter has swept up to `until` (capture time), or `timeout` seconds pass."""
        deadline = time.monotonic() + timeout
        while self.swept < until and time.monotonic() < deadline and self.proc.poll() is None:
            time.sleep(0.05)

    def rows(self) -> "tuple[str | None, list[str]]":
        """The header and every row final since the last call."""
        with self.lock:
            rows, self.ready = self.ready, []
        return self.columns, rows

    def close(self) -> None:
        self.pipe.close()
        self.proc.wait(timeout=30)


class Live:
    """Watches the capture folder, runs the chain, and keeps the Forecast payload current."""

    def __init__(self, chain: Chain, inbox: Path, *, block10: Path, window: int, idle: float, rollout_steps: int,
                 rollout_seeds: int, hold: float = HOLD_S):
        self.chain, self.inbox, self.block10 = chain, Path(inbox), Path(block10)
        self.window, self.idle, self.hold = window, idle, hold
        self.rollout_steps, self.rollout_seeds = rollout_steps, rollout_seeds
        self.threshold = served_threshold(self.block10)
        self.pcaps: list[Path] = []
        self.seen: set = set()
        self.cycles = 0
        self.packets: dict = {}          # capture file name -> its parsed packets, id offset and time span (None: empty)
        self.next_frame = 0              # packet ids stay unique across files: file offset + its own frame number
        self.next_flow = 0               # flow ids stay unique across slices
        self.slabs: list = []            # (latest flow end, the flows finished in one cycle), oldest first
        self.stream = FlowStream(chain.cicflowmeter, chain.work / "stream")
        self.status = {"status": "NOT_CONNECTED", "reason": "live runner started; waiting for the first finished "
                       "capture file", "source": {"mode": "live"}}

    def finished(self) -> list[Path]:
        """Capture files that are done being written: not the newest, or idle for `idle` seconds."""
        files = sorted((p for pattern in CAPTURES for p in self.inbox.glob(pattern)), key=lambda p: p.stat().st_mtime)
        now = time.time()
        return [p for i, p in enumerate(files)
                if p.name not in self.seen and (i < len(files) - 1 or now - p.stat().st_mtime > self.idle)]

    def step(self) -> bool:
        """When a capture file finishes, rebuild the window and the forecast. Output: whether anything new arrived."""
        new = self.finished()
        if not new:
            return False
        self.seen.update(p.name for p in new)
        # The ring buffer deletes its oldest files; a window only holds files that still exist.
        self.pcaps = [p for p in self.pcaps + new if p.exists()][-self.window:]
        self.cycles += 1
        cycle = self.chain.work / "cycles" / f"{self.cycles:06d}"
        cycle.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        for pcap in new:
            self.parse(pcap)
            if self.packets.get(pcap.name) and self.stream.feed(pcap):
                # The meter sweeps once per second of capture time, so it has caught up within a second of the end.
                self.stream.wait(self.packets[pcap.name]["last"] - 1.0)
        for name in [n for n in self.packets if n not in {p.name for p in self.pcaps}]:   # left the window
            shutil.rmtree(self.chain.work / "files" / Path(name).stem, ignore_errors=True)
            del self.packets[name]
        files = [p for p in self.pcaps if self.packets.get(p.name)]
        if not files:
            self.status = {**self.status, "reason": f"{len(self.pcaps)} capture file(s) in the window, no packets yet"}
            return True
        newest = max(self.packets[p.name]["last"] for p in files)
        start = min(self.packets[p.name]["first"] for p in files) + self.hold
        # Every flow that started before swept - hold is final and has been written (CICFlowMeter's flow timeout).
        cutoff = min(newest, self.stream.swept) - self.hold
        self.take(cycle / "new")
        self.slabs = [s for s in self.slabs if s[0] >= start - self.hold]   # flows still inside the window
        events = 0
        if self.slabs and cutoff > start:
            folder = self.assemble(files, cycle / "capture" / "window")
            events = self.chain.build(folder, cycle, start, cutoff)
        if not events:
            self.status = {**self.status, "reason": f"no complete flow yet: a flow is used once {self.hold:.0f} s of "
                           f"capture follow its start and {self.hold:.0f} s precede it (CICFlowMeter's flow timeout), so "
                           f"the window needs more than {2 * self.hold:.0f} s of capture"}
        else:
            self.status = self.forecast(cycle, time.monotonic() - started, cutoff, newest)
        for old in sorted((self.chain.work / "cycles").iterdir())[:-2]:   # keep the last two for inspection
            shutil.rmtree(old, ignore_errors=True)
        return True

    def parse(self, pcap: Path) -> None:
        """The packet parser on one finished capture file, once. Its packets keep ids unique across files."""
        out = self.chain.work / "files" / pcap.stem
        out.mkdir(parents=True, exist_ok=True)
        entry = None
        if pcap_to_parquet(pcap, out / "packets.parquet", label_matcher=None):
            table = pq.read_table(out / "packets.parquet", columns=["frame_no", "timestamp"])
            times = table.column("timestamp").to_numpy()
            entry = {"path": out / "packets.parquet", "base": self.next_frame,
                     "first": float(times.min()), "last": float(times.max())}
            self.next_frame += int(pc.max(table.column("frame_no")).as_py()) + 1
        self.packets[pcap.name] = entry

    def window_packets(self, files: "list[Path]") -> pa.Table:
        """The cached packets of these files as one table, frame numbers offset so each packet id is unique."""
        tables = []
        for pcap in files:
            entry = self.packets[pcap.name]
            table = pq.read_table(entry["path"])
            at = table.schema.get_field_index("frame_no")
            tables.append(table.set_column(at, "frame_no", pc.add(table.column("frame_no"), entry["base"])))
        return pa.concat_tables(tables)

    def take(self, folder: Path) -> None:
        """The flows the meter finished since the last cycle, kept until they end before the window starts."""
        columns, rows = self.stream.rows()
        if not rows:
            return
        (folder / "csv").mkdir(parents=True, exist_ok=True)
        (folder / "csv" / "window.pcap_Flow.csv").write_text(columns + "\n" + "\n".join(rows) + "\n")
        try:
            csv_to_parquet(find_flow_csvs(folder / "csv"), folder / "flows.parquet", day=DAY, matcher=None)
        except RuntimeError:
            return
        flows = pq.read_table(folder / "flows.parquet")
        # Flow ids are per conversion; renumber so they stay unique across cycles.
        flows = flows.set_column(flows.schema.get_field_index("flow_uid"), "flow_uid",
                                 pa.array([f"window#{self.next_flow + i}" for i in range(len(flows))]))
        self.next_flow += len(flows)
        span = flows.select(["Timestamp", "Flow Duration"]).to_pandas()
        began = pd.to_datetime(span["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
        ends = (began - pd.Timestamp("1970-01-01")).dt.total_seconds() + span["Flow Duration"].fillna(0) / 1e6
        self.slabs.append((float(ends.max()) if len(ends) else float("-inf"), flows))

    def assemble(self, files: "list[Path]", folder: Path) -> Path:
        """The window's capture folder, laid out as Chain.ingest writes it, from cached packets and the slices' flows."""
        folder.mkdir(parents=True, exist_ok=True)
        pq.write_table(self.window_packets(files), folder / "packets.parquet", compression="zstd")
        pq.write_table(pa.concat_tables([s[1] for s in self.slabs], promote_options="default"),
                       folder / "flows.parquet", compression="zstd")
        # The packet map is built over the whole window, as a whole-window ingest builds it: a packet goes to the
        # latest flow of its connection that started before it, so every flow of a connection has to be present.
        build_flow_packet_map(folder / "flows.parquet", folder / "packets.parquet", folder / "flow_packet_map.parquet")
        build_edges(folder / "flows.parquet", folder / "edges.parquet")
        return folder

    def forecast(self, cycle: Path, build_seconds: float, cutoff: float, newest: float) -> dict:
        run = receive([cycle / "latents" / DAY])
        replay = Replay(run, self.block10, split=None, device=self.chain.device, attention=False)
        replay.advance(len(run))
        replay.finish()
        rollouts = replay.rollout(self.rollout_steps, self.rollout_seeds)
        last_t = float(replay.rows["t"][-1]) if replay.rows["t"] else None
        source = {"mode": "live", "tag": TAG, "day": "this machine", "position": replay.scored, "total": len(run),
                  "t": last_t, "captures": [p.name for p in self.pcaps], "cycle": self.cycles,
                  "local_ips": local_addresses(),
                  "build_seconds": round(build_seconds, 1),
                  # The state is as of the cutoff: every flow in it had started by then and has since closed.
                  "state_as_of": cutoff, "newest_packet": newest, "hold_seconds": self.hold,
                  "lag_seconds": round(time.time() - cutoff, 1)}
        if not rollouts:
            return {"status": "NOT_CONNECTED", "reason": "the window has events but too few for a rollout yet",
                    "current_state": "S[t]", "future_states": [], "predicted_stage": STAGE_UNAVAILABLE,
                    "source": source}
        caveats = [
            f"live: the last {len(self.pcaps)} capture file(s) of this machine, rebuilt every cycle; the state is as of "
            f"{source['lag_seconds']:.0f} s ago",
            f"only complete flows: those that started at least {self.hold:.0f} s before the newest captured packet "
            f"(CICFlowMeter closes every flow within that) and {self.hold:.0f} s after the window's first, so none was "
            "open before the window; the state always lags the wire by the hold or more",
            "each step's target is the ranking head's choice; a predicted link has not happened",
        ]
        if self.threshold and self.threshold.get("recall", 1) == 0:
            caveats.append("the served checkpoint caught none of its test attacks at this threshold; see "
                           "docs/dev/guides/world-model.md, 'Block 10 calibration'")
        names = node_names(cycle / "events" / DAY / "node_index.parquet")
        return forecast_payload(rollouts, replay.rows, caveats=caveats, names=names, threshold=self.threshold,
                                source=source,
                                explanation=seed_explanations(replay, {r["seed_id"] for r in rollouts}, names))


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--input", type=Path, required=True, help="folder the capture ring buffer writes into")
    parser.add_argument("--work", type=Path, required=True, help="where ingest outputs and cycles are kept")
    parser.add_argument("--registry", type=Path, default=None,
                        help="serving.json (models.serving.registry): serve the checkpoints of the `lag` tag, the one "
                             "this runner implements. Default: artifacts/current/serving.json, the latest promoted run "
                             "(tools/promote.py). Or name the four checkpoints below")
    parser.add_argument("--block7", type=Path, default=None, help="v1 flow encoder checkpoint (with its stats)")
    parser.add_argument("--block8", type=Path, default=None)
    parser.add_argument("--block9", type=Path, default=None)
    parser.add_argument("--block10", type=Path, default=None)
    parser.add_argument("--cicflowmeter", type=Path, default=Path("tools/CICFlowMeter"))
    parser.add_argument("--window", type=int, default=16,
                        help="capture files per window; the state covers the window less 2 x --hold")
    parser.add_argument("--hold", type=float, default=HOLD_S,
                        help="use only flows that started this many seconds before the newest packet; must be at least "
                             "CICFlowMeter's flow timeout (120 s) for every flow in the state to be complete")
    parser.add_argument("--idle", type=float, default=90.0,
                        help="seconds without writes after which the newest file counts as finished")
    parser.add_argument("--poll", type=float, default=3.0)
    parser.add_argument("--rollout-steps", type=int, default=6)
    parser.add_argument("--rollout-seeds", type=int, default=4)
    parser.add_argument("--port", type=int, default=8901)
    parser.add_argument("--device", default=None)
    parser.add_argument("--once", action="store_true", help="process what is there, print the payload, and exit")
    args = parser.parse_args(argv)
    if args.registry is None and None in (args.block7, args.block8, args.block9, args.block10) and CURRENT.exists():
        args.registry = CURRENT
    if args.registry is not None:
        from models.serving.registry import resolve
        models = resolve(args.registry, TAG)
        args.block7, args.block8, args.block9, args.block10 = (models[r] for r in ("block7", "block8", "block9", "block10"))
    if None in (args.block7, args.block8, args.block9, args.block10):
        parser.error("give --registry, or all of --block7 --block8 --block9 --block10")

    args.input.mkdir(parents=True, exist_ok=True)
    chain = Chain(args.work, block7=args.block7, block8=args.block8, block9=args.block9,
                  cicflowmeter=args.cicflowmeter, device=args.device)
    live = Live(chain, args.input, block10=args.block10, window=args.window, idle=args.idle,
                rollout_steps=args.rollout_steps, rollout_seeds=args.rollout_seeds, hold=args.hold)
    print(f"live runner: watching {args.input}, models on {chain.device}", flush=True)
    if args.once:
        live.idle = 0.0
        live.step()
        payload = live.status
        print(json.dumps({k: payload.get(k) for k in ("status", "reason", "source", "events_scored")}, default=str))
        print(f"predicted links: {len(payload.get('predicted_edges', []))}, observed links: "
              f"{len((payload.get('observed') or {}).get('edges', []))}")
        return 0 if payload.get("status") == "CONNECTED" else 1

    Handler.payload = live.status

    def loop() -> None:
        while True:
            try:
                if live.step():
                    Handler.payload = live.status
                    print(f"cycle {live.cycles}: {live.status.get('status')} "
                          f"{live.status.get('source', {}).get('build_seconds', '')}s", flush=True)
                else:
                    Handler.payload = live.status
            except Exception:                     # a failed cycle must not take the sensor down
                traceback.print_exc()
            time.sleep(args.poll)

    threading.Thread(target=loop, daemon=True).start()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    print(f"live forecast on http://127.0.0.1:{args.port}/forecast", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
