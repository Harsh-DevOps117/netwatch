"""Numerical and state regressions for flood-throughput optimizations."""
import copy
import contextlib
import io
import tempfile
import unittest
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import torch

from ingest.build.events import AGG_COLUMNS
from models.context_encoder.model import ContextEncoder, LinkMemory
from models.data.inputs import PACKET_FEATURES
from models.data.prefix import _aggregates
from models.flow_encoder.encoder import FlowAutoencoder
from models.flow_encoder.train import embed
from models.serving.detect_live import Detector, Flow, K, StreamingContext, flow_embeddings
from models.serving.graph import NodeRegistry
from models.serving.emitter import AlertEmitter
from models.serving.test_live_input_contract import packet


class DetectionPerformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.threads = torch.get_num_threads()
        torch.set_num_threads(1)

    @classmethod
    def tearDownClass(cls):
        torch.set_num_threads(cls.threads)

    def test_encoder_only_matches_autoencoder_embeddings(self):
        torch.manual_seed(7)
        model = FlowAutoencoder(a_width=len(AGG_COLUMNS), predict=True).eval()
        rng = np.random.default_rng(7)
        data = {"a": rng.normal(size=(17, len(AGG_COLUMNS))).astype(np.float32),
                "a_future": np.zeros((17, len(AGG_COLUMNS)), np.float32),
                "pkt": rng.normal(size=(17, K, len(PACKET_FEATURES))).astype(np.float32),
                "dt": rng.uniform(0, 1, (17, K)).astype(np.float32),
                "n_pkt": np.arange(17, dtype=np.int16) % K + 1,
                "attack": np.zeros(17, bool)}
        with torch.no_grad():
            expected, _ = embed(model, data, np.arange(17), batch_size=8)
        actual = flow_embeddings(model, data, "cpu", batch_size=8)
        np.testing.assert_array_equal(actual, expected)

    def test_batched_summaries_match_individual_flows_and_keep_pending(self):
        flows = []
        for i in range(519):
            p = packet("192.0.2.10", "198.51.100.5", 1024 + i, 443, 100 + i * .1)
            flow = Flow(i, p, round(p["timestamp"] * 1e6),
                        (p["src_ip"], p["dst_ip"], p["src_port"], p["dst_port"], 6))
            for j in range(1, 1 + i % K):
                flow.add({**p, "timestamp": p["timestamp"] + j * .02})
            flows.append(flow)
        detector = Detector.__new__(Detector)
        detector.tracker = SimpleNamespace(summaries=flows, clock=200)
        detector.pending_summaries = {f.id: (f.id, f.t + .01) for f in flows[:-1]}
        detector.log, detector.oracle = [], None
        calls = []
        detector.context = SimpleNamespace(queue_summary=lambda *args: calls.append(args))
        expected = []
        for flow in flows[:-1]:
            pkt, dt, count = flow.arrays()
            expected.append(_aggregates(pkt[None], dt[None], (np.arange(K) < count)[None])[0])
        detector._summaries()
        np.testing.assert_array_equal(np.stack([r["summary"] for r in detector.log]), np.stack(expected))
        self.assertEqual(detector.tracker.summaries, [flows[-1]])
        self.assertEqual(detector.pending_summaries, {})
        self.assertEqual(len(calls), 1)
        self.assertTrue(np.all(calls[0][2] > np.array([flows[i].t + .01 for i in calls[0][0]])))

    def test_attention_limit_keeps_same_context_and_last_rows(self):
        torch.manual_seed(8)
        model = ContextEncoder("split", flow_messages=True).eval().requires_grad_(False)
        full = StreamingContext(model, capacity=32, batch=16, ring=256)
        limited = StreamingContext(copy.deepcopy(model), capacity=32, batch=16, ring=256)
        rng = np.random.default_rng(8)
        n = 39
        inputs = {"h_split": rng.normal(size=(n, 32)).astype(np.float32),
                  **{name: np.zeros(n, np.float32) for name in
                     ("dt_src", "dt_dst", "port_delta", "dst_port_new", "reversed")}}
        sender, receiver = np.arange(n) % 7, np.arange(n) % 5 + 7
        times = np.arange(n) * .01
        s, links, rows = full.encode(inputs, sender, receiver, times)
        limited_s, limited_links, last = limited.encode(inputs, sender, receiver, times, explanation_limit=8)
        np.testing.assert_array_equal(s, limited_s)
        np.testing.assert_array_equal(links, limited_links)
        self.assertEqual(last, rows[-8:])

    def test_capped_memory_eviction_preserves_residents_and_resets_new_slots(self):
        memory = LinkMemory(32, d_mem=4)
        memory.reset(100_000, capacity=3)
        first = memory._slots(torch.tensor([10, 20, 30]), allocate=True)
        memory.state[first] = 9
        memory.used[first] = True
        # Keep two residents in this update, forcing the third to be recycled.
        slots = memory._slots(torch.tensor([10, 20, 40]), allocate=True)
        self.assertEqual(slots[:2].tolist(), first[:2].tolist())
        self.assertEqual(memory.slot_of[30].item(), -1)
        self.assertEqual(memory.link_at[slots].tolist(), [10, 20, 40])
        self.assertEqual(memory.evictions, 1)
        self.assertFalse(memory.used[slots[2]])
        self.assertTrue(torch.equal(memory.state[slots[2]], torch.zeros(4)))
        self.assertTrue(torch.equal(memory.state[slots[:2]], torch.full((2, 4), 9.0)))
        memory.grow(200_000)
        self.assertEqual(memory._slots(torch.tensor([40]), allocate=False).item(), slots[2].item())
        memory.reset(2, capacity=3)
        self.assertEqual(memory.link_at.tolist(), [-1, -1])

    def test_reverse_host_names_survive_reload_and_forget_evicted_ids(self):
        nodes = NodeRegistry(capacity=2)
        nodes.ids(["a", "b", "c"])
        self.assertEqual(nodes.ip_of, {1: "b", 2: "c"})
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "nodes.json"
            nodes.save(path)
            self.assertEqual(NodeRegistry.load(path, capacity=2).ip_of, nodes.ip_of)

    def test_attack_evidence_survives_run_reset_and_capacity_pruning(self):
        detector = Detector.__new__(Detector)
        detector.heads = SimpleNamespace(families=["Bot"], thresholds={"Bot": .8})
        detector.threshold_mode = SimpleNamespace(status=lambda _: {"effective": "checkpoint"})
        detector.live_calibration, detector.incident_history = None, None
        detector.adaptive, detector.incident_event_cache = {}, {}
        detector.emitters = {"Bot": AlertEmitter(.8, capacity=1)}
        detector.pending_incident_flags = {"Bot": {}}
        detector.detections, detector.incidents = deque(), deque()
        detector.counts = {"Bot": 0}

        def score(key, scores, start):
            flows = [SimpleNamespace(id=int(start) + i, src="a", dst="b", sport=1234, dport=443,
                                     proto=6, senders=["a"]) for i in range(len(scores))]
            detector._alerts(flows, np.full(len(scores), key), start + np.arange(len(scores)),
                             np.array(scores)[:, None])

        with contextlib.redirect_stdout(io.StringIO()):
            score(1, [.9, .9, .9], 1)
            self.assertEqual(len(detector.incident_events("Bot", 1, 3.0)), 3)
            score(1, [.1, .9], 10)
            self.assertEqual(len(detector.pending_incident_flags["Bot"][1]), 1)
            score(2, [.9, .9, .9], 500)
        self.assertNotIn(1, detector.pending_incident_flags["Bot"])
        self.assertEqual(len(detector.incident_events("Bot", 2, 502.0)), 3)


if __name__ == "__main__":
    unittest.main()
