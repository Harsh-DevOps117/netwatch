"""The whole cascade held in memory, event in and verdict out.

Training writes a file per stage and the next stage reads it back. That is right for training -- each stage is fitted
once, frozen, and its output reused by many later runs, so materialising it is a cache rather than a detour -- and
wrong for serving, where an event must reach a verdict without ever touching disk.

This loads every stage once, keeps them on one device, and passes tensors straight down the chain:

    packets + side features
        -> flow encoder      -> h      (32)
        -> context encoder   -> s      (100)   [link memory and the neighbourhood carry across calls]
        -> compressor        -> z, recon_error
        -> detector          -> per-family probability -> threshold, persistence, incident

**The context encoder is stateful and the others are not.** Link memory and the neighbourhood accumulate across calls,
which is the whole point of it, and it also means a cascade instance is bound to one stream: feeding two unrelated
streams through the same instance mixes their memory. `reset()` starts a new stream.

What this does not do is extract features from packets; that needs the sensor's own capture path, and the graph the
context encoder reads is built by `models.serving.graph`. `score_latents` is the entry point when those are already in
hand, which is the case for anything replaying a day.
"""
from __future__ import annotations

import json
from pathlib import Path

import torch

from models.compressor.autoencoder import ENCODERS, EventAutoencoder
from models.context_encoder.model import ContextEncoder
from models.detector.model import Head
from models.serving.emitter import AlertEmitter


class Cascade:
    """Every stage, loaded once, applied in order.

    Input:  a directory of checkpoints, or explicit paths per stage; the device
    Output: object; score_latents() scores compressed events, decide() adds the alert verdict

    Stages are frozen on load -- `eval()` and `requires_grad_(False)` -- because a serving process that accidentally
    builds a graph leaks memory for as long as it runs, and it is the kind of fault that only appears under load.
    """

    def __init__(self, checkpoints: "str | Path | None" = None, *, detector: "Path | None" = None,
                 context_encoder: "Path | None" = None, compressor: "Path | None" = None,
                 device: str | None = None, capacity: "int | float | None" = None):
        root = Path(checkpoints) if checkpoints else None
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.detector, self.families, self.scaler, self.serve_threshold = self._load_detector(
            detector or (root / "detector.pt" if root else None))
        self.context_encoder = self._load_context(context_encoder or (root / "context_encoder.pt" if root else None),
                                                  capacity)
        self.compressor = self._load_compressor(compressor or (root / "compressor.pt" if root else None))
        self.emitters: dict[str, AlertEmitter] = {}

    def _load_detector(self, path):
        """The detection head, its scaler, its families and its committed threshold."""
        if path is None or not Path(path).is_file():
            raise FileNotFoundError(f"the cascade needs a detector checkpoint; {path} is not a file")
        state = torch.load(path, map_location="cpu", weights_only=False)
        if state.get("format") != "supervised-head-v1":
            raise ValueError(f"{path}: not a detector checkpoint")
        head = Head(int(state["width"]), int(state["classes"]), int(state["hidden"])).to(self.device)
        head.load_state_dict(state["head"])
        head.eval().requires_grad_(False)
        scaler = (torch.as_tensor(state["mean"], dtype=torch.float32, device=self.device),
                  torch.as_tensor(state["std"], dtype=torch.float32, device=self.device))
        return head, list(state["families"]), scaler, state.get("serve_threshold") or {}

    def _load_context(self, path, capacity):
        """The context encoder, or None when scoring latents that already carry the context."""
        if path is None or not Path(path).is_file():
            return None
        state = torch.load(path, map_location="cpu", weights_only=False)
        model = ContextEncoder(state["arm"], flow_messages=state.get("flow_messages", False),
                               flow_records=state.get("flow_records", False),
                               record_split=state.get("record_split", True),
                               capacity=capacity if capacity is not None else state.get("capacity")).to(self.device)
        model.load_state_dict(state["model"])
        model.eval().requires_grad_(False)
        return model

    def _load_compressor(self, path):
        """The compressor, or None when the caller supplies `z` directly."""
        if path is None or not Path(path).is_file():
            return None
        state = torch.load(path, map_location="cpu", weights_only=False)
        if state["encoder"] not in ENCODERS:
            raise ValueError(f"{path}: encoder {state['encoder']!r} is not one of {ENCODERS}")
        # The context width comes from the checkpoint's own normalisation vector, not from a Block 8 beside it: a
        # serving process may load the compressor alone, and guessing 100 here would build the wrong shape in silence.
        width = int(state["model"]["s_mean"].numel())
        if state.get("target", "s") != "s":
            raise ValueError(f"{path}: only the variant-B compressor (target 's') reconstructs the context width; "
                             f"this one targets {state['target']!r}")
        model = EventAutoencoder(state["encoder"], d_s=width, d_z=int(state["d_z"]), target=width)
        model.load_state_dict(state["model"])
        model.to(self.device).eval().requires_grad_(False)
        return model

    def reset(self, links: int = 1) -> None:
        """Begin a new stream, clearing the context encoder's memory.

        Input:  how many links the stream has, for sizing link memory
        Output: none

        A cascade instance carries link memory across calls, so it belongs to one stream. Reusing it for another
        without resetting silently mixes two hosts' histories.
        """
        if self.context_encoder is not None:
            self.context_encoder.begin_day(links)
        for emitter in self.emitters.values():
            emitter.run.clear()
            emitter.open_until.clear()

    @torch.no_grad()
    def score_latents(self, z: torch.Tensor, context: "torch.Tensor | None" = None,
                      embedding: "torch.Tensor | None" = None) -> torch.Tensor:
        """Per-family probabilities for events whose representation is already built.

        Input:  the compressed latent (N, 32) -- unused when `embedding` and `context` are given -- plus either the
                detector's full input as `embedding` (N, 132) or its two halves
        Output: (N, classes) probabilities, benign first

        The detector reads the flow embedding and the context vector, not `z`: the compressor's latent feeds the world
        model. Passing `z` alone is therefore rejected rather than silently padded, because a wrong-width input that
        happened to broadcast would score every event against meaningless weights.
        """
        if embedding is None:
            if context is None:
                raise ValueError("the detector reads the flow embedding beside the context vector; pass `embedding`, "
                                 "or both halves. `z` alone is the world model's input, not this one")
            embedding = context
        x = torch.as_tensor(embedding, dtype=torch.float32, device=self.device)
        if x.dim() == 1:
            x = x[None, :]
        mean, std = self.scaler
        if x.shape[1] != mean.numel():
            raise ValueError(f"detector expects {mean.numel()} features per event, got {x.shape[1]}")
        return self.detector((x - mean) / std).softmax(-1)

    def decide(self, features, keys=None, times=None, family: "str | None" = None,
               persist: int = 3, gap: float = 60.0) -> dict:
        """Score events and apply the emission rules, in one call.

        Input:  the detector's input (N, W), per-event key and observation time (needed for the emission rules), which
                family to emit on (the only one, when there is one), the run length and the incident gap
        Output: dict with the probabilities, the threshold used, and any incidents opened

        The emitter is kept per family and **across calls**, because persistence is a run of consecutive events and an
        incident spans them: rebuilding it per batch would reset both and silently inflate the incident count.
        """
        probabilities = self.score_latents(None, embedding=features)
        name = family or (self.families[0] if len(self.families) == 1 else None)
        out = {"probabilities": probabilities, "families": self.classes}
        if name is None:
            raise ValueError(f"which family to emit on? this checkpoint has {self.families}")
        column = self.classes.index(name)
        committed = self.serve_threshold.get(name)
        if committed is None:
            out["incidents"], out["threshold"] = [], None
            return out
        threshold = float(committed["threshold"])
        if name not in self.emitters:
            self.emitters[name] = AlertEmitter(threshold, persist=persist, gap=gap)
        if keys is None or times is None:
            raise ValueError("the emission rules are per key and over time; pass keys and times")
        out["threshold"] = threshold
        out["incidents"] = self.emitters[name].push_batch(keys, probabilities[:, column], times)
        return out

    @property
    def classes(self) -> list[str]:
        """Class names in the model's own order: benign first, then each family."""
        return ["Benign", *self.families]

    def info(self) -> dict:
        """What is loaded, for a health endpoint."""
        return {"device": self.device, "families": self.families,
                "feature_width": int(self.scaler[0].numel()),
                "context_encoder": self.context_encoder is not None,
                "compressor": self.compressor is not None,
                "serve_threshold": self.serve_threshold,
                "emitters": {name: e.rates(1.0) for name, e in self.emitters.items()}}


def demo() -> None:
    """Self-check on a checkpoint written here, so the chain is exercised without any trained artefact."""
    import tempfile

    from models.detector.checkpoint import save_head

    torch.manual_seed(0)
    width, families = 132, ["Bot"]
    head = Head(width, len(families) + 1, 64)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "detector.pt"
        save_head(path, head=head, mean=torch.zeros(width).numpy(), std=torch.ones(width).numpy(),
                  families=families, thresholds={("Bot", 0.001): 0.5}, width=width, hidden=64,
                  feature="h_split+s", day="test", seed=0, context=None, calibrate=0.0)

        cascade = Cascade(detector=path, device="cpu")
        assert cascade.classes == ["Benign", "Bot"]
        assert cascade.info()["feature_width"] == width

        x = torch.randn(8, width)
        probabilities = cascade.score_latents(None, embedding=x)
        assert probabilities.shape == (8, 2)
        assert torch.allclose(probabilities.sum(1), torch.ones(8), atol=1e-5)

        # a wrong width must be refused, not broadcast into a meaningless score
        try:
            cascade.score_latents(None, embedding=torch.randn(4, 10))
            raise AssertionError("a wrong feature width must raise")
        except ValueError:
            pass
        # z alone is the world model's input and must not be accepted here
        try:
            cascade.score_latents(torch.randn(4, 32))
            raise AssertionError("z alone must be refused")
        except ValueError:
            pass

        # no committed threshold: no alert is invented
        decided = cascade.decide(x, keys=torch.zeros(8, dtype=torch.long), times=torch.arange(8.0))
        assert decided["threshold"] is None and decided["incidents"] == []

        # with one committed, the emitter persists across calls: three consecutive events, split over two calls
        cascade.serve_threshold = {"Bot": {"threshold": 0.0}}          # everything clears it
        keys, times = torch.zeros(2, dtype=torch.long), torch.tensor([0.0, 1.0])
        first = cascade.decide(x[:2], keys=keys, times=times)
        assert first["incidents"] == [], "two events cannot satisfy a run of three"
        second = cascade.decide(x[2:3], keys=torch.zeros(1, dtype=torch.long), times=torch.tensor([2.0]))
        assert len(second["incidents"]) == 1, "the run must carry across calls, not restart per batch"
        cascade.reset()
        assert cascade.emitters["Bot"].run == {}
    print("demo ok")


if __name__ == "__main__":
    demo()
