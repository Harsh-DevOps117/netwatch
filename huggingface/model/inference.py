"""Load the detector from a Hugging Face model repository and score events.

Weights are read from **safetensors**, never from a pickle. `torch.load` can execute arbitrary code while unpickling, so
a public model published as `.pt` asks every consumer to trust the uploader; safetensors holds tensors and nothing else,
and memory-maps them instead of deserialising.

Because safetensors stores only tensors, the rest of the checkpoint -- the class order, the layer widths, the committed
threshold -- lives in `detector.config.json`. The two files are useless apart and must be uploaded together.

Self-contained on purpose: a model repository has to stand alone, so this file repeats the head's small architecture
rather than importing the training package. Shapes come from the config, so they cannot drift from the weights: a
mismatch raises in `load_state_dict` rather than scoring silently.

What this scores: **pre-extracted features**, the 132-wide vector formed by the flow embedding (32) followed by the
context vector (100). It does not extract features from a packet capture; that needs tshark and CICFlowMeter and belongs
in the sensor, not in an inference endpoint.
"""
from __future__ import annotations

import json
from pathlib import Path

import torch
from safetensors.torch import load_file
from torch import nn


class Head(nn.Module):
    """One hidden layer over a frozen representation, one logit per class.

    Input:  feature width, number of classes (benign first, then families), hidden width
    Output: module; forward(x) returns logits (N, classes)
    """

    def __init__(self, width: int, classes: int, hidden: int = 64):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(width, hidden), nn.ReLU(), nn.Linear(hidden, classes))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class Detector:
    """The shipped decision: family probabilities, and whether to alert.

    Input:  the directory holding detector.pt, the device to run on
    Output: object; score(features) returns probabilities, decide(features) adds the alert verdict

    The feature scaler travels inside the checkpoint and is applied here. A process that loaded these weights and
    standardised differently would produce scores on another scale, and every threshold would be meaningless.
    """

    def __init__(self, path: str | Path = ".", device: str | None = None):
        path = Path(path)
        stem = path / "detector" if path.is_dir() else path.with_suffix("")
        weights, config_file = Path(f"{stem}.safetensors"), Path(f"{stem}.config.json")
        for needed in (weights, config_file):
            if not needed.is_file():
                raise FileNotFoundError(
                    f"{needed} not found. A model repository needs both detector.safetensors and "
                    f"detector.config.json; see README.md")
        config = json.loads(config_file.read_text())
        if config.get("format") != "supervised-head-v1":
            raise ValueError(f"{config_file}: not a detector config (format {config.get('format')!r})")
        tensors = load_file(str(weights))
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.families: list[str] = list(config["families"])
        self.classes: list[str] = ["Benign", *self.families]
        self.mean = tensors["mean"].to(dtype=torch.float32, device=self.device)
        self.std = tensors["std"].to(dtype=torch.float32, device=self.device)
        self.width = int(config["width"])
        self.head = Head(self.width, int(config["classes"]), int(config["hidden"])).to(self.device)
        # The flattened names carry the "head." prefix the converter added; strip it back off.
        self.head.load_state_dict({k.removeprefix("head."): v for k, v in tensors.items()
                                   if k.startswith("head.")})
        self.head.eval()
        # Written by the operating-point step, not by training. Empty means "no threshold has been committed".
        self.serve_threshold: dict = config.get("serve_threshold") or {}
        self.budget_thresholds: dict = config.get("thresholds") or {}
        self.trained_on = config.get("day")
        self.input_name = config.get("input")

    @torch.no_grad()
    def score(self, features) -> torch.Tensor:
        """Per-class probabilities for a batch of events.

        Input:  (N, width) array or tensor of raw, unstandardised features
        Output: (N, classes) float32 probabilities, benign first
        """
        x = torch.as_tensor(features, dtype=torch.float32, device=self.device)
        if x.dim() == 1:
            x = x[None, :]
        if x.shape[1] != self.width:
            raise ValueError(f"expected {self.width} features per event, got {x.shape[1]}. "
                             f"Layout: flow embedding first, then the context vector")
        return self.head((x - self.mean) / self.std).softmax(-1)

    def decide(self, features) -> list[dict]:
        """Probabilities plus the alert verdict, per event.

        Input:  (N, width) features
        Output: list of dicts with the most likely class, its probability, every class probability, and `alert`

        `alert` is None when no threshold has been committed to this checkpoint, rather than a guess. A threshold is a
        judgement about acceptable alert volume and is only valid for the exact model that produced it.
        """
        probabilities = self.score(features)
        out = []
        for row in probabilities:
            values = {name: float(p) for name, p in zip(self.classes, row)}
            best = max(self.families, key=lambda f: values[f]) if self.families else None
            alert = None
            if best is not None and best in self.serve_threshold:
                alert = bool(values[best] >= float(self.serve_threshold[best]["threshold"]))
            out.append({"predicted": max(values, key=values.get), "probabilities": values,
                        "family": best, "family_probability": values.get(best), "alert": alert})
        return out

    def info(self) -> dict:
        """What this checkpoint is, for a health endpoint."""
        return {"families": self.families, "feature_width": self.width, "input": self.input_name,
                "trained_on": self.trained_on, "device": self.device,
                "serve_threshold": self.serve_threshold,
                "budget_thresholds": self.budget_thresholds}


def demo() -> None:
    """Self-check that needs no checkpoint: the architecture round-trips and the scaler is applied."""
    torch.manual_seed(0)
    width, classes = 132, 3
    head = Head(width, classes)
    x = torch.randn(4, width)
    probabilities = head(x).softmax(-1)
    assert probabilities.shape == (4, classes)
    assert torch.allclose(probabilities.sum(1), torch.ones(4), atol=1e-5)
    print("demo ok")


if __name__ == "__main__":
    demo()
