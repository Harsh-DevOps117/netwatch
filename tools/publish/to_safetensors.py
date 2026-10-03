"""Convert a training checkpoint to safetensors plus a JSON config, for publishing.

Run: uv run python tools/publish/to_safetensors.py data/model_cache/serve/head_<day>.pt huggingface/model/model
     uv run python tools/publish/to_safetensors.py --stage huggingface/model --serve data/model_cache/serve

Why not publish the `.pt` files. `torch.load` unpickles, so loading a downloaded checkpoint can execute arbitrary code;
anyone consuming a public model has to either trust the uploader or audit the file. safetensors stores tensors and
nothing else, so a malicious file cannot run anything, and it memory-maps rather than deserialising.

The cost is that safetensors holds **only tensors**. Our checkpoints also carry family names, thresholds, layer widths
and the day they were fitted on, none of which is a tensor. Those go to a sibling `.config.json`, and the two files are
useless apart: the config names the shapes the tensors must have, and the tensors are meaningless without the scaler and
the class order. Both are written together and both must be uploaded.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

import numpy as np
import torch
from safetensors.torch import load_file, save_file

# Checkpoint keys whose value is a state_dict rather than a single tensor. Flattened as "<key>.<param>". Any other dict
# made only of tensors (the record encoder's `decoder`) is flattened the same way, and the config lists them all in
# `nested_keys`; files written before that list existed are read with this fixed set.
NESTED = ("model", "head", "encoder", "ae")


def flatten(checkpoint: dict) -> tuple[dict[str, torch.Tensor], dict]:
    """Split a checkpoint into tensors and everything else.

    Input:  a dict from torch.load
    Output: ({name: contiguous tensor}, JSON-safe config dict)

    Numpy arrays become tensors, because a feature scaler stored as numpy is still a tensor in every sense that matters
    here. Anything that is neither is repr'd into the config rather than dropped -- silently losing a field is how a
    checkpoint arrives on the far side missing its thresholds.
    """
    tensors: dict[str, torch.Tensor] = {}
    config: dict = {}
    nested, numpy_keys = [], []
    for key, value in checkpoint.items():
        all_tensors = isinstance(value, dict) and bool(value) and all(isinstance(p, torch.Tensor) for p in value.values())
        if (key in NESTED and isinstance(value, dict)) or all_tensors:
            nested.append(key)
            for name, param in value.items():
                if isinstance(param, torch.Tensor):
                    tensors[f"{key}.{name}"] = param.detach().cpu().contiguous()
                else:
                    config.setdefault(f"{key}_non_tensor", {})[name] = repr(param)
            continue
        if isinstance(value, torch.Tensor):
            tensors[key] = value.detach().cpu().contiguous()
            continue
        as_tensor = _maybe_tensor(value)
        if as_tensor is not None:
            tensors[key] = as_tensor
            numpy_keys.append(key)                   # restored as numpy, so the file comes back as it went in
            continue
        try:
            json.dumps(value)
            config[key] = value
        except (TypeError, ValueError):
            config[key] = repr(value)
    config["nested_keys"], config["numpy_keys"] = nested, numpy_keys
    return tensors, config


def _maybe_tensor(value):
    """A numpy array as a contiguous tensor, or None when the value is not array-like.

    Input:  any checkpoint value
    Output: tensor or None
    """
    if type(value).__module__ == "numpy" and hasattr(value, "dtype") and hasattr(value, "shape"):
        return torch.as_tensor(value).detach().cpu().contiguous()
    return None


def convert(source: Path, destination: Path) -> dict:
    """Write `<destination>.safetensors` and `<destination>.config.json` from one checkpoint.

    Input:  the .pt file, the destination stem (no extension)
    Output: the config that was written

    The safetensors header carries the same config as a JSON string as well, so a file that becomes separated from its
    sibling can still be identified. The JSON file stays the one a consumer reads.
    """
    checkpoint = torch.load(source, map_location="cpu", weights_only=False)
    if not isinstance(checkpoint, dict):
        checkpoint = {"model": checkpoint}                      # a bare state_dict, as Block 7 wrote before v1
    tensors, config = flatten(checkpoint)
    if not tensors:
        raise SystemExit(f"{source}: no tensors found, nothing to convert")
    config["source_checkpoint"] = source.name
    config["tensor_names"] = sorted(tensors)
    destination.parent.mkdir(parents=True, exist_ok=True)
    save_file(tensors, f"{destination}.safetensors", metadata={"config": json.dumps(config)})
    Path(f"{destination}.config.json").write_text(json.dumps(config, indent=2) + "\n")
    total = sum(t.numel() * t.element_size() for t in tensors.values())
    print(f"  {source.name} -> {destination.name}.safetensors  "
          f"({len(tensors)} tensors, {total / 1024:,.1f} KB) + {destination.name}.config.json")
    return config


def unflatten(stem: Path) -> dict:
    """Rebuild a checkpoint dict from `<stem>.safetensors` and `<stem>.config.json`: the inverse of `flatten`.

    Input:  the stem, without extension
    Output: a dict the training and serving code can torch.save and load, as they load their own checkpoints

    For a consumer who downloaded the safetensors: the pickle is written locally from tensors they already trust.
    Numpy arrays come back as numpy (files from before `numpy_keys` existed return them as tensors); values `flatten`
    had to repr stay strings.
    """
    tensors = load_file(f"{stem}.safetensors")
    config = json.loads(Path(f"{stem}.config.json").read_text())
    nested, numpy_keys = set(config.get("nested_keys", NESTED)), set(config.get("numpy_keys", ()))
    checkpoint = {k: v for k, v in config.items() if k not in ("source_checkpoint", "tensor_names", "nested_keys",
                                                               "numpy_keys") and not k.endswith("_non_tensor")}
    for name, tensor in tensors.items():
        key, _, param = name.partition(".")
        if key in nested and param:
            checkpoint.setdefault(key, {})[param] = tensor
        else:
            checkpoint[name] = tensor.numpy() if name in numpy_keys else tensor
    # v1.0.0 published the flow encoder's nested numpy scalers as their repr.
    # Recover the numbers using a strict data parser, never eval downloaded text.
    if checkpoint.get("format") in ("flow-encoder-v1", "block7-encoder-v1") and isinstance(checkpoint.get("stats"), str):
        checkpoint["stats"] = _legacy_stats(checkpoint["stats"])
    return checkpoint


def _legacy_stats(value: str) -> dict:
    """Read legacy numpy-array scaler metadata without executing Python code."""
    def read(node):
        if isinstance(node, ast.Constant) and type(node.value) in (str, int, float):
            return node.value
        if isinstance(node, (ast.List, ast.Tuple)):
            values = [read(item) for item in node.elts]
            return tuple(values) if isinstance(node, ast.Tuple) else values
        if isinstance(node, ast.Dict):
            return {read(key): read(item) for key, item in zip(node.keys, node.values)}
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            number = read(node.operand)
            if type(number) in (int, float):
                return -number if isinstance(node.op, ast.USub) else number
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "array"
                and len(node.args) == 1 and len(node.keywords) == 1):
            dtype = node.keywords[0]
            if dtype.arg == "dtype" and isinstance(dtype.value, ast.Name) and dtype.value.id in ("float32", "float64"):
                return np.asarray(read(node.args[0]), dtype=np.dtype(dtype.value.id))
        raise ValueError("Unsupported expression in legacy flow-encoder scaler metadata")

    stats = read(ast.parse(value, mode="eval").body)
    if not isinstance(stats, dict) or not {"a", "pkt"}.issubset(stats):
        raise ValueError("The published flow encoder is missing its normalisation statistics")
    for pair in stats.values():
        if (not isinstance(pair, (list, tuple)) or len(pair) != 2
                or any(not isinstance(array, np.ndarray) or array.ndim != 1 or not np.isfinite(array).all()
                       for array in pair) or pair[0].shape != pair[1].shape or np.any(pair[1] <= 0)):
            raise ValueError("Invalid normalisation statistics in the published flow encoder")
    return stats


def verify(destination: Path, source: Path) -> None:
    """Check the safetensors file reproduces the original tensors exactly.

    Input:  the destination stem, the original checkpoint
    Output: none; raises SystemExit on any mismatch

    Bit-exact, not approximate. A conversion that changed a weight by one bit would move every score, and a threshold
    read off the original would no longer mean anything.
    """
    original, _ = flatten(torch.load(source, map_location="cpu", weights_only=False))
    restored = load_file(f"{destination}.safetensors")
    if set(original) != set(restored):
        raise SystemExit(f"tensor names differ: only in source {sorted(set(original) - set(restored))}, "
                         f"only in output {sorted(set(restored) - set(original))}")
    for name, tensor in original.items():
        # NaN never equals itself, and Block 10's last_seen buffer is NaN for every node not yet seen.
        other = restored[name]
        same = tensor.shape == other.shape and bool(((tensor == other) | (tensor.isnan() & other.isnan())).all()) \
            if tensor.is_floating_point() else torch.equal(tensor, other)
        if not same:
            raise SystemExit(f"{name}: values changed during conversion")
    # The round trip a consumer makes: every tensor and array of the original must come back, of the same kind. The
    # tensor check above cannot see a field `flatten` turned into text -- how the record decoder was once lost.
    lost = _arrays(torch.load(source, map_location="cpu", weights_only=False)).keys() - _arrays(unflatten(destination)).keys()
    if lost:
        raise SystemExit(f"lost in the round trip: {sorted(lost)}")
    print(f"  verified: {len(original)} tensors identical to {source.name}, round trip complete")


def _arrays(value, prefix: str = "") -> dict:
    """Every tensor and numpy array in a checkpoint, by path and kind."""
    if isinstance(value, dict):
        return {k: v for key, item in value.items() for k, v in _arrays(item, f"{prefix}/{key}").items()}
    if isinstance(value, torch.Tensor) or _maybe_tensor(value) is not None:
        return {(prefix, type(value).__name__): value}
    return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("source", nargs="?", type=Path, help="a .pt checkpoint")
    parser.add_argument("destination", nargs="?", type=Path, help="output stem, without extension")
    parser.add_argument("--stage", type=Path, default=None,
                        help="convert a whole staged model directory in place: every .pt becomes .safetensors")
    parser.add_argument("--keep-pt", action="store_true",
                        help="leave the .pt files in the staging directory. Off by default: publishing both invites "
                             "a consumer to load the pickle")
    parser.add_argument("--to-pt", type=Path, default=None, metavar="STEM",
                        help="the reverse: rebuild <source>.pt from STEM.safetensors + STEM.config.json, for the "
                             "repository's own loaders (e.g. --to-pt world_model world_model.pt)")
    args = parser.parse_args(argv)

    if args.to_pt:
        if not args.source:
            parser.error("--to-pt STEM needs the .pt path to write as the first argument")
        torch.save(unflatten(args.to_pt), args.source)
        print(f"  {args.to_pt.name}.safetensors -> {args.source}")
        return 0

    if args.stage:
        found = sorted(args.stage.glob("*.pt"))
        if not found:
            raise SystemExit(f"no .pt files in {args.stage}; stage the checkpoints first "
                             f"(tools/publish/huggingface.py --what model)")
        for path in found:
            convert(path, path.with_suffix(""))
            verify(path.with_suffix(""), path)
            if not args.keep_pt:
                path.unlink()
                print(f"  removed {path.name}")
        return 0

    if not args.source or not args.destination:
        parser.error("give a source and destination, or --stage <dir>")
    convert(args.source, args.destination)
    verify(args.destination, args.source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
