"""Explicit serving device selection and a real CUDA execution check."""
import argparse

import torch


def checked_device(requested: str = "cuda") -> str:
    device = torch.device(requested)
    if device.type not in ("cuda", "cpu"):
        raise ValueError("Use cuda (default) or cpu for model serving")
    if device.type == "cuda":
        if not torch.cuda.is_available():
            raise ValueError("CUDA is unavailable. Run uv sync --frozen with an NVIDIA driver installed, "
                             "or explicitly select --device cpu (-Device cpu in PowerShell).")
        # Validate the driver/runtime and a GPU operation before announcing CUDA.
        torch.ones(1, device=device).add_(1)
        torch.cuda.synchronize(device)
    return str(device)


def device_description(device: str) -> str:
    target = torch.device(device)
    return (f"CUDA ({torch.cuda.get_device_name(target)})" if target.type == "cuda" else "CPU")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="cuda")
    args = parser.parse_args()
    try:
        selected = checked_device(args.device)
    except (ValueError, RuntimeError) as error:
        parser.error(str(error))
    print(f"Model device ready: {device_description(selected)}", flush=True)
