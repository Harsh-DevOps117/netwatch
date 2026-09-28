"""Backend configuration: numerics first, speed second.

This project has already lost three measured claims to nondeterminism, so the default here is the reproducible
configuration and every speed option is opt-in. The two settings that matter:

`cudnn.benchmark` autotunes by timing several algorithms for each new input shape and caching the winner. It is fast
for fixed shapes and counterproductive for varying ones, because every unseen shape pays the benchmarking cost. More
importantly the chosen algorithm can differ between runs, and different algorithms accumulate in different orders, so
results move in the last bits. Differences of that kind are expensive to attribute after the fact.

TF32 lets Ampere and later run float32 matmuls through tensor cores with a 10-bit mantissa. It is typically 2-8x faster
and it changes results. Acceptable while training, not while measuring a threshold to six significant figures.

So: `configure()` gives the stable path, and `configure(fast=True)` gives the fast one. Call it once at start-up.
"""
from __future__ import annotations

import os

import torch


def configure(fast: bool = False, deterministic: bool = True, seed: int | None = None) -> dict:
    """Set the backend flags for this process.

    Input:  fast (enable cuDNN autotuning and TF32), deterministic (fail loudly on nondeterministic kernels),
            an optional seed to set for torch, cuda and python hashing
    Output: dict describing what was applied, for logging into a result row

    `deterministic` uses `use_deterministic_algorithms(warn_only=True)`: a kernel with no deterministic implementation
    warns rather than raising, so a run is never blocked, but the warning names the operation instead of leaving a
    silent source of variance to be discovered later.
    """
    applied = {"cuda": torch.cuda.is_available(), "fast": bool(fast), "deterministic": bool(deterministic)}
    if seed is not None:
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        os.environ.setdefault("PYTHONHASHSEED", str(seed))
        applied["seed"] = seed

    torch.backends.cudnn.benchmark = bool(fast)
    torch.backends.cudnn.deterministic = not fast
    torch.backends.cudnn.allow_tf32 = bool(fast)
    torch.backends.cuda.matmul.allow_tf32 = bool(fast)
    torch.set_float32_matmul_precision("high" if fast else "highest")
    if deterministic and not fast:
        # warn_only: a run is never blocked, but a nondeterministic kernel is named rather than left to be found later.
        torch.use_deterministic_algorithms(True, warn_only=True)
        os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    else:
        torch.use_deterministic_algorithms(False)
    applied["matmul_precision"] = torch.get_float32_matmul_precision()
    return applied


def compiler_available() -> bool:
    """Whether torch.compile can build kernels in this environment.

    Input:  none
    Output: True when a host C compiler is on PATH

    Inductor generates C++ and Triton and shells out to a compiler. Without one, `torch.compile` raises
    `InductorError: Failed to find C compiler` on first call -- at run time, after the work has started.
    """
    from shutil import which
    return any(which(name) for name in ("cc", "gcc", "clang", "g++")) or bool(os.environ.get("CC"))


def maybe_compile(fn, enabled: bool = True, **kwargs):
    """Compile a callable when that is both asked for and possible, else return it unchanged.

    Input:  the callable, whether compilation was requested, keyword arguments for torch.compile
    Output: the compiled callable, or the original

    Compilation is worth it for many small operations repeated thousands of times, where Python and launch overhead
    dominate -- a per-chunk training step, for example. It is not worth it for a handful of large reductions: measured
    on this repository's evaluation path, the fusible tensor work was 1.6 ms of a 105 ms call, the rest being host
    transfers and a stateful Python loop that no graph compiler can absorb. Compiling that would add a one-off cost of
    seconds to save under two milliseconds.
    """
    if not enabled:
        return fn
    if not compiler_available():
        print("torch.compile requested but no C compiler is on PATH; running eager", flush=True)
        return fn
    try:
        return torch.compile(fn, **kwargs)
    except Exception as error:                       # a failed compile must never fail the run
        print(f"torch.compile unavailable ({type(error).__name__}); running eager", flush=True)
        return fn


def demo() -> None:
    """Self-check: the flags land where they are meant to, and both modes round-trip."""
    stable = configure(fast=False, seed=0)
    assert torch.backends.cudnn.benchmark is False
    assert torch.get_float32_matmul_precision() == "highest"
    assert torch.backends.cuda.matmul.allow_tf32 is False
    assert stable["seed"] == 0 and stable["deterministic"] is True

    quick = configure(fast=True)
    assert torch.backends.cudnn.benchmark is True
    assert torch.get_float32_matmul_precision() == "high"
    assert quick["fast"] is True

    configure(fast=False)                            # leave the process in the reproducible configuration
    assert torch.backends.cudnn.benchmark is False

    identity = maybe_compile(lambda x: x + 1, enabled=False)
    assert identity(torch.ones(2)).tolist() == [2.0, 2.0]
    # with compilation requested, the result must still be correct whether or not a compiler exists
    compiled = maybe_compile(lambda x: x * 2, enabled=True)
    assert compiled(torch.ones(2)).tolist() == [2.0, 2.0]
    assert isinstance(compiler_available(), bool)
    print("demo ok")


if __name__ == "__main__":
    demo()
