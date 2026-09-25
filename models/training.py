"""Shared training machinery: telemetry, learning-rate schedules, and resuming an interrupted run.

Written once and used by every trainer, because three copies of a resume path is three places for it to be subtly
wrong, and a run that resumes into a slightly different optimiser state is the kind of difference nobody notices until
a result will not reproduce.

**On schedules.** The default is `none`, deliberately. Every measured number in this repository was produced with a
constant learning rate and early stopping over at most ten epochs; switching the default would invalidate all of them
while claiming an improvement nobody has measured. `cosine` and `plateau` are available to opt into, and the honest
expectation is that they matter little at this scale -- these are small models that early-stop long before a schedule
has room to work. Measure before believing a gain.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import torch


def make_schedule(optimiser: torch.optim.Optimizer, kind: str, epochs: int, patience: int = 1):
    """A learning-rate schedule, or None for a constant rate.

    Input:  the optimiser, "none" / "cosine" / "plateau", how many epochs the run plans, patience for plateau
    Output: a torch scheduler, or None

    `cosine` anneals over the planned epochs and ignores the metric. `plateau` reacts to it, so the caller must pass
    the validation value to `step_schedule`; it also interacts with early stopping, and a plateau patience at or above
    the early-stopping patience means the run ends before the rate is ever reduced.
    """
    if kind == "none":
        return None
    if kind == "cosine":
        return torch.optim.lr_scheduler.CosineAnnealingLR(optimiser, T_max=max(epochs, 1))
    if kind == "plateau":
        return torch.optim.lr_scheduler.ReduceLROnPlateau(optimiser, mode="min", patience=max(patience - 1, 0))
    raise ValueError(f"unknown schedule {kind!r}: choose none, cosine or plateau")


def step_schedule(scheduler, metric: float | None = None) -> None:
    """Advance a schedule at the end of an epoch.

    Input:  the scheduler or None, the validation metric (needed only by plateau)
    Output: none

    Separated from the loop so a trainer does not have to know which schedules consume a metric. Passing a metric to
    a schedule that ignores it is silently accepted, which is how a plateau schedule ends up never stepping.
    """
    if scheduler is None:
        return
    if isinstance(scheduler, torch.optim.lr_scheduler.ReduceLROnPlateau):
        if metric is None:
            raise ValueError("the plateau schedule needs the validation metric")
        scheduler.step(metric)
    else:
        scheduler.step()


class Telemetry:
    """TensorBoard writer that is inert when TensorBoard is not wanted or not installed.

    Input:  a log directory or None to disable, a run name
    Output: object; log(step, **values) writes scalars, close() flushes

    Inert rather than optional at every call site: a trainer should not be littered with `if writer is not None`, and a
    missing TensorBoard should not stop a training run that was going to succeed.
    """

    def __init__(self, log_dir: "str | Path | None", run: str = ""):
        self.writer = None
        self.log_dir = None
        if log_dir is None:
            return
        try:
            from torch.utils.tensorboard import SummaryWriter
        except ImportError:                                    # pragma: no cover - depends on the environment
            print("tensorboard is not installed; training continues without it", flush=True)
            return
        self.log_dir = Path(log_dir) / run if run else Path(log_dir)
        self.writer = SummaryWriter(str(self.log_dir))
        print(f"tensorboard: tensorboard --logdir {Path(log_dir)}", flush=True)

    def log(self, step: int, prefix: str = "", **values) -> None:
        """Write scalar values for one step.

        Input:  the step (an epoch, usually), an optional prefix grouping the scalars, name=value pairs
        Output: none; non-finite values are skipped rather than written as NaN
        """
        if self.writer is None:
            return
        for name, value in values.items():
            try:
                number = float(value)
            except (TypeError, ValueError):
                continue
            if number == number and abs(number) != float("inf"):
                self.writer.add_scalar(f"{prefix}/{name}" if prefix else name, number, step)

    def close(self) -> None:
        if self.writer is not None:
            self.writer.flush()
            self.writer.close()


@dataclass
class Resume:
    """The state a run needs to continue where an interrupted one stopped.

    Input:  built by `load_resume`; `save` writes it after every epoch
    Output: dataclass with the epoch to start from, the best metric so far, how many epochs have not improved, and the
            history already recorded

    Saved separately from the best checkpoint. The best checkpoint is the deliverable and must not be overwritten by a
    worse later epoch; this is the bookkeeping that says where the run had got to, which is a different question.
    """

    epoch: int = 0
    best: float = float("inf")
    stale: int = 0
    history: list = field(default_factory=list)
    higher_is_better: bool = False

    def improved(self, metric: float) -> bool:
        """Whether this epoch beat the best so far, and record it if so."""
        better = metric > self.best if self.higher_is_better else metric < self.best
        if better:
            self.best, self.stale = metric, 0
        else:
            self.stale += 1
        return better

    def save(self, path: "str | Path", model=None, optimiser=None, scheduler=None) -> None:
        """Write the bookkeeping, and optionally the live weights, so a run can continue.

        Input:  destination, the model, the optimiser, the schedule
        Output: none

        The optimiser state is included because Adam's moments are part of where the run had got to: resuming with a
        fresh optimiser is a different trajectory, not a continuation.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        state = {"epoch": self.epoch, "best": self.best, "stale": self.stale, "history": self.history,
                 "higher_is_better": self.higher_is_better}
        if model is not None:
            state["model"] = model.state_dict()
        if optimiser is not None:
            state["optimiser"] = optimiser.state_dict()
        if scheduler is not None:
            state["scheduler"] = scheduler.state_dict()
        torch.save(state, path)


def load_resume(path: "str | Path | None", model=None, optimiser=None, scheduler=None,
                higher_is_better: bool = False, device: str = "cpu") -> Resume:
    """Restore a run's position, or start a fresh one.

    Input:  the resume file (None or missing starts fresh), the model, optimiser and schedule to restore into,
            whether a higher metric is better, device
    Output: a Resume

    A missing file is a fresh start rather than an error, so `--resume` can be passed unconditionally in a script that
    may be running for the first time.
    """
    fresh = Resume(higher_is_better=higher_is_better, best=-float("inf") if higher_is_better else float("inf"))
    if path is None or not Path(path).is_file():
        return fresh
    state = torch.load(path, map_location=device, weights_only=False)
    if model is not None and "model" in state:
        model.load_state_dict(state["model"])
    if optimiser is not None and "optimiser" in state:
        optimiser.load_state_dict(state["optimiser"])
    if scheduler is not None and "scheduler" in state:
        scheduler.load_state_dict(state["scheduler"])
    resumed = Resume(epoch=int(state.get("epoch", 0)), best=float(state.get("best", fresh.best)),
                     stale=int(state.get("stale", 0)), history=list(state.get("history", [])),
                     higher_is_better=bool(state.get("higher_is_better", higher_is_better)))
    print(f"resuming from {path}: epoch {resumed.epoch}, best {resumed.best:.6f}, "
          f"{resumed.stale} epoch(s) without improvement", flush=True)
    return resumed


def add_training_arguments(parser, default_epochs: int) -> None:
    """The flags every trainer shares, so they are spelled and documented identically.

    Input:  an argparse parser, the trainer's default epoch count
    Output: none; adds --tensorboard, --run-name, --lr-schedule and --resume
    """
    parser.add_argument("--tensorboard", type=Path, default=None, metavar="DIR",
                        help="write scalars here for TensorBoard; omitted disables it entirely")
    parser.add_argument("--run-name", default="", help="subdirectory under --tensorboard for this run")
    parser.add_argument("--lr-schedule", choices=("none", "cosine", "plateau"), default="none",
                        help="none keeps the constant rate every measured result used. cosine anneals over the "
                             "planned epochs; plateau reacts to validation. Changing this changes results, so "
                             "re-measure rather than assuming a gain")
    parser.add_argument("--resume", type=Path, default=None, metavar="FILE",
                        help="continue an interrupted run from this file, writing it after every epoch. A missing "
                             "file starts fresh, so it is safe to pass on a first run")


def demo() -> None:
    """Self-check: schedules step, telemetry is inert without a directory, resume round-trips."""
    import tempfile

    model = torch.nn.Linear(4, 2)
    optimiser = torch.optim.Adam(model.parameters(), lr=1e-2)

    assert make_schedule(optimiser, "none", 10) is None
    cosine = make_schedule(optimiser, "cosine", 10)
    before = optimiser.param_groups[0]["lr"]
    step_schedule(cosine)
    assert optimiser.param_groups[0]["lr"] < before, "cosine must anneal"
    plateau = make_schedule(optimiser, "plateau", 10, patience=2)
    step_schedule(plateau, metric=1.0)
    try:
        step_schedule(plateau)
        raise AssertionError("plateau must refuse to step without a metric")
    except ValueError:
        pass
    try:
        make_schedule(optimiser, "linear", 10)
        raise AssertionError("an unknown schedule must not be accepted silently")
    except ValueError:
        pass

    quiet = Telemetry(None)
    quiet.log(0, loss=1.0)                                     # must not raise
    quiet.close()

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "resume.pt"
        state = load_resume(path, higher_is_better=False)
        assert state.epoch == 0 and state.best == float("inf"), "a missing file must start fresh"
        assert state.improved(0.5) and not state.improved(0.9)
        assert state.stale == 1
        state.epoch = 3
        state.history.append({"epoch": 3, "loss": 0.5})
        state.save(path, model=model, optimiser=optimiser)

        again = torch.nn.Linear(4, 2)
        again_optimiser = torch.optim.Adam(again.parameters(), lr=1e-2)
        back = load_resume(path, model=again, optimiser=again_optimiser)
        assert back.epoch == 3 and back.best == 0.5 and back.stale == 1
        assert len(back.history) == 1
        for a, b in zip(model.parameters(), again.parameters()):
            assert torch.equal(a, b), "resume must restore the weights exactly"

        higher = load_resume(None, higher_is_better=True)
        assert higher.best == -float("inf") and higher.improved(0.1)

        watched = Telemetry(Path(tmp) / "tb", run="unit")
        watched.log(1, prefix="train", loss=0.25, ignored=float("nan"))
        watched.close()
        assert watched.log_dir is None or watched.log_dir.exists()
    print("demo ok")


if __name__ == "__main__":
    demo()
