from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

try:
    import resource
except ImportError:
    resource = None  # Not available on Windows.

from ingest.sources.packets import capture_name, find_pcaps
from ingest.pipeline import process_capture

try:
    import psutil
except ImportError:
    psutil = None


def _memory_status() -> str:
    """Memory and swap snippet for progress lines.

    Input:  none
    Output: formatted string, empty when psutil is unavailable
    """

    if psutil is None:
        return ""

    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return f" | mem={vm.percent:.0f}% swap={swap.percent:.0f}%"


class ProgressTracker:
    """
    Write progress.json after every capture.

    Input:  output path, total job count, total day count
    Output: none; rewrites the file on each record_* call

    Written atomically via os.replace, so a concurrent `watch cat` never sees
    a partial document. Only the main process writes it.
    """

    def __init__(self, path: Path, total_jobs: int, total_days: int):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

        self.total_jobs = total_jobs
        self.total_days = total_days
        self.completed = 0
        self.failed = 0
        self.total_flows = 0
        self.total_edges = 0
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.per_day: dict[str, dict[str, int]] = {}
        self._durations: list[float] = []
        # Kept for the life of the run and written into every payload, so the
        # reason a capture failed survives into the finished progress.json.
        self.failures: list[dict[str, str]] = []

        self._write(status="running")

    def record_success(
        self, day: str, name: str, flows: int, edges: int, duration: float
    ) -> None:
        self.completed += 1
        self.total_flows += flows
        self.total_edges += edges
        self._durations.append(duration)

        d = self.per_day.setdefault(
            day, {"completed": 0, "failed": 0, "flows": 0, "edges": 0}
        )
        d["completed"] += 1
        d["flows"] += flows
        d["edges"] += edges

        self._write(
            status="running",
            last_capture=f"{day}/{name}",
            last_result="ok",
        )

    def record_failure(
        self, day: str, name: str, error: str, duration: float
    ) -> None:
        self.failed += 1
        self._durations.append(duration)

        d = self.per_day.setdefault(
            day, {"completed": 0, "failed": 0, "flows": 0, "edges": 0}
        )
        d["failed"] += 1
        self.failures.append({"day": day, "capture": name, "error": error})

        self._write(
            status="running",
            last_capture=f"{day}/{name}",
            last_result="failed",
            last_error=error,
        )

    def finish(self) -> None:
        self._write(status="done")

    def _write(self, **extra) -> None:
        done = self.completed + self.failed
        remaining = self.total_jobs - done

        avg = (
            sum(self._durations) / len(self._durations)
            if self._durations
            else None
        )
        eta_seconds = avg * remaining if avg is not None else None

        payload = {
            "started_at": self.started_at,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total_captures": self.total_jobs,
            "total_days": self.total_days,
            "completed": self.completed,
            "failed": self.failed,
            "remaining": remaining,
            "percent_complete": (
                round(100 * done / self.total_jobs, 1)
                if self.total_jobs
                else 100.0
            ),
            "total_flows": self.total_flows,
            "total_edges": self.total_edges,
            "failures": self.failures,
            "avg_seconds_per_capture": (
                round(avg, 1) if avg is not None else None
            ),
            "eta_seconds": (
                round(eta_seconds, 1) if eta_seconds is not None else None
            ),
            "per_day": self.per_day,
        }
        payload.update(extra)

        fd, tmp_name = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=".progress_",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_name, self.path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise


def _limit_worker_memory(limit_mb: int) -> None:
    """
    Cap this worker's virtual address space.

    Input:  limit in MB
    Output: none; best-effort, silently skipped where unsupported

    RLIMIT_AS is inherited across fork/exec, so a runaway tshark or JVM fails
    its own allocation and exits normally instead of triggering the system OOM
    killer, whose SIGKILL would bypass cleanup and orphan the child. Needs
    headroom above the JVM's virtual reservation or CICFlowMeter will not start.
    """
    if resource is None:
        return  # Windows: no rlimit support, skip silently.

    limit_bytes = limit_mb * 1024 * 1024

    try:
        resource.setrlimit(
            resource.RLIMIT_AS, (limit_bytes, limit_bytes)
        )
    except (ValueError, OSError):
        # Containers may already have a lower hard limit; best-effort only.
        pass


def process_one_capture(
    cfm_dir: Path,
    pcap: Path,
    output_root: Path,
    day: str,
    *,
    max_worker_mem_mb: int,
) -> tuple[str, int, int]:
    """Process exactly one capture, in a worker process.

    Input:  CICFlowMeter directory, capture path, output root, day, memory cap
    Output: (capture name, flow rows, edge rows)

    One capture per worker means one output directory per worker, so no two
    workers write the same path. The capture is never copied.
    """

    _limit_worker_memory(max_worker_mem_mb)
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    print(
        f"[RLIMIT] worker AS limit: "
        f"soft={soft / (1024**3):.2f} GiB, "
        f"hard={hard / (1024**3):.2f} GiB",
        flush=True,
    )
    pcap = Path(pcap).resolve()
    cfm_dir = Path(cfm_dir).resolve()
    output_root = Path(output_root).resolve()

    # NOT pcap.stem -- see capture_name(): these filenames end in an IP octet
    # that Path.stem would strip, collapsing distinct captures into one
    # directory and silently discarding all but the first.
    capture_output = (
        output_root
        / day
        / capture_name(pcap)
    )

    flows, edges = process_capture(
        cfm_dir=cfm_dir,
        pcap_dir=pcap.parent,
        output_dir=capture_output,
        day=day,
        pcap=pcap,
    )

    return pcap.name, flows, edges


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Process CIC-IDS2018 PCAP captures."
    )

    parser.add_argument(
        "--raw",
        type=Path,
        default=Path("data/raw"),
        help="Raw dataset root.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed"),
        help="Processed dataset root.",
    )

    parser.add_argument(
        "--days",
        nargs="+",
        default=None,
        help=(
            "Days to process. Pass one or more day directory names. "
            "Use 'all' to process all available days. "
            "If omitted, all available days are processed."
        ),
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel capture workers. Default: 1.",
    )

    parser.add_argument(
        "--progress-file",
        type=Path,
        default=None,
        help=(
            "Where to write live progress as JSON, updated after "
            "every capture. Default: <output>/progress.json."
        ),
    )

    parser.add_argument(
        "--min-free-mb",
        type=int,
        default=2048,
        help=(
            "Don't start a new capture unless at least this much "
            "RAM is free. Default: 2048 (2 GiB)."
        ),
    )

    parser.add_argument(
        "--max-swap-percent",
        type=float,
        default=50.0,
        help=(
            "Don't start a new capture if swap usage is already "
            "above this percent. Default: 50.0."
        ),
    )

    parser.add_argument(
        "--max-worker-mem-mb",
        type=int,
        default=6656,
        help=(
            "Hard virtual-memory ceiling (RLIMIT_AS) per capture "
            "worker, inherited by its tshark/gradlew children. A "
            "capture that would exceed this fails cleanly and is "
            "recorded as a normal job failure, instead of risking a "
            "system-wide OOM kill that can orphan a child process. "
            "Must stay comfortably above the JVM's virtual-memory "
            "reservation (observed ~4.8 GB here) or CICFlowMeter "
            "will fail to start. Default: 6656 (6.5 GiB)."
        ),
    )

    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be >= 1")

    cpu_count = os.cpu_count() or 1

    if args.workers > cpu_count:
        print(
            f"Warning: --workers {args.workers} exceeds detected "
            f"CPU count ({cpu_count}); capping to {cpu_count}."
        )
        args.workers = cpu_count

    # No pre-flight RAM cap: --max-worker-mem-mb is a virtual-address ceiling
    # sized for the JVM's ~4.8 GB reservation, not resident use, and only one
    # JVM runs at a time. _memory_ok() admits each capture on real free RAM.

    if args.workers > 1:
        print(
            "Note: CICFlowMeter/Gradle invocations are always "
            "serialized across workers (its build directory is "
            "project-global shared state). --workers > 1 mainly "
            "parallelizes TShark packet extraction and Parquet "
            "conversion, not CICFlowMeter itself."
        )

    raw_root = args.raw.resolve()
    output_root = args.output.resolve()
    cfm_dir = Path("tools/CICFlowMeter").resolve()

    if not raw_root.is_dir():
        raise FileNotFoundError(
            f"Raw dataset does not exist: {raw_root}"
        )

    if not cfm_dir.is_dir():
        raise FileNotFoundError(
            f"CICFlowMeter directory does not exist: {cfm_dir}"
        )


    available_days = sorted(
        p
        for p in raw_root.iterdir()
        if p.is_dir()
    )

    if args.days is None or "all" in args.days:
        selected_days = available_days
    else:
        requested = set(args.days)

        selected_days = [
            p
            for p in available_days
            if p.name in requested
        ]

        missing = requested - {
            p.name
            for p in selected_days
        }

        if missing:
            raise FileNotFoundError(
                "Requested day(s) not found:\n"
                + "\n".join(
                    f"  {day}"
                    for day in sorted(missing)
                )
            )


    jobs: list[tuple[Path, Path, str]] = []

    print(f"Dataset root:  {raw_root}")
    print(f"Output root:   {output_root}")
    print(f"Days selected: {len(selected_days)}")

    for day_dir in selected_days:
        pcap_dir = day_dir / "pcap"

        if not pcap_dir.is_dir():
            print(
                f"\nSKIP {day_dir.name}: "
                "no pcap directory"
            )
            continue

        # Captures are chosen by content: a file must start with a pcap header
        # and its first packet must fall on this day. Every rejection is shown.
        try:
            day_date = datetime.strptime(day_dir.name, "%A-%d-%m-%Y").date()
        except ValueError:
            day_date = None
        skipped: list[tuple[Path, str]] = []
        pcaps = find_pcaps(pcap_dir, day_date, skipped)
        for path, reason in skipped:
            print(f"SKIP {day_dir.name}/{path.name}: {reason}")

        if not pcaps:
            print(
                f"\nSKIP {day_dir.name}: "
                "no PCAP files"
            )
            continue

        print(f"\n=== {day_dir.name} ===")
        print(f"PCAPs: {len(pcaps)}")

        for pcap in pcaps:
            jobs.append(
                (
                    pcap,
                    output_root,
                    day_dir.name,
                )
            )

    if not jobs:
        print("\nNo capture jobs found.")
        return

    print(f"\nCapture jobs:  {len(jobs)}")
    print(f"Workers:       {args.workers}")

    progress_path = args.progress_file or (output_root / "progress.json")
    progress = ProgressTracker(
        progress_path,
        total_jobs=len(jobs),
        total_days=len(selected_days),
    )
    print(f"Progress file: {progress_path}")

    # One job per PCAP, not per directory -- see process_capture().

    total_flows = 0
    total_edges = 0
    total_captures = 0
    failed_captures = 0

    # Workers are recycled after every task. Each pipeline step is already
    # memory-bounded per capture, but pandas/PyArrow do not always return
    # allocations to the OS, so a long-lived worker's RSS creeps upward across
    # hundreds of captures. max_tasks_per_child needs Python 3.11+.

    # The pre-flight cap is one guess for the whole run, but PCAP sizes vary
    # by orders of magnitude. Jobs are therefore submitted one at a time, up to
    # --workers in flight, each gated on live free memory and swap.
    MIN_FREE_MB = args.min_free_mb
    MAX_SWAP_PERCENT = args.max_swap_percent

    def _memory_ok() -> bool:
        if psutil is None:
            return True  # Can't check -- don't block.

        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()

        free_mb = vm.available / (1024 * 1024)

        return (
            free_mb >= MIN_FREE_MB
            and swap.percent <= MAX_SWAP_PERCENT
        )

    pending = list(jobs)
    in_flight: dict = {}
    submit_times: dict = {}
    waiting_on_memory = False

    def _submit_next(executor: ProcessPoolExecutor) -> None:
        pcap, output_root_, day = pending.pop(0)

        future = executor.submit(
            process_one_capture,
            cfm_dir,
            pcap,
            output_root_,
            day,
            max_worker_mem_mb=args.max_worker_mem_mb,
        )

        in_flight[future] = (pcap, day)
        submit_times[future] = time.monotonic()

    try:
        executor = ProcessPoolExecutor(
            max_workers=args.workers,
            max_tasks_per_child=1,
        )
    except TypeError:
        executor = ProcessPoolExecutor(
            max_workers=args.workers,
        )

    try:
        with executor:

            # Always admit one job, or a tight box would never start any.
            if pending:
                _submit_next(executor)

            last_progress = 0.0

            while pending or in_flight:

                while (
                    pending
                    and len(in_flight) < args.workers
                    and _memory_ok()
                ):
                    if waiting_on_memory:
                        print(
                            f"[MEM] Headroom recovered"
                            f"{_memory_status()} -- resuming."
                        )
                        waiting_on_memory = False

                    _submit_next(executor)

                if pending and len(in_flight) < args.workers:
                    if not waiting_on_memory:
                        print(
                            f"[MEM] Holding off new captures until "
                            f">= {MIN_FREE_MB} MB free / swap <= "
                            f"{MAX_SWAP_PERCENT:.0f}%"
                            f"{_memory_status()}"
                        )
                        waiting_on_memory = True

                    time.sleep(3)

                if not in_flight:
                    continue

                done, _ = wait(
                    in_flight.keys(),
                    timeout=5.0,
                    return_when=FIRST_COMPLETED,
                )

                if not done:
                    # Once a minute, naming what is running: the largest
                    # capture takes over an hour and a bare count reads as a hang.
                    if time.monotonic() - last_progress >= 60:
                        last_progress = time.monotonic()
                        seen = progress.completed + progress.failed
                        running = ", ".join(
                            f"{in_flight[f][0].name} "
                            f"{(last_progress - submit_times[f]) / 60:.0f}m"
                            for f in in_flight
                        )
                        print(
                            f"[PROGRESS] Completed: {progress.completed} | "
                            f"Failed: {progress.failed} | "
                            f"Remaining: {progress.total_jobs - seen} | "
                            f"running: {running}"
                            f"{_memory_status()}"
                        )
                    continue

                for future in done:
                    pcap, day = in_flight.pop(future)
                    duration = time.monotonic() - submit_times.pop(future)

                    try:
                        name, flows, edges = future.result()

                        total_captures += 1
                        total_flows += flows
                        total_edges += edges

                        progress.record_success(
                            day, name, flows, edges, duration
                        )

                        print(
                            f"[OK] {day}/{name}: "
                            f"flows={flows}, "
                            f"edges={edges}"
                            f"{_memory_status()}"
                        )

                    except Exception as exc:
                        failed_captures += 1

                        progress.record_failure(
                            day,
                            pcap.name,
                            f"{type(exc).__name__}: {exc}",
                            duration,
                        )

                        print(
                            f"[FAILED] {day}/{pcap.name}: "
                            f"{type(exc).__name__}: {exc}"
                            f"{_memory_status()}"
                        )

    except KeyboardInterrupt:
        print("\n[!] Ctrl+C received. Cleaning up background processes (please wait)...")
        # Do not terminate(): SIGTERM bypasses the workers' finally blocks and
        # orphans their java/tshark children. The OS already delivered SIGINT,
        # so they raise KeyboardInterrupt and clean up their own subprocesses.
        executor.shutdown(wait=True, cancel_futures=True)
        progress.finish()
        import sys
        sys.exit(130)


    progress.finish()

    print("\n=== Dataset summary ===")
    print(f"Days:     {len(selected_days)}")
    print(f"Captures: {total_captures}")
    print(f"Failed:   {failed_captures}")
    print(f"Flows:    {total_flows}")
    print(f"Edges:    {total_edges}")


if __name__ == "__main__":
    main()
