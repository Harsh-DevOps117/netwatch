"""Extract a zip without filling memory, safe to stop and resume.

Run: python3 tools/dataset/extract_zip.py data/raw/<day>/pcap.zip data/raw/<day>

Each file streams out of the archive into `<name>.part`, its CRC-32 is checked while it
is written, and it is renamed to its real name only when complete, so an interrupted run
never leaves a truncated file under a final name. A file already present at its full
size is skipped, so a rerun resumes. After each file the written data and the archive
pages just read are released from the page cache: extracting tens of GB otherwise fills
memory with cached file data, which is what stopped the first attempt.
"""
import os
import time
import sys
import zipfile
import zlib
from pathlib import Path

CHUNK = 16 << 20
RELEASE_EVERY = 64 << 20
LOW_MEMORY = 2 << 30


def free_memory() -> int:
    """MemFree in bytes, from /proc/meminfo."""
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemFree:"):
                return int(line.split()[1]) << 10
    return 0


def wait_for_memory() -> None:
    """Pause while free memory is below LOW_MEMORY; the partly written file waits unrenamed."""
    while free_memory() < LOW_MEMORY:
        time.sleep(5)


def release(fd: int) -> None:
    """Drop a file's cached pages; data already flushed to disk stays on disk."""
    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)


def extract(archive: str, dest: Path) -> tuple[int, int]:
    """Extract every file not already complete; returns (extracted, skipped)."""
    done = skipped = 0
    with open(archive, "rb") as raw, zipfile.ZipFile(raw) as z:
        entries = [e for e in z.infolist() if not e.is_dir()]
        for n, entry in enumerate(entries, 1):
            target = dest / entry.filename
            part = target.with_name(target.name + ".part")
            if target.is_file() and target.stat().st_size == entry.file_size:
                part.unlink(missing_ok=True)   # leftover of an interrupted earlier run
                skipped += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            crc = written = 0
            with z.open(entry) as src, open(part, "wb") as out:
                while chunk := src.read(CHUNK):
                    out.write(chunk)
                    crc = zlib.crc32(chunk, crc)
                    written += len(chunk)
                    if written % RELEASE_EVERY < CHUNK:
                        # Flush and drop this file's and the archive's cached pages incrementally,
                        # so even a 3.5 GB entry never piles up in memory
                        out.flush(); os.fdatasync(out.fileno())
                        release(out.fileno()); release(raw.fileno())
                        wait_for_memory()
                out.flush()
                os.fsync(out.fileno())
                release(out.fileno())
            release(raw.fileno())
            if crc != entry.CRC or part.stat().st_size != entry.file_size:
                part.unlink()
                raise SystemExit(f"CRC or size mismatch on {entry.filename}; nothing renamed")
            os.replace(part, target)
            done += 1
            print(f"{n}/{len(entries)} {entry.filename} {entry.file_size / 1e6:,.0f} MB, free {free_memory() / 2**30:.1f} GiB", flush=True)
    return done, skipped


if __name__ == "__main__":
    extracted, skipped = extract(sys.argv[1], Path(sys.argv[2]))
    print(f"extracted {extracted}, already complete {skipped}")
