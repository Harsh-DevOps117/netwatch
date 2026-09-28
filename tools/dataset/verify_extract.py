"""Check an extracted zip against the archive's own sizes and CRC-32 checksums.

Run: python3 tools/dataset/verify_extract.py data/raw/<day>/pcap.zip data/raw/<day>

Reads every extracted file end to end and compares it with the checksum stored in the
zip, so a truncated, missing or altered file is reported by name. Exit code 1 on any
problem, 0 when every file matches.
"""
import os
import sys
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def check(entry: zipfile.ZipInfo, dest: Path) -> str | None:
    """One archive entry against its extracted file; None when they match."""
    path = dest / entry.filename
    if not path.is_file():
        return f"MISSING {entry.filename}"
    if path.stat().st_size != entry.file_size:
        return f"SIZE    {entry.filename}: {path.stat().st_size:,} vs {entry.file_size:,}"
    crc = 0
    with open(path, "rb") as f:
        while chunk := f.read(8 << 20):
            crc = zlib.crc32(chunk, crc)
        os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)   # do not fill memory with cache
    return None if crc == entry.CRC else f"CRC     {entry.filename}"


if __name__ == "__main__":
    archive, dest = sys.argv[1], Path(sys.argv[2])
    entries = [e for e in zipfile.ZipFile(archive).infolist() if not e.is_dir()]
    with ThreadPoolExecutor(4) as pool:
        problems = [p for p in pool.map(lambda e: check(e, dest), entries) if p]
    print(f"{archive}: {len(entries)} files checked, {len(problems)} problems")
    for p in problems:
        print("  " + p)
    sys.exit(1 if problems else 0)
