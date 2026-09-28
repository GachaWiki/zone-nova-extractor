#!/usr/bin/env python3
"""Locate encrypted Zone Nova master data blobs by magic bytes.

The live master data is a hash-named raw AES file (NOT a Unity bundle;
UnityPy and bundle indexers silently skip it). It is identified by its
first 8 bytes: b5 61 2a 39 2a 41 b8 09. Finds such files in a pulled
directory tree, and inside zip/apk archives (scanning decompressed
entries, e.g. the APK builtin copy at assets/bin/Data/...).

Usage:
    python find_masterdata.py <dir-or-archive> [more paths...]
"""
import sys
import zipfile
from pathlib import Path

MAGIC = bytes.fromhex("b5612a392a41b809")


def check_bytes(data: bytes) -> bool:
    return data.startswith(MAGIC)


def scan_file(path: Path) -> list[tuple[str, int]]:
    hits = []
    with path.open("rb") as f:
        if check_bytes(f.read(8)):
            hits.append((str(path), path.stat().st_size))
    return hits


def scan_zip(path: Path) -> list[tuple[str, int]]:
    hits = []
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            with z.open(info) as f:
                if check_bytes(f.read(8)):
                    hits.append((f"{path}!{info.filename}", info.file_size))
    return hits


def scan(path: Path) -> list[tuple[str, int]]:
    if path.is_file():
        if zipfile.is_zipfile(path):
            return scan_zip(path)
        return scan_file(path)
    hits = []
    for p in sorted(path.rglob("*")):
        if not p.is_file():
            continue
        try:
            if zipfile.is_zipfile(p):
                hits += scan_zip(p)
            else:
                hits += scan_file(p)
        except OSError as e:
            print(f"  (skipping {p}: {e})", file=sys.stderr)
    return hits


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    found = []
    for arg in sys.argv[1:]:
        found += scan(Path(arg))
    if not found:
        print("no master data blob found (expected magic b5 61 2a 39 2a 41 b8 09)")
        return 1
    for name, size in found:
        print(f"{size:>12,} bytes  {name}")
    print("\nnext: python decrypt.py <file> -o master-data.bin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
