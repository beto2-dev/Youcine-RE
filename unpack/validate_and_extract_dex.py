#!/usr/bin/env python3
"""Validate dumped blobs and write canonical classes*.dex files."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def is_dex(data: bytes) -> bool:
    if len(data) < 0x70:
        return False
    if not data.startswith(b"dex\n"):
        return False
    if data[7] != 0 or not data[4:7].isdigit():
        return False
    size = int.from_bytes(data[32:36], "little")
    return size == len(data) and 0x70 <= size <= 80_000_000


def is_cdex(data: bytes) -> bool:
    """CompactDex blob (ART in-memory representation). Not directly
    loadable - kept for offline cdex->dex conversion in the rebuild flow."""
    return (len(data) >= 0x38 and data.startswith(b"cdex")
            and data[4:7].isdigit())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument(
        "--min-size",
        type=int,
        default=0x70,
        help="drop DEX blobs smaller than this (packer stub is ~14 KiB)",
    )
    args = ap.parse_args()
    dump_dir = Path(args.dump_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    blobs = []
    cdex_files = []
    for p in sorted(dump_dir.glob("*")):
        if not p.is_file():
            continue
        data = p.read_bytes()
        if is_dex(data) and len(data) >= args.min_size:
            blobs.append(data)
            continue
        if is_cdex(data) and len(data) >= args.min_size:
            cdex_files.append((p, data))
    # de-dupe by sha256, keep largest unique
    uniq = {}
    for b in blobs:
        uniq[hashlib.sha256(b).hexdigest()] = b
    ordered = sorted(uniq.values(), key=lambda x: -len(x))
    for p, data in cdex_files:
        (out_dir / ("compact_" + p.name)).write_bytes(data)
        print(f"[e] {p.name}: compact-dex blob {len(data)} bytes -> "
              f"compact_{p.name} (needs cdex->dex conversion)", flush=True)
    if not ordered:
        print("[!] no valid standard DEX in dump dir", flush=True)
        return 0 if cdex_files else 1
    for i, b in enumerate(ordered):
        name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
        (out_dir / name).write_bytes(b)
        print(f"[+] {name} {len(b)} sha256={hashlib.sha256(b).hexdigest()}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
