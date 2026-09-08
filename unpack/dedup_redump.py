#!/usr/bin/env python3
"""Dedup the phase-2 re-dump snapshots into the 5 most-materialized DEXes.

WHY: the phase-2 warm-up interleaves SIGSTOP re-dump snapshots every 20
batches (checkpoint 20..160, run 34193490749), and every snapshot round
writes EVERY DEX image it finds in /proc/<pid>/maps.  validate_and_extract_dex.py
then de-duplicates only by sha256, so ONE run leaves several snapshots of
the SAME dex (16 files -> 5 unique layouts):
    5 x 11865264  1 x 11477164  4 x 10864568  5 x 6313996  1 x 619752

iJiami's extraction stubs only materialize a method body when its class
is initialized, so snapshots taken LATER in the warm-up carry MORE real
bodies.  The checkpoint provenance is lost in the filenames (the output
is size-sorted), so this tool picks the best snapshot per size-group by
CONTENT: the snapshot that differs the most from the pristine phase-1
static dump of the same size is the most materialized one.

The tool also verifies the basics of every candidate (magic, file_size
field) and writes the winners as a canonical classes.dex..classesN.dex
set (largest first) ready for rebuild_unpacked_apk.py --dump-dir.

Usage:
  python3 unpack/dedup_redump.py \
      --redump-dir  work/redump-dexes \
      --baseline-dir work/dump-dexes \
      --out-dir     work/booteable-dexes
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

DEX_MAGIC = b"dex\n"


def dex_file_size(data: bytes) -> int:
    """Header field 32..36 = file_size.  0 when unreadable."""
    if len(data) < 40 or not data.startswith(DEX_MAGIC):
        return 0
    return struct.unpack_from("<I", data, 32)[0]


def load_dexes(d: Path) -> list[Path]:
    return sorted(
        (p for p in d.glob("*.dex") if p.is_file()),
        key=lambda p: p.stat().st_size,
    )


def diff_score(a: bytes, b: bytes) -> int:
    """Number of differing bytes (same length expected; min-length safe)."""
    if len(a) != len(b):  # pragma: no cover - grouped by exact size anyway
        n = min(len(a), len(b))
    else:
        n = len(a)
    step = 8  # scan in 8-byte words: exact byte count is not needed, only the ranking
    diff = 0
    for off in range(0, n, step):
        if a[off:off + step] != b[off:off + step]:
            chunk = min(step, n - off)
            diff += sum(1 for i in range(chunk) if a[off + i] != b[off + i])
    return diff


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--redump-dir", required=True, type=Path,
                    help="directory with the phase-2 classes*.dex snapshots")
    ap.add_argument("--baseline-dir", required=True, type=Path,
                    help="directory with the pristine phase-1 dump DEXes")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="output directory for the deduplicated dex set")
    args = ap.parse_args()

    redump = load_dexes(args.redump_dir)
    baseline = load_dexes(args.baseline_dir)
    if not redump:
        print(f"[!] no classes*.dex under {args.redump_dir}", flush=True)
        return 1
    if not baseline:
        print(f"[!] no classes*.dex under {args.baseline_dir}", flush=True)
        return 1

    baselines = {}  # file size on disk -> bytes
    for p in baseline:
        baselines.setdefault(p.stat().st_size, p.read_bytes())

    groups: dict[int, list[Path]] = {}
    for p in redump:
        size = p.stat().st_size
        declared = dex_file_size(p.read_bytes()[:40])
        if declared != size:
            print(f"[!] {p.name}: header file_size {declared} != disk {size}"
                  " (kept, but suspicious)", flush=True)
        groups.setdefault(size, []).append(p)

    winners: list[tuple[int, Path]] = []
    for size in sorted(groups, reverse=True):
        cands = groups[size]
        base = baselines.get(size)
        scored = []
        for p in cands:
            data = p.read_bytes()
            if not data.startswith(DEX_MAGIC):
                print(f"[!] {p.name}: bad magic - skipped", flush=True)
                continue
            score = (diff_score(data, base) if base is not None else -1)
            sha = hashlib.sha256(data).hexdigest()[:12]
            scored.append((score, p, sha))
        if not scored:
            continue
        if base is None:
            print(f"[!] no phase-1 baseline of {size} bytes - keeping the"
                  f" FIRST snapshot ({scored[0][1].name})", flush=True)
            best = scored[0]
        else:
            # most differing bytes vs the pristine stub dump = most
            # extraction-stub bodies replaced by real code
            best = max(scored, key=lambda t: t[0])
        for score, p, sha in sorted(scored, key=lambda t: -t[0]):
            tag = "WINNER" if p == best[1] else "      "
            print(f"[{tag}] {p.name} {size}B sha256={sha} "
                  f"diff_vs_phase1={score}B", flush=True)
        winners.append((size, best[1]))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for i, (size, p) in enumerate(winners, start=1):
        name = "classes.dex" if i == 1 else f"classes{i}.dex"
        data = p.read_bytes()
        (args.out_dir / name).write_bytes(data)
        print(f"[+] {name} <- {p.name} ({size}B, "
              f"{len(data)} bytes, sha256="
              f"{hashlib.sha256(data).hexdigest()})", flush=True)
    print(f"[*] wrote {len(winners)} deduplicated DEXes -> {args.out_dir}",
          flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
