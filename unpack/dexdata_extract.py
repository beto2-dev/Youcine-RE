#!/usr/bin/env python3
"""Targeted extractor for ART's [anon:dalvik-DEX data] containers.

Run evidence (34124326711 .. 34129023827, redroid): the directly-launched
Youcine app DECRYPTS AND RUNS, and its maps contain [anon:dalvik-DEX data]
regions - ART's raw dex containers. The generic dd sweep never captured
them (high addresses; toybox dd produced nothing), the packer wipes its
own buffer, and each dex SPANS SEVERAL map entries: big r--p pieces
interleaved with small -wxp pieces (8-32 KiB, no read permission) that a
perms-based filter drops. /proc/<pid>/mem reads use FOLL_FORCE, which
reads write-only pages fine, so pread64 crosses them.

Algorithm:
 1. SIGSTOP the app
 2. cat /proc/<pid>/maps, take EVERY [anon:dalvik-DEX data] entry
    (any perms, any size)
 3. group address-adjacent entries (gap <= 64 KiB) into spans
 4. read each span with tools/memread (static pread64 helper) as ONE
    contiguous range
 5. at each span start (and at any dex magic found inside), parse the
    standard dex header, slice file_size bytes, verify adler32 + sha1
 6. write dex_<n>_<sha12>.bin + dexdata_count.txt, SIGCONT

Usage:
  ANDROID_SERIAL=localhost:5555 python3 unpack/dexdata_extract.py \
      --app com.world.youcinemobile --out-dir dumped/youcine \
      [--memread tools/memread] [--min-size 65536]
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

ADB = os.environ.get("ADB", "adb")
MAP_LINE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)$")
GAP_TOLERANCE = 0x10000  # 64 KiB: -wxp pieces sit right between r--p ones


def adb_shell(cmd: str, timeout: float = 60.0):
    return subprocess.run([ADB, "shell", cmd], capture_output=True,
                          timeout=timeout)


def pid_of(app: str):
    r = adb_shell(f"pidof {app}", 15)
    txt = (r.stdout or b"").decode("utf-8", "replace").strip()
    if txt.split():
        try:
            return int(txt.split()[0])
        except ValueError:
            pass
    return None


def dex_headers_in(data: bytes):
    """Yield (offset, file_size, adler32, sha1) for every plausible
    standard-dex header in the blob."""
    off = 0
    while True:
        i = data.find(b"dex\n", off)
        if i < 0:
            return
        if (i + 0x70 <= len(data) and data[i + 4:i + 7].isdigit()
                and data[i + 7] == 0):
            fsize = struct.unpack_from("<I", data, i + 32)[0]
            if 0x70 <= fsize <= 80_000_000:
                adler = struct.unpack_from("<I", data, i + 8)[0]
                sha1 = data[i + 12:i + 32]
                yield i, fsize, adler, sha1
        off = i + 4


def main() -> int:
    ap = argparse.ArgumentParser(description="dalvik-DEX data extractor")
    ap.add_argument("--app", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--memread", default="tools/memread")
    ap.add_argument("--min-size", type=int, default=65536,
                    help="min size of a dex candidate")
    ap.add_argument("--keep-frozen", action="store_true")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    memread = Path(args.memread)
    if not memread.exists():
        print(f"[!] memread helper missing: {memread} (compile tools/memread.c)",
              flush=True)
        return 2

    pid = pid_of(args.app)
    if pid is None:
        print(f"[!] {args.app} is not running", flush=True)
        return 2
    print(f"[*] pid {pid}", flush=True)

    adb_shell(f"kill -STOP {pid}", 15)
    time.sleep(0.5)

    r = adb_shell(f"cat /proc/{pid}/maps", 30)
    maps = (r.stdout or b"").decode("utf-8", "replace")

    entries = []  # (start, end, perms, path)
    for line in maps.splitlines():
        m = MAP_LINE.match(line)
        if not m:
            continue
        start_s, end_s, perms, path = m.groups()
        if "DEX data" not in path and "dex data" not in path:
            continue
        entries.append((int(start_s, 16), int(end_s, 16), perms))
    # ALL perms are kept: the -wxp pieces (no read bit) between the big
    # r--p ones belong to the same dex container and pread64/FOLL_FORCE
    # reads them anyway.
    entries.sort()
    print(f"[*] {len(entries)} DEX-data map entries (any perms)", flush=True)
    if not entries:
        adb_shell(f"kill -CONT {pid}", 15)
        print("[!] no DEX data regions found (app not decrypted?)", flush=True)
        return 1

    # group into spans
    spans = []  # (start, end, piece_count)
    cur_s, cur_e, cnt = entries[0][0], entries[0][1], 1
    for s, e, _ in entries[1:]:
        if s - cur_e <= GAP_TOLERANCE:
            cur_e = max(cur_e, e)
            cnt += 1
        else:
            spans.append((cur_s, cur_e, cnt))
            cur_s, cur_e, cnt = s, e, 1
    spans.append((cur_s, cur_e, cnt))
    print(f"[*] {len(spans)} contiguous span(s)", flush=True)
    for i, (s, e, c) in enumerate(spans):
        print(f"    span {i}: {s:x}-{e:x} ({(e-s)/1048576:.1f} MB, "
              f"{c} pieces)", flush=True)

    r = subprocess.run([ADB, "push", str(memread), "/data/local/tmp/memread"],
                       capture_output=True, timeout=60)
    if r.returncode != 0:
        adb_shell(f"kill -CONT {pid}", 15)
        print("[!] adb push memread failed", flush=True)
        return 2
    adb_shell("chmod 755 /data/local/tmp/memread", 15)

    seen: set[str] = set()
    n_ok = 0
    n_bad = 0
    for i, (s, e, cnt) in enumerate(spans):
        size = e - s
        if size < 4096:
            continue
        remote = f"/data/local/tmp/span_{i:02d}.bin"
        r = adb_shell(
            f"/data/local/tmp/memread {pid} {s:x} {size} {remote}", 600)
        err = (r.stderr or b"").decode("utf-8", "replace").strip()
        print(f"[*] span {i} ({size} bytes): {err}", flush=True)
        r2 = subprocess.run([ADB, "exec-out", f"cat {remote}"],
                            capture_output=True, timeout=600)
        data = r2.stdout or b""
        adb_shell(f"rm -f {remote}", 15)
        if not data:
            print(f"[!] span {i}: nothing pulled", flush=True)
            continue
        # keep raw span for offline analysis
        (out_dir / f"span_{i:02d}.raw").write_bytes(data)
        for off, fsize, adler, sha1 in dex_headers_in(data):
            if fsize < args.min_size:
                continue
            dex = data[off:off + fsize]
            if len(dex) < fsize:
                print(f"[!] span {i} dex @+{off}: truncated "
                      f"({len(dex)}/{fsize})", flush=True)
                n_bad += 1
                continue
            adler_calc = zlib.adler32(dex[12:]) & 0xFFFFFFFF
            sha1_calc = hashlib.sha1(dex[32:]).digest()
            digest = hashlib.sha256(dex).hexdigest()
            ok = (adler_calc == adler) and (sha1_calc == sha1)
            tag = "VALID" if ok else "INVALID(checksum)"
            print(f"[{'+' if ok else '!'}] span {i} dex @+{off}: {fsize} "
                  f"bytes {tag} sha256={digest[:12]}", flush=True)
            if digest in seen:
                continue
            seen.add(digest)
            name = out_dir / f"dex_{len(seen):02d}_{digest[:12]}.bin"
            name.write_bytes(dex)
            if ok:
                n_ok += 1
            else:
                n_bad += 1

    if not args.keep_frozen:
        adb_shell(f"kill -CONT {pid}", 15)

    (out_dir / "dexdata_count.txt").write_text(f"{n_ok}\n")
    print(f"[*] dexdata extraction: {n_ok} checksum-valid dex "
          f"({n_bad} invalid) in {len(seen)} candidates", flush=True)
    return 0 if n_ok else 1


if __name__ == "__main__":
    sys.exit(main())
