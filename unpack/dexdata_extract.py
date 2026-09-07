#!/usr/bin/env python3
"""Targeted extractor for ART's [anon:dalvik-DEX data] containers.

Run evidence (34124326711 / 34127034994, redroid): the directly-launched
Youcine app DECRYPTS AND RUNS (activities displayed, app libs loaded), and
its frozen maps contain [anon:dalvik-DEX data] regions of 10.2 / 7.8 / 6.1
MB - the raw decrypted dex containers. The generic dd sweep never captured
them (high addresses), and the packer wipes the original buffer, so this
targeted path is the primary extraction vector:

 1. freeze the app (SIGSTOP)
 2. cat /proc/<pid>/maps, select every [anon:dalvik-DEX data] region
    (fallback: any *DEX* named anon region)
 3. push tools/memread (static arm64 pread64 helper, compiled by the
    workflow) and run it per region -> exact byte range
 4. pull, validate the standard dex header locally, dedupe, write
    dex_<n>_<sha>.bin + dexdata_count.txt
 5. SIGCONT the app

Regions smaller than --min-size are skipped (the 13.6 KB packer stub dex
lives in a 'dalvik-DEX data' region too on some builds).

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
import subprocess
import sys
import time
from pathlib import Path

ADB = os.environ.get("ADB", "adb")
MAP_LINE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)$")


def adb_shell(cmd: str, timeout: float = 30.0):
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


def main() -> int:
    ap = argparse.ArgumentParser(description="dalvik-DEX data extractor")
    ap.add_argument("--app", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--memread", default="tools/memread")
    ap.add_argument("--min-size", type=int, default=65536)
    ap.add_argument("--keep-frozen", action="store_true",
                    help="do not SIGCONT at the end")
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

    targets = []  # (start, end, size, name)
    for line in maps.splitlines():
        m = MAP_LINE.match(line)
        if not m:
            continue
        start_s, end_s, perms, path = m.groups()
        if "r" not in perms:
            continue
        if "DEX data" not in path and "dex data" not in path:
            # fallback pattern: any dalvik-named DEX-ish region
            if not ("dalvik" in path and "dex" in path.lower()):
                continue
        start, end = int(start_s, 16), int(end_s, 16)
        size = end - start
        if size < args.min_size:
            print(f"[-] skip small {path!r} region {start_s}-{end_s} "
                  f"({size} bytes)", flush=True)
            continue
        targets.append((start, end, size, path))
    print(f"[*] {len(targets)} DEX-data region(s) >= {args.min_size} bytes",
          flush=True)
    if not targets:
        adb_shell(f"kill -CONT {pid}", 15)
        print("[!] no DEX data regions found (app not decrypted?)", flush=True)
        return 1

    # push the helper
    r = subprocess.run([ADB, "push", str(memread), "/data/local/tmp/memread"],
                       capture_output=True, timeout=60)
    if r.returncode != 0:
        adb_shell(f"kill -CONT {pid}", 15)
        print("[!] adb push memread failed", flush=True)
        return 2
    adb_shell("chmod 755 /data/local/tmp/memread", 15)

    seen: dict[str, bytes] = {}
    n = 0
    for i, (start, end, size, name) in enumerate(targets):
        remote = f"/data/local/tmp/dexdata_{i:02d}.bin"
        hexaddr = f"{start:x}"
        r = adb_shell(
            f"/data/local/tmp/memread {pid} {hexaddr} {size} {remote}", 300)
        err = (r.stderr or b"").decode("utf-8", "replace").strip()
        print(f"[*] region {start:x}-{end:x} ({size} bytes, {name!r}): {err}",
              flush=True)
        local = out_dir / f"dexdata_{i:02d}.raw"
        r2 = subprocess.run([ADB, "exec-out", f"cat {remote}"],
                            capture_output=True, timeout=300)
        data = r2.stdout or b""
        adb_shell(f"rm -f {remote}", 15)
        if len(data) != size:
            print(f"[!] pulled {len(data)} of {size} bytes for region {i}",
                  flush=True)
        if not data:
            local.unlink(missing_ok=True)
            continue
        local.write_bytes(data)
        # validate: a standard dex header inside (usually at offset 0)
        off = data.find(b"dex\n")
        while off >= 0:
            if off + 0x70 <= len(data):
                hdr = data[off:off + 4]
                ver = data[off + 4:off + 8]
                fsize = int.from_bytes(data[off + 32:off + 36], "little")
                if (ver[:3].isdigit() and ver[3] == 0 and
                        0x70 <= fsize <= 80_000_000 and off + fsize <= len(data)):
                    dex = data[off:off + fsize]
                    digest = hashlib.sha256(dex).hexdigest()
                    if digest not in seen:
                        seen[digest] = dex
                        n += 1
                        name_out = out_dir / f"dex_{n:02d}_{digest[:12]}.bin"
                        name_out.write_bytes(dex)
                        print(f"[+] dex_{n:02d}_{digest[:12]}.bin {fsize} "
                              f"bytes (region {i} @+{off})", flush=True)
            off = data.find(b"dex\n", off + 4)
        if data[:4] not in (b"dex\n", b"cdex"):
            print(f"[e] region {i} has no dex magic at start "
                  f"({data[:16].hex()})", flush=True)

    if not args.keep_frozen:
        adb_shell(f"kill -CONT {pid}", 15)

    (out_dir / "dexdata_count.txt").write_text(f"{n}\n")
    print(f"[*] dexdata extraction: {n} unique standard dex", flush=True)
    return 0 if n else 1


if __name__ == "__main__":
    sys.exit(main())
