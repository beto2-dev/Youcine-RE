#!/usr/bin/env python3
"""Out-of-process DEX dump via rooted adb (/proc/<pid>/maps + /proc/<pid>/mem).

iJiami libexec.so uses ptrace. An in-process Frida agent is optional and may
be killed; this dumper never maps into the target.

Environment:
  ADB   adb binary (default: adb on PATH)

Usage:
  python3 unpack/external_memdump.py --app com.world.youcinemobile --out-dir dumped
"""
from __future__ import annotations

import argparse
import os
import subprocess
import time
from pathlib import Path

DEX_MAGIC = b"dex\n"

ADB = os.environ.get("ADB", "adb")


def adb(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [ADB, *args],
        check=False,
        capture_output=True,
        timeout=timeout,
    )


def adb_bytes(*args: str, timeout: int = 60) -> bytes:
    p = adb(*args, timeout=timeout)
    return p.stdout or b""


def pid_of(app: str) -> int | None:
    for cmd in (("pidof", app), ("pidof", "-s", app)):
        p = adb("shell", *cmd)
        text = (p.stdout or b"").decode("utf-8", "replace").strip()
        if text.split():
            try:
                return int(text.split()[0])
            except ValueError:
                continue
    p = adb("shell", "ps", "-A")
    for line in (p.stdout or b"").decode("utf-8", "replace").splitlines():
        if app in line.split():
            parts = line.split()
            for tok in parts:
                if tok.isdigit():
                    return int(tok)
    return None


def parse_maps(maps: str) -> list[tuple[int, int, str, str]]:
    regions = []
    for line in maps.splitlines():
        # addr-addr perms offset dev inode pathname
        try:
            addr, rest = line.split(" ", 1)
            start_s, end_s = addr.split("-")
            start, end = int(start_s, 16), int(end_s, 16)
        except ValueError:
            continue
        perms = rest[:4] if len(rest) >= 4 else rest
        path = rest[rest.find("/") :] if "/" in rest else rest.split()[-1] if rest.split() else ""
        regions.append((start, end, perms, path))
    return regions


def pull_chunk(pid: int, start: int, size: int) -> bytes:
    # dd from /proc/pid/mem; skip is in bytes via ibs=1 (slow but portable)
    # Use a small helper on-device with toybox dd if possible.
    cmd = (
        f"dd if=/proc/{pid}/mem bs=4096 skip={start // 4096} "
        f"count={(size + 4095) // 4096} 2>/dev/null"
    )
    p = adb("exec-out", "su", "-c", cmd, timeout=120)
    data = p.stdout or b""
    off = start % 4096
    return data[off : off + size] if data else b""


def pull_chunk_run_as(pid: int, start: int, size: int) -> bytes:
    # Fallback without su: adb root makes this work as shell.
    cmd = (
        f"dd if=/proc/{pid}/mem bs=4096 skip={start // 4096} "
        f"count={(size + 4095) // 4096} 2>/dev/null"
    )
    p = adb("exec-out", "sh", "-c", cmd, timeout=120)
    data = p.stdout or b""
    off = start % 4096
    return data[off : off + size] if data else b""


def extract_dex(blob: bytes) -> list[bytes]:
    found = []
    idx = 0
    while True:
        i = blob.find(DEX_MAGIC, idx)
        if i < 0:
            break
        if i + 8 > len(blob):
            break
        # dex\n035\0 or dex\n037\0 etc.
        if not (blob[i + 4 : i + 7].isdigit() and blob[i + 7] == 0):
            idx = i + 4
            continue
        if i + 0x70 > len(blob):
            break
        file_size = int.from_bytes(blob[i + 32 : i + 36], "little")
        if file_size < 0x70 or file_size > 80_000_000 or i + file_size > len(blob):
            idx = i + 4
            continue
        found.append(blob[i : i + file_size])
        idx = i + file_size
    return found


def dump_once(pid: int, out_dir: Path, seen: set[bytes]) -> int:
    maps = adb_bytes("shell", "cat", f"/proc/{pid}/maps").decode("utf-8", "replace")
    if not maps.strip():
        print(f"[!] empty maps for pid {pid}", flush=True)
        return 0
    added = 0
    for start, end, perms, path in parse_maps(maps):
        size = end - start
        if size <= 0 or size > 96_000_000:
            continue
        interesting = (
            "r" in perms
            and (
                "dalvik" in path.lower()
                or "dex" in path.lower()
                or path in ("", "[anon:dalvik-main space]", "[heap]")
                or path.startswith("[anon")
                or "app_dex" in path
                or "jit-cache" in path
            )
        )
        # Always scan anonymous RW and large R-- mappings.
        if not interesting:
            if "rw" in perms and size >= 0x10000 and ("/" not in path or "dalvik" in path):
                interesting = True
        if not interesting:
            continue
        blob = pull_chunk(pid, start, size)
        if not blob:
            blob = pull_chunk_run_as(pid, start, size)
        if not blob:
            continue
        for dex in extract_dex(blob):
            digest = hashlib_sha256(dex)
            if digest in seen:
                continue
            seen.add(digest)
            name = f"dex_{len(seen):02d}_{digest[:12]}.bin"
            (out_dir / name).write_bytes(dex)
            print(f"[+] {name} {len(dex)} bytes from {path or 'anon'} {hex(start)}", flush=True)
            added += 1
    return added


def hashlib_sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Out-of-process iJiami DEX dump")
    ap.add_argument("--app", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--sweep-delays", default="2,4,8,15,30")
    args = ap.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    delays = [int(x) for x in args.sweep_delays.split(",") if x.strip()]
    seen: set[bytes] = set()
    for delay in delays:
        print(f"[*] sleep {delay}s then sweep", flush=True)
        time.sleep(delay)
        pid = pid_of(args.app)
        if pid is None:
            print("[!] app pid not found", flush=True)
            continue
        print(f"[*] pid {pid}", flush=True)
        try:
            dump_once(pid, out_dir, seen)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] sweep failed: {exc}", flush=True)
    print(f"[*] unique dumps: {len(seen)}", flush=True)
    return 0 if seen else 1


if __name__ == "__main__":
    raise SystemExit(main())
