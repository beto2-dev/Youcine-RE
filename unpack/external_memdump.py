#!/usr/bin/env python3
"""Poll-and-freeze out-of-process DEX dump via rooted adb.

iJiami's libexec.so uses ptrace-based anti-debug, so we never inject into
the target. Strategy:

 1. poll `pidof <app>` until the process appears (caller does `am start`)
 2. sleep --settle seconds so s.h.e.l.l.N.al() decrypts assets/ijiami.dat
    (decryption happens in attachBaseContext, long before any Activity)
 3. SIGSTOP the process: freezes packer watchdogs, anti-debug timers and
    post-decrypt crashes; /proc/<pid>/mem is now stable
 4. batch-sweep maps+mem ON-DEVICE with a root shell (one dd per region),
    stream the region files out with `adb exec-out tar` (no pty mangling)
 5. scan locally for DEX magic, validate headers, dedupe by sha256
 6. SIGCONT, wait, freeze again; stop after --expect unique DEX or
    --timeout, or after 3 consecutive sweeps without new findings
 7. optionally tar /data/data/<app> (packers sometimes drop the decrypted
    dex on disk)

Usage:
  python3 unpack/external_memdump.py --app com.world.youcinemobile \
      --out-dir dumped/youcine --expect 4 --timeout 300

Exit code: 0 if at least one unique DEX was captured.
Writes: <out-dir>/*.bin (raw DEX), <out-dir>/dex_count.txt,
        <out-dir>/appdata.tar (optional), <out-dir>/maps_snapshot.txt
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

DEX_MAGIC = b"dex\n"
# ART keeps in-memory dex as CompactDex (magic "cdex0011") when the class
# data has been dequickened - run 34122336734 (redroid): the app ran real
# code (activities displayed, app native libs loaded) but 8 memory sweeps
# found ZERO b"dex\n" - the decrypted classes live on as compact dex.
CDEX_MAGIC = b"cdex"
VDEX_MAGIC = b"vdex"
MAX_REGION = 96_000_000
MIN_REGION = 0x10000

ADB = os.environ.get("ADB", "adb")

# POSIX sh sweep script executed as root on the device.
# Filter: readable regions, >= 64 KiB; file-backed paths only when they
# look dex/dalvik/memfd related; anonymous + [anon:*] + [heap] always.
# Regions larger than 64 MiB (the 1 GiB dalvik region space!) are swept
# in 64 MiB chunks with a 2 MiB overlap so a DEX straddling a chunk
# boundary is still captured whole.
SWEEP_SH = r"""#!/system/bin/sh
# usage: sweep.sh PID OUTDIR
PID="$1"
OUT="$2"
rm -rf "$OUT"
mkdir -p "$OUT"
cp "/proc/$PID/maps" "$OUT/maps.txt" 2>/dev/null
CHUNK=$((64*1024*1024))
OVL=$((2*1024*1024))
while IFS= read -r line; do
  addr=${line%% *}
  case "$addr" in
    *-*) ;;
    *) continue ;;
  esac
  rest=${line#* }
  perms=${rest%% *}
  path=${line##* }
  start=$(( 0x${addr%%-*} ))
  end=$(( 0x${addr##*-} ))
  sz=$(( end - start ))
  [ "$sz" -lt MINREGION ] && continue
  case "$perms" in
    r*) ;;
    *) continue ;;
  esac
  case "$path" in
    /apex/*|/system/*|/vendor/*|/product/*|/data/*|/dev/*|/proc/*)
      case "$path" in
        *dalvik*|*dex*|*memfd*|*cache*) ;;
        *) continue ;;
      esac
      ;;
  esac
  off=0
  while [ $off -lt $sz ]; do
    csz=$(( CHUNK + OVL ))
    rem=$(( sz - off ))
    [ $csz -gt $rem ] && csz=$rem
    addr2=$(( start + off ))
    skip=$(( addr2 / 4096 ))
    cnt=$(( (csz + 4095) / 4096 ))
    dd if="/proc/$PID/mem" of="$OUT/r_$(printf %x $addr2)_$csz.bin" bs=4096 skip=$skip count=$cnt 2>/dev/null
    off=$(( off + CHUNK ))
  done
done < "/proc/$PID/maps"
sync
"""

DEV_SWEEP = "/data/local/tmp/yc_sweep.sh"
DEV_OUT = "/data/local/tmp/yc_dump"


def adb(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run([ADB, *args], check=False, capture_output=True, timeout=timeout)


def adb_shell(cmd: str, timeout: int = 120) -> subprocess.CompletedProcess:
    # Single string arg -> passed verbatim to the device shell.
    return subprocess.run([ADB, "shell", cmd], check=False, capture_output=True, timeout=timeout)


def pid_of(app: str) -> int | None:
    p = adb_shell(f"pidof {app}", timeout=15)
    text = (p.stdout or b"").decode("utf-8", "replace").strip()
    if text.split():
        try:
            return int(text.split()[0])
        except ValueError:
            pass
    return None


def stop_proc(pid: int) -> None:
    adb_shell(f"kill -STOP {pid}", timeout=15)


def cont_proc(pid: int) -> None:
    adb_shell(f"kill -CONT {pid}", timeout=15)


def kill_proc(pid: int) -> None:
    adb_shell(f"kill -9 {pid}", timeout=15)


def push_sweep_script() -> None:
    sweep = SWEEP_SH.replace("MINREGION", str(MIN_REGION))
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
        fh.write(sweep)
        path = fh.name
    adb("push", path, DEV_SWEEP, timeout=30)
    os.unlink(path)


def batch_sweep(pid: int, local_dir: Path) -> list[Path]:
    """Run the on-device dd sweep and stream the dumps back as a tar."""
    local_dir.mkdir(parents=True, exist_ok=True)
    adb_shell(f"sh {DEV_SWEEP} {pid} {DEV_OUT}", timeout=1500)
    # verify something was produced
    probe = adb_shell(f"ls {DEV_OUT}", timeout=30)
    if b".bin" not in (probe.stdout or b""):
        return []
    tar_path = local_dir / "sweep.tar"
    with open(tar_path, "wb") as fh:
        subprocess.run(
            [ADB, "exec-out", f"tar -cf - -C {DEV_OUT} ."],
            stdout=fh,
            check=False,
            timeout=1800,
        )
    if tar_path.stat().st_size < 1024:
        tar_path.unlink()
        return []
    files: list[Path] = []
    try:
        with tarfile.open(tar_path, "r") as tf:
            tf.extractall(local_dir)  # noqa: S202 - trusted self-produced tar
    except (tarfile.TarError, OSError) as exc:
        print(f"[!] tar extract failed: {exc}", flush=True)
    for p in sorted(local_dir.glob("*.bin")):
        files.append(p)
    # region files may be sparse/empty
    files = [p for p in files if p.stat().st_size > 0]
    return files


def extract_dex(blob: bytes) -> list[bytes]:
    found: list[bytes] = []
    idx = 0
    while True:
        i = blob.find(DEX_MAGIC, idx)
        if i < 0:
            break
        if i + 0x70 > len(blob):
            break
        if not (blob[i + 4 : i + 7].isdigit() and blob[i + 7] == 0):
            idx = i + 4
            continue
        file_size = int.from_bytes(blob[i + 32 : i + 36], "little")
        if file_size < 0x70 or file_size > 80_000_000 or i + file_size > len(blob):
            idx = i + 4
            continue
        found.append(blob[i : i + file_size])
        idx = i + file_size
    return found


def _cdex_size(blob: bytes, i: int) -> int | None:
    """Best-effort total size of the compact dex starting at i.

    CompactDex::Header layout is not fully documented: try file_size at the
    standard-dex offset 0x20 and fall back to the map_off at 0x34. Both are
    validated against sanity ranges; on failure the caller caps the blob.
    """
    if i + 0x38 > len(blob):
        return None
    fsize = int.from_bytes(blob[i + 0x20 : i + 0x24], "little")
    map_off = int.from_bytes(blob[i + 0x34 : i + 0x38], "little")
    if 0x70 <= fsize <= 80_000_000 and i + fsize <= len(blob):
        return fsize
    if 0x28 <= map_off <= len(blob) - i:
        # map list lives at the end: map_off + 24*entries + 12 is close to
        # the total size; use it only when file_size is unusable
        return None
    return None


def extract_cdex(blob: bytes, out_prefix: str, out_dir: Path,
                 seen_cdx: set[str]) -> int:
    """Capture compact-dex blobs: whole-bounded regions around the magic.

    A trailing region of up to 16 MiB (or up to the next cdex magic) is
    captured as cdexraw evidence; the rebuild stage converts/trims offline.
    Returns number of new files written."""
    written = 0
    idx = 0
    positions: list[int] = []
    while True:
        i = blob.find(CDEX_MAGIC, idx)
        if i < 0:
            break
        if i + 8 <= len(blob) and blob[i + 4 : i + 7].isdigit() and blob[i + 8 - 1 : i + 8] == b"\x00":
            positions.append(i)
        idx = i + 4
    for i in positions:
        size = _cdex_size(blob, i)
        if size is None:
            # cap: next magic or 16 MiB
            nxt = min([p for p in positions if p > i] + [i + 16 * 1024 * 1024, len(blob)])
            size = nxt - i
        chunk = blob[i : i + size]
        digest = hashlib.sha256(chunk).hexdigest()
        if digest in seen_cdx:
            continue
        seen_cdx.add(digest)
        (out_dir / f"{out_prefix}_{len(seen_cdx):02d}_{digest[:12]}.cdex").write_bytes(chunk)
        print(f"[+] cdex blob {size} bytes @+{i}", flush=True)
        written += 1
    return written


def diagnose_magics(files: list[Path]) -> dict[str, int]:
    """Count raw magic occurrences in the pulled regions (debug evidence)."""
    counts = {"dex\n": 0, "cdex": 0, "vdex": 0}
    for p in files:
        try:
            blob = p.read_bytes()
        except OSError:
            continue
        counts["dex\n"] += blob.count(DEX_MAGIC)
        counts["cdex"] += blob.count(CDEX_MAGIC)
        counts["vdex"] += blob.count(VDEX_MAGIC)
    return counts


def sweep_local(files: list[Path], out_dir: Path, seen: dict[str, bytes],
                seen_cdx: set[str]) -> int:
    added = 0
    for p in files:
        try:
            blob = p.read_bytes()
        except OSError:
            continue
        if not blob:
            continue
        for dex in extract_dex(blob):
            digest = hashlib.sha256(dex).hexdigest()
            if digest in seen:
                continue
            seen[digest] = dex
            name = f"dex_{len(seen):02d}_{digest[:12]}.bin"
            (out_dir / name).write_bytes(dex)
            print(f"[+] {name} {len(dex)} bytes", flush=True)
            added += 1
        added += extract_cdex(blob, "cdex", out_dir, seen_cdx)
    return added


def save_magic_regions(files: list[Path], out_dir: Path, limit: int = 6) -> None:
    """Preserve raw regions that contain any dex/cdex magic (evidence)."""
    kept = 0
    for p in files:
        if kept >= limit:
            break
        try:
            blob = p.read_bytes()
        except OSError:
            continue
        if DEX_MAGIC in blob or (CDEX_MAGIC + b"00") in blob or VDEX_MAGIC in blob:
            name = out_dir / f"region_{p.name}"
            if not name.exists():
                name.write_bytes(blob[: 32 * 1024 * 1024])
                print(f"[e] kept {name.name} ({len(blob)} bytes, has dex/cdex magic)",
                      flush=True)
                kept += 1


def snapshot_maps(pid: int, out_dir: Path) -> None:
    p = adb_shell(f"cat /proc/{pid}/maps", timeout=30)
    data = p.stdout or b""
    if data:
        (out_dir / "maps_snapshot.txt").write_bytes(data)


def pull_app_data(app: str, out_dir: Path) -> None:
    print("[*] tarring /data/data for on-disk evidence", flush=True)
    tar_path = out_dir / "appdata.tar"
    with open(tar_path, "wb") as fh:
        subprocess.run(
            [ADB, "exec-out", f"tar -cf - -C /data/data {app}"],
            stdout=fh,
            check=False,
            timeout=600,
        )
    if tar_path.stat().st_size < 512:
        tar_path.unlink()
        return
    print(f"[+] app data tar {tar_path.stat().st_size} bytes", flush=True)
    try:
        with tarfile.open(tar_path, "r") as tf:
            names = tf.getnames()
            interesting = [n for n in names if not n.endswith(".so")
                           and tf.getmember(n).size > 0x4000]
            for n in interesting[:40]:
                print(f"    data: {n}", flush=True)
    except (tarfile.TarError, OSError):
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Poll-and-freeze external DEX dump")
    ap.add_argument("--app", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--expect", type=int, default=4, help="unique DEX to stop early")
    ap.add_argument("--timeout", type=int, default=300, help="total seconds")
    ap.add_argument("--settle", type=float, default=1.2, help="seconds to wait after pid appears")
    ap.add_argument("--resweep-gap", type=float, default=6.0, help="seconds between freezes")
    ap.add_argument("--pull-app-data", action="store_true")
    ap.add_argument(
        "--no-freeze",
        action="store_true",
        help="sweep the live process without SIGSTOP (e.g. while a frida tracer is attached)",
    )
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    adb("wait-for-device", timeout=60)
    push_sweep_script()

    seen: dict[str, bytes] = {}
    seen_cdx: set[str] = set()
    deadline = time.time() + args.timeout
    start = time.time()
    pid_seen_once = False
    empty_streak = 0

    while time.time() < deadline:
        pid = pid_of(args.app)
        if pid is None:
            if pid_seen_once and seen:
                # process died after we captured DEX - we are done
                print(f"[*] process gone after {len(seen)} unique dumps", flush=True)
                break
            time.sleep(0.3)
            continue
        pid_seen_once = True
        print(f"[*] pid {pid} up ({time.time() - start:.1f}s); settle {args.settle}s", flush=True)
        time.sleep(args.settle)
        # re-check pid (may have died during settle)
        if pid_of(args.app) != pid:
            print("[*] pid changed/died during settle; retrying", flush=True)
            continue
        if not args.no_freeze:
            stop_proc(pid)
            print(f"[*] SIGSTOP {pid}; sweeping /proc/{pid}/mem", flush=True)
        else:
            print(f"[*] sweeping live process {pid} (no freeze)", flush=True)
        snapshot_maps(pid, out_dir)
        with tempfile.TemporaryDirectory(prefix="yc_sweep_") as td:
            files = batch_sweep(pid, Path(td))
            print(f"[*] pulled {len(files)} region files", flush=True)
            mag = diagnose_magics(files)
            print(f"[*] magic occurrences: dex\n={mag['dex\n']} cdex={mag['cdex']} "
                  f"vdex={mag['vdex']}", flush=True)
            save_magic_regions(files, out_dir)
            added = sweep_local(files, out_dir, seen, seen_cdx)
        if len(seen) >= args.expect:
            print(f"[*] reached expect={args.expect}; done", flush=True)
            kill_proc(pid)
            break
        if not args.no_freeze:
            cont_proc(pid)
        if added == 0:
            empty_streak += 1
            if empty_streak >= 3 and seen:
                print("[*] 3 sweeps without new DEX; stopping", flush=True)
                break
        else:
            empty_streak = 0
        time.sleep(args.resweep_gap)

    (out_dir / "dex_count.txt").write_text(f"{len(seen)}\n")
    if args.pull_app_data and pid_seen_once:
        try:
            pull_app_data(args.app, out_dir)
        except Exception as exc:  # noqa: BLE001 - evidence over crash
            print(f"[!] pull_app_data failed: {exc}", flush=True)
    print(f"[*] unique DEX captured: {len(seen)} (cdex blobs: {len(seen_cdx)})", flush=True)
    for digest, dex in seen.items():
        print(f"    {len(dex):>10}  {digest}", flush=True)
    return 0 if seen or seen_cdx else 1


if __name__ == "__main__":
    sys.exit(main())
