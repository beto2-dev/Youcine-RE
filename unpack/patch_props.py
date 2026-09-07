#!/usr/bin/env python3
"""Runtime property-area patcher for rooted emulators (host-side driver).

Android system properties live in shared-memory files under
/dev/__properties__/ (regular tmpfs files, mmapped MAP_SHARED by every
process). `setprop` refuses ro.* (and empty) values, but a targeted
in-place byte patch of the value field is immediately visible to every
future reader - including iJiami's __system_property_get calls in freshly
forked app processes.

The serialized layout of a prop_info entry is not assumed: we locate the
NUL-terminated property NAME inside the file, then search a +/-120 byte
window for the expected CURRENT value string (NUL-terminated) and patch it
in place. Verification is done via `adb shell getprop` afterwards.

Flow per file: adb pull -> local patch -> adb push to /data/local/tmp ->
on-device `dd conv=notrunc` (no truncate: shared mappings stay valid).

Usage:
  patch_props.py [--adb ADB] --set 'name=old:new' [--set ...] [--verify-only]

Exit code 0 if every requested prop was patched and verified.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile

PROP_DIR = "/dev/__properties__"
WINDOW = 120  # search +/- this many bytes around the name for the value


def sh(adb: list, cmd: str, timeout: float = 30.0):
    return subprocess.run(adb + ["shell", cmd], capture_output=True,
                          text=True, timeout=timeout)


def list_prop_files(adb: list) -> list:
    r = sh(adb, f"ls {PROP_DIR}/ 2>/dev/null")
    return [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]


def pull(adb: list, remote: str, local: str) -> bool:
    r = subprocess.run(adb + ["pull", remote, local], capture_output=True,
                       text=True, timeout=60)
    return r.returncode == 0


def find_name_offset(data: bytes, name: str) -> int:
    pat = name.encode() + b"\x00"
    return data.find(pat)


def find_value_offset(data: bytes, name_off: int, old: str) -> int:
    """Closest NUL-terminated occurrence of `old` within +/-WINDOW of name."""
    want = old.encode() + b"\x00"
    best = -1
    best_d = 1 << 30
    start = max(0, name_off - WINDOW)
    end = min(len(data), name_off + WINDOW)
    i = start
    while True:
        j = data.find(want, i, end)
        if j == -1:
            break
        d = abs(j - name_off)
        if d < best_d:
            best_d, best = d, j
        i = j + 1
    return best


def patch_local(local: str, sets: list, name: str) -> int:
    """Patch one pulled file. Returns number of props patched."""
    with open(local, "rb") as fh:
        data = bytearray(fh.read())
    patched = 0
    for prop, old, new in sets:
        noff = find_name_offset(data, prop)
        if noff == -1:
            continue
        voff = find_value_offset(data, noff, old)
        if voff == -1:
            print(f"[!] {prop}: name found @{noff:#x} but old value "
                  f"{old!r} not found in window; skipped", flush=True)
            continue
        newb = new.encode() + b"\x00"
        data[voff:voff + len(newb)] = newb
        print(f"[+] {prop}: {old!r} -> {new!r} (name@{noff:#x} "
              f"value@{voff:#x} in {os.path.basename(local)})", flush=True)
        patched += 1
    if patched:
        with open(local, "wb") as fh:
            fh.write(data)
    return patched


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adb", default="adb")
    ap.add_argument("--set", action="append", default=[],
                    help="'name=oldvalue:newvalue' (old is used to locate "
                         "and validate the slot; new is written raw)")
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()

    adb = [args.adb]
    sets = []
    for s in args.set:
        m = re.match(r"^([^=]+)=([^:]*):(.*)$", s)
        if not m:
            print(f"[!] bad --set spec: {s!r}", flush=True)
            return 2
        sets.append((m.group(1), m.group(2), m.group(3)))

    if not sets:
        print("[!] nothing to do", flush=True)
        return 2

    # map prop -> file containing it
    files = list_prop_files(adb)
    if not files:
        print(f"[!] no files under {PROP_DIR} (root?)", flush=True)
        return 2
    print(f"[*] {len(files)} property-area files", flush=True)

    remaining = list(sets)
    total = 0
    with tempfile.TemporaryDirectory() as td:
        for f in files:
            if not remaining:
                break
            remote = f"{PROP_DIR}/{f}"
            local = os.path.join(td, "prop.bin")
            # adb pull/push take the remote path as a direct arg (no shell);
            # colons in SELinux-context filenames are fine. For adb shell
            # commands the path must be shell-quoted (q below).
            q = f"'{remote}'"
            if not pull(adb, remote, local):
                continue
            if not any(find_name_offset(open(local, "rb").read(), p) != -1
                       for p, _, _ in remaining):
                continue
            n = patch_local(local, remaining, f)
            if not n:
                continue
            total += n
            staged = f"/data/local/tmp/prop_patch_{abs(hash(f)) % 99999}.bin"
            subprocess.run(adb + ["push", local, staged], capture_output=True,
                           timeout=60)
            r = sh(adb, f"dd if={staged} of={q} bs=1M conv=notrunc 2>&1")
            sh(adb, f"rm -f {staged}")
            if r.returncode != 0:
                print(f"[!] dd failed for {f}: {r.stdout} {r.stderr}",
                      flush=True)
            remaining = [s for s in remaining
                         if not prop_done(s, local)]

    # verify via getprop
    fails = []
    for prop, old, new in sets:
        r = sh(adb, f"getprop {prop}")
        val = (r.stdout or "").strip()
        ok = (val == new) or (new == "" and val == "")
        print(f"[{'+' if ok else '!'}] getprop {prop} = {val!r} "
              f"(want {new!r})", flush=True)
        if not ok:
            fails.append(prop)

    print(f"[*] patched={total} verify_failed={len(fails)}", flush=True)
    return 1 if fails else 0


def prop_done(spec, local: str) -> bool:
    prop, old, new = spec
    try:
        with open(local, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    noff = find_name_offset(data, prop)
    if noff == -1:
        return False
    voff = find_value_offset(data, noff, old)
    if voff == -1:
        return True  # old value gone: already patched
    return data[voff:voff + len(new) + 1] == new.encode() + b"\x00"


if __name__ == "__main__":
    raise SystemExit(main())
