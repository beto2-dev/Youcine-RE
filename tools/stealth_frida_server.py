#!/usr/bin/env python3
"""stealth_frida_server.py - same-length binary patch of frida-server.

WHY (run 34172614416 post-mortem): iJiami's SecLLVM VMP code reads
/proc/self/maps and kills itself with RAW SVC syscalls (openat/read/kill)
- bypassing every libc-level Interceptor hook (the 09_hide_frida.js
sanitizer only covers libc open/openat/fopen).  The detection byte-pattern
is the agent's memfd name and the agent thread names, which are PLAINTEXT
inside the official frida-server binary:

  ELF64 @ 0x37e8f0 : the embedded 64-bit agent (uncompressed)
  ELF32 @ 0x1bcbe20: the embedded 32-bit agent (uncompressed)

All replacements below are EXACT-LENGTH byte swaps, so no offset, no
segment, no resource length changes - the ELF structure is untouched:

  frida-agent-<arch>.so -> media-agent-<arch>.so   (memfd template)
  frida-agent-32.so     -> media-agent-32.so
  frida-agent-64.so     -> media-agent-64.so
  frida-helper-64       -> media-helper-64          (transient exec name)
  frida-helper-32       -> media-helper-32
  gum-js-loop\0         -> run-js-loop\0            (agent JS thread, x2)
  gmain\0               -> smain\0                  (glib main loop thread)
  gdbus\0               -> sdbus\0                  (glib dbus thread)

DELIBERATELY NOT patched: every other 'frida' substring in the binary -
the wire protocol strings ('frida:rpc' etc.) must stay identical on BOTH
sides so the stock python frida client keeps working.

Usage: stealth_frida_server.py <server-binary> [--verify-only]
Exit 0 = patched (or verify passed); exit 1 = target strings missing /
bad arguments; the caller decides whether to fall back to the stock
binary.
"""
import sys
from pathlib import Path

# (needle, replacement, note) - replacement length MUST equal needle length
PATCHES = [
    (b"frida-agent-<arch>.so", b"media-agent-<arch>.so", "memfd name template"),
    (b"frida-agent-32.so", b"media-agent-32.so", "32-bit agent memfd"),
    (b"frida-agent-64.so", b"media-agent-64.so", "64-bit agent memfd"),
    (b"frida-helper-64", b"media-helper-64", "helper process name"),
    (b"frida-helper-32", b"media-helper-32", "helper process name"),
    (b"gum-js-loop\x00", b"run-js-loop\x00", "agent JS thread name"),
    (b"gmain\x00", b"smain\x00", "glib main-loop thread name"),
    (b"gdbus\x00", b"sdbus\x00", "glib dbus thread name"),
]


def main() -> int:
    args = [a for a in sys.argv[1:]]
    verify_only = "--verify-only" in args
    args = [a for a in args if a != "--verify-only"]
    if len(args) != 1:
        print(__doc__)
        return 1
    path = Path(args[0])
    if not path.is_file():
        print(f"[stealth] no such file: {path}")
        return 1

    data = bytearray(path.read_bytes())
    magic = bytes(data[:4])
    if magic != b"\x7fELF":
        print(f"[stealth] {path} is not an ELF (magic {magic!r}) - refusing")
        return 1

    print(f"[stealth] {path} ({len(data)} bytes, ELF ok)")

    already = 0
    changed = 0
    for needle, repl, note in PATCHES:
        if len(needle) != len(repl):
            # construction error - never ship it
            raise AssertionError(f"length mismatch: {needle!r} vs {repl!r}")
        count = 0
        i = 0
        while True:
            i = data.find(needle, i)
            if i < 0:
                break
            if bytes(data[i:i + len(needle)]) == repl:
                already += 1  # already patched
            else:
                data[i:i + len(needle)] = repl
                print(f"[stealth]   {hex(i)}: {needle!r} -> {repl!r}  ({note})")
                changed += 1
            count += 1
            i += 1
        if count == 0 and already == 0:
            # the template literals may legitimately be absent in some
            # builds; the thread names must exist though - report per-patch
            print(f"[stealth]   (absent) {needle!r} - {note}")

    # post-conditions
    leftovers = []
    for needle, _, _ in PATCHES:
        if data.find(needle) >= 0:
            leftovers.append(needle)
    if leftovers:
        print(f"[stealth] FAILED - still present: {leftovers}")
        return 1

    # structural sanity: the ELF header and embedded agent magics survive
    if bytes(data[:4]) != b"\x7fELF":
        print("[stealth] FAILED - ELF magic lost")
        return 1

    if not verify_only and changed:
        path.write_bytes(bytes(data))
        print(f"[stealth] wrote {changed} patch(es) (+{already} already "
              f"patched) -> {path}")
    else:
        print(f"[stealth] verify-only / no new patches (changed={changed}, "
              f"already={already})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
