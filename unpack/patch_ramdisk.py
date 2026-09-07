#!/usr/bin/env python3
"""Patch boot properties inside an Android emulator ramdisk image.

The google_apis ramdisk /default.prop sets ro.secure=1 and ro.debuggable=1.
Both are first-set-wins read-only props, so no runtime override is possible:
the only clean fix is editing the ramdisk before the AVD boots.

- Parses gzip or raw newc-format cpio archives (stdlib only).
- Rewrites the requested key=value lines inside default.prop
  (or any file matching --file).
- Re-emits the archive byte-faithfully except for the edited file
  (mode/uid/gid/mtime/nlink preserved; data length + checksum updated).

Usage:
  patch_ramdisk.py --image ramdisk.img --set ro.debuggable=1:0 --set ro.secure=1:0
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import struct
import sys

MAGIC = b"070701"  # newc


def parse_cpio(data: bytes):
    """Yield (name, mode, uid, gid, mtime, filesize, filedata, raw_header)."""
    off = 0
    out = []
    while off + 110 <= len(data):
        if data[off:off + 6] != MAGIC:
            raise ValueError(f"bad newc magic at {off:#x}")
        hdr = data[off:off + 110]
        fields = [int(hdr[6 + 8 * i:6 + 8 * (i + 1)], 16) for i in range(13)]
        (ino, mode, uid, gid, nlink, mtime, fsize, devmaj, devmin,
         rdevmaj, rdevmin, namesize, chksum) = fields
        name = data[off + 110:off + 110 + namesize - 1].decode(
            "utf-8", "replace")
        # 4-byte align header+name
        hpad = (-(110 + namesize)) % 4
        doff = off + 110 + namesize + hpad
        fdata = data[doff:doff + fsize]
        dpad = (-fsize) % 4
        next_off = doff + fsize + dpad
        out.append(dict(name=name, mode=mode, uid=uid, gid=gid, mtime=mtime,
                        fsize=fsize, data=fdata, hdr=hdr, off=off))
        if name == "TRAILER!!!":
            break
        off = next_off
    return out, data[off:] if off < len(data) else b""


def hexfmt(v: int) -> bytes:
    return b"%08X" % v


def build_cpio(entries) -> bytes:
    out = bytearray()
    for e in entries:
        if e["name"] == "TRAILER!!!":
            name = b"TRAILER!!!"
        else:
            name = e["name"].encode() + b"\x00"
        fdata = e["data"]
        hdr = bytearray()
        hdr += MAGIC
        for v in (0, e["mode"], e["uid"], e["gid"], e.get("nlink", 1),
                  e["mtime"], len(fdata), 0, 0, 0, 0, len(name), 0):
            hdr += hexfmt(v)
        out += hdr
        out += name
        out += b"\x00" * ((-(len(hdr) + len(name))) % 4)
        out += fdata
        out += b"\x00" * ((-len(fdata)) % 4)
    # trailer
    tname = b"TRAILER!!!\x00"
    thdr = bytearray(MAGIC)
    for v in (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(tname), 0):
        thdr += hexfmt(v)
    out += thdr + tname
    out += b"\x00" * ((-(len(thdr) + len(tname))) % 4)
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--file", default="default.prop",
                    help="file inside the ramdisk to edit")
    ap.add_argument("--set", action="append", default=[],
                    help="'key=old:new'")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    raw = open(args.image, "rb").read()
    gz = raw[:2] == b"\x1f\x8b"
    data = gzip.decompress(raw) if gz else raw
    entries, tail = parse_cpio(data)
    print(f"[*] {args.image}: {len(entries)-1} cpio entries "
          f"(gzip={gz}, tail={len(tail)}B)")

    target = None
    for e in entries:
        if e["name"] == args.file:
            target = e
            break
    if target is None:
        names = [e["name"] for e in entries[:20]]
        print(f"[!] {args.file!r} not in ramdisk; entries start with {names}")
        return 2

    text = target["data"].decode("utf-8", "replace")
    lines = text.splitlines(keepends=True)
    changed = 0
    for spec in args.set:
        m = None
        for i, ln in enumerate(lines):
            key, _, rest = ln.partition("=")
            if key.strip() == spec.split("=")[0]:
                m = i
                break
        if m is None:
            print(f"[!] key {spec.split('=')[0]} not found in {args.file}")
            continue
        key, old, new = spec.split("=")[0], spec.split("=")[1].split(":")[0], \
            spec.split("=")[1].split(":")[1]
        cur = lines[m].split("=", 1)[1].strip()
        if cur != old:
            print(f"[!] {key}: current {cur!r} != expected {old!r}; "
                  f"forcing to {new!r}")
        newline = f"{key}={new}\n"
        lines[m] = newline
        changed += 1
        print(f"[+] {key}: {cur!r} -> {new!r}")

    if not changed:
        print("[!] nothing changed")
        return 1
    target["data"] = "".join(lines).encode()

    out_bytes = build_cpio(entries)
    out_raw = gzip.compress(out_bytes, 9) if gz else out_bytes
    out_path = args.out or args.image
    with open(out_path, "wb") as fh:
        fh.write(out_raw)
    print(f"[*] wrote {out_path} ({len(out_raw)} bytes, was {len(raw)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
