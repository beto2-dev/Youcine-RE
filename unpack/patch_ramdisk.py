#!/usr/bin/env python3
"""Patch boot properties inside an Android emulator ramdisk image.

Modern API-30 emulator ramdisks are MULTI-STAGE: one gzip stream containing
a concatenated sequence of newc cpio archives (early mount dirs, then the
real rootfs with default.prop, ...). After each TRAILER!!! the kernel's
initramfs extractor keeps scanning, so concatenated stages are normal.

Strategy (surgical, same-length values only):
  1. decompress the whole stream
  2. parse ALL concatenated cpio stages; locate the target file
  3. patch the key=value bytes IN PLACE inside the decompressed buffer
     (same length: e.g. ro.debuggable=1 -> ro.debuggable=0)
  4. re-compress and write back

Usage:
  patch_ramdisk.py --image ramdisk.img --set ro.debuggable=1:0
"""
from __future__ import annotations

import argparse
import gzip

MAGIC = b"070701"


def parse_stages(data: bytes):
    """Parse concatenated newc cpio archives.

    Returns a list of stages; each stage is a list of entries:
      {name, mode, uid, gid, mtime, fsize, data_off, data}
    and the byte offset just past the stage's trailer.
    """
    stages = []
    off = 0
    n = len(data)
    while off < n:
        # skip zero padding between stages
        while off < n and data[off] == 0:
            off += 1
        if off >= n or off + 110 > n:
            break
        if data[off:off + 6] != MAGIC:
            # not a cpio any more - stop
            break
        entries = []
        stage_end = None
        cur = off
        while cur + 110 <= n:
            if data[cur:cur + 6] != MAGIC:
                stage_end = cur
                break
            fsize = int(data[cur + 54:cur + 62], 16)
            namesize = int(data[cur + 94:cur + 102], 16)
            name = data[cur + 110:cur + 110 + namesize - 1].decode(
                "utf-8", "replace")
            hpad = (-(110 + namesize)) % 4
            doff = cur + 110 + namesize + hpad
            fdata = data[doff:doff + fsize]
            dpad = (-fsize) % 4
            nxt = doff + fsize + dpad
            entries.append(dict(name=name, fsize=fsize, data_off=doff,
                                data=fdata))
            if name == "TRAILER!!!":
                stage_end = nxt
                break
            cur = nxt
        if stage_end is None:
            break
        stages.append(entries)
        off = stage_end
    return stages


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--file", default="default.prop")
    ap.add_argument("--set", action="append", default=[],
                    help="'key=old:new' (same length required)")
    args = ap.parse_args()

    raw = open(args.image, "rb").read()
    gz = raw[:2] == b"\x1f\x8b"
    data = bytearray(gzip.decompress(raw) if gz else raw)
    stages = parse_stages(bytes(data))
    if not stages:
        print("[!] no cpio stages parsed")
        return 2
    total = sum(len(s) for s in stages)
    print(f"[*] {args.image}: {len(stages)} cpio stages, "
          f"{total} entries (gzip={gz})")
    for i, s in enumerate(stages):
        names = [e["name"] for e in s if e["name"] != "TRAILER!!!"]
        print(f"    stage {i}: {len(names)} entries: "
              f"{names[:8]}{'...' if len(names) > 8 else ''}")

    target = None
    for s in stages:
        for e in s:
            if e["name"] == args.file:
                target = e
                break
        if target:
            break
    if target is None:
        print(f"[!] {args.file!r} not found in any stage")
        return 2

    text = bytes(target["data"]).decode("utf-8", "replace")
    base = target["data_off"]
    print(f"[*] {args.file} @ decompressed {base:#x} "
          f"({target['fsize']} bytes)")

    failures = 0
    for spec in args.set:
        key, rest = spec.split("=", 1)
        old, new = rest.split(":", 1)
        if len(old) != len(new):
            print(f"[!] {key}: old/new must be the same length "
                  f"({old!r} vs {new!r})")
            failures += 1
            continue
        pat = f"{key}={old}\n".encode()
        idx = text.find(f"{key}={old}\n")
        if idx == -1:
            # maybe present with a different current value
            alt = [ln for ln in text.splitlines()
                   if ln.startswith(key + "=")]
            print(f"[!] {key}={old} not found; lines starting with {key}: "
                  f"{alt[:3]}")
            failures += 1
            continue
        # byte offset inside the file -> absolute in decompressed buffer
        data[base + idx:base + idx + len(pat)] = f"{key}={new}\n".encode()
        print(f"[+] {key}: {old} -> {new} "
              f"(file offset {idx:#x}, abs {base + idx:#x})")

    if failures:
        print(f"[!] {failures} spec(s) failed")
        return 1

    out = gzip.compress(bytes(data), 9) if gz else bytes(data)
    with open(args.image, "wb") as fh:
        fh.write(out)
    print(f"[*] wrote {args.image} ({len(out)} bytes, was {len(raw)})")

    # verify round-trip
    reread = gzip.decompress(open(args.image, "rb").read()) if gz else \
        open(args.image, "rb").read()
    stages2 = parse_stages(reread)
    ok = True
    for spec in args.set:
        key, rest = spec.split("=", 1)
        old, new = rest.split(":", 1)
        found = False
        for s in stages2:
            for e in s:
                if e["name"] == args.file:
                    t = e["data"].decode("utf-8", "replace")
                    if f"{key}={new}\n" in t and f"{key}={old}\n" not in t:
                        found = True
        ok = ok and found
        print(f"[*] verify {key}={new}: {'OK' if found else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
