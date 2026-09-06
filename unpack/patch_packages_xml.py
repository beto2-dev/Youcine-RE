#!/usr/bin/env python3
"""Transplant the ORIGINAL APK signature into the dump-build's
packages.xml entry (rooted signature spoofing for the dump phase).

iJiami's anti-tamper check reads the app's signing certificate through
PackageManager (the cert recorded at install time). The dump-build
(x86_64, libexec runs natively) is necessarily re-signed with a debug
key, so the check fails and the packer suicides / hangs. Fixing the
INPUT instead of the symptom: install the original APK once (framework
records the original cert), extract its <sigs> block, then install the
dump-build and swap the block in /data/system/packages.xml while the
framework is stopped. After restart PackageManager reports the ORIGINAL
certificate for the dump-build -> the check passes -> decryption
proceeds.

Usage (see unpack-emulator.yml for the full stop/pull/patch/push/start
sequence):
  python3 unpack/patch_packages_xml.py \
      --orig work/packages-orig.xml \
      --dump work/packages-dump.xml \
      --out  work/packages-patched.xml
"""
from __future__ import annotations

import argparse
import re
import sys

DEFAULT_PKG = "com.world.youcinemobile"


def package_block(xml: str, pkg: str) -> str | None:
    m = re.search(r"<package name=\"%s\"[^>]*>.*?</package>" % re.escape(pkg), xml, re.S)
    return m.group(0) if m else None


def sigs_of(block: str) -> str | None:
    m = re.search(r"<sigs[^>]*>.*?</sigs>", block, re.S)
    return m.group(0) if m else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--orig", required=True, help="packages.xml with original install")
    ap.add_argument("--dump", required=True, help="packages.xml with dump-build install")
    ap.add_argument("--out", required=True)
    ap.add_argument("--package", default=DEFAULT_PKG)
    args = ap.parse_args()

    orig = open(args.orig, encoding="utf-8").read()
    dump = open(args.dump, encoding="utf-8").read()

    ob = package_block(orig, args.package)
    db = package_block(dump, args.package)
    if not ob:
        print(f"[-] package block not found in {args.orig}")
        return 1
    if not db:
        print(f"[-] package block not found in {args.dump}")
        return 1

    osig = sigs_of(ob)
    dsig = sigs_of(db)
    if not osig:
        print("[-] <sigs> not found in the original package block")
        return 1
    if not dsig:
        print("[-] <sigs> not found in the dump package block")
        return 1

    print(f"[*] orig sigs block ({len(osig)} bytes): {osig[:100]}...")
    print(f"[*] dump sigs block ({len(dsig)} bytes): {dsig[:100]}...")

    new_block = db.replace(dsig, osig, 1)
    if new_block == db:
        print("[-] replacement had no effect")
        return 1
    out = dump.replace(db, new_block, 1)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(out)
    print(f"[+] transplanted original <sigs> into {args.out} ({len(out)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
