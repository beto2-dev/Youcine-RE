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

# The ORIGINAL YouCine 1.17.6 signing certificate (CN=xxl, O=XXL, OU=OTT)
# as recorded by PackageManager, harvested from a real install's
# packages.xml (run 34055278741 artifact). Transplanting this block into
# the dump-build's package entry makes PackageManager report the original
# signer, satisfying iJiami's anti-tamper signature check.
ORIGINAL_SIGS = '''<sigs count="1" schemeVersion="2">
            <cert index="29" key="3082034130820229a00302010202047f673ac3300d06092a864886f70d01010b05003051310b3009060355040613023836310b3009060355040813024744310b300906035504071302535a310c300a060355040a130358584c310c300a060355040b13034f5454310c300a0603550403130378786c301e170d3230303631383036323134365a170d3435303631323036323134365a3051310b3009060355040613023836310b3009060355040813024744310b300906035504071302535a310c300a060355040a130358584c310c300a060355040b13034f5454310c300a0603550403130378786c30820122300d06092a864886f70d01010105000382010f003082010a0282010100b4ecbeb43f7757f9bcf70dd613a5653bec3b5d7b6f3332a8e1bd3dd59065faabaf219e9fbd21a1d77cf6721276bd88cc538cf26a141e1c36ab4c7424a6402b48a1079bc7af83dc8972596cafe327a013d68d7627ca1124d08b24576c4d781e43b3ea5b6d0abbb3ec3d45e07b7790584368f5f716ec32f422e47173a42ae29e8b1885be4123f815b75439224756c7ed304e67e08228b8c8e05d9068166408c9d478426e5792265de405c7d16cd79b7ab3f445fc3b1a2e860e56d1f796d8610fff6b1ad608e3c9240853c25657a1d9fa985b81827d571b6b8d9613d156e3444123e37aa66d0095a42072d12b168fbd7d103209b47c08de1faea71f7af7564568bb0203010001a321301f301d0603551d0e04160414f77677e402bc98844cd41af2de6495708355e973300d06092a864886f70d01010b0500038201010013813841dbb97ac3c4e4390b18fe602702f5e0b7748f3afb76ce44e509cbf859b1d03000254ad35e6ca73438332c66cb5014497f3fb8e7cd9a022d9d49204568cc850a875feeae64b3f671a6b3327bd0712412602477469c26353f8ac2804a57bbc0d4f165bbf3d3a0e9d293fabf236693bc30d7bd69df187af330f638d7b7acd014d4c215a83218d39673dcf5a448ba49f0a4a9635d67d94cc835b426bff76b573100bd7490c9aa8ec117cef3ac3a711ae9eeb65e1a957b62f244ac8f8b64d8a443c1669f7b50b078cafd189770d79eaa5c1964f161e9ea3be99fdde86186fcad1c6b00fb23e4abb8f20bd812ec34171fd953f59fc162b8787ef154768dc556" />
        </sigs>'''


def package_block(xml: str, pkg: str) -> str | None:
    m = re.search(r"<package name=\"%s\"[^>]*>.*?</package>" % re.escape(pkg), xml, re.S)
    return m.group(0) if m else None


def sigs_of(block: str) -> str | None:
    m = re.search(r"<sigs[^>]*>.*?</sigs>", block, re.S)
    return m.group(0) if m else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--orig", default=None, help="packages.xml with original install (optional; the baked ORIGINAL_SIGS is used otherwise)")
    ap.add_argument("--dump", required=True, help="packages.xml with dump-build install")
    ap.add_argument("--out", required=True)
    ap.add_argument("--package", default=DEFAULT_PKG)
    args = ap.parse_args()

    dump = open(args.dump, encoding="utf-8").read()

    db = package_block(dump, args.package)
    if not db:
        print(f"[-] package block not found in {args.dump}")
        return 1

    if args.orig:
        orig = open(args.orig, encoding="utf-8").read()
        ob = package_block(orig, args.package)
        if not ob:
            print(f"[-] package block not found in {args.orig}")
            return 1
        osig = sigs_of(ob)
    else:
        osig = ORIGINAL_SIGS

    dsig = sigs_of(db)
    if not osig:
        print("[-] original <sigs> unavailable")
        return 1
    if not dsig:
        print("[-] <sigs> not found in the dump package block")
        return 1

    print(f"[*] orig sigs block ({len(osig)} bytes): {osig[:80]}...")
    print(f"[*] dump sigs block ({len(dsig)} bytes): {dsig[:80]}...")

    if dsig == osig:
        print("[!] sigs blocks are identical; nothing to transplant (already original?)")
        return 0

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
