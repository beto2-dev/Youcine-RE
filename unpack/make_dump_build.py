#!/usr/bin/env python3
"""Build an x86_64 'dump build' of the packed iJiami APK.

Why: on an x86_64 emulator that advertises native-bridge ARM translation,
an APK whose lib/ only ships ARM ABIs is assigned primaryCpuAbi=arm64-v8a.
The iJiami stub then reports an ARM process ABI, extracts
assets/ijm_lib/arm64-v8a/libexec.so and dlopens it through the translator
(log evidence: "ndk_translation: Initialized NDK translation (aarch64)").
SecLLVM self-modifying code does not survive binary translation, JNI
registration never happens and the stub dies with
UnsatisfiedLinkError: s.h.e.l.l.N.al before any DEX is decrypted.

Fix: drop lib/<arm>/ entries (and stale v1 signature files) so the APK
carries no ARM native code. The installer assigns no ARM primary ABI,
the app process is a pure x86_64 ART process, and the stub selects
assets/ijm_lib/x86_64/libexec.so which runs natively.

The dump build is only used to observe the packer and dump the decrypted
DEX; the rebuilt research APK keeps the original lib/ payloads.

Output: <out> (unsigned zip; run zipalign + apksigner afterwards) and
<out>.sha256.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import zipfile
from pathlib import Path

# ARM ABI dirs to drop; keep x86 / x86_64 (if the sample ever ships them).
ARM_LIB = re.compile(r"^lib/(armeabi|armeabi-v7a|arm64-v8a|mips|mips64)/")
# NOTE: the original v1 JAR signature files (META-INF/XXL-OTT.RSA etc.) are
# KEPT ON PURPOSE. The dump-build is re-signed at v2/v3 level for install,
# but iJiami's signature check may read the v1 cert file directly - keeping
# the original makes that variant of the check pass.


def build(src: Path, dst: Path) -> tuple[int, int]:
    dropped = 0
    kept = 0
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(
        dst, "w"
    ) as zout:
        for info in zin.infolist():
            name = info.filename
            if ARM_LIB.match(name):
                dropped += 1
                continue
            entry = zipfile.ZipInfo(name, date_time=info.date_time)
            entry.compress_type = info.compress_type
            entry.external_attr = info.external_attr
            entry.internal_attr = info.internal_attr
            entry.create_system = info.create_system
            data = zin.read(name)
            zout.writestr(entry, data)
            kept += 1
    return kept, dropped


def main() -> int:
    ap = argparse.ArgumentParser(description="Strip ARM lib/ from packed APK")
    ap.add_argument("--apk", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    src = Path(args.apk)
    dst = Path(args.out)
    if not src.is_file():
        raise SystemExit(f"[-] missing APK: {src}")
    kept, dropped = build(src, dst)
    sha = hashlib.sha256(dst.read_bytes()).hexdigest()
    Path(str(dst) + ".sha256").write_text(f"{sha}  {dst.name}\n")
    print(f"[+] dump build: {dst} ({dst.stat().st_size} bytes)", flush=True)
    print(f"[+] kept {kept} entries, dropped {dropped} (ARM lib/; v1 sigs kept)", flush=True)
    print(f"[+] sha256 {sha}", flush=True)
    print("[!] next: zipalign -f 4 <out> && apksigner sign (see workflow)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
