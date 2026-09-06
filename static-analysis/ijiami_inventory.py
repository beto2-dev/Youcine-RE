#!/usr/bin/env python3
"""Parse iJiami assets from an unpacked zip directory or APK.

Environment:
  SAMPLE_APK   packed APK (used if SAMPLE_UNZIP is unset)
  SAMPLE_UNZIP directory already unzipped (optional)
  OUT_DIR      report directory
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_payload(data: bytes) -> dict:
    info = {
        "size": len(data),
        "sha256": _sha256(data),
        "head_hex": data[:64].hex(),
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data[:64]),
    }
    if len(data) >= 40:
        info["u32le_0"] = int.from_bytes(data[0:4], "little")
        info["u32le_4"] = int.from_bytes(data[4:8], "little")
        try:
            info["md5_ascii"] = data[8:40].decode("ascii")
        except UnicodeDecodeError:
            info["md5_ascii"] = None
    if data[:6] == b"indl01":
        info["magic"] = "indl01"
    if data[:4] == b"dex\n":
        info["magic"] = "dex"
    return info


def from_dir(root: Path) -> dict:
    assets = root / "assets"
    result = {"files": {}}
    names = [
        "ijiami.dat",
        "ijiami.ajm",
        "IJMDal.Data",
        "signed.bin",
        "af.bin",
        "libijmDataEncryption.so",
        "libijmDataEncryption_arm64.so",
        "libijmDataEncryption_x86.so",
        "libijmDataEncryption_x86_64.so",
    ]
    for name in names:
        p = assets / name
        if p.is_file():
            result["files"][f"assets/{name}"] = inspect_payload(p.read_bytes())
    libexec = {}
    ijm_lib = assets / "ijm_lib"
    if ijm_lib.is_dir():
        for so in sorted(ijm_lib.rglob("*.so")):
            libexec[str(so.relative_to(root))] = {
                "size": so.stat().st_size,
                "sha256": _sha256(so.read_bytes()),
            }
    result["libexec"] = libexec
    return result


def main() -> int:
    out_dir = Path(os.environ.get("OUT_DIR", "work/static"))
    out_dir.mkdir(parents=True, exist_ok=True)
    unzip = os.environ.get("SAMPLE_UNZIP")
    if unzip:
        report = from_dir(Path(unzip))
    else:
        apk = Path(os.environ.get("SAMPLE_APK", ""))
        if not apk.is_file():
            raise SystemExit("set SAMPLE_UNZIP or SAMPLE_APK")
        with tempfile.TemporaryDirectory() as td:
            with zipfile.ZipFile(apk) as zf:
                zf.extractall(td)
            report = from_dir(Path(td))
    (out_dir / "ijiami-inventory.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
