#!/usr/bin/env python3
"""Static inventory of a packed YouCine APK (androguard + zipfile).

Environment:
  SAMPLE_APK   path to the packed APK (required)
  OUT_DIR      directory for JSON/text reports (default: ./work/static)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from pathlib import Path

from androguard.misc import AnalyzeAPK


IJIAMI_MARKERS = (
    "assets/ijiami.dat",
    "assets/ijiami.ajm",
    "assets/IJMDal.Data",
    "assets/signed.bin",
    "s.h.e.l.l.S",
)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def zip_inventory(apk: Path) -> dict:
    with zipfile.ZipFile(apk) as zf:
        infos = zf.infolist()
        dex = [
            {"name": i.filename, "size": i.file_size}
            for i in infos
            if i.filename.endswith(".dex")
        ]
        assets = [
            {"name": i.filename, "size": i.file_size}
            for i in infos
            if i.filename.startswith("assets/")
        ]
        libs = [
            {"name": i.filename, "size": i.file_size}
            for i in infos
            if i.filename.startswith("lib/") and i.filename.endswith(".so")
        ]
        markers = [m for m in IJIAMI_MARKERS if any(i.filename == m or m in i.filename for i in infos)]
        # also flag shell classes via path
        if any(i.filename.endswith("s/h/e/l/l/S.smali") or "ijiami" in i.filename.lower() for i in infos):
            markers = list(sorted(set(markers + ["ijiami-asset"])))
        return {
            "entries": len(infos),
            "dex": dex,
            "assets_top": sorted(assets, key=lambda x: -x["size"])[:40],
            "native": libs,
            "markers_present": [
                m
                for m in (
                    "assets/ijiami.dat",
                    "assets/ijiami.ajm",
                    "assets/IJMDal.Data",
                    "assets/signed.bin",
                    "assets/libijmDataEncryption.so",
                )
                if any(i.filename == m for i in infos)
            ],
        }


def main() -> int:
    apk = Path(os.environ.get("SAMPLE_APK", "")).expanduser()
    if not apk.is_file():
        raise SystemExit("SAMPLE_APK is missing or not a file")
    out_dir = Path(os.environ.get("OUT_DIR", "work/static"))
    out_dir.mkdir(parents=True, exist_ok=True)

    digest = sha256_of(apk)
    zinv = zip_inventory(apk)
    a, _d, _dx = AnalyzeAPK(str(apk))

    report = {
        "file": apk.name,
        "size": apk.stat().st_size,
        "sha256": digest,
        "package": a.get_package(),
        "app_name": a.get_app_name(),
        "version_name": a.get_androidversion_name(),
        "version_code": a.get_androidversion_code(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "main_activity": a.get_main_activity(),
        "permissions": sorted(set(a.get_permissions() or [])),
        "zip": zinv,
        "packer_guess": "iJiami" if zinv["markers_present"] else "unknown",
    }
    (out_dir / "quickscan.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        f"file {apk.name}",
        f"sha256 {digest}",
        f"package {report['package']}",
        f"version {report['version_name']} ({report['version_code']})",
        f"packer {report['packer_guess']}",
        f"dex {report['zip']['dex']}",
        f"ijiami markers {report['zip']['markers_present']}",
        f"main {report['main_activity']}",
    ]
    (out_dir / "quickscan.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
