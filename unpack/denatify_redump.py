#!/usr/bin/env python3
"""De-natify the phase-2 re-dump DEXes so the packer-free APK fully boots.

Background (docs/en/06-dynamic-unpack.md, "final defense layer"): the
~805 ACC_NATIVE methods get their JNI implementations registered only by
libexec's content-gated engine, which requires the byte-exact original
APK.  Removing the packer removes the registrar, so the rebuilt app dies
at the first VMP-protected method:

    App.onCreate:139 -> Aria.init -> SqlHelper.getDb -> UnsatisfiedLinkError

The natives are SeLLVM-compiled inside libexec.so (they never re-materialize
as DEX bytecode: every phase-2 snapshot keeps code_off=0 on all of them), so
they cannot be recovered by any re-dump.  This tool replaces the native
declarations at the smali layer instead, with three policies:

  KEEP   genuine JNI - the method's own library ships in the APK and
         registers it (crashlytics-ndk, the DE SDK, EFS prefs, ED25519).
         The declaration stays native.
  REAL   faithful bodies from the open-source upstream (Aria ORM
         SqlHelper - unpack/denatify_bodies.json, verified field-by-field
         against the app DEX: same INSTANCE/mContext fields, same real
         siblings init/handleLowAriaUpdate/handle360/365/366/
         addTaskRecordType, same SqlUtil.tableExists/createTable).
  STUB   per-return-type default body (return-void / const-4 0 / const-null
         / const-wide 0).  Removes the UnsatisfiedLinkError; the method is
         silently wrong - the documented research caveat of the booteable
         build.  Only void natives were stubbed by the packer itself
         (13,478 ctors + 31,760 void methods); non-void natives get a
         synthesized default here.

Pipeline position:  dedup_redump.py  ->  THIS  ->  rebuild_unpacked_apk.py
(the output keeps the classes.dex..classesN.dex names the rebuild expects;
the confusion patch runs inside the rebuild on the carrier, independent of
this step).

Usage:
  python3 unpack/denatify_redump.py \
      --dex-dir work/booteable-dexes --out-dir work/denatified-dexes \
      [--bodies unpack/denatify_bodies.json] [--apktool work/apktool.jar]

Verification (built in, hard failure on mismatch):
  - every output DEX: magic + header file_size == len + method count equal
    to its input + class count equal
  - remaining natives == exactly the KEEP set
  - report json: per-dex counts of real/stub/keep + the full stub list
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# policy tables
# ---------------------------------------------------------------------------
KEEP_PREFIXES = (
    # genuine JNI: their own .so ships in the rebuilt APK and registers them
    "Lcom/google/firebase/crashlytics/ndk/",
    "Lcom/ijm/dataencryption/",
    "Lcom/efs/sdk/",
    "Lcom/hpplay/component/protocol/encrypt/ED25519Encode",  # covers ...Encrypt and ...Encrypt2
)

METHOD_RE = re.compile(r"^\.method\s+(.*?)\s+([A-Za-z_$<>0-9_]+)\((.*?)\)(\S+)\s*$")
CLASS_RE = re.compile(r"^\.class\s+.*?(L[^;]+;)")


def default_body_smali(proto_ret: str) -> tuple[int, str]:
    """(locals_count, smali body lines) for a synthesized default return."""
    if proto_ret == "V":
        return 0, "    return-void\n"
    if proto_ret in ("Z", "I", "B", "S", "C", "F"):
        return 1, "    const/4 v0, 0x0\n\n    return v0\n"
    if proto_ret in ("J", "D"):
        return 2, "    const-wide/16 v0, 0x0\n\n    return-wide v0\n"
    # object / array
    return 1, "    const/4 v0, 0x0\n\n    return-object v0\n"


def parse_dex_headers(path: Path) -> tuple[int, int, int]:
    """(class_defs_size, method count total, native count) sanity snapshot."""
    data = path.read_bytes()
    if data[:4] != b"dex\n":
        raise ValueError(f"{path}: bad magic")
    file_size = struct.unpack_from("<I", data, 32)[0]
    if file_size != len(data):
        raise ValueError(f"{path}: header file_size {file_size} != {len(data)}")
    cls_size, cls_off = struct.unpack_from("<II", data, 96)
    str_size, str_off = struct.unpack_from("<II", data, 56)
    type_size, type_off = struct.unpack_from("<II", data, 64)

    def uleb(off: int) -> tuple[int, int]:
        result = 0
        shift = 0
        while True:
            b = data[off]
            off += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result, off

    strings: list[str] = []
    for i in range(str_size):
        so = struct.unpack_from("<I", data, str_off + 4 * i)[0]
        _, p = uleb(so)
        end = data.index(b"\x00", p)
        strings.append(data[p:end].decode("utf-8", "replace"))
    methods = natives = 0
    for i in range(cls_size):
        cdo = struct.unpack_from("<I", data, cls_off + 32 * i + 24)[0]
        if cdo == 0:
            continue
        off = cdo
        n_static, off = uleb(off)
        n_inst, off = uleb(off)
        n_direct, off = uleb(off)
        n_virtual, off = uleb(off)
        off += 0  # fields parsed below
        for _ in range(n_static + n_inst):
            _, off = uleb(off)
            _, off = uleb(off)
        for _ in range(n_direct + n_virtual):
            _, off = uleb(off)
            flags, off = uleb(off)
            _, off = uleb(off)
            methods += 1
            if flags & 0x0100:
                natives += 1
    return cls_size, methods, natives


# ---------------------------------------------------------------------------
# smali patcher
# ---------------------------------------------------------------------------
def patch_smali_file(path: Path, bodies: dict, report: dict) -> None:
    """Rewrite every native method declaration in one .smali file."""
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    cls_m = CLASS_RE.search(text)
    cls_desc = cls_m.group(1) if cls_m else "L?;"
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if not line.startswith(".method "):
            out.append(line)
            i += 1
            continue
        header = line
        m = METHOD_RE.match(header)
        # collect the whole method block first
        j = i + 1
        block: list[str] = []
        while j < n and lines[j] != ".end method":
            block.append(lines[j])
            j += 1
        end_line = lines[j] if j < n else ".end method"
        if m and " native " in header + " ":
            flags, name, params, ret = m.group(1), m.group(2), m.group(3), m.group(4)
            key = f"{cls_desc}|{name}|({params}){ret}"
            if any(cls_desc.startswith(p) for p in KEEP_PREFIXES):
                # KEEP - leave the native declaration untouched
                report["keep"].append(key)
                out.append(header)
                out.extend(block)
                out.append(end_line)
            elif key in bodies:
                body = bodies[key]
                new_header = header.replace(" native ", " ", 1)
                if new_header == header:
                    new_header = re.sub(r"\bnative\b\s*", "", header, count=1)
                out.append(new_header)
                out.extend(block)          # annotations, if any
                out.append(body.rstrip("\n"))
                out.append(end_line)
                report["real"].append(key)
            else:
                locals_n, body = default_body_smali(ret)
                new_header = header.replace(" native ", " ", 1)
                if new_header == header:
                    new_header = re.sub(r"\bnative\b\s*", "", header, count=1)
                out.append(new_header)
                out.append(f"    .locals {locals_n}")
                out.extend(block)          # annotations, if any
                out.append(body.rstrip("\n"))
                out.append(end_line)
                report["stub"].append(key)
        else:
            out.append(header)
            out.extend(block)
            out.append(end_line)
        i = j + 1
    path.write_text("\n".join(out), encoding="utf-8")


# ---------------------------------------------------------------------------
# apktool round trip
# ---------------------------------------------------------------------------
def apktool_decode_dex(apktool: Path, dex: Path, out_dir: Path, workdir: Path) -> Path:
    fake = workdir / (dex.stem + ".apk")
    with zipfile.ZipFile(fake, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(dex, "classes.dex")
    cmd = ["java", "-jar", str(apktool), "d", "--no-res", "-f",
           "-o", str(out_dir), str(fake)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    if r.returncode != 0 or not (out_dir / "smali").is_dir():
        raise RuntimeError(f"apktool d failed on {dex.name}: {r.stderr[-800:]}")
    return out_dir


def apktool_build_dex(apktool: Path, decoded: Path, workdir: Path) -> bytes:
    out_apk = workdir / "rebuilt.apk"
    cmd = ["java", "-jar", str(apktool), "b", str(decoded), "-o", str(out_apk)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=2400)
    if r.returncode != 0 or not out_apk.is_file():
        raise RuntimeError(f"apktool b failed: {r.stderr[-800:]}")
    with zipfile.ZipFile(out_apk) as zf:
        return zf.read("classes.dex")


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    here = Path(__file__).resolve().parent
    ap.add_argument("--dex-dir", required=True,
                    help="booteable winners (classes.dex..classesN.dex)")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--bodies", default=str(here / "denatify_bodies.json"))
    ap.add_argument("--apktool", default="work/apktool.jar")
    args = ap.parse_args()

    dex_dir = Path(args.dex_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    apktool = Path(args.apktool)
    if not apktool.is_file():
        # download if missing (CI caches it in work/)
        print(f"[!] apktool jar missing: {apktool}", flush=True)
        return 1
    bodies = json.loads(Path(args.bodies).read_text(encoding="utf-8"))
    bodies = {k: v for k, v in bodies.items() if not k.startswith("_")}

    def canon(p: Path) -> int:
        s = p.stem
        return 0 if s == "classes" else int(s.replace("classes", "") or 0)
    dexes = sorted(dex_dir.glob("classes*.dex"), key=canon)
    if not dexes:
        print(f"[!] no classes*.dex in {dex_dir}", flush=True)
        return 1

    full_report = {"dexes": [], "policy": {
        "keep_prefixes": list(KEEP_PREFIXES),
        "bodies_file": str(args.bodies),
    }}
    failures = []
    for dex in dexes:
        print(f"[*] de-natifying {dex.name} ({dex.stat().st_size:,} B)", flush=True)
        cls_pre, m_pre, n_pre = parse_dex_headers(dex)
        report = {"dex": dex.name, "real": [], "stub": [], "keep": []}
        with tempfile.TemporaryDirectory(prefix="denatify_") as td:
            workdir = Path(td)
            decoded = apktool_decode_dex(apktool, dex, workdir / "decoded", workdir)
            smali_root = decoded / "smali"
            count = 0
            for smali in sorted(smali_root.rglob("*.smali")):
                txt = smali.read_text(encoding="utf-8")
                if "\n.method " not in txt and not txt.startswith(".method "):
                    continue
                if " native " not in txt and not re.search(
                        r"^\.method[^\n]*\bnative\b", txt, re.M):
                    continue
                patch_smali_file(smali, bodies, report)
                count += 1
            data = apktool_build_dex(apktool, decoded, workdir)
        (out_dir / dex.name).write_bytes(data)
        cls_post, m_post, n_post = parse_dex_headers(out_dir / dex.name)
        entry = {
            "dex": dex.name,
            "in_size": dex.stat().st_size,
            "out_size": len(data),
            "classes_in": cls_pre, "classes_out": cls_post,
            "methods_in": m_pre, "methods_out": m_post,
            "natives_in": n_pre, "natives_out": n_post,
            "real": len(report["real"]),
            "stub": len(report["stub"]),
            "keep": len(report["keep"]),
        }
        full_report["dexes"].append(entry)
        print(f"    real={entry['real']} stub={entry['stub']} "
              f"keep={entry['keep']} natives {n_pre} -> {n_post}", flush=True)
        # hard verification
        if cls_pre != cls_post or m_pre != m_post:
            failures.append(f"{dex.name}: class/method count changed "
                            f"({cls_pre}/{m_pre} -> {cls_post}/{m_post})")
        if n_post != entry["keep"]:
            failures.append(f"{dex.name}: natives remaining {n_post} != "
                            f"keep set {entry['keep']}")
        if entry["real"] == 0 and dex.name == "classes.dex":
            failures.append(f"{dex.name}: the SqlHelper REAL bodies did not "
                            "apply - check denatify_bodies.json keys")

    # aggregate
    full_report["totals"] = {
        "real": sum(d["real"] for d in full_report["dexes"]),
        "stub": sum(d["stub"] for d in full_report["dexes"]),
        "keep": sum(d["keep"] for d in full_report["dexes"]),
    }
    (out_dir / "denatify_report.json").write_text(
        json.dumps(full_report, indent=2) + "\n", encoding="utf-8")

    if failures:
        for f in failures:
            print(f"[!] {f}", flush=True)
        print("[!] DE-NATIFY FAILED verification", flush=True)
        return 1
    t = full_report["totals"]
    print(f"[+] de-natify OK: real={t['real']} stubbed={t['stub']} "
          f"kept-native={t['keep']} -> {out_dir}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
