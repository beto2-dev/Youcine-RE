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
  KILL   the <clinit> body is replaced with return-void.  For SDKs whose
         native lib is a signing-certificate kill-switch (Titan Ranger:
         JNI_OnLoad rejects the re-signed research build) this stops the
         SDK from ever loading - no loadLibrary, no JNI_OnLoad, no handler
         threads started by the lib, no NPE in its Runnables.  Applied only
         to classes proven self-contained by cross-reference scan (no
         non-ranger class references them).
  CTORFIX the warm-up of phase 2 materialized most of the packer's
         extraction stubs (return-void padded with nops), but the classes
         never initialized during warm-up keep the stub body.  For a
         CONSTRUCTOR the Dalvik verifier rejects any body that returns
         without calling a superclass constructor: boot-test 34282297861
         died at da.w.<init>(String) with 6,529 such stub-constructors
         still present across the 5 winners (744/16/2587/3182/0 per dex).
         Every <init> whose executable body is only return-void + nops gets
         invoke-direct {p0}, Ljava/lang/Object;-><init>()V injected -
         verifier-legal from any class (Object is a superclass of
         everything).  Real constructors always contain an invoke-direct/
         invoke-super <init> call, so they are never touched.

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

# KILL: replace the <clinit> of these classes with return-void.  The Titan
# Ranger SDK is a signing-certificate kill-switch of the same class as
# ConfusionUtils (boot-test 34281060343: com.titan.ranger.NativeJni.<clinit>
# -> System.loadLibrary("ranger-jni") -> JNI_OnLoad validates the cert and
# returns JNI_ERR -> UnsatisfiedLinkError).  The r3 try/catch guard kept the
# clinit alive, but JNI_OnLoad had ALREADY started the handlerRanger thread
# before rejecting the cert, and the clinit aborted at the throw point - so
# the posted NativeJni$v runnable read a null static and NPE-killed the
# process (boot-test 34282297861: FATAL EXCEPTION: handlerRanger,
# RangerResult.getRes() on a null object reference).  An empty clinit is the
# only complete neutralization: no loadLibrary attempt, no JNI_OnLoad, no
# threads started by the lib, no posted runnables.  Cross-reference scan of
# the 5 winners (all invokes + static field ops + const-strings): NO class
# outside com.titan.ranger.* references the SDK - killing both clinitis is
# provably side-effect-free for the rest of the app.
KILL_CLASSES = (
    "Lcom/titan/ranger/NativeJni;",
    "Lcom/titan/ranger/JniHandler;",
)

# the smali-level extraction-stub signature of an <init> body: executable
# instructions are only return-void and nop (the packer pads to a fixed
# size).  A real constructor ALWAYS contains an invoke-direct/invoke-super
# <init> call (javac/kotlin/d8 emit it unconditionally).
CTOR_STUB_OK = {"return-void", "nop"}

METHOD_RE = re.compile(r"^\.method\s+(.*?)\s+([A-Za-z_$<>0-9_]+)\((.*?)\)(\S+)\s*$")
CLASS_RE = re.compile(r"^\.class\s+.*?(L[^;]+;)")


def default_body_smali(proto_ret: str, name: str = "") -> tuple[int, str]:
    """(locals_count, smali body lines) for a synthesized default return.

    Constructors are special: the Dalvik verifier REQUIRES every <init> to
    call a superclass constructor before returning (boot-test 34281060343:
    'da.w.<init>(String) failed to verify: Constructor returning without
    calling superclass constructor').  invoke-direct on Object.<init> is
    verifier-legal from ANY class (Object is a superclass of everything),
    so the guarded stub boots even when the real super chain is unknown.
    """
    if name == "<init>":
        return 0, ("    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n"
                   "\n    return-void\n")
    if proto_ret == "V":
        return 0, "    return-void\n"
    if proto_ret in ("Z", "I", "B", "S", "C", "F"):
        return 1, "    const/4 v0, 0x0\n\n    return v0\n"
    if proto_ret in ("J", "D"):
        return 2, "    const-wide/16 v0, 0x0\n\n    return-wide v0\n"
    # object / array
    return 1, "    const/4 v0, 0x0\n\n    return-object v0\n"


def dex_stub_ctor_count(data: bytes) -> int:
    """Count <init> methods whose code units are only return-void + nops.

    The post-build verification: this MUST be 0 on every de-natified output
    DEX, otherwise a VerifyError bomb survived the ctorfix pass.
    """
    if data[:4] != b"dex\n":
        raise ValueError("bad magic")
    cls_size, cls_off = struct.unpack_from("<II", data, 96)
    str_size, str_off = struct.unpack_from("<II", data, 56)

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

    # locate the <init> string index
    init_idx = None
    for i in range(str_size):
        so = struct.unpack_from("<I", data, str_off + 4 * i)[0]
        _, p = uleb(so)
        end = data.index(b"\x00", p)
        if data[p:end] == b"<init>":
            init_idx = i
            break
    if init_idx is None:
        return 0
    type_size, type_off = struct.unpack_from("<II", data, 64)
    meth_size, meth_off = struct.unpack_from("<II", data, 88)
    # method_ids: class_idx u16, proto_idx u16, name_idx u32
    init_methods = set()
    for i in range(meth_size):
        name_idx = struct.unpack_from("<I", data, meth_off + 8 * i + 4)[0]
        if name_idx == init_idx:
            init_methods.add(i)
    bombs = 0
    for i in range(cls_size):
        cdo = struct.unpack_from("<I", data, cls_off + 32 * i + 24)[0]
        if cdo == 0:
            continue
        off = cdo
        n_static, off = uleb(off)
        n_inst, off = uleb(off)
        n_direct, off = uleb(off)
        n_virtual, off = uleb(off)
        for _ in range(n_static + n_inst):
            _, off = uleb(off)
            _, off = uleb(off)
        idx = 0
        for _ in range(n_direct):  # constructors are always direct methods
            diff, off = uleb(off)
            idx += diff
            flags, off = uleb(off)
            code_off, off = uleb(off)
            if idx not in init_methods or flags & 0x0100 or code_off == 0:
                continue
            insns_size = struct.unpack_from("<I", data, code_off + 12)[0]
            if insns_size == 0:
                continue
            units = struct.unpack_from("<%dH" % insns_size, data,
                                       code_off + 16)
            s = set(units)
            if 0x000E in s and s <= {0x000E, 0x0000}:
                bombs += 1
    return bombs


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
def param_words(params: str) -> int:
    """Register-word count of a smali parameter type list (J/D = 2 words,
    arrays = 1 word regardless of the element type)."""
    words = 0
    i = 0
    n = len(params)
    while i < n:
        c = params[i]
        if c == "L":
            i = params.index(";", i) + 1
            words += 1
        elif c == "[":
            while i < n and params[i] == "[":
                i += 1
            if i < n and params[i] == "L":
                i = params.index(";", i) + 1
            elif i < n:
                i += 1
            words += 1
        elif c in "JD":
            words += 2
            i += 1
        else:
            words += 1
            i += 1
    return words


def this_register(block: list[str], params: str):
    """Absolute register index of p0 from the method's register directive.

    `.locals M` -> p0 = vM (locals v0..vM-1, params vM..);
    `.registers T` -> p0 = T - ins with ins = 1 (this) + param words.
    Returns None when the block carries no register directive.
    """
    for raw in block:
        s = raw.strip()
        if s.startswith(".locals"):
            return int(s.split()[1])
        if s.startswith(".registers"):
            total = int(s.split()[1])
            return total - (1 + param_words(params))
    return None


def super_call_smali(block: list[str], params: str) -> str:
    """The verifier-legal super() call for an extraction-stub constructor.

    invoke-direct's 35c format only references registers v0-v15 (4-bit
    fields); in a wide constructor (.locals > 15) p0 maps to a register the
    format cannot encode - apktool fails with 'Invalid register: v17' (found
    on com/titans/entity/ProgramInfo during the local chain validation).
    dx's own fallback for that case is the 3rc range form, whose start
    register field is 16 bits wide: invoke-direct/range {p0}, ...
    """
    p0 = this_register(block, params)
    if p0 is not None and p0 > 15:
        return "    invoke-direct/range {p0}, Ljava/lang/Object;-><init>()V"
    return "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V"


def iter_exec_lines(block: list[str]):
    """Yield (index, stripped) for the EXECUTABLE lines of a smali method
    block: comments, directives, labels and blank lines are skipped, and
    whole .annotation/.subannotation ... .end sub-blocks are skipped too -
    baksmali renders method-level annotations (e.g. the R8 Signature
    annotation on generic constructors) INSIDE the method block, and their
    value tables contain lines like 'value = {' or '"(' that must never be
    mistaken for instructions."""
    depth = 0
    for idx, raw in enumerate(block):
        s = raw.strip()
        if depth:
            if s.startswith(".end "):
                depth -= 1
            continue
        if s.startswith(".annotation") or s.startswith(".subannotation"):
            depth += 1
            continue
        if not s or s.startswith(".") or s.startswith("#") or \
                s.startswith(":"):
            continue
        yield idx, s


def is_stub_ctor_block(block: list[str]) -> bool:
    """True when the smali method body is an iJiami extraction stub.

    Executable lines must be only return-void / nop.  Real constructors
    always contain an invoke-direct/invoke-super <init> call, so they never
    match.
    """
    saw_return = False
    for _idx, s in iter_exec_lines(block):
        if s == "return-void":
            saw_return = True
            continue
        if s == "nop":
            continue
        return False
    return saw_return


def patch_smali_file(path: Path, bodies: dict, report: dict) -> None:
    """Rewrite native declarations, kill clinitis and fix stub ctors."""
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    cls_m = CLASS_RE.search(text)
    cls_desc = cls_m.group(1) if cls_m else "L?;"
    killed = cls_desc in KILL_CLASSES
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
        if m and (" native " in header + " " or
                  (killed and m.group(2) == "<clinit>")):
            flags, name, params, ret = m.group(1), m.group(2), m.group(3), m.group(4)
            key = f"{cls_desc}|{name}|({params}){ret}"
            if killed and name == "<clinit>":
                # KILL: the whole class-init body is replaced.  The SDK's
                # native lib is a signing kill-switch and its JNI_OnLoad
                # starts handler threads BEFORE returning JNI_ERR, so a
                # try/catch guard still leaves those threads NPE-killing
                # the process.  Empty clinit = the SDK never loads.
                new_header = header
                out.append(new_header)
                out.append("    .locals 0")
                out.append("")
                out.append("    return-void")
                out.append(end_line)
                report["kill"].append(key)
            elif any(cls_desc.startswith(p) for p in KEEP_PREFIXES):
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
                locals_n, body = default_body_smali(ret, name)
                new_header = header.replace(" native ", " ", 1)
                if new_header == header:
                    new_header = re.sub(r"\bnative\b\s*", "", header, count=1)
                out.append(new_header)
                out.append(f"    .locals {locals_n}")
                out.extend(block)          # annotations, if any
                out.append(body.rstrip("\n"))
                out.append(end_line)
                report["stub"].append(key)
        elif m and m.group(2) == "<init>" and " native " not in header + " " \
                and is_stub_ctor_block(block):
            # CTORFIX: extraction-stub constructor - the verifier rejects a
            # constructor that returns without calling a superclass
            # constructor.  Inject the Object.<init> super call in front.
            key = f"{cls_desc}|<init>|({m.group(3)}){m.group(4)}"
            out.append(header)
            super_line = super_call_smali(block, m.group(3))
            exec_idx = [idx for idx, _s in iter_exec_lines(block)]
            inject_at = exec_idx[0] if exec_idx else len(block)
            for b_idx, raw in enumerate(block):
                if b_idx == inject_at:
                    out.append(super_line)
                out.append(raw)
            if not exec_idx:  # defensible: no executable lines at all
                out.append(super_line)
            out.append(end_line)
            report["ctorfix"].append(key)
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
        "kill_classes": list(KILL_CLASSES),
        "bodies_file": str(args.bodies),
    }}
    report_template_keys = ("real", "stub", "keep", "kill", "ctorfix")
    failures = []
    for dex in dexes:
        print(f"[*] de-natifying {dex.name} ({dex.stat().st_size:,} B)", flush=True)
        cls_pre, m_pre, n_pre = parse_dex_headers(dex)
        report = {"dex": dex.name, "real": [], "stub": [],
                  "keep": [], "kill": [], "ctorfix": []}
        with tempfile.TemporaryDirectory(prefix="denatify_") as td:
            workdir = Path(td)
            decoded = apktool_decode_dex(apktool, dex, workdir / "decoded", workdir)
            smali_root = decoded / "smali"
            count = 0
            for smali in sorted(smali_root.rglob("*.smali")):
                txt = smali.read_text(encoding="utf-8")
                if "\n.method " not in txt and not txt.startswith(".method "):
                    continue
                has_native = " native " in txt or re.search(
                    r"^\.method[^\n]*\bnative\b", txt, re.M)
                has_kill = any(g in txt for g in KILL_CLASSES)
                # cheap pre-filter for the ctorfix pass: an extraction-stub
                # ctor body always contains a return-void
                has_ctors = "<init>" in txt and "return-void" in txt
                if not has_native and not has_kill and not has_ctors:
                    continue
                patch_smali_file(smali, bodies, report)
                count += 1
            data = apktool_build_dex(apktool, decoded, workdir)
        (out_dir / dex.name).write_bytes(data)
        cls_post, m_post, n_post = parse_dex_headers(out_dir / dex.name)
        bombs_post = dex_stub_ctor_count(data)
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
            "kill": len(report["kill"]),
            "ctorfix": len(report["ctorfix"]),
            "stub_ctors_remaining": bombs_post,
        }
        full_report["dexes"].append(entry)
        print(f"    real={entry['real']} stub={entry['stub']} "
              f"keep={entry['keep']} kill={entry['kill']} "
              f"ctorfix={entry['ctorfix']} "
              f"natives {n_pre} -> {n_post}", flush=True)
        # hard verification
        if cls_pre != cls_post or m_pre != m_post:
            failures.append(f"{dex.name}: class/method count changed "
                            f"({cls_pre}/{m_pre} -> {cls_post}/{m_post})")
        if n_post != entry["keep"]:
            failures.append(f"{dex.name}: natives remaining {n_post} != "
                            f"keep set {entry['keep']}")
        if bombs_post != 0:
            failures.append(f"{dex.name}: {bombs_post} extraction-stub "
                            "constructors survived the ctorfix pass - the "
                            "verifier would kill the process on first load")
        if entry["real"] == 0 and dex.name == "classes.dex":
            failures.append(f"{dex.name}: the SqlHelper REAL bodies did not "
                            "apply - check denatify_bodies.json keys")

    # aggregate
    full_report["totals"] = {
        "real": sum(d["real"] for d in full_report["dexes"]),
        "stub": sum(d["stub"] for d in full_report["dexes"]),
        "keep": sum(d["keep"] for d in full_report["dexes"]),
        "kill": sum(d["kill"] for d in full_report["dexes"]),
        "ctorfix": sum(d["ctorfix"] for d in full_report["dexes"]),
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
          f"kept-native={t['keep']} killed-clinit={t['kill']} "
          f"ctorfix={t['ctorfix']} "
          f"-> {out_dir}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
