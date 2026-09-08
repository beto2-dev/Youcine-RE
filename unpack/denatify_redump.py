#!/usr/bin/env python3
"""De-natify + stub-fix the phase-2 re-dump DEXes so the packer-free APK fully boots.

Background (docs/en/06-dynamic-unpack.md, "final defense layer"): the
~805 ACC_NATIVE methods get their JNI implementations registered only by
libexec's content-gated engine, which requires the byte-exact original
APK.  Removing the packer removes the registrar, so the rebuilt app dies
at the first VMP-protected method:

    App.onCreate:139 -> Aria.init -> SqlHelper.getDb -> UnsatisfiedLinkError

The natives are SecLLVM-compiled inside libexec.so (they never re-materialize
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

Phase-3 r4 additions (boot-test 34282297861: the app died at
VerifyError da.w.<init>(String) "Constructor returning without calling
superclass constructor", then the ranger handler thread NPE'd):

  CTOR-STUB FIX  the warm-up materialized the extraction-stub bodies for
     ~21,600 of 32,459 classes; the remaining ones keep the packer's
     return-void+nop stub bodies in NON-native ctors (6,940 in the
     1.17.6 winners).  The ART verifier rejects every one of them at
     class-load time.  For each such ctor this pass PREPENDS a
     super-constructor invocation:
       * FORWARD - the direct superclass (resolved from the DEX class
         tables, or the framework table extracted from android.jar)
         declares an accessible <init> with the SAME proto -> forward
         the parameter registers (p0, p1, ...) / invoke-direct/range
         when the arg words exceed the 35c format.
       * NOARG   - the superclass has an accessible <init>()V.
       * DEFAULTS - synthesize default arguments (null / 0 / 0L) for the
         superclass' shortest accessible <init> proto (Kotlin lambda
         superctors, View/Dialog families, ...).
     Native-flagged ctor stubs get the same supercall inside their
     synthesized default body (r3 injected Object.<init> - legal ONLY
     when Object is the direct superclass; r4 resolves the real one).
     The original stub instructions after return-void become unreachable
     dead code, which the ART verifier skips - annotations, .line info
     and .param blocks are preserved untouched.

  RUN SHIELD  background SDK threads whose native methods were de-natified
     to null-returning stubs die on the first use of the null result and
     take the WHOLE process down (Android kills the process on any
     uncaught exception, even off-main).  Boot-test 34282297861:
     com.titan.ranger.NativeJni$v.run -> Gson.fromJson(null) ->
     RangerResult.getRes() NPE on the handlerRanger thread.  The
     original run() is renamed to run$shielded and a new run() wrapper
     delegates inside try/catch Throwable - the thread degrades
     silently instead of killing the app.

  KILL   (integration with the parallel r4-beta line) the <clinit> of
     SDK classes whose native JNI_OnLoad starts handler threads that
     NPE against the de-natified stubs is replaced with return-void
     outright - the SDK never initializes, its threads never start.
     Cross-DEX xref evidence showed nothing outside com.titan.ranger.*
     references the SDK, so there are zero app-side side effects; the
     SHIELD stays as defense in depth behind it.

Pipeline position:  dedup_redump.py  ->  THIS  ->  rebuild_unpacked_apk.py
(the output keeps the classes.dex..classesN.dex names the rebuild expects;
the confusion patch runs inside the rebuild on the carrier, independent of
this step).

Usage:
  python3 unpack/denatify_redump.py \
      --dex-dir work/booteable-dexes --out-dir work/denatified-dexes \
      [--bodies unpack/denatify_bodies.json] [--apktool work/apktool.jar] \
      [--framework-ctors work/framework-ctors.json]

Verification (built in, hard failure on mismatch):
  - every output DEX: magic + header file_size == len + method count equal
    to its input + class count equal
  - remaining natives == exactly the KEEP set
  - remaining super-less ctors == exactly the CTORFIX "left" set (classes
    whose direct super has no accessible <init> anywhere)
  - report json: per-dex counts of real/stub/keep/guard/ctorfix + the
    full stub list
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

# GUARD: wrap the <clinit> of these classes in a try/catch so a loadLibrary
# failure (SDK kill-switch: the lib's JNI_OnLoad validates the signing
# certificate and returns JNI_ERR on the re-signed research build) kills the
# CLASS init gracefully instead of the PROCESS.  Boot-test 34281060343:
# com.titan.ranger.NativeJni.<clinit> -> System.loadLibrary("ranger-jni") ->
# UnsatisfiedLinkError: JNI_ERR returned from JNI_OnLoad in libranger-jni.so
# -> FATAL EXCEPTION on the handlerTitan thread.
GUARD_CLASSES = (  # empty since r4: NativeJni moved to KILL_CLASSES
    # (the try/catch wrap mechanism stays for future signature-gated SDKs)
)

# KILL: replace the <clinit> of these classes with return-void entirely
# (takes precedence over GUARD for the same class).  Boot-test
# 34282297861 post-mortem: the r3 guard kept the NativeJni class-init
# alive, but its JNI_OnLoad had ALREADY started the handlerRanger
# thread before rejecting the re-signed certificate, and the clinit
# aborted at the throw point - the posted runnable then read a null
# static and NPE'd.  A cross-DEX xref scan of all 5 winners (invokes +
# static field ops + const-strings) shows NO class outside
# com.titan.ranger.* ever references the SDK, so killing the class-init
# prevents the thread from starting at all with zero app-side side
# effects.
KILL_CLASSES = (
    "Lcom/titan/ranger/NativeJni;",
    "Lcom/titan/ranger/JniHandler;",
)

# SHIELD: rename-wrap run()V of these classes so an uncaught Throwable on
# the SDK's handler thread degrades that thread instead of the process
# (defense in depth behind KILL: anything that still posts a runnable
# against the de-natified natives gets caught).
SHIELD_RUN_CLASSES = (
    "Lcom/titan/ranger/NativeJni$v;",   # run() NPEs on the null stub result
)

# Built-in framework ctor table used when --framework-ctors is not given
# (the CI build extracts the authoritative table from android.jar; this
# fallback covers the java.lang families that always matter locally).
_THROWABLE_PROTOS = [
    "()V",
    "(Ljava/lang/String;)V",
    "(Ljava/lang/String;Ljava/lang/Throwable;)V",
    "(Ljava/lang/Throwable;)V",
]
FRAMEWORK_BUILTIN = {
    "Ljava/lang/Object;": ["()V"],
    "Ljava/lang/Throwable;": _THROWABLE_PROTOS,
    "Ljava/lang/Exception;": _THROWABLE_PROTOS,
    "Ljava/lang/Error;": _THROWABLE_PROTOS,
    "Ljava/lang/RuntimeException;": _THROWABLE_PROTOS,
    "Ljava/lang/IllegalStateException;": _THROWABLE_PROTOS,
    "Ljava/lang/IllegalArgumentException;": _THROWABLE_PROTOS,
    "Ljava/lang/IllegalAccessException;": _THROWABLE_PROTOS,
    "Ljava/lang/IndexOutOfBoundsException;": _THROWABLE_PROTOS,
    "Ljava/lang/ArrayIndexOutOfBoundsException;": _THROWABLE_PROTOS,
    "Ljava/lang/StringIndexOutOfBoundsException;": _THROWABLE_PROTOS,
    "Ljava/lang/ArithmeticException;": _THROWABLE_PROTOS,
    "Ljava/lang/ClassCastException;": _THROWABLE_PROTOS,
    "Ljava/lang/NullPointerException;": _THROWABLE_PROTOS,
    "Ljava/lang/UnsupportedOperationException;": _THROWABLE_PROTOS,
    "Ljava/lang/ClassNotFoundException;": _THROWABLE_PROTOS,
    "Ljava/lang/InterruptedException;": _THROWABLE_PROTOS,
    "Ljava/lang/InterruptedException;": _THROWABLE_PROTOS,
    "Ljava/io/IOException;": _THROWABLE_PROTOS,
    "Ljava/lang/IllegalThreadStateException;": _THROWABLE_PROTOS,
    "Ljava/util/concurrent/atomic/AtomicReference;": ["()V", "(Ljava/lang/Object;)V"],
    "Ljava/util/concurrent/atomic/AtomicInteger;": ["()V", "(I)V"],
    "Ljava/util/concurrent/atomic/AtomicLong;": ["()V", "(J)V"],
    "Ljava/util/concurrent/atomic/AtomicBoolean;": ["()V", "(Z)V"],
    "Ljava/util/concurrent/atomic/AtomicMarkableReference;": ["(Ljava/lang/Object;Z)V"],
    "Ljava/util/concurrent/atomic/AtomicStampedReference;":
        ["(Ljava/lang/Object;I)V"],
    "Ljava/lang/Thread;": ["()V", "(Ljava/lang/String;)V"],
    "Ljava/lang/Thread$UncaughtExceptionHandler;": [],
    "Ljava/util/TimerTask;": ["()V"],
    "Ljava/lang/Enum;": ["(Ljava/lang/String;I)V"],
    # org.apache.http lives on the platform BOOT CLASSPATH but was
    # dropped from the public API-30 android.jar - the com.loopj
    # async-http subclasses still invoke-direct these (protected from
    # a subclass is legal regardless of package)
    "Lorg/apache/http/entity/HttpEntityWrapper;":
        ["(Lorg/apache/http/HttpEntity;)V"],
    "Lorg/apache/http/client/methods/HttpEntityEnclosingRequestBase;":
        ["()V"],
    "Lorg/apache/http/impl/client/DefaultRedirectHandler;": ["()V"],
}

METHOD_RE = re.compile(r"^\.method\s+(.*?)\s+([A-Za-z_$<>0-9_]+)\((.*?)\)(\S+)\s*$")
CLASS_RE = re.compile(r"^\.class\s+.*?(L[^;]+;)")
SUPER_RE = re.compile(r"^\.super\s+(L[^;]+;)")
INVOKE_INIT_RE = re.compile(
    r"^\s*invoke-direct(?:/range)?\s+.*?-><init>\(", re.M)
ACC_PUBLIC = 0x1
ACC_PRIVATE = 0x2
ACC_PROTECTED = 0x4

# ---------------------------------------------------------------------------
# DEX class-map: supers, ctor protos, super-less stub ctors (phase-3 r4)
# ---------------------------------------------------------------------------

def _uleb(d: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = d[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, off


class DexClassMap:
    """Cross-DEX class map: super chain, accessible ctor protos per class,
    and the set of (class, proto) ctors whose body never calls a
    super/this constructor (the un-materialized extraction stubs)."""

    def __init__(self, dex_paths: list[Path]):
        self.supers: dict[str, str] = {}
        self.ctor_protos: dict[str, list[tuple[str, int]]] = {}
        self.bad_ctors: list[tuple[str, str]] = []
        self.bad_ctors_per_dex: dict[str, list[tuple[str, str]]] = {}
        for p in dex_paths:
            self._ingest(p)

    def _ingest(self, path: Path) -> None:
        d = path.read_bytes()
        if d[:4] != b"dex\n":
            raise ValueError(f"{path}: bad magic")
        str_size, str_off = struct.unpack_from("<II", d, 56)
        type_size, type_off = struct.unpack_from("<II", d, 64)
        proto_off = struct.unpack_from("<I", d, 76)[0]
        m_size, m_off = struct.unpack_from("<II", d, 88)
        cls_size, cls_off = struct.unpack_from("<II", d, 96)

        strings: list[str] = []
        for i in range(str_size):
            so = struct.unpack_from("<I", d, str_off + 4 * i)[0]
            _, p = _uleb(d, so)
            end = d.index(b"\x00", p)
            strings.append(d[p:end].decode("utf-8", "replace"))

        def tstr(idx: int) -> str:
            sidx = struct.unpack_from("<I", d, type_off + 4 * idx)[0]
            return strings[sidx]

        def proto_of(pidx: int) -> str:
            e = proto_off + 12 * pidx
            ridx = struct.unpack_from("<I", d, e + 4)[0]
            poff = struct.unpack_from("<I", d, e + 8)[0]
            params = []
            if poff:
                n = struct.unpack_from("<I", d, poff)[0]
                for k in range(n):
                    ti = struct.unpack_from("<H", d, poff + 4 + 2 * k)[0]
                    params.append(tstr(ti))
            return "(" + "".join(params) + ")" + tstr(ridx)

        def method_info(midx: int) -> tuple[str, str, str]:
            off = m_off + 8 * midx
            cls_idx, proto_idx, name_idx = struct.unpack_from("<HHI", d, off)
            return tstr(cls_idx), strings[name_idx], proto_of(proto_idx)

        def body_calls_ctor(code_off: int) -> bool:
            # any invoke-direct/-super opcode in the low byte of the insn
            # units = a real super/this call; the packer's extraction stubs
            # are return-void+nops.  Opcodes live in the LOW byte of each
            # little-endian 16-bit unit: 0x6f invoke-super, 0x70
            # invoke-direct, 0x75 invoke-super/range, 0x76
            # invoke-direct/range.
            if not code_off:
                return False
            insns_size = struct.unpack_from("<I", d, code_off + 12)[0]
            insns = d[code_off + 16:code_off + 16 + insns_size * 2]
            for k in range(0, len(insns) - 1, 2):
                if insns[k] in (0x6F, 0x70, 0x75, 0x76):
                    return True
            return False

        for i in range(cls_size):
            base = cls_off + 32 * i
            # class_def_item: class_idx@0 access@4 superclass_idx@8
            # interfaces@12 source@16 annotations@20 class_data@24
            cls = tstr(struct.unpack_from("<I", d, base)[0])
            sup_idx = struct.unpack_from("<I", d, base + 8)[0]
            cdo = struct.unpack_from("<I", d, base + 24)[0]
            self.supers[cls] = tstr(sup_idx) if sup_idx != 0xFFFFFFFF else ""
            if not cdo:
                continue
            off = cdo
            n_static, off = _uleb(d, off)
            n_inst, off = _uleb(d, off)
            n_direct, off = _uleb(d, off)
            n_virtual, off = _uleb(d, off)
            for _ in range(n_static + n_inst):   # encoded fields: 2 ulebs
                _, off = _uleb(d, off)
                _, off = _uleb(d, off)
            protos = self.ctor_protos.setdefault(cls, [])
            for list_len in (n_direct, n_virtual):
                prev_m = 0
                for _ in range(list_len):
                    md, off = _uleb(d, off)
                    prev_m += md
                    flags, off = _uleb(d, off)
                    code_off, off = _uleb(d, off)
                    _, name, proto = method_info(prev_m)
                    if name != "<init>":
                        continue
                    protos.append((proto, flags))
                    if not (flags & 0x0100) and not body_calls_ctor(code_off):
                        self.bad_ctors.append((cls, proto))
                        self.bad_ctors_per_dex.setdefault(path.name, []).append(
                            (cls, proto))


def load_framework_ctors(path: str | Path) -> dict[str, list[str]]:
    """{class descriptor: [accessible <init> protos]}.  Layered: the
    android.jar extract (unpack/framework_ctors.py) first, the built-in
    java.lang/org.apache.http table under it (the SDK jar misses the
    boot-classpath http legacy and the Sable mirror trims the rest)."""
    out = dict(FRAMEWORK_BUILTIN)
    p = Path(path)
    if p.is_file():
        raw = json.loads(p.read_text(encoding="utf-8"))
        for k, v in raw.items():
            if v:
                out[k] = list(v)
    return out


# ---------------------------------------------------------------------------
# super-call selection + smali emission (phase-3 r4)
# ---------------------------------------------------------------------------

def _proto_params(proto: str) -> list[str]:
    """top-level parameter descriptors of a proto."""
    params = proto[1:proto.rindex(")")]
    out: list[str] = []
    i = 0
    while i < len(params):
        ch = params[i]
        if ch == "[":
            j = i
            while j < len(params) and params[j] == "[":
                j += 1
            if j < len(params) and params[j] == "L":
                end = params.index(";", j)
                out.append(params[i:end + 1])
                i = end + 1
            else:
                out.append(params[i:j + 1])
                i = j + 1
        elif ch == "L":
            end = params.index(";", i)
            out.append(params[i:end + 1])
            i = end + 1
        else:
            out.append(ch)
            i += 1
    return out


def _proto_words(proto: str) -> int:
    """register words of a proto's parameters (J/D take two)."""
    return sum(2 if t in ("J", "D") else 1 for t in _proto_params(proto))


def _same_package(a: str, b: str) -> bool:
    """True when two class descriptors share their java package."""
    pa = a[:a.rindex("/")] if "/" in a else ""
    pb = b[:b.rindex("/")] if "/" in b else ""
    return pa == pb


def choose_super_call(cls: str, proto: str, supers: dict, ctor_protos: dict,
                      framework_ctors: dict):
    """(mode, super_desc, target_proto) for the super-call to inject.

    mode: "forward" (param registers reused), "noarg" (()V),
          "defaults" (synthesized default args), or None (left as-is:
          the direct super exposes no accessible <init> anywhere).

    Accessibility: PUBLIC/PROTECTED supers' ctors are invocable from any
    subclass; PACKAGE-PRIVATE ctors (the obfuscated app dexes strip the
    access bits to ACC_CONSTRUCTOR-only, e.g. reactivex'
    AbstractFlowableWithUpstream) are legal when the subclass lives in
    the SAME java package - the io/reactivex internal operator
    hierarchy (169 of the 352 unpatched ctors) is exactly that shape."""
    sup = supers.get(cls)
    if not sup:
        return None
    protos: list[str] | None = None
    if sup in ctor_protos:
        same_pkg = _same_package(cls, sup)
        protos = [p for (p, fl) in ctor_protos[sup]
                  if (fl & (ACC_PUBLIC | ACC_PROTECTED))
                  or (same_pkg and not fl & ACC_PRIVATE)]
    if not protos:
        protos = framework_ctors.get(sup)
    if not protos:
        if sup == "Ljava/lang/Object;":
            return ("forward" if proto == "()V" else "noarg",
                    sup, "()V")
        return None
    if proto in protos:
        return ("forward", sup, proto)
    if "()V" in protos:
        return ("noarg", sup, "()V")
    target = sorted(protos, key=_proto_words)[0]
    return ("defaults", sup, target)


def _reg_list_for_forward(proto: str) -> tuple[list[str], bool]:
    """(register list for p0+params, needs_range).  Registers: p0 this,
    then each param's START register (wide pairs list only the first)."""
    regs = ["p0"]
    r = 1
    for t in _proto_params(proto):
        regs.append(f"p{r}")
        r += 2 if t in ("J", "D") else 1
    words = 1 + (r - 1)
    return regs, words > 5


def _read_frame_locals(block: list[str], param_words: int) -> int:
    """effective .locals count of a method block (handles .registers)."""
    for ln in block:
        m = re.match(r"^\s*\.locals\s+(\d+)\s*$", ln)
        if m:
            return int(m.group(1))
        m = re.match(r"^\s*\.registers\s+(\d+)\s*$", ln)
        if m:
            # .registers = total frame (locals + param words incl. this)
            return max(int(m.group(1)) - param_words, 0)
    return 0


def emit_super_call(cls: str, proto: str, mode: str, sup: str, target: str,
                    as_body: bool, frame_locals: int = 0) -> tuple[int, str]:
    """(locals_count, smali lines) of the super <init> invocation.

    as_body=True -> full replacement body (native ctor stubs): the call
    plus return-void.  as_body=False -> prependable snippet ending with a
    blank line (non-native stubs keep their return-void + dead nops).

    frame_locals: the stub's CURRENT .locals (prepended patches only) -
    p0's final v-index equals it, and the 35c format encodes register
    indices as 4-bit nibbles, so any p-register beyond v15 forces the
    invoke-direct/range form (smali 'Invalid register: vNN. Must be
    between v0 and v15' otherwise - classes3 dex build, ProgramInfo's
    17-word Kotlin default ctor)."""
    if mode == "forward":
        words = _proto_words(target)
        use_range = (1 + words > 5) or (frame_locals + words > 15)
        if use_range:
            regs, _ = _reg_list_for_forward(target)
            last = regs[-1]
            invoke = (f"    invoke-direct/range {{p0 .. {last}}}, "
                      f"{sup}-><init>{target}\n")
        else:
            regs, _ = _reg_list_for_forward(target)
            invoke = (f"    invoke-direct {{{', '.join(regs)}}}, "
                      f"{sup}-><init>{target}\n")
        if as_body:
            return 0, invoke + "\n    return-void\n"
        return 0, invoke
    if mode == "noarg":
        use_range = frame_locals > 15
        if use_range:
            invoke = f"    invoke-direct/range {{p0 .. p0}}, {sup}-><init>()V\n"
        else:
            invoke = f"    invoke-direct {{p0}}, {sup}-><init>()V\n"
        if as_body:
            return 0, invoke + "\n    return-void\n"
        return 0, invoke
    # defaults: synthesize null/0 args for the target proto
    params = _proto_params(target)
    words = _proto_words(target)
    use_range = (1 + words) > 5 or frame_locals > 15
    lines: list[str] = []
    if use_range:
        # v0 = this, v1.. = args, contiguous -> invoke-direct/range
        locals_n = 1 + words
        # move-object/from16 (22x): the plain move-object is 12x with TWO
        # 4-bit register slots - p0 lives beyond v15 on wide-frame stubs
        # ('Invalid register: v20', classes3 y6/b.<init>(Context))
        lines.append("    move-object/from16 v0, p0")
        r = 1
        for t in params:
            lines.extend(_default_const(t, r))
            r += 2 if t in ("J", "D") else 1
        invoke = (f"    invoke-direct/range {{v0 .. v{locals_n - 1}}}, "
                  f"{sup}-><init>{target}\n")
    else:
        locals_n = max(words, 1)
        r = 0
        starts = []
        for t in params:
            starts.append(f"v{r}")
            lines.extend(_default_const(t, r))
            r += 2 if t in ("J", "D") else 1
        invoke = (f"    invoke-direct {{p0, {', '.join(starts)}}}, "
                  f"{sup}-><init>{target}\n") if starts else \
                 (f"    invoke-direct {{p0}}, {sup}-><init>{target}\n")
    body = "\n".join(lines) + "\n" if lines else ""
    if as_body:
        return locals_n, body + invoke + "\n    return-void\n"
    return locals_n, body + invoke


def _default_const(t: str, reg: int) -> list[str]:
    if t in ("J", "D"):
        # const-wide/16 is 51l (8-bit register): fine for any reg < 256
        return [f"    const-wide/16 v{reg}, 0x0"]
    if reg > 15:
        # const/4 is 11n (4-bit register): switch to const/16 (21s, 8-bit)
        return [f"    const/16 v{reg}, 0x0"]
    if t.startswith("L") or t.startswith("["):
        return [f"    const/4 v{reg}, 0x0"]
    # Z B S C I F: const/4 0 covers every cat-1 zero literal
    return [f"    const/4 v{reg}, 0x0"]


def default_body_smali(proto_ret: str, name: str = "",
                       cls: str = "", proto: str = "",
                       supers: dict | None = None, ctor_protos: dict | None = None,
                       framework_ctors: dict | None = None) -> tuple[int, str]:
    """(locals_count, smali body lines) for a synthesized default return.

    Constructors are special: the Dalvik verifier REQUIRES every <init> to
    call a superclass constructor before returning (boot-test 34281060343:
    'da.w.<init>(String) failed to verify: Constructor returning without
    calling superclass constructor').  r4 resolves the REAL direct
    superclass (DEX map + framework table) instead of assuming Object -
    invoke-direct on Object.<init> only verifies when Object IS the
    direct super."""
    if name == "<init>":
        choice = choose_super_call(cls, proto, supers or {},
                                   ctor_protos or {}, framework_ctors or {})
        if choice:
            mode, sup, target = choice
            return emit_super_call(cls, proto, mode, sup, target, as_body=True)
        # unreachable super: Object.<init> as the only legal-ish fallback
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


def parse_dex_headers(path: Path) -> tuple[int, int, int]:
    """(class_defs_size, method count total, native count) sanity snapshot."""
    data = path.read_bytes()
    if data[:4] != b"dex\n":
        raise ValueError(f"{path}: bad magic")
    file_size = struct.unpack_from("<I", data, 32)[0]
    if file_size != len(data):
        raise ValueError(f"{path}: header file_size {file_size} != {len(data)}")
    cls_size, cls_off = struct.unpack_from("<II", data, 96)

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

def patch_smali_file(path: Path, bodies: dict, report: dict,
                     supers: dict, ctor_protos: dict,
                     framework_ctors: dict,
                     bad_ctor_classes: set) -> None:
    """Rewrite every native method declaration in one .smali file, inject
    super-calls into un-materialized ctor stubs, and shield run() bodies."""
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    cls_m = CLASS_RE.search(text)
    cls_desc = cls_m.group(1) if cls_m else "L?;"
    guarded = cls_desc in GUARD_CLASSES
    killed = cls_desc in KILL_CLASSES
    shielded = cls_desc in SHIELD_RUN_CLASSES
    ctor_stub = cls_desc in bad_ctor_classes
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
        if not m:
            out.append(header)
            out.extend(block)
            out.append(end_line)
            i = j + 1
            continue
        flags, name, params, ret = m.group(1), m.group(2), m.group(3), m.group(4)
        proto = f"({params}){ret}"
        key = f"{cls_desc}|{name}|{proto}"
        is_native = " native " in header + " " or re.search(
            r"\bnative\b", header)
        block_text = "\n".join(block)

        # ---- SHIELD: rename-wrap run() of noisy SDK handler threads ----
        if shielded and name == "run" and params == "" and ret == "V" \
                and not is_native:
            new_name = "run$shielded"
            new_header = re.sub(r"\b" + re.escape(name) + r"\(",
                                new_name + "(", header, count=1)
            out.append(new_header)
            out.extend(block)
            out.append(end_line)
            report["shield"].append(key)
            # synthesized wrapper run()
            inv = "invoke-direct" if " private " in header + " " else \
                  "invoke-virtual"
            out.append(".method public run()V")
            out.append("    .locals 0")
            out.append("")
            out.append("    :try_start_0")
            out.append(f"    {inv} {{p0}}, {cls_desc}->run$shielded()V")
            out.append("    :try_end_0")
            out.append("    .catch Ljava/lang/Throwable; "
                       "{:try_start_0 .. :try_end_0} :catch_0")
            out.append("")
            out.append("    return-void")
            out.append("")
            out.append("    :catch_0")
            out.append("    return-void")
            out.append(".end method")
            i = j + 1
            continue

        # ---- KILL: replace the whole <clinit> of noisy SDK classes ----
        if killed and name == "<clinit>":
            # The SDK's native JNI_OnLoad already started its handler
            # threads before rejecting the re-signed certificate; a
            # guarded (try/catch) class-init still leaves those threads
            # running against null stubs.  Killing the class-init
            # outright prevents the library load (and the threads) from
            # ever happening.
            out.append(header)
            out.append("    .locals 0")
            out.append("")
            out.append("    return-void")
            out.append(end_line)
            report["kill"].append(key)
            i = j + 1
            continue

        # ---- GUARD: <clinit> of SDK classes with signature-gated libs ----
        if guarded and name == "<clinit>":
            # keep the original class-init body but make a loadLibrary
            # failure (SDK signature gate in JNI_OnLoad) non-fatal - the
            # (de-natified) siblings degrade to stubs instead of killing
            # the process at class-init time.
            out.append(header)
            out.append("    :try_start_0")
            out.extend(block)
            out.append("    :try_end_0")
            out.append("    .catch Ljava/lang/UnsatisfiedLinkError; "
                       "{:try_start_0 .. :try_end_0} :catch_0")
            out.append("    :catch_0")
            out.append("    return-void")
            out.append(end_line)
            report["guard"].append(key)
            i = j + 1
            continue

        # ---- KEEP: genuine JNI, declaration untouched ----
        if is_native and any(cls_desc.startswith(p) for p in KEEP_PREFIXES):
            report["keep"].append(key)
            out.append(header)
            out.extend(block)
            out.append(end_line)
            i = j + 1
            continue

        # ---- CTOR-STUB FIX (non-native): prepend the super call ----
        if not is_native and name == "<init>" and ctor_stub \
                and not INVOKE_INIT_RE.search(block_text):
            choice = choose_super_call(cls_desc, proto, supers,
                                       ctor_protos, framework_ctors)
            if choice:
                mode, sup, target = choice
                param_words = 1 + _proto_words(proto)
                frame_locals = _read_frame_locals(block, param_words)
                locals_n, snippet = emit_super_call(
                    cls_desc, proto, mode, sup, target, as_body=False,
                    frame_locals=frame_locals)
                out.append(header)
                if locals_n:
                    block = _bump_locals(block, locals_n)
                out.append(snippet.rstrip("\n"))
                out.append("")
                out.extend(block)
                out.append(end_line)
                report["ctorfix"].setdefault(mode, []).append(key)
            else:
                # no accessible super ctor anywhere: leave it (VerifyError
                # only if the class is actually loaded)
                out.append(header)
                out.extend(block)
                out.append(end_line)
                report["ctorfix"]["left"].append(key)
            i = j + 1
            continue

        # ---- native de-natify: KEEP(real bodies)/STUB(defaults) ----
        if is_native:
            if key in bodies:
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
                locals_n, body = default_body_smali(
                    ret, name, cls_desc, proto, supers, ctor_protos,
                    framework_ctors)
                new_header = header.replace(" native ", " ", 1)
                if new_header == header:
                    new_header = re.sub(r"\bnative\b\s*", "", header, count=1)
                out.append(new_header)
                out.append(f"    .locals {locals_n}")
                out.extend(block)          # annotations, if any
                out.append(body.rstrip("\n"))
                out.append(end_line)
                report["stub"].append(key)
            i = j + 1
            continue

        out.append(header)
        out.extend(block)
        out.append(end_line)
        i = j + 1
    path.write_text("\n".join(out), encoding="utf-8")


def _bump_locals(block: list[str], needed: int) -> list[str]:
    """raise the .locals directive of a method block to `needed`
    (grows a .registers directive by the same delta)."""
    for k, ln in enumerate(block):
        m = re.match(r"^(\s*)\.locals\s+(\d+)\s*$", ln)
        if m:
            cur = int(m.group(2))
            if cur < needed:
                block[k] = f"{m.group(1)}.locals {needed}"
            return block
    for k, ln in enumerate(block):
        m = re.match(r"^(\s*)\.registers\s+(\d+)\s*$", ln)
        if m:
            # .registers R == .locals R - param_words; growing the total
            # by `needed` grows the locals by the same amount
            cur = int(m.group(2))
            block[k] = f"{m.group(1)}.registers {cur + needed}"
            return block
    # no .locals directive (implicit 0): insert at the top
    block.insert(0, f"    .locals {needed}")
    return block


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
    ap.add_argument("--framework-ctors", default="",
                    help="JSON {class: [accessible <init> protos]} from "
                         "unpack/framework_ctors.py (android.jar)")
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

    # phase-3 r4: cross-DEX class maps (supers, ctor protos, stub ctors)
    cmap = DexClassMap(dexes)
    framework_ctors = load_framework_ctors(args.framework_ctors)
    bad_ctor_classes = {cls for (cls, _) in cmap.bad_ctors}
    print(f"[*] class maps: {len(cmap.supers)} classes, "
          f"{len(cmap.bad_ctors)} super-less ctor stubs, "
          f"{len(framework_ctors)} framework supers", flush=True)

    full_report = {"dexes": [], "policy": {
        "keep_prefixes": list(KEEP_PREFIXES),
        "shield_run_classes": list(SHIELD_RUN_CLASSES),
        "kill_classes": list(KILL_CLASSES),
        "bodies_file": str(args.bodies),
        "framework_ctors": str(args.framework_ctors or "<builtin>"),
    }}
    failures = []
    for dex in dexes:
        print(f"[*] de-natifying {dex.name} ({dex.stat().st_size:,} B)", flush=True)
        cls_pre, m_pre, n_pre = parse_dex_headers(dex)
        report = {"dex": dex.name, "real": [], "stub": [],
                  "keep": [], "guard": [], "shield": [], "kill": [],
                  "ctorfix": {"forward": [], "noarg": [], "defaults": [],
                              "left": []}}
        with tempfile.TemporaryDirectory(prefix="denatify_") as td:
            workdir = Path(td)
            decoded = apktool_decode_dex(apktool, dex, workdir / "decoded", workdir)
            smali_root = decoded / "smali"
            count = 0
            for smali in sorted(smali_root.rglob("*.smali")):
                txt = smali.read_text(encoding="utf-8")
                if "\n.method " not in txt and not txt.startswith(".method "):
                    continue
                cls_m = CLASS_RE.search(txt)
                cls_desc = cls_m.group(1) if cls_m else "L?;"
                needs = (re.search(r"^\.method[^\n]*\bnative\b", txt, re.M)
                         or cls_desc in GUARD_CLASSES
                         or cls_desc in KILL_CLASSES
                         or cls_desc in bad_ctor_classes
                         or cls_desc in SHIELD_RUN_CLASSES)
                if not needs:
                    continue
                patch_smali_file(smali, bodies, report, cmap.supers,
                                 cmap.ctor_protos, framework_ctors,
                                 bad_ctor_classes)
                count += 1
            data = apktool_build_dex(apktool, decoded, workdir)
        (out_dir / dex.name).write_bytes(data)
        cls_post, m_post, n_post = parse_dex_headers(out_dir / dex.name)
        # re-scan the output for remaining super-less ctor stubs
        out_cmap = DexClassMap([out_dir / dex.name])
        dex_bad_in = [kp for kp in cmap.bad_ctors_per_dex.get(dex.name, [])]
        entry = {
            "dex": dex.name,
            "in_size": dex.stat().st_size,
            "out_size": len(data),
            "classes_in": cls_pre, "classes_out": cls_post,
            "methods_in": m_pre, "methods_out": m_post,
            "natives_in": n_pre, "natives_out": n_post,
            "bad_ctors_in": len(dex_bad_in),
            "bad_ctors_out": len(out_cmap.bad_ctors),
            "real": len(report["real"]),
            "stub": len(report["stub"]),
            "keep": len(report["keep"]),
            "guard": len(report["guard"]),
            "shield": len(report["shield"]),
            "kill": len(report["kill"]),
            "ctorfix_forward": len(report["ctorfix"]["forward"]),
            "ctorfix_noarg": len(report["ctorfix"]["noarg"]),
            "ctorfix_defaults": len(report["ctorfix"]["defaults"]),
            "ctorfix_left": len(report["ctorfix"]["left"]),
        }
        full_report["dexes"].append(entry)
        print(f"    real={entry['real']} stub={entry['stub']} "
              f"keep={entry['keep']} guard={entry['guard']} "
              f"shield={entry['shield']} kill={entry['kill']} "
              f"ctorfix(f/n/d)={entry['ctorfix_forward']}/"
              f"{entry['ctorfix_noarg']}/{entry['ctorfix_defaults']} "
              f"left={entry['ctorfix_left']} "
              f"natives {n_pre} -> {n_post} "
              f"bad_ctors -> {entry['bad_ctors_out']}", flush=True)
        # hard verification
        if cls_pre != cls_post:
            failures.append(f"{dex.name}: class count changed "
                            f"({cls_pre} -> {cls_post})")
        if m_post != m_pre + entry["shield"]:
            # each run-shield rename-wrap adds exactly one synthetic
            # wrapper method (run()V) per shielded class
            failures.append(f"{dex.name}: method count changed "
                            f"({m_pre} + {entry['shield']} shield -> "
                            f"{m_post})")
        if n_post != entry["keep"]:
            failures.append(f"{dex.name}: natives remaining {n_post} != "
                            f"keep set {entry['keep']}")
        left_keys = {k for k in report["ctorfix"]["left"]}
        left_pairs = {(k.split("|")[0], k.split("|")[2])
                      for k in left_keys}
        out_pairs = {(c, p) for (c, p) in out_cmap.bad_ctors}
        if out_pairs != left_pairs:
            failures.append(f"{dex.name}: super-less ctors remaining "
                            f"{len(out_pairs)} != expected left "
                            f"{len(left_pairs)} - the injection did not "
                            "apply everywhere")
        if entry["real"] == 0 and dex.name == "classes.dex":
            failures.append(f"{dex.name}: the SqlHelper REAL bodies did not "
                            "apply - check denatify_bodies.json keys")

    # aggregate
    full_report["totals"] = {
        "real": sum(d["real"] for d in full_report["dexes"]),
        "stub": sum(d["stub"] for d in full_report["dexes"]),
        "keep": sum(d["keep"] for d in full_report["dexes"]),
        "guard": sum(d["guard"] for d in full_report["dexes"]),
        "shield": sum(d["shield"] for d in full_report["dexes"]),
        "kill": sum(d["kill"] for d in full_report["dexes"]),
        "ctorfix_forward": sum(d["ctorfix_forward"] for d in full_report["dexes"]),
        "ctorfix_noarg": sum(d["ctorfix_noarg"] for d in full_report["dexes"]),
        "ctorfix_defaults": sum(d["ctorfix_defaults"] for d in full_report["dexes"]),
        "ctorfix_left": sum(d["ctorfix_left"] for d in full_report["dexes"]),
        "bad_ctors_out": sum(d["bad_ctors_out"] for d in full_report["dexes"]),
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
          f"kept-native={t['keep']} guarded-clinit={t['guard']} "
          f"shielded-run={t['shield']} killed-clinit={t['kill']} "
          f"ctorfix(f/n/d/l)={t['ctorfix_forward']}/{t['ctorfix_noarg']}/"
          f"{t['ctorfix_defaults']}/{t['ctorfix_left']} "
          f"-> {out_dir}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
