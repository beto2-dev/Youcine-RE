#!/usr/bin/env python3
"""Extract every framework class' accessible <init> protos from android.jar.

Phase-3 r4 support for denatify_redump.py: the super-call injector needs
the exact accessible constructor signatures of framework superclasses
(android.widget.FrameLayout, java.util.concurrent.ThreadPoolExecutor,
android.os.AsyncTask, ...) to emit verifier-valid invoke-direct calls.
The app DEXes only describe the app's own classes, so the framework table
comes from the platform jar the CI already installs
($ANDROID_HOME/platforms/android-<api>/android.jar).

The SDK android.jar is a Java archive of .class files (javac needs
bytecode for -bootclasspath), so the primary parser walks the Java class
file format: constant pool -> this_class -> methods -> <init> descriptor.
A classes.dex inside the jar (some builds ship one) is parsed with the
same DEX walker used by the other tools.  Method descriptors and DEX
protos share the exact same grammar, so the output needs no translation.

Output JSON: {class descriptor: ["(Ljava/lang/String;I)V", ...]} covering
every class that declares at least one PUBLIC or PROTECTED <init> (the
only flags an app subclass may invoke-direct; protected is legal from
subclasses, private/package-private are excluded).

Usage:
  python3 unpack/framework_ctors.py \
      --jar "$ANDROID_HOME/platforms/android-30/android.jar" \
      --out work/framework-ctors.json
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import zipfile
from pathlib import Path

ACC_PUBLIC = 0x1
ACC_PROTECTED = 0x4
ACC_NATIVE = 0x100
ACC_ABSTRACT = 0x400


# ---------------------------------------------------------------------------
# Java .class parsing (constant pool + this_class + methods)
# ---------------------------------------------------------------------------

def _parse_class_file(data: bytes) -> tuple[str, list[tuple[str, int]]] | None:
    """(class descriptor, [(<init> proto, access_flags)]) or None."""
    if data[:4] != b"\xca\xfe\xba\xbe":
        return None
    off = 8  # magic + minor + major
    cp_count = struct.unpack_from(">H", data, off)[0]
    off += 2
    # constant pool: index 0 unused, tags 1..cp_count-1
    cp: dict[int, tuple] = {}
    i = 1
    while i < cp_count:
        tag = data[off]
        off += 1
        if tag == 1:  # Utf8: u2 len + bytes
            ln = struct.unpack_from(">H", data, off)[0]
            off += 2
            cp[i] = ("utf8", data[off:off + ln].decode("utf-8", "replace"))
            off += ln
        elif tag == 3:  # Integer
            cp[i] = ("int", None)
            off += 4
        elif tag == 4:  # Float
            cp[i] = ("float", None)
            off += 4
        elif tag == 5:  # Long (takes two slots)
            cp[i] = ("long", None)
            off += 8
            i += 1
        elif tag == 6:  # Double (takes two slots)
            cp[i] = ("double", None)
            off += 8
            i += 1
        elif tag == 7:  # Class: u2 name_index
            cp[i] = ("class", struct.unpack_from(">H", data, off)[0])
            off += 2
        elif tag == 8:  # String
            cp[i] = ("string", None)
            off += 2
        elif tag in (9, 10, 11):  # Field/Method/InterfaceMethod ref
            cp[i] = ("ref", None)
            off += 4
        elif tag == 12:  # NameAndType
            cp[i] = ("nat", None)
            off += 4
        elif tag == 15:  # MethodHandle
            cp[i] = ("mh", None)
            off += 3
        elif tag == 16:  # MethodType
            cp[i] = ("mt", None)
            off += 2
        elif tag == 17:  # Dynamic
            cp[i] = ("dyn", None)
            off += 4
        elif tag == 18:  # InvokeDynamic
            cp[i] = ("indy", None)
            off += 4
        elif tag == 19:  # Module
            cp[i] = ("mod", None)
            off += 2
        elif tag == 20:  # Package
            cp[i] = ("pkg", None)
            off += 2
        else:
            raise ValueError(f"unknown cp tag {tag} at index {i}")
        i += 1
    access_flags, this_class = struct.unpack_from(">HH", data, off)
    off += 4
    _super_class = struct.unpack_from(">H", data, off)[0]
    off += 2
    # this_class -> Class info -> utf8 name ("java/util/concurrent/...")
    name_idx = cp[this_class][1] if this_class in cp else 0
    name = cp[name_idx][1] if isinstance(cp.get(name_idx), tuple) and \
        cp.get(name_idx, (None,))[0] == "utf8" else ""
    if not name:
        return None
    cls_desc = "L" + name + ";"
    # interfaces
    n_ifaces = struct.unpack_from(">H", data, off)[0]
    off += 2 + 2 * n_ifaces
    # fields
    n_fields = struct.unpack_from(">H", data, off)[0]
    off += 2
    for _ in range(n_fields):
        off += 6
        off = _attr_end(data, off)
    # methods
    n_methods = struct.unpack_from(">H", data, off)[0]
    off += 2
    ctors: list[tuple[str, int]] = []
    for _ in range(n_methods):
        macc, mname, mdesc = struct.unpack_from(">HHH", data, off)
        off += 6
        off = _attr_end(data, off)
        if cp.get(mname, (None,))[0] == "utf8" and \
                cp[mname][1] == "<init>" and \
                cp.get(mdesc, (None,))[0] == "utf8":
            ctors.append((cp[mdesc][1], macc))
    return cls_desc, ctors


def _attr_end(data: bytes, off: int) -> int:
    """offset just past an attribute table at `off`."""
    n_attrs = struct.unpack_from(">H", data, off)[0]
    off += 2
    for _ in range(n_attrs):
        _name, ln = struct.unpack_from(">HI", data, off)
        off += 6 + ln
    return off


# ---------------------------------------------------------------------------
# DEX parsing (for jars that ship classes.dex)
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


def extract_dex(dex: bytes) -> dict[str, list[str]]:
    if dex[:4] != b"dex\n":
        raise ValueError("classes.dex: bad magic")
    str_size, str_off = struct.unpack_from("<II", dex, 56)
    type_size, type_off = struct.unpack_from("<II", dex, 64)
    proto_off = struct.unpack_from("<I", dex, 76)[0]
    m_off = struct.unpack_from("<I", dex, 92)[0]
    cls_size, cls_off = struct.unpack_from("<II", dex, 96)

    strings: list[str] = []
    for i in range(str_size):
        so = struct.unpack_from("<I", dex, str_off + 4 * i)[0]
        _, p = _uleb(dex, so)
        end = dex.index(b"\x00", p)
        strings.append(dex[p:end].decode("utf-8", "replace"))

    def tstr(idx: int) -> str:
        sidx = struct.unpack_from("<I", dex, type_off + 4 * idx)[0]
        return strings[sidx]

    def proto_of(pidx: int) -> str:
        e = proto_off + 12 * pidx
        ridx = struct.unpack_from("<I", dex, e + 4)[0]
        poff = struct.unpack_from("<I", dex, e + 8)[0]
        params = []
        if poff:
            n = struct.unpack_from("<I", dex, poff)[0]
            for k in range(n):
                ti = struct.unpack_from("<H", dex, poff + 4 + 2 * k)[0]
                params.append(tstr(ti))
        return "(" + "".join(params) + ")" + tstr(ridx)

    def method_name(midx: int) -> str:
        return strings[struct.unpack_from("<I", dex, m_off + 8 * midx + 4)[0]]

    out: dict[str, list[str]] = {}
    for i in range(cls_size):
        base = cls_off + 32 * i
        cls = tstr(struct.unpack_from("<I", dex, base)[0])
        cdo = struct.unpack_from("<I", dex, base + 24)[0]
        if not cdo:
            continue
        off = cdo
        n_static, off = _uleb(dex, off)
        n_inst, off = _uleb(dex, off)
        n_direct, off = _uleb(dex, off)
        n_virtual, off = _uleb(dex, off)
        for _ in range(n_static + n_inst):
            _, off = _uleb(dex, off)
            _, off = _uleb(dex, off)
        protos: list[str] = []
        for list_len in (n_direct, n_virtual):
            prev_m = 0
            for _ in range(list_len):
                md, off = _uleb(dex, off)
                prev_m += md
                flags, off = _uleb(dex, off)
                _, off = _uleb(dex, off)
                if method_name(prev_m) != "<init>":
                    continue
                if not (flags & (ACC_PUBLIC | ACC_PROTECTED)):
                    continue
                if flags & (ACC_NATIVE | ACC_ABSTRACT):
                    continue
                protos.append(proto_of(prev_m))
        if protos:
            out[cls] = protos
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jar", required=True, help="android.jar path")
    ap.add_argument("--out", required=True, help="output JSON path")
    args = ap.parse_args()

    table: dict[str, list[str]] = {}
    with zipfile.ZipFile(args.jar) as zf:
        names = zf.namelist()
        if "classes.dex" in names:
            # dex-based jar (rare): the DEX walker is authoritative
            table = extract_dex(zf.read("classes.dex"))
        else:
            # standard SDK jar: .class files
            parsed = classes = 0
            for n in names:
                if not n.endswith(".class") or n.startswith("module-info") \
                        or n.endswith("package-info.class"):
                    continue
                classes += 1
                try:
                    r = _parse_class_file(zf.read(n))
                except Exception:
                    continue
                if not r:
                    continue
                parsed += 1
                cls_desc, ctors = r
                protos = [p for (p, fl) in ctors
                          if fl & (ACC_PUBLIC | ACC_PROTECTED)
                          and not fl & (ACC_NATIVE | ACC_ABSTRACT)]
                if protos:
                    table[cls_desc] = protos
            print(f"[+] parsed {parsed}/{classes} .class entries", flush=True)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(table), encoding="utf-8")
    print(f"[+] {len(table)} framework classes with accessible ctors "
          f"-> {args.out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
