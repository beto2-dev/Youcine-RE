#!/usr/bin/env python3
"""Neutralize the app-embedded iJiami anti-tamper kill-switch (Java side).

com.ijiami.residconfusion.ConfusionUtils is embedded in the decrypted DEX by
the packer. App.onCreate -> check(Context) spawns a watchdog thread that
re-reads the APK's v1 JAR certificates, MD5s them and compares against a
one-entry allowlist (the ORIGINAL developer cert MD5
545A2148B8864DB769E025EA43C6A699 plus debug placeholders). On mismatch -
which is ALWAYS the case for a re-signed research build - it fires
e(): HOME intent + System.exit(0). The CI boot log shows this exit firing
~0.3s after the SqlHelper.getDb crash (run 34142729238, logcat 16:21:55).

This tool performs minimal binary DEX surgery, keeping every structure
offset identical:

  cc(Ljava/lang/String;)Z  ->  const/4 v0, 1 ; return v0
  e()V                     ->  return-void

Only the first 2/4 bytes of each code item are overwritten; the remaining
original bytes become unreachable dead code, so tries/handlers and every
other structure stay valid for the verifier. DEX checksums (sha1 then
adler32, in that order - see validate_and_extract_dex.py) are recomputed
afterwards so ART accepts the file.

Usage:
  python3 patch_confusion_cc.py --dex classes.dex --out classes.patched.dex
  python3 patch_confusion_cc.py --dex classes.dex            (in place)
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zlib
from pathlib import Path

TARGET_CLASS = "Lcom/ijiami/residconfusion/ConfusionUtils;"
PATCH_CC_NAME = "cc"
PATCH_CC_DESC_PREFIX = "(Ljava/lang/String;)"
PATCH_CC_RET = "Z"
PATCH_CC_BYTES = bytes.fromhex("12100f00")  # const/4 v0,1 ; return v0
PATCH_E_NAME = "e"
PATCH_E_DESC_PREFIX = "()"
PATCH_E_RET = "V"
PATCH_E_BYTES = bytes.fromhex("0e00")      # return-void


def uleb128(data, off):
    result = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7


def read_mutf8_string(data, string_data_off):
    _, off = uleb128(data, string_data_off)
    end = data.index(b"\x00", off)
    return data[off:end].decode("utf-8", "replace")


class Dex:
    """Minimal read/write DEX view. All offsets stay byte-stable under the
    patches we apply (first-insn overwrite only)."""

    def __init__(self, data: bytearray):
        self.data = data
        if bytes(data[:4]) != b"dex\n":
            raise ValueError("not a dex file")
        (self.string_ids_size, self.string_ids_off) = struct.unpack_from("<II", data, 0x38)
        (self.type_ids_size, self.type_ids_off) = struct.unpack_from("<II", data, 0x40)
        (self.proto_ids_size, self.proto_ids_off) = struct.unpack_from("<II", data, 0x48)
        (self.method_ids_size, self.method_ids_off) = struct.unpack_from("<II", data, 0x58)
        (self.class_defs_size, self.class_defs_off) = struct.unpack_from("<II", data, 0x60)

    def string(self, idx):
        off = struct.unpack_from("<I", self.data, self.string_ids_off + 4 * idx)[0]
        return read_mutf8_string(self.data, off)

    def type_desc(self, idx):
        sidx = struct.unpack_from("<I", self.data, self.type_ids_off + 4 * idx)[0]
        return self.string(sidx)

    def proto_desc(self, idx):
        off = self.proto_ids_off + 12 * idx
        ret_type = struct.unpack_from("<I", self.data, off + 4)[0]
        params_off = struct.unpack_from("<I", self.data, off + 8)[0]
        desc = "("
        if params_off:
            size = struct.unpack_from("<I", self.data, params_off)[0]
            for i in range(size):
                tidx = struct.unpack_from("<H", self.data, params_off + 4 + 2 * i)[0]
                desc += self.type_desc(tidx)
        desc += ")" + self.type_desc(ret_type)
        return desc

    def method_id(self, idx):
        off = self.method_ids_off + 8 * idx
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.data, off)
        return (
            self.type_desc(class_idx),
            self.string(name_idx),
            self.proto_desc(proto_idx),
        )

    def find_class_data_off(self, class_desc):
        for i in range(self.class_defs_size):
            off = self.class_defs_off + 32 * i
            type_idx = struct.unpack_from("<I", self.data, off)[0]
            if self.type_desc(type_idx) == class_desc:
                return struct.unpack_from("<I", self.data, off + 24)[0]
        return 0

    def iter_methods(self, class_desc):
        """Yield (method_idx, access_flags, code_off) for every defined
        method (direct + virtual) of the class."""
        cd_off = self.find_class_data_off(class_desc)
        if cd_off == 0:
            return
        data = self.data
        off = cd_off
        static_n, off = uleb128(data, off)
        instance_n, off = uleb128(data, off)
        direct_n, off = uleb128(data, off)
        virtual_n, off = uleb128(data, off)
        for _ in range(static_n + instance_n):
            _, off = uleb128(data, off)  # field_idx_diff
            _, off = uleb128(data, off)  # access
        for _count in (direct_n, virtual_n):
            method_idx = 0
            for _ in range(_count):
                diff, off = uleb128(data, off)
                method_idx += diff
                access, off = uleb128(data, off)
                code_off, off = uleb128(data, off)
                yield method_idx, access, code_off

    def patch_method(self, class_desc, name, desc_prefix, ret, new_bytes):
        """Overwrite the first bytes of a method's insns.
        Returns (patched, code_off)."""
        for method_idx, _access, code_off in self.iter_methods(class_desc):
            _cls, mname, mdesc = self.method_id(method_idx)
            if mname == name and mdesc.startswith(desc_prefix) and mdesc.endswith(ret) and code_off:
                regs, ins, outs, tries = struct.unpack_from("<HHHH", self.data, code_off)
                debug_info_off = struct.unpack_from("<I", self.data, code_off + 8)[0]
                insns_size = struct.unpack_from("<I", self.data, code_off + 12)[0]
                insns_off = code_off + 16
                if insns_size * 2 < len(new_bytes):
                    print(f"[!] {name}{mdesc}: insns too small; skipped")
                    return False, code_off
                old = bytes(self.data[insns_off : insns_off + len(new_bytes)])
                self.data[insns_off : insns_off + len(new_bytes)] = new_bytes
                print(
                    f"[+] {class_desc}->{name}{mdesc}: patched "
                    f"{old.hex()} -> {new_bytes.hex()} "
                    f"(code_off=0x{code_off:x}, regs={regs}, ins={ins}, "
                    f"outs={outs}, tries={tries}, debug=0x{debug_info_off:x}, "
                    f"insns={insns_size}u)"
                )
                return True, code_off
        print(f"[!] {class_desc}->{name}: not found")
        return False, 0


def repair_checksums(buf: bytearray) -> None:
    # order matters: sha1 covers [32:end]; adler covers [12:end] (which
    # includes the fresh sha1) - same logic as validate_and_extract_dex.py
    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dex", required=True)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    src = Path(args.dex)
    data = bytearray(src.read_bytes())
    dex = Dex(data)
    if dex.find_class_data_off(TARGET_CLASS) == 0:
        print(f"[!] class {TARGET_CLASS} not present in {src}; nothing to do")
        return 2

    ok_cc, _ = dex.patch_method(
        TARGET_CLASS, PATCH_CC_NAME, PATCH_CC_DESC_PREFIX, PATCH_CC_RET, PATCH_CC_BYTES
    )
    ok_e, _ = dex.patch_method(
        TARGET_CLASS, PATCH_E_NAME, PATCH_E_DESC_PREFIX, PATCH_E_RET, PATCH_E_BYTES
    )
    if not (ok_cc or ok_e):
        print("[!] no target method patched")
        return 1

    repair_checksums(data)
    out = Path(args.out) if args.out else src
    out.write_bytes(bytes(data))
    print(
        f"[+] wrote {out} ({len(data)} bytes, "
        f"adler=0x{int.from_bytes(data[8:12], 'little'):08x})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
