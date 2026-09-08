#!/usr/bin/env python3
"""Cross-reference scanner for the UNPACKED iJiami libexec.so image (x86).

The unpacked image shares vaddr layout with the original file:
  RX 0x0-0x7389c (code), RW 0xe5c00-0xf7d44 (data/strings/GOT).
SecShell code references strings via R_386_RELATIVE GOT slots (filled at
load) and via direct 32-bit immediates. This script:
  1. parses .rel.dyn of the ORIGINAL libexec.so -> {GOT slot: target vaddr}
  2. parses .rel.plt (JMPREL) -> {GOT slot: import name}
  3. scans the unpacked image for LE-encoded refs to interesting string
     vaddrs / their GOT slots / import GOT slots
  4. maps each code hit to the containing Ghidra function (funcs report)
Usage: xref_scan.py
"""
import struct, bisect, subprocess, sys

ORIG = "/home/z/youcine-re/ijm/assets/ijm_lib/x86/libexec.so"
IMG = "/tmp/unpack-exec/unpacked_image.bin"
FUNCS = "/tmp/ghidra-8a/reports/unpacked-funcs.txt"

orig = open(ORIG, "rb").read()
img = open(IMG, "rb").read()

# ---- parse dynamic ----
phoff = struct.unpack("<I", orig[28:32])[0]
dyn_off = dyn_sz = None
for i in range(struct.unpack("<H", orig[44:46])[0]):
    p = orig[phoff+32*i: phoff+32*(i+1)]
    t, off, va, pa, fsz, msz, fl, al = struct.unpack("<8I", p)
    if t == 2:
        dyn_off, dyn_sz = off, fsz
dyn = {}
p = dyn_off
while p < dyn_off + dyn_sz:
    tag, val = struct.unpack("<II", orig[p:p+8]); dyn[tag] = val; p += 8
    if tag == 0: break
symtab, strtab, strsz = dyn[6], dyn[5], dyn[10]
rel_off, rel_sz = dyn[17], dyn[12]          # .rel.dyn
jmprel, pltrelsz = dyn[23], dyn[2]          # .rel.plt
nb, nchain = struct.unpack("<II", orig[dyn[4]:dyn[4]+8])
def symname(j):
    no = struct.unpack("<I", orig[symtab+16*j:symtab+16*j+4])[0]
    if no >= strsz: return f"<oob{j}>"
    return orig[strtab+no:orig[strtab+no].find(b'\x00', strtab+no) if False else strtab+no+orig[strtab+no:].find(b'\x00')].decode('latin1')

# .rel.dyn: R_386_RELATIVE (type 8): *r_offset = base + addend(=target vaddr)
got_rel = {}          # got_slot -> target_vaddr
for k in range(rel_sz // 8):
    off, info = struct.unpack("<II", orig[rel_off+8*k:rel_off+8*k+8])
    if info & 0xff == 8:
        if off + 4 <= len(orig):
            addend = struct.unpack("<I", orig[off:off+4])[0]
            got_rel[off] = addend
# .rel.plt: import GOT slots
got_imp = {}
for k in range(pltrelsz // 8):
    off, info = struct.unpack("<II", orig[jmprel+8*k:jmprel+8*k+8])
    got_imp[off] = symname(info >> 8)
print(f".rel.dyn RELATIVE: {len(got_rel)} slots; .rel.plt: {len(got_imp)} import slots")

# ---- interesting strings (addr in unpacked img == vaddr) ----
INTERESTING = [
    ("s/h/e/l/l/N", 0x0f24bd), ("s/h/e/l/l/A", 0x0f2499), ("s/h/e/l/l/S", 0x0f24a5),
    ("s/h/e/l/l/C", 0x0f24c9), ("TracerPid", 0x0ef1e5), ("/proc/self/status", 0x0ef1d0),
    ("ro.kernel.qemu", 0x0ef374), ("/dev/qemu_pipe", 0x0ef232), ("goldfish", 0x0ef271),
    ("ijiami.dat", 0x0f251e), ("ijiami.dat(2)", 0x0f21be), ("sign_verify.png", 0x0f2226),
    ("libexecmain.so", 0x0f24e7), ("/proc/self/maps", 0x0ec41b),
    ("persist.nox.device", 0x0ef3e0), ("magisk-path", 0x0ef415),
    ("ro.product.device", 0x0ef390), ("qemu.hw.mainkeys", 0x0ef2b0),
    ("ro.debuggable?", None),
]
# find any string containing debuggable/ro.secure in img
for probe in (b"ro.debuggable", b"ro.secure", b"ro.build.tags", b"test-keys", b"JDWP", b"jdwp"):
    i = img.find(probe)
    if i >= 0:
        INTERESTING.append((probe.decode(), i))
    else:
        print(f"NOT FOUND in image: {probe.decode()!r}")

# string vaddr -> got slot
rev_rel = {}
for slot, tgt in got_rel.items():
    rev_rel.setdefault(tgt, slot)

# import names of interest
IMP_INT = {"__system_property_get", "fopen", "fgets", "ptrace", "kill", "fork",
           "pthread_create", "dlopen", "dlsym", "AAssetManager_open", "AAsset_read",
           "getpid", "getppid", "syscall", "access", "open", "read", "waitpid", "prctl",
           "opendir", "readdir", "readlink", "__system_property_get", "dl_iterate_phdr",
           "regcomp", "stat", "getenv", "sigaction", "bsd_signal"}

# Ghidra functions (vaddr, name) sorted
fns = []
for line in open(FUNCS):
    if line.startswith("FUNC "):
        parts = line.split()
        fns.append((int(parts[1], 16), parts[2], int(parts[3].split("=")[1])))
fns.sort()
starts = [f[0] for f in fns]
def find_fn(addr):
    i = bisect.bisect_right(starts, addr) - 1
    if i >= 0:
        s, nm, sz = fns[i]
        if addr < s + sz + 64:
            return f"{nm}@0x{s:x}+0x{addr-s:x}"
    return "<no-fn>"

def scan_img(le_value, label, limit=12):
    needle = struct.pack("<I", le_value)
    hits = []
    i = img.find(needle)
    while i != -1 and len(hits) < limit:
        hits.append(i)
        i = img.find(needle, i + 1)
    for h in hits:
        print(f"  ref {label} (0x{le_value:x}) @ img 0x{h:x} in {find_fn(h)}")
    if not hits:
        print(f"  ref {label} (0x{le_value:x}): NONE")
    return hits

print("\n=== refs to strings / their GOT slots ===")
allhits = {}
for label, va in INTERESTING:
    if va is None: continue
    print(f"-- {label} @0x{va:x}:")
    allhits[label] = scan_img(va, f"{label}-imm")
    slot = rev_rel.get(va)
    if slot:
        allhits[label + "/got"] = scan_img(slot, f"{label}-gotslot")

print("\n=== refs to import GOT slots (call sites) ===")
for slot, nm in sorted(got_imp.items()):
    if nm in IMP_INT:
        print(f"-- import {nm} (GOT 0x{slot:x}):")
        allhits[f"imp:{nm}"] = scan_img(slot, f"call {nm}")

# also: JNI_OnLoad target 0x5cbc0 (from emulate_stage2)
print("\n=== entry xrefs: 0x5cbc0 (JNI_OnLoad candidate) ===")
allhits["jni_onload"] = scan_img(0x5cbc0, "JNI_OnLoad")

import json
out = {k: [h for h in v] for k, v in allhits.items() if v}
open("/tmp/ghidra-8a/xref_hits.json", "w").write(json.dumps(out, indent=1))
print("\nsaved /tmp/ghidra-8a/xref_hits.json")
