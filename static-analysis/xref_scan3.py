#!/usr/bin/env python3
"""XREF v3 (correct) for the unpacked iJiami libexec.so memory image.

Key fixes vs v2:
- vaddr != file offset for the RW PT_LOAD (vaddr 0xe5c00 -> file 0x75c00)
- the image IS a memory image (vaddr == image offset), so strings found in
  it are addressed by vaddr directly
- import calls are indirect: scan for `ff 15 <got>` / `ff 25 <got>` and any
  LE occurrence of import GOT slots in the code region
- string refs via R_386_RELATIVE pointer tables: find relocated data words
  whose addend == string vaddr, then find code refs to those words
Usage: xref_scan3.py
"""
import struct, bisect, re, json

ORIG = "/home/z/youcine-re/ijm/assets/ijm_lib/x86/libexec.so"
IMG = "/tmp/unpack-exec/unpacked_image.bin"
FUNCS = "/tmp/ghidra-8a/reports/unpacked-funcs.txt"
RX_END = 0x7389c

orig = open(ORIG, "rb").read()
img = open(IMG, "rb").read()

def v2f(v):
    return v if v < RX_END else v - 0x70000

phoff = struct.unpack("<I", orig[28:32])[0]
dyn_off = None
for i in range(struct.unpack("<H", orig[44:46])[0]):
    p = orig[phoff+32*i: phoff+32*(i+1)]
    if struct.unpack("<8I", p)[0] == 2:
        dyn_off = struct.unpack("<8I", p)[1]
d = {}
p = dyn_off
while True:
    tag, val = struct.unpack("<II", orig[p:p+8]); d[tag] = val; p += 8
    if tag == 0: break
symtab, strtab, strsz = d[6], d[5], d[10]
rel_off, rel_sz = d[17], d[18]
jmprel, pltrelsz = d[23], d[2]
def symname(j):
    no = struct.unpack("<I", orig[symtab+16*j:symtab+16*j+4])[0]
    e = orig.find(b"\x00", strtab+no)
    return orig[strtab+no:e].decode("latin1")

relrel = {}   # slot vaddr -> addend (target vaddr)
for k in range(rel_sz // 8):
    off, info = struct.unpack("<II", orig[rel_off+8*k:rel_off+8*k+8])
    if info & 0xff == 8:
        f = v2f(off)
        if f + 4 <= len(orig):
            relrel[off] = struct.unpack("<I", orig[f:f+4])[0]
imp_got = {}
for k in range(pltrelsz // 8):
    off, info = struct.unpack("<II", orig[jmprel+8*k:jmprel+8*k+8])
    imp_got[off] = symname(info >> 8)
print(f"RELATIVE {len(relrel)}, GLOB_DAT? imp slots {len(imp_got)}")

fns = []
for line in open(FUNCS):
    if line.startswith("FUNC "):
        parts = line.split()
        fns.append((int(parts[1], 16), parts[2], int(parts[3].split("=")[1])))
fns.sort()
starts = [f[0] for f in fns]
def find_fn(a):
    i = bisect.bisect_right(starts, a) - 1
    if i >= 0:
        s, nm, sz = fns[i]
        if a < s + sz + 64:
            return nm, s
    return None, None

def scan_code(val, label, only_code=True):
    """all LE refs to val inside RX code region; report objdump-ish context"""
    needle = struct.pack("<I", val)
    out = []
    i = img.find(needle)
    while i != -1:
        if (not only_code) or i < RX_END:
            pre = img[max(0, i-2):i]
            kind = ""
            if pre[-1:] == b"\x15" and pre[-2:-1] in (b"\xff", b"\x00", b"\x8b", b"\x89"):
                kind = "call/jmp [imm32]?"
            if pre[-1:] == b"\x25" and pre[-2:-1] == b"\xff":
                kind = "jmp [imm32]"
            fnm, fs = find_fn(i)
            out.append((i, fnm, fs, kind))
        i = img.find(needle, i + 1)
    return out

INTER_IMPORTS = ["__system_property_get", "fopen", "fgets", "fread", "access",
    "open", "read", "ptrace", "kill", "fork", "waitpid", "pthread_create",
    "dlopen", "dlsym", "AAssetManager_open", "AAsset_read", "AAsset_getLength64",
    "getpid", "getppid", "syscall", "readlink", "opendir", "readdir", "regcomp",
    "prctl", "getenv", "dl_iterate_phdr", "stat", "lstat", "bsd_signal", "exit",
    "_exit", "mmap2", "mprotect", "munmap", "abort", "syscall", "memcpy",
    "__system_property_get", "siglongjmp", "sigsetjmp", "pipe", "execv", "wait",
    "chdir", "chmod", "getauxval", "mprotect", "sem_wait", "sem_post"]

report = {}
print("\n== IMPORT GOT references in code ==")
for slot, nm in sorted(imp_got.items()):
    if nm not in INTER_IMPORTS:
        continue
    refs = scan_code(slot, nm)
    uniq = sorted({(f, s) for _, f, s, _ in refs if f})
    report[f"imp:{nm}"] = refs
    print(f"  {nm} (GOT 0x{slot:x}): {len(refs)} refs; fns: "
          + ", ".join(f"{f}@0x{s:x}" for f, s in uniq[:10]))

print("\n== STRING refs (direct imm + RELATIVE pointer-table slots) ==")
PROBES = [b"s/h/e/l/l/N", b"s/h/e/l/l/A", b"s/h/e/l/l/S", b"s/h/e/l/l/C",
          b"s/h/e/l/l/HM", b"TracerPid", b"/proc/self/status", b"ro.kernel.qemu",
          b"/dev/qemu_pipe", b"ijiami.dat", b"sign_verify.png", b"libexecmain.so",
          b"goldfish", b"qemu.hw.mainkeys", b"persist.nox.device", b"/proc/self/maps",
          b"frida-agent", b"app_process32_xposed", b"ro.dalvik.vm.native.bridge",
          b"/dev/__properties__", b"getOpCode", b"core", b"ijiami"]
add_by_val = {}
for slot, add in relrel.items():
    add_by_val.setdefault(add, []).append(slot)
for probe in PROBES:
    va = img.find(probe)
    if va < 0:
        print(f"  {probe.decode()!r}: not in image")
        continue
    print(f"  {probe.decode()!r} @0x{va:x}:")
    direct = scan_code(va, "str")
    for i, f, s, k in direct[:8]:
        print(f"    direct ref @0x{i:x} in {f}@0x{s:x} {k}")
    if not direct:
        print("    direct refs: none")
    for slot in add_by_val.get(va, []):
        print(f"    ptr-table slot 0x{slot:x} (RELATIVE -> 0x{va:x})")
        r = scan_code(slot, "slot")
        for i, f, s, k in r[:8]:
            print(f"      code ref to slot @0x{i:x} in {f}@0x{s:x} {k}")
        if not r:
            print("      code refs to slot: none")
    report[f"str:{probe.decode()}"] = [(i, f, s, k) for i, f, s, k in direct]

json.dump({k: v for k, v in report.items() if v},
          open("/tmp/ghidra-8a/xref3.json", "w"), indent=1)
print("\nsaved /tmp/ghidra-8a/xref3.json")
