#!/usr/bin/env python3
"""XREF v2: PLT-aware call-site mapping + string GOT slots for the unpacked
iJiami libexec.so (x86).

Steps:
  1. Correctly parse .rel.dyn (DT_REL=17/DT_RELSZ=18) of the ORIGINAL file
     -> R_386_RELATIVE GOT slots (base-pointer indirections for data).
  2. Parse .rel.plt -> import GOT slots.
  3. Disassemble the unpacked image with objdump; every `call/jmp <plt>`
     is resolved to its import name; every call site is mapped to the
     containing Ghidra function.
  4. Scan for GOT slots that point at interesting decrypted strings.
Usage: xref_scan2.py  (writes /tmp/ghidra-8a/xref2_calls.txt + prints summary)
"""
import struct, bisect, subprocess, re, json, sys

ORIG = "/home/z/youcine-re/ijm/assets/ijm_lib/x86/libexec.so"
IMG = "/tmp/unpack-exec/unpacked_image.bin"
FUNCS = "/tmp/ghidra-8a/reports/unpacked-funcs.txt"

orig = open(ORIG, "rb").read()
img = open(IMG, "rb").read()

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
rel_off, rel_sz = dyn[17], dyn[18]
jmprel, pltrelsz = dyn[23], dyn[2]
def symname(j):
    no = struct.unpack("<I", orig[symtab+16*j:symtab+16*j+4])[0]
    e = orig.find(b'\x00', strtab+no)
    return orig[strtab+no:e].decode('latin1')

got_rel = {}
for k in range(rel_sz // 8):
    off, info = struct.unpack("<II", orig[rel_off+8*k:rel_off+8*k+8])
    t = info & 0xff
    if t == 8 and off + 4 <= len(orig):        # R_386_RELATIVE
        got_rel[off] = struct.unpack("<I", orig[off:off+4])[0]
got_imp = {}
for k in range(pltrelsz // 8):
    off, info = struct.unpack("<II", orig[jmprel+8*k:jmprel+8*k+8])
    got_imp[off] = symname(info >> 8)
print(f"R_386_RELATIVE: {len(got_rel)} (RELCOUNT says {dyn[0x6ffffffa]}), import slots: {len(got_imp)}")

# PLT: scan image 0xd800-0xe200 for "ff 25 <got>" patterns -> plt_stub -> got
plt = {}
for a in range(0xd800, 0xe200):
    if img[a:a+2] == b"\xff\x25":
        got = struct.unpack("<I", img[a+2:a+6])[0]
        if got in got_imp:
            plt[a] = got_imp[got]
print(f"PLT stubs found: {len(plt)} (region scan)")
inv_plt = plt

# Ghidra functions
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
        if addr < s + sz + 48:
            return (nm, s)
    return (None, None)

# objdump full image
dis = subprocess.run(["objdump", "-D", "-b", "binary", "-m", "i386",
                      "--adjust-vma=0", IMG],
                     capture_output=True, text=True).stdout
call_re = re.compile(r"^\s*([0-9a-f]+):\s+(?:f 2?4 )?(?:\S+\s+)*?\s*"
                     r"(e8|e9)\s+([0-9a-f ]+)\s*\t(?:call|jmp)\s+([0-9a-f]+)")
calls = {}          # import name -> [(site, fn)]
n_call = 0
for line in dis.splitlines():
    m = re.match(r"^\s*([0-9a-f]+):\s((?:[0-9a-f]{2} )+)\s*\t(call|jmp)\s+([0-9a-f]+)", line)
    if not m:
        continue
    site = int(m.group(1), 16)
    tgt = int(m.group(4), 16)
    if tgt in plt:
        n_call += 1
        nm = plt[tgt]
        fnm, fs = find_fn(site)
        calls.setdefault(nm, []).append((site, fnm, fs))
print(f"import call/jmp sites resolved: {n_call} across {len(calls)} imports")
INTER = ["__system_property_get", "fopen", "fgets", "fread", "access", "open", "read",
         "ptrace", "kill", "fork", "waitpid", "pthread_create", "dlopen", "dlsym",
         "AAssetManager_open", "AAsset_read", "AAsset_getLength64", "getpid", "getppid",
         "syscall", "readlink", "opendir", "readdir", "regcomp", "prctl", "getenv",
         "dl_iterate_phdr", "stat", "lstat", "bsd_signal", "sigaction", "exit", "_exit",
         "mmap2", "mprotect", "munmap", "execv", "abort", "sleep", "usleep", "time"]
with open("/tmp/ghidra-8a/xref2_calls.txt", "w") as w:
    for nm in INTER:
        lst = calls.get(nm, [])
        uniq_fns = sorted({(f, s) for _, f, s in lst if f}) 
        w.write(f"== {nm}: {len(lst)} call sites, {len(uniq_fns)} functions\n")
        for site, f, s in lst:
            w.write(f"   site 0x{site:x} in {f}@0x{s:x}\n")
        print(f"{nm}: {len(lst)} sites / {len(uniq_fns)} fns -> {[f'{f}@{s:x}' for f, s in uniq_fns[:8]]}")

# GOT slots pointing at interesting strings (relative relocs)
STRS = {"s/h/e/l/l/N": 0x0f24bd, "s/h/e/l/l/A": 0x0f2499, "s/h/e/l/l/S": 0x0f24a5,
        "s/h/e/l/l/C": 0x0f24c9, "s/h/e/l/l/HM": 0x0f23de, "TracerPid": 0x0ef1e5,
        "/proc/self/status": 0x0ef1d0, "ro.kernel.qemu": 0x0ef374,
        "/dev/qemu_pipe": 0x0ef232, "ijiami.dat": 0x0f251e, "ijiami.dat2": 0x0f21be,
        "sign_verify.png": 0x0f2226, "libexecmain.so": 0x0f24e7, "goldfish": 0x0ef271,
        "qemu.hw.mainkeys": 0x0ef2b0, "persist.nox.device": 0x0ef3e0}
rev = {v: k for k, v in got_rel.items()}
print("\nGOT slots holding interesting string addrs:")
for nm, va in STRS.items():
    slot = rev.get(va)
    if slot is not None:
        print(f"  {nm}: GOT 0x{slot:x}")
        # scan image for refs to that GOT slot
        needle = struct.pack("<I", slot)
        i = img.find(needle)
        while i != -1:
            fnm, fs = find_fn(i)
            print(f"     ref @0x{i:x} in {fnm}@0x{fs:x}" if fnm else f"     ref @0x{i:x} (no fn)")
            i = img.find(needle, i + 1)
    else:
        print(f"  {nm}: no GOT slot (direct-ref scan next)")
        needle = struct.pack("<I", va)
        i = img.find(needle)
        cnt = 0
        while i != -1 and cnt < 6:
            fnm, fs = find_fn(i)
            print(f"     direct ref @0x{i:x} in {fnm}@0x{fs:x}" if fnm else f"     direct ref @0x{i:x} (no fn)")
            i = img.find(needle, i + 1); cnt += 1

json.dump({k: [(s, f, st) for s, f, st in v] for k, v in calls.items()},
          open("/tmp/ghidra-8a/xref2_calls.json", "w"))
print("\nsaved /tmp/ghidra-8a/xref2_calls.txt + .json")
