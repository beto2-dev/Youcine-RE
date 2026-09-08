#!/usr/bin/env python3
"""Dump the REAL import list of iJiami SecShell natives (x86 32-bit).

SecShell hides imports: .dynsym section headers claim 3 symbols, but the
linker uses DT_HASH nchain + DT_JMPREL, which reference the real (hidden)
symbol table. This script reconstructs the true import/export surface from
the dynamic segment only. Usage: dump_real_imports.py <lib.so>
"""
import sys, struct

PATH = sys.argv[1]
d = open(PATH, "rb").read()
print(f"file: {PATH}  size: {len(d)}")

phoff = struct.unpack("<I", d[28:32])[0]
phentsize, phnum = struct.unpack("<HH", d[42:46])
dyn_off = dyn_sz = None
for i in range(phnum):
    p = d[phoff + 32*i: phoff + 32*(i+1)]
    t, off, va, pa, fsz, msz, fl, al = struct.unpack("<8I", p)
    if t == 2:
        dyn_off, dyn_sz = off, fsz

# parse DT_ tags
dyn = {}
p = dyn_off
while p < dyn_off + dyn_sz:
    tag, val = struct.unpack("<II", d[p:p+8])
    dyn[tag] = val
    p += 8
    if tag == 0:
        break

symtab = dyn[6]; strtab = dyn[5]; strsz = dyn[10]
jmprel = dyn[23]; pltrelsz = dyn[2]
hash_off = dyn[4]
nb, nchain = struct.unpack("<II", d[hash_off:hash_off+8])
print(f"DT_HASH: nbucket={nb} nchain={nchain} -> real dynsym count = {nchain}")
print(f"symtab=0x{symtab:x} strtab=0x{strtab:x} strsz=0x{strsz:x} "
      f"jmprel=0x{jmprel:x} pltrelsz={pltrelsz} ({pltrelsz//8} slots)")

def symname(j):
    if j >= nchain:
        return f"<idx-oob:{j}>"
    no = struct.unpack("<I", d[symtab+16*j:symtab+16*j+4])[0]
    if no >= strsz:
        return f"<str-oob:{j}>"
    end = d[strtab+no:].find(b"\x00")
    return d[strtab+no:strtab+no+end].decode("latin1")

print("\n-- all dynsym entries --")
exports, imports = [], []
for j in range(nchain):
    st_name, st_value, st_size, st_info, st_other, st_shndx = \
        struct.unpack("<IIIBBH", d[symtab+16*j:symtab+16*j+16])
    nm = symname(j)
    kind = "IMP" if st_shndx == 0 else ("EXP" if st_value else "LOC")
    entry = (j, nm, st_value, st_size, st_info)
    (imports if st_shndx == 0 else exports if st_value else []).append(entry)
for j, nm, v, s, i in imports:
    print(f"  [{j:3d}] IMP {nm}")
for j, nm, v, s, i in exports:
    print(f"  [{j:3d}] EXP {nm} value=0x{v:x} size={s}")

print("\n-- JMP_SLOT (PLT/GOT) relocations --")
seen = set()
for k in range(pltrelsz // 8):
    off, info = struct.unpack("<II", d[jmprel+8*k:jmprel+8*k+8])
    nm = symname(info >> 8)
    seen.add(nm)
    print(f"  GOT 0x{off:06x} <- {nm}")

print(f"\nunique imported names via JMPREL: {len(seen)}")
inter = {"__system_property_get", "fopen", "open", "openat", "read", "pread",
         "ptrace", "fork", "kill", "pthread_create", "dlopen", "dlsym",
         "AAssetManager_open", "AAsset_read", "mmap", "mprotect", "syscall",
         "getppid", "access", "stat", "readlink", "opendir", "__android_log_print",
         "memcpy", "sigaction", "prctl", "getenv", "sysconf"}
print("import surface of interest:", sorted(seen & inter))
