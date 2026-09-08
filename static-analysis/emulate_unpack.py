#!/usr/bin/env python3
"""Unicorn-based static unpacker for iJiami SecShell natives (x86 32-bit).

The packer's DT_INIT is a hand-rolled multi-stage unpacker:
  1. DT_INIT -> setup helper (pops retaddr, reads inline u32 table to calibrate
     the load base, locates the blob descriptor struct)
  2. mmap(RWX, ANON) via raw int 0x80 (syscall 90 old_mmap)  -> copies blob
  3. mmap(MAP_FIXED, RW) at a hole vaddr -> copies decompressed code
  4. NRV2B-style LZ decompressor (literals XOR 0x0C - "SeLLVM compiler 1.7.4.20")
  5. E8/E9/0F8x rel32 call-patch loop
  6. Jumps into the unpacked region (more stages may follow)

This script emulates the exact x86 code with Unicorn, hooking int 0x80 to
service mmap/mprotect/write/exit, and dumps every mapped region at the end.

Usage: emulate_unpack.py <lib.so> <dt_init_hex> <outdir>
"""
import sys, os, struct
from unicorn import *
from unicorn.x86_const import *

LIB = sys.argv[1]
DT_INIT = int(sys.argv[2], 0)
OUTDIR = sys.argv[3]
os.makedirs(OUTDIR, exist_ok=True)

data = open(LIB, 'rb').read()
# program headers (ELF32)
phoff = struct.unpack('<I', data[28:32])[0]
phentsize, phnum = struct.unpack('<HH', data[42:46])
loads = []
for i in range(phnum):
    p = data[phoff + phentsize*i: phoff + phentsize*(i+1)]
    p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack('<8I', p)
    if p_type == 1:
        loads.append((p_offset, p_vaddr, p_filesz, p_memsz, p_flags))
print("PT_LOAD:", [(hex(o), hex(v), hex(fs), hex(ms), fl) for o, v, fs, ms, fl in loads])

uc = Uc(UC_ARCH_X86, UC_MODE_32)
BASE = 0          # emulate at load base 0 (vaddrs == emulated addresses)
PAGE = 0x1000

def align_down(x): return x & ~(PAGE-1)
def align_up(x): return (x + PAGE-1) & ~(PAGE-1)

# map PT_LOADs
for off, vaddr, filesz, memsz, flags in loads:
    start, end = align_down(BASE+vaddr), align_up(BASE+vaddr+memsz)
    try:
        uc.mem_map(start, end-start, UC_PROT_ALL)
    except UcError:
        pass
    uc.mem_write(BASE+vaddr, data[off:off+filesz])
    print(f"mapped LOAD off=0x{off:x} vaddr=0x{vaddr:x} filesz=0x{filesz:x} memsz=0x{memsz:x}")

STACK = 0x7f000000
uc.mem_map(STACK - 0x200000, 0x200000, UC_PROT_ALL)   # 2MB stack
HEAP_HINT = 0x40000000                                # anonymous mmap arena
uc.mem_map(HEAP_HINT, 0x10000000, UC_PROT_ALL)        # 256MB arena, no real alloc
heap_cur = HEAP_HINT

SENTINEL = 0x9e9e9e9e
esp = STACK - 0x10000
uc.mem_write(esp, struct.pack('<I', SENTINEL))         # fake return addr
uc.reg_write(UC_X86_REG_ESP, esp)
uc.reg_write(UC_X86_REG_EBP, STACK - 0x20000)

mapped_regions = []   # (start, size, tag)
insn_count = [0]
log = []

MMAP_SYSCALLS = {90, 192}

def do_map(addr, length, prot, flags, tag):
    global heap_cur
    if flags & 0x10 and addr:          # MAP_FIXED
        start, end = align_down(addr), align_up(addr + length)
        # map page-by-page, skipping pages that are already mapped
        p = start
        while p < end:
            try:
                uc.mem_map(p, PAGE, UC_PROT_ALL)
            except UcError:
                pass    # already mapped: keep (packer re-maps over its regions)
            p += PAGE
        mapped_regions.append((start, end-start, f"fixed:{tag}"))
        return start
    # anonymous: carve from arena
    start = align_up(heap_cur)
    end = align_up(start + max(length, PAGE))
    heap_cur = end
    mapped_regions.append((start, end-start, f"anon:{tag}"))
    return start

def intr_hook(uc, intno, user_data):
    if intno != 0x80:
        return
    eax = uc.reg_read(UC_X86_REG_EAX)
    ebx = uc.reg_read(UC_X86_REG_EBX)
    ecx = uc.reg_read(UC_X86_REG_ECX)
    edx = uc.reg_read(UC_X86_REG_EDX)
    esi = uc.reg_read(UC_X86_REG_ESI)
    edi = uc.reg_read(UC_X86_REG_EDI)
    ebp = uc.reg_read(UC_X86_REG_EBP)
    if eax == 90:                      # old_mmap: struct at ebx
        s = struct.unpack('<6I', uc.mem_read(ebx, 24))
        addr, length, prot, flags, fd, off = s
        ret = do_map(addr, length, prot, flags, "old_mmap")
        log.append(f"int80 old_mmap struct@0x{ebx:x}: addr=0x{addr:x} len=0x{length:x} prot={prot} flags=0x{flags:x} -> 0x{ret:x}")
        uc.reg_write(UC_X86_REG_EAX, ret)
    elif eax == 192:                   # mmap2
        ret = do_map(ebx, ecx, edx, esi, "mmap2")
        log.append(f"int80 mmap2: addr=0x{ebx:x} len=0x{ecx:x} prot={edx} flags=0x{esi:x} -> 0x{ret:x}")
        uc.reg_write(UC_X86_REG_EAX, ret)
    elif eax == 125:                   # mprotect
        log.append(f"int80 mprotect: addr=0x{ebx:x} len=0x{ecx:x} prot={edx}")
        uc.reg_write(UC_X86_REG_EAX, 0)
    elif eax in (1, 252):              # exit
        log.append(f"int80 exit({ebx}) at eip=0x{uc.reg_read(UC_X86_REG_EIP):x}")
        uc.emu_stop()
    elif eax == 4:                     # write
        try:
            buf = bytes(uc.mem_read(ecx, min(edx, 256)))
        except UcError:
            buf = b'<unreadable>'
        log.append(f"int80 write fd={ebx}: {buf!r}")
        uc.reg_write(UC_X86_REG_EAX, edx)
    elif eax == 122:                   # uname
        uc.reg_write(UC_X86_REG_EAX, 0)
    else:
        log.append(f"int80 syscall {eax} (ebx=0x{ebx:x} ecx=0x{ecx:x}) -> 0")
        uc.reg_write(UC_X86_REG_EAX, 0)

def code_hook(uc, addr, size, user_data):
    insn_count[0] += 1
    if insn_count[0] > 80_000_000:
        log.append("instruction cap reached")
        uc.emu_stop()
    if addr == SENTINEL:
        log.append("returned to sentinel: unpacker finished")
        uc.emu_stop()

def mem_invalid_hook(uc, access, address, size, value, user_data):
    eip = uc.reg_read(UC_X86_REG_EIP)
    log.append(f"INVALID MEM access={access} addr=0x{address:x} size={size} eip=0x{eip:x}")
    return False

uc.hook_add(UC_HOOK_INTR, intr_hook)
uc.hook_add(UC_HOOK_CODE, code_hook)
uc.hook_add(UC_HOOK_MEM_INVALID, mem_invalid_hook)

uc.reg_write(UC_X86_REG_EIP, DT_INIT)
try:
    uc.emu_start(DT_INIT, SENTINEL, timeout=0, count=200_000_000)
except UcError as e:
    log.append(f"UcError: {e} at eip=0x{uc.reg_read(UC_X86_REG_EIP):x}")

print("\n==== EMULATION LOG ====")
for line in log:
    print(" ", line)
print(f"instructions: {insn_count[0]}")

# dump all interesting memory: the PT_LOADs (post-modification) + mapped regions
print("\n==== DUMP ====")
for start, size, tag in mapped_regions:
    out = os.path.join(OUTDIR, f"{start:08x}_{size:x}_{tag.replace(':', '_')}.bin")
    try:
        blob = bytes(uc.mem_read(start, size))
        open(out, 'wb').write(blob)
        print(f"  {out} ({size} bytes) [{tag}]")
    except UcError as e:
        print(f"  {start:#x} ({tag}): read failed {e}")
# also dump modified LOAD segments (unpacked in place?)
for i, (off, vaddr, filesz, memsz, flags) in enumerate(loads):
    out = os.path.join(OUTDIR, f"load{i}_{vaddr:08x}_after.bin")
    blob = bytes(uc.mem_read(BASE+vaddr, memsz))
    orig = data[off:off+filesz] + b'\x00'*(memsz-filesz)
    if blob != orig:
        open(out, 'wb').write(blob)
        print(f"  {out} (LOAD {i} MODIFIED, {memsz} bytes)")
print("done.")
