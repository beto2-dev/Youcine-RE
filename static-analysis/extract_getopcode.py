#!/usr/bin/env python3
"""Extract the SecLLVM opcode-substitution table (getOpCode) from the
UNPACKED iJiami libexecmain.so stage (x86).

libexecmain.so exports getOpCode(u8) -> u8, implemented as a hand-rolled
binary search tree over opcode values. libexec.so's SecLLVM unpacker calls
it to descramble opcode bytes of the packed code stream.
This script emulates the function for all 256 inputs with Unicorn and
writes the full table (raw + changes-only) to JSON/CSV.

Usage: extract_getopcode.py [fixed_mmap_bin]
"""
import sys, json, collections
from unicorn import *
from unicorn.x86_const import *

BIN = sys.argv[1] if len(sys.argv) > 1 else "/tmp/unpack-main/00001000_19000_fixed_old_mmap.bin"
STAGE_BASE = 0x1000            # the fixed mmap region vaddr
GETOPCODE = 0x1a60
FN_END = 0x1a60 + 2953

m = open(BIN, "rb").read()

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(STAGE_BASE, ((len(m) + 0xfff) // 0x1000) * 0x1000, UC_PROT_ALL)
uc.mem_write(STAGE_BASE, m)
STACK = 0x7f000000
uc.mem_map(STACK - 0x100000, 0x100000, UC_PROT_ALL)
SENTINEL = 0x9e9e9e9e

table = {}
for op in range(256):
    esp = STACK - 0x8000
    uc.mem_write(esp, b"\x9e\x9e\x9e\x9e")         # return sentinel
    uc.mem_write(esp + 4, bytes([op, 0, 0, 0]))    # arg1 (u8 in byte, cdecl)
    uc.reg_write(UC_X86_REG_ESP, esp)
    for r in (UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
              UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP):
        uc.reg_write(r, 0)
    try:
        uc.emu_start(GETOPCODE, SENTINEL, count=200000)
        table[op] = uc.reg_read(UC_X86_REG_EAX) & 0xff
    except UcError as e:
        table[op] = None

ok = sum(1 for v in table.values() if v is not None)
print(f"getOpCode emulated: {ok}/256 inputs ok")
identity = [o for o, v in table.items() if v == o]
changed = {o: v for o, v in table.items() if v is not None and v != o}
print(f"identity mappings: {len(identity)}; changed: {len(changed)}")
print("sample (op -> new):", dict(list(changed.items())[:16]))
# injectivity check
vals = [v for v in table.values() if v is not None]
print(f"unique outputs: {len(set(vals))} / {len(vals)} "
      f"({'INJECTIVE' if len(set(vals)) == len(vals) else 'NOT injective'})")
json.dump({str(k): v for k, v in table.items()},
          open("/home/z/youcine-re/Youcine-RE/static-analysis/ghidra-exports/getopcode_table.json", "w"),
          indent=0, sort_keys=True)
csv = "\n".join(f"{o},{v}" for o, v in sorted(table.items()))
open("/home/z/youcine-re/Youcine-RE/static-analysis/ghidra-exports/getopcode_table.csv", "w").write(csv)
print("saved ghidra-exports/getopcode_table.json + .csv")
