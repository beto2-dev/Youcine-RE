#!/usr/bin/env python3
"""stealth_frida_server.py - same-length binary patch of frida components.

WHY (run 34173350484 detection matrix): the app dies on the agent's mere
PRESENCE (L1: attach + empty script = death; L0 spawn-gate-only = alive;
control = alive).  iJiami's SecLLVM VMP scans the process's own memory
with RAW SVC reads for the byte pattern 'frida' - the agent blob carries
815 lowercase + 1013 capitalized occurrences (memfd name, dynsym
'frida_agent_main', DBus paths '/re/frida/...', 'frida:rpc' quickjs
string constants, 'Frida.Peer' interface names, ...).

MODES
  default : the surgical patch set from run 34173015540 (memfd template,
            helper names, thread names).
  --deep  : additionally rename EVERY 'frida' -> 'afcda' and
            'Frida' -> 'Afcda' occurrence that is NOT inside an
            EXECUTABLE segment - of the outer ELF AND of every embedded
            agent ELF (the agents are embedded uncompressed: ELF64 and
            ELF32 blobs are located by scanning for \\x7fELF + sane
            program headers).  Same-length swaps keep every offset,
            resource index, quickjs string length prefix and dynsym
            entry intact; replacing the string CONTENT consistently on
            BOTH sides of every wire protocol (client <-> server <->
            agent) keeps the protocol working.

Apply --deep to BOTH:
  1. the frida-server binary (includes the embedded agents)
  2. the pip-installed python client (_frida.abi3.so - it shares
     /re/frida paths, re.frida names and 'frida:rpc' constants)

Usage: stealth_frida_server.py <elf> [--deep] [--verify-only]
"""
import sys
from pathlib import Path

# (needle, replacement, note) - replacement length MUST equal needle length
PATCHES = [
    (b"frida-agent-<arch>.so", b"media-agent-<arch>.so", "memfd name template"),
    (b"frida-agent-32.so", b"media-agent-32.so", "32-bit agent memfd"),
    (b"frida-agent-64.so", b"media-agent-64.so", "64-bit agent memfd"),
    (b"frida-helper-64", b"media-helper-64", "helper process name"),
    (b"frida-helper-32", b"media-helper-32", "helper process name"),
    (b"gum-js-loop\x00", b"run-js-loop\x00", "agent JS thread name"),
    (b"gmain\x00", b"smain\x00", "glib main-loop thread name"),
    (b"gdbus\x00", b"sdbus\x00", "glib dbus thread name"),
]

DEEP = [
    (b"frida", b"afcda"),
    (b"Frida", b"Afcda"),
]

# Applied context-blind (no forbidden-range check): the RPC magic is a
# 9-byte ASCII sequence that cannot appear as machine code, and it MUST
# be identical on the client shim, the server and the agent shim - the
# client embeds the shim as plaintext JS inside a code-flagged segment,
# which the range check would otherwise skip (found in the client:
# 'send(["frida:rpc",t,e,s])').
FORCE = [
    (b"frida:rpc", b"afcda:rpc"),
]

PT_LOAD = 1
PF_X = 0x1


def elf_class(data: bytes) -> int:
    if data[:4] != b"\x7fELF":
        return 0
    return data[4]           # 1 = ELF32, 2 = ELF64


def exec_ranges(data: bytes, base: int) -> list:
    """Executable PT_LOAD file-offset ranges of the ELF whose header is at
    data[0] and whose file start is at absolute offset `base`.  `data` may
    be the full file (base=0) or a slice starting at the agent blob."""
    cls = elf_class(data)
    rng = []
    import struct
    if cls == 2:
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phentsize = struct.unpack_from("<H", data, 0x36)[0]
        phnum = struct.unpack_from("<H", data, 0x38)[0]
        for i in range(phnum):
            off = phoff + i * phentsize        # slice-relative
            if off + 56 > len(data):
                break
            p_type, p_flags = struct.unpack_from("<II", data, off)
            p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from("<QQQQQQ", data, off + 8)
            if p_type == PT_LOAD and (p_flags & PF_X):
                rng.append((base + p_offset, base + p_offset + p_filesz))
    elif cls == 1:
        phoff = struct.unpack_from("<I", data, 0x1C)[0]
        phentsize = struct.unpack_from("<H", data, 0x2A)[0]
        phnum = struct.unpack_from("<H", data, 0x2C)[0]
        for i in range(phnum):
            off = phoff + i * phentsize        # slice-relative
            if off + 32 > len(data):
                break
            p_type = struct.unpack_from("<I", data, off)[0]
            p_offset = struct.unpack_from("<I", data, off + 4)[0]
            p_filesz = struct.unpack_from("<I", data, off + 16)[0]
            # ELF32 phdr flags at off+24
            p_flags = struct.unpack_from("<I", data, off + 24)[0]
            if p_type == PT_LOAD and (p_flags & PF_X):
                rng.append((base + p_offset, base + p_offset + p_filesz))
    return rng


def section_table(data: bytes) -> list:
    """[(name, sh_offset, sh_size)] via section headers."""
    import struct
    out = []
    if elf_class(data) != 2 or len(data) < 0x40:
        return out
    try:
        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
        if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
            return out
        sh = e_shoff + e_shstrndx * e_shentsize
        strtab_off = struct.unpack_from("<Q", data, sh + 0x18)[0]
        strtab_size = struct.unpack_from("<Q", data, sh + 0x20)[0]
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + 0x40 > len(data):
                break
            sh_name = struct.unpack_from("<I", data, off)[0]
            name = data[strtab_off + sh_name:
                        strtab_off + strtab_size].split(b"\x00")[0]
            sh_offset = struct.unpack_from("<Q", data, off + 0x18)[0]
            sh_size = struct.unpack_from("<Q", data, off + 0x20)[0]
            if sh_size:
                out.append((name, sh_offset, sh_size))
    except Exception:
        pass
    return out


# sections whose bytes must NEVER be renamed: symbol names are resolved
# by external loaders (PyInit__frida! dlsym of the injector!) and hashed
# (.gnu.hash/.hash) - renaming without rehashing breaks lookups.  The
# embedded agent blobs' own dynsyms are inside the blobs (not outer
# sections) and ARE patched, consistently with their injectors.
SYMBOL_SECTIONS = (b".dynsym", b".dynstr", b".symtab", b".strtab",
                   b".gnu.version", b".gnu.version_r", b".gnu.version_d",
                   b".hash", b".gnu.hash", b".rela.dyn", b".rela.plt",
                   b".rel.dyn", b".rel.plt")


def text_section_range(data: bytes) -> list:
    """[sh_offset, sh_offset+sh_size) of the .text/.plt sections.  The
    outer server's r-x PT_LOAD contains .rodata too (the agents live
    inside it!), so the coarse exec LOAD range would protect far too
    much - only the real .text must be off-limits."""
    return [(off, off + size)
            for name, off, size in section_table(data)
            if name in (b".text", b".plt")]


def find_embedded_agents(data: bytes) -> list:
    """File offsets of embedded agent ELF blobs (magic + sane phdrs).
    Offset 0 (the outer ELF itself) is excluded."""
    out = []
    i = 4                      # skip the outer ELF at 0
    while True:
        i = data.find(b"\x7fELF", i)
        if i < 0:
            break
        cls = elf_class(data[i:])
        ok = False
        try:
            import struct
            if cls == 2:
                phoff = struct.unpack_from("<Q", data, i + 0x20)[0]
                phentsize, phnum = struct.unpack_from("<HH", data, i + 0x36)
                ok = 0 < phnum <= 16 and phentsize == 56 and phoff < 0x10000
            elif cls == 1:
                phoff = struct.unpack_from("<I", data, i + 0x1C)[0]
                phentsize, phnum = struct.unpack_from("<HH", data, i + 0x2A)
                ok = 0 < phnum <= 16 and phentsize == 32 and phoff < 0x10000
        except Exception:
            ok = False
        if ok:
            out.append(i)
        i += 4
    return out


def agent_span(data: bytes, a: int) -> tuple:
    """[start, end) of the whole embedded agent blob: max PT_LOAD end."""
    import struct
    cls = elf_class(data[a:])
    end = a + 0x1000
    if cls == 2:
        phoff = struct.unpack_from("<Q", data, a + 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, a + 0x36)
        for i in range(phnum):
            off = a + phoff + i * phentsize
            p_type = struct.unpack_from("<I", data, off)[0]
            p_offset = struct.unpack_from("<Q", data, off + 8)[0]
            p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
            if p_type == PT_LOAD:
                end = max(end, a + p_offset + p_filesz)
    elif cls == 1:
        phoff = struct.unpack_from("<I", data, a + 0x1C)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, a + 0x2A)
        for i in range(phnum):
            off = a + phoff + i * phentsize
            p_type = struct.unpack_from("<I", data, off)[0]
            p_offset = struct.unpack_from("<I", data, off + 4)[0]
            p_filesz = struct.unpack_from("<I", data, off + 16)[0]
            if p_type == PT_LOAD:
                end = max(end, a + p_offset + p_filesz)
    return (a, end)


def forbidden_ranges(data: bytes) -> list:
    """Ranges that must never be patched.  frida embeds the agent blobs
    INSIDE the outer .text (the section is 53 MB!), so the protected
    outer-code range is .text/.plt MINUS the agent blobs; symbol-related
    sections are protected (PyInit__frida / dlsym / hash tables); the
    agents' own executable PT_LOAD segments are protected separately."""
    rng = []
    for name, off, size in section_table(data):
        if name in SYMBOL_SECTIONS:
            rng.append((off, off + size))
    agents = find_embedded_agents(data)
    spans = [agent_span(data, a) for a in agents]
    for tlo, thi in text_section_range(data):
        cur = [(tlo, thi)]
        for alo, ahi in spans:
            new = []
            for lo, hi in cur:
                if ahi <= lo or alo >= hi:
                    new.append((lo, hi))
                    continue
                if lo < alo:
                    new.append((lo, alo))
                if ahi < hi:
                    new.append((ahi, hi))
            cur = new
        rng.extend(cur)
    for a in agents:
        rng.extend(exec_ranges(data[a:], a))
    print(f"[stealth] embedded agent ELF(s) at "
          f"{[hex(a) for a in agents]} (spans "
          f"{[(hex(lo), hex(hi)) for lo, hi in spans]})")
    return sorted(rng)


def in_forbidden(off: int, rng: list) -> bool:
    return any(lo <= off < hi for lo, hi in rng)


def main() -> int:
    argv = sys.argv[1:]
    verify_only = "--verify-only" in argv
    deep = "--deep" in argv
    args = [a for a in argv if a not in ("--verify-only", "--deep")]
    if len(args) != 1:
        print(__doc__)
        return 1
    path = Path(args[0])
    if not path.is_file():
        print(f"[stealth] no such file: {path}")
        return 1

    data = bytearray(path.read_bytes())
    if elf_class(bytes(data)) == 0:
        print(f"[stealth] {path} is not an ELF - refusing")
        return 1

    print(f"[stealth] {path} ({len(data)} bytes, "
          f"ELF{'32' if elf_class(bytes(data)) == 1 else '64'})")

    changed = 0
    # pass 1: the surgical set
    for needle, repl, note in PATCHES:
        if len(needle) != len(repl):
            raise AssertionError(f"length mismatch: {needle!r} vs {repl!r}")
        i = 0
        while True:
            i = data.find(needle, i)
            if i < 0:
                break
            data[i:i + len(needle)] = repl
            print(f"[stealth]   {hex(i)}: {needle!r} -> {repl!r}  ({note})")
            changed += 1
            i += 1

    # pass 2 (deep): every frida/Frida outside executable code
    if deep:
        forbidden = forbidden_ranges(bytes(data))
        print(f"[stealth] deep mode: {len(forbidden)} executable range(s) "
              f"protected: {[hex(lo) + '-' + hex(hi) for lo, hi in forbidden]}")
        for needle, repl in DEEP:
            i = 0
            skipped = 0
            n = 0
            while True:
                i = bytes(data).find(needle, i)
                if i < 0:
                    break
                if in_forbidden(i, forbidden):
                    skipped += 1
                else:
                    data[i:i + len(needle)] = repl
                    n += 1
                i += 1
            changed += n
            print(f"[stealth]   deep {needle!r} -> {repl!r}: {n} patched, "
                  f"{skipped} skipped (exec)")

    # pass 3 (force): protocol-critical magics, context-blind
    for needle, repl in FORCE:
        i = 0
        n = 0
        while True:
            i = bytes(data).find(needle, i)
            if i < 0:
                break
            data[i:i + len(needle)] = repl
            n += 1
            i += 1
        if n:
            print(f"[stealth]   force {needle!r} -> {repl!r}: {n} patched")
            changed += n

    if verify_only:
        print(f"[stealth] verify-only (changed would be {changed})")
        return 0

    if changed:
        path.write_bytes(bytes(data))
        print(f"[stealth] wrote {changed} patch(es) -> {path}")
    else:
        print("[stealth] nothing to patch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
