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


def find_all(data: bytes, needle: bytes) -> list:
    out = []
    i = 0
    while True:
        i = data.find(needle, i)
        if i < 0:
            return out
        out.append((i, i + len(needle)))
        i += 1


def in_forbidden(off: int, rng: list) -> bool:
    return any(lo <= off < hi for lo, hi in rng)


# ---------------------------------------------------------------------------
# DT_HASH re-link: the deep rename changes a dynsym name's SysV hash
# bucket, and the injector resolves the agent entry through DT_HASH
# (run 34174568790: "undefined symbol: afcda_agent_main").  SysV chains
# hold symbol INDICES (names are matched by strcmp), so moving the symbol
# to the head of its new bucket's chain is a complete fix.
# ---------------------------------------------------------------------------
def elf_hash(name: bytes) -> int:
    h = 0
    for c in name:
        h = ((h << 4) + c) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= (~g) & 0xFFFFFFFF
    return h


def fix_agent_hash_chains(data: bytearray, base: int, cls: int) -> int:
    import struct
    if cls == 2:
        phoff = struct.unpack_from("<Q", data, base + 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, base + 0x36)
        dynent, sym_ent_fmt = 16, 24
    else:
        phoff = struct.unpack_from("<I", data, base + 0x1C)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, base + 0x2A)
        dynent, sym_ent_fmt = 8, 16
    loads = []
    dyn_vaddr = None
    for i in range(phnum):
        off = base + phoff + i * phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if cls == 2:
            p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 8)[:2]
            p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        else:
            p_offset = struct.unpack_from("<I", data, off + 4)[0]
            p_vaddr = struct.unpack_from("<I", data, off + 8)[0]
            p_filesz = struct.unpack_from("<I", data, off + 16)[0]
        if p_type == 1:
            loads.append((p_vaddr, p_vaddr + p_filesz,
                          base + p_offset, base + p_offset + p_filesz))
        elif p_type == 2:
            dyn_vaddr = p_vaddr

    def v2o(v: int):
        for vlo, vhi, flo, fhi in loads:
            if vlo <= v < vhi:
                return flo + (v - vlo)
        return None

    if dyn_vaddr is None:
        return 0
    doff = v2o(dyn_vaddr)
    if doff is None:
        return 0
    ents = {}
    i = doff
    while True:
        if cls == 2:
            tag, val = struct.unpack_from("<QQ", data, i)
        else:
            tag, val = struct.unpack_from("<II", data, i)
        if tag == 0:
            break
        ents.setdefault(tag, val)
        i += dynent
    if 4 not in ents or 6 not in ents or 5 not in ents:
        return 0          # no SysV hash table (GNU-hash only) - nothing to fix
    hash_off = v2o(ents[4])
    sym_off = v2o(ents[6])
    str_off = v2o(ents[5])
    syment = ents.get(11, sym_ent_fmt)
    strsz = ents.get(10, 0)
    if None in (hash_off, sym_off, str_off):
        return 0
    nbucket, nchain = struct.unpack_from("<II", data, hash_off)
    buckets_off = hash_off + 8
    chains_off = buckets_off + 4 * nbucket
    fixed = 0
    for si in range(nchain):
        st_name = struct.unpack_from("<I", data, sym_off + si * syment)[0]
        if st_name >= strsz:
            continue
        nul = data.find(b"\x00", str_off + st_name, str_off + strsz)
        if nul < 0:
            continue
        name = bytes(data[str_off + st_name:nul])
        if b"afcda" not in name:
            continue
        old = name.replace(b"afcda", b"frida")
        ob = elf_hash(old) % nbucket
        nb = elf_hash(name) % nbucket
        if ob == nb:
            continue       # same bucket - strcmp still finds it
        # unlink si from the old bucket chain
        head = struct.unpack_from("<I", data, buckets_off + 4 * ob)[0]
        if head == si:
            nxt = struct.unpack_from("<I", data, chains_off + 4 * si)[0]
            struct.pack_into("<I", data, buckets_off + 4 * ob, nxt)
        else:
            cur = head
            while cur:
                nxt = struct.unpack_from("<I", data, chains_off + 4 * cur)[0]
                if nxt == si:
                    si_next = struct.unpack_from(
                        "<I", data, chains_off + 4 * si)[0]
                    struct.pack_into("<I", data, chains_off + 4 * cur,
                                     si_next)
                    break
                cur = nxt
        # push si onto the new bucket chain
        old_head = struct.unpack_from("<I", data, buckets_off + 4 * nb)[0]
        struct.pack_into("<I", data, chains_off + 4 * si, old_head)
        struct.pack_into("<I", data, buckets_off + 4 * nb, si)
        fixed += 1
        print(f"[stealth]   DT_HASH re-link @blob {hex(base)}: "
              f"symbol #{si} {old!r} bucket {ob} -> {nb} ({name!r})")
    return fixed


def fix_all_agent_hashes(data: bytearray) -> int:
    total = 0
    for a in find_embedded_agents(bytes(data)):
        cls = elf_class(bytes(data[a:]))
        total += fix_agent_hash_chains(data, a, cls)
    return total


def main() -> int:
    argv = sys.argv[1:]
    verify_only = "--verify-only" in argv
    deep = "--deep" in argv
    keep_symbol = "--keep-agent-symbol" in argv
    args = [a for a in argv if a not in ("--verify-only", "--deep",
                                        "--keep-agent-symbol")]
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
        if keep_symbol:
            # keep the agent entry symbol (and its hash-table entries)
            # intact - used for LOCAL reproduction where stealth is
            # irrelevant and GNU-hash agents cannot be re-linked yet
            forbidden.extend(find_all(bytes(data), b"frida_agent_main"))
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

    # pass 4: re-link the agents' SysV DT_HASH chains so the renamed
    # dynsym entries are still resolvable by the injector
    if deep:
        nfix = fix_all_agent_hashes(data)
        if nfix:
            print(f"[stealth]   DT_HASH re-links: {nfix}")
            changed += nfix

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
