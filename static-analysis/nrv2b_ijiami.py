#!/usr/bin/env python3
"""Python port of the iJiami/SeLLVM NRV2B-style LZ decompressor found in
libexecmain.so (x86) DT_INIT @ vaddr 0x52e8 (Ghidra entry_152e8).

Ground truth (raw asm, objdump):
  - MSB-first bit reader over 32-bit LE words with sentinel trick
    (refill: ebx = 2*word + 1 so refill triggers exactly after 32 bits)
  - bit==1 -> literal byte XOR 0x0C (self-unpack variant)
  - bit==0 -> match: m = 1; do { m = 2m + bit } while (bit == 0)
      m == 2            -> rep-match (reuse last offset)
      m >= 3            -> offset_word = ((m-3) << 8) | next_byte
                           offset = ~offset_word;  offset==0 -> END
      len: 2 bits; if 0 -> len = 1; do { len = 2*len + bit } while(bit==0); len += 2
      len += 1 + (offset_u32 < 0xfffff300)
      copy from dst - (offset_word + 1)
Usage: nrv2b_ijiami.py <srcfile> [start_off] [literal_xor] [max_out]
"""
import sys, struct

M32 = 0xFFFFFFFF

def decompress(src, pos=0, literal_xor=0x0C, max_out=64 * 1024 * 1024):
    s = bytearray(src)
    n = len(s)
    out = bytearray()
    ebx = 0
    ebp = 1  # last offset (u32)
    esi = pos

    def getbit():
        nonlocal ebx, esi
        cf = (ebx >> 31) & 1
        ebx = (ebx << 1) & M32
        if ebx == 0:  # ZF -> refill
            if esi + 4 > n:
                raise EOFError(f"refill OOB esi=0x{esi:x}")
            w = struct.unpack_from("<I", s, esi)[0]
            esi += 4
            cf = (w >> 31) & 1
            ebx = (2 * w + 1) & M32
        return cf

    try:
        while len(out) < max_out:
            if getbit():  # literal
                if esi >= n:
                    raise EOFError("literal OOB")
                out.append(s[esi] ^ literal_xor)
                esi += 1
                continue
            # match
            eax = 1
            while True:
                eax = ((eax << 1) | getbit()) & M32
                if getbit() == 1:
                    break
            ecx = 0
            if eax >= 3:
                eax = ((eax - 3) << 8) & M32
                if esi >= n:
                    raise EOFError("offset byte OOB")
                eax |= s[esi]
                esi += 1
                eax ^= M32  # ~offset_word
                if eax == 0:
                    return bytes(out), esi, "END"
                ebp = eax
            # length
            ecx = (ecx << 1) | getbit()
            ecx = (ecx << 1) | getbit()
            if ecx == 0:
                ecx = 1
                while True:
                    ecx = ((ecx << 1) | getbit()) & M32
                    if getbit() == 1:
                        break
                ecx += 2
            ecx = ecx + 1 + (1 if ebp < 0xFFFFF300 else 0)
            # copy: source = dst_pos + signed(ebp)
            dist = (M32 - ebp) + 1  # offset_word + 1
            srcpos = len(out) - dist
            if srcpos < 0:
                raise ValueError(f"bad distance 0x{dist:x} at out=0x{len(out):x}")
            for _ in range(ecx):
                out.append(out[srcpos])
                srcpos += 1
    except (EOFError, ValueError) as e:
        return bytes(out), esi, f"ERR:{e}"
    return bytes(out), esi, "MAX"


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ijm/apk/assets/ijiami.dat"
    start = int(sys.argv[2], 0) if len(sys.argv) > 2 else 40
    xor = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x0C
    data = open(path, "rb").read()
    out, consumed, status = decompress(data, start, xor)
    print(f"status={status} in_consumed=0x{consumed:x} out_len=0x{len(out):x} ({len(out)})")
    print("head 32:", out[:32].hex())
    print("tail 16:", out[-16:].hex() if out else "")
    magic_ok = out[:4] == b"dex\n"
    print("DEX magic:", magic_ok)
    if magic_ok:
        open("/tmp/ijm/dat_decoded_dex.bin", "wb").write(out)
        print("saved /tmp/ijm/dat_decoded_dex.bin")
