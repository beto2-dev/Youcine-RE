#!/usr/bin/env python3
"""Static layout + entropy analysis of iJiami encrypted payload (assets/ijiami.dat).

Youcine-RE / Task 8-a. Usage: python3 analyze_ijiami_dat.py [path/to/ijiami.dat]
Outputs: header field decode, per-4KB-block entropy (min/max/mean), block entropy
profile (ASCII sparkline), trailing-region stats, and magic scans under simple
XOR keys for zlib/gzip/zip/dex signatures.
"""
import sys, math, collections

PATH = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ijm/ijiami.dat"
data = open(PATH, "rb").read()
print(f"file: {PATH}  size: {len(data)}")

def u32(off): return int.from_bytes(data[off:off+4], "little")
def u32be(off): return int.from_bytes(data[off:off+4], "big")

print("\n== HEADER (first 64 bytes) ==")
print("hex[0:64]:", data[:64].hex())
for off in range(0, 64, 4):
    print(f"  +{off:02d}: u32le={u32(off):<12} u32be={u32be(off):<12} hex={data[off:off+4].hex()}")
# candidate ASCII region
for start in range(0, 48):
    chunk = data[start:start+32]
    if all(0x20 <= b < 0x7f for b in chunk):
        print(f"  ASCII32 @+{start}: {chunk.decode()!r}")
        nxt = data[start+32:start+64]
        if all(0x20 <= b < 0x7f for b in nxt):
            print(f"  ASCII64 @+{start}: {(chunk+nxt).decode()!r}")

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

print("\n== PER-4KB-BLOCK ENTROPY ==")
BS = 4096
ents = [entropy(data[i:i+BS]) for i in range(0, len(data), BS)]
print(f"blocks={len(ents)} min={min(ents):.3f} max={max(ents):.3f} mean={sum(ents)/len(ents):.3f}")
full = entropy(data)
print(f"whole-file entropy: {full:.3f} bits/byte")

# sparkline profile (each char = one 4KB block, quantized 0-9)
profile = "".join(str(min(9, int(e * 10 // 10 * 9))) for e in
                  [min(e, 7.999) for e in ents])
# simpler: quantize into 8 levels 0-7 + '.' high
def q(e):
    if e < 6.0: return "0"
    if e < 6.5: return "1"
    if e < 7.0: return "2"
    if e < 7.5: return "3"
    if e < 7.9: return "4"
    return "."
profile = "".join(q(e) for e in ents)
print("\nentropy profile (4KB blocks; 0<6.0 ... 4<7.5 .>=7.9):")
for i in range(0, len(profile), 120):
    print(f"  blk {i*BS//1024:5d}K |{profile[i:i+120]}|")

# low-entropy regions (structure!)
print("\nlow-entropy blocks (<6.0 bits/byte):")
low = [(i, e) for i, e in enumerate(ents) if e < 6.0]
for i, e in low[:60]:
    off = i * BS
    print(f"  blk#{i:5d} off=0x{off:08x} ({off:9d}) ent={e:.3f} head={data[off:off+24].hex()}")
print(f"  total low blocks: {len(low)}")

# byte histogram of header area
print("\n== ASCII ratio scan (windows of 256B where printable >= 90%) ==")
run = 0; start = None
for off in range(0, min(len(data), 1 << 20), 256):
    w = data[off:off+256]
    pr = sum(1 for b in w if 0x20 <= b < 0x7f) / len(w)
    if pr >= 0.9:
        if start is None: start = off
        run += 1
    else:
        if run: print(f"  printable run @0x{start:08x}-{start+run*256:08x} ({run*256}B): {data[start:start+64]!r}")
        run = 0; start = None

print("\n== MAGIC SCAN (raw) ==")
magics = {b"\x1f\x8b": "gzip", b"\x78\x9c": "zlib", b"\x78\xda": "zlib", b"\x78\x01": "zlib",
          b"PK\x03\x04": "zip", b"dex\n": "dex", b"\xfd7zXZ": "xz", b"BZh": "bzip2",
          b"\x28\xb5\x2f\xfd": "zstd", b"\x04\x22\x4d\x18": "lz4"}
for m, name in magics.items():
    pos = []
    i = data.find(m)
    while i != -1 and len(pos) < 10:
        pos.append(i); i = data.find(m, i+1)
    if pos: print(f"  {name}: {pos}")

print("\n== MAGIC SCAN under single-byte XOR (key 1..255) ==")
hits = 0
for k in range(1, 256):
    x = bytes(b ^ k for b in data[: 1 << 20])  # first MiB is enough for a probe
    for m, name in magics.items():
        if m in x:
            i = x.find(m)
            print(f"  XOR 0x{k:02x}: {name} @ {i}")
            hits += 1
print(f"  ({hits} hits)")
print("\ndone.")
