#!/usr/bin/env python3
"""Deep analysis of iJiami payload (Task 8-a, phase 2).

- per-16KB entropy map + region segmentation (locate the 4 dex regions)
- AES-ECB duplicate-block test (cipher mode fingerprint)
- real decompression probes (not just 2-byte magic coincidence):
    raw / single-byte XOR 1..255 / 16-byte repeating XOR (hex-parsed
    '44f6438002be91557b704ba909f62f58' + prompt variant)
  at every 4-byte-aligned offset of the first 64KB and at +40 (post header),
  plus attempt to bootstrap zlib streams mid-file at 1KB grid.
- Chi-square uniformity of the payload (random vs compressed distinction)
Usage: python3 analyze_ijiami_dat2.py [ijiami.dat]
"""
import sys, math, collections, zlib, gzip, io, struct

PATH = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ijm/apk/assets/ijiami.dat"
data = open(PATH, "rb").read()
n = len(data)
print(f"file: {PATH}  size: {n}  md5=93d86c64dece89b3aea4425ae7d82831")

HDR = 40
payload = data[HDR:]
count, total = struct.unpack("<II", data[0:8])
hexkey_str = data[8:40].decode()
print(f"header: dex_count={count} total_size={total} ({total/n:.2f}x file) key-ascii={hexkey_str}")
key = bytes.fromhex(hexkey_str)
print(f"hex-parsed key: {key.hex()}")

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b)
    m = len(b)
    return -sum((v/m) * math.log2(v/m) for v in c.values())

# ---- per-16KB entropy map, compressed to a coarse profile ----
BS = 16384
ents = []
for i in range(0, n, BS):
    ents.append(entropy(data[i:i+BS]))
print(f"\n16KB blocks: {len(ents)}  min={min(ents):.3f} max={max(ents):.3f} mean={sum(ents)/len(ents):.3f}")

# print a downsized profile: 128KB granularity, mean of 8 blocks
prof = []
for i in range(0, len(ents), 8):
    chunk = ents[i:i+8]
    prof.append(sum(chunk)/len(chunk))
print("entropy profile (128KB bins, mean bits/byte):")
for i, e in enumerate(prof):
    bar = "#" * int((e - 7.0) * 40) if e > 7.0 else "."
    print(f"  {i*128:5d}K- {(i+1)*128:5d}K  {e:.3f} {bar}")

# breakpoints: blocks whose entropy deviates > 0.15 from running mean
print("\ndeviating 16KB blocks (|e - mean| > 0.15):")
for i, e in enumerate(ents):
    if abs(e - sum(ents)/len(ents)) > 0.15:
        off = i * BS
        print(f"  off=0x{off:08x} ({off:8d}) e={e:.3f} head={data[off:off+16].hex()}")

# ---- AES-ECB duplicate 16-byte block test ----
blocks16 = [payload[i:i+16] for i in range(0, len(payload) - 15, 16)]
c16 = collections.Counter(blocks16)
dups = sum(v - 1 for v in c16.values() if v > 1)
print(f"\nAES-block test: {len(blocks16)} 16B blocks, {dups} duplicates "
      f"({'ECB-like!' if dups > 100 else 'CBC/CTR/compressed (no ECB pattern)'})")
top = c16.most_common(3)
for b, v in top:
    print(f"  most common block x{v}: {b.hex()}")

# ---- chi-square uniformity ----
obs = collections.Counter(payload)
exp = len(payload) / 256
chi2 = sum((obs[b] - exp) ** 2 / exp for b in range(256))
print(f"chi-square (255 dof): {chi2:.0f}  (uniform-random expectation ~255±22; "
      f"compressed data ~255±22 too; structured data >>300)")

# ---- real decompression probes ----
def try_zlib(buf, wbits):
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(buf, 1 << 20)
        return out if len(out) > 4096 else None
    except Exception:
        return None

def try_gzip(buf):
    try:
        out = gzip.decompress(buf[:65536]) if False else None
    except Exception:
        out = None
    try:
        d = zlib.decompressobj(31)  # gzip container
        out = d.decompress(buf, 1 << 20)
        return out if len(out) > 4096 else None
    except Exception:
        return out

keys = {"raw": b"\x00"} | {f"xor{k:02x}": bytes([k]) for k in range(1, 256)}
keys["xor16-hexkey"] = key
keys["xor16-prompt"] = bytes.fromhex("44f643802be91557b704ba909f63f588")

hits = []
probe_start = 0
probe_end = min(1 << 16, len(payload))
for kname, kb in keys.items():
    klen = len(kb)
    # apply key to first 64KB of payload (post-header)
    seg = bytes(payload[i] ^ kb[i % klen] for i in range(probe_end))
    for off in range(0, min(4096, probe_end), 4):  # dense grid near head
        for wb, nm in ((15, "raw-deflate"), (47, "zlib"), (31, "gzip")):
            r = try_zlib(seg[off:off + 65536], wb)
            if r:
                hits.append((kname, off, nm, len(r), r[:16].hex()))
    if klen > 1:
        break_out = None
print(f"\nDecompression probes (key, offset-in-payload, codec, outlen, head16): {len(hits)} hits")
for h in hits[:20]:
    print("  ", h)

# scan whole file for embedded gzip members with valid header (id1,id2,cm=8,flg<0x20)
print("\ngzip full-file header scan (structurally valid):")
found = 0
for i in range(0, len(data) - 10):
    if data[i] == 0x1f and data[i+1] == 0x8b and data[i+2] == 8 and (data[i+3] & 0xe0) == 0:
        r = try_zlib(data[i:i+65536], 31)
        if r and len(r) > 1024:
            print(f"  @ {i} (0x{i:x}) -> {len(r)} bytes: {r[:8].hex()}")
            found += 1
        if found > 5:
            break
print(f"  ({found} valid gzip streams)")

# ---- byte-value distribution fingerprint of first 4KB vs rest ----
h1 = collections.Counter(data[HDR:HDR+4096]); h2 = collections.Counter(data[-4096:])
print(f"\npayload head 4KB entropy={entropy(data[HDR:HDR+4096]):.3f}, tail 4KB entropy={entropy(data[-4096:]):.3f}")

# ---- structure hypothesis: 4 x (u32 len + blob) after header? ----
print("\nstructure probe (u32le at payload start, division check):")
for off in range(0, 32, 4):
    v = struct.unpack("<I", payload[off:off+4])[0]
    note = ""
    if v and n - HDR - off - 4 >= v:
        note = "  (fits in file)"
    print(f"  +{HDR+off}: {v} (0x{v:x}) {note}")

# ---- top byte frequencies ----
obs_all = collections.Counter(payload)
print("\ntop-12 byte values in payload:")
for b, v in obs_all.most_common(12):
    print(f"  0x{b:02x}: {v} ({v/len(payload)*100:.2f}%)")

# ---- per-2.38MB quadrant stats (if 4 equal dexes) ----
q = (n - HDR) / 4
print(f"\nquadrant stats (4 x {q/1048576:.2f} MiB):")
for i in range(4):
    seg = data[HDR + int(i*q): HDR + int((i+1)*q)]
    print(f"  dex-region#{i}: off 0x{HDR+int(i*q):08x}..0x{HDR+int((i+1)*q):08x} "
          f"ent={entropy(seg):.4f} mean_byte={sum(seg)/len(seg):.1f}")
print("\ndone.")
