#!/usr/bin/env python3
"""Try AES / XOR key candidates against assets/ijiami.dat (static decrypt probe).

Header (40 bytes): u32 dex_count, u32 total_uncompressed_size, 32-char ASCII
hex key. Payload: high-entropy, 16-byte block structure (ECB duplicates seen).
"""
import sys
from Crypto.Cipher import AES

dat = open("/tmp/ijm/assets/ijiami.dat", "rb").read()
hdr = dat[:40]
payload = dat[40:]
hexkey = hdr[8:40].decode()
key16 = bytes.fromhex(hexkey)
print(f"file={len(dat)} header_dex_count={int.from_bytes(hdr[0:4],'little')} "
      f"total_size={int.from_bytes(hdr[4:8],'little')} key_ascii={hexkey}")
print(f"key16={key16.hex()} payload={len(payload)}")

DEX_MAGICS = (b"dex\n", b"PK\x03\x04", b"\x1f\x8b", b"78\x9c", b"78\xda", b"78\x01")


def score_plain(p: bytes, tag: str):
    head = p[:16]
    verdict = ""
    for m in DEX_MAGICS:
        if head.startswith(m):
            verdict = f"  <<< MATCHES {m!r}"
    printable = sum(32 <= b < 127 for b in p[:256]) / 256
    print(f"[{tag}] head={head.hex()} printable={printable:.2f}{verdict}")
    return verdict


hits = []

# 1) AES-128-ECB, key = hex-parsed header key
c = AES.new(key16, AES.MODE_ECB)
p = c.decrypt(payload[:512])
score_plain(p, "AES-128-ECB key16")

# 2) AES-128-CBC zero IV
c = AES.new(key16, AES.MODE_CBC, iv=b"\x00" * 16)
p = c.decrypt(payload[:512])
score_plain(p, "AES-128-CBC key16 iv0")

# 3) AES-128-CBC IV = first payload block
c = AES.new(key16, AES.MODE_CBC, iv=payload[:16])
p = c.decrypt(payload[16:528])
score_plain(p, "AES-128-CBC key16 iv=payload[:16]")

# 4) AES-256 with the 32-byte ASCII string as key
c = AES.new(hdr[8:40], AES.MODE_ECB)
p = c.decrypt(payload[:512])
score_plain(p, "AES-256-ECB asciikey")

# 5) AES-128 key = 16 bytes starting AFTER the hex key (maybe key is binary there)
# header might be: 8 + 32 hex + binary key material -> test first 16 bytes of payload as key
c = AES.new(payload[:16], AES.MODE_ECB)
p = c.decrypt(payload[16:528])
score_plain(p, "AES-128-ECB key=payload[:16]")

# 6) XOR with key16 repeated
p = bytes(payload[i] ^ key16[i % 16] for i in range(256))
score_plain(p, "XOR key16")

# 7) XOR with ascii key repeated
ak = hdr[8:40]
p = bytes(payload[i] ^ ak[i % 32] for i in range(256))
score_plain(p, "XOR ascii32")

# 8) full ECB decrypt of the first 64KB for the best candidates, magic scan
for name, mk in [("ecb16", key16), ("ecb32", hdr[8:40])]:
    c = AES.new(mk, AES.MODE_ECB)
    chunk = c.decrypt(payload[:65536])
    found = [m for m in DEX_MAGICS if chunk.find(m) != -1]
    print(f"[full {name}] magic hits in first 64KB: {found}")
    if found:
        hits.append(name)

print("HITS:", hits)
