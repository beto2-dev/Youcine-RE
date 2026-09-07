#!/usr/bin/env python3
"""analyze_dat.py — recompute the evidence header digest for any iJiami
.dat blob and characterise its payload for the static AES attack.

Reproduces the evidence/ijiami-dat-header.txt report (size, sha256,
head_64 hex/ascii, u32le fields, md5-like ascii field) and adds the
statistics that inform the decryption strategy:

  * 16-byte duplicate-block count / percentage — duplicated ciphertext
    blocks are the classic ECB indicator (identical plaintext blocks ->
    identical ciphertext blocks; iJiami's dat shows them);
  * entropy per 64 KiB block (min/avg/max + the first low-entropy
    offsets — a compressed+encrypted payload should be uniformly high);
  * printable-byte ratio;
  * trailing-bytes / padding-like analysis (payload is NOT a multiple of
    16 for the 1.17.6 sample — the tail looks like a trailer, not
    ciphertext).

stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from collections import Counter
from pathlib import Path

HEX_CHARS = set("0123456789abcdefABCDEF")
LOW_ENTROPY = 6.5          # bits/byte threshold for "low" block report
ENTROPY_BLOCK = 64 * 1024
BLOCK = 16                 # AES block size for duplicate statistics


def log(msg: str) -> None:
    print(f"[analyze] {msg}")


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def ascii_repr(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def analyze(dat: bytes) -> dict:
    size = len(dat)
    sha256 = hashlib.sha256(dat).hexdigest()
    head = dat[:64]
    head_hex = head.hex()
    head_ascii = ascii_repr(head)

    count = struct.unpack_from("<I", dat, 0)[0] if size >= 4 else None
    total = struct.unpack_from("<I", dat, 4)[0] if size >= 8 else None
    ascii32 = ""
    ascii32_is_hex = False
    if size >= 40:
        try:
            ascii32 = dat[8:40].decode("ascii")
            ascii32_is_hex = all(c in HEX_CHARS for c in ascii32)
        except UnicodeDecodeError:
            ascii32 = ""

    payload = dat[40:]
    plen = len(payload)

    # ---- 16-byte duplicate blocks (ECB indicator)
    blocks = [payload[i:i + BLOCK] for i in range(0, plen - BLOCK + 1, BLOCK)]
    seen = Counter(blocks)
    distinct = len(seen)
    repeated = len(blocks) - distinct        # occurrences beyond the first
    dup_pct = (repeated / len(blocks) * 100) if blocks else 0.0
    top_dups = [
        {"block_hex": b.hex(), "occurrences": c}
        for b, c in sorted(seen.items(), key=lambda kv: -kv[1])[:3] if c > 1
    ]

    # ---- entropy per 64 KiB
    ent = []
    for i in range(0, plen, ENTROPY_BLOCK):
        ent.append(shannon(payload[i:i + ENTROPY_BLOCK]))
    ent_stats = {
        "blocks": len(ent),
        "min": round(min(ent), 4) if ent else None,
        "avg": round(sum(ent) / len(ent), 4) if ent else None,
        "max": round(max(ent), 4) if ent else None,
    }
    low = [(i * ENTROPY_BLOCK, round(e, 4))
           for i, e in enumerate(ent) if e < LOW_ENTROPY]
    ent_stats["low_entropy_first10"] = low[:10]
    ent_stats["low_entropy_count"] = len(low)

    printable = (sum(1 for b in payload if 32 <= b < 127) / plen * 100) \
        if plen else 0.0

    # ---- trailing bytes / padding-likeness
    tail = payload[-32:].hex() if plen >= 32 else payload.hex()
    rem = plen % BLOCK
    last_partial = payload[plen - rem:] if rem else b""
    pad_like = None
    if rem:
        pad_like = {
            "all_zero": all(b == 0 for b in last_partial),
            "all_ff": all(b == 0xFF for b in last_partial),
            "pkcs7": (last_partial[-1] == rem
                      and all(b == rem for b in last_partial)),
        }

    return {
        "size_bytes": size,
        "sha256": sha256,
        "head_64_hex": head_hex,
        "head_64_ascii": ascii_repr(head),
        "u32le_0": count,
        "u32le_4": total,
        "md5_ascii": ascii32,
        "md5_ascii_is_hex": ascii32_is_hex,
        "payload_len": plen,
        "payload_len_mod_16": rem,
        "duplicate_blocks": {
            "total_blocks": len(blocks),
            "distinct_blocks": distinct,
            "repeated_occurrences": repeated,
            "repeat_pct": round(dup_pct, 4),
            "top3": top_dups,
        },
        "entropy_64k": ent_stats,
        "printable_pct": round(printable, 3),
        "tail_32_hex": tail,
        "tail_padding_like": pad_like,
    }


def render(r: dict) -> str:
    """Text report in the evidence/ijiami-dat-header.txt style."""
    lines = []
    a = lines.append
    a(f"size_bytes={r['size_bytes']}")
    a(f"sha256={r['sha256']}")
    a(f"head_64_hex={r['head_64_hex']}")
    a(f"head_64_ascii={r['head_64_ascii']}")
    a(f"u32le_0={r['u32le_0']}  # encrypted dex count")
    a(f"u32le_4={r['u32le_4']}  # likely uncompressed payload size")
    a(f"md5_ascii={r['md5_ascii']}"
      + ("" if r["md5_ascii_is_hex"] else "  # NOT ascii-hex!"))
    a(f"payload_len={r['payload_len']} (payload_len%16="
      f"{r['payload_len_mod_16']})")
    db = r["duplicate_blocks"]
    a(f"dup_blocks={db['repeated_occurrences']}/{db['total_blocks']} "
      f"({db['repeat_pct']}%)  # ECB duplicate-block indicator")
    for t in db["top3"]:
        a(f"  top dup block {t['block_hex']} x{t['occurrences']}")
    e = r["entropy_64k"]
    a(f"entropy_64k: blocks={e['blocks']} min={e['min']} avg={e['avg']} "
      f"max={e['max']} low(<{LOW_ENTROPY})={e['low_entropy_count']}")
    for off, val in e["low_entropy_first10"][:5]:
        a(f"  low entropy @ 0x{off:x} (payload) = {val}")
    a(f"printable_pct={r['printable_pct']}")
    a(f"tail_32_hex={r['tail_32_hex']}")
    tp = r["tail_padding_like"]
    if tp:
        a(f"tail_padding_like={tp}  # last {r['payload_len_mod_16']} "
          f"bytes: trailer/padding, not a full AES block")
    return "\n".join(lines)


def build_parser():
    p = argparse.ArgumentParser(
        description="Header digest + ECB/entropy statistics for an "
                    "iJiami .dat payload.")
    p.add_argument("--dat", default=os.environ.get(
        "IJIAMI_DAT", "assets/ijiami.dat"),
        help="path to the .dat (default: $IJIAMI_DAT or "
             "assets/ijiami.dat)")
    p.add_argument("--json", metavar="PATH",
                   help="also write the full statistics as JSON")
    p.add_argument("--skip-blocks", action="store_true",
                   help="skip the 16-byte duplicate-block statistics "
                        "(slow-ish on huge files)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.dat)
    if not path.exists():
        print(f"[analyze] ERROR: {args.dat} not found — extract it from "
              "the packed apk (unzip -p ycMob_1.17.6_ycsite.apk "
              "assets/ijiami.dat) or set IJIAMI_DAT", file=sys.stderr)
        return 2
    dat = path.read_bytes()
    r = analyze(dat)
    if args.skip_blocks:
        r["duplicate_blocks"] = {"skipped": True}
    print(render(r))
    if args.json:
        Path(args.json).write_text(json.dumps(r, indent=2))
        print(f"[analyze] wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
