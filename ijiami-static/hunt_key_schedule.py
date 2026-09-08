#!/usr/bin/env python3
"""hunt_key_schedule.py — find AES key schedules (and recover the original
round-0 keys) inside memory dump files.

Inputs: the raw region .bin files produced by the redroid memdump runs
(unpack/external_memdump.py sweeps, dumped/<...>/*.bin), any single blob via
--file, or a whole directory via --dump-dir.

Two independent detectors are run over every candidate offset:

1. FORWARD verification — the original key sits at the offset, followed by
   its own expanded schedule (AES key material + round keys are frequently
   stored contiguously by OpenSSL/BoringSSL/mbedTLS key-setup functions).
   Classified FULL (all comparison words match) or PARTIAL (>= --min-words
   match; dump boundaries can truncate the tail).

2. CONSISTENCY-only — the internal schedule recurrence
       w[i] = w[i-Nk] ^ f(w[i-1])        f = SubWord(RotWord(w)) ^ Rcon
   holds for rounds 1..9 *without* the round-0 words being present at the
   start of the region (e.g. only round keys 3..10 survived in the dump).
   The Rcon values are checked agnostically (must be a member of the Rcon
   table and strictly consecutive, since the round counter is monotonic).
   When >= 20 consecutive words satisfy the recurrence, the INVERSE key
   schedule walks the words back to round 0 for every possible round
   alignment and forward-verifies each candidate -> original key.

A fast first-check (the recurrence at the first g-position, Rcon-agnostic)
rejects virtually every offset; it is vectorised with numpy when numpy is
importable and falls back to pure python otherwise.

Performance: ~1 GB in pure python is slow (hours); with numpy the
first-check runs at hundreds of MB/s. Use --stride 1 (--slow) only on
small regions — key schedules are word-aligned in practice.

Self test (--selftest): FIPS-197 known-answer expansion/encryption vectors,
synthetic schedule round-trips for AES-128/256 (forward, truncated,
consistency-only, unaligned), and a false-positive check on random data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:  # optional fast path
    HAS_NUMPY = False

# ---------------------------------------------------------------- constants

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

# Rcon[i] = 2^i in GF(2^8); index 0 is used for round 1 (FIPS j = i/Nk).
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
        0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]
RCON_SET = frozenset(RCON)

KEYLENS = (16, 24, 32)
CONSISTENCY_MIN_WORDS = 20   # ">= 20 consecutive words" rule (spec)
CHUNK_WORDS = 1 << 22        # 16 Mi words per numpy chunk
M32 = 0xFFFFFFFF


def _fail(msg: str) -> None:
    print(f"[hunt] ERROR: {msg}", file=sys.stderr)


# ------------------------------------------------------------- AES schedule

def key_expansion(key: bytes) -> bytes:
    """Standard AES key expansion (FIPS-197). Returns the full schedule
    (round-0 words first). Works on byte sequences in memory order."""
    nk = len(key) // 4
    if len(key) % 4 or nk not in (4, 6, 8):
        raise ValueError(f"bad key length {len(key)}")
    total = 4 * (nk + 7)
    w = [bytearray(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, total):
        temp = bytearray(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                       # RotWord
            temp = bytearray(SBOX[b] for b in temp)          # SubWord
            temp[0] ^= RCON[i // nk - 1]                     # Rcon (leading byte)
        elif nk > 6 and i % nk == 4:                         # AES-256 extra
            temp = bytearray(SBOX[b] for b in temp)          # SubWord only
        w.append(bytearray(a ^ b for (a, b) in zip(w[i - nk], temp)))
    return b"".join(bytes(x) for x in w)


def schedule_words(schedule: bytes) -> list:
    return [int.from_bytes(schedule[4 * i:4 * i + 4], "little")
            for i in range(len(schedule) // 4)]


def _subword(x: int) -> int:
    return (SBOX[x & 0xFF]
            | (SBOX[(x >> 8) & 0xFF] << 8)
            | (SBOX[(x >> 16) & 0xFF] << 16)
            | (SBOX[(x >> 24) & 0xFF] << 24))


def _rotword(x: int) -> int:
    # FIPS RotWord on a little-endian uint32 == rotate right by 8 bits.
    return ((x >> 8) | (x << 24)) & M32


def _g(x: int, rcon: int) -> int:
    return _subword(_rotword(x)) ^ rcon


def _f(w_prev: int, j: int, nk: int) -> int:
    """temp() of the forward expansion for word index j (absolute)."""
    if j % nk == 0:
        return _g(w_prev, RCON[j // nk - 1])
    if nk > 6 and j % nk == 4:
        return _subword(w_prev)
    return w_prev


# --------------------------------------------------- forward verify (per hit)

def forward_verify(buf: bytes, off: int, key_len: int, min_words: int):
    """Take key_len bytes at off, expand, compare against the following
    bytes. Returns (match_words, avail_words, key) or None."""
    if off + key_len > len(buf):
        return None
    key = bytes(buf[off:off + key_len])
    try:
        sched = key_expansion(key)
    except ValueError:
        return None
    nk = key_len // 4
    comp = sched[key_len:]                      # words nk .. 4(nk+7)-1
    avail = min((len(buf) - off - key_len) // 4, len(comp) // 4)
    match = 0
    for k in range(avail):
        if buf[off + key_len + 4 * k: off + key_len + 4 * k + 4] == \
                comp[4 * k:4 * k + 4]:
            match += 1
        else:
            break
    return match, avail, key


# ------------------------------------------------ consistency check (per hit)

def consistency_run(buf: bytes, base: int, key_len: int):
    """Count consecutive words (from j=Nk) satisfying the schedule
    recurrence, Rcon-agnostic (member of table + strictly consecutive).
    Returns (run_len, words) where words are the uint32s at base."""
    nk = key_len // 4
    nwords = (len(buf) - base) // 4
    if nwords < nk + 1:
        return 0, []
    words = [int.from_bytes(buf[base + 4 * i: base + 4 * i + 4], "little")
             for i in range(nwords)]
    run = 0
    prev_rc = None
    for j in range(nk, nwords):
        wj, wprev, wback = words[j], words[j - 1], words[j - nk]
        if j % nk == 0:
            x = wj ^ wback ^ _subword(_rotword(wprev))
            if x not in RCON_SET:
                break
            idx = RCON.index(x)
            if prev_rc is not None and idx != prev_rc + 1:
                break
            prev_rc = idx
        elif nk > 6 and j % nk == 4:
            if wj ^ wback ^ _subword(wprev) != 0:
                break
        else:
            if wj ^ wback ^ wprev != 0:
                break
        run += 1
    return run, words


def recover_keys_from_run(words: list, key_len: int):
    """Inverse key schedule: given a run of schedule words (relative index 0
    = first known word), try every round alignment dk and walk back to
    round 0. Returns [(dk, key_bytes, verified_bool)]."""
    nk = key_len // 4
    total = 4 * (nk + 7)
    known = len(words)
    out = []
    dk_max = max(0, (total - known) // nk)
    for dk in range(dk_max + 1):
        j_start = nk * dk                     # true index of words[0]
        mem = {j_start + i: w for i, w in enumerate(words)}
        ok = True
        for j in range(j_start + known - 1, nk - 1, -1):
            wj = mem.get(j)
            wprev = mem.get(j - 1)
            if wj is None or wprev is None:
                ok = False
                break
            mem[j - nk] = wj ^ _f(wprev, j, nk)
        if not ok:
            continue
        key = b"".join(mem[i].to_bytes(4, "little") for i in range(nk))
        # forward-verify the candidate against the in-memory run
        verified = False
        try:
            exp = schedule_words(key_expansion(key))
        except ValueError:
            continue
        if all(exp[j_start + i] == words[i] for i in range(known)):
            verified = True
        out.append((dk, key, verified))
    return out


# ------------------------------------------------------- first-check filters

def first_check_numpy(buf: bytes, key_len: int, stride: int):
    """Vectorised Rcon-agnostic first recurrence check.
    Returns byte offsets (survivors). stride 4 (word aligned) uses uint32
    views; stride 1 uses sliding byte windows (slower, more memory)."""
    nk = key_len // 4
    n = len(buf)
    need = nk * 4 + 4
    if n < need:
        return []
    survivors = []
    sbox_np = np.frombuffer(SBOX, dtype=np.uint8)
    rc_set = np.zeros(256, dtype=bool)
    rc_set[np.array(RCON, dtype=np.uint8)] = True

    if stride == 4:
        words = np.frombuffer(buf[: (len(buf) // 4) * 4], dtype="<u4")
        total = len(words)
        step = CHUNK_WORDS
        for c0 in range(0, total - nk, step):
            chunk = words[c0: c0 + step + nk]      # overlap so s+knk in-chunk
            m = len(chunk) - nk
            if m <= 0:
                break
            b = chunk.view(np.uint8).reshape(-1, 4)
            rot = np.empty_like(b)
            rot[:, 0] = b[:, 1]
            rot[:, 1] = b[:, 2]
            rot[:, 2] = b[:, 3]
            rot[:, 3] = b[:, 0]
            g = sbox_np[rot].view(np.uint32).reshape(-1)
            x = chunk[nk:] ^ chunk[:-nk] ^ g[nk - 1: nk - 1 + m]
            mask = ((x >> np.uint32(8)) == 0) & rc_set[x & np.uint32(0xFF)]
            for s in np.nonzero(mask)[0].tolist():
                survivors.append((c0 + s) * 4)
        return survivors

    # stride == 1: byte-level sliding windows, chunked
    barr = np.frombuffer(buf, dtype=np.uint8)
    step = 1 << 24                  # 16 MiB chunks
    kb = nk * 4
    for c0 in range(0, n - need, step):
        seg = barr[c0: c0 + step + need]
        m = len(seg) - need
        if m <= 0:
            break
        a0 = seg[kb: kb + m]
        a1 = seg[kb + 1: kb + 1 + m]
        a2 = seg[kb + 2: kb + 2 + m]
        a3 = seg[kb + 3: kb + 3 + m]
        c = (nk - 1) * 4
        s0 = sbox_np[seg[c + 1: c + 1 + m]]       # SubWord(RotWord(w_{nk-1}))
        s1 = sbox_np[seg[c + 2: c + 2 + m]]
        s2 = sbox_np[seg[c + 3: c + 3 + m]]
        s3 = sbox_np[seg[c: c + m]]
        x0 = a0 ^ seg[0: m] ^ s0
        x1 = a1 ^ seg[1: 1 + m] ^ s1
        x2 = a2 ^ seg[2: 2 + m] ^ s2
        x3 = a3 ^ seg[3: 3 + m] ^ s3
        mask = (x1 == 0) & (x2 == 0) & (x3 == 0) & rc_set[x0]
        for s in np.nonzero(mask)[0].tolist():
            survivors.append(c0 + s)
    return survivors


def first_check_python(buf: bytes, key_len: int, stride: int):
    """Pure-python fallback of the same first check (slow)."""
    nk = key_len // 4
    kb = nk * 4
    survivors = []
    frombytes = int.from_bytes
    sbox, rset, sub, rot = SBOX, RCON_SET, _subword, _rotword
    end = len(buf) - (kb + 4)
    for off in range(0, end + 1, stride):
        try:
            w = frombytes(buf[off: off + 4], "little")
            wn = frombytes(buf[off + kb: off + kb + 4], "little")
            wc = frombytes(buf[off + kb - 4: off + kb], "little")
        except Exception:
            continue
        if wn ^ w ^ sub(rot(wc)) in rset:
            survivors.append(off)
    return survivors


def first_check(buf: bytes, key_len: int, stride: int, use_numpy=None):
    if use_numpy is None:
        use_numpy = HAS_NUMPY
    if use_numpy and HAS_NUMPY:
        try:
            return first_check_numpy(buf, key_len, stride)
        except Exception as e:            # never die on a numpy oddity
            _fail(f"numpy first-check failed ({e}); falling back to python")
    return first_check_python(buf, key_len, stride)


# ------------------------------------------------------------------ scanning

def scan_buffer(buf: bytes, path: str, key_len: int, stride: int,
                min_words: int, mode: str, use_numpy=None):
    """Scan one buffer. Returns report rows:
    dicts with file/offset/type/key_hex/first16/schedule_sha256/verified."""
    rows = []
    t0 = time.time()
    survivors = first_check(buf, key_len, stride, use_numpy=use_numpy)
    t1 = time.time()
    print(f"[hunt] {path}: {len(buf)} bytes, {len(survivors)} first-check "
          f"survivor(s) in {t1 - t0:.2f}s (stride={stride}, "
          f"{'numpy' if (use_numpy if use_numpy is not None else HAS_NUMPY) and HAS_NUMPY else 'python'})")

    seen = set()
    for off in survivors:
        if mode in ("forward", "both"):
            r = forward_verify(buf, off, key_len, min_words)
            if r is not None:
                match, avail, key = r
                comp_total = (4 * (key_len // 4 + 7) - key_len // 4)
                if match >= min_words:
                    typ = "FULL" if (match == comp_total and
                                     avail == comp_total) else "PARTIAL"
                    sig = (path, off, key.hex())
                    if sig not in seen:
                        seen.add(sig)
                        rows.append(_row(path, off, typ, key,
                                         key_expansion(key), buf))
        if mode in ("consistency", "both"):
            run, words = consistency_run(buf, off, key_len)
            if run >= CONSISTENCY_MIN_WORDS and words:
                # only the consecutive run (plus its nk seed words) is a
                # schedule — the tail past the run is unrelated memory
                run_words = words[: key_len // 4 + run]
                for dk, key, verified in recover_keys_from_run(run_words,
                                                                key_len):
                    sig = (path, off, key.hex())
                    if sig in seen:
                        continue
                    seen.add(sig)
                    typ = ("CONSISTENCY" if verified
                           else "CONSISTENCY-UNVERIFIED")
                    rows.append(_row(path, off, typ, key,
                                     key_expansion(key), buf,
                                     note=f"dk={dk} run={run}"))
    return rows


def _row(path, off, typ, key, sched, buf, note=""):
    return {
        "file": path,
        "offset": off,
        "type": typ,
        "key_hex": key.hex(),
        "first16_hex": bytes(buf[off: off + 16]).hex(),
        "schedule_sha256": hashlib.sha256(sched).hexdigest(),
        "verified": typ in ("FULL", "CONSISTENCY"),
        "note": note,
    }


# ---------------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(
        description="Find AES key schedules (and recover round-0 keys) in "
                    "memory dumps.",
        epilog="Performance: pure python over ~1 GB is slow (the "
               "first-check is O(n) with big constants); the numpy path "
               "(auto-detected) is hundreds of MB/s. Keep --stride 4 for "
               "big dumps; --slow (stride 1) only for small regions.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dump-dir", help="scan every file under DIR")
    p.add_argument("--file", help="scan a single dump/blob file")
    p.add_argument("--key-len", type=int, default=16, choices=KEYLENS,
                    help="AES key size in bytes (default 16 = AES-128)")
    p.add_argument("--stride", type=int, default=4,
                    help="candidate offset stride in bytes (default 4)")
    p.add_argument("--slow", action="store_true",
                    help="shorthand for --stride 1 (byte granularity)")
    p.add_argument("--min-words", type=int, default=8,
                    help="PARTIAL threshold for the forward check "
                         "(default 8); consistency mode is fixed at 20")
    p.add_argument("--limit-mb", type=float, default=None,
                    help="read at most this many MB per file (default all)")
    p.add_argument("--mode", choices=("forward", "consistency", "both"),
                    default="both", help="detectors to run (default both)")
    p.add_argument("--out", default="candidates.json",
                    help="write hits to this JSON file")
    p.add_argument("--no-numpy", action="store_true",
                   help="force the pure-python first-check")
    p.add_argument("--selftest", action="store_true",
                   help="run the synthetic round-trip self test and exit")
    return p


def collect_files(args):
    files = []
    if args.file:
        files.append(Path(args.file))
    if args.dump_dir:
        d = Path(args.dump_dir)
        if not d.is_dir():
            _fail(f"--dump-dir {d} is not a directory")
        files.extend(sorted(q for q in d.rglob("*") if q.is_file()))
    return [f for f in files if f.exists()]


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.file and not args.dump_dir:
        _fail("nothing to scan: pass --file PATH and/or --dump-dir DIR")
        return 2
    if args.slow:
        args.stride = 1

    rows = []
    limit = None if args.limit_mb is None else int(args.limit_mb * 1024 * 1024)
    for f in collect_files(args):
        try:
            data = f.read_bytes() if limit is None else f.read_bytes()[:limit]
        except OSError as e:
            _fail(f"cannot read {f}: {e}")
            continue
        if not data:
            continue
        rows.extend(scan_buffer(data, str(f), args.key_len, args.stride,
                                args.min_words, args.mode,
                                use_numpy=(False if args.no_numpy else None)))

    print(f"\n{'FILE':<40} {'OFFSET':>12} {'TYPE':<24} {'KEY HEX':<34} "
          f"{'FIRST 16B':<34}")
    for r in rows:
        print(f"{Path(r['file']).name:<40} 0x{r['offset']:08x} "
              f"{r['type']:<24} {r['key_hex']:<34} {r['first16_hex']:<34}")
    print(f"[hunt] {len(rows)} candidate(s)")
    out = Path(args.out)
    out.write_text(json.dumps(rows, indent=2))
    print(f"[hunt] wrote {out}")
    return 0 if rows else 1


# ----------------------------------------------------------------- self test

def _aes_block_encrypt(schedule: bytes, block: bytes) -> bytes:
    """Minimal AES block encryption from a schedule (self test only)."""
    words = schedule_words(schedule)
    nr = len(words) // 4 - 1
    s = [[block[r + 4 * c] for c in range(4)] for r in range(4)]

    def ark(rnd):
        for c in range(4):
            k = words[4 * rnd + c]
            for r in range(4):
                s[r][c] ^= (k >> (8 * r)) & 0xFF

    def xt(a):
        a <<= 1
        return (a ^ 0x1B) & 0xFF if a & 0x100 else a

    def mix(c):
        a = [s[r][c] for r in range(4)]
        s[0][c] = xt(a[0]) ^ xt(a[1]) ^ a[1] ^ a[2] ^ a[3]
        s[1][c] = a[0] ^ xt(a[1]) ^ xt(a[2]) ^ a[2] ^ a[3]
        s[2][c] = a[0] ^ a[1] ^ xt(a[2]) ^ xt(a[3]) ^ a[3]
        s[3][c] = xt(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xt(a[3])

    ark(0)
    for rnd in range(1, nr):
        for r in range(4):
            for c in range(4):
                s[r][c] = SBOX[s[r][c]]
        for r in range(1, 4):                       # ShiftRows
            s[r] = s[r][r:] + s[r][:r]
        for c in range(4):
            mix(c)
        ark(rnd)
    for r in range(4):
        for c in range(4):
            s[r][c] = SBOX[s[r][c]]
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]
    ark(nr)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _selftest_checks():
    """Generator of (name, ok, detail) tuples."""
    # 1. known-answer: FIPS-197 Appendix A word 4 (hand-verified value)
    sched128 = key_expansion(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    yield ("expansion w4 known-answer",
           sched128[16:20] == bytes.fromhex("a0fafe17"),
           sched128[16:20].hex())

    # 2. known-answer block encryption, FIPS-197 Appendix B (AES-128) and
    #    the classic AES-256 vector
    k128 = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = _aes_block_encrypt(key_expansion(k128), pt)
    yield ("AES-128 block FIPS-197 B",
           ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex())
    k256 = bytes(range(32))
    ct2 = _aes_block_encrypt(key_expansion(k256), pt)
    yield ("AES-256 block vector",
           ct2.hex() == "8ea2b7ca516745bfeafc49904b496089", ct2.hex())

    # cross-check against pycryptodome when available (extra confidence)
    try:
        from Crypto.Cipher import AES as _AES
        import os as _os
        ok = True
        for klen in (16, 24, 32):
            k = _os.urandom(klen)
            p = _os.urandom(16)
            ok = ok and (_aes_block_encrypt(key_expansion(k), p)
                         == _AES.new(k, _AES.MODE_ECB).encrypt(p))
        yield ("pycryptodome cross-check (16/24/32)", ok, "")
    except ImportError:
        yield ("pycryptodome cross-check (16/24/32)", None,
               "SKIP (pycryptodome not installed)")

    # 3. forward scan round-trips
    import os as _os
    for klen in (16, 32):
        key = _os.urandom(klen)
        sched = key_expansion(key)
        blob = _os.urandom(1024) + sched + _os.urandom(512)
        for label, use_np in (("numpy", True), ("python", False)):
            if use_np and not HAS_NUMPY:
                yield (f"forward AES-{klen * 8} [{label}]",
                       None, "SKIP (no numpy)")
                continue
            rows = scan_buffer(blob, f"synthetic-{klen}", klen, 4, 8,
                               "both", use_numpy=use_np)
            hit = [r for r in rows if r["offset"] == 1024
                   and r["type"] == "FULL" and r["key_hex"] == key.hex()]
            yield (f"forward AES-{klen * 8} [{label}]",
                   bool(hit), f"{len(rows)} rows")

    # 4. truncated forward (PARTIAL)
    key = _os.urandom(16)
    sched = key_expansion(key)
    blob = _os.urandom(512) + sched[:16 + 32]          # key + 8 words
    rows = scan_buffer(blob, "synthetic-trunc", 16, 4, 8, "forward")
    hit = [r for r in rows if r["offset"] == 512 and r["type"] == "PARTIAL"
           and r["key_hex"] == key.hex()]
    yield ("forward truncated PARTIAL", bool(hit), f"{len(rows)} rows")

    # 5. consistency-only (round-0 key NOT in the blob) + inverse recovery
    for klen in (16, 32):
        key = _os.urandom(klen)
        sched = key_expansion(key)
        body = sched[klen:]                            # round keys only
        blob = _os.urandom(768) + body + _os.urandom(256)
        rows = scan_buffer(blob, f"synthetic-cons-{klen}", klen, 4, 8,
                           "consistency")
        hit = [r for r in rows if r["type"] == "CONSISTENCY"
               and r["key_hex"] == key.hex()]
        yield (f"consistency-only recovery AES-{klen * 8}", bool(hit),
               f"{len(rows)} rows, "
               f"{[r['key_hex'][:8] for r in rows]}")

    # 5b. consistency with a truncated tail (dump boundary)
    key = _os.urandom(16)
    body = key_expansion(key)[16:16 + 100]            # 25 words >= 20
    blob = _os.urandom(640) + body
    rows = scan_buffer(blob, "synthetic-cons-trunc", 16, 4, 8, "consistency")
    hit = [r for r in rows if r["type"] == "CONSISTENCY"
           and r["key_hex"] == key.hex()]
    yield ("consistency truncated tail", bool(hit), f"{len(rows)} rows")

    # 6. unaligned schedule found with stride 1 (--slow)
    key = _os.urandom(16)
    sched = key_expansion(key)
    blob = _os.urandom(1026) + sched + _os.urandom(64)
    rows = scan_buffer(blob, "synthetic-unaligned", 16, 1, 8, "forward")
    hit = [r for r in rows if r["offset"] == 1026
           and r["key_hex"] == key.hex()]
    yield ("unaligned via stride 1", bool(hit), f"{len(rows)} rows")

    # 7. false-positive sanity on random data
    blob = _os.urandom(64 * 1024)
    rows = scan_buffer(blob, "synthetic-random", 16, 4, 8, "both")
    yield ("no false positives on 64 KiB random", len(rows) == 0,
           f"{len(rows)} rows")


def selftest() -> int:
    print("[hunt] selftest — synthetic AES key-schedule round trips")
    fails = []
    for name, ok, detail in _selftest_checks():
        if ok is None:
            print(f"  SKIP   {name} ({detail})")
            continue
        print(f"  {'PASS' if ok else 'FAIL'}  {name}"
              + (f"  [{detail}]" if detail else ""))
        if not ok:
            fails.append(name)
    if fails:
        print(f"[hunt] SELFTEST: FAIL ({len(fails)} check(s))")
        return 1
    print("[hunt] SELFTEST: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
