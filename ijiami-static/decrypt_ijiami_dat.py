#!/usr/bin/env python3
"""decrypt_ijiami_dat.py — offline AES decryption and verification of
assets/ijiami.dat (YouCine 1.17.6, iJiami packer).

Takes candidate AES keys (from ijiami-static/hunt_key_schedule.py
candidates.json, from ijiami-static/capture_aes_key.js keys.jsonl, or
--key HEX on the command line) and runs the full candidate matrix:

    keys x modes {ECB, CBC} x IVs {zero, first payload block}
         x key size (128/192/256 by key byte length)

Each decrypted stream is verified by magic bytes (dex\\n, PK\\x03\\04,
gzip, zlib), 'Lcom/' class-descriptor density, and — when the raw magic
fails — by NRV2B decompression (reusing the working decompressor from
../static-analysis/nrv2b_ijiami.py, iJiami's historical payload codec)
with re-verification of the decompressed head.

Verified streams are split into payloads (dex magic scan at 16-byte
aligned offsets + u32 length-field probing) and extracted to
out/payload_<n>.<ext>. out/report.json records every tried combination.

Exit code: 0 when at least one payload verified, 1 otherwise (prints the
top-5 most promising candidates by 'Lcom/' density).

Key hygiene: full key material is NEVER printed to stdout (CI logs are
public) — only the first 8 hex chars + '…'. Full keys live in
report.json, a local artifact that must not be pasted into CI output.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:          # import-guard: clear message, no fake results
    AES = None

# ---------------------------------------------------------------- constants

HERE = Path(__file__).resolve().parent
NRV2B_DIR = HERE.parent / "static-analysis"

KNOWN = {                    # evidence/ijiami-dat-header.txt (1.17.6)
    "size": 9_543_463,
    "sha256": "228d6a21182cf07a5da80b254994cba37208098e9538448fc905aaada98698af",
    "dex_count": 4,
    "total_uncompressed": 41_140_828,
    "md5_ascii": "44f6438002be91557b704ba909f62f58",
}

MAGICS = (
    (b"dex\n", "dex"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"\x78\x9c", "zlib"),
    (b"\x78\xda", "zlib"),
    (b"\x78\x01", "zlib"),
)

HEAD_KIB = 256               # density window (first 256 KiB)


def log(msg: str) -> None:
    print(f"[dat] {msg}")


def fail(msg: str) -> None:
    print(f"[dat] ERROR: {msg}", file=sys.stderr)


def short_key(hexstr: str) -> str:
    # WHY truncated: token/key hygiene — stdout lands in public CI logs.
    # Full key material only goes to out/report.json (local artifact).
    return hexstr[:8] + "…" if len(hexstr) > 8 else hexstr


def require_pycryptodome() -> bool:
    if AES is None:
        fail("pycryptodome is required for AES: pip3 install pycryptodome")
        return False
    return True


# ------------------------------------------------------------------- NRV2B

try:                                        # import read-only, no duplication
    sys.path.insert(0, str(NRV2B_DIR))
    from nrv2b_ijiami import decompress as _nrv2b_impl
except Exception:
    _nrv2b_impl = None


def nrv2b_decompress(data: bytes, offset: int = 0, literal_xor: int = 0x0C,
                     max_out: int = 64 * 1024 * 1024):
    """Returns (out, consumed, status) or None when unavailable."""
    if _nrv2b_impl is not None:
        try:
            return _nrv2b_impl(data, offset, literal_xor, max_out)
        except Exception as e:
            return None
    # subprocess fallback (nrv2b_ijiami.py present but not importable)
    if not (NRV2B_DIR / "nrv2b_ijiami.py").exists():
        return None
    code = (
        "import sys, base64, json\n"
        f"sys.path.insert(0, {str(NRV2B_DIR)!r})\n"
        "from nrv2b_ijiami import decompress\n"
        "data = open(sys.argv[1], 'rb').read()\n"
        "out, consumed, status = decompress(data, int(sys.argv[2]), "
        "int(sys.argv[3]), int(sys.argv[4]))\n"
        "print(json.dumps({'consumed': consumed, 'status': status}))\n"
        "sys.stdout.flush()\n"
        "sys.stdout.buffer.write(base64.b64encode(out))\n"
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(data)
        tmp = tf.name
    try:
        r = subprocess.run([sys.executable, "-c", code, tmp, str(offset),
                            str(literal_xor), str(max_out)],
                           capture_output=True)
        if r.returncode != 0:
            return None
        nl = r.stdout.index(b"\n")
        meta = json.loads(r.stdout[:nl])
        blob = base64.b64decode(r.stdout[nl + 1:])
        return blob, meta["consumed"], meta["status"]
    except Exception:
        return None
    finally:
        os.unlink(tmp)


def _nrv2b_literal_encode(plain: bytes, xor: int = 0x0C) -> bytes:
    """Self-test helper: literal-only NRV2B stream (32 one-bits per
    32-bit LE word = 32 literal signals, mirrors the reader's refill)."""
    out = bytearray()
    for i in range(0, len(plain), 32):
        out += b"\xff\xff\xff\xff"
        out += bytes(b ^ xor for b in plain[i:i + 32])
    return bytes(out)


# ------------------------------------------------------------------ header

def parse_header(dat: bytes) -> dict:
    if len(dat) < 40:
        raise ValueError(f"file too small for the 40-byte header: {len(dat)}")
    count = struct.unpack_from("<I", dat, 0)[0]
    total = struct.unpack_from("<I", dat, 4)[0]
    ascii32 = dat[8:40]
    try:
        ascii_hex = ascii32.decode("ascii")
        is_hex = all(c in "0123456789abcdefABCDEF" for c in ascii_hex)
    except UnicodeDecodeError:
        ascii_hex, is_hex = "", False
    return {
        "count": count, "total_uncompressed": total,
        "ascii32": ascii_hex, "ascii32_is_hex": is_hex,
        "payload_len": len(dat) - 40,
    }


def check_header(dat: bytes, hdr: dict) -> list:
    warns = []
    if len(dat) != KNOWN["size"]:
        warns.append(f"size {len(dat)} != known {KNOWN['size']}")
    if hdr["count"] != KNOWN["dex_count"]:
        warns.append(f"dex_count {hdr['count']} != known {KNOWN['dex_count']}")
    if hdr["total_uncompressed"] != KNOWN["total_uncompressed"]:
        warns.append("total_uncompressed "
                     f"{hdr['total_uncompressed']} != known "
                     f"{KNOWN['total_uncompressed']}")
    if hdr["ascii32"] != KNOWN["md5_ascii"]:
        warns.append(f"md5_ascii {hdr['ascii32']!r} != known "
                     f"{KNOWN['md5_ascii']!r}")
    import hashlib
    sha = hashlib.sha256(dat).hexdigest()
    if sha != KNOWN["sha256"]:
        warns.append(f"sha256 mismatch (got {sha}) — different build?")
    return warns


# -------------------------------------------------------------------- keys

def load_keys(args) -> list:
    """Returns [(key_bytes, source_label)] — deduped."""
    keys = []
    hdr = None

    def add(raw: bytes, label: str):
        if len(raw) in (16, 24, 32) and raw not in [k for k, _ in keys]:
            keys.append((raw, label))

    # header-derived candidates (the dat_aes_probe negatives, kept for the
    # record and for cross-checking any new build)
    try:
        dat = Path(args.dat).read_bytes()[:40]
        hdr = parse_header(dat)
        if hdr["ascii32_is_hex"]:
            try:
                add(bytes.fromhex(hdr["ascii32"]), "header ascii-hex parsed")
            except ValueError:
                pass
        add(dat[8:40], "header ascii raw 32B")
    except (OSError, ValueError):
        pass

    for hexstr in (args.key or []):
        try:
            k = bytes.fromhex(hexstr)
        except ValueError:
            fail(f"--key {short_key(hexstr)}: not valid hex")
            continue
        if len(k) not in (16, 24, 32):
            fail(f"--key {short_key(hexstr)}: {len(k)} bytes "
                 "(need 16/24/32)")
            continue
        add(k, "--key")

    for kf in (args.keys_file or []):
        try:
            entries = _parse_keys_file(Path(kf))
        except Exception as e:
            fail(f"--keys-file {kf}: {e}")
            continue
        for raw, label in entries:
            add(raw, label)
            # EVP-style captures read a 32B window; a 16B key may sit at
            # the front — also try the derived prefix.
            if len(raw) == 32:
                add(raw[:16], label + " derived16")
    return keys


def _parse_keys_file(path: Path) -> list:
    text = path.read_text()
    out = []
    entries = []
    try:
        loaded = json.loads(text)
        entries = loaded if isinstance(loaded, list) else [loaded]
    except json.JSONDecodeError:
        entries = []                      # try jsonl
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                if len(line) in (32, 48, 64) and \
                        all(c in "0123456789abcdefABCDEF" for c in line):
                    entries.append(line)   # raw hex line
    for e in entries:
        if isinstance(e, str):
            hexstr = e
            label = path.name
        elif isinstance(e, dict):
            if e.get("type") == "aes_table":
                continue                  # table hits carry no key
            hexstr = e.get("key") or e.get("key_hex") or ""
            label = (f"{path.name}:{e.get('fn', '')}"
                     f"@{e.get('module', '')}").rstrip(":")
        else:
            continue
        hexstr = str(hexstr).strip()
        try:
            raw = bytes.fromhex(hexstr)
        except ValueError:
            continue
        if len(raw) in (16, 24, 32):
            out.append((raw, label))
    return out


# -------------------------------------------------------------- decryption

def decrypt_head(payload: bytes, key: bytes, mode: str, iv_spec) -> bytes:
    """Decrypt the first HEAD_KIB (plus one block for firstblock IV)."""
    if mode == "ecb":
        blk = payload[:HEAD_KIB * 1024]
        return AES.new(key, AES.MODE_ECB).decrypt(blk[:len(blk) // 16 * 16])
    if iv_spec[0] == "zero":
        iv = b"\x00" * 16
        data = payload[:HEAD_KIB * 1024]
    else:                                  # firstblock: IV = payload[:16]
        iv = payload[:16]
        data = payload[16:16 + HEAD_KIB * 1024]
    data = data[:len(data) // 16 * 16]
    return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data)


def decrypt_full(payload: bytes, key: bytes, mode: str, iv_spec):
    """Decrypt the whole payload (floor to 16-byte blocks). Returns
    (stream, tail) — tail = bytes beyond the last full block, carried raw."""
    n = len(payload) // 16 * 16
    if mode == "ecb":
        return AES.new(key, AES.MODE_ECB).decrypt(payload[:n]), payload[n:]
    if iv_spec[0] == "zero":
        iv = b"\x00" * 16
        body, tail = payload[:n], payload[n:]
    else:
        iv, body, tail = payload[:16], payload[16:n], payload[n:]
    body = body[:len(body) // 16 * 16]
    return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(body), tail


# ------------------------------------------------------------ verification

def verify_head(head: bytes) -> dict:
    magic = None
    for m, name in MAGICS:
        if head.startswith(m):
            magic = name
            break
    window = head[:HEAD_KIB * 1024]
    lcom = window.count(b"Lcom/")
    ljava = window.count(b"Ljava/")
    # aligned_hits only counts the STRONG 4-byte magics (dex, zip): the
    # 2-byte gzip/zlib magics appear by chance in decrypted garbage at
    # 16-byte-aligned offsets (~1% per head for a wrong mode/IV), which
    # once flipped a CI selftest verdict via the CBC-zero-on-ECB path
    # (run 34280862511).  A 4-byte magic at an aligned offset is real
    # boundary evidence; a 2-byte one is not.
    aligned_hits = sum(1 for off in range(0, max(0, len(head) - 3), 16)
                       if magic_name(head, off) in ("dex", "zip"))
    # 'strong' requires the magic AND class-descriptor/boundary evidence:
    # CBC with the wrong IV still decrypts block 0 correctly (P0 = D(C0) ^
    # IV), so a lone magic at offset 0 is NOT proof — the rest of the head
    # must look like payload too.
    return {
        "magic": magic,
        "lcom_density": lcom,
        "ljava_count": ljava,
        "aligned_magic_hits": aligned_hits,
        "strong": magic is not None and (lcom >= 2 or aligned_hits >= 2),
    }


def try_nrv2b(head: bytes, max_out: int) -> dict:
    """Try NRV2B on the decrypted head (iJiami's literal xor is 0x0C).
    verified requires magic AND Lcom/ evidence (see verify_head)."""
    best = {"tried": False, "magic": None, "lcom_density": 0,
            "verified": False}
    for xor in (0x0C, 0x00):
        r = nrv2b_decompress(head, 0, xor, max_out)
        if r is None:
            continue
        out, consumed, status = r
        best["tried"] = True
        for m, name in MAGICS:
            if out.startswith(m):
                best["magic"] = name
                best["lcom_density"] = out[:HEAD_KIB * 1024].count(b"Lcom/")
                best["xor"] = xor
                best["head_len"] = len(out)
                best["status"] = status
                best["verified"] = best["lcom_density"] >= 2
                return best
    return best


# ------------------------------------------------------------ payload split

def magic_name(stream: bytes, off: int):
    for m, name in MAGICS:
        if stream[off:off + 4].startswith(m):
            return name
    return None


def split_payloads(stream: bytes, max_payloads: int):
    """Scan for magic at 16-byte aligned offsets; probe the u32 at off-4 as
    a length field of the PREVIOUS payload. Returns (bounds, table)."""
    starts = [0]
    if magic_name(stream, 0) is None:
        # stream start not magic-aligned: still scan (NRV2B output may be
        # offset by a header) but keep 0 as the first boundary
        pass
    off = 16
    while off + 4 <= len(stream) and len(starts) < max_payloads:
        if magic_name(stream, off) is not None:
            starts.append(off)
        off += 16
    table = []
    bounds = []
    prev = None
    for i, s in enumerate(starts):
        if i == 0:
            bounds.append((0, None, "start"))
            prev = 0
            continue
        verdict = "magic-only boundary"
        end_of_prev = s
        if s >= 4:
            try:
                cand = struct.unpack_from("<I", stream, s - 4)[0]
            except struct.error:
                cand = None
            if cand is not None:
                if prev + cand + 4 == s:
                    verdict = (f"length-suffix confirmed (u32@{s - 4} = "
                               f"{cand})")
                    end_of_prev = s - 4
                elif abs(prev + cand - s) <= 16:
                    verdict = f"approx length {cand}"
        table.append({"start": s, "prev_start": prev,
                      "prev_end": end_of_prev, "verdict": verdict})
        bounds.append((s, None, verdict))
        prev = s
    # close the last payload (strip a trailing length field if plausible)
    last_start = starts[-1]
    end = len(stream)
    if end - last_start >= 4:
        try:
            tail_len = struct.unpack_from("<I", stream, end - 4)[0]
            if last_start + tail_len == end - 4:
                end = end - 4
                table.append({"start": None, "prev_start": last_start,
                              "prev_end": end,
                              "verdict": f"trailing length ({tail_len})"})
        except struct.error:
            pass
    # materialise payload extents
    extents = []
    for i, (s, _, verdict) in enumerate(bounds):
        nxt = bounds[i + 1][0] if i + 1 < len(bounds) else end
        # previous payload ends just before the next start (minus any
        # length field detected above)
        if i + 1 < len(bounds):
            pe = next((t["prev_end"] for t in table
                       if t.get("start") == nxt), nxt)
            extents.append((s, pe))
        else:
            extents.append((s, end))
    return extents, table


def extract_payloads(stream: bytes, extents, out_dir: Path,
                     max_payloads: int, tag: str) -> list:
    files = []
    for n, (a, b) in enumerate(extents[:max_payloads], start=1):
        blob = bytes(stream[a:b])
        ext = ".bin"
        for m, name in MAGICS:
            if blob.startswith(m):
                ext = {"dex": ".dex", "zip": ".zip", "gzip": ".gz",
                       "zlib": ".zlib"}[name]
                break
        path = out_dir / f"payload_{n}_{tag}{ext}"
        path.write_bytes(blob)
        files.append({"n": n, "start": a, "end": b, "len": len(blob),
                      "ext": ext, "file": str(path),
                      "magic": magic_name(stream, a)})
    return files


# --------------------------------------------------------------------- run

def build_parser():
    p = argparse.ArgumentParser(
        description="Offline AES decrypt + verify + split of "
                    "assets/ijiami.dat.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dat", default=os.environ.get("IJIAMI_DAT",
                                                    "assets/ijiami.dat"),
                   help="path to ijiami.dat (default: $IJIAMI_DAT or "
                        "assets/ijiami.dat; extract from the packed apk: "
                        "unzip -p <apk> assets/ijiami.dat > ...)")
    p.add_argument("--key", action="append", default=[],
                   help="candidate AES key as hex (repeatable)")
    p.add_argument("--keys-file", action="append", default=[],
                   help="candidates.json (hunt_key_schedule.py) and/or "
                        "keys.jsonl (capture_aes_key.js) — both formats")
    p.add_argument("--mode", choices=("auto", "ecb", "cbc"),
                   default="auto")
    p.add_argument("--iv", default="auto",
                   help="auto|zero|firstblock|HEX (CBC only)")
    p.add_argument("--out-dir", default=str(HERE / "out"),
                   help=f"default: {HERE / 'out'} (generated, git-ignored "
                        "content)")
    p.add_argument("--max-payloads", type=int, default=4,
                   help="payloads to extract per verified stream (default 4)")
    p.add_argument("--max-decompress-mb", type=int, default=64,
                   help="NRV2B output cap in MiB (default 64)")
    p.add_argument("--split", choices=("auto", "none"), default="auto")
    p.add_argument("--selftest", action="store_true",
                   help="synthetic AES+NRV2B round trip, prints PASS/FAIL")
    return p


def run(args) -> int:
    if AES is None:
        require_pycryptodome()
        return 2
    dat_path = Path(args.dat)
    if not dat_path.exists():
        fail(f"--dat {args.dat} not found — extract it from the packed "
             "apk (unzip -p ycMob_1.17.6_ycsite.apk assets/ijiami.dat) "
             "or set IJIAMI_DAT")
        return 2
    dat = dat_path.read_bytes()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    hdr = parse_header(dat)
    warns = check_header(dat, hdr)
    log(f"dat={dat_path} size={len(dat)} payload={hdr['payload_len']}")
    log(f"header: dex_count={hdr['count']} "
        f"total_uncompressed={hdr['total_uncompressed']} "
        f"ascii32={hdr['ascii32']!r}")
    for w in warns:
        log(f"WARN header mismatch: {w}")

    keys = load_keys(args)
    if not keys:
        fail("no candidate keys (pass --key, --keys-file, or keep the "
             "header-derived defaults)")
        return 2
    log(f"{len(keys)} candidate key(s): "
        + ", ".join(f"{short_key(k.hex())} ({lbl})" for k, lbl in keys))

    payload = dat[40:]
    iv_specs = _iv_specs(args)
    combos = []
    for key, label in keys:
        for mode in (("ecb", "cbc") if args.mode == "auto"
                     else (args.mode,)):
            for iv_spec in (iv_specs if mode == "cbc" else [("none", None)]):
                combos.append((key, label, mode, iv_spec))

    report = {
        "_note": "Full key material is included here. report.json is a "
                 "local artifact — never paste it into public CI logs.",
        "dat": {"path": str(dat_path), "size": len(dat),
                "header": hdr, "warnings": warns},
        "combos": [],
    }
    verified_any = False
    for key, label, mode, iv_spec in combos:
        entry = {
            "key_hex": key.hex(), "key_source": label,
            "bits": len(key) * 8, "mode": mode,
            "iv": iv_spec[0] if iv_spec[0] != "hex" else iv_spec[1],
            "verdict": None,
        }
        log(f"try {short_key(key.hex())} ({label}) {mode}"
            + (f" iv={iv_spec[0]}" if mode == "cbc" else ""))
        try:
            head = decrypt_head(payload, key, mode, iv_spec)
        except Exception as e:
            entry["verdict"] = f"decrypt error: {e}"
            report["combos"].append(entry)
            continue
        v = verify_head(head)
        entry.update({"head_magic": v["magic"],
                      "lcom_density": v["lcom_density"],
                      "ljava_count": v["ljava_count"],
                      "aligned_magic_hits": v["aligned_magic_hits"]})
        stream = None
        tag = f"{mode}_{iv_spec[0]}"
        if v["strong"]:
            stream, tail = decrypt_full(payload, key, mode, iv_spec)
            entry["full_len"] = len(stream)
            entry["tail_len"] = len(tail)
        else:
            nr = try_nrv2b(head, args.max_decompress_mb * 1024 * 1024)
            entry["nrv2b"] = nr
            if nr.get("verified"):
                stream_full, tail = decrypt_full(payload, key, mode, iv_spec)
                r = nrv2b_decompress(stream_full, 0, nr["xor"],
                                     args.max_decompress_mb * 1024 * 1024)
                if r is not None and len(r[0]) > 0:
                    stream = r[0]
                    entry["nrv2b"]["full_len"] = len(stream)
                    entry["nrv2b"]["status"] = r[2]
                    tag = f"{mode}_{iv_spec[0]}_nrv2b"
        if stream is None:
            entry["verdict"] = "not verified"
            report["combos"].append(entry)
            continue
        entry["verdict"] = "verified"
        verified_any = True
        if args.split == "none":
            blob_path = out_dir / f"stream_{tag}_{short_key(key.hex())[:-1]}.bin"
            blob_path.write_bytes(bytes(stream))
            entry["stream_file"] = str(blob_path)
            report["combos"].append(entry)
            continue
        extents, table = split_payloads(stream, args.max_payloads)
        entry["boundaries"] = table
        log(f"  VERIFIED {entry['verdict']} — "
            f"{len(extents)} payload boundary(ies)")
        for t in table:
            log(f"  boundary @ {t['start']}: {t['verdict']} "
                f"(prev payload {t['prev_start']}..{t['prev_end']})")
        files = extract_payloads(stream, extents, out_dir,
                                 args.max_payloads, tag)
        entry["payloads"] = files
        for f in files:
            log(f"  wrote {f['file']} ({f['len']} bytes, magic={f['magic']})")
        report["combos"].append(entry)

    (out_dir / "report.json").write_text(json.dumps(report, indent=2))
    log(f"wrote {out_dir / 'report.json'}")

    if verified_any:
        log("SUMMARY: PASS — at least one payload decrypted and verified")
        return 0
    log("SUMMARY: FAIL — no combination verified")
    ranked = sorted(report["combos"],
                    key=lambda c: -(c.get("lcom_density") or 0))[:5]
    if ranked:
        log("top-5 most promising (by 'Lcom/' density):")
        for c in ranked:
            log(f"  {short_key(c['key_hex'])} ({c['key_source']}) "
                f"{c['mode']} iv={c.get('iv')} -> "
                f"lcom={c.get('lcom_density')} "
                f"magic={c.get('head_magic')}")
    return 1


def _iv_specs(args):
    raw = (args.iv or "auto").lower()
    if raw == "auto":
        return [("zero", None), ("firstblock", None)]
    if raw == "zero":
        return [("zero", None)]
    if raw == "firstblock":
        return [("firstblock", None)]
    try:
        iv = bytes.fromhex(raw)
    except ValueError:
        fail(f"--iv {raw}: not hex")
        return []
    if len(iv) != 16:
        fail("--iv must be 16 bytes (32 hex chars)")
        return []
    return [("hex", raw)]


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()
    return run(args)


# ----------------------------------------------------------------- selftest

def _fake_dex(n: int, tag: str) -> bytes:
    body = bytearray(b"dex\n035\x00")
    body += struct.pack("<I", 0xCAFEBABE)
    body += b"\x00" * 12
    i = 0
    while len(body) < n:
        body += f"Lcom/world/youcinemobile/{tag}{i};".encode()
        body += b"\x00"
        i += 1
    return bytes(body[:n])


def _selftest_checks():
    import io
    import os
    import hashlib
    from contextlib import redirect_stdout

    if AES is None:
        yield ("pycryptodome availability", None, "SKIP")
        return
    yield ("pycryptodome availability", True, AES.__name__)

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        # DETERMINISTIC key: os.urandom once produced garbage whose
        # CBC-zero-on-ECB head accidentally met the strong criteria on
        # CI (run 34280862511) - a selftest must be reproducible.
        key = bytes(range(16))

        # ---- synthetic A: two plain dexes, [len] after each dex
        # dex1 length ≡ 12 mod 16 so dex2 starts at a 16-byte aligned
        # offset (the split heuristic only scans aligned offsets)
        dex1, dex2 = _fake_dex(780, "Alpha"), _fake_dex(512, "Beta")
        blob = dex1 + struct.pack("<I", len(dex1)) + dex2
        blob += b"\x00" * ((-len(blob)) % 16)
        hdr = struct.pack("<II", 2, len(dex1) + len(dex2)) + b"ab" * 16
        dat = hdr + AES.new(key, AES.MODE_ECB).encrypt(blob)

        # ---- synthetic B: NRV2B-compressed dex payload (xor 0x0C)
        plain = _fake_dex(4096, "Nrv")
        comp = _nrv2b_literal_encode(plain, 0x0C)
        comp += b"\x00" * ((-len(comp)) % 16)
        dat_b = hdr + AES.new(key, AES.MODE_ECB).encrypt(comp)

        for name, datfile, want_files, want_stream in (
                ("plain dex stream", tdp / "syn_a.dat", 2, dex1),
                ("NRV2B stream", tdp / "syn_b.dat", 1, plain[:4096])):
            datfile.write_bytes(dat if name.startswith("plain") else dat_b)
            out_dir = tdp / f"out_{datfile.stem}"
            argv = ["--dat", str(datfile), "--key", key.hex(),
                    "--out-dir", str(out_dir)]
            cap = io.StringIO()
            code = 1
            try:
                with redirect_stdout(cap):
                    code = main(argv)
            except SystemExit as e:
                code = e.code
            report = json.loads((out_dir / "report.json").read_text())
            ok_code = code == 0
            files = sorted(out_dir.glob("payload_*"))
            ok_files = len(files) == want_files
            blobs = [f.read_bytes() for f in files]
            ok_content = blobs and blobs[0].startswith(want_stream[:64])
            key_leak = key.hex() in cap.getvalue()
            key_in_report = key.hex() in (out_dir / "report.json").read_text()
            yield (f"{name}: exit 0", ok_code, f"code={code}")
            yield (f"{name}: {want_files} payload file(s)", ok_files,
                   str(files))
            yield (f"{name}: payload content starts with dex", ok_content,
                   "")
            yield (f"{name}: full key NOT printed to stdout", not key_leak,
                   "")
            yield (f"{name}: full key present in report.json", key_in_report,
                   "")

        # ---- keys-file path (candidates.json from hunt_key_schedule.py)
        cand = [{"file": "syn", "offset": 0, "key_hex": key.hex(),
                 "schedule_sha256": hashlib.sha256(b"x").hexdigest(),
                 "type": "FULL", "verified": True}]
        (tdp / "candidates.json").write_text(json.dumps(cand))
        out_dir = tdp / "out_c"
        cap = io.StringIO()
        try:
            with redirect_stdout(cap):
                code = main(["--dat", str(tdp / "syn_a.dat"),
                             "--keys-file", str(tdp / "candidates.json"),
                             "--out-dir", str(out_dir)])
        except SystemExit as e:
            code = e.code
        yield ("keys-file (candidates.json) path", code == 0
               and len(list(out_dir.glob("payload_*"))) == 2,
               f"code={code}")

        # ---- keys.jsonl path (frida capture format)
        lines = [
            json.dumps({"type": "aes_table", "module": "libexec.so",
                        "address": "0x1234"}),
            json.dumps({"type": "aes_key", "fn": "AES_set_encrypt_key",
                        "module": "libexec.so", "key": key.hex(),
                        "bits": 128, "iv": ""}),
        ]
        (tdp / "keys.jsonl").write_text("\n".join(lines) + "\n")
        out_dir = tdp / "out_j"
        cap = io.StringIO()
        try:
            with redirect_stdout(cap):
                code = main(["--dat", str(tdp / "syn_a.dat"),
                             "--keys-file", str(tdp / "keys.jsonl"),
                             "--out-dir", str(out_dir)])
        except SystemExit as e:
            code = e.code
        yield ("keys-file (keys.jsonl) path", code == 0
               and any(out_dir.glob("payload_*")), f"code={code}")

        # ---- wrong key must fail (exit 1, top-5 printed)
        out_dir = tdp / "out_bad"
        cap = io.StringIO()
        try:
            with redirect_stdout(cap):
                code = main(["--dat", str(tdp / "syn_a.dat"),
                             "--key", os.urandom(16).hex(),
                             "--out-dir", str(out_dir)])
        except SystemExit as e:
            code = e.code
        yield ("wrong key -> exit 1 + top-5 printed", code == 1
               and "top-5" in cap.getvalue(), f"code={code}")


def selftest() -> int:
    print("[dat] selftest — synthetic AES(+NRV2B) ijiami.dat round trip")
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
        print(f"[dat] SELFTEST: FAIL ({len(fails)} check(s))")
        return 1
    print("[dat] SELFTEST: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
