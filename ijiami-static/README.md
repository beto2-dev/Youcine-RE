# ijiami-static — post-dump static decryption of assets/ijiami.dat

> **STATUS: ACTIVE.**
> This folder was gated on the success of the native runtime dump — the
> GitHub release `dumps-1.17.6` (5 decrypted DEXes from the redroid
> arm64 run) exists, so the static path is now live. Goal: an
> **independent, offline path to the same DEXes** — extract the AES key,
> decrypt `assets/ijiami.dat` on the bench, and cross-validate both
> methods against each other.

## What is known

### Header layout (evidence/ijiami-dat-header.txt, confirmed by analyze_dat.py)

| offset | size | meaning | value (1.17.6) |
|-------:|-----:|---------|----------------|
| 0 | 4 | u32le encrypted DEX count | `4` |
| 4 | 4 | u32le likely uncompressed total | `41,140,828` (~4.3× payload → compression) |
| 8 | 32 | ASCII "MD5-like" hex string | `44f6438002be91557b704ba909f62f58` |
| 40 | — | encrypted stream | 9,543,423 bytes |

File: `size = 9,543,463`,
`sha256 = 228d6a21182cf07a5da80b254994cba37208098e9538448fc905aaada98698af`.

### Payload statistics (analyze_dat.py, smoke-run on the real 1.17.6 dat)

- **16-byte duplicate blocks: 1,324 of 596,463 (0.222%)** — top duplicate
  `e8e8e8…` ×33 and a periodic `b92d2e b92d2e …` pattern ×22. Random
  16-byte blocks essentially never collide (birthday bound), so *every*
  duplicate is structural → consistent with **ECB** (or per-block ECB
  over a structured/compressed stream), **not** with CBC/chaining.
- Entropy per 64 KiB: min **7.7626** / avg **7.9670** / max **7.9965**
  bits-per-byte — uniformly high, zero low-entropy regions (no plaintext
  leaks, no header islands).
- Printable ratio: **36.2%**.
- `payload_len % 16 == 15` — the last 15 bytes are **not** a full AES
  block and not PKCS#7-like → likely a trailer/checksum, not ciphertext.
  `decrypt_ijiami_dat.py` decrypts the 16-aligned prefix and carries the
  tail raw.

### Negative results (static-analysis/dat_aes_probe.py)

AES-128-ECB/CBC (zero IV / first-block IV) with the header hex parsed as
a key, AES-256 with the raw ASCII, XOR with both, and 64 KiB magic scans
→ **no `dex\n` / zip / gzip / zlib magic anywhere**. The ASCII-hex string
is *not* the AES key; it is an integrity tag. The real key is derived
inside the SecLLVM-obfuscated `libexec.so` (x86_64 ~667 KiB, `BIND_NOW`,
JNI symbols stripped — see `static-analysis/ghidra-exports/
FUN_0005d480-engine.txt`, the decryption engine, and `getopcode_table.csv`
for its opcode table).

### History & context

- iJiami historically **NRV2B-compresses** the payload before
  encryption: a working decompressor port exists at
  `static-analysis/nrv2b_ijiami.py` (MSB-first bit reader, literal XOR
  `0x0C` self-unpack variant). `decrypt_ijiami_dat.py` reuses it
  (import, read-only) for post-decrypt verification.
- `libijmDataEncryption.so` / `DETool` is the **SM4
  encrypted-SharedPreferences engine** (EFS) — a *separate* subsystem,
  NOT related to `ijiami.dat`. Do not conflate (its key material will
  still be captured by the frida hook, which is fine — the offline
  verifier filters by result).

## Method overview — 4 attack vectors

| vector | tool | what it does |
|--------|------|--------------|
| **A. Runtime key capture** | `capture_aes_key.js` | frida script that hooks every AES key-material entry point (OpenSSL `AES_set_*_key`, `EVP_*Init*`, mbedTLS, `rijndael*`, tiny-AES-c) in every module as it loads, plus sweeps `libexec.so` for the AES S-box byte patterns (custom SecLLVM AES table candidates → Ghidra xrefs give the key-setup function). Emits `send()` events and appends to `/data/local/tmp/youcine_re_phase2/keys.jsonl`. Pairs with the phase-2 driver (`unpack/frida_phase2_driver.py`, agent 2-a): its `on_message` already handles `aes_key` events, and guard scripts are resolved by name under `frida-scripts/` — copy or symlink this file there and add it to `GUARD_SCRIPTS`; also runs standalone with the frida CLI. |
| **B. Key-schedule hunt in dumps** | `hunt_key_schedule.py` | scans the redroid memdump artifacts (raw region `.bin` files) for AES key schedules: (1) forward — key followed by its own expansion; (2) consistency-only — the schedule recurrence holds without the round-0 key present, recovered via the **inverse key schedule**. Output: `candidates.json` with recovered keys. |
| **C. Offline decrypt + verify** | `decrypt_ijiami_dat.py` | candidate matrix (keys × ECB/CBC × IV zero/first-block × 128/192/256) against the payload; verification by magic (`dex\n`, zip, gzip, zlib), `Lcom/` class-descriptor density, and NRV2B re-decompression; payload split (magic scan at 16-aligned offsets + u32 length probing) and extraction; `out/report.json` with every verdict. |
| **D. Header re-analysis** | `analyze_dat.py` | recompute the evidence digest for any `.dat`: header fields, sha256, duplicate-block stats (ECB indicator), per-64 KiB entropy, printable ratio, tail/padding analysis. Pure stdlib. |

Vectors A and B produce key candidates; C turns them into payloads; D
sanity-checks the input. A and B are complementary: A catches the key at
key-setup time (even if the schedule is never laid out contiguously), B
catches it post-hoc in frozen memory (even if the app crashed after
decrypt — the SIGSTOP freeze in `unpack/external_memdump.py` keeps the
region stable).

## Usage walkthroughs

```bash
# 0) get the payload out of the packed apk (any working copy)
export IJIAMI_DAT=/tmp/ijm/assets/ijiami.dat
mkdir -p /tmp/ijm/assets
unzip -p ycMob_1.17.6_ycsite.apk assets/ijiami.dat > "$IJIAMI_DAT"

# D) re-derive the evidence digest + payload statistics
python3 ijiami-static/analyze_dat.py --dat "$IJIAMI_DAT" --json out/analyze.json
#   -> size_bytes=9543463  sha256=228d6a...  u32le_0=4  u32le_4=41140828
#      md5_ascii=44f6438002be91557b704ba909f62f58
#      dup_blocks=1324/596463 (0.222%)  entropy avg=7.967 ...

# A) capture key material from a live run (redroid with frida-server,
#    see the phase-2 flow; also load the ptrace bypass):
frida -U -f com.world.youcinemobile \
      -l frida-scripts/02_bypass_ptrace.js \
      -l ijiami-static/capture_aes_key.js --no-pause
#   -> console lines '[aeskey] KEY AES_set_encrypt_key module=libexec.so
#      bits=128 key=<hex> iv=<hex>'  and events {type:'aes_key',...};
#      keys also appended to /data/local/tmp/youcine_re_phase2/keys.jsonl
#      (pull it: adb pull /data/local/tmp/youcine_re_phase2/keys.jsonl out/)
#    '[aeskey] TABLE AES S-box (forward) in libexec.so @ 0x7...' marks
#      custom AES tables — cross-reference those addresses in Ghidra to
#      find FUN_0005d480's key-setup family.
#
# A') same hook inside the phase-2 driver run (agent 2-a): guard scripts
#     are resolved by NAME under frida-scripts/, and the driver's message
#     handler already knows 'aes_key' events:
cp ijiami-static/capture_aes_key.js frida-scripts/         # or symlink
GUARD_SCRIPTS=02_bypass_ptrace.js,capture_aes_key.js \
  python3 unpack/frida_phase2_driver.py

# B) hunt expanded key schedules in the memdump artifacts
python3 ijiami-static/hunt_key_schedule.py --dump-dir dumped/youcine \
      --out ijiami-static/out/candidates.json
#   -> FILE/OFFSET/TYPE/KEY HEX/first-16B table; candidates.json entries
#      {file, offset, key_hex, schedule_sha256, type, verified}
#    (numpy is used automatically when present; ~1 GB pure python is
#     slow — see --help)

# C) offline decrypt + verify + split with everything we collected
python3 ijiami-static/decrypt_ijiami_dat.py --dat "$IJIAMI_DAT" \
      --keys-file ijiami-static/out/candidates.json \
      --keys-file ijiami-static/out/keys.jsonl \
      --out-dir ijiami-static/out
#   -> per-combination verdicts, boundary table, out/payload_<n>_<tag>.dex
#      and out/report.json; exit 0 only if >=1 payload verified,
#      otherwise exit 1 + the top-5 most promising candidates.

# self tests (synthetic AES + NRV2B round trips, no sample needed)
python3 ijiami-static/hunt_key_schedule.py --selftest     # PASS/FAIL
python3 ijiami-static/decrypt_ijiami_dat.py --selftest    # PASS/FAIL
```

Expected end state when vector A or B finds the key: `decrypt_ijiami_dat.py`
prints `VERIFIED`, writes `out/payload_1_*.dex … payload_4_*.dex` (or a
single NRV2B-decompressed stream that splits into them) and `SUMMARY: PASS`.

Environment variables: `IJIAMI_DAT` (payload path for all three tools),
`FRIDA_REMOTE`/`ADB` are handled by the phase-2 driver (agent 2-a), not
by this folder.

## Success criteria

- At least one of the 4 payloads decrypts (possibly after NRV2B
  decompression) to a stream that **verifies as DEX** (magic at offset 0
  or post-NRV2B magic, `Lcom/` density ≥ 2 in the first 256 KiB), and
- the extracted DEXes **match the runtime-dumped classes** from the
  `dumps-1.17.6` release (spot-check: shared class-descriptor strings,
  comparable sizes, `sha256` overlap for identical files).

This folder is deliberately an **independent path to the same DEXes the
runtime dump produced** — if both methods agree, the unpacking pipeline
no longer depends on a rooted emulator at all, and any future Youcine
build can be unpacked offline once the key is recovered again.

## Notes

- `out/` is **generated** (payloads, report.json, candidates.json,
  analyze.json). Do not commit its contents; the repo `.gitignore`
  already excludes `*.dex`/`*.log` style artifacts and the main agent
  owns the ignore list.
- **Key hygiene:** tools never print full key material to stdout (public
  CI logs) — only the first 8 hex chars + `…`. Full keys live in
  `out/report.json` / `candidates.json`, local artifacts that must not be
  pasted into CI output.
- `decrypt_ijiami_dat.py` needs `pycryptodome`
  (`pip3 install pycryptodome`); the other tools are stdlib-only
  (numpy optional, auto-detected).
- The NRV2B decompressor is **imported read-only** from
  `../static-analysis/nrv2b_ijiami.py` — never duplicated here.
