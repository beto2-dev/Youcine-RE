# Youcine-RE

Complete reverse-engineering lab for **YouCine** (`com.world.youcinemobile`) version **1.17.6**.

The packed sample uses the commercial **iJiami (AiJiami)** packer: a 14 KiB stub DEX
(`s.h.e.l.l.S` / `s.h.e.l.l.A`), encrypted multi-DEX in `assets/ijiami.dat`,
native loader `libexec.so` compiled with **SecLLVM 1.7.4.20**, and a data-encryption
sidecar (`com.ijm.dataencryption.DETool`).

- **RE authors:** beto-2dev, ChapzoMods
- **License:** GNU GPL 3.0 (`LICENSE`)
- **Languages:** [English](README.md) · [Espanol](README.es.md)
- **Scope:** packer removal methodology, protection map, SDK inventory, client vs server split, emulator pipelines

This repository contains **tools, scripts, and documentation produced during the
research**. It does **not** contain APKs, dumped DEX, or original application
source. Samples live in **private GitHub Releases**.

## Sample (analysed)

| Field | Value |
|---|---|
| File | `ycMob_1.17.6_ycsite.apk` |
| Package | `com.world.youcinemobile` |
| Version | 1.17.6 (11706) |
| min / target SDK | 19 / 33 |
| SHA-256 | `28d028d75c89e6ab90c8b7e57a32c42355ac5ae2e388ea1e541bd003cae10d83` |
| Stub DEX | `classes.dex` 13608 bytes |
| Encrypted DEX | `assets/ijiami.dat` 9543463 bytes, header count **4** |
| Real Application | `com.mobile.brasiltv.app.App` |
| Shell Application | `s.h.e.l.l.S` |
| Component factory | `s.h.e.l.l.A` wrapping `androidx.core.app.CoreComponentFactory` |
| Signer | self-signed `C=86, ST=GD, L=SZ, O=XXL, OU=OTT, CN=xxl` |
| Family | Same `com.mobile.brasiltv.*` lineage as Magis / Xuper / Brasil TV, rebranded YouCine, packed with iJiami instead of SecNeo |

## Tools

| Tool | Version | Role |
|---|---|---|
| Jadx | 1.5.6 | stub DEX to Java |
| Apktool | 2.12.1 | manifest, resources, rebuild |
| Ghidra | 12.1.3 (headless, JDK 21) | `libexec.so` / JNI |
| androguard | 4.x | APK parse |
| Frida | 16.6.x | optional in-process dump |
| Android emulator | API 30 x86_64 (dump), API 33 arm64 (boot) | GitHub Actions + KVM / Apple Silicon |
| GitHub Actions | ubuntu-latest, macos-14 | unpack + boot + Ghidra |

`tools/setup_env.sh` downloads JDK 21, Ghidra 12.1.3, Jadx 1.5.6, Apktool and
platform-tools into `TOOLS_DIR` (default `./tools`). Override every path with
environment variables; scripts do not hard-code machine locations.

## What is client-side vs server-side

**Client (can be unpacked / patched locally)**

- iJiami shell, encrypted DEX, `libexec` anti-debug (`ptrace`, `/proc/self/maps`)
- ABI extractor (`assets/ijm_lib/<abi>/libexec.so`, including **x86_64**)
- Data-encryption sidecar, `signed.bin` / ed25519 integrity
- UI, ijkplayer, Aria, Cast, HPPlay/LeLink, Firebase, Umeng, AdMob, Facebook SDK
- Embedded rotating hosts in `strings.xml` (portal, EPG, upgrade, notice, ads, H5)

**Server (cannot be removed by stripping the packer)**

- Catalog / VOD / live portal (`portal_main` / `portal_backup`)
- EPG, force-upgrade / version kill-switch, notices, ad config
- Account, VIP, device bind, redemption, payments
- Stream URL minting (not in the stub DEX)

Stripping iJiami yields a research build that **boots the original
`com.mobile.brasiltv.app.App`**. Entitlements and CDN URLs still come from the
portal hosts.

## Unpack pipeline

1. Static scan: `SAMPLE_APK=... python3 static-analysis/apk_quickscan.py`
2. GitHub Action **Dynamic unpack (emulator)** -> job `unpack-macos-tcg`:
   boots an arm64-v8a AVD with `-accel off` (same-arch TCG on the Apple
   Silicon runner - fully NATIVE ARM execution), installs the ORIGINAL
   packed APK, launches `SplashAty` and dumps the decrypted DEX
   out-of-process from `/proc/<pid>/mem` (no injection, no ptrace, no
   in-process agent -> undetectable by the packer's anti-debug).
3. `unpack/rebuild_unpacked_apk.py` restores the real Application class,
   drops packer assets, zip-replaces `classes*.dex`, zipaligns, signs and
   publishes the private release `unpacked-1.17.6`.
4. GitHub Action **Boot test (unpacked APK)** installs the rebuilt
   packer-free build on an arm64 emulator and verifies the real
   `com.mobile.brasiltv.*` UI boots (screenshots + logcat + dumpsys).

## Status (2026-09-08)

Every tool in the pipeline is finished and validated piece by piece
across ~30 instrumented CI runs; see
[docs/en/03-protections-and-bypass.md](docs/en/03-protections-and-bypass.md)
for the complete layer-by-layer map (ABI/translation trap, SecLLVM,
content-integrity gate, the raw-syscall/int3/ud2/SIGSEGV death ladder and
its neutralization in `unpack/trace_guard.c`).

The packer-free rebuild now boots the REAL app as far as physically
possible (rebuild v5, `rebuild-fix.yml` fast loop): a
`com.youcine.re.BootProvider` loads the iJiami DE SDK (SM4 prefs
engine) before `Application.onCreate` - including the ndk_translation
ABI rescue - the embedded signature kill-switch
(`ConfusionUtils.cc`) is neutralized by minimal DEX surgery, and the
process runs every non-protected layer until the first iJiami-VMP
method (`SqlHelper.getDb`). Full boot is impossible without the
packer's content-gated engine: the ~805 ACC_NATIVE bodies and ~45k
extraction stubs are materialized only by libexec at runtime. See the
corrected verdict in
[docs/en/06-dynamic-unpack.md](docs/en/06-dynamic-unpack.md).

The empirical conclusion of the hosted-CI research: **ARM guests are
impossible on GitHub-hosted runners** (Linux launcher refuses arm64 AVDs
on x86 hosts; macOS runners force HVF and lack the entitlement - even
with `-accel off`). The dump therefore finishes on real hardware, one
command away:

* **A rooted Android phone** (recommended, the classic path):

  ```bash
  adb install -r -g ycMob_1.17.6_ycsite.apk
  adb shell am start -n com.world.youcinemobile/com.mobile.brasiltv.activity.SplashAty
  python3 unpack/external_memdump.py --app com.world.youcinemobile \
      --out-dir dumped/youcine --expect 4 --timeout 600 --settle 3
  python3 unpack/validate_and_extract_dex.py --dump-dir dumped/youcine \
      --out-dir dexs --min-size 65536
  python3 unpack/rebuild_unpacked_apk.py --apk ycMob_1.17.6_ycsite.apk \
      --dump-dir dexs --out youcine-1.17.6-unpacked.apk \
      --keystore re.keystore --storepass android
  ```

* **Your own Mac as a self-hosted runner** (labels `[self-hosted, macOS]`):
  dispatch **Dynamic unpack (emulator)** with the `run_selfhosted` input
  enabled; `rebuild` and **Boot test** then run automatically end-to-end.

Full details: [docs/en/06-dynamic-unpack.md](docs/en/06-dynamic-unpack.md).

Fast iteration: the **Rebuild fix (fast loop)** workflow re-derives the
build deterministically from the immutable `packed-1.17.6` +
`dumps-1.17.6` releases and chains the boot test.

Frida scripts under `frida-scripts/` remain as an in-process alternative.
`libexec` calls `ptrace`; if the agent is killed, the memdump path still works.

## Documentation

| EN | ES |
|---|---|
| [01 Executive summary](docs/en/01-executive-summary.md) | [01 Resumen ejecutivo](docs/es/01-resumen-ejecutivo.md) |
| [02 iJiami packer](docs/en/02-packer-ijiami.md) | [02 Packer iJiami](docs/es/02-packer-ijiami.md) |
| [03 Protections](docs/en/03-protections-and-bypass.md) | [03 Protecciones](docs/es/03-protecciones-y-bypass.md) |
| [04 SDKs](docs/en/04-sdks.md) | [04 SDKs](docs/es/04-sdks.md) |
| [05 Client vs server](docs/en/05-client-vs-server.md) | [05 Cliente vs servidor](docs/es/05-cliente-vs-servidor.md) |
| [06 Dynamic unpack](docs/en/06-dynamic-unpack.md) | [06 Unpack dinamico](docs/es/06-unpack-dinamico.md) |
| [07 Legal](docs/en/07-legal.md) | [07 Legal](docs/es/07-legal.md) |

Machine-readable map: `evidence/findings.json`. Stub sources from Jadx:
`evidence/stub/`.

## Releases (private)

| Tag | Content |
|---|---|
| `packed-1.17.6` | Original packed sample (analysis material) |
| `unpacked-1.17.6` | Research APK with iJiami shell removed (after a successful dump) |

## Legal

Educational security research only: packer analysis, malware-analysis
methodology, SDK classification. Authors do not provide copyrighted media,
bypass of paid entitlements, or a redistribution of the vendor's bytecode.
See [docs/en/07-legal.md](docs/en/07-legal.md).
