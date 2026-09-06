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
2. GitHub Action **Dynamic unpack (emulator)** installs the packed APK on an
   x86_64 AVD (iJiami ships `libexec` for x86_64), launches `SplashAty`, and
   dumps decrypted DEX out-of-process from `/proc/<pid>/mem`.
3. `unpack/rebuild_unpacked_apk.py` restores the real Application class, drops
   packer assets, zip-replaces `classes*.dex`, zipaligns and signs.
4. GitHub Action **Boot test** installs the unpacked APK on an **arm64**
   emulator (ijkplayer / Ranger JNI have no x86_64 builds) and stores logcat
   plus a screenshot.

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
