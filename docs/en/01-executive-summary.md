# 01 - Executive summary

## Target

YouCine mobile 1.17.6 (`com.world.youcinemobile`), distributed as
`ycMob_1.17.6_ycsite.apk` (42 877 511 bytes).

SHA-256: `28d028d75c89e6ab90c8b7e57a32c42355ac5ae2e388ea1e541bd003cae10d83`.

The visible product name is YouCine. Internally the code is the
`com.mobile.brasiltv.*` tree used by Magis TV / Xuper TV / Brasil TV:
same activity names (`SplashAty`, `MainAty`, `PlayAty`), same upgrade /
portal / EPG host pattern, different packer (iJiami here, SecNeo on the
Xuper-RE sample).

## Packer

| Item | Finding |
|---|---|
| Vendor | iJiami (AiJiami) |
| Stub | 14 KiB `classes.dex` with four classes: `S`, `A`, `N`, `C` in `s.h.e.l.l` |
| Encrypted payload | `assets/ijiami.dat` (9.5 MiB), little-endian count **4**, ASCII MD5 `44f6438002be91557b704ba909f62f58`, likely uncompressed size 41 140 828 |
| Native loader | `assets/ijm_lib/<abi>/libexec.so` + `libexecmain.so` for armeabi, arm64-v8a, x86, x86_64 |
| Compiler | string `ijiami SecLLVM compiler 1.7.4.20` |
| AJM | `assets/ijiami.ajm` magic `indl01` (native protection blob) |
| Data encryption | `S.sp()` reflects `com.ijm.dataencryption.DETool.loadDEso` |
| Real Application | **`com.mobile.brasiltv.app.App`** (hard-coded in `A.orignAppName` and `S.attachBaseContext`) |

Because x86_64 `libexec` is shipped, an x86_64 emulator can run the
decryptor without ARM translation. Playback libraries (ijkplayer, Ranger
JNI) are ARM-only, so a **boot** test of the unpacked app uses an arm64 AVD.

## Protections vs entitlements

Removing iJiami is a **client** operation: restore the real Application,
drop packer assets, replace DEX. It does **not** mint VIP tokens, does
**not** disable the upgrade kill-switch, and does **not** invent stream
URLs. Those are **server** resources on rotating portal/EPG/upgrade hosts
embedded in `strings.xml`.

## Pipeline

Static (this repo, no emulator) already identified packer, original
Application class, SDK list and host map. Dynamic unpack and boot run on
GitHub Actions because a nested ARM/KVM emulator does not fit the local
analysis box.

## Authors

beto-2dev, ChapzoMods. License GPL-3.0.
