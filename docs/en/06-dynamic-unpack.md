# 06 - Dynamic unpack (GitHub Actions)

Local analysis boxes in this project do not run a nested Android
emulator. All device work is **GitHub Actions**.

## Workflows

| Workflow | Runner | What |
|---|---|---|
| `static-analysis.yml` | ubuntu-latest | androguard + iJiami inventory |
| `unpack-emulator.yml` | ubuntu-latest + KVM | x86_64 AVD, memdump, rebuild |
| `boot-test.yml` | macos-14 | arm64 AVD, install unpacked APK, screenshot |
| `ghidra-headless.yml` | ubuntu-latest | JDK 21 + Ghidra 12.1.3 on `libexec.so` |

## Secrets / inputs

- Private release `packed-1.17.6` asset `ycMob_1.17.6_ycsite.apk` **or**
  repository secret `SAMPLE_URL`.
- Never commit the APK. `tools/fetch_sample.sh` uses `SAMPLE_URL`.

## Unpack action (x86_64)

Why x86_64: `S.c("x86_64")` extracts `assets/ijm_lib/x86_64/libexec.so`.
The stub does not need houdini for decryption.

1. `adb root`, `adb install -g` packed APK.
2. `am start -n com.world.youcinemobile/com.mobile.brasiltv.activity.SplashAty`.
3. `unpack/external_memdump.py` sweeps `/proc/<pid>/mem` at 2,4,8,15,30 s
   for `dex\n03x\0` with a consistent `file_size`.
4. `validate_and_extract_dex.py` writes `classes.dex`, `classes2.dex`, ...
5. `rebuild_unpacked_apk.py` (apktool `--no-src`, manifest patch, asset
   strip, zip-replace DEX, apksigner).

Frida remains optional (`unpack/run_unpack.py` + zygote child gating,
non-default port `127.0.0.1:1337`). If `libexec` kills the agent, the
memdump still stands.

## Boot action (arm64)

ijkplayer and `libranger-jni.so` ship only `armeabi-v7a` / `arm64-v8a`.
An unpacked APK on x86_64 will `UnsatisfiedLinkError` in the player.
`boot-test.yml` therefore uses macos-14 + `google_apis;arm64-v8a`.

Success criteria: process stays up, `dumpsys activity` shows `SplashAty`
or `MainAty`, logcat has no `s.h.e.l.l` / iJiami fatal, screenshot
captured as artifact.
