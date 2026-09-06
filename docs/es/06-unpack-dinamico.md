# 06 - Unpack dinamico (GitHub Actions)

Las maquinas locales de este proyecto no levantan un emulador Android
anidado. El trabajo de dispositivo es **GitHub Actions**.

## Workflows

| Workflow | Runner | Que hace |
|---|---|---|
| `static-analysis.yml` | ubuntu-latest | androguard + inventario iJiami |
| `unpack-emulator.yml` | ubuntu-latest + KVM | AVD x86_64, memdump, rebuild |
| `boot-test.yml` | macos-14 | AVD arm64, instala el APK unpack, screenshot |
| `ghidra-headless.yml` | ubuntu-latest | JDK 21 + Ghidra 12.1.3 sobre `libexec.so` |

## Secretos / entradas

- Release privada `packed-1.17.6` o secreto `SAMPLE_URL`.
- Nunca commitear el APK. `tools/fetch_sample.sh` usa `SAMPLE_URL`.

## Unpack (x86_64)

`S.c("x86_64")` extrae `assets/ijm_lib/x86_64/libexec.so`. El stub no
necesita houdini para descifrar.

1. `adb root`, `adb install -g`.
2. `am start -n com.world.youcinemobile/com.mobile.brasiltv.activity.SplashAty`.
3. `unpack/external_memdump.py` barre `/proc/<pid>/mem`.
4. `validate_and_extract_dex.py` escribe `classes*.dex`.
5. `rebuild_unpacked_apk.py` (apktool `--no-src`, parche de manifest,
   strip de assets, zip-replace, apksigner).

Frida es opcional. Si `libexec` mata el agente, el memdump sigue.

## Boot (arm64)

ijkplayer y Ranger solo traen ARM. Un APK unpack en x86_64 falla el
player. `boot-test.yml` usa macos-14 + `google_apis;arm64-v8a`.

Criterio: proceso vivo, `SplashAty` o `MainAty`, logcat sin fatal de
iJiami, screenshot en el artifact.
