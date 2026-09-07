#!/usr/bin/env bash
# playstore_flow.sh - BlackDex sandbox unpack on the PRODUCTION playstore image.
#
# The google_apis_playstore image is a production build: ro.debuggable=0
# (apps run non-debuggable, no JDWP), no su, adbd is plain shell - i.e. the
# cleanest environment the iJiami gates have ever seen. BlackDex (GPL-3.0,
# https://github.com/CodingGay/BlackDex) needs no root: it runs the target
# inside its own sandbox and installs it from the REAL applicationInfo
# .sourceDir, so the byte-identical original APK passes the content and
# signature gates.
#
# PRIMARY: BlackDex32 (top.niunaijun.blackdexa32) - its sandbox process is
# 32-bit, so the iJiami stub extracts ijm_lib/x86 (NATIVE x86 SecLLVM:
# decryption actually runs) while BlackDex's cookie-dump engine only READS
# memory (translation-safe for its armeabi-v7a libblackdex.so).
# SECONDARY: BlackDex64 as a backup attempt.
set -x

export PATH="$ANDROID_HOME/platform-tools:$PATH"
cd "${GITHUB_WORKSPACE:-$(dirname "$0")/..}"
mkdir -p work dumped/youcine count dumps

BD32_PKG=top.niunaijun.blackdexa32
BD64_PKG=top.niunaijun.blackdexa64
TARGET=com.world.youcinemobile

# ---- device guard: never let adb block forever on a dead emulator --------
if ! timeout 30 adb get-state >/dev/null 2>&1; then
  echo "::error::no adb device - the playstore emulator is not up"
  adb devices -l || true
  tail -40 work/emulator.log 2>/dev/null || true
  echo "0" > count/dex_count
  exit 1
fi

# ---- environment evidence --------------------------------------------------
adb shell "getprop | grep -iE 'qemu|debug|secure|tags|fingerprint|model|abilist'" \
  | tee work/props-evidence.txt || true
echo "ro.debuggable=$(adb shell getprop ro.debuggable 2>/dev/null | tr -d '\r')"

# ---- provision past the GMS setup wizard (blocks UI automation) ------------
adb shell "settings put global device_provisioned 1" || true
adb shell "settings put secure user_setup_complete 1" || true
adb shell "am force-stop com.google.android.setupwizard" 2>/dev/null || true
adb shell "pm disable-user --user 0 com.google.android.setupwizard" 2>/dev/null || true

# ---- install BlackDex32 + ORIGINAL target ----------------------------------
adb install -r -g work/blackdex32.apk || true
adb install -r -g work/packed.apk || true
adb shell "pm path $BD32_PKG" || echo BD32_NOT_INSTALLED || true
adb shell "pm path $TARGET" || echo TARGET_NOT_INSTALLED || true
adb shell "dumpsys package $TARGET | grep -iE 'primaryCpuAbi' | head -2" \
  | tee work/abi-info.txt || true
adb shell "dumpsys package $BD32_PKG | grep -iE 'primaryCpuAbi' | head -2" \
  | tee work/bd32-abi.txt || true

timeout 30 adb logcat -c || true

# ---- drive BlackDex32 (uiautomator row tap + dialog handling) --------------
python3 unpack/blackdex_auto.py \
  --bd-package "$BD32_PKG" \
  --app-id "$TARGET" \
  --label YouCine \
  --out-dir dumps/blackdex32 \
  --timeout 360 || true

# ---- fallback: BlackDex64 (translated sandbox) ------------------------------
have_fix=$(find dumps/blackdex32 -type f \( -name "*_fix.dex" -o -name "*.dex_fix" \) 2>/dev/null | wc -l)
have_big=$(find dumps/blackdex32 -type f -name "classes*.dex" -size +64k 2>/dev/null | wc -l)
if [ "$have_fix" -eq 0 ] && [ "$have_big" -eq 0 ]; then
  echo "== BlackDex32 produced nothing usable; trying BlackDex64 =="
  adb install -r -g work/blackdex64.apk || true
  python3 unpack/blackdex_auto.py \
    --bd-package "$BD64_PKG" \
    --app-id "$TARGET" \
    --label YouCine \
    --out-dir dumps/blackdex64 \
    --timeout 300 || true
fi

timeout 90 adb logcat -d -b main,system,crash > work/logcat-playstore.txt 2>/dev/null || true
echo "== BlackDex sandbox evidence =="
grep -nE "youcine|blackdex|ijiami|s\.h\.e\.l\.l|UnsatisfiedLink|FATAL|DexDump|cookieDump" \
  work/logcat-playstore.txt | head -40 || true
adb shell "ps -A | grep -iE 'youcine|blackdex'" | tee work/ps-after.txt || true

# ---- normalize: BlackDex output -> dumped/youcine/dex_*.bin ----------------
# prefer *_fix.dex (DexUtils.fixDex repaired headers), fall back to raw
n=0
for f in $(find dumps -type f \( -name "*_fix.dex" -o -name "*.dex_fix" \) 2>/dev/null | sort); do
  n=$((n+1))
  cp "$f" "dumped/youcine/dex_blackdex_${n}.bin"
done
if [ "$n" -eq 0 ]; then
  for f in $(find dumps -type f -name "classes*.dex" 2>/dev/null | sort); do
    n=$((n+1))
    cp "$f" "dumped/youcine/dex_blackdex_${n}.bin"
  done
fi
ls -la dumped/youcine || true

# ---- count (min-size filter drops the 13.6 KB packer stub dex) ------------
m=0
for f in dumped/youcine/dex_*.bin; do
  [ -f "$f" ] || continue
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  [ "$sz" -ge 65536 ] && m=$((m+1))
done
echo "$m" > count/dex_count
echo "dex_count=$m"
