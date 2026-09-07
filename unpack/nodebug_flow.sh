#!/usr/bin/env bash
# nodebug_flow.sh v5 - ORIGINAL apk, spoofed environment, framework restart.
#
# Run evidence:
#   * 34044920876/34048953559/34049784110/34081223822: s.h.e.l.l.N.al
#     silently refuses to register on the stock debuggable image.
#   * 34084986538 (playstore/BlackDex): inside the sandbox the packer PASSED
#     the environment gate and the decrypted app started running - with ALL
#     qemu signals present - so the gate is NOT qemu: the remaining google_apis
#     suspects are the JDWP transport (apps debuggable) and the
#     userdebug/dev-keys build identity.
#   * 34085315293 (v3): ro.debuggable=0 + ro.secure=0 property-area patch and
#     the framework restart WORKED (no jdwp connections after restart) but
#     two self-inflicted failures: patching ro.hardware.egl crash-looped
#     surfaceflinger and the ':' in fingerprint values broke --set parsing.
#   * 34086236774 (v4): install-before-restart + readiness wait worked, but
#     the app NEVER LAUNCHED: 'am start' failed with
#     "Failure calling service activity: Broken pipe (32)" - hiding the qemu
#     device nodes (chmod 000 + mv) kills system_server within seconds on
#     this image. Since 34084986538 proves the qemu devices are NOT the gate,
#     v5 REMOVES all device-node manipulation entirely.
#
# v5 changes:
#   1. NO qemu device-node hiding (fatal + unnecessary).
#   2. Prop set trimmed to the two gate suspects (debuggable/JDWP +
#      userdebug/dev-keys identity). Dropped: all qemu.* runtime props
#      (qemu.hw.mainkeys crash-suspect for the systemui NPE, qemu.sf.* are
#      surfaceflinger-loaded), init.svc/init.svc_debug_pid.* (rewritten by
#      init anyway) and the ndk_translation/native-bridge markers - those
#      are REQUIRED for the armeabi-v7a install to spawn translated
#      processes; blanking ro.dalvik.vm.isa.arm would break the launch itself
#      (34084986538 also showed translation markers present while the packer
#      passed the gate).
#   3. patch_props.py whole-file fallback now lands the long-value props that
#      failed in v4 (ro.product.*.model, ro.product/bootimage fingerprint).
#   4. am start retry loop (system_server needs a moment after the restart).
set -x

export PATH="$ANDROID_HOME/platform-tools:$PATH"
cd "${GITHUB_WORKSPACE:-$(dirname "$0")/..}"
mkdir -p work dumped/youcine count

DBG=$(adb shell getprop ro.debuggable 2>/dev/null | tr -d '\r')
SEC=$(adb shell getprop ro.secure 2>/dev/null | tr -d '\r')
echo "boot props: ro.debuggable='$DBG' ro.secure='$SEC'"

adb root >/dev/null 2>&1 || true
sleep 5
echo "adb identity: $(adb shell id 2>/dev/null | tr -d '\r' | head -1)"
echo "SELinux: $(adb shell getenforce 2>/dev/null | tr -d '\r')"

# ---- install ORIGINAL apk as a 32-bit process (while the system is healthy)
adb install -r -g --abi armeabi-v7a work/packed.apk || \
  { echo "::error::install failed before patching"; exit 1; }
adb shell "dumpsys package $APP_ID | grep -iE 'primaryCpuAbi|nativeLibraryDir' | head -6" \
  | tee work/abi-info.txt || true
APPDIR=$(adb shell pm path "$APP_ID" 2>/dev/null | head -1 | tr -d '\r' \
  | sed 's/package://' | xargs -r dirname 2>/dev/null)
echo "APPDIR='$APPDIR'"

# ---- libstdc++ stub (insurance: libexecmain.so DT_NEEDED libstdc++.so) ----
echo 'int ijiami_stub_marker;' | gcc -shared -nostdlib -m32 \
  -o work/libstdcxx-i386.so -xc - || true
[ -n "$APPDIR" ] && adb push work/libstdcxx-i386.so "$APPDIR/lib/arm/libstdc++.so" || true

# ---- 1. property-area spoofing (values use the '|' separator) -------------
# NOTE: do NOT patch anything a restarted HAL/service reads to LOAD drivers:
# ro.hardware.egl (surfaceflinger -> EGL loader), ro.hardware.audio.primary
# (audioserver), *vulkan* (vulkan loader) - v3 crash-looped surfaceflinger.
# And do NOT blank the native-bridge/ndk_translation markers - the arm app
# needs them to spawn (see header, v5 change 2).
SAMSUNG_FP="samsung/o1sxxx/o1s:11/RP1A.200720.012/G991BXXU5CUL5:user/release-keys"
GOOGLE_FP="google/sdk_gphone_x86_64/generic_x86_64_arm64:11/RSR1.240422.006/12134477:userdebug/dev-keys"
python3 unpack/patch_props.py \
  --set "ro.debuggable=1|0" \
  --set "ro.secure=1|0" \
  --set "ro.build.tags=dev-keys|release-keys" \
  --set "ro.product.build.tags=dev-keys|release-keys" \
  --set "ro.build.type=userdebug|user" \
  --set "ro.product.build.type=userdebug|user" \
  --set "ro.build.fingerprint=${GOOGLE_FP}|${SAMSUNG_FP}" \
  --set "ro.product.build.fingerprint=${GOOGLE_FP}|${SAMSUNG_FP}" \
  --set "ro.bootimage.build.fingerprint=${GOOGLE_FP}|${SAMSUNG_FP}" \
  --set "ro.product.model=sdk_gphone_x86_64|SM-G991B" \
  --set "ro.product.odm.model=sdk_gphone_x86_64|SM-G991B" \
  --set "ro.product.product.model=sdk_gphone_x86_64|SM-G991B" \
  --set "ro.product.system_ext.model=sdk_gphone_x86_64|SM-G991B" \
  --set "ro.product.vendor.model=sdk_gphone_x86_64|SM-G991B" \
  --set "ro.hardware=ranchu|qcom" \
  --set "ro.boot.hardware=ranchu|qcom" \
  || echo "::warning::some prop patches failed (see output)"
echo "after patch: ro.debuggable=$(adb shell getprop ro.debuggable 2>/dev/null | tr -d '\r') ro.secure=$(adb shell getprop ro.secure 2>/dev/null | tr -d '\r')"
adb shell "getprop | grep -iE 'qemu|goldfish|debuggable|secure|tags|fingerprint|type|model|hardware' | head -40" \
  | tee work/props-after.txt || true

# ---- 2. framework restart: AMS re-reads ro.debuggable ---------------------
adb shell stop || true
for i in $(seq 1 60); do
  adb shell getprop init.svc.zygote 2>/dev/null | tr -d '\r' | grep -q stopped && break
  sleep 1
done
adb shell start || true
# strict readiness: the package and activity services must REGISTER
# (v3 lesson: 'pm path com.android.shell' was not strict enough - the
# install hit 'Can't find service: package' after surfaceflinger looping)
READY=""
for i in $(seq 1 120); do
  PKG=$(adb shell service check package 2>/dev/null | tr -d '\r')
  ACT=$(adb shell service check activity 2>/dev/null | tr -d '\r')
  echo "$PKG" | grep -q "found" && echo "$ACT" | grep -q "found" && READY=1 && break
  sleep 2
done
sleep 10
echo "framework restarted: ro.debuggable=$(adb shell getprop ro.debuggable 2>/dev/null | tr -d '\r')"
echo "package service: $(adb shell service check package 2>/dev/null | tr -d '\r')"
echo "activity service: $(adb shell service check activity 2>/dev/null | tr -d '\r')"
echo "surfaceflinger: $(adb shell getprop init.svc.surfaceflinger 2>/dev/null | tr -d '\r')"
echo "adb still root: $(adb shell id 2>/dev/null | tr -d '\r' | head -1)"
if [ -z "$READY" ]; then
  echo "::warning::framework did not fully restart; proceeding anyway"
fi
adb shell "pm path $APP_ID" || echo APP_GONE_AFTER_RESTART || true

# ---- 3. (v5: NO device-node hiding - it kills system_server on this image
#      and 34084986538 proved the qemu devices are not the gate) -----------

# ---- environment evidence --------------------------------------------------
adb shell "getprop | grep -iE 'qemu|debug|secure|tags|fingerprint|model|hardware|abilist' | head -40" \
  | tee work/props-evidence.txt || true

adb logcat -c || true

# ---- launch (retry: system_server needs a moment after the restart) -------
echo "== launching $APP_ID/$LAUNCH (up to 3 attempts) =="
for i in 1 2 3; do
  adb shell service check activity 2>/dev/null | tr -d '\r' | grep -q found || sleep 5
  OUT=$(adb shell am start -W -n "$APP_ID/$LAUNCH" 2>&1 | tr -d '\r')
  { echo "--- attempt $i ---"; echo "$OUT"; } | head -24 | tee -a work/am-start.txt
  PID=$(adb shell pidof "$APP_ID" 2>/dev/null | tr -d '\r')
  if [ -n "$PID" ]; then break; fi
  if echo "$OUT" | grep -qE "Broken pipe|Error type|does not exist|SecurityException|Starting:.*Error"; then
    echo "launch attempt $i failed; waiting 10s before retry"; sleep 10
  elif [ -z "$OUT" ]; then
    echo "launch attempt $i produced no output (adb dead?); retrying"; sleep 10
  else
    break
  fi
done
sleep 15
PID=$(adb shell pidof "$APP_ID" 2>/dev/null | tr -d '\r')
echo "pid after 15s: '$PID'"

# ---- out-of-process poll -> SIGSTOP freeze -> /proc/<pid>/mem sweep -------
python3 unpack/external_memdump.py \
  --app "$APP_ID" \
  --out-dir dumped/youcine \
  --expect "$EXPECT_DEX" \
  --timeout 240 \
  --settle 1.0 \
  --resweep-gap 12 \
  --pull-app-data || true

# ---- evidence capture ------------------------------------------------------
adb shell "dmesg 2>/dev/null | grep -iE 'dlopen|libexec|stdc|linker' | head -60" \
  > work/dmesg-linker.txt || true
adb logcat -d -b main,system,crash > work/logcat-nodebug.txt 2>/dev/null || true
echo "== key logcat lines (jdwp presence is the debuggable indicator) =="
grep -nE "jdwp|s\.h\.e\.l\.l|ijiami|UnsatisfiedLink|FATAL|AndroidRuntime|Fatal signal" \
  work/logcat-nodebug.txt | head -40 || true
adb shell "ps -A | grep -i youcine" | tee work/ps-after.txt || true
PID=$(adb shell pidof "$APP_ID" 2>/dev/null | tr -d '\r')
if [ -n "$PID" ]; then
  adb shell "cat /proc/$PID/maps 2>/dev/null | grep -E 'libexec|ijm|stdc|dex|ndk' | head -24" \
    | tee work/maps-app.txt || true
fi

# ---- count (min-size filter drops the 13.6 KB packer stub dex) ------------
ls -la dumped/youcine || true
n=0
for f in dumped/youcine/dex_*.bin; do
  [ -f "$f" ] || continue
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  [ "$sz" -ge 65536 ] && n=$((n+1))
done
echo "$n" > count/dex_count
echo "dex_count=$n"
