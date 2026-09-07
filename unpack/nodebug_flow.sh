#!/usr/bin/env bash
# nodebug_flow.sh v4 - ORIGINAL apk, spoofed environment, framework restart.
#
# Run evidence:
#   * 34044920876/34048953559/34049784110/34081223822: s.h.e.l.l.N.al
#     silently refuses to register on the stock debuggable image.
#   * 34084986538 (playstore/BlackDex): inside the sandbox the packer PASSED
#     the environment gate and the decrypted app started running - with all
#     qemu signals present - so the gate is NOT qemu: the remaining google_apis
#     suspects are the JDWP transport (apps debuggable) and the
#     userdebug/dev-keys build identity.
#   * 34085315293 (v3): ro.debuggable=0 + ro.secure=0 property-area patch and
#     the framework restart WORKED (no jdwp connections after restart) but
#     two self-inflicted failures: patching ro.hardware.egl crash-looped
#     surfaceflinger ("couldn't find an OpenGL ES implementation") so the
#     package service never re-registered and the APK never installed
#     ("Can't find service: package"); and the ':' in fingerprint values
#     broke the --set spec parser (12 verify failures).
#
# v4 fixes: install the APK while the system is still healthy (before the
# restart), drop the HAL-loaded props from the patch set (ro.hardware.egl,
# ro.hardware.audio.primary, *vulkan*), '|' spec separator, and a strict
# post-restart readiness wait on `service check package` + `activity`.
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
SAMSUNG_FP="samsung/o1sxxx/o1s:11/RP1A.200720.012/G991BXXU5CUL5:user/release-keys"
GOOGLE_FP="google/sdk_gphone_x86_64/generic_x86_64_arm64:11/RSR1.240422.006/12134477:userdebug/dev-keys"
python3 unpack/patch_props.py \
  --set "ro.debuggable=1|0" \
  --set "ro.secure=1|0" \
  --set "ro.kernel.qemu=1|0" \
  --set "ro.kernel.android.qemud=1|0" \
  --set "init.svc.qemu-props=running|stopped" \
  --set "qemu.hw.mainkeys=1|0" \
  --set "qemu.sf.fake_camera=none|" \
  --set "qemu.sf.lcd_density=160|" \
  --set "qemu.logcat=start|" \
  --set "qemu.networknamespace=ready|" \
  --set "qemu.timezone=Etc/UTC|" \
  --set "qemu.adb.secure=1|0" \
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
  --set "ro.ndk_translation.version=0.2.2|" \
  --set "ro.enable.native.bridge.exec=1|0" \
  --set "ro.dalvik.vm.isa.arm64=x86_64|" \
  --set "ro.dalvik.vm.isa.arm=x86|" \
  --set "init.svc_debug_pid.qemu-props=168|" \
  --set "init.svc_debug_pid.goldfish-logcat=360|" \
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

# ---- 3. device-node hiding (early chmod: app opens fail, system safe) -----
adb shell "for d in /dev/qemu_pipe /dev/goldfish_pipe /dev/goldfish_address_space /dev/goldfish_sync /dev/socket/qemud; do chmod 000 \$d 2>/dev/null && echo chmod-000 \$d; done" || true
adb shell "ls -la /dev/qemu_pipe /dev/goldfish_pipe /dev/goldfish_address_space /dev/goldfish_sync /dev/socket/qemud 2>/dev/null" | tee work/qemu-devices.txt || true

# ---- environment evidence --------------------------------------------------
adb shell "getprop | grep -iE 'qemu|debug|secure|tags|fingerprint|model|hardware|abilist' | head -40" \
  | tee work/props-evidence.txt || true

# ---- bionic per-dlopen kernel logging (definitive load evidence) ----------
adb shell "setprop debug.ld.app.$APP_ID dlopen" || true
adb shell "dmesg -c > /dev/null 2>&1" || true
adb logcat -c || true

# ---- LATE device rename (existence checks fail; system survives ~55s) ------
adb shell "for d in /dev/qemu_pipe /dev/goldfish_pipe /dev/goldfish_address_space /dev/goldfish_sync /dev/socket/qemud; do mv \$d \$d.hdn 2>/dev/null && echo hidden \$d; done" || true

# ---- launch ---------------------------------------------------------------
echo "== launching $APP_ID/$LAUNCH =="
adb shell am start -W -n "$APP_ID/$LAUNCH" 2>&1 | head -24 || true
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
