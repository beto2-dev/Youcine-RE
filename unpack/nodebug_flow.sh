#!/usr/bin/env bash
# nodebug_flow.sh - ORIGINAL apk on a NON-DEBUGGABLE google_apis emulator
# (ramdisk-patched: ro.debuggable=0, ro.secure=0) with full qemu-signal
# spoofing.
#
# Run evidence:
#   * 34044920876/34048953559/34049784110: s.h.e.l.l.N.al silently refuses
#     to register on the stock debuggable image (JDWP transport open in
#     every app). No ro.debuggable/jdwp string exists in the packer's
#     decrypted strings, but the JDWP thread is still a detectable signal.
#   * 34081223822: emulator rejects non-qemu -prop; /system remount fails
#     (overlayfs deps), so build.prop editing is impossible at runtime;
#     renaming qemu device nodes killed system_server ~55s later.
#
# Countermeasures (this script):
#   * the workflow pre-patches the ramdisk (ro.debuggable=0 + ro.secure=0)
#   * unpack/patch_props.py rewrites property values in the shared
#     /dev/__properties__ area as root: fakes ro.kernel.qemu, init.svc.*,
#     every qemu.* prop, dev-keys/userdebug fingerprints, ranchu hardware,
#     ndk_translation markers - immediately visible to fresh readers.
#   * chmod 000 on qemu/goldfish device nodes early (app opens fail with
#     EACCES, root processes unaffected) and a late rename right before
#     launch (existence checks fail; the ~55s system lifetime after the
#     rename is far more than the dump window needs).
set -x

export PATH="$ANDROID_HOME/platform-tools:$PATH"
cd "${GITHUB_WORKSPACE:-$(dirname "$0")/..}"
mkdir -p work dumped/youcine count

DBG=$(adb shell getprop ro.debuggable 2>/dev/null | tr -d '\r')
SEC=$(adb shell getprop ro.secure 2>/dev/null | tr -d '\r')
echo "boot props: ro.debuggable='$DBG' ro.secure='$SEC'"
[ "$DBG" = "0" ] || echo "::warning::ramdisk patch did NOT take effect"

adb root >/dev/null 2>&1 || true
sleep 5
echo "adb identity: $(adb shell id 2>/dev/null | tr -d '\r' | head -1)"
echo "SELinux: $(adb shell getenforce 2>/dev/null | tr -d '\r')"

# ---- qemu-signal spoofing (decrypted-string evidence) ---------------------
SAMSUNG_FP="samsung/o1sxxx/o1s:11/RP1A.200720.012/G991BXXU5CUL5:user/release-keys"
GOOGLE_FP="google/sdk_gphone_x86_64/generic_x86_64_arm64:11/RSR1.240422.006/12134477:userdebug/dev-keys"
python3 unpack/patch_props.py \
  --set "ro.kernel.qemu=1:0" \
  --set "ro.kernel.android.qemud=1:0" \
  --set "init.svc.qemu-props=running:stopped" \
  --set "qemu.hw.mainkeys=1:0" \
  --set "qemu.sf.fake_camera=none:" \
  --set "qemu.sf.lcd_density=160:" \
  --set "qemu.logcat=start:" \
  --set "qemu.networknamespace=ready:" \
  --set "qemu.timezone=Etc/UTC:" \
  --set "qemu.adb.secure=1:0" \
  --set "ro.build.tags=dev-keys:release-keys" \
  --set "ro.product.build.tags=dev-keys:release-keys" \
  --set "ro.build.type=userdebug:user" \
  --set "ro.product.build.type=userdebug:user" \
  --set "ro.build.fingerprint=${GOOGLE_FP}:${SAMSUNG_FP}" \
  --set "ro.product.build.fingerprint=${GOOGLE_FP}:${SAMSUNG_FP}" \
  --set "ro.bootimage.build.fingerprint=${GOOGLE_FP}:${SAMSUNG_FP}" \
  --set "ro.product.model=sdk_gphone_x86_64:SM-G991B" \
  --set "ro.product.odm.model=sdk_gphone_x86_64:SM-G991B" \
  --set "ro.product.product.model=sdk_gphone_x86_64:SM-G991B" \
  --set "ro.product.system_ext.model=sdk_gphone_x86_64:SM-G991B" \
  --set "ro.product.vendor.model=sdk_gphone_x86_64:SM-G991B" \
  --set "ro.hardware=ranchu:qcom" \
  --set "ro.boot.hardware=ranchu:qcom" \
  --set "ro.boot.hardware.vulkan=ranchu:qcom" \
  --set "ro.hardware.vulkan=ranchu:qcom" \
  --set "ro.hardware.egl=emulation:Adreno" \
  --set "ro.hardware.audio.primary=goldfish:qcom" \
  --set "ro.ndk_translation.version=0.2.2:" \
  --set "ro.enable.native.bridge.exec=1:0" \
  --set "ro.dalvik.vm.isa.arm64=x86_64:" \
  --set "ro.dalvik.vm.isa.arm=x86:" \
  --set "init.svc_debug_pid.qemu-props=168:" \
  --set "init.svc_debug_pid.goldfish-logcat=360:" \
  || echo "::warning::some prop patches failed (see output)"

adb shell "getprop | grep -iE 'qemu|goldfish|debuggable|tags|fingerprint|model|hardware|ndk_translation|isa' | head -40" \
  | tee work/props-after.txt || true

# ---- device-node hiding (early chmod: app opens fail, system unaffected) ---
adb shell "for d in /dev/qemu_pipe /dev/goldfish_pipe /dev/goldfish_address_space /dev/goldfish_sync /dev/socket/qemud; do chmod 000 \$d 2>/dev/null && echo chmod-000 \$d; done" || true
adb shell "ls -la /dev/qemu_pipe /dev/goldfish_pipe /dev/goldfish_address_space /dev/goldfish_sync /dev/socket/qemud 2>/dev/null" | tee work/qemu-devices.txt || true

# ---- environment evidence --------------------------------------------------
adb shell "getprop | grep -iE 'qemu|debug|secure|tags|fingerprint|model|hardware|abilist' | head -40" \
  | tee work/props-evidence.txt || true
adb shell "cat /system/etc/public.libraries.txt 2>/dev/null" | tee work/public-libraries.txt || true

# ---- install ORIGINAL apk as a 32-bit process -----------------------------
adb install -r -g --abi armeabi-v7a work/packed.apk || true
adb shell "dumpsys package $APP_ID | grep -iE 'primaryCpuAbi|nativeLibraryDir' | head -6" \
  | tee work/abi-info.txt || true

# ---- libstdc++ stub (insurance: libexecmain.so DT_NEEDED libstdc++.so) ----
echo 'int ijiami_stub_marker;' | gcc -shared -nostdlib -m32 \
  -o work/libstdcxx-i386.so -xc - || true
APPDIR=$(adb shell pm path "$APP_ID" 2>/dev/null | head -1 | tr -d '\r' \
  | sed 's/package://' | xargs -r dirname 2>/dev/null)
echo "APPDIR='$APPDIR'"
[ -n "$APPDIR" ] && adb push work/libstdcxx-i386.so "$APPDIR/lib/arm/libstdc++.so" || true

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
# fast resweep: the renamed device nodes give the system ~55s of life
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
echo "== key logcat lines =="
grep -nE "jdwp|s\.h\.e\.l\.l|ijiami|UnsatisfiedLink|FATAL|AndroidRuntime" \
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
