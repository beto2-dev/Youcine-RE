#!/usr/bin/env bash
# nodebug_flow.sh - ORIGINAL apk on a NON-DEBUGGABLE google_apis emulator (root kept).
#
# Run evidence (34044920876 / 34048953559 / 34049784110): on the stock
# google_apis image every app runs debuggable - logcat shows
#   "adbd: jdwp connection from <pid>" ~90 ms before s.h.e.l.l.N.al
#   refuses to register (No implementation found -> UnsatisfiedLinkError).
# The packer loads libexec.so + libexecmain.so with ZERO linker errors,
# so the silent RegisterNatives skip is an ENVIRONMENT gate, not a load
# failure. The emulator is booted with `-prop ro.debuggable=0 -prop
# ro.secure=0` (boot-time props win over build.prop), which is the one
# variable never tested: apps run non-debuggable (no JDWP) while adbd
# stays root (ro.secure=0) for the out-of-process /proc/<pid>/mem sweep.
#
# ABI: install with --abi armeabi-v7a so the app process is 32-bit and the
# stub extracts ijm_lib/x86 (NATIVE x86 SecLLVM, no binary translation) -
# proven by run 34048953559 (extracted md5 0e33dcf007 == ijm_lib/x86).
#
# No ptrace, no frida, no dump-build: the APK on disk is byte-identical to
# the released one, so the iJiami content-integrity / signature gates pass.
set -x

export PATH="$ANDROID_HOME/platform-tools:$PATH"
cd "${GITHUB_WORKSPACE:-$(dirname "$0")/..}"
mkdir -p work dumped/youcine count

DBG=$(adb shell getprop ro.debuggable 2>/dev/null | tr -d '\r')
SEC=$(adb shell getprop ro.secure 2>/dev/null | tr -d '\r')
echo "boot props: ro.debuggable='$DBG' ro.secure='$SEC'"

# ---- fallback: if -prop did not win, patch build.prop and reboot ----------
if [ "$DBG" != "0" ]; then
  echo "== -prop did not take effect; patching build.prop in-place =="
  adb root || true
  sleep 8
  adb remount || true
  adb shell "mount -o remount,rw /system 2>/dev/null" || true
  adb shell "grep -nE 'ro\.(debuggable|secure)' /system/build.prop" || true
  adb shell "cat /default.prop 2>/dev/null | grep -nE 'ro\.(debuggable|secure)' || echo NO_DEFAULT_PROP" || true
  adb shell "sed -i 's/^ro\.debuggable=.*/ro.debuggable=0/; s/^ro\.secure=.*/ro.secure=0/' /system/build.prop" || true
  adb shell "grep -nE 'ro\.(debuggable|secure)' /system/build.prop" || true
  adb reboot || true
  adb wait-for-device || true
  for i in $(seq 1 90); do
    v=$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
    [ "$v" = "1" ] && break
    sleep 5
  done
  sleep 10
  DBG=$(adb shell getprop ro.debuggable 2>/dev/null | tr -d '\r')
  echo "after reboot: ro.debuggable='$DBG'"
fi

adb root || true
sleep 5
echo "adb identity: $(adb shell id 2>/dev/null | tr -d '\r' | head -1)"
echo "SELinux: $(adb shell getenforce 2>/dev/null | tr -d '\r')"

# ---- environment evidence (anti-analysis documentation material) ----------
adb shell "getprop | grep -iE 'qemu|debug|secure|tags|fingerprint|model|hardware|abilist'" \
  | tee work/props-evidence.txt || true
adb shell "cat /system/etc/public.libraries.txt 2>/dev/null" | tee work/public-libraries.txt || true
adb shell "cat /default.prop 2>/dev/null" | tee work/default-prop.txt || true

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
[ -n "$APPDIR" ] && adb shell "ls -la $APPDIR/lib/ 2>/dev/null" || true

# ---- bionic per-dlopen kernel logging (definitive load evidence) ----------
adb shell "setprop debug.ld.app.$APP_ID dlopen" || true
adb shell "dmesg -c > /dev/null 2>&1" || true
adb logcat -c || true

# ---- launch ---------------------------------------------------------------
echo "== launching $APP_ID/$LAUNCH =="
adb shell am start -W -n "$APP_ID/$LAUNCH" 2>&1 | head -24 || true
sleep 15
PID=$(adb shell pidof "$APP_ID" 2>/dev/null | tr -d '\r')
echo "pid after 15s: '$PID'"

# ---- out-of-process poll -> SIGSTOP freeze -> /proc/<pid>/mem sweep -------
# (SIGSTOP does not set TracerPid; the sweep reads raw memory - it works on
#  native and translated processes alike)
python3 unpack/external_memdump.py \
  --app "$APP_ID" \
  --out-dir dumped/youcine \
  --expect "$EXPECT_DEX" \
  --timeout 300 \
  --settle 1.0 \
  --resweep-gap 45 \
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
  adb shell "cat /proc/$PID/maps 2>/dev/null | grep -E 'libexec|ijm|stdc|dex' | head -24" \
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
