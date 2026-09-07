#!/usr/bin/env bash
# redroid_flow.sh v1 - native-arm64 Android 11 unpack flow (redroid).
#
# WHY REDROID (and not the x86_64 emulator):
#   * Run 34084986538: on the x86_64 google_apis image the iJiami gate
#     PASSED inside the BlackDex sandbox (decrypted app code executed with
#     every qemu signal present), but the sandboxed process then died with
#     SIGSEGV, rip inside the ndk_translation region - the packer's SecLLVM
#     self-modifying native code cannot survive mixed translated/native
#     execution.  GitHub's ubuntu-24.04-arm runner is a REAL aarch64 host:
#     redroid runs Android 11 natively, so the APK's arm64-v8a libexec.so
#     executes on real hardware - no translation, no mixed-mode SIGSEGV.
#   * No qemu anywhere: no /dev/qemu_pipe or goldfish devices, no
#     ro.kernel.qemu / qemu.* / ranchu props - the whole emulator
#     fingerprint surface nodebug_flow.sh had to spoof does not exist.  The
#     remaining google_apis gate suspects (JDWP transport via
#     ro.debuggable=1, userdebug/dev-keys build identity) are closed by
#     patching build.prop BEFORE first boot: ro.debuggable=0, ro.secure=0,
#     user/release-keys Samsung SM-G991B (o1s) identity.
#   * ro.secure=0 keeps adbd running as root - REQUIRED for the
#     /proc/<pid>/mem sweep in external_memdump.py - while
#     ro.debuggable=0 means app processes are not debuggable (no JDWP).
#   * The ORIGINAL, byte-identical packed.apk is installed: per the task-5
#     conclusion (content-integrity gate kills any modified APK), a
#     legitimate native-ARM environment + the original APK is the only
#     viable decrypt vector left.
#
# build.prop patching happens BEFORE first boot: docker create (container
# NOT started) -> docker cp the patched props in -> docker start, so init
# reads the patched values when the property area is first populated.
#
# Env: APP_ID, LAUNCH, EXPECT_DEX (defaults below).  Leaves the container
# RUNNING after the flow so evidence can still be gathered post-hoc.
set -x

APP_ID="${APP_ID:-com.world.youcinemobile}"
LAUNCH="${LAUNCH:-com.mobile.brasiltv.activity.SplashAty}"
EXPECT_DEX="${EXPECT_DEX:-4}"

if [ -n "$ANDROID_HOME" ]; then
  export PATH="$ANDROID_HOME/platform-tools:$PATH"
fi

cd "${GITHUB_WORKSPACE:-$(dirname "$0")/..}"
mkdir -p work dumped/youcine count work/redroid-data

# ---------------------------------------------------------------------------
# 1. host kernel: binder devices (mandatory), ashmem (best effort)
# ---------------------------------------------------------------------------
sudo apt-get update && sudo apt-get install -y "linux-modules-extra-$(uname -r)" || true
sudo modprobe binder_linux devices="binder,hwbinder,vndbinder" || sudo modprobe binder_linux
# Android 11 redroid works with memfd; ashmem is best-effort only.
sudo modprobe ashmem_linux || true
# binderfs fallback for kernels that only register the filesystem
if ! ls /dev/binder* >/dev/null 2>&1; then
  sudo mkdir -p /dev/binderfs
  sudo mount -t binder binder /dev/binderfs || true
fi
echo "== binder devices: $(ls /dev/binder* 2>/dev/null | tr '\n' ' ') =="
if ! ls /dev/binder* >/dev/null 2>&1; then
  echo "::error::no binder devices under /dev/binder* (modprobe binder_linux failed) - redroid cannot run"
  sudo dmesg 2>/dev/null | tail -20 || true
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. patch build.prop BEFORE first boot
#    docker cp works on a created-but-never-started container: the image
#    layers are readable, so we can pull the pristine build.prop files out
#    of a throwaway yc-stage container, patch them, and inject them into
#    the real container's rw layer BEFORE docker start (after start, init
#    has already consumed build.prop).
# ---------------------------------------------------------------------------
docker rm -f youcine-re yc-stage >/dev/null 2>&1 || true

docker create --name yc-stage redroid/redroid:android11-latest
docker cp yc-stage:/system/build.prop work/system-build.prop
if [ ! -s work/system-build.prop ]; then
  echo "::error::could not extract /system/build.prop from the redroid image (docker create/pull or image layout failure)"
  docker rm -f yc-stage >/dev/null 2>&1 || true
  exit 1
fi
VENDOR_PROP=""
if docker cp yc-stage:/vendor/build.prop work/vendor-build.prop 2>/dev/null && [ -s work/vendor-build.prop ]; then
  VENDOR_PROP=work/vendor-build.prop
else
  echo "::notice::redroid image has no /vendor/build.prop - vendor props skipped"
fi
docker rm -f yc-stage >/dev/null 2>&1 || true

# setprop_line <file> <key> <value>: replace an existing key=value line in
# place (sed replaces EVERY matching line, so duplicate entries stay
# consistent), else append it.  '|' is the sed delimiter because the
# fingerprint values contain '/'; values here contain no '|', '&' or '\'
# so the double-quoted expansion is safe.
setprop_line() {
  local file="$1" key="$2" value="$3"
  [ -f "$file" ] || return 0
  sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  grep -q "^${key}=" "$file" || echo "${key}=${value}" >> "$file"
}

SAMSUNG_FP="samsung/o1sxxx/o1s:11/RP1A.200720.012/G991BXXU5CUL5:user/release-keys"

# system build.prop: non-debuggable + non-secure + Samsung release identity
setprop_line work/system-build.prop ro.debuggable 0
setprop_line work/system-build.prop ro.secure 0            # keeps adbd root - REQUIRED for the memdump
setprop_line work/system-build.prop ro.build.type user
setprop_line work/system-build.prop ro.build.tags release-keys
setprop_line work/system-build.prop ro.product.build.tags release-keys
setprop_line work/system-build.prop ro.product.build.type user
setprop_line work/system-build.prop ro.build.fingerprint "$SAMSUNG_FP"
setprop_line work/system-build.prop ro.product.build.fingerprint "$SAMSUNG_FP"
setprop_line work/system-build.prop ro.bootimage.build.fingerprint "$SAMSUNG_FP"
setprop_line work/system-build.prop ro.product.model "SM-G991B"
setprop_line work/system-build.prop ro.product.brand samsung
setprop_line work/system-build.prop ro.product.manufacturer samsung
setprop_line work/system-build.prop ro.product.device o1s
setprop_line work/system-build.prop ro.product.name o1sxxx
setprop_line work/system-build.prop ro.hardware qcom

if [ -n "$VENDOR_PROP" ]; then
  setprop_line "$VENDOR_PROP" ro.product.vendor.model "SM-G991B"
  setprop_line "$VENDOR_PROP" ro.product.vendor.device o1s
  setprop_line "$VENDOR_PROP" ro.product.vendor.brand samsung
  setprop_line "$VENDOR_PROP" ro.vendor.build.fingerprint "$SAMSUNG_FP"
  setprop_line "$VENDOR_PROP" ro.boot.hardware qcom
fi

echo "== patched system build.prop (identity lines) =="
grep -E "^(ro\.(debuggable|secure|build\.|product\.)|ro\.hardware)" work/system-build.prop | head -24 || true
if [ -n "$VENDOR_PROP" ]; then
  echo "== patched vendor build.prop =="
  grep -E "^ro\.(product\.vendor|vendor\.build|boot\.hardware)" "$VENDOR_PROP" || true
fi

# ---------------------------------------------------------------------------
# 3. create the real container, cp the patched props in, THEN start
# ---------------------------------------------------------------------------
docker create --name youcine-re --privileged -p 5555:5555 \
  -v "$PWD/work/redroid-data:/data" redroid/redroid:android11-latest
docker cp work/system-build.prop youcine-re:/system/build.prop
[ -n "$VENDOR_PROP" ] && docker cp "$VENDOR_PROP" youcine-re:/vendor/build.prop
docker start youcine-re || {
  docker logs youcine-re > work/docker-redroid.txt 2>&1 || true
  echo "::error::docker start youcine-re failed"
  exit 1
}

sleep 5
echo "== docker logs (first boot, t=5s) =="
docker logs --tail 20 youcine-re 2>&1 || true

# ---------------------------------------------------------------------------
# 4. wait for adb + full boot
# ---------------------------------------------------------------------------
DEV=localhost:5555
CONNECTED=""
for i in $(seq 1 30); do
  adb connect "$DEV" >/dev/null 2>&1 || true
  ST=$(adb -s "$DEV" get-state 2>/dev/null | tr -d '\r')
  if [ "$ST" = "device" ]; then CONNECTED=1; break; fi
  echo "adb connect attempt $i of 30: state='$ST'"
  docker logs --tail 4 youcine-re 2>&1 || true
  sleep 5
done
if [ -z "$CONNECTED" ]; then
  docker logs youcine-re > work/docker-redroid.txt 2>&1 || true
  echo "::error::adb never reached $DEV within 150s - redroid container did not come up"
  exit 1
fi

BOOTED=""
for i in $(seq 1 84); do  # 84 x 5s = 420s
  B=$(adb -s "$DEV" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
  if [ "$B" = "1" ]; then BOOTED=1; break; fi
  if [ $((i % 6)) -eq 0 ]; then
    echo "== boot wait $((i * 5))s: sys.boot_completed='$B' =="
    docker logs --tail 6 youcine-re 2>&1 || true
  fi
  sleep 5
done
if [ -z "$BOOTED" ]; then
  adb -s "$DEV" logcat -d -b main,system,crash > work/logcat-redroid.txt 2>&1 || true
  docker logs youcine-re > work/docker-redroid.txt 2>&1 || true
  echo "::error::Android did not finish booting within 420s (sys.boot_completed != 1)"
  exit 1
fi

sleep 10
echo "== environment evidence (patched build.prop now live) =="
echo "ro.debuggable         = $(adb -s "$DEV" shell getprop ro.debuggable 2>/dev/null | tr -d '\r')"
echo "ro.secure             = $(adb -s "$DEV" shell getprop ro.secure 2>/dev/null | tr -d '\r')"
echo "ro.build.fingerprint  = $(adb -s "$DEV" shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r')"
echo "ro.product.model      = $(adb -s "$DEV" shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
echo "ro.product.cpu.abilist = $(adb -s "$DEV" shell getprop ro.product.cpu.abilist 2>/dev/null | tr -d '\r')"
adb -s "$DEV" shell "getprop | grep -iE 'qemu|goldfish|ranchu|debuggable|secure|fingerprint|model|hardware|abilist|tags|build.type' | head -40" \
  | tee work/props-redroid.txt || true

# adbd must be root for the /proc/<pid>/mem sweep (ro.secure=0 should do it)
ID=$(adb -s "$DEV" shell id 2>/dev/null | tr -d '\r')
echo "adb shell id: $ID"
if ! echo "$ID" | grep -q "uid=0"; then
  echo "::warning::adbd not root yet; trying adb root + reconnect"
  adb -s "$DEV" root >/dev/null 2>&1 || true
  sleep 3
  adb disconnect >/dev/null 2>&1 || true
  adb connect "$DEV" >/dev/null 2>&1 || true
  sleep 2
  ID=$(adb -s "$DEV" shell id 2>/dev/null | tr -d '\r')
  echo "adb shell id (after adb root + reconnect): $ID"
fi
echo "$ID" | grep -q "uid=0" || echo "::warning::adb is NOT root - /proc/<pid>/mem sweep will likely fail"
adb -s "$DEV" shell setenforce 0 >/dev/null 2>&1 || true
echo "SELinux: $(adb -s "$DEV" shell getenforce 2>/dev/null | tr -d '\r')"

# ---------------------------------------------------------------------------
# 5. install the ORIGINAL packed apk (byte-identical: no tamper trip)
#    multi-ABI APK: its arm64-v8a libs make it install as native arm64
# ---------------------------------------------------------------------------
adb -s "$DEV" install -r -g work/packed.apk || {
  echo "::warning::first install failed - reconnecting and retrying once"
  adb disconnect >/dev/null 2>&1 || true
  sleep 3
  adb connect "$DEV" >/dev/null 2>&1 || true
  sleep 2
  adb -s "$DEV" install -r -g work/packed.apk || \
    echo "::warning::install retry failed too - continuing to launch/evidence anyway"
}
adb -s "$DEV" shell pm path "$APP_ID" | tee work/pm-path-redroid.txt || true
adb -s "$DEV" shell "dumpsys package $APP_ID | grep -iE 'primaryCpuAbi|nativeLibraryDir' | head -6" \
  | tee work/abi-info-redroid.txt || true

# ---------------------------------------------------------------------------
# 6. launch (retries: Broken pipe / system not ready)
# ---------------------------------------------------------------------------
adb -s "$DEV" logcat -c >/dev/null 2>&1 || true
adb -s "$DEV" shell "setprop debug.ld.app.$APP_ID dlopen" || true
for i in 1 2 3; do
  echo "== am start attempt $i =="
  adb -s "$DEV" shell am start -W -n "$APP_ID/$LAUNCH" 2>&1 | head -24 | tee -a work/am-start-redroid.txt || true
  sleep 10
  P=$(adb -s "$DEV" shell pidof "$APP_ID" 2>/dev/null | tr -d '\r')
  [ -n "$P" ] && break
done
sleep 15
P=$(adb -s "$DEV" shell pidof "$APP_ID" 2>/dev/null | tr -d '\r')
echo "pidof $APP_ID after launch + 15s: '$P'"

# ---------------------------------------------------------------------------
# 7. memory dump - the critical handoff to external_memdump.py
#    Device selection VERIFIED against the code: external_memdump.py uses
#      line 44:  ADB = os.environ.get("ADB", "adb")
#      line 106: subprocess.run([ADB, *args], ...)   (also 111/157/232)
#    i.e. ADB is a SINGLE argv[0] element, so ADB="adb -s localhost:5555"
#    would try to exec a binary literally named "adb -s localhost:5555"
#    (FileNotFoundError even with check=False).  adb honors ANDROID_SERIAL
#    natively for every invocation (including wait-for-device at line 270),
#    so that is the correct mechanism here.
# ---------------------------------------------------------------------------
export ADB="adb"
export ANDROID_SERIAL="$DEV"
python3 unpack/external_memdump.py \
  --app "$APP_ID" \
  --out-dir dumped/youcine \
  --expect "$EXPECT_DEX" \
  --timeout 300 \
  --settle 1.0 \
  --resweep-gap 12 \
  --pull-app-data || true

# ---------------------------------------------------------------------------
# 8. evidence capture (ALWAYS - even on failure)
# ---------------------------------------------------------------------------
adb -s "$DEV" logcat -d -b main,system,crash > work/logcat-redroid.txt 2>&1 || true
docker logs youcine-re > work/docker-redroid.txt 2>&1 || true
echo "== key logcat lines (jdwp presence is the debuggable indicator) =="
grep -nE "jdwp|s\.h\.e\.l\.l|ijiami|UnsatisfiedLink|FATAL|AndroidRuntime|Fatal signal" \
  work/logcat-redroid.txt | head -40 || true
adb -s "$DEV" shell "ps -A | grep -i youcine" | tee work/ps-after-redroid.txt || true
PID=$(adb -s "$DEV" shell pidof "$APP_ID" 2>/dev/null | tr -d '\r')
if [ -n "$PID" ]; then
  adb -s "$DEV" shell "cat /proc/$PID/maps" 2>/dev/null \
    | grep -E "libexec|ijm|dex|art" | head -24 > work/maps-app-redroid.txt || true
fi
docker exec youcine-re dmesg 2>/dev/null \
  | grep -iE "dlopen|linker|sigsegv|libexec" | head -60 > work/dmesg-redroid.txt || true
# the container may not ship the dmesg binary -> host fallback (binder/ashmem health)
if [ ! -s work/dmesg-redroid.txt ]; then
  sudo dmesg 2>/dev/null | grep -iE "binder|ashmem" | head -30 > work/dmesg-host.txt || true
fi

# ---------------------------------------------------------------------------
# 9. count DEX exactly like nodebug_flow.sh (min-size filter drops the
#    13.6 KB packer stub dex; real dexes are ~10 MB)
# ---------------------------------------------------------------------------
ls -la dumped/youcine || true
n=0
for f in dumped/youcine/dex_*.bin; do
  [ -f "$f" ] || continue
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  [ "$sz" -ge 65536 ] && n=$((n+1))
done
mkdir -p count && echo "$n" > count/dex_count
echo "dex_count=$n"

# ---------------------------------------------------------------------------
# 10. summary (container left RUNNING for post-hoc inspection)
# ---------------------------------------------------------------------------
echo "==============================================================="
echo " redroid_flow.sh summary"
echo "   image     : redroid/redroid:android11-latest (native arm64)"
echo "   container : youcine-re -> $(docker ps --filter name=youcine-re --format '{{.Status}}' 2>/dev/null || echo 'not running')"
echo "   binder    : $(ls /dev/binder* 2>/dev/null | tr '\n' ' ')"
echo "   dex_count : $n  (unique DEX >= 64 KiB in dumped/youcine)"
echo "   raw dumps : $(ls dumped/youcine/dex_*.bin 2>/dev/null | wc -l) file(s)"
echo "   evidence  : work/logcat-redroid.txt work/docker-redroid.txt work/props-redroid.txt"
echo "               work/abi-info-redroid.txt work/ps-after-redroid.txt work/maps-app-redroid.txt"
echo "               work/dmesg-redroid.txt work/dmesg-host.txt work/am-start-redroid.txt"
echo "==============================================================="
exit 0
