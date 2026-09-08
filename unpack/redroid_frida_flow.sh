#!/usr/bin/env bash
# redroid_frida_flow.sh v1 - PHASE 2 frida capture flow (redroid, arm64).
#
# WHY PHASE-2 FRIDA NEEDS THIS FLOW:
#   redroid_flow.sh (run 34133100459) UNPACKS: it boots a native-arm64
#   Android 11 redroid, launches the ORIGINAL byte-identical APK and sweeps
#   ART's [anon:dalvik-DEX data] containers out of /proc/<pid>/mem.  That
#   yields the 5 static dexes but NOT the ~45k extraction-stub bodies that
#   libexec only materializes when a class is loaded, and NOT the
#   805-method RegisterNatives table - so the rebuild dies at the first
#   VMP method (SqlHelper.getDb).  This flow INSTRUMENTS the same proven
#   environment: frida spawn-gates the ORIGINAL APK, captures the
#   RegisterNatives table, warm-loads every class, then re-dumps
#   (docs/en/06-dynamic-unpack.md - "Phase 2").  The environment blocks
#   (kernel binder, build.prop patch-before-first-boot, adbd root, runtime
#   verify-and-fix) are copied verbatim from redroid_flow.sh; only the
#   frida-server bring-up and the phase-2 driver invocation are new.
#
# ANTI-FRIDA (iJiami fingerprints frida):
#   * frida-server is pushed under a RANDOMIZED binary name - the packer's
#     native code scans for the default 'frida-server' name.
#   * it listens on 127.0.0.1:${FRIDA_PORT} (default 47890), NOT the
#     default port 27042; the host reaches it through
#     `adb forward tcp:4789 tcp:${FRIDA_PORT}` so the DRIVER contract
#     endpoint stays fixed at FRIDA_REMOTE=127.0.0.1:4789.
#   * the python frida package version MUST match the frida-server version
#     (FRIDA_VERSION, default 16.6.6) or the protocol handshake fails.
#
# INTERFACE CONTRACT with unpack/frida_phase2_driver.py (agent 2-a):
#   ANDROID_SERIAL=localhost:5555 APP_ID=com.world.youcinemobile \
#   FRIDA_REMOTE=127.0.0.1:4789 DEX_DIR=work/dumps-dex OUT_DIR=work/phase2 \
#   python3 unpack/frida_phase2_driver.py
#   The driver SPAWNS the app itself via frida (spawn-gating) - this flow
#   must NEVER `am start` the app first, or the packer's native loader runs
#   uninstrumented and the death ladder kills the process before the hooks
#   install.  The driver installs nothing: frida-server is RUNNING and the
#   ORIGINAL byte-identical APK is INSTALLED before it is invoked.
#
# Env: APP_ID, REDROID_IMAGE, FRIDA_VERSION, FRIDA_PORT, EXPECT_MIN_RN,
#      APK_SOURCE (release|url), SAMPLE_URL (when APK_SOURCE=url).
# Leaves the container RUNNING after the flow so evidence can still be
# gathered post-hoc.
set -x

APP_ID="${APP_ID:-com.world.youcinemobile}"
REDROID_IMAGE="${REDROID_IMAGE:-redroid/redroid:11.0.0-latest}"
FRIDA_VERSION="${FRIDA_VERSION:-16.6.6}"
FRIDA_PORT="${FRIDA_PORT:-47890}"
EXPECT_MIN_RN="${EXPECT_MIN_RN:-1}"

if [ -n "$ANDROID_HOME" ]; then
  export PATH="$ANDROID_HOME/platform-tools:$PATH"
fi

cd "${GITHUB_WORKSPACE:-$(dirname "$0")/..}"
mkdir -p work work/redroid-data work/dumps-dex

# ---------------------------------------------------------------------------
# 1. host kernel: binder devices (mandatory), ashmem (best effort)
#    (adb/xz are host deps too - Ubuntu's adb is native arm64, Google's
#    platform-tools zip is x86_64-only; xz decompresses frida-server)
# ---------------------------------------------------------------------------
command -v adb >/dev/null 2>&1 || sudo apt-get install -y adb || true
command -v xz >/dev/null 2>&1 || sudo apt-get install -y xz-utils || true
command -v adb >/dev/null 2>&1 || {
  echo "::error::adb not found on the host (sudo apt-get install adb)"
  exit 1
}
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
docker rm -f youcine-fr yc-stage >/dev/null 2>&1 || true

# redroid image tag (run 34119615160: 'android11-latest' does not exist on
# Docker Hub - the Android 11 tag is '11.0.0-latest'). Make it overridable
# and pre-verify the manifest so a tag/registry hiccup fails fast and loud.
docker manifest inspect "$REDROID_IMAGE" > /dev/null 2>&1 || {
  echo "::error::manifest for $REDROID_IMAGE not found - check the tag on Docker Hub"
  exit 1
}

docker create --name yc-stage "$REDROID_IMAGE" || {
  echo "::error::docker create yc-stage failed (image pull?)"
  exit 1
}
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

# replace_line <file> <key> <value>: ONLY replaces a key that already
# exists.  NEVER appends.  Run 34121251995 post-mortem: the pristine control
# container boots fine but the docker-cp'd one died BEFORE any console
# output - init aborts while loading build.prop. The original redroid props
# are PARTITION-SCOPED (ro.product.system.*, ro.product.vendor.*) and
# appending plain ro.product.model / ro.hardware / ro.bootimage.* to
# system/build.prop or ro.boot.* to vendor/build.prop violates init's
# property-context loader (ro.boot.* is cmdline-context only; plain
# ro.product.* is an alias auto-set by the property service). Identity
# stragglers are fixed at RUNTIME by the verify-and-fix block (property-area
# patch + framework restart - no init parse risk, the technique proven on
# the emulator path since v3).
replace_line() {
  local file="$1" key="$2" value="$3"
  [ -f "$file" ] || return 0
  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "::warning::replace_line: $key absent from $file - left for the runtime patcher"
  fi
}

SAMSUNG_FP="samsung/o1sxxx/o1s:11/RP1A.200720.012/G991BXXU5CUL5:user/release-keys"

# system build.prop: REPLACE-ONLY (every key below exists in the original)
replace_line work/system-build.prop ro.debuggable 0
replace_line work/system-build.prop ro.secure 0            # keeps adbd root - REQUIRED for frida-server + the dump pulls
replace_line work/system-build.prop ro.build.type user
replace_line work/system-build.prop ro.build.tags release-keys
replace_line work/system-build.prop ro.build.fingerprint "$SAMSUNG_FP"
replace_line work/system-build.prop ro.build.display.id "o1sxxx-user 11 RP1A.200720.012 G991BXXU5CUL5 release-keys"
replace_line work/system-build.prop ro.build.description "o1sxxx-user 11 RP1A.200720.012 G991BXXU5CUL5 release-keys"
# partition-scoped identity (these are the keys the image actually defines)
replace_line work/system-build.prop ro.product.system.model "SM-G991B"
replace_line work/system-build.prop ro.product.system.brand samsung
replace_line work/system-build.prop ro.product.system.manufacturer samsung
replace_line work/system-build.prop ro.product.system.device o1s
replace_line work/system-build.prop ro.product.system.name o1sxxx

if [ -n "$VENDOR_PROP" ]; then
  # replace-only as well: NO ro.boot.* (cmdline context), NO appends
  replace_line "$VENDOR_PROP" ro.product.vendor.model "SM-G991B"
  replace_line "$VENDOR_PROP" ro.product.vendor.device o1s
  replace_line "$VENDOR_PROP" ro.product.vendor.brand samsung
  replace_line "$VENDOR_PROP" ro.vendor.build.fingerprint "$SAMSUNG_FP"
  replace_line "$VENDOR_PROP" ro.vendor.build.tags release-keys
  replace_line "$VENDOR_PROP" ro.vendor.build.type user
fi

echo "== patched system build.prop (identity lines) =="
grep -E "^(ro\.(debuggable|secure|build\.|product\.)|ro\.hardware)" work/system-build.prop | head -24 || true
if [ -n "$VENDOR_PROP" ]; then
  echo "== patched vendor build.prop =="
  grep -E "^ro\.(product\.vendor|vendor\.build|boot\.hardware)" "$VENDOR_PROP" || true
fi

# main container: docker create -> cp patched props in -> docker start
# (--tty so init's /dev/console output lands in docker logs)
# Port 5555 published on the LOOPBACK only; the data volume mirrors
# redroid_flow.sh (root-owned - never uploaded as an artifact).
CNAME="youcine-fr"
docker create --tty --name "$CNAME" --privileged \
  --security-opt apparmor=unconfined \
  -p 127.0.0.1:5555:5555 -v "$PWD/work/redroid-data:/data" "$REDROID_IMAGE" || {
  echo "::error::docker create $CNAME failed"
  exit 1
}
docker cp work/system-build.prop "$CNAME:/system/build.prop"
[ -n "$VENDOR_PROP" ] && docker cp "$VENDOR_PROP" "$CNAME:/vendor/build.prop"
docker start "$CNAME" || {
  docker logs "$CNAME" > work/docker-phase2.txt 2>&1 || true
  echo "::error::docker start $CNAME failed"
  exit 1
}

sleep 5
echo "== docker logs (first boot, t=5s; --tty so console output is visible) =="
docker logs --tail 20 "$CNAME" 2>&1 || true

# ---------------------------------------------------------------------------
# 3. wait for adb, ESTABLISH adbd ROOT, wait for full boot
#    (R32 lesson, redroid_flow.sh 5a: adbd root FIRST - the runtime prop
#    patch, the framework restart, frida-server and the driver's adb pulls
#    ALL need root. ro.secure=0 in the patched build.prop should already
#    give a root adbd; verify and escalate if not.)
# ---------------------------------------------------------------------------
DEV=localhost:5555
CONNECTED=""
for i in $(seq 1 60); do  # 60 x 5s = 300s: first boot formats /data
  adb connect "$DEV" >/dev/null 2>&1 || true
  ST=$(adb -s "$DEV" get-state 2>/dev/null | tr -d '\r')
  if [ "$ST" = "device" ]; then CONNECTED=1; break; fi
  if [ $((i % 6)) -eq 0 ]; then
    echo "adb connect attempt $i of 60: state='$ST'"
    docker inspect --format "main: status={{.State.Status}} exit={{.State.ExitCode}}" "$CNAME" 2>/dev/null || true
    docker logs --tail 6 "$CNAME" 2>&1 || true
  fi
  sleep 5
done
if [ -z "$CONNECTED" ]; then
  docker logs "$CNAME" > work/docker-phase2.txt 2>&1 || true
  docker inspect --format "main final: status={{.State.Status}} exit={{.State.ExitCode}} err={{.State.Error}}" "$CNAME" 2>/dev/null || true
  echo "::error::patched (docker-cp build.prop) container never became adb-reachable within 300s - see work/docker-phase2.txt"
  exit 1
fi

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
echo "$ID" | grep -q "uid=0" || echo "::warning::adb is NOT root - property patch, frida-server and the driver's adb pulls will fail"

BOOTED=""
for i in $(seq 1 60); do  # 60 x 5s = 300s
  adb connect "$DEV" >/dev/null 2>&1 || true
  B=$(adb -s "$DEV" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
  if [ "$B" = "1" ]; then BOOTED=1; break; fi
  if [ $((i % 6)) -eq 0 ]; then
    echo "== boot wait $((i * 5))s: sys.boot_completed='$B' =="
    docker logs --tail 6 "$CNAME" 2>&1 || true
  fi
  sleep 5
done
if [ -z "$BOOTED" ]; then
  adb -s "$DEV" logcat -d -b main,system,crash > work/logcat-phase2.txt 2>&1 || true
  docker logs "$CNAME" > work/docker-phase2.txt 2>&1 || true
  echo "== last logcat lines (boot timeout) =="
  tail -40 work/logcat-phase2.txt || true
  echo "::error::Android did not finish booting within 300s (sys.boot_completed != 1)"
  exit 1
fi

sleep 10
echo "== environment evidence =="
echo "ro.debuggable         = $(adb -s "$DEV" shell getprop ro.debuggable 2>/dev/null | tr -d '\r')"
echo "ro.secure             = $(adb -s "$DEV" shell getprop ro.secure 2>/dev/null | tr -d '\r')"
echo "ro.build.fingerprint  = $(adb -s "$DEV" shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r')"
echo "ro.product.model      = $(adb -s "$DEV" shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
echo "ro.product.cpu.abilist = $(adb -s "$DEV" shell getprop ro.product.cpu.abilist 2>/dev/null | tr -d '\r')"
adb -s "$DEV" shell "getprop | grep -iE 'qemu|goldfish|ranchu|redroid|debuggable|secure|fingerprint|model|hardware|abilist|tags|build.type' | head -50" \
  | tee work/props-phase2.txt || true

# ---------------------------------------------------------------------------
# 4. runtime property verify-and-fix + framework restart ONLY if needed
#    (minimal mirror of redroid_flow.sh's verify-and-fix block: build.prop
#    was patched before first boot, so usually nothing to do; stragglers
#    like ro.boot.hardware=redroid / alias props land here.  ro.secure is
#    NOT touched - adbd is already root and a framework restart must never
#    disturb that.)
# ---------------------------------------------------------------------------
SET_ARGS=()
rd_cur() { adb -s "$DEV" shell getprop "$1" 2>/dev/null | tr -d '\r'; }
fix_prop() {  # name desired
  local cur desired
  cur=$(rd_cur "$1"); desired="$2"
  [ -z "$cur" ] && return 0          # prop absent: nothing to patch
  [ "$cur" = "$desired" ] && return 0  # already correct
  SET_ARGS+=(--set "$1=$cur|$desired")
}
fix_prop ro.debuggable 0
fix_prop ro.build.type user
fix_prop ro.build.tags release-keys
fix_prop ro.build.fingerprint "$SAMSUNG_FP"
fix_prop ro.product.model "SM-G991B"
fix_prop ro.product.brand samsung
fix_prop ro.product.device o1s
fix_prop ro.product.manufacturer samsung
fix_prop ro.product.vendor.model "SM-G991B"
fix_prop ro.hardware qcom
fix_prop ro.boot.hardware qcom
fix_prop ro.kernel.qemu 0
if [ ${#SET_ARGS[@]} -gt 0 ]; then
  echo "== runtime property-area patch needed ($((${#SET_ARGS[@]} / 2)) specs) =="
  ANDROID_SERIAL="$DEV" python3 unpack/patch_props.py "${SET_ARGS[@]}" \
    || echo "::warning::some runtime prop patches failed"
  # framework restart so system_server/AMS re-reads ro.debuggable etc.
  adb -s "$DEV" shell stop || true
  sleep 5
  adb -s "$DEV" shell start || true
  RDY=""
  for i in $(seq 1 60); do
    PKG=$(adb -s "$DEV" shell service check package 2>/dev/null | tr -d '\r')
    ACT=$(adb -s "$DEV" shell service check activity 2>/dev/null | tr -d '\r')
    echo "$PKG" | grep -q found && echo "$ACT" | grep -q found && RDY=1 && break
    sleep 3
  done
  echo "framework restarted: ready=$RDY ro.debuggable=$(rd_cur ro.debuggable) ro.build.tags=$(rd_cur ro.build.tags) ro.product.model=$(rd_cur ro.product.model)"
  [ -n "$RDY" ] || echo "::warning::framework not fully ready after restart; proceeding"
  # wait for package manager to re-register fully (APK install needs it)
  for i in $(seq 1 20); do
    adb -s "$DEV" shell pm path com.android.shell >/dev/null 2>&1 && break
    sleep 3
  done
  # refresh evidence after the fix
  adb -s "$DEV" shell "getprop | grep -iE 'qemu|goldfish|ranchu|redroid|debuggable|secure|fingerprint|model|hardware|abilist|tags|build.type' | head -50" \
    | tee work/props-phase2-after.txt || true
else
  echo "== build.prop patch took effect: no runtime patching needed =="
fi

# framework restart can disturb the adb tcp connection - re-establish
adb disconnect >/dev/null 2>&1 || true
sleep 2
adb connect "$DEV" >/dev/null 2>&1 || true
sleep 2
adb -s "$DEV" shell setenforce 0 >/dev/null 2>&1 || true
echo "SELinux: $(adb -s "$DEV" shell getenforce 2>/dev/null | tr -d '\r')"
echo "adb identity after restart: $(adb -s "$DEV" shell id 2>/dev/null | tr -d '\r' | head -1)"
# cheap prophylactic for any meta-reflection in the warm-up sweep (same fix
# as the BlackDex hidden-API unseal problem, run 34125551716); frida's own
# Java bridge bypasses the policy natively, so this is harmless either way.
adb -s "$DEV" shell settings put global hidden_api_policy 1 >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 5. frida-server: randomized name, non-standard loopback port
#    (iJiami fingerprints BOTH the default 'frida-server' binary name and
#    the default port 27042 - so neither is used)
# ---------------------------------------------------------------------------
FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz"
curl -fL --retry 3 -o work/fs.xz "$FRIDA_URL" || {
  echo "::error::download failed: $FRIDA_URL"
  exit 1
}
xz -d -f work/fs.xz || {
  echo "::error::xz -d work/fs.xz failed (xz-utils missing on the host?)"
  exit 1
}
# STEALTH PATCH (run 34172614416 post-mortem): iJiami's SecLLVM VMP reads
# /proc/self/maps and kills itself with RAW SVC syscalls that bypass every
# libc-level hook (09_hide_frida.js only covers libc).  The same-length
# byte swaps below rename the agent memfd (frida-agent-<arch>.so ->
# media-agent-<arch>.so), the helper process names and the agent thread
# names (gum-js-loop/gmain/gdbus) AT THE SOURCE, so even a raw maps scan
# finds no frida signature.  || true: a patcher failure degrades to the
# stock binary and the capture continues.
if [ -f tools/stealth_frida_server.py ]; then
  python3 tools/stealth_frida_server.py work/fs --deep > work/stealth-server.log 2>&1 \
    || echo "::warning::stealth patch failed - using the stock frida-server"
  tail -4 work/stealth-server.log || true
else
  echo "::warning::tools/stealth_frida_server.py missing - stock frida-server"
fi
chmod 755 work/fs
ls -l work/fs || true
# randomized on-device name (iJiami scans /proc/*/cmdline + maps for the
# default 'frida-server' name): 'mon.' + 8 hex chars of entropy
SV_NAME="mon.$(head -c4 /dev/urandom | od -An -tx4 | tr -d ' \n')"
SV_PATH="/data/local/tmp/${SV_NAME}"
adb -s "$DEV" push work/fs "$SV_PATH" || {
  echo "::error::adb push frida-server -> $SV_PATH failed"
  exit 1
}
adb -s "$DEV" shell "chmod 755 $SV_PATH" || true
# start_sv <prefix>: background the server with output redirected so the
# adb shell returns immediately; 'setsid' additionally detaches it from the
# shell session (proven pattern, frida-trace.yml) - the plain form is the
# spec fallback if the image's toybox lacks setsid.
start_sv() {
  adb -s "$DEV" shell "${1}${SV_PATH} -l 127.0.0.1:${FRIDA_PORT} > /data/local/tmp/sv.log 2>&1 &" || true
}
# -l 127.0.0.1:${FRIDA_PORT}: NOT the default port 27042 (iJiami port scan)
start_sv "setsid "
sleep 2
SV_PID="$(adb -s "$DEV" shell pidof "$SV_NAME" 2>/dev/null | tr -d '\r' | awk '{print $1}')"
if [ -z "$SV_PID" ]; then
  echo "::warning::frida-server ($SV_NAME) not alive after first start - log so far:"
  adb -s "$DEV" shell "cat /data/local/tmp/sv.log 2>/dev/null" || true
  adb -s "$DEV" shell "kill -9 \$(pidof $SV_NAME) 2>/dev/null" || true
  sleep 1
  start_sv ""
  sleep 3
  SV_PID="$(adb -s "$DEV" shell pidof "$SV_NAME" 2>/dev/null | tr -d '\r' | awk '{print $1}')"
fi
if [ -z "$SV_PID" ]; then
  echo "== /data/local/tmp/sv.log (both attempts) =="
  adb -s "$DEV" shell "cat /data/local/tmp/sv.log 2>/dev/null" || true
  echo "::error::frida-server failed to stay alive (see sv.log above: arch mismatch / SELinux / port busy)"
  exit 1
fi
echo "frida-server alive: name=$SV_NAME pid=$SV_PID listen=127.0.0.1:${FRIDA_PORT}"
# host-side tunnel for the DRIVER contract endpoint (fixed at 4789)
adb -s "$DEV" forward tcp:4789 tcp:"${FRIDA_PORT}" || {
  echo "::error::adb forward tcp:4789 tcp:${FRIDA_PORT} failed"
  exit 1
}
adb -s "$DEV" forward --list | tee work/adb-forwards.txt || true

# ---------------------------------------------------------------------------
# 6. python frida client - the version MUST match frida-server
# ---------------------------------------------------------------------------
pip3 install --quiet "frida==${FRIDA_VERSION}" > work/pip-frida.log 2>&1 || {
  cat work/pip-frida.log || true
  echo "::error::pip3 install frida==${FRIDA_VERSION} failed (aarch64 wheel missing for this version?)"
  exit 1
}
python3 -c "import frida; print('frida python client:', frida.__version__)" || {
  cat work/pip-frida.log || true
  echo "::error::python 'import frida' failed after pip install - see work/pip-frida.log"
  exit 1
}
# STEALTH the python client too: the client shares the wire-protocol
# strings ('/re/frida/...', 're.frida...', the 'frida:rpc' shim it injects
# with every script) with the server and the agent - all three sides must
# be renamed IDENTICALLY or the protocol breaks.  Symbol sections
# (PyInit__frida etc.) are protected by the patcher itself.
FRIDA_CLIENT_SO="$(python3 - <<'PY'
import frida, pathlib
so = list(pathlib.Path(frida.__file__).parent.glob("_frida*.so"))
print(so[0] if so else "")
PY
)"
if [ -n "$FRIDA_CLIENT_SO" ] && [ -f "$FRIDA_CLIENT_SO" ] && [ -f tools/stealth_frida_server.py ]; then
  python3 tools/stealth_frida_server.py "$FRIDA_CLIENT_SO" --deep >> work/stealth-client.log 2>&1 \
    || echo "::warning::client stealth patch failed - see work/stealth-client.log"
  python3 -c "import frida; print('client re-import after stealth patch: OK', frida.__version__)" \
    || { echo "::error::frida client broken by the stealth patch - see work/stealth-client.log"; exit 1; }
else
  echo "::warning::could not locate the frida client .so - skipping its stealth patch"
fi
# reachability probe: enumerate_processes actually round-trips to the server
python3 - <<'PY' 2>/dev/null || echo "::warning::frida remote 127.0.0.1:4789 not reachable - check work/adb-forwards.txt and /data/local/tmp/sv.log; the driver will fail"
import frida

mgr = frida.get_device_manager()
device = mgr.add_remote_device("127.0.0.1:4789")
procs = device.enumerate_processes()
print("[*] frida remote endpoint OK:", device, "(%d processes visible)" % len(procs))
PY

# ---------------------------------------------------------------------------
# 7. immutable sources: ORIGINAL packed apk + phase-1 dump dexes
#    (gh is available in Actions; locally `gh` needs GH_TOKEN with your PAT)
# ---------------------------------------------------------------------------
REPO_SLUG="${GITHUB_REPOSITORY:-beto2-dev/Youcine-RE}"
if [ "${APK_SOURCE:-release}" = "release" ]; then
  gh release download packed-1.17.6 -R "$REPO_SLUG" -p ycMob_1.17.6_ycsite.apk -O work/packed.apk || {
    echo "::error::gh release download packed-1.17.6 failed (private release? export GH_TOKEN with your PAT when running locally)"
    exit 1
  }
else
  curl -fL --retry 3 -o work/packed.apk "${SAMPLE_URL:?APK_SOURCE != release requires SAMPLE_URL}" || {
    echo "::error::curl SAMPLE_URL failed"
    exit 1
  }
fi
sha256sum work/packed.apk | tee work/apk-phase2.sha256 || true
gh release download dumps-1.17.6 -R "$REPO_SLUG" -p dump-dexes-1.17.6.zip -O work/dump-dexes.zip || {
  echo "::error::gh release download dumps-1.17.6 failed"
  exit 1
}
command -v unzip >/dev/null 2>&1 || sudo apt-get install -y unzip || true
unzip -o work/dump-dexes.zip -d work/dumps-dex/ >/dev/null || {
  echo "::error::unzip work/dump-dexes.zip -> work/dumps-dex/ failed"
  exit 1
}
DEX_SRC_N="$(find work/dumps-dex -type f \( -name '*.dex' -o -name '*.bin' -o -name '*.cdex' \) 2>/dev/null | wc -l | tr -d ' ')"
echo "phase-1 dump dexes in work/dumps-dex: $DEX_SRC_N"
if [ "$DEX_SRC_N" -lt 1 ]; then
  echo "::error::work/dumps-dex contains no .dex/.bin/.cdex file - the phase-2 driver needs the phase-1 dump dexes (DEX_DIR contract)"
  exit 1
fi
ls -la work/dumps-dex | head -20 || true

# ---------------------------------------------------------------------------
# 8. install the ORIGINAL byte-identical packed apk (assert exit 0)
#    multi-ABI APK: its arm64-v8a libs make it install as native arm64
#    (no tamper trip: the content-integrity gate only passes originals)
# ---------------------------------------------------------------------------
adb -s "$DEV" install -r -g work/packed.apk || {
  echo "::warning::first install failed - reconnecting and retrying once"
  adb disconnect >/dev/null 2>&1 || true
  sleep 3
  adb connect "$DEV" >/dev/null 2>&1 || true
  sleep 2
  adb -s "$DEV" install -r -g work/packed.apk || {
    echo "::error::adb install -r -g work/packed.apk failed (original APK install is a hard contract requirement)"
    exit 1
  }
}
adb -s "$DEV" shell pm path "$APP_ID" | tee work/pm-path-phase2.txt || true
# kernel-level port probe block (defense in depth for the RAW-SVC connect:
# a raw connect(2) to the frida port bypasses the 09 libc hook; iptables
# REJECT for the app uid makes the probe fail even then).  Best-effort -
# if the image lacks iptables or the owner match, we continue without it.
APP_UID="$(adb -s "$DEV" shell "stat -c %u /data/data/$APP_ID 2>/dev/null" | tr -d '\r' | head -1)"
if [ -n "$APP_UID" ] && [ "$APP_UID" != "0" ]; then
  adb -s "$DEV" shell "iptables -A OUTPUT -p tcp --dport $FRIDA_PORT -m owner --uid-owner $APP_UID -j REJECT" \
    && echo "iptables: app uid $APP_UID cannot connect to frida port $FRIDA_PORT" \
    || echo "::warning::iptables REJECT unavailable - raw port probes stay possible (libc connect hook still active)"
else
  echo "::warning::could not resolve the app uid - skipping the iptables port block"
fi
adb -s "$DEV" shell "dumpsys package $APP_ID | grep -iE 'primaryCpuAbi|nativeLibraryDir' | head -6" \
  | tee work/abi-info-phase2.txt || true
# the install-retry reconnect may have dropped the forward - re-establish
# (idempotent) so the driver's FRIDA_REMOTE=127.0.0.1:4789 stays valid
adb -s "$DEV" forward tcp:4789 tcp:"${FRIDA_PORT}" || true
adb -s "$DEV" shell pidof "$SV_NAME" >/dev/null 2>&1 || echo "::warning::frida-server no longer alive right before the driver"

# ---------------------------------------------------------------------------
# 9. run the PHASE-2 DRIVER - exact 2-a/2-b interface contract:
#      ANDROID_SERIAL=localhost:5555 APP_ID=com.world.youcinemobile \
#      FRIDA_REMOTE=127.0.0.1:4789 DEX_DIR=work/dumps-dex \
#      OUT_DIR=work/phase2 python3 unpack/frida_phase2_driver.py
#    The driver spawns the app itself (frida spawn-gating) - there is
#    deliberately NO `am start` in this flow.  `|| true`: the flow must
#    ALWAYS continue to evidence collection; the driver's own exit code is
#    recorded in work/phase2-driver.exit and the workflow verdict step
#    turns 0 RegisterNatives into a job failure.
# ---------------------------------------------------------------------------
if [ ! -f unpack/frida_phase2_driver.py ]; then
  echo "::error::unpack/frida_phase2_driver.py is missing (agent 2-a owns it) - the phase-2 driver cannot run"
fi
# tools/memread: the driver's step 13 (authoritative pread64 re-dump, which
# crosses the -wxp no-read pieces the in-proc reads cannot) passes
# --memread tools/memread - resolved at the REPO ROOT, not under work/.
# Same recipe as the PROVEN redroid_flow.sh (run 34133100459): static build,
# host aarch64 == device aarch64.  Without it dexdata_extract.py degrades
# to a warning and produces no re-dump.
if [ ! -f tools/memread ]; then
  if command -v gcc >/dev/null 2>&1; then
    gcc -static -O2 -o tools/memread tools/memread.c 2>/dev/null \
      || echo "::warning::memread compile failed - the authoritative pread64 re-dump (driver step 13) will be degraded"
  else
    echo "::warning::no gcc on runner - the authoritative pread64 re-dump (driver step 13) will be degraded"
  fi
fi
[ -f tools/memread ] && echo "tools/memread ready ($(stat -c '%s bytes' tools/memread)) for driver step 13"
# ijiami-static vector A: capture_aes_key.js hooks the AES key-material
# entry points (AES_set_*_key / EVP_*Init / mbedtls / tiny-AES) AND scans
# libexec.so for the AES S-box, feeding keys.jsonl on the device (the
# driver pulls it into work/phase2/inproc/ and notes every aes_key event).
# Canonical copy lives in ijiami-static/ - staged into frida-scripts/ at
# runtime so there is exactly ONE source of truth in the repo.
if [ -f ijiami-static/capture_aes_key.js ]; then
  cp ijiami-static/capture_aes_key.js frida-scripts/capture_aes_key.js
  # 09_hide_frida.js: run 34171467849 - the gated process was SIGKILLed ~1s
  # after resume (frida-agent memfd visible in /proc/self/maps + frida
  # threads + the 47890 listener).  09 sanitizes those reads, hides the
  # frida threads and blocks/logs the death ladder (kill/exit/abort) with a
  # backtrace of the killer; the driver re-attaches to the AMS-restarted
  # instance if it still dies.
  PHASE2_GUARDS="02_bypass_ptrace.js,09_hide_frida.js,capture_aes_key.js"
  echo "AES key capture + anti-anti-frida wired: GUARD_SCRIPTS=$PHASE2_GUARDS"
else
  PHASE2_GUARDS="02_bypass_ptrace.js,09_hide_frida.js"
  echo "::warning::ijiami-static/capture_aes_key.js missing - running phase 2 without AES key capture"
fi
# keep the pre-driver boot log, then start a clean logcat for the app phase
adb -s "$DEV" logcat -d -b main,system,crash > work/logcat-boot-phase2.txt 2>&1 || true
adb -s "$DEV" logcat -c >/dev/null 2>&1 || true
DRIVER_RC=0
# PHASE2_MODE=matrix: rounds 1-4 all die the same way; the matrix probe
# determines WHICH instrumentation layer trips iJiami's death ladder
# (spawn-gate / agent presence / libc hooks / ptrace replace / crypto
# hooks / libart hooks / full config) before the capture pipeline runs.
ANDROID_SERIAL="$DEV" APP_ID="$APP_ID" FRIDA_REMOTE="127.0.0.1:4789" \
  DEX_DIR="work/dumps-dex" OUT_DIR="work/phase2" \
  GUARD_SCRIPTS="$PHASE2_GUARDS" PHASE2_MODE="matrix" \
  python3 unpack/frida_phase2_driver.py || DRIVER_RC=$?
echo "phase-2 driver exit code: $DRIVER_RC"
echo "$DRIVER_RC" > work/phase2-driver.exit || true

# ---------------------------------------------------------------------------
# 10. evidence capture (ALWAYS - even on driver failure); container LEFT RUNNING
# ---------------------------------------------------------------------------
adb -s "$DEV" logcat -d -b main,system,crash > work/logcat-phase2.txt 2>&1 || true
docker logs "$CNAME" > work/docker-phase2.txt 2>&1 || true
echo "== key logcat lines (jdwp presence is the debuggable indicator) =="
grep -nE "jdwp|ijiami|frida|RegisterNatives|UnsatisfiedLink|FATAL|AndroidRuntime|Fatal signal" \
  work/logcat-phase2.txt | head -60 || true
adb -s "$DEV" shell ps -A > work/ps-phase2.txt 2>&1 || true
adb -s "$DEV" shell "ps -A | grep -i youcine" || true
PID="$(adb -s "$DEV" shell pidof "$APP_ID" 2>/dev/null | tr -d '\r' | awk '{print $1}')"
echo "pidof $APP_ID: '$PID'"
if [ -n "$PID" ]; then
  adb -s "$DEV" shell "cat /proc/$PID/maps" > work/maps-app-phase2.txt 2>&1 || true
else
  echo "::warning::$APP_ID is not running post-driver (expected if the death ladder won) - no maps"
fi
adb -s "$DEV" shell dumpsys window > work/dumpsys-window-phase2.txt 2>&1 || true
adb -s "$DEV" pull /data/local/tmp/sv.log work/sv.log >/dev/null 2>&1 || true
adb -s "$DEV" shell "ls -la /data/local/tmp/youcine_re_phase2/ 2>/dev/null" \
  | tee work/device-phase2-dir.txt || true

# ---------------------------------------------------------------------------
# 11. summary (container left RUNNING for post-hoc inspection)
# ---------------------------------------------------------------------------
echo "==============================================================="
echo " redroid_frida_flow.sh summary"
echo "   image          : $REDROID_IMAGE (native arm64)"
echo "   container      : $CNAME -> $(docker ps --filter "name=$CNAME" --format '{{.Status}}' 2>/dev/null || echo 'not running')"
echo "   frida-server   : name=$SV_NAME pid=${SV_PID:-dead} listen=127.0.0.1:${FRIDA_PORT} (host tunnel tcp:4789)"
echo "   frida version  : $FRIDA_VERSION (server + python client must match)"
echo "   driver exit    : $DRIVER_RC (work/phase2-driver.exit)"
echo "   phase-1 dexes  : $DEX_SRC_N file(s) in work/dumps-dex (DEX_DIR)"
echo "   evidence       : work/logcat-phase2.txt work/docker-phase2.txt work/ps-phase2.txt"
echo "                   work/maps-app-phase2.txt work/dumpsys-window-phase2.txt"
echo "                   work/props-phase2*.txt work/sv.log work/adb-forwards.txt"
echo "==============================================================="
if [ -f work/phase2/summary.json ]; then
  echo "== work/phase2/summary.json =="
  cat work/phase2/summary.json || true
else
  echo "::warning::work/phase2/summary.json missing - the phase-2 driver did not complete"
fi
# defensive parse: the driver's exact summary keys are owned by agent 2-a,
# so try the plausible spellings before falling back to 0
RN="$(python3 - <<'PY' 2>/dev/null || echo 0
import json

try:
    with open("work/phase2/summary.json") as f:
        d = json.load(f)
except Exception:
    print(0)
    raise SystemExit(0)

def as_int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, (list, tuple)):
        return len(v)
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None

for key in ("rn_methods", "rn_count", "register_natives", "register_natives_count",
            "jni_methods", "rn_total", "methods"):
    if key in d:
        v = as_int(d[key])
        if v is not None:
            print(v)
            break
else:
    print(0)
PY
)"
REPAIRED="$(find work/phase2/repaired -type f 2>/dev/null | wc -l | tr -d ' ')"
echo "rn_methods=${RN:-0}  redump_repaired_files=${REPAIRED:-0}  (EXPECT_MIN_RN=${EXPECT_MIN_RN})"
if [ "${RN:-0}" -lt "${EXPECT_MIN_RN}" ]; then
  echo "::warning::RegisterNatives methods captured (${RN:-0}) < EXPECT_MIN_RN (${EXPECT_MIN_RN}) - see work/logcat-phase2.txt / work/sv.log (the driver exit code already reflects severity)"
fi
if [ -d work/phase2/repaired ]; then
  ls -la work/phase2/repaired | head -20 || true
fi
exit 0
