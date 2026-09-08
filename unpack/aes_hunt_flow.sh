#!/usr/bin/env bash
# aes_hunt_flow.sh v1 - the ijiami-static key-recovery flow (redroid, arm64).
#
# WHY THIS FLOW EXISTS:
#   capture_aes_key.js hooks the STANDARD crypto entry points
#   (AES_set_*_key / EVP_*Init / mbedtls / tiny-AES) - but the phase-2 run
#   (34226758009) proved iJiami's AES for assets/ijiami.dat is a CUSTOM
#   SecLLVM-obfuscated implementation inside libexec.so that never calls
#   any of them: the only captured keys were Java TLS traffic keys
#   (verified: none of them decrypts the dat - see
#   ijiami-static/out/report.json, SUMMARY: FAIL).
#
#   THE INJECTION-FREE PATH: external_memdump.py never injects into the
#   process (iJiami's ptrace anti-debug is irrelevant), it polls pidof,
#   settles, SIGSTOPs (freezes the packer watchdogs + the death ladder)
#   and sweeps /proc/<pid>/mem regions out with a root adb shell.  The
#   decryption of ijiami.dat happens in attachBaseContext - long before
#   any Activity - so the AES expanded key schedule (176 B for AES-128,
#   240 B for AES-256) is ALREADY in memory (libexec.so .data/.bss or the
#   Java heap) when the first freeze lands.  hunt_key_schedule.py then
#   scans the kept region files offline: it verifies the AES key-schedule
#   recurrence (w[i] = w[i-Nk] ^ SubWord(RotWord(w[i-1])) ^ Rcon) and can
#   even WALK A PARTIAL SCHEDULE BACK to the original key, and
#   decrypt_ijiami_dat.py verifies candidates directly against the real
#   dat payload (magic + 'Lcom/' density) - VERIFIED/FAIL, no guessing.
#
# ENVIRONMENT (verbatim from redroid_frida_flow.sh, the PROVEN phase-2
# recipe): kernel binder devices, build.prop patched BEFORE first boot
# (REPLACE-ONLY - appending kills init), native arm64 redroid 11, adbd
# root, runtime property verify-and-fix.  FRIDA IS NOT USED AT ALL.
#
# Env: APP_ID, REDROID_IMAGE, SETTLE (default 1.5), MEMDUMP_TIMEOUT
#      (default 150), APK_SOURCE (release|url), SAMPLE_URL.
# Leaves the container RUNNING after the flow so evidence can still be
# gathered post-hoc.
set -x

APP_ID="${APP_ID:-com.world.youcinemobile}"
REDROID_IMAGE="${REDROID_IMAGE:-redroid/redroid:11.0.0-latest}"
SETTLE="${SETTLE:-1.5}"
MEMDUMP_TIMEOUT="${MEMDUMP_TIMEOUT:-150}"

if [ -n "$ANDROID_HOME" ]; then
  export PATH="$ANDROID_HOME/platform-tools:$PATH"
fi

cd "${GITHUB_WORKSPACE:-$(dirname "$0")/..}"
mkdir -p work work/redroid-data work/aes-hunt ijiami-static/out

# ---------------------------------------------------------------------------
# 1. host kernel: binder devices (mandatory), ashmem (best effort)
# ---------------------------------------------------------------------------
command -v adb >/dev/null 2>&1 || sudo apt-get install -y adb || true
command -v xz >/dev/null 2>&1 || sudo apt-get install -y xz-utils || true
command -v adb >/dev/null 2>&1 || {
  echo "::error::adb not found on the host (sudo apt-get install adb)"
  exit 1
}
sudo apt-get update && sudo apt-get install -y "linux-modules-extra-$(uname -r)" || true
sudo modprobe binder_linux devices="binder,hwbinder,vndbinder" || sudo modprobe binder_linux
sudo modprobe ashmem_linux || true
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
# 2. patch build.prop BEFORE first boot (REPLACE-ONLY, never append)
# ---------------------------------------------------------------------------
docker rm -f youcine-aes yc-stage >/dev/null 2>&1 || true

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
  echo "::error::could not extract /system/build.prop from the redroid image"
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

replace_line work/system-build.prop ro.debuggable 0
replace_line work/system-build.prop ro.secure 0
replace_line work/system-build.prop ro.build.type user
replace_line work/system-build.prop ro.build.tags release-keys
replace_line work/system-build.prop ro.build.fingerprint "$SAMSUNG_FP"
replace_line work/system-build.prop ro.build.display.id "o1sxxx-user 11 RP1A.200720.012 G991BXXU5CUL5 release-keys"
replace_line work/system-build.prop ro.build.description "o1sxxx-user 11 RP1A.200720.012 G991BXXU5CUL5 release-keys"
replace_line work/system-build.prop ro.product.system.model "SM-G991B"
replace_line work/system-build.prop ro.product.system.brand samsung
replace_line work/system-build.prop ro.product.system.manufacturer samsung
replace_line work/system-build.prop ro.product.system.device o1s
replace_line work/system-build.prop ro.product.system.name o1sxxx

if [ -n "$VENDOR_PROP" ]; then
  replace_line "$VENDOR_PROP" ro.product.vendor.model "SM-G991B"
  replace_line "$VENDOR_PROP" ro.product.vendor.device o1s
  replace_line "$VENDOR_PROP" ro.product.vendor.brand samsung
  replace_line "$VENDOR_PROP" ro.vendor.build.fingerprint "$SAMSUNG_FP"
  replace_line "$VENDOR_PROP" ro.vendor.build.tags release-keys
  replace_line "$VENDOR_PROP" ro.vendor.build.type user
fi

CNAME="youcine-aes"
docker create --tty --name "$CNAME" --privileged \
  --security-opt apparmor=unconfined \
  -p 127.0.0.1:5555:5555 -v "$PWD/work/redroid-data:/data" "$REDROID_IMAGE" || {
  echo "::error::docker create $CNAME failed"
  exit 1
}
docker cp work/system-build.prop "$CNAME:/system/build.prop"
[ -n "$VENDOR_PROP" ] && docker cp "$VENDOR_PROP" "$CNAME:/vendor/build.prop"
docker start "$CNAME" || {
  docker logs "$CNAME" > work/docker-aes.txt 2>&1 || true
  echo "::error::docker start $CNAME failed"
  exit 1
}

sleep 5
echo "== docker logs (first boot, t=5s) =="
docker logs --tail 20 "$CNAME" 2>&1 || true

# ---------------------------------------------------------------------------
# 3. wait for adb, ESTABLISH adbd ROOT, wait for full boot
# ---------------------------------------------------------------------------
DEV=localhost:5555
CONNECTED=""
for i in $(seq 1 60); do
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
  docker logs "$CNAME" > work/docker-aes.txt 2>&1 || true
  echo "::error::container never became adb-reachable within 300s - see work/docker-aes.txt"
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
echo "$ID" | grep -q "uid=0" || echo "::warning::adb is NOT root - the memdump sweeps will fail"

BOOTED=""
for i in $(seq 1 60); do
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
  adb -s "$DEV" logcat -d -b main,system,crash > work/logcat-aes.txt 2>&1 || true
  echo "::error::Android did not finish booting within 300s"
  exit 1
fi

sleep 10
echo "== environment evidence =="
adb -s "$DEV" shell "getprop | grep -iE 'qemu|goldfish|ranchu|redroid|debuggable|secure|fingerprint|model|hardware|abilist|tags|build.type' | head -50" \
  | tee work/props-aes.txt || true

# ---------------------------------------------------------------------------
# 4. runtime property verify-and-fix + framework restart ONLY if needed
# ---------------------------------------------------------------------------
SET_ARGS=()
rd_cur() { adb -s "$DEV" shell getprop "$1" 2>/dev/null | tr -d '\r'; }
fix_prop() {
  local cur desired
  cur=$(rd_cur "$1"); desired="$2"
  [ -z "$cur" ] && return 0
  [ "$cur" = "$desired" ] && return 0
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
  echo "framework restarted: ready=$RDY"
  [ -n "$RDY" ] || echo "::warning::framework not fully ready after restart; proceeding"
  for i in $(seq 1 20); do
    adb -s "$DEV" shell pm path com.android.shell >/dev/null 2>&1 && break
    sleep 3
  done
fi

adb disconnect >/dev/null 2>&1 || true
sleep 2
adb connect "$DEV" >/dev/null 2>&1 || true
sleep 2
adb -s "$DEV" shell setenforce 0 >/dev/null 2>&1 || true
echo "SELinux: $(adb -s "$DEV" shell getenforce 2>/dev/null | tr -d '\r')"
adb -s "$DEV" shell settings put global hidden_api_policy 1 >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 5. immutable source: the ORIGINAL packed apk (never a rebuilt asset)
# ---------------------------------------------------------------------------
REPO_SLUG="${GITHUB_REPOSITORY:-beto2-dev/Youcine-RE}"
if [ "${APK_SOURCE:-release}" = "release" ]; then
  gh release download packed-1.17.6 -R "$REPO_SLUG" -p ycMob_1.17.6_ycsite.apk -O work/packed.apk || {
    echo "::error::gh release download packed-1.17.6 failed"
    exit 1
  }
else
  curl -fL --retry 3 -o work/packed.apk "${SAMPLE_URL:?APK_SOURCE != release requires SAMPLE_URL}" || {
    echo "::error::curl SAMPLE_URL failed"
    exit 1
  }
fi
sha256sum work/packed.apk | tee work/apk-aes.sha256 || true
command -v unzip >/dev/null 2>&1 || sudo apt-get install -y unzip || true
unzip -o -j work/packed.apk assets/ijiami.dat -d work/assets >/dev/null || {
  echo "::error::assets/ijiami.dat not found inside work/packed.apk"
  exit 1
}
ls -la work/assets/ijiami.dat
sha256sum work/assets/ijiami.dat

# ---------------------------------------------------------------------------
# 6. install the ORIGINAL byte-identical packed apk
# ---------------------------------------------------------------------------
adb -s "$DEV" install -r -g work/packed.apk || {
  echo "::warning::first install failed - reconnecting and retrying once"
  adb disconnect >/dev/null 2>&1 || true
  sleep 3
  adb connect "$DEV" >/dev/null 2>&1 || true
  sleep 2
  adb -s "$DEV" install -r -g work/packed.apk || {
    echo "::error::adb install failed (original APK install is a hard contract requirement)"
    exit 1
  }
}
adb -s "$DEV" shell pm path "$APP_ID" | tee work/pm-path-aes.txt || true

# ---------------------------------------------------------------------------
# 7. freeze-and-sweep: launch + external_memdump with region keeping
#    (--include-libs: the packer cipher context lives in libexec.so's
#     .data/.bss, which the stock dalvik/dex/memfd/cache filter excludes;
#     --expect 99: never stop early - every sweep state is evidence,
#     the process death / timeout ends the loop)
# ---------------------------------------------------------------------------
echo "== launching $APP_ID for the freeze-and-sweep =="
# the proven phase-1 launcher component (redroid_flow.sh run 34133100459)
adb -s "$DEV" shell am start -W -n "$APP_ID/com.mobile.brasiltv.activity.SplashAty" 2>&1 | head -24 \
  || adb -s "$DEV" shell monkey -p "$APP_ID" -c android.intent.category.LAUNCHER 1 \
  || echo "::warning::could not launch the app - external_memdump will poll anyway"
export ANDROID_SERIAL="$DEV"
python3 unpack/external_memdump.py \
  --app "$APP_ID" \
  --out-dir work/aes-hunt \
  --settle "$SETTLE" \
  --timeout "$MEMDUMP_TIMEOUT" \
  --expect 99 \
  --keep-regions \
  --include-libs \
  --pull-app-data || echo "::warning::external_memdump exited nonzero - regions may still exist"
echo "== kept region sweeps =="
ls -la work/aes-hunt/ 2>/dev/null || true
for d in work/aes-hunt/regions_*; do
  [ -d "$d" ] || continue
  echo "-- $d: $(ls "$d" | wc -l) files, $(du -sh "$d" | cut -f1)"
done

# ---------------------------------------------------------------------------
# 8. offline hunt: expanded key schedules in the kept regions
# ---------------------------------------------------------------------------
python3 -m pip install --quiet numpy pycryptodome > work/pip-aes.log 2>&1 \
  || { cat work/pip-aes.log || true; echo "::warning::pip install numpy/pycryptodome failed - hunt degrades to pure python"; }
python3 -c "import numpy; print('numpy', numpy.__version__)" 2>/dev/null \
  || echo "::warning::numpy unavailable - hunt_key_schedule runs pure python (slow)"

# self-test first: a broken detector must fail the flow loudly
python3 ijiami-static/hunt_key_schedule.py --selftest || {
  echo "::error::hunt_key_schedule selftest FAILED - refusing to run a broken detector"
  exit 1
}
python3 ijiami-static/decrypt_ijiami_dat.py --selftest || {
  echo "::error::decrypt_ijiami_dat selftest FAILED - refusing to run a broken decryptor"
  exit 1
}

echo "== hunting AES key schedules in $(du -sh work/aes-hunt/regions_* 2>/dev/null | wc -l) sweep(s) =="
python3 ijiami-static/hunt_key_schedule.py \
  --dump-dir work/aes-hunt \
  --out ijiami-static/out/candidates.json \
  2>&1 | tee work/hunt-output.txt
[ -f ijiami-static/out/candidates.json ] \
  && echo "== candidates.json: $(python3 -c "import json; print(len(json.load(open('ijiami-static/out/candidates.json'))))" 2>/dev/null) hit(s)" \
  || echo "::warning::no candidates.json produced"

# ---------------------------------------------------------------------------
# 9. offline decrypt + verify against the real payload
# ---------------------------------------------------------------------------
python3 ijiami-static/decrypt_ijiami_dat.py \
  --dat work/assets/ijiami.dat \
  --keys-file ijiami-static/out/candidates.json \
  --out-dir ijiami-static/out \
  2>&1 | tee work/decrypt-output.txt
DR_EXIT=$?
echo "$DR_EXIT" > work/decrypt.exit
if [ "$DR_EXIT" = "0" ]; then
  echo "== AES KEY RECOVERED: ijiami.dat statically decrypted and VERIFIED =="
else
  echo "== not verified this run: candidates + report preserved as evidence =="
fi
exit 0
