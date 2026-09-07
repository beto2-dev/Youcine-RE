#!/usr/bin/env python3
"""BlackDex UI-automation driver (host-side, no root needed).

Drives the open-source BlackDex64 unpacker (top.niunaijun.blackdexa64,
GPL, https://github.com/CodingGay/BlackDex) on an Android emulator via
adb + uiautomator, and pulls the dumped DEX files.

Why UI automation: BlackDex v3.2 exports no automation surface. The
manifest has exactly one intent-filter (the LAUNCHER WelcomeActivity);
MainActivity, services and receivers are not exported and accept no
extras. The only entry point to the dump engine is tapping an app row
in MainActivity's RecyclerView (MainViewModel.startDexDump -> DexDump
Repository.dumpDex -> BlackDexCore.dumpDex).

Flow implemented here (see static-analysis/blackdex-internals.md):
  0. appops pre-grant MANAGE_EXTERNAL_STORAGE (Android 11 needs All
     Files Access for the default dump dir; falls back to UI if denied)
  1. force-stop + am start MainActivity (shell holds START_ANY_ACTIVITY,
     so the non-exported activity starts; falls back to the LAUNCHER)
  2. wait for the app list, uiautomator dump in a retry loop
     ("could not get idle state" is retried), pull window_dump.xml via
     `adb exec-out cat`, find the target row (label or package text)
     and tap its center -> unpacking starts immediately (no confirm
     dialog: MainActivity$initView$1 calls startDexDump directly)
  3. generic dialog handling: re-dump and tap positive/unpack-related
     buttons ("Confirm", "Grant Permission", ...), never "Github"
     (opens the browser) or "Cancel"/"Later"; if the All-Files-Access
     settings page appears, flip the switch and press BACK
  4. poll /storage/emulated/0/Download/dexDump/<pkg> until files stop
     growing or --timeout (the in-app countdown is only a single 20 s
     delay, so we trust the filesystem, not the dialog)
  5. pull the dump dir (adb pull, tar fallback, per-file cat fallback)

Usage:
  python3 unpack/blackdex_auto.py --app-id com.world.youcinemobile \
      --label YouCine --out-dir dumps/blackdex --timeout 300

Exit code: 0 only if at least one dumped file was pulled.
Stdlib only; adb taken from PATH (override with $ADB or --adb).
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

# ---------------------------------------------------------------- constants
BD_PACKAGE = "top.niunaijun.blackdexa64"
BD_MAIN = "top.niunaijun.blackdex.view.main.MainActivity"
BD_WELCOME = "top.niunaijun.blackdex.view.base.WelcomeActivity"  # LAUNCHER
WINDOW_DUMP = "/sdcard/window_dump.xml"

# BlackDex64 on Android 11 (R) saves to
# context.externalCacheDir.parent^4 + Download/dexDump  ==>
# /storage/emulated/0/Android/data/<pkg>/cache -> ... -> /storage/emulated/0
DUMP_DIR_R = "/storage/emulated/0/Download/dexDump"
# pre-R fallback (not used on our API 30 image); template - formatted
# lazily so --bd-package (a32/a64) stays correct
DUMP_DIR_LEGACY_TPL = "/storage/emulated/0/Android/data/%s/dump"

ADB_DEFAULT = os.environ.get("ADB", "adb")

# Positive / progress dialog buttons we may tap (lowercase, substring).
POSITIVE_TEXTS = (
    "confirm", "ok", "yes", "allow", "grant permission", "确定",
    "开始", "开始解包", "dump", "unpack", "解包",
)
# Never tap these even though they are buttons.
NEGATIVE_TEXTS = ("github", "cancel", "later", "取消", "以后", "稍后")
# Success / failure dialog markers (substring, lowercase).
SUCCESS_TEXTS = ("unpack successfully", "were saved in", "saved in", "解包成功")
FAIL_TEXTS = ("unpack failed", "error:", "may be the app is incompatible", "解包失败")
# All-Files-Access settings page marker
ALL_FILES_TEXTS = ("manage all files", "allow access to manage all files",
                   "all files access")

POSIX_TS = "%H:%M:%S"


def log(msg: str) -> None:
    print(time.strftime("[%Y-%m-%d ") + time.strftime(POSIX_TS) + "] " + msg,
          flush=True)


# ---------------------------------------------------------------- adb plumbing
class Adb:
    def __init__(self, adb: str, serial: str | None, tries: int = 3,
                 timeout: float = 30.0):
        self.base = [adb] + (["-s", serial] if serial else [])
        self.tries = tries
        self.timeout = timeout

    def run(self, *args, timeout: float | None = None, check: bool = False,
            binary: bool = False, quiet: bool = False):
        """Run one adb command with retries. Returns CompletedProcess."""
        cmd = self.base + list(args)
        tmo = timeout if timeout is not None else self.timeout
        last = None
        for attempt in range(1, self.tries + 1):
            try:
                if binary:
                    last = subprocess.run(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=tmo)
                else:
                    last = subprocess.run(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, encoding="utf-8", errors="replace",
                        timeout=tmo)
                if check and last.returncode != 0:
                    raise RuntimeError(
                        "adb %s failed rc=%d: %s" % (
                            " ".join(args), last.returncode,
                            (last.stderr or last.stdout or "")[:400]))
                return last
            except (subprocess.TimeoutExpired, OSError, RuntimeError) as exc:
                if not quiet:
                    log("adb %s attempt %d/%d failed: %s" % (
                        " ".join(args[:3]), attempt, self.tries, exc))
                if attempt == self.tries:
                    if last is None:
                        last = subprocess.CompletedProcess(cmd, 1)
                    return last
                time.sleep(1.5 * attempt)
        return last  # unreachable


def sh(adb: Adb, script: str, timeout: float | None = None):
    """Run `adb shell <script>` (single sh invocation)."""
    return adb.run("shell", script, timeout=timeout)


# ---------------------------------------------------------------- uiautomator
def ui_dump(adb: Adb, tries: int = 6) -> str | None:
    """uiautomator dump + `exec-out cat` of the XML. Retries the classic
    'ERROR: could not get idle state' failure mode."""
    for attempt in range(1, tries + 1):
        # drop any stale file first so a failed dump can never serve old XML
        sh(adb, "rm -f %s" % WINDOW_DUMP, quiet=True)
        r = sh(adb, "uiautomator dump %s 2>&1" % WINDOW_DUMP, timeout=45)
        out = (r.stdout or "") + (r.stderr or "")
        if "dumped to" in out or "UI hierarchie dumped" in out:
            c = adb.run("exec-out", "cat", WINDOW_DUMP, timeout=30,
                        binary=True)
            if c.returncode == 0 and c.stdout and b"<hierarchy" in c.stdout:
                sh(adb, "rm -f %s" % WINDOW_DUMP, quiet=True)
                return c.stdout.decode("utf-8", "replace")
            log("dump ok but read failed (rc=%d len=%d), retrying" % (
                c.returncode, len(c.stdout or b"")))
        else:
            flat = " ".join(out.split())[:160]
            log("uiautomator dump attempt %d/%d: %s" % (attempt, tries, flat))
        time.sleep(min(2.0 * attempt, 8))
    return None


def parse_bounds(bounds: str):
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds or "")
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    if x2 <= x1 or y2 <= y1:
        return None
    return (x1 + x2) // 2, (y1 + y2) // 2


def walk_nodes(root):
    for node in root.iter("node"):
        yield node, {k: (v or "") for k, v in node.attrib.items()}


def find_target_row(xml_text: str, label: str, app_id: str):
    """Find the best node for the target app row. The item layout
    (item_package.xml) is [icon | TextView name | TextView packageName]
    inside a clickable LinearLayout row; tapping the text works."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        log("XML parse error: %s" % exc)
        return None
    label_l = label.lower()
    pkg_l = app_id.lower()
    candidates = []
    for _node, a in walk_nodes(root):
        text = a.get("text", "").strip()
        desc = a.get("content-desc", "").strip()
        rid = a.get("resource-id", "").lower()
        hay = (text + " " + desc).lower()
        if not hay:
            continue
        score = 0
        if hay == pkg_l:
            score = 100  # package name text is unique
        elif pkg_l in hay:
            score = 90
        elif hay == label_l:
            score = 80
        elif label_l and label_l in hay:
            score = 70
        elif rid.endswith("id/packagename") and text:
            score += 20
        if score <= 0:
            continue
        # the list rows also show BlackDex itself and the search view; skip
        # nodes that are the toolbar/search of BlackDex UI
        if a.get("package", "") != BD_PACKAGE:
            score -= 30
        if a.get("clickable") == "true":
            score += 15
        center = parse_bounds(a.get("bounds", ""))
        if center:
            candidates.append((score, center, text or desc))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    score, center, txt = candidates[0]
    log("row candidate: score=%d text=%r center=%s" % (score, txt, center))
    return center


def find_dialog_button(xml_text: str):
    """Find a positive dialog button to tap (Confirm / Grant Permission /
    开始 ...). Avoids Github / Cancel / Later."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    best = None
    for _node, a in walk_nodes(root):
        if a.get("package", "") != BD_PACKAGE:
            continue
        if a.get("clickable") != "true":
            continue
        text = (a.get("text", "") or a.get("content-desc", "")).strip()
        if not text:
            continue
        low = text.lower()
        if any(neg in low for neg in NEGATIVE_TEXTS):
            continue
        if any(pos in low for pos in POSITIVE_TEXTS):
            center = parse_bounds(a.get("bounds", ""))
            if center:
                # prefer "confirm"-ish over "grant permission" (opens settings)
                rank = 0 if "confirm" in low or "ok" == low else 1
                if best is None or rank < best[0]:
                    best = (rank, center, text)
    return (best[1], best[2]) if best else None


def find_all_files_toggle(xml_text: str):
    """On the All-Files-Access settings page find the Switch / row to tap."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    for _node, a in walk_nodes(root):
        cls = a.get("class", "")
        text = (a.get("text", "") or "").lower()
        desc = (a.get("content-desc", "") or "").lower()
        rid = a.get("resource-id", "").lower()
        if cls == "android.widget.Switch" or "switch_widget" in rid:
            center = parse_bounds(a.get("bounds", ""))
            if center:
                return center
        if any(t in text or t in desc for t in ALL_FILES_TEXTS):
            center = parse_bounds(a.get("bounds", ""))
            if center:
                return center
    return None


def screen_texts(xml_text: str):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ""
    buf = []
    for _n, a in walk_nodes(root):
        t = (a.get("text", "") or a.get("content-desc", "")).strip()
        if t:
            buf.append(t)
    return " ".join(buf).lower()


# ---------------------------------------------------------------- main flow
def grant_all_files(adb: Adb, app_id: str) -> bool:
    """Pre-grant All Files Access so dumps land in Download/dexDump.
    `appops set` works from the adb shell uid on API 30 images."""
    r = sh(adb, "appops set %s MANAGE_EXTERNAL_STORAGE allow" % BD_PACKAGE)
    ok = r.returncode == 0
    # verify: dumpsys appops (only when set succeeded)
    if ok:
        v = sh(adb, "dumpsys appops %s MANAGE_EXTERNAL_STORAGE" % BD_PACKAGE)
        state = (v.stdout or "")
        ok = "allow" in state.lower() and "deny" not in state.lower()
        log("appops MANAGE_EXTERNAL_STORAGE -> %s"
            % ("allow (verified)" if ok else "NOT verified: %s" %
               " ".join(state.split())[:120]))
    if not ok:
        log("WARNING: appops grant failed (rc=%d %s); will rely on the "
            "in-app permission dialog" % (r.returncode,
                                          (r.stderr or "")[:120]))
    return ok


def launch_blackdex(adb: Adb) -> bool:
    sh(adb, "am force-stop %s" % BD_PACKAGE, quiet=True)
    time.sleep(1)
    # MainActivity is not exported, but the adb shell uid holds
    # START_ANY_ACTIVITY, so a direct component start works.
    r = sh(adb, "am start -W -n %s/%s" % (BD_PACKAGE, BD_MAIN), timeout=60)
    out = (r.stdout or "") + (r.stderr or "")
    if "Permission Denial" in out or "SecurityException" in out \
            or r.returncode != 0:
        log("direct MainActivity start denied, using LAUNCHER instead: %s"
            % " ".join(out.split())[:160])
        r = sh(adb, "am start -W -n %s/%s" % (BD_PACKAGE, BD_WELCOME),
               timeout=60)
        out = (r.stdout or "") + (r.stderr or "")
    ok = "Status: ok" in out or r.returncode == 0
    # WelcomeActivity forwards to MainActivity immediately.
    log("am start: %s" % (" ".join(out.split())[:160]))
    return ok


def wait_for_list(adb: Adb, label: str, app_id: str, timeout: float):
    """Wait until the app list contains the target row. Also swallows the
    first-run storage-permission dialog if it appears (taps Grant
    Permission, flips the All-Files switch, presses BACK)."""
    deadline = time.time() + timeout
    seen_permission_dialog = False
    while time.time() < deadline:
        xml_text = ui_dump(adb)
        if not xml_text:
            time.sleep(2)
            continue
        screen = screen_texts(xml_text)
        # storage permission dialog (first run without appops grant)
        if ("permission required" in screen or "required permission" in
                screen) and not seen_permission_dialog:
            seen_permission_dialog = True
            log("storage permission dialog detected")
            btn = find_dialog_button(xml_text)
            if btn and "grant" in btn[1].lower():
                log("tapping 'Grant Permission' -> All-Files settings")
                sh(adb, "input tap %d %d" % btn[0])
                time.sleep(2.5)
                xml2 = ui_dump(adb) or ""
                toggle = find_all_files_toggle(xml2)
                if toggle:
                    log("toggling All-Files switch at %s" % (toggle,))
                    sh(adb, "input tap %d %d" % toggle)
                    time.sleep(1.0)
                sh(adb, "input keyevent 4")  # BACK to BlackDex
                time.sleep(2.0)
                continue
        center = find_target_row(xml_text, label, app_id)
        if center:
            return center
        # list still loading (StateView loading) or empty
        log("target row not visible yet (screen: %s)" % screen[:90])
        time.sleep(3)
    return None


def tap_start_dump(adb: Adb, center) -> bool:
    log("tapping target row at %s -> startDexDump" % (center,))
    r = sh(adb, "input tap %d %d" % center)
    return r.returncode == 0


def poll_output_dir(adb: Adb, dump_dir: str, timeout: float,
                    stable_checks: int = 3, interval: float = 5.0):
    """Poll `ls -la <dump_dir>/<pkg>` until files stop growing.
    Returns (files: dict[name->bytes], success_dialog_seen: bool)."""
    deadline = time.time() + timeout
    snapshot = {}
    stable = 0
    saw_files_at = 0.0
    while time.time() < deadline:
        r = sh(adb, "ls -la %s 2>&1" % dump_dir, timeout=20)
        out = r.stdout or ""
        current = {}
        for line in out.splitlines():
            # classic `ls -l` field layout: perms links owner group size date.. name
            fields = line.split()
            if len(fields) >= 7 and fields[0].startswith("-"):
                try:
                    current[fields[-1]] = int(fields[4])
                except ValueError:
                    pass
        if current:
            if current != snapshot:
                if snapshot:
                    log("dump dir growing: %d file(s), %d bytes"
                        % (len(current), sum(current.values())))
                snapshot = current
                stable = 0
                saw_files_at = time.time()
            else:
                stable += 1
            if not saw_files_at:
                saw_files_at = time.time()
        # poll the UI too: the success dialog is the strongest signal,
        # but files may still be written (countdown posts at 20 s), so we
        # only early-exit when files are also stable once.
        if stable >= stable_checks and snapshot:
            log("output stable for %d checks: %s" % (
                stable, ", ".join("%s(%d)" % kv for kv in
                                  sorted(snapshot.items()))))
            return snapshot, True
        if stable >= 1:
            xml_text = ui_dump(adb, tries=1)
            if xml_text:
                screen = screen_texts(xml_text)
                if any(s in screen for s in SUCCESS_TEXTS):
                    log("success dialog observed")
                    btn = find_dialog_button(xml_text)
                    if btn:
                        log("tapping dialog button %r" % btn[1])
                        sh(adb, "input tap %d %d" % btn[0])
                    # keep polling files a bit longer
                    stable = 0
                    deadline = min(deadline, time.time() + 30)
                elif any(s in screen for s in FAIL_TEXTS):
                    log("failure dialog observed: %s" % screen[:140])
                    btn = find_dialog_button(xml_text)
                    if btn:
                        sh(adb, "input tap %d %d" % btn[0])
        time.sleep(interval)
    return snapshot, False


def pull_dump_dir(adb: Adb, device_dir: str, out_dir: Path) -> int:
    """Pull the dump dir. adb pull -> exec-out tar -> per-file cat."""
    out_dir.mkdir(parents=True, exist_ok=True)
    r = sh(adb, "ls %s 2>/dev/null" % device_dir)
    names = [n for n in (r.stdout or "").split() if n not in (".", "..")]
    if not names:
        log("device dir empty: %s" % device_dir)
        return 0
    # 1) adb pull (fast, works for shared storage)
    pr = adb.run("pull", device_dir, str(out_dir), timeout=180)
    pulled = 0
    if pr.returncode == 0:
        local = out_dir / Path(device_dir).name
        if local.exists():
            pulled = sum(1 for f in local.iterdir() if f.is_file())
    if pulled:
        log("adb pull ok: %d file(s) -> %s" % (pulled, out_dir))
        return pulled
    log("adb pull failed (%s), falling back to tar" %
        " ".join(((pr.stderr or pr.stdout or "")).split())[:160])
    # 2) exec-out tar stream
    local_dir = out_dir / Path(device_dir).name
    local_dir.mkdir(parents=True, exist_ok=True)
    tar_cmd = "tar -cf - -C %s ." % device_dir
    tr = adb.run("exec-out", "shell", tar_cmd, timeout=300, binary=True)
    if tr.returncode == 0 and tr.stdout and len(tr.stdout) > 100:
        import io
        import tarfile
        try:
            with tarfile.open(fileobj=io.BytesIO(tr.stdout)) as tf:
                tf.extractall(local_dir)
            pulled = sum(1 for f in local_dir.rglob("*") if f.is_file())
            if pulled:
                log("tar fallback ok: %d file(s)" % pulled)
                return pulled
        except Exception as exc:  # noqa: BLE001
            log("tar extract failed: %s" % exc)
    # 3) per-file cat
    for name in names:
        cr = adb.run("exec-out", "cat", "%s/%s" % (device_dir, name),
                     timeout=120, binary=True)
        if cr.returncode == 0 and cr.stdout:
            (local_dir / name).write_bytes(cr.stdout)
            pulled += 1
            log("cat fallback: %s (%d bytes)" % (name, len(cr.stdout)))
    return pulled


def main() -> int:
    global BD_PACKAGE
    ap = argparse.ArgumentParser(
        description="Automate BlackDex64 unpacking over adb (no root).")
    ap.add_argument("--app-id", default="com.world.youcinemobile",
                    help="target package (default: Youcine)")
    ap.add_argument("--label", default="YouCine",
                    help="target app label shown in BlackDex list")
    ap.add_argument("--out-dir", default="dumps/blackdex",
                    help="local output directory")
    ap.add_argument("--timeout", type=float, default=300.0,
                    help="max seconds to wait for the dump (default 300)")
    ap.add_argument("--serial", default=None, help="adb device serial")
    ap.add_argument("--adb", default=ADB_DEFAULT, help="adb binary")
    ap.add_argument("--dump-dir", default=None,
                    help="device dump dir override (default: auto "
                         "/storage/emulated/0/Download/dexDump/<app-id>)")
    ap.add_argument("--label-variants", default="YouCine,Youcine,youcine",
                    help="extra label texts to try matching")
    ap.add_argument("--bd-package", default=BD_PACKAGE,
                    help="BlackDex host package override "
                         "(top.niunaijun.blackdexa32 for the 32-bit build)")
    args = ap.parse_args()
    BD_PACKAGE = args.bd_package

    t0 = time.time()
    adb = Adb(args.adb, args.serial, tries=3, timeout=30.0)
    out_dir = Path(args.out_dir)

    # sanity: device + BlackDex installed (workflow pre-installs both)
    r = sh(adb, "pm path %s" % BD_PACKAGE)
    if r.returncode != 0 or "package:" not in (r.stdout or ""):
        log("FATAL: BlackDex64 (%s) is not installed" % BD_PACKAGE)
        return 2
    log("BlackDex64 installed: %s" % (r.stdout or "").strip().splitlines()[0])

    dump_dir = args.dump_dir or "%s/%s" % (DUMP_DIR_R, args.app_id)
    log("expected device dump dir: %s" % dump_dir)

    # 0. all-files-access (Android 11: required for Download/dexDump writes)
    grant_all_files(adb, args.app_id)

    # 1. launch
    if not launch_blackdex(adb):
        log("FATAL: could not start BlackDex")
        return 2

    # 2. wait for the list & find the row
    label = args.label
    center = wait_for_list(adb, label, args.app_id,
                           timeout=min(args.timeout, 120.0))
    if center is None:
        for variant in [v.strip() for v in args.label_variants.split(",")
                        if v.strip()] + [args.app_id]:
            if variant.lower() == label.lower():
                continue
            log("retrying list search with label %r" % variant)
            center = wait_for_list(adb, variant, args.app_id, timeout=30.0)
            if center:
                break
    if center is None:
        log("FATAL: target app row not found in BlackDex list "
            "(installed? abi-compatible? QUERY_ALL_PACKAGES?)")
        return 2

    # 3. tap -> dump starts (no confirmation dialog in BlackDex v3.2)
    if not tap_start_dump(adb, center):
        log("FATAL: tap failed")
        return 2
    time.sleep(3)

    # 3b. swallow any dialogs that pop up right after the tap
    #     (storage permission on first run, immediate failure, etc.)
    xml_text = ui_dump(adb, tries=2)
    if xml_text:
        screen = screen_texts(xml_text)
        if any(s in screen for s in FAIL_TEXTS):
            log("immediate failure dialog: %s" % screen[:160])
        btn = find_dialog_button(xml_text)
        if btn:
            log("post-tap dialog button %r -> tapping" % btn[1])
            sh(adb, "input tap %d %d" % btn[0])
            time.sleep(2)

    # 4. poll the dump output dir
    files, stable = poll_output_dir(adb, dump_dir, args.timeout)
    log("poll finished: %d file(s) on device, stable=%s (%.0fs elapsed)"
        % (len(files), stable, time.time() - t0))
    if files:
        for name, size in sorted(files.items()):
            log("  device file: %s (%d bytes)" % (name, size))

    # 5. pull
    pulled = pull_dump_dir(adb, dump_dir, out_dir) if files else 0
    # also grab the state of the :p proxy processes as diagnostics
    ps = sh(adb, "ps -A | grep -E '%s|youcine' | head -20" % BD_PACKAGE)
    for line in (ps.stdout or "").splitlines():
        log("  proc: %s" % line)

    if pulled > 0:
        log("SUCCESS: %d dumped file(s) pulled to %s" % (pulled, out_dir))
        return 0
    log("FAILURE: no dumped files pulled (see static-analysis/"
        "blackdex-internals.md for the failure-mode matrix)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
