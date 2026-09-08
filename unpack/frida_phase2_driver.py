#!/usr/bin/env python3
"""Frida phase-2 driver: RegisterNatives capture + class warm-up + re-dump.

Runs against the ORIGINAL packed APK on the native-arm64 redroid container
(the only environment where libexec's content gate fires - run
34133100459).  The packer-free rebuild v5 boots through every
non-protected layer and dies at the first VMP-protected method (runs
34166188171 / 34166250339); phase 2 extracts what only the packer engine
can materialize:

  1. spawn-gated start with the guard scripts (default
     02_bypass_ptrace.js - NEVER 05_tamper_guard.js here: its SIGSTOP at
     Instrumentation.newApplication freezes the process, incompatible with
     the long-running warm-up sweep below)
  2. 06_register_natives_table.js records the complete JNI registration
     table (~805 ACC_NATIVE: class -> method/signature -> fnPtr as
     module+offset)
  3. the class list is parsed locally from the phase-1 DEX dumps
  4. 07_class_warmup.js force-loads every class (Class.forName,
     initialize=true, loader cascade) so libexec re-materializes the
     ~45,238 extracted stub bodies in ART's [anon:dalvik-DEX data] pages
  5. 08_redump_dex.js dumps libexec.so / libijmDataEncryption.so memory
     images pre+post warm-up (SecLLVM self-modifies: memory != disk) plus
     a DEX-span census
  6. AUTHORITATIVE out-of-process re-dump via unpack/dexdata_extract.py
     (pread64/FOLL_FORCE crosses the -wxp no-read pieces in-process reads
     cannot), then repair via unpack/validate_and_extract_dex.py

Environment (exact names - the redroid shell flow depends on them):
  APP_ID           package (default com.world.youcinemobile)
  FRIDA_REMOTE     frida-server endpoint (default 127.0.0.1:4789)
  DEX_DIR          REQUIRED: directory with the 5 dumped .dex/.bin files
  OUT_DIR          output dir (default work/phase2)
  ADB              adb binary (default adb)
  SETTLE           seconds of app boot before the RN quiet-window (10)
  REG_QUIET        seconds without new RegisterNatives = stable (12)
  WARMUP_BATCH     class names per warmup rpc call (200)
  PHASE2_TIMEOUT   overall budget in seconds (900)
  GUARD_SCRIPTS    comma-separated guard script names loaded first
                   (default 02_bypass_ptrace.js)

Exit codes: 0 = table captured AND re-dump produced DEXes; 2 = zero
RegisterNatives registrations (check frida-server port / anti-frida);
3 = app died before any dump; 1 = setup error / partial result.
"""
from __future__ import annotations

import json
import mmap
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import frida


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip() or default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"[!] invalid {name}={raw!r} - using {default}", flush=True)
        return default


APP_ID = _env("APP_ID", "com.world.youcinemobile")
FRIDA_REMOTE = _env("FRIDA_REMOTE", "127.0.0.1:4789")
DEX_DIR = os.environ.get("DEX_DIR", "").strip()
OUT_DIR = os.path.abspath(_env("OUT_DIR", "work/phase2"))
ADB = _env("ADB", "adb")
SETTLE = _env_int("SETTLE", 10)
REG_QUIET = _env_int("REG_QUIET", 12)
WARMUP_BATCH = _env_int("WARMUP_BATCH", 200)
PHASE2_TIMEOUT = _env_int("PHASE2_TIMEOUT", 900)
GUARD_SCRIPTS = _env("GUARD_SCRIPTS", "02_bypass_ptrace.js")
PHASE2_MODE = _env("PHASE2_MODE", "capture")      # capture | matrix
PROBE_WAIT = _env_int("PROBE_WAIT", 8)              # matrix level wait

START = time.time()
DEADLINE = START + PHASE2_TIMEOUT

MIN_DEX_BYTES = 65536  # keep the 13.6 KiB packer stub DEX out of the sweep

OUT = Path(OUT_DIR)
LOG_F = None          # OUT/phase2.log, opened in main()
JSONL_F = None        # OUT/jni_table_events.jsonl, raw 'rn' events

# pipeline state
RN_TABLE: dict[str, list[dict]] = {}
DETACHED = {"flag": False, "reason": ""}
DUMPED_MODULES: set[str] = set()
DUMPS_DONE = False    # at least one successful in-proc module dump / redump


def note(line: str) -> None:
    print(line, flush=True)
    if LOG_F is not None:
        LOG_F.write(line + "\n")
        LOG_F.flush()


def on_detached(reason: str, *args) -> None:
    DETACHED["flag"] = True
    DETACHED["reason"] = str(reason)
    # the pipeline continues: out-of-proc pread64 dumping only needs a live
    # pid, and even that is checked per-step
    note(f"[!] session detached: {reason} (continuing pipeline - "
         f"out-of-proc dump will still be attempted)")


def reload_scripts(session, load_names):
    """(Re)load every guard + phase-2 script into a session with the single
    message handler.  Used for the initial load and for re-attaches."""
    scripts = {}
    for name, path in load_names:
        try:
            source = path.read_text(encoding="utf-8")
            s = session.create_script(source)
            s.on("message", on_message)
            s.load()
            scripts[name] = s
            note(f"[phase2] loaded {name}")
        except Exception as e:
            note(f"[!] loading {name} failed: {e}")
    return scripts


# ---------------------------------------------------------------------------
def adb_shell(cmd: str, timeout: float = 30.0) -> str:
    try:
        r = subprocess.run([ADB, "shell", cmd], capture_output=True,
                           text=True, timeout=timeout)
        return (r.stdout or "").strip()
    except Exception as e:
        note(f"[!] adb shell {cmd!r} failed: {e}")
        return ""


EMPTY_SCRIPT = """/* no-op probe script: hooks NOTHING, reports that it is
 * alive every second so the driver can tell 'script running' from
 * 'session dead'. */
'use strict';
var n = 0;
setInterval(function () {
  try { send({ type: 'probe_alive', tick: n++ }); } catch (e) {}
}, 1000);
"""


MATRIX_LEVELS = [
    (1, "agent + empty script (control)",
     ["@empty"]),
    (2, "agent + 06+07+08+capture (CANDIDATE A: full capture stack)",
     ["06_register_natives_table.js", "07_class_warmup.js",
      "08_redump_dex.js", "capture_aes_key.js"]),
    (3, "agent + 06+07+08 (capture stack without the AES hooks)",
     ["06_register_natives_table.js", "07_class_warmup.js",
      "08_redump_dex.js"]),
    (4, "agent + 06 only (pure-rpc observe sweep)",
     ["06_register_natives_table.js"]),
    (5, "agent + 07 only (rpc warm-up, no hooks)",
     ["07_class_warmup.js"]),
    (6, "agent + 08 only (Memory reads + Java File)",
     ["08_redump_dex.js"]),
    (7, "agent + capture_aes_key only (libcrypto inline hooks)",
     ["capture_aes_key.js"]),
    (8, "agent + 02 only (ptrace replace)",
     ["02_bypass_ptrace.js"]),
    (9, "agent + 09 only (libc inline hooks - KNOWN KILLER)",
     ["09_hide_frida.js"]),
    (10, "@probe: Java.perform at the gate (init-window theory)",
     ["@probe-java-gate"]),
    (11, "@probe: reflection at the gate (init-window theory)",
     ["@probe-reflect-gate"]),
    (12, "@probe: reflection DELAYED 10s (after the init window)",
     ["@probe-reflect-delayed"]),
]

# inline probe scripts for the matrix (theory: the packer's init window
# kills ANY agent-side Java activity; everything must be deferred)
PROBE_SCRIPTS = {
    "@probe-java-gate": """'use strict';
console.log('[probe] gate-time Java.perform...');
Java.perform(function () {
  try {
    Java.use('java.lang.Class');
    console.log('[probe] gate Java.perform OK');
  } catch (e) { console.log('[probe] ' + e); }
});
""",
    "@probe-reflect-gate": """'use strict';
console.log('[probe] gate-time reflection...');
Java.perform(function () {
  try {
    var ms = Java.use('android.util.Log').class.getDeclaredMethods();
    console.log('[probe] gate reflection OK: ' + ms.length + ' methods');
  } catch (e) { console.log('[probe] ' + e); }
});
""",
    "@probe-reflect-delayed": """'use strict';
console.log('[probe] reflection deferred by 10s');
setTimeout(function () {
  try {
    Java.perform(function () {
      var ms = Java.use('android.util.Log').class.getDeclaredMethods();
      console.log('[probe] delayed reflection OK: ' + ms.length + ' methods');
      send({ type: 'probe_reflect_ok', methods: ms.length });
    });
  } catch (e) { console.log('[probe] ' + e); }
}, 10000);
""",
}


def probe_matrix(device, scripts_dir) -> list:
    """Determine which instrumentation layer trips iJiami's death ladder.
    Every level starts from a CLEAN app state (am force-stop + pm clear) -
    pm clear also wipes any on-disk tamper flag a previous level could
    have left.  A final L0 control re-run tells whether a persistent flag
    survived the clears (or the app simply crash-looped itself)."""
    results = []
    try:
        mgr = frida.get_device_manager()
        device = mgr.add_remote_device(FRIDA_REMOTE)
    except Exception as e:
        note(f"[matrix] frida device failed: {e}")
        return [{"level": -1, "error": str(e)}]

    for level, desc, script_names in MATRIX_LEVELS:
        entry = {"level": level, "desc": desc, "status": "?",
                 "seconds": 0.0}
        t0 = time.time()
        # clean state
        adb_shell(f"am force-stop {APP_ID}", 15)
        adb_shell(f"pm clear {APP_ID}", 30)
        time.sleep(1.5)
        try:
            pid = device.spawn([APP_ID])
        except Exception as e:
            entry["status"] = f"spawn-failed: {e}"
            results.append(entry)
            continue
        session = None
        detached = {"flag": False}
        level_wait = PROBE_WAIT
        if level >= 1:
            try:
                session = device.attach(pid)

                def _on_det(reason, *a, _d=detached):
                    _d["flag"] = True
                session.on("detached", _on_det)
                for name in script_names:
                    if name == "@empty":
                        source = EMPTY_SCRIPT
                    elif name in PROBE_SCRIPTS:
                        source = PROBE_SCRIPTS[name]
                        if name == "@probe-reflect-delayed":
                            level_wait = PROBE_WAIT + 8  # see the callback
                    else:
                        source = (scripts_dir / name).read_text(
                            encoding="utf-8")
                    s = session.create_script(source)
                    s.on("message", on_message)
                    s.load()
            except Exception as e:
                entry["status"] = f"attach/load-failed: {e}"
                results.append(entry)
                try:
                    device.resume(pid)
                except Exception:
                    pass
                continue
        try:
            device.resume(pid)
        except Exception as e:
            entry["status"] = f"resume-failed: {e}"
        # watch the level for level_wait seconds
        while time.time() - t0 < level_wait:
            if detached["flag"]:
                break
            time.sleep(0.5)
        now = pidof(APP_ID)
        if now is None:
            entry["status"] = "dead"
        elif now == pid:
            entry["status"] = "alive"
        else:
            entry["status"] = f"restarted (pid {pid} -> {now})"
        entry["seconds"] = round(time.time() - t0, 1)
        entry["pid"] = pid
        results.append(entry)
        note(f"[matrix] L{level} [{desc}] -> {entry['status']} "
             f"({entry['seconds']}s)")
        # teardown
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass
        adb_shell(f"am force-stop {APP_ID}", 15)

    # control: one more clean L0 (detects persistent flags / crash loops)
    adb_shell(f"pm clear {APP_ID}", 30)
    time.sleep(1.5)
    try:
        pid = device.spawn([APP_ID])
        device.resume(pid)
        time.sleep(PROBE_WAIT)
        now = pidof(APP_ID)
        ctrl = {"level": 0, "desc": "CONTROL re-run (spawn only, after all "
                                    "levels + pm clear)",
                "status": "dead" if now is None else
                          ("alive" if now == pid else f"restarted ({now})"),
                "pid": pid}
        results.append(ctrl)
        note(f"[matrix] control -> {ctrl['status']}")
        adb_shell(f"am force-stop {APP_ID}", 15)
    except Exception as e:
        results.append({"level": 0, "desc": "CONTROL", "error": str(e)})
    return results


def try_reattach(device, load_names, old_session, old_scripts, reattaches):
    """iJiami's death ladder can SIGKILL the instrumented process ~1s after
    resume (run 34171467849: pid 3480 killed, AMS restarted the app at 3512
    uninstrumented and the whole capture was lost).  If the session died but
    the app is alive at a NEW pid, attach there and re-load every script:
    late/lazy RegisterNatives, the warm-up sweep, module dumps and the AES
    key hooks all still work on the restarted instance."""
    new_pid = pidof(APP_ID)
    if new_pid is None:
        # AMS restarts a killed top-activity process within ~0.5-2s; poll
        # briefly before giving up (run 34172332498 post-mortem: the check
        # ran a single pidof a few ms after the death, missed the restart
        # that landed moments later and the capture ended with rc=3)
        for _ in range(12):
            if out_of_budget("re-attach restart-wait"):
                break
            time.sleep(0.5)
            new_pid = pidof(APP_ID)
            if new_pid is not None:
                note(f"[phase2] app restarted at pid {new_pid} "
                     "(restart-wait) - re-attaching")
                break
    if new_pid is None:
        note("[phase2] re-attach skipped: app is dead "
             "(no AMS restart within the wait window)")
        return old_session, old_scripts, None, None, None, reattaches
    try:
        new_session = device.attach(new_pid)
    except Exception as e:
        note(f"[!] re-attach to restarted pid {new_pid} failed: {e}")
        return old_session, old_scripts, None, None, None, reattaches
    new_session.on("detached", on_detached)
    new_scripts = reload_scripts(new_session, load_names)
    if not new_scripts:
        note("[!] re-attach produced no scripts - capture is over")
        return old_session, old_scripts, None, None, None, reattaches
    DETACHED["flag"] = False
    DETACHED["reason"] = ""
    reattaches += 1
    note(f"[phase2] RE-ATTACHED to restarted pid {new_pid} "
         f"(attempt {reattaches}) - all scripts reloaded")
    return (new_session, new_scripts,
            new_scripts.get("06_register_natives_table.js"),
            new_scripts.get("07_class_warmup.js"),
            new_scripts.get("08_redump_dex.js"),
            reattaches)


def merge_rn(cls: str, methods) -> None:
    """Accumulate RegisterNatives rows; dedup by (name, sig) keeping the
    LATEST fn - libexec re-registers methods as classes re-materialize."""
    lst = RN_TABLE.setdefault(cls, [])
    index = {(m.get("name"), m.get("sig")): i for i, m in enumerate(lst)}
    for m in methods:
        if not isinstance(m, dict):
            continue
        key = (m.get("name"), m.get("sig"))
        if key in index:
            lst[index[key]] = m
        else:
            index[key] = len(lst)
            lst.append(m)


def on_message(message: dict, data: object) -> None:
    mtype = message.get("type")
    if mtype == "send":
        payload = message.get("payload")
        if isinstance(payload, dict):
            t = str(payload.get("type") or payload.get("t") or "")
            if t == "rn":
                cls = str(payload.get("class"))
                methods = payload.get("methods") or []
                merge_rn(cls, methods)
                if JSONL_F is not None:
                    JSONL_F.write(json.dumps(payload, ensure_ascii=False) + "\n")
                    JSONL_F.flush()
                total = sum(len(v) for v in RN_TABLE.values())
                note(f"[rn] {cls}: +{len(methods)} "
                     f"(table {len(RN_TABLE)} classes / {total} methods)")
            elif t == "warmup_progress":
                note(f"[warmup] done {payload.get('done')}/{payload.get('total')} "
                     f"ok={payload.get('ok')} notfound={payload.get('notfound')} "
                     f"fail={payload.get('fail')}")
            elif (t == "rn_warn" or t == "dexcensus" or t == "aes_key"
                    or t == "kill_block" or t == "hidefrida"
                    or t.startswith("redump_")):
                note("[js] " + json.dumps(payload, ensure_ascii=False)[:200])
            else:
                note("[js] " + str(payload)[:200])
        else:
            note("[js] " + str(payload)[:200])
    elif mtype == "error":
        desc = str(message.get("description", ""))
        stack = str(message.get("stack") or "")
        first = stack.splitlines()[0] if stack else ""
        note("[js!] " + desc + ((" " + first) if first else ""))
    elif mtype == "log":
        note("[js] " + str(message.get("payload", ""))[:200])
    else:
        note("[js?] " + str(message)[:200])


# ---------------------------------------------------------------------------
# frida rpc helpers - every call wrapped, a failure never kills the pipeline
# ---------------------------------------------------------------------------
def rpc(script, name: str, *args):
    exp = getattr(script, "exports", None)
    if exp is None:
        raise RuntimeError("script.exports unavailable (frida too old?)")
    fn = getattr(exp, name, None)
    if fn is None or not callable(fn):
        raise RuntimeError(f"rpc export '{name}' missing")
    return fn(*args)


def rpc_watchdog(script, name: str, args: tuple, desc: str, timeout: float = 300.0):
    """frida rpc has no timeout of its own - run the call in a daemon
    thread and move on after `timeout` seconds (the call may still
    complete in the background).  A stuck script thread blocks all LATER
    rpc calls on that script, so callers decide whether to keep going."""
    box = {}

    def _run():
        try:
            box["result"] = ("ok", rpc(script, name, *args))
        except Exception as e:  # noqa: BLE001 - log everything, never die
            box["result"] = ("err", f"{type(e).__name__}: {e}")

    th = threading.Thread(target=_run, daemon=True, name=f"rpc-{name}")
    th.start()
    th.join(timeout)
    if th.is_alive():
        note(f"[!] watchdog: {desc} exceeded {timeout:.0f}s - continuing "
             f"(the call may still complete in the background)")
        return None
    status, val = box["result"]
    if status != "ok":
        note(f"[!] {desc} failed: {val}")
        return None
    return val


def out_of_budget(what: str) -> bool:
    if time.time() > DEADLINE:
        note(f"[!] PHASE2_TIMEOUT ({PHASE2_TIMEOUT}s) exceeded before {what} "
             f"- skipping it (finalization still runs)")
        return True
    return False


# ---------------------------------------------------------------------------
# quiet-window: poll 06 count() every 1s, stable when no increase for
# REG_QUIET seconds, capped at PHASE2_TIMEOUT // 3
# ---------------------------------------------------------------------------
def wait_rn_quiet(rn_script, stage: str, cap_s: int) -> int:
    note(f"[phase2] {stage}: RegisterNatives quiet-window "
         f"(REG_QUIET={REG_QUIET}s, cap {cap_s}s)")
    last = -1
    last_change = time.time()
    started = time.time()
    while time.time() - started < cap_s:
        if DETACHED["flag"]:
            note(f"[phase2] {stage}: session detached - stopping quiet-window")
            break
        try:
            c = rpc(rn_script, "count")
        except Exception as e:
            note(f"[phase2] {stage}: count() rpc failed "
                 f"({type(e).__name__}: {e}) - stopping quiet-window")
            break
        if c is None:
            break
        if c != last:
            last = c
            last_change = time.time()
            note(f"[phase2] {stage}: rn count={c}")
        elif time.time() - last_change >= REG_QUIET:
            note(f"[phase2] {stage}: stable at {last} methods")
            break
        time.sleep(1.0)
    return max(last, 0)


# ---------------------------------------------------------------------------
# 08_redump_dex.js orchestration
# ---------------------------------------------------------------------------
def module_dump_cycle(redump_script, tag: str) -> None:
    global DUMPS_DONE
    if DETACHED["flag"]:
        note(f"[phase2] skipping {tag} module dumps: session detached")
        return
    # explicit + discovered (ijm*/exec*); dedup so libexec.so is not
    # dumped twice (the explicit entry and the 'exec' discovery overlap)
    wanted = ["libexec.so", "libijmDataEncryption.so"]
    for flt in ("ijm", "exec"):
        found = rpc_watchdog(redump_script, "listmodules", (flt,),
                             f"listmodules('{flt}') [{tag}]", 120.0)
        if isinstance(found, list):
            for m in found:
                if isinstance(m, dict) and m.get("name"):
                    wanted.append(str(m["name"]))
    seen: set[str] = set()
    uniq = []
    for n in wanted:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    note(f"[phase2] {tag} module dump set: {', '.join(uniq)}")
    for name in uniq:
        if DETACHED["flag"]:
            break
        res = rpc_watchdog(redump_script, "dumpmodule", (name, tag),
                           f"dumpmodule({name}, {tag})", 240.0)
        if res is None:
            continue
        if isinstance(res, dict) and res.get("error"):
            note(f"[phase2] dumpmodule {name} [{tag}]: {res.get('error')}")
            continue
        DUMPED_MODULES.add(name)
        if res.get("written") or res.get("readable_bytes"):
            DUMPS_DONE = True
        note(f"[phase2] dumpmodule {name} [{tag}]: "
             f"{json.dumps(res, ensure_ascii=False)[:200]}")


def dex_census(redump_script, tag: str) -> None:
    if DETACHED["flag"]:
        note(f"[phase2] skipping {tag} dexcensus: session detached")
        return
    res = rpc_watchdog(redump_script, "dexcensus", (),
                       f"dexcensus [{tag}]", 120.0)
    if not isinstance(res, dict):
        return
    try:
        (OUT / f"dexcensus_{tag}.json").write_text(
            json.dumps(res, indent=2) + "\n", encoding="utf-8")
    except Exception as e:
        note(f"[phase2] dexcensus[{tag}] write failed: {e}")
    spans = res.get("spans") or []
    parts = "; ".join(
        f"{s.get('start')}-{s.get('end')} r={s.get('readable')} "
        f"holes={s.get('holes')} dex={s.get('dex_magic')} "
        f"size={s.get('dex_size')}" for s in spans[:8])
    note(f"[phase2] dexcensus[{tag}]: {len(spans)} spans"
         + (f" [{parts}]" if parts else ""))


# ---------------------------------------------------------------------------
# warm-up sweep via 07_class_warmup.js
# ---------------------------------------------------------------------------
def write_warmup_stats(stats: dict, done: int, total: int,
                       loaded_pre=None, loaded_post=None) -> None:
    # crash-safe partial: rewritten after every chunk
    try:
        payload = {
            "names_done": done,
            "names_total": total,
            "ok": stats["ok"],
            "notfound": stats["notfound"],
            "fail": stats["fail"],
            "errors": stats["errors"][:20],
            "loaded_pre": loaded_pre,
            "loaded_post": loaded_post,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        (OUT / "warmup_stats.json").write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except Exception as e:
        note(f"[phase2] warmup_stats write failed: {e}")


def run_warmup(warm_script, names: list[str]) -> dict:
    stats = {"ok": 0, "notfound": 0, "fail": 0, "errors": []}
    total = len(names)
    note(f"[phase2] warm-up: {total} class names in batches of {WARMUP_BATCH}")
    loaded_pre = rpc_watchdog(warm_script, "loadedcount", (),
                              "loadedcount (pre)", 120.0) \
        if not DETACHED["flag"] else None
    if loaded_pre is not None:
        note(f"[phase2] loaded classes before warm-up: {loaded_pre}")
    write_warmup_stats(stats, 0, total, loaded_pre=loaded_pre)
    done = 0
    for i in range(0, total, WARMUP_BATCH):
        if DETACHED["flag"]:
            note("[phase2] session detached mid-warm-up - stopping sweep "
                 "(continuing pipeline)")
            break
        if out_of_budget(f"warm-up chunk {i // WARMUP_BATCH + 1}"):
            break
        chunk = names[i:i + WARMUP_BATCH]
        res = rpc_watchdog(warm_script, "warmup", (chunk,),
                           f"warmup chunk {i // WARMUP_BATCH + 1} "
                           f"({len(chunk)} names)", 300.0)
        if res is None:
            # the script thread is stuck or the call failed: further chunks
            # would just queue behind it - abort the sweep, keep moving
            note("[phase2] warm-up chunk stalled/failed - "
                 "aborting remaining chunks")
            break
        if isinstance(res, dict):
            stats["ok"] += int(res.get("ok", 0) or 0)
            stats["notfound"] += int(res.get("notfound", 0) or 0)
            stats["fail"] += int(res.get("fail", 0) or 0)
            for e in (res.get("errors") or [])[:20]:
                if len(stats["errors"]) < 20:
                    stats["errors"].append(str(e))
        done = i + len(chunk)
        write_warmup_stats(stats, done, total, loaded_pre=loaded_pre)
    loaded_post = None
    if not DETACHED["flag"] and not out_of_budget("loadedcount (post)"):
        loaded_post = rpc_watchdog(warm_script, "loadedcount", (),
                                   "loadedcount (post)", 120.0)
    if loaded_post is not None:
        note(f"[phase2] loaded classes after warm-up: {loaded_post}")
    write_warmup_stats(stats, done, total, loaded_pre=loaded_pre,
                       loaded_post=loaded_post)
    return stats


# ---------------------------------------------------------------------------
# minimal DEX parser: class list from the phase-1 dumps (stdlib only)
# header offsets: string_ids size@56 off@60, type_ids size@64 off@68,
# class_defs size@96 off@100; string items are MUTF-8: uleb128 length,
# then bytes up to NUL
# ---------------------------------------------------------------------------
def _read_uleb128(mm: mmap.mmap, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if off >= len(mm):
            break
        b = mm[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 28:
            break  # corrupt length - give up rather than loop forever
    return result, off


def parse_dex_classes(path: Path) -> tuple[list[str], str]:
    size = path.stat().st_size
    if size < 0x70:
        return [], f"{size} bytes - smaller than a DEX header"
    with open(path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            if mm[:4] != b"dex\n":
                return [], f"magic {bytes(mm[:8])!r} (not a standard dex)"
            file_size = struct.unpack_from("<I", mm, 32)[0]
            endian_tag = struct.unpack_from("<I", mm, 40)[0]
            if endian_tag != 0x12345678:
                return [], f"endian tag {endian_tag:#x}"
            if not (0x70 <= file_size <= 200_000_000):
                return [], f"implausible file_size {file_size}"
            str_size, str_off = struct.unpack_from("<II", mm, 56)
            type_size, type_off = struct.unpack_from("<II", mm, 64)
            cls_size, cls_off = struct.unpack_from("<II", mm, 96)
            if (str_off + 4 * str_size > size
                    or type_off + 4 * type_size > size
                    or cls_off + 32 * cls_size > size):
                return [], (f"ids out of bounds (strings={str_size}@{str_off:#x} "
                            f"types={type_size}@{type_off:#x} "
                            f"classes={cls_size}@{cls_off:#x})")
            strings: list[str] = []
            for i in range(str_size):
                so = struct.unpack_from("<I", mm, str_off + 4 * i)[0]
                if so >= size:
                    strings.append("")  # keep indices aligned
                    continue
                _, p = _read_uleb128(mm, so)
                end = mm.find(b"\x00", p, size)
                if end < 0:
                    end = min(p + 256, size)
                strings.append(mm[p:end].decode("utf-8", "replace"))
            names: list[str] = []
            for i in range(cls_size):
                type_idx = struct.unpack_from("<I", mm, cls_off + 32 * i)[0]
                if type_idx >= type_size:
                    continue
                str_idx = struct.unpack_from("<I", mm, type_off + 4 * type_idx)[0]
                if str_idx >= str_size:
                    continue
                desc = strings[str_idx]
                # 'Lx/y/Z;' -> 'x.y.Z' (inner classes keep their '$')
                if len(desc) > 2 and desc.startswith("L") and desc.endswith(";"):
                    names.append(desc[1:-1].replace("/", "."))
            status = (f"file_size={file_size} strings={str_size} "
                      f"types={type_size} class_defs={cls_size}")
            return names, status
        finally:
            mm.close()


def collect_dex_classes(dexdir: Path) -> list[str]:
    files = sorted(p for p in dexdir.iterdir()
                   if p.is_file() and p.suffix in (".dex", ".bin"))
    if not files:
        note(f"[!] no .dex/.bin files in {dexdir}")
        return []
    names: set[str] = set()
    for p in files:
        size = p.stat().st_size
        try:
            classes, status = parse_dex_classes(p)
        except Exception as e:
            note(f"[phase2] {p.name}: parse error {type(e).__name__}: {e}")
            continue
        if size < MIN_DEX_BYTES:
            # still tried the header (above) for diagnostics; the 13.6 KiB
            # packer stub DEX must not enter the warm-up sweep
            note(f"[phase2] {p.name}: {size} bytes - below 64 KiB: skipped "
                 f"for warm-up (packer stub?); header: {status}")
            continue
        note(f"[phase2] {p.name}: {status} -> {len(classes)} classes")
        names.update(classes)
    return sorted(names)


# ---------------------------------------------------------------------------
# misc helpers
# ---------------------------------------------------------------------------
def pidof(app: str) -> int | None:
    try:
        r = subprocess.run([ADB, "shell", f"pidof {app}"],
                           capture_output=True, timeout=15)
        txt = (r.stdout or b"").decode("utf-8", "replace").strip()
        if txt.split():
            return int(txt.split()[0])
    except Exception as e:
        note(f"[phase2] pidof failed: {e}")
    return None


def merge_move(src: Path, dst: Path) -> None:
    """Merge pulled directory trees (adb pull nests remote dirs one level
    deeper; two pull sources must not clobber each other)."""
    if not src.exists():
        return
    try:
        if dst.exists():
            if src.is_dir() and dst.is_dir():
                for child in src.iterdir():
                    merge_move(child, dst / child.name)
                try:
                    src.rmdir()
                except OSError:
                    pass
            else:
                dst.unlink()
                shutil.move(str(src), str(dst))
        else:
            shutil.move(str(src), str(dst))
    except Exception as e:
        note(f"[phase2] merge_move {src} -> {dst}: {e}")


def pull_inproc_artifacts() -> None:
    # 08 writes to /data/local/tmp/youcine_re_phase2 when SELinux allows
    # it, else falls back to the app's own files dir - pull BOTH
    # (best-effort, errors ignored) and flatten the nesting.
    pulls = [
        ("/data/local/tmp/youcine_re_phase2", OUT / "inproc"),
        (f"/data/data/{APP_ID}/files/youcine_re_phase2", OUT / "inproc"),
    ]
    for remote, dst in pulls:
        try:
            r = subprocess.run([ADB, "pull", remote, str(dst)],
                               capture_output=True, timeout=300)
            err = (r.stderr or b"").decode("utf-8", "replace").strip()
            note(f"[phase2] adb pull {remote} rc={r.returncode}"
                 + (f" ({err.splitlines()[-1][:120]})" if err else ""))
        except Exception as e:
            note(f"[phase2] adb pull {remote} failed: {e}")
        merge_move(dst / "youcine_re_phase2", dst)


def run_step_subprocess(cmd: list[str], tag: str, timeout: float) -> int:
    note(f"[phase2] $ {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        note(f"[!] {tag} timed out ({timeout:.0f}s)")
        return -1
    except Exception as e:
        note(f"[!] {tag} failed: {e}")
        return -1
    for line in (r.stdout or "").splitlines():
        note(f"[{tag}] {line}")
    for line in (r.stderr or "").splitlines():
        note(f"[{tag}!] {line}")
    note(f"[phase2] {tag} rc={r.returncode}")
    return r.returncode


# ---------------------------------------------------------------------------
def main() -> int:
    global LOG_F, JSONL_F, RN_TABLE
    here = Path(__file__).resolve().parent
    repo = here.parent
    scripts_dir = repo / "frida-scripts"

    # -- step 1: prepare output dirs + log -------------------------------
    for sub in ("redump", "repaired", "inproc"):
        (OUT / sub).mkdir(parents=True, exist_ok=True)
    LOG_F = open(OUT / "phase2.log", "a", encoding="utf-8")
    JSONL_F = open(OUT / "jni_table_events.jsonl", "a", encoding="utf-8")
    note(f"[phase2] === frida phase 2 start (pid {os.getpid()}) ===")
    note(f"[phase2] env: APP_ID={APP_ID} FRIDA_REMOTE={FRIDA_REMOTE} "
         f"DEX_DIR={DEX_DIR} OUT_DIR={OUT_DIR} ADB={ADB} SETTLE={SETTLE} "
         f"REG_QUIET={REG_QUIET} WARMUP_BATCH={WARMUP_BATCH} "
         f"PHASE2_TIMEOUT={PHASE2_TIMEOUT} GUARD_SCRIPTS={GUARD_SCRIPTS}")

    if not DEX_DIR:
        note("[!] DEX_DIR is required (dir with the 5 dumped .dex/.bin "
             "files, e.g. the unpacked dumps-1.17.6 release) - aborting")
        return 1
    dexdir = Path(DEX_DIR)
    if not dexdir.is_dir():
        note(f"[!] DEX_DIR {dexdir} is not a directory - aborting")
        return 1

    # -- step 2: script list (guards + the three phase-2 scripts) --------
    guard_names = [s.strip() for s in GUARD_SCRIPTS.split(",") if s.strip()]
    phase2_names = [
        "06_register_natives_table.js",
        "07_class_warmup.js",
        "08_redump_dex.js",
    ]
    load_names = []
    for name in guard_names + phase2_names:
        path = scripts_dir / name
        if not path.is_file():
            if name in guard_names:
                note(f"[phase2] guard script missing, skipping: {path}")
            else:
                note(f"[!] required phase-2 script missing: {path} - aborting")
                return 1
        else:
            load_names.append((name, path))

    # -- optional: detection-matrix probe BEFORE the capture pipeline -----
    # Round 34175038958 (deep-stealth server): L0 spawn-gate ALIVE,
    # L1 agent-presence ALIVE (the stealth patch defeated the memory
    # scan!), L2 + 09's libc inline hooks DEAD - the packer detects the
    # MODIFIED LIBC PROLOGUES (code-integrity check).  02/09 are dropped
    # from the capture config; the matrix now tests each capture layer in
    # ISOLATION and picks the guard set for the actual capture run:
    #   candidate A (level 2) = 06+07+08+capture_aes_key, no guards
    #   candidate B (level 3) = 06+07+08 without the crypto hooks
    if PHASE2_MODE == "matrix":
        matrix_results = probe_matrix(device=None, scripts_dir=scripts_dir)
        (OUT / "matrix.json").write_text(
            json.dumps(matrix_results, indent=2) + "\n", encoding="utf-8")
        note(f"[phase2] matrix results: {json.dumps(matrix_results)}")

        def _status(level: int) -> str:
            for r in matrix_results:
                if r.get("level") == level:
                    return str(r.get("status") or "?")
            return "?"

        if _status(2) == "alive":
            chosen_guards = ["capture_aes_key.js"]
            note("[phase2] matrix verdict: candidate A (06+07+08+capture) "
                 "survives - capture with the AES key hooks")
        elif _status(3) == "alive":
            chosen_guards = []
            note("[phase2] matrix verdict: candidate B (06+07+08 without "
                 "crypto hooks) survives - dropping capture_aes_key")
        else:
            chosen_guards = []
            note("[!] matrix verdict: NO capture configuration survives - "
                 "running the pipeline anyway for the evidence")
        # rebuild the load list from the decided guards
        load_names = []
        for name in chosen_guards + phase2_names:
            p = scripts_dir / name
            if p.is_file():
                load_names.append((name, p))
            else:
                note(f"[phase2] decided guard missing, skipping: {p}")
        note(f"[phase2] capture-phase script list: "
             f"{[n for n, _ in load_names]}")

    # -- step 3: remote device, spawn gated, attach ----------------------
    try:
        mgr = frida.get_device_manager()
        device = mgr.add_remote_device(FRIDA_REMOTE)
    except Exception as e:
        note(f"[!] frida device failed: {type(e).__name__}: {e} "
             f"(is frida-server listening on {FRIDA_REMOTE}?)")
        return 1
    # spawn with cooldown + retries: after the matrix's rapid spawn/kill
    # cycles AMS needs breathing room (run 34176663572: the capture spawn
    # timed out right after 13 matrix levels - the app is fine, the
    # launcher is just slow)
    pid = None
    for attempt in range(1, 4):
        try:
            pid = device.spawn([APP_ID])
            break
        except Exception as e:
            note(f"[!] frida spawn failed (attempt {attempt}/3): "
                 f"{type(e).__name__}: {e}")
            if attempt == 3:
                note("[!] spawn exhausted - aborting")
                return 1
            adb_shell(f"am force-stop {APP_ID}", 15)
            note("[phase2] cooldown 25s before the retry")
            time.sleep(25)
    note(f"[phase2] spawned {APP_ID} pid={pid} (gated)")
    try:
        session = device.attach(pid)
    except Exception as e:
        note(f"[!] attach failed: {e} - aborting")
        return 1
    session.on("detached", on_detached)

    # -- step 4: load every script with the single message handler -------
    scripts = reload_scripts(session, load_names)
    if not scripts:
        note("[!] no frida script could be loaded - aborting")
        return 1
    rn_script = scripts.get("06_register_natives_table.js")
    warm_script = scripts.get("07_class_warmup.js")
    redump_script = scripts.get("08_redump_dex.js")

    # -- step 5: resume + settle (app boot) ------------------------------
    reattaches = 0
    max_reattach = _env_int("MAX_REATTACH", 2)
    try:
        device.resume(pid)
        note(f"[phase2] resumed pid={pid}; settling {SETTLE}s for app boot")
    except Exception as e:
        note(f"[!] resume failed: {e} (continuing - the app may self-start)")
    # sub-second settle poll: the death ladder can kill the gated process
    # ~1s after resume (run 34171467849) - reacting fast lets the re-attach
    # land on the AMS-restarted instance while packer init is still running
    settle_start = time.time()
    while time.time() - settle_start < SETTLE:
        if DETACHED["flag"]:
            break
        time.sleep(0.5)
    note(f"[phase2] settle done; app pid={pidof(APP_ID)}"
         + (f" (detached: {DETACHED['reason']})" if DETACHED["flag"] else ""))

    # checkpoint 1: re-attach if the gated process was killed and AMS
    # restarted the app (fresh instance runs the packer init again)
    if DETACHED["flag"] and reattaches < max_reattach \
            and not out_of_budget("re-attach 1"):
        session, scripts, rn_script, warm_script, redump_script, reattaches = \
            try_reattach(device, load_names, session, scripts, reattaches)

    # -- step 6: pre-warm-up RegisterNatives quiet-window ----------------
    quiet_cap = max(1, PHASE2_TIMEOUT // 3)
    if rn_script is not None:
        wait_rn_quiet(rn_script, "pre-warmup", quiet_cap)
    else:
        note("[phase2] 06 script not loaded - skipping RN quiet-window")

    # extra evidence: DEX-span census before the warm-up (how much is
    # readable in-proc BEFORE libexec re-materializes the ~45k stubs)
    if redump_script is not None:
        dex_census(redump_script, "pre")

    # -- step 7: pre-warm-up native module memory dumps ------------------
    # (SecLLVM self-modifies: capture the pre-warm-up image for diffing;
    # nothing pulled yet - the pull happens after step 11)
    if redump_script is not None:
        module_dump_cycle(redump_script, "pre")

    # -- step 8: class list from the phase-1 DEX dumps -------------------
    names = collect_dex_classes(dexdir)
    note(f"[phase2] warm-up list: {len(names)} unique class names from {dexdir}")
    if not names:
        note("[!] empty warm-up list - the sweep will be skipped "
             "(check DEX_DIR contents)")

    # checkpoint 2: the death ladder may fire again mid-pipeline (second
    # kill of the re-attached instance) - re-attach once more before the
    # warm-up sweep, the most valuable capture step
    if DETACHED["flag"] and reattaches < max_reattach \
            and not out_of_budget("re-attach 2"):
        session, scripts, rn_script, warm_script, redump_script, reattaches = \
            try_reattach(device, load_names, session, scripts, reattaches)

    # -- step 9: warm-up sweep -------------------------------------------
    if warm_script is not None and names:
        warm_stats = run_warmup(warm_script, names)
    else:
        warm_stats = {"ok": 0, "notfound": 0, "fail": 0, "errors": []}
        if warm_script is None:
            note("[phase2] 07 script not loaded - skipping warm-up")

    # -- step 9b: OBSERVE-ONLY RegisterNatives sweep (06 v3) --------------
    # 06 no longer hooks anything (every interception - inline code patch
    # or vtable data swap - is detected by the packer's VMP); it runs a
    # post-hoc Java reflection sweep over the loaded classes once the
    # warm-up has materialized them, so the table is read AFTER the sweep.
    if rn_script is not None and names:
        sweep_rpc = getattr(rn_script.exports, "sweep", None)
        if sweep_rpc is not None:
            remaining = max(1, int(DEADLINE - time.time()))
            r = rpc_watchdog(rn_script, "sweep",
                             (min(300000, remaining * 1000),),
                             "rn sweep (post-warm-up)", 600.0)
            note(f"[phase2] rn sweep result: {r}")

    # -- step 10: post-warm-up quiet-window (new registrations expected
    # as libexec re-materializes classes) --------------------------------
    if rn_script is not None and not DETACHED["flag"] \
            and not out_of_budget("post-warmup quiet-window"):
        remaining = max(1, int(DEADLINE - time.time()))
        wait_rn_quiet(rn_script, "post-warmup", min(quiet_cap, remaining))

    # extra evidence: DEX-span census after the warm-up
    if redump_script is not None and not out_of_budget("dexcensus (post)"):
        dex_census(redump_script, "post")

    # -- step 11: post-warm-up module dumps (same modules, tag 'post') --
    if redump_script is not None and not out_of_budget("post module dumps"):
        module_dump_cycle(redump_script, "post")

    # -- step 12: final JNI table ----------------------------------------
    rn_methods_total = sum(len(v) for v in RN_TABLE.values())
    if rn_script is not None and not DETACHED["flag"] \
            and not out_of_budget("jni table cross-check"):
        # cross-check with the in-script table; adopt it if events were
        # lost (send() drop) or the driver-side accumulation is empty
        tbl = rpc_watchdog(rn_script, "table", (), "table() cross-check", 120.0)
        if isinstance(tbl, dict):
            tbl_methods = sum(len(v) for v in tbl.values())
            note(f"[phase2] jni table cross-check: driver-side "
                 f"{rn_methods_total} vs script-side {tbl_methods}")
            if tbl_methods > rn_methods_total:
                if rn_methods_total == 0:
                    note("[phase2] adopting script-side table "
                         "(driver-side accumulation was empty)")
                RN_TABLE = tbl
                rn_methods_total = tbl_methods
    (OUT / "jni_table.json").write_text(
        json.dumps(RN_TABLE, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8")
    note(f"[phase2] jni_table: {len(RN_TABLE)} classes / {rn_methods_total} "
         f"methods -> {OUT / 'jni_table.json'}")

    # -- step 13: AUTHORITATIVE out-of-process re-dump -------------------
    # in-proc reads cannot cross the -wxp no-read pieces of the DEX spans;
    # pread64 with FOLL_FORCE can (dexdata_extract.py SIGSTOPs the app
    # itself and SIGCONTs at the end)
    redump_rc = None
    app_pid = pidof(APP_ID)
    if app_pid is None:
        note("[!] app is dead - skipping out-of-proc redump "
             "(in-proc artifacts only)")
    else:
        cmd = [sys.executable, str(here / "dexdata_extract.py"),
               "--app", APP_ID, "--out-dir", str(OUT / "redump")]
        memread = repo / "tools" / "memread"
        if memread.exists():
            # absolute path: robust regardless of the driver's CWD
            cmd += ["--memread", str(memread)]
        else:
            note("[!] tools/memread missing - dexdata_extract.py will "
                 "report the same (compile tools/memread.c)")
        redump_rc = run_step_subprocess(cmd, "dexdata", 900.0)
        if pidof(APP_ID) is None:
            note("[phase2] app died during the redump "
                 "(dexdata SIGSTOP/CONT cycle) - continuing")

    # -- step 14: repair / validate into canonical classes*.dex ----------
    vcmd = [sys.executable, str(here / "validate_and_extract_dex.py"),
            "--dump-dir", str(OUT / "redump"),
            "--out-dir", str(OUT / "repaired"),
            "--min-size", "65536"]
    run_step_subprocess(vcmd, "validate", 300.0)

    # -- step 15: pull in-process artifacts -------------------------------
    pull_inproc_artifacts()

    # -- step 16: summary -------------------------------------------------
    repaired_dir = OUT / "repaired"
    redump_dex_count = (len([p for p in repaired_dir.iterdir() if p.is_file()])
                        if repaired_dir.is_dir() else 0)
    inproc_modules = sorted(p.name for p in (OUT / "inproc").rglob("*.mem")) \
        if (OUT / "inproc").is_dir() else []
    app_alive = pidof(APP_ID) is not None
    summary = {
        "rn_classes": len(RN_TABLE),
        "rn_methods": rn_methods_total,
        "warmup": {
            "ok": warm_stats["ok"],
            "notfound": warm_stats["notfound"],
            "fail": warm_stats["fail"],
        },
        "redump_dex_count": redump_dex_count,
        "inproc_modules": inproc_modules,
        "app_alive": app_alive,
        "reattaches": reattaches,
        "timeline_seconds": round(time.time() - START, 1),
    }
    (OUT / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    note(f"[phase2] summary: {json.dumps(summary, ensure_ascii=False)}")
    note(f"[phase2] done in {summary['timeline_seconds']}s "
         f"(modules dumped in-proc: {sorted(DUMPED_MODULES)})")

    # -- step 17: exit code ----------------------------------------------
    app_died_before_dump = DETACHED["flag"] and not DUMPS_DONE \
        and redump_dex_count == 0 and redump_rc is None
    if app_died_before_dump:
        note(f"[!] app died before any dump "
             f"(detached: {DETACHED['reason']}) - exit 3")
        return 3
    if rn_methods_total == 0:
        note("[!] zero RegisterNatives registrations captured - check the "
             "frida-server port and the anti-frida defenses (exit 2)")
        return 2
    if redump_dex_count >= 1:
        note("[phase2] SUCCESS: jni table captured AND re-dumped dexes "
             f"present ({redump_dex_count}) - exit 0")
        return 0
    note(f"[phase2] partial: {rn_methods_total} RN methods captured but "
         f"{redump_dex_count} re-dumped dexes - inspect the log (exit 1)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
