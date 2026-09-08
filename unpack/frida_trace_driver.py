#!/usr/bin/env python3
"""Frida spawn-gated driver: neutralize packer tamper-kill, freeze at the
right moment, then dump the decrypted DEX out-of-process.

Flow (dump-build / pure x86_64 process):
 1. spawn com.world.youcinemobile gated, inject the guard script
    (default frida-scripts/05_tamper_guard.js) BEFORE any app code
 2. resume; the guard suppresses the iJiami signature-check suicide
    (libc kill/tgkill/exit/abort) and SIGSTOPs the process exactly when
    Instrumentation.newApplication is about to build the real
    com.mobile.brasiltv.app.App (decrypted DEX now lives in memory)
 3. on [FROZEN] (or timeout), run the external memdump sweeps

Environment:
  FRIDA_REMOTE   endpoint (default 127.0.0.1:4789)
  APP_ID         package (default com.world.youcinemobile)
  SCRIPT         frida script file name (default 05_tamper_guard.js)
  TRACE_SECONDS  max wait for freeze (default 60)
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

import frida

APP_ID = os.environ.get("APP_ID", "com.world.youcinemobile")
TRACE_SECONDS = int(os.environ.get("TRACE_SECONDS", "60"))
SCRIPT_NAME = os.environ.get("SCRIPT", "05_tamper_guard.js")
FRIDA_REMOTE = os.environ.get("FRIDA_REMOTE", "127.0.0.1:4789")

OUT = open("work/trace.log", "a", encoding="utf-8")
FROZEN = threading.Event()


def note(line: str) -> None:
    print(line, flush=True)
    OUT.write(line + "\n")
    OUT.flush()


def on_message(message: dict, data: object) -> None:
    mtype = message.get("type")
    if mtype == "send":
        payload = message.get("payload")
        text = str(payload.get("msg")) if isinstance(payload, dict) else str(payload)
        note("[js] " + text)
        if "FROZEN" in text:
            FROZEN.set()
    elif mtype == "error":
        note("[js!] " + str(message.get("description")))
    else:
        note("[js?] " + str(message))


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    js_path = os.path.join(here, "..", "frida-scripts", SCRIPT_NAME)
    source = open(js_path, encoding="utf-8").read()

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device(FRIDA_REMOTE)
    note(f"[*] remote device: {device}")

    pid = device.spawn([APP_ID])
    note(f"[*] spawned {APP_ID} pid={pid} (gated)")
    session = device.attach(pid)
    session.on("detached", lambda reason, *a: note(f"[!] session detached: {reason}"))
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    note("[*] script injected; resuming")
    device.resume(pid)

    deadline = time.time() + TRACE_SECONDS
    while time.time() < deadline and not FROZEN.is_set():
        time.sleep(0.4)

    if FROZEN.is_set():
        note("[*] process FROZEN at decryption point; sweeping memory")
    else:
        note("[*] no freeze signal; checking app state")

    alive = subprocess.run(
        ["adb", "shell", f"pidof {APP_ID}"], capture_output=True, timeout=10
    )
    pid_text = (alive.stdout or b"").decode().strip()
    if pid_text:
        note(f"[*] app pid {pid_text}; running external memdump")
        memdump = os.path.join(here, "external_memdump.py")
        subprocess.run(
            [
                sys.executable,
                memdump,
                "--app",
                APP_ID,
                "--out-dir",
                "dumped/youcine",
                "--expect",
                os.environ.get("EXPECT_DEX", "4"),
                "--timeout",
                os.environ.get("DUMP_TIMEOUT", "240"),
                "--settle",
                "0.2",
                "--no-freeze",
            ],
            check=False,
        )
    else:
        note("[!] app is dead; no dump possible (inspect trace + logcat)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
