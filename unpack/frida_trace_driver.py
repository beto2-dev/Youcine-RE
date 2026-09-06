#!/usr/bin/env python3
"""Frida spawn-gated driver: trace iJiami lib loads, then optionally dump.

Spawns com.world.youcinemobile suspended, injects
frida-scripts/04_trace_loads.js BEFORE any app code runs, resumes it and
collects messages. If the process survives (packer satisfied), runs the
external poll-and-freeze memdump afterwards to capture the decrypted DEX.

Environment:
  FRIDA_REMOTE   frida-server endpoint (default 127.0.0.1:4789)
  APP_ID         package (default com.world.youcinemobile)
  TRACE_SECONDS  message collection window (default 40)
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import frida

APP_ID = os.environ.get("APP_ID", "com.world.youcinemobile")
TRACE_SECONDS = int(os.environ.get("TRACE_SECONDS", "40"))
FRIDA_REMOTE = os.environ.get("FRIDA_REMOTE", "127.0.0.1:4789")

OUT = open("work/trace.log", "a", encoding="utf-8")


def note(line: str) -> None:
    print(line, flush=True)
    OUT.write(line + "\n")
    OUT.flush()


def on_message(message: dict, data: object) -> None:
    mtype = message.get("type")
    if mtype == "send":
        payload = message.get("payload")
        if isinstance(payload, dict):
            note("[js] " + str(payload.get("msg")))
        else:
            note("[js] " + str(payload))
    elif mtype == "error":
        note("[js!] " + str(message.get("description")))
        stack = message.get("stack")
        if stack:
            note(str(stack))
    else:
        note("[js?] " + str(message))


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    js_path = os.path.join(here, "..", "frida-scripts", "04_trace_loads.js")
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
    while time.time() < deadline:
        time.sleep(0.5)
        try:
            procs = [p.pid for p in device.enumerate_processes() if p.pid == pid]
        except Exception:
            procs = []
        if not procs:
            note("[!] process died during trace")
            break
        try:
            alive = subprocess.run(
                ["adb", "shell", f"pidof {APP_ID}"],
                capture_output=True,
                timeout=10,
            )
            if not (alive.stdout or b"").strip():
                note("[!] app pid gone from device")
                break
        except Exception:
            pass

    note("[*] trace window complete")

    # If the app survived the packer stage, sweep its memory for DEX.
    alive = subprocess.run(
        ["adb", "shell", f"pidof {APP_ID}"], capture_output=True, timeout=10
    )
    pid_text = (alive.stdout or b"").decode().strip()
    if pid_text:
        note(f"[*] app alive (pid {pid_text}); running external memdump")
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
                "1.0",
                "--no-freeze",
            ],
            check=False,
        )
    else:
        note("[!] app is dead; no dump possible (inspect trace + logcat)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
