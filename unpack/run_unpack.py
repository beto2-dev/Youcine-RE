#!/usr/bin/env python3
"""Frida driver for the iJiami unpack scripts (zygote-gating or spawn).

Same approach as the Magis/Xuper lab: inject before Application.attachBaseContext
so N.al() / libexec decryption is observed.

Environment:
  FRIDA_REMOTE  default 127.0.0.1:1337
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

import frida

LAUNCH_ACTIVITY = "com.mobile.brasiltv.activity.SplashAty"
FRIDA_REMOTE = os.environ.get("FRIDA_REMOTE", "127.0.0.1:1337")


def on_message(message: dict, data: object) -> None:
    mtype = message.get("type")
    if mtype == "log":
        print(f"[js] {message.get('payload')}", flush=True)
    elif mtype == "send":
        print(f"[js>] {message.get('payload')}", flush=True)
    elif mtype == "error":
        print(f"[js!] {message.get('description')}", file=sys.stderr, flush=True)
        stack = message.get("stack")
        if stack:
            print(stack, file=sys.stderr, flush=True)
    else:
        print(f"[js?] {message}", flush=True)


class Injector:
    def __init__(self, device: frida.core.Device, script_paths: list[str]):
        self.device = device
        self.script_paths = script_paths
        self.sessions: dict[int, object] = {}
        self.dead: set[int] = set()

    def inject(self, pid: int) -> bool:
        if pid in self.sessions or pid in self.dead:
            return False
        try:
            session = self.device.attach(pid)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] attach({pid}) failed: {exc}", flush=True)
            return False
        session.on("detached", lambda reason, *a, pid=pid: self.on_detached(pid, reason))
        for path in self.script_paths:
            try:
                source = open(path, encoding="utf-8").read()
                script = session.create_script(source)
                script.on("message", on_message)
                script.load()
            except Exception as exc:  # noqa: BLE001
                print(f"[!] script {path} failed on pid {pid}: {exc}", file=sys.stderr, flush=True)
        self.sessions[pid] = session
        print(f"[*] injected scripts into pid {pid}", flush=True)
        return True

    def on_detached(self, pid: int, reason, *extra) -> None:
        self.dead.add(pid)
        print(f"[!] pid {pid} detached: {reason}", flush=True)


def find_process(device: frida.core.Device, name: str) -> int | None:
    for proc in device.enumerate_processes():
        if proc.name == name:
            return proc.pid
    return None


def am_start(app: str, activity: str) -> None:
    cmd = ["adb", "shell", "am", "start", "-n", f"{app}/{activity}"]
    print(f"[*] {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=False, timeout=30)


def run_zygote_mode(device, injector, app, activity, wait: int) -> None:
    zygote_pid = find_process(device, "zygote64")
    if zygote_pid is None:
        raise SystemExit("[!] zygote64 not found")
    print(f"[*] zygote64 pid {zygote_pid}", flush=True)
    zyg_session = device.attach(zygote_pid)
    zyg_session.enable_child_gating()
    am_start(app, activity)
    seen: set[int] = set()
    deadline = time.time() + wait
    try:
        while time.time() < deadline:
            for child in device.enumerate_pending_children():
                pid = child.pid
                if pid not in seen:
                    seen.add(pid)
                    injector.inject(pid)
                try:
                    device.resume(pid)
                except Exception as exc:  # noqa: BLE001
                    print(f"[!] resume({pid}) failed: {exc}", flush=True)
            time.sleep(0.1)
    finally:
        try:
            zyg_session.disable_child_gating()
            zyg_session.detach()
        except Exception:
            pass


def run_spawn_mode(device, injector, app, wait: int) -> None:
    pid = device.spawn(app)
    print(f"[*] spawned {app} (pid {pid})", flush=True)
    injector.inject(pid)
    device.resume(pid)
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(5)


def get_device(connect_timeout: int):
    try:
        device = frida.get_device_manager().add_remote_device(FRIDA_REMOTE)
        device.enumerate_processes()
        print(f"[*] device: remote {FRIDA_REMOTE}", flush=True)
        return device
    except Exception as exc:  # noqa: BLE001
        print(f"[!] remote {FRIDA_REMOTE} unavailable ({exc}); USB fallback", flush=True)
        return frida.get_usb_device(timeout=connect_timeout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)
    ap.add_argument("--script", action="append", dest="scripts", required=True)
    ap.add_argument("--mode", choices=["zygote", "spawn"], default="zygote")
    ap.add_argument("--wait", type=int, default=90)
    ap.add_argument("--launch-activity", default=LAUNCH_ACTIVITY)
    ap.add_argument("--connect-timeout", type=int, default=30)
    args = ap.parse_args()
    print(f"[*] frida {frida.__version__}", flush=True)
    device = get_device(args.connect_timeout)
    injector = Injector(device, args.scripts)
    if args.mode == "zygote":
        run_zygote_mode(device, injector, args.app, args.launch_activity, args.wait)
    else:
        run_spawn_mode(device, injector, args.app, args.wait)
    print("[*] done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
