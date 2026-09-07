#!/usr/bin/env python3
"""Rebuild a packer-free APK from dumped DEX + apktool (resources only).

  apktool d --no-src  -> patch Application / strip iJiami assets
  apktool b           -> zip-replace classes*.dex
  zipalign + apksigner

Environment: APKTOOL_JAR or TOOLS_DIR, ANDROID_HOME for apksigner/zipalign.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

SHELL_APP = "s.h.e.l.l.S"
SHELL_ACF = "s.h.e.l.l.A"
ORIG_APP = "com.mobile.brasiltv.app.App"
ORIG_ACF = "androidx.core.app.CoreComponentFactory"

# Packer payload to strip: the encrypted dex blob and the SecLLVM
# engines. NOTE: libijmDataEncryption*.so assets are KEPT - they are
# the ijm Data-Encryption SDK's runtime libs (com.ijm.dataencryption.
# DETool copies them to files/ and System.load()s them; the native
# bodies of methods the packer converted - e.g. com.arialyy.aria.orm.
# SqlHelper.getDb - live there). The arm/arm64 variants were stripped
# from the original APK's assets by the packer (it delivers them at
# runtime); we re-add the captured one via --ijm-lib.
IJIAMI_ASSETS = (
    "ijiami.dat",
    "ijiami.ajm",
    "IJMDal.Data",
    "signed.bin",
    "af.bin",
)

# asset names under which the captured arm64 DE lib is bundled: DETool
# picks by /proc/self/exe + lib64/libart.so probing, which on translated
# emulators and real arm64 devices both resolve to the '_x86_64'/'_arm64'
# names - the process is arm64 in both cases, so arm64 bytes under every
# name is the universally-correct payload.
IJM_LIB_ASSET_NAMES = (
    "libijmDataEncryption.so",
    "libijmDataEncryption_arm64.so",
    "libijmDataEncryption_x86_64.so",
)


def run(cmd: list[str]) -> None:
    print("[*]", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def find_apktool() -> str:
    env = os.environ.get("APKTOOL_JAR")
    if env and Path(env).is_file():
        return env
    tools = Path(os.environ.get("TOOLS_DIR", "tools"))
    cand = tools / "apktool.jar"
    if cand.is_file():
        return str(cand)
    raise SystemExit("APKTOOL_JAR / TOOLS_DIR/apktool.jar not found")


def patch_manifest(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    text = text.replace(f'android:name="{SHELL_APP}"', f'android:name="{ORIG_APP}"')
    text = text.replace(
        f'android:appComponentFactory="{SHELL_ACF}"',
        f'android:appComponentFactory="{ORIG_ACF}"',
    )
    path.write_text(text, encoding="utf-8")


def strip_ijiami_assets(decoded: Path) -> None:
    assets = decoded / "assets"
    for name in IJIAMI_ASSETS:
        p = assets / name
        if p.exists():
            p.unlink()
    ijm_lib = assets / "ijm_lib"
    if ijm_lib.exists():
        shutil.rmtree(ijm_lib)


def add_ijm_lib(decoded: Path, ijm_lib: Path) -> None:
    """Bundle the captured libijmDataEncryption.so (from the runtime
    appdata.tar evidence) under every DETool asset name."""
    if not ijm_lib.is_file():
        print(f"[!] --ijm-lib {ijm_lib} not found; skipping")
        return
    data = ijm_lib.read_bytes()
    if data[:4] != b"\x7fELF":
        print(f"[!] --ijm-lib {ijm_lib} is not an ELF; skipping")
        return
    assets = decoded / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    for name in IJM_LIB_ASSET_NAMES:
        (assets / name).write_bytes(data)
        print(f"[+] assets/{name} <- captured DE lib ({len(data)} bytes)",
              flush=True)


def collect_dex(dump_dir: Path, extra_dex: list[str]) -> list[tuple[str, Path]]:
    ordered = []
    names = ["classes.dex"] + [f"classes{i}.dex" for i in range(2, 16)]
    for name in names:
        p = dump_dir / name
        if p.is_file():
            ordered.append((name, p))
    if ordered:
        pass
    else:
        extras = sorted(dump_dir.glob("*.dex"))
        for i, p in enumerate(extras):
            name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
            ordered.append((name, p))
    # appended AFTER the real dexes: the no-op s.h.e.l.l.C stub defuses
    # the packer's injected <clinit> kill-switches (run 34135095450:
    # FacebookInitProvider.<clinit> -> s.h.e.l.l.C.i() is a native
    # trampoline that requires files/libijmDataEncryption.so, extracted
    # only by the packer Application we removed; a plain-Java no-op C
    # makes every injected call harmless)
    for i, p in enumerate(extra_dex):
        n = len(ordered) + i + 1
        ordered.append((f"classes{n}.dex", Path(p)))
    # dedupe names (paranoia)
    seen_names = set()
    out = []
    for name, p in ordered:
        if name in seen_names:
            continue
        seen_names.add(name)
        out.append((name, p))
    return out


def zip_replace_dex(apk: Path, dex_files: list[tuple[str, Path]], dest: Path) -> None:
    with zipfile.ZipFile(apk, "r") as zin, zipfile.ZipFile(
        dest, "w", compression=zipfile.ZIP_DEFLATED
    ) as zout:
        skip = {name for name, _ in dex_files}
        skip.update({"classes.dex"})
        for i in range(2, 32):
            skip.add(f"classes{i}.dex")
        for info in zin.infolist():
            if info.filename in skip:
                continue
            # drop leftover packer assets if apktool left them
            base = info.filename.split("/")[-1]
            if info.filename.startswith("assets/ijm_lib/") or base in IJIAMI_ASSETS:
                continue
            zout.writestr(info, zin.read(info.filename))
        for name, path in dex_files:
            zout.write(path, name)


def sign_apk(src: Path, dest: Path, keystore: Path, storepass: str) -> None:
    build_tools = None
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if android_home:
        bt = Path(android_home) / "build-tools"
        if bt.is_dir():
            versions = sorted((p for p in bt.iterdir() if p.is_dir()), reverse=True)
            if versions:
                build_tools = versions[0]
    zipalign = shutil.which("zipalign")
    apksigner = shutil.which("apksigner")
    if build_tools:
        zipalign = zipalign or str(build_tools / "zipalign")
        apksigner = apksigner or str(build_tools / "apksigner")
    aligned = dest.with_suffix(".aligned.apk")
    if zipalign:
        run([zipalign, "-f", "4", str(src), str(aligned)])
    else:
        shutil.copy2(src, aligned)
        print("[!] zipalign not found; copying unaligned", flush=True)
    if not keystore.exists():
        run(
            [
                "keytool",
                "-genkey",
                "-keystore",
                str(keystore),
                "-storepass",
                storepass,
                "-alias",
                "re",
                "-keypass",
                storepass,
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "10000",
                "-dname",
                "CN=Youcine-RE,O=Research,C=US",
            ]
        )
    if not apksigner:
        raise SystemExit("apksigner not on PATH / ANDROID_HOME")
    run(
        [
            apksigner,
            "sign",
            "--ks",
            str(keystore),
            "--ks-pass",
            f"pass:{storepass}",
            "--out",
            str(dest),
            str(aligned),
        ]
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True)
    ap.add_argument("--dump-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--keystore", required=True)
    ap.add_argument("--storepass", default="android")
    ap.add_argument("--work-dir", default="")
    ap.add_argument("--extra-dex", action="append", default=[],
                    help="additional .dex to append (e.g. the no-op "
                         "s.h.e.l.l.C stub that defuses injected "
                         "packer kill-switches)")
    ap.add_argument("--ijm-lib", default="",
                    help="captured libijmDataEncryption.so (from the "
                         "appdata.tar evidence) to bundle as the DE "
                         "SDK assets")
    args = ap.parse_args()

    dex_files = collect_dex(Path(args.dump_dir), args.extra_dex)
    if not dex_files:
        raise SystemExit("no DEX in dump-dir")

    apktool = find_apktool()
    tmp_own = False
    work = Path(args.work_dir) if args.work_dir else Path(tempfile.mkdtemp(prefix="youcine-rebuild-"))
    tmp_own = not bool(args.work_dir)
    decoded = work / "decoded"
    if decoded.exists():
        shutil.rmtree(decoded)
    run(["java", "-jar", apktool, "d", "-f", "-s", "-o", str(decoded), str(args.apk)])
    patch_manifest(decoded / "AndroidManifest.xml")
    strip_ijiami_assets(decoded)
    if args.ijm_lib:
        add_ijm_lib(decoded, Path(args.ijm_lib))
    built = work / "resigned-stub.apk"
    run(["java", "-jar", apktool, "b", str(decoded), "-o", str(built)])
    replaced = work / "replaced.apk"
    zip_replace_dex(built, dex_files, replaced)
    sign_apk(replaced, Path(args.out), Path(args.keystore), args.storepass)
    print(f"[+] unpacked apk {args.out}", flush=True)
    if tmp_own:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
