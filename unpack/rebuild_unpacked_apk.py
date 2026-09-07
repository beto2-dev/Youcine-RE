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
# DETool copies the variant for the runtime ABI to files/ and
# System.load()s it; the native bodies of methods the packer converted
# - e.g. com.arialyy.aria.orm.SqlHelper.getDb - live there). The packed
# APK ships all four ABI variants in assets/ (default=armeabi-v7a,
# _x86, _x86_64, _arm64); keep them byte-identical so DETool's ABI
# probing and CRC check succeed. --ijm-lib only re-adds the arm64
# variant if it is missing (e.g. rebuilding from a source APK that had
# it stripped).
IJIAMI_ASSETS = (
    "ijiami.dat",
    "ijiami.ajm",
    "IJMDal.Data",
    "signed.bin",
    "af.bin",
)

# asset name under which the captured arm64 DE lib is re-added when the
# source APK lacks it. DETool picks the asset by /proc/self/exe
# (e_machine) + /proc/self/maps (lib64) probing: on x86_64 ->
# _x86_64.so, on arm32 -> default name, on arm64 -> _arm64.so. Each
# asset must contain the bytes of ITS OWN ABI (rebuild v3 bundled the
# captured arm64 lib under every name, which left broken ABI-payload
# pairs for v7a/x86_64; fixed in v4).
IJM_LIB_ASSET_NAMES = (
    "libijmDataEncryption_arm64.so",
)

# early DE-SDK loader (see unpack/stubs/src/com/youcine/re/
# BootProvider.java): installed by installContentProviders() BEFORE
# Application.onCreate, so DETool.loadDEso() runs before App.onCreate
# -> Aria.init -> SqlHelper.getDb (the first packer-natified method).
BOOT_PROVIDER_CLASS = "com.youcine.re.BootProvider"
BOOT_PROVIDER_AUTHORITY = "com.world.youcinemobile.ycre-boot"


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
    """Re-add the captured libijmDataEncryption.so (from the runtime
    appdata.tar evidence) as the _arm64 asset, but only when the source
    APK does not already ship it."""
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
        target = assets / name
        if target.is_file() and target.read_bytes()[:4] == b"\x7fELF":
            print(f"[+] assets/{name} already present ({target.stat().st_size} "
                  "bytes); keeping source bytes", flush=True)
            continue
        target.write_bytes(data)
        print(f"[+] assets/{name} <- captured DE lib ({len(data)} bytes)",
              flush=True)


def inject_boot_provider(path: Path) -> None:
    """Declare the BootProvider in the apktool-decoded manifest text so
    it is installed before Application.onCreate (providers always run
    first) and can load the DE SDK before the first natified method is
    called."""
    text = path.read_text(encoding="utf-8")
    if BOOT_PROVIDER_CLASS in text:
        print("[+] manifest already declares the BootProvider", flush=True)
        return
    idx = text.find("<application")
    if idx < 0:
        raise SystemExit("no <application> tag in decoded manifest")
    gt = text.find(">", idx)
    if gt < 0:
        raise SystemExit("malformed <application> tag in decoded manifest")
    provider = (
        f'\n        <provider android:name="{BOOT_PROVIDER_CLASS}" '
        f'android:authorities="{BOOT_PROVIDER_AUTHORITY}" '
        f'android:exported="false"/>'
    )
    text = text[: gt + 1] + provider + text[gt + 1 :]
    path.write_text(text, encoding="utf-8")
    print(f"[+] manifest: injected provider {BOOT_PROVIDER_CLASS}", flush=True)


def patch_confusion_dex(dex_files: list[tuple[str, Path]], work: Path) -> None:
    """Run unpack/patch_confusion_cc.py against the dump DEX that carries
    com.ijiami.residconfusion.ConfusionUtils (the app-embedded signature
    kill-switch: allowlist MD5 545A...A699 -> HOME + System.exit(0) on the
    re-signed build). The patched copy replaces the original entry."""
    script = Path(__file__).resolve().parent / "patch_confusion_cc.py"
    if not script.is_file():
        print(f"[!] {script} missing; confusion patch skipped")
        return
    import sys as _sys

    for i, (name, p) in enumerate(dex_files):
        out = work / f"confusion-patched-{name}"
        out.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            [_sys.executable, str(script), "--dex", str(p), "--out", str(out)],
            capture_output=True,
            text=True,
        )
        if r.returncode == 0:
            print(r.stdout, end="", flush=True)
            dex_files[i] = (name, out)
            print(f"[+] confusion kill-switch neutralized in {name}", flush=True)
            return
        if r.returncode == 2:
            continue  # ConfusionUtils not in this dex
        print(r.stdout, r.stderr, flush=True)
    print("[!] ConfusionUtils not found in any dump DEX; patch not applied",
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
                         "appdata.tar evidence) to re-add as the arm64 "
                         "DE SDK asset when the source APK lacks it")
    ap.add_argument("--patch-confusion", action="store_true",
                    help="neutralize the app-embedded iJiami signature "
                         "kill-switch (com.ijiami.residconfusion."
                         "ConfusionUtils.cc/e) in the dump DEXes")
    ap.add_argument("--boot-dex", default="",
                    help="DEX with com.youcine.re.BootProvider (early "
                         "DE-SDK loader); also declares the provider in "
                         "the manifest so it is installed before "
                         "Application.onCreate")
    args = ap.parse_args()

    dex_files = collect_dex(Path(args.dump_dir), args.extra_dex)
    if not dex_files:
        raise SystemExit("no DEX in dump-dir")

    apktool = find_apktool()
    tmp_own = False
    work = Path(args.work_dir) if args.work_dir else Path(tempfile.mkdtemp(prefix="youcine-rebuild-"))
    tmp_own = not bool(args.work_dir)
    if args.patch_confusion:
        patch_confusion_dex(dex_files, work)
    if args.boot_dex:
        boot = Path(args.boot_dex)
        if not boot.is_file():
            raise SystemExit(f"--boot-dex {boot} not found")
        dex_files.append((f"classes{len(dex_files) + 1}.dex", boot))
    decoded = work / "decoded"
    if decoded.exists():
        shutil.rmtree(decoded)
    run(["java", "-jar", apktool, "d", "-f", "-s", "-o", str(decoded), str(args.apk)])
    patch_manifest(decoded / "AndroidManifest.xml")
    if args.boot_dex:
        inject_boot_provider(decoded / "AndroidManifest.xml")
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
