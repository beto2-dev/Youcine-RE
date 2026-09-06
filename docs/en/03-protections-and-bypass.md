# 03 - Protections and bypass

All bypass notes are for **analysis builds** running on a lab emulator.
They are not a consumer "crack".

| ID | Layer | What it does | Lab response |
|---|---|---|---|
| iJiami shell | client | Replaces Application and AppComponentFactory | After dump, set Application to `com.mobile.brasiltv.app.App` and factory to `androidx.core.app.CoreComponentFactory` (`unpack/rebuild_unpacked_apk.py`) |
| Encrypted DEX | client | 4 payloads in `ijiami.dat` | Memory dump + zip-replace `classes*.dex` |
| SecLLVM / AJM | client | Native obfuscation of `libexec` | Ghidra; not required to boot Java |
| ptrace | client | `libexec` anti-debug | Prefer out-of-process dump; Frida `ptrace` replace as fallback |
| `/proc/self/maps` | client | 64-bit detection + possibly artifact scan | Harmless for ABI pick; memdump does not inject |
| DETool sidecar | client | Extra native crypto `.so` from assets | Delete with packer assets |
| `signed.bin` + ed25519 | client | Payload / APK signature check | Dropped with packer; rebuilt APK is re-signed |
| `allowBackup=false` | client policy | Blocks `adb backup` | Optional analysis patch only |
| `usesCleartextTraffic=true` | client policy | HTTP allowed | Useful for portal capture; not a packer |
| Force upgrade | **server** | `upgrade_main` / `version_forbidden_*` strings | Host decides; packing is irrelevant |
| VIP / device bind | **server** | LoginAty, DeviceManageAty, redemption | Out of packer scope |
| ARM-only playback JNI | client ABI | `libijkplayer`, `libranger-jni` | Dump on x86_64; boot test on arm64 AVD |

## Rebuild checklist

1. Valid DEX dumps (magic `dex\n03x\0`, `file_size` field matches length).
2. Manifest Application + AppComponentFactory restored.
3. Deleted: `assets/ijiami.*`, `assets/ijm_lib/`, `libijmDataEncryption*.so`,
   `IJMDal.Data`, `signed.bin`, `af.bin`, stub smali `s/h/e/l/l`.
4. Keep: ijkplayer, Ranger, Cast, Firebase, Umeng natives (needed to boot UX).
5. zipalign 4, apksigner with a **lab** keystore (original XXL/OTT cert is
   not reused).
