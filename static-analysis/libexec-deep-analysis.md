# iJiami SecShell 1.7.4.20 — native-layer deep analysis

> Research artifact of the **Youcine-RE** project (educational packer/malware
> analysis). Target: `com.world.youcinemobile` 1.17.6, packed with iJiami
> SecShell **1.7.4.20** ("SeLLVM compiler 1.7.4.20" marker in the NRV2B
> stage). This report consolidates the Ghidra/unicorn static passes (the
> 8-a agent run, killed mid-work, artifacts preserved in
> `ghidra-exports/`) with the dynamic run evidence from GitHub Actions.

## 1. Artifact inventory

| file | size | md5 | notes |
|---|---|---|---|
| `ijm_lib/x86/libexec.so` | 556,824 | `0e33dcf007398831d64bfd21b5093673` | 32-bit x86, the ABI the stub extracts on a 32-bit emulator process (proven: extracted copy in run 34048953559 matched this md5) |
| `ijm_lib/x86/libexecmain.so` | 36,816 | `96d6288fcc7cb6671db05719f7b76a1f` | 32-bit x86, NEEDED: liblog, libandroid, **libz**, libc, libm, **libstdc++**, libdl |
| `ijm_lib/x86_64/{libexec,libexecmain}.so` | 667,144 / 36,816 | — | 64-bit twins |
| `ijm_lib/armeabi{,-v7a}/…`, `arm64-v8a/…` | — | — | ARM variants (die under ndk_translation: SecLLVM self-modifying code) |
| `assets/ijiami.dat` | 9,543,463 | `93d86c64dece89b3aea4425ae7d82831` | encrypted DEX payload |

`libexecmain.so` DT_NEEDED `libstdc++.so` is satisfied on emulator images
(**`libstdc++.so` is listed in `/system/etc/public.libraries.txt`**), so the
historic "missing libstdc++" load-failure theory is disproven: every
observed load succeeded and the `N.al` refusal is an environment gate, not
a link failure.

## 2. ijiami.dat structure (the encrypted payload)

Header (40 bytes):

```
00000000  04 00 00 00          u32le  4           encrypted DEX count
00000004  1c 72 c2 02          u32le  41,140,828  total uncompressed size (4.31x)
00000008  "44f6438002be91557b704ba909f62f58"     32-char ASCII hex (16 bytes)
00000028  <payload: 9,543,423 bytes>
```

* Payload entropy is uniformly ~7.99 bits/byte with **1,324 duplicate
  16-byte blocks** (ECB-like repetition; most common block `e8e8…e8` ×33).
* 4 quadrant boundaries are not visible in the entropy profile - the
  payload is one continuous ciphertext stream.
* Direct-key probes all failed (`dat_aes_probe.py`): AES-128/256-ECB/CBC
  with the hex-parsed key, the ASCII key, payload-derived keys, and XOR
  variants produce no DEX/zlib/gzip magic. **The AES key is derived inside
  the obfuscated native code** (likely from device/APK inputs - the
  decrypted strings show certificate and signature-related JNI paths).

## 3. SecLLVM multi-stage self-unpacking (libexecmain.so DT_INIT)

The DT_INIT of `libexecmain.so` is a hand-rolled multi-stage unpacker
(reverse-engineered with `emulate_unpack.py` / `emulate_stage2.py`, Unicorn):

1. pops the return address, reads an inline u32 table to calibrate the
   load base, locates the blob descriptor struct;
2. `mmap(RWX, ANON)` via **raw `int 0x80`** (syscall 90, old_mmap — no
   libc involvement) and copies the blob;
3. `mmap(MAP_FIXED, RW)` at a hole vaddr for the decompressed code;
4. **NRV2B-style LZ decompression** (ported in `nrv2b_ijiami.py`):
   MSB-first bit reader over 32-bit LE words with a sentinel refill trick
   (`ebx = 2*word + 1`), literal bytes **XOR 0x0C**, rep-matches, and an
   end-marker encoded as offset word 0;
5. E8/E9/0F8x **rel32 call-patch loop** (classic packer relocation of
   relative branches);
6. jump into the unpacked region (further stages follow).

The fully unpacked `libexecmain` decompilation (5.2 MB,
`ghidra-exports/libexecmain-unpacked.txt`) is the analysis ground truth:
~8,513 functions, decrypted string table, and the register/dispatch layer.

## 4. The detection arsenal (decrypted string table)

`ghidra-exports/decrypted-strings-rw.txt` (1,291 strings) proves the
packer checks, in order of the dynamic evidence:

| category | strings / imports |
|---|---|
| anti-debug | `/proc/self/status`, **`TracerPid`**, `/proc/self/wchan`, `ptrace_stop`, `ptrace`+`waitpid` imports |
| emulator | `/dev/qemu_pipe`, `/dev/socket/qemud`, `goldfish`, `init.svc.qemud`, `init.svc.qemu-props`, `qemu.hw.mainkeys`, `qemu.sf.fake_camera`, `qemu.sf.lcd_density`, `ro.kernel.android.qemud`, `ro.kernel.qemu.gles`, **`ro.kernel.qemu`**, `generic`, `Build.HARDWARE`, `Build.MODEL`, `getStackTrace` sweeps |
| root | `/system/bin/su`, `/system/xbin/su`, `/system/sbin/su`, `/sbin/su`, `/vendor/bin/su`, `/su/bin/su`, `/sbin/.magisk`, `/system/bin/magisk`, `/data/data/com.topjohnwu.magisk`, `MAGISK_INJ_`, `MAGISKFD=libdvm.so`, kernelsu paths |
| hook frameworks | `de.robv.android.xposed.XposedHelpers`, `com.swift.sandhook.SandHook`, `com.windy.wrapper.SandHook`, `top.canyie.pine.Pine`, `np.manager.FuckSign`, `com.pairip.application.Application`, `bin/mt/apksignaturekillerplus/HookApplication`, `libmthook.so`, `Java_cc_binmt_signature_Hook_hookOpen` |
| frida | `/data/local/tmp/re.frida.server`, `frida-agent{,-32,-64,-raw}.so`, `FridaAgentStopReason`, frida port strings |
| ART internals | `_ZN3art7Runtime9instance_E`, `dalvik/system/VMDebug`, ClassLinker/DexFile symbol manglings (per-Android-version dispatch) |

**Notably absent: any `ro.debuggable` / `jdwp` string.** The empirical
correlation (jdwp transport opens ~90 ms before the `N.al` refusal) is
therefore likely coincidental - the JDWP thread itself may still be
detectable via the `Thread.getStackTrace` sweeps, but the primary gates
match the table above.

## 5. The gate behavior (dynamic evidence matrix)

| run | environment | APK | result |
|---|---|---|---|
| 34044920876 | google_apis, debuggable, qemu signals | original, arm64-v8a install | `N.al` UnsatisfiedLinkError (translated SecLLVM) |
| 34048953559 | google_apis, debuggable | original, `--abi armeabi-v7a` (native x86 packer) | `N.al` refused silently - no kill, no linker error |
| 34049784110 | same + libstdc++ stub pushed | same | identical refusal (stub irrelevant) |
| 34081223822 | same + qemu/goldfish device nodes renamed, su hidden (none existed) | same | identical refusal; renaming the pipes killed system_server ~55 s later |
| 34046807813/34051553362/… | google_apis + frida/ptrace guards | **re-signed dump-build** | raw-syscall death ladder (kill/tgkill/exit/int3/ud2/SIGSEGV) - the **content-integrity gate** kills modified APKs |
| 34084634643 | playstore image (production, no root) | original, BlackDex sandbox | (automation crashed on a tool bug; re-running) |

Interpretation: two distinct responses exist - **tampered APK → kill
ladder**; **bad environment → silent RegisterNatives skip** (app dies of
the resulting `UnsatisfiedLinkError`). The environment checks that were
still live in every failing run: `ro.kernel.qemu=1`, all `qemu.*` props,
`init.svc.qemu-props=running`, `ranchu`/`goldfish` hardware strings,
`userdebug/dev-keys` fingerprints, `sdk_gphone` model, and
`/proc/self/maps` ndk_translation mappings (un-hideable without ptrace).

## 6. Countermeasures deployed (iteration 2, run 34084986538)

1. **ramdisk surgery** (`unpack/patch_ramdisk.py`): the API-30 ramdisk is
   a multi-stage concatenated cpio; patching `/default.prop`
   `ro.debuggable=1→0` and `ro.secure=1→0` before first boot gives a
   non-debuggable userspace (no JDWP transport in any app) while keeping
   adbd root for the out-of-process `/proc/<pid>/mem` sweep.
2. **property-area spoofing** (`unpack/patch_props.py`): in-place rewrite
   of the shared `/dev/__properties__` values (pull → locate name →
   nearest old-value match → `dd conv=notrunc` so every MAP_SHARED reader
   sees the new bytes): `ro.kernel.qemu`, `ro.kernel.android.qemud`,
   `init.svc.qemu-props`, all `qemu.*`, `dev-keys→release-keys`,
   `userdebug→user`, Samsung SM-G991B fingerprints/model, `ranchu→qcom`,
   `emulation→Adreno`, ndk_translation markers blanked.
3. **device-node hiding**: early `chmod 000` (app opens fail EACCES,
   root/system unaffected) + late rename (existence checks fail) of
   `/dev/qemu_pipe`, `/dev/goldfish_pipe`, `/dev/goldfish_address_space`,
   `/dev/goldfish_sync`, `/dev/socket/qemud`.
4. **BlackDex sandbox** (no-root fallback, playstore image): the GPL-3.0
   unpacker installs the target from its real `sourceDir` (byte-identical
   APK → content and signature gates pass) and dumps cookies from its own
   virtual process.

## 7. Static-decrypt feasibility verdict

* Format: header (count+size+hex-key) + AES-ECB-ish ciphertext, key NOT
  the header hex (all probes failed), derived at runtime.
* A full offline decrypt requires reversing the key-derivation inside the
  unpacked SecLLVM code (`FUN_0005d480` engine, 14 KB decompiled in
  `FUN_0005d480-engine.txt`) - feasible but multi-hour work with the
  unicorn emulation harness already scaffolded in `emulate_stage2.py`.
* The dynamic paths (non-debuggable + spoofed environment, BlackDex
  sandbox) are strictly cheaper; the physical-device / self-hosted-Mac
  native-ARM path remains the documented worst-case fallback.
