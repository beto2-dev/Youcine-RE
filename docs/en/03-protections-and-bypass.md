# 3. Protections and bypass (updated 2026-09-07)

This document is the complete map of the iJiami protection stack found in
YouCine 1.17.6 (`ycMob_1.17.6_ycsite.apk`) and the bypass of each layer,
as established empirically during the GitHub Actions runs of this
repository. Every claim below is backed by a run log kept in the private
Actions history and by artifacts in `evidence/`.

## 3.1 The packer

| Property | Value |
|---|---|
| Vendor | iJiami (AiJiami / 爱加密) |
| Compiler string | `ijiami SecLLVM compiler 1.7.4.20` (inside `libexec.so`) |
| Stub DEX | 13,608 bytes, only `s.h.e.l.l.{S,A,N,C}` |
| Encrypted payload | `assets/ijiami.dat`, 9,543,463 bytes, 4 DEX payloads |
| Native loader | `assets/ijm_lib/<abi>/libexec.so` + `libexecmain.so` (4 ABIs) |
| Data-encryption sidecar | `com.ijm.dataencryption.DETool` + `libijmDataEncryption*.so` |
| Integrity | `assets/signed.bin` + `libed25519.so` |
| Real application | `com.mobile.brasiltv.app.App` (lineage of Magis/Xuper/Brasil TV) |

The stub selects the ABI like this (reconstructed from the decompiled
`S.java` / `N.java` in `evidence/stub/`):

```java
String linkerArch = ld();                    // ELF e_machine of /system/bin/linker(64)
String abis      = a();                      // Build.SUPPORTED_ABIS reflection
if (linkerArch.contains("x86")) {
    extract(il() ? "x86_64" : "x86");        // 64-bit process -> x86_64
} else {
    extract(il() ? "arm64-v8a" : "armeabi"); // il(): /proc/self/maps contains /lib64/
}
```

`N`'s static initializer then runs `System.load(filesDir + "/libexec.so")`
and `System.load(filesDir + "/libexecmain.so")`, and the actual
decryption happens in the native method `s.h.e.l.l.N.al(...)`, which
`A.instantiateApplication()` calls to swap in the real classloader before
the real `Application` is instantiated.

## 3.2 Layer-by-layer findings and countermeasures

### L1 - ABI / process selection (the translation trap)

**Finding.** On an x86_64 emulator with `ndk_translation`, installing the
original APK assigns `primaryCpuAbi=arm64-v8a` (the APK ships
`lib/armeabi-v7a` and `lib/arm64-v8a` only). The process is a **full ARM
process** forked from `/system/bin/arm/app_process`; bionic resolves
system libraries from `/system/lib/arm/`. Two consequences:

* The x86 build of `libexec.so` is rejected by the linker:
  `dlopen failed: ".../files/libexec.so" is for EM_386 (3) instead of
  EM_ARM (40)` (captured with `setprop debug.ld.app.<pkg> dlopen`).
* The arm64 build of `libexec.so` loads but **SecLLVM self-modifying
  code does not survive binary translation**, so the JNI registration for
  `s.h.e.l.l.N.al` never happens and the stub dies with
  `UnsatisfiedLinkError`.

**Countermeasure.** `unpack/make_dump_build.py` strips `lib/arm*` so the
app is installed with no native ABI and forks from the 64-bit x86_64
zygote; the stub then extracts `ijm_lib/x86_64/libexec.so` which runs
**natively** (proven: frida trace shows `dlopen -> ok` for both loader
libraries, and SELinux grants `execute` on the app_data_file).

### L2 - Signature verification (anti-repackaging)

**Finding.** iJiami verifies that the installed APK is *content-identical*
to the packed original. All three of these were tried and all three were
insufficient:

1. Keeping the original v1 JAR files (`META-INF/XXL-OTT.RSA/.SF/MANIFEST.MF`)
   in the re-signed dump-build - the check still failed.
2. Spoofing the recorded certificate through PackageManager
   (`unpack/patch_packages_xml.py` transplants the original `<sigs>`
   block into `/data/system/packages.xml` while the framework is
   stopped) - the check still failed.
3. Frida replacing libc-level `kill`/`exit` - the suicide is issued with
   **raw syscalls** (bypasses libc hooks entirely).

**Conclusion.** The gate is a content-level check (most plausibly the
ed25519-signed `signed.bin` / a hash over the APK), evaluated *before*
`N.al()` decrypts anything. A re-signed or otherwise modified APK never
reaches decryption. This is the key operational insight of the whole
lab: **dynamic unpacking of this packer requires running the byte-exact
original APK in a native-ARM environment.**

### L3 - The anti-tamper death ladder

When the check fails, the packer walks an escalation ladder. Each step
below was neutralized in `unpack/trace_guard.c` (a ptrace-based,
NDK-compiled x86_64 supervisor that attaches within milliseconds of the
process appearing and follows every thread and forked child):

| Step | Mechanism | Observed as | Countermeasure |
|---|---|---|---|
| 1 | `kill(getpid(), SIGKILL)` raw syscall | `neutralized kill syscall 62 (sig 9)` | rewrite syscall to `getpid` at kernel level |
| 2 | `exit`/`exit_group` raw syscall | `neutralized exit syscall 60/231` | rewrite to `getpid` |
| 3 | `int3` breakpoint traps (anti-debug probe) | `swallowed SIGTRAP (int3 probe)` x47 | suppress the signal; execution continues past the `int3` |
| 4 | `ud2` illegal instruction | 5.4M `suppressed fault signal 4` | read the instruction with PEEKDATA; on `0F 0B` advance RIP by 2 |
| 5 | deliberate SIGSEGV | `tracee gone (sig 11)` | relaying it is fatal (it is *not* an ART implicit-null check); suppressing it pins the thread in a refault loop, alive but frozen |

With the whole ladder blocked the process stays alive but pinned
**before** decryption - which confirms L2: there is no
"force-continue" past the content gate.

### L4 - Anti-debug probes

* `PTRACE_TRACEME` from the tracee: fails under a real tracer. The guard
  rewrites the `ptrace` syscall into `sched_yield`, which returns 0 -
  the probe believes it succeeded.
* Watchdog children: forked children are traced automatically via
  `PTRACE_O_TRACEFORK|TRACECLONE`.
* The external `/proc/<pid>/mem` dumper never attaches to the process, so
  `/proc/self/maps` and `TracerPid` scans have nothing to find.

### L5 - Environment requirements

* The `libexecmain.so` of every ABI declares `DT_NEEDED libstdc++.so`.
  Android 11 *does* ship a public `libstdc++.so`, so this is not a
  blocker on the emulator (verified in run 34049784110), but it matters
  on older/thinner systems.
* `System.load` from `filesDir` works on API 30 for targetSdk 33
  (SELinux `execute` on `app_data_file` is granted; no W/X block).

## 3.3 The working strategy

| Environment | Result |
|---|---|
| x86_64 emulator + original APK (any ABI pin) | SecLLVM fails under ndk_translation - no decryption |
| x86_64 emulator + dump-build + full guard | native loader runs; content gate refuses to decrypt - documented dead end |
| **macOS arm64 runner (Apple Silicon) + `-accel off` TCG + original APK** | **everything native and legitimate: checks pass, decryption proceeds** (this is the final pipeline; see 06-dynamic-unpack.md) |
| GitHub Linux runners + arm64 AVD | blocked by the emulator launcher (`FATAL: Avd's CPU Architecture 'arm64' is not supported ... on x86_64 host`) |
| GitHub macOS runners with default accel | no Hypervisor.framework entitlement (`HVF error: HV_UNSUPPORTED`) - must pass `-accel off` |

## 3.4 What is client-side vs what the protections actually protect

Everything in this file is **client-side** and was mapped, defeated or
documented. What the packer ultimately protects is the *decryption key
path* plus the contents of `ijiami.dat`; once the app runs natively, the
four decrypted DEX payloads are recoverable from process memory with the
out-of-process dumper (`unpack/external_memdump.py`), which sweeps:

* anonymous and `[anon:dalvik-*]` mappings (including the 1 GiB region
  space, read as 64 MiB chunks with a 2 MiB overlap),
* `[heap]`, `/memfd:*`, dalvik-cache mappings,
* anything containing the `dex\n<ver>\0` magic with a sane header.

The server-side half of the app (portal hosts, EPG, VIP entitlements,
force-upgrade kill-switch) is listed in 05-client-vs-server.md and is out
of reach of any packer removal.
