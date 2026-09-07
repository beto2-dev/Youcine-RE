# 6. Dynamic unpack methodology (updated 2026-09-07)

The pipeline in `.github/workflows/unpack-emulator.yml` is the result of
~20 instrumented GitHub Actions runs. This document explains how to run
it, what each stage does, and what the remaining steps are.

## 6.1 The pipeline

```
workflow_dispatch (unpack-emulator.yml)
   |
   |- unpack-macos-tcg (primary)   macOS arm64 runner, -accel off TCG,
   |                               ORIGINAL apk, external memdump
   |- unpack-x86 (skipped default) documented research path: dump-build
   |                               + trace_guard ptrace supervisor
   |- rebuild                      validate DEX -> restore manifest ->
                                   strip packer assets -> swap classes*.dex
                                   -> zipalign -> apksigner -> release
                                   'unpacked-1.17.6'
   '- boot-test.yml                installs the rebuilt APK on an arm64
                                   emulator, screenshots, logcat, verdict
```

## 6.2 The dumper (`unpack/external_memdump.py`)

Out-of-process, root-only, no injection:

1. Poll `pidof` until the app appears (the app is started with `am
   start` by the workflow).
2. Wait `--settle` seconds (decryption happens inside
   `attachBaseContext`/`instantiateApplication`, long before any
   Activity).
3. SIGSTOP the process (freezes packer watchdogs and anti-debug timers).
4. On-device batch sweep of `/proc/<pid>/mem` (single root shell, one
   `dd` per region; regions larger than 64 MiB - e.g. the 1 GiB dalvik
   region space - are read as 64 MiB chunks with a 2 MiB overlap).
5. The region files are streamed out with `adb exec-out tar` (no pty
   corruption) and scanned locally for the DEX magic
   (`dex\n` + ASCII version + `\0` + sane `file_size`), de-duplicated by
   sha256.
6. Repeat sweeps until `--expect` unique DEX (4 expected: the header of
   `ijiami.dat` declares 4 payloads) or timeout, then optionally tar
   `/data/data/<pkg>` as on-disk evidence.

Nothing is ever mapped into the target, no ptrace is used, no threads
are created in the process: `/proc/self/maps` and `TracerPid` scans have
nothing to detect.

## 6.3 The rebuild (`unpack/rebuild_unpacked_apk.py` + `validate_and_extract_dex.py`)

1. `apktool d --no-src` (resources + manifest only).
2. Patch `AndroidManifest.xml`: `android:name` `s.h.e.l.l.S` ->
   `com.mobile.brasiltv.app.App`, `android:appComponentFactory`
   `s.h.e.l.l.A` -> `androidx.core.app.CoreComponentFactory`.
3. Delete all iJiami assets (`ijiami.dat`, `ijiami.ajm`, `IJMDal.Data`,
   `signed.bin`, `af.bin`, `libijmDataEncryption*.so`, `ijm_lib/`).
4. `apktool b`, then zip-replace `classes*.dex` with the dumped DEX
   files (sorted by size, minimum 64 KiB so the 13.6 KiB stub DEX is
   excluded).
5. `zipalign -f 4` + `apksigner sign` (v2/v3 research key).
6. Publish as the private release `unpacked-1.17.6` for the boot test.

The resulting build contains zero packer code: the stub DEX is dropped,
the encrypted payload is dropped, the native loaders are dropped and the
manifest points at the real application class.

## 6.4 Verified run history (evidence for every claim in 03)

| Run | What it proved |
|---|---|
| 34044920876 | original apk on x86_64: arm64 process under translation, `N.al` unregistered |
| 34046564135 | android-emulator-runner executes each script line in its own `sh -c` (no line continuations!) |
| 34046807813 | dump-build installs + stub extracts native x86_64 libexec; re-signed apk SIGKILLed ~0.2s (raw syscall) |
| 34047934644 | GitHub macOS runners have no Hypervisor.framework (`HVF_UNSUPPORTED`) |
| 34048953559 / 34049784110 | armeabi-v7a pin: `dlopen ... is for EM_386 instead of EM_ARM`; `libstdc++.so` IS public on the image |
| 34051123509 | bionic `debug.ld.app.<pkg>` logging + frida trace: both loader libs `dlopen -> ok` natively |
| 34051553362 | libc-level suppression insufficient - the suicide bypasses libc |
| 34052830854 / 34053461147 / 34057250027 | the full death ladder neutralized layer by layer (kill, exit, int3, ud2, SIGSEGV) |
| 34055917392 / 34057901348 | packages.xml transplant + SIGSEGV relay: the content gate blocks decryption of any modified APK |
| 34058535954 | linux emulator ships `qemu-system-aarch64` but the launcher blocks arm64 AVDs on x86 hosts |

## 6.5 Final status: GitHub-hosted ARM is impossible; finish on real hardware

The definitive environment matrix (all entries empirically proven):

| Environment | Verdict |
|---|---|
| Linux x86_64 runner + x86_64 AVD | KVM works, but ARM translation breaks SecLLVM and the content gate blocks modified APKs |
| Linux x86_64 runner + arm64 AVD | launcher-refused: `FATAL: Avd's CPU Architecture 'arm64' is not supported ... on x86_64 host` (even though `qemu-system-aarch64` ships in the package) |
| macOS runner (Apple Silicon) + arm64 AVD, any accel setting | qemu always initializes HVF; runners have no Hypervisor.framework entitlement (`HVF error: HV_UNSUPPORTED`) - `-accel off` does NOT override this (proven in runs 34063246076 and 34068661659) |
| macOS runner + arm64 TCG | not available (see above) |

Two ways to finish the dump, both one command away with the tools in
this repo:

### Option A - a physical Android phone (the classic; recommended)

Any real ARM Android device (the packer's target platform - everything
is native and legitimate):

```bash
# on the phone: enable Developer options + USB debugging, plug it in
adb devices                                      # confirm it is visible
adb root 2>/dev/null || true                     # optional; the dumper
                                                 # only needs root for
                                                 # /proc/pid/mem reads
adb install -r -g ycMob_1.17.6_ycsite.apk        # ORIGINAL apk
adb shell am start -n com.world.youcinemobile/com.mobile.brasiltv.activity.SplashAty
ADB="adb" python3 unpack/external_memdump.py \
    --app com.world.youcinemobile \
    --out-dir dumped/youcine --expect 4 --timeout 600 --settle 3
python3 unpack/validate_and_extract_dex.py \
    --dump-dir dumped/youcine --out-dir dexs --min-size 65536
python3 unpack/rebuild_unpacked_apk.py \
    --apk ycMob_1.17.6_ycsite.apk --dump-dir dexs \
    --out youcine-1.17.6-unpacked.apk \
    --keystore re.keystore --storepass android
adb install -r -g youcine-1.17.6-unpacked.apk    # the packer-free build
```

The phone must be rooted for the `/proc/<pid>/mem` reads (or use
`adb shell su -c ...` - the dumper already falls back to `su`).

### Option B - self-hosted macOS runner

Register a self-hosted runner on your own Mac (Settings -> Actions ->
Runners; labels `[self-hosted, macOS]`). On real hardware
Hypervisor.framework works, so the arm64 emulator runs at full speed.
Then dispatch **Dynamic unpack (emulator)** with the `run_selfhosted`
input enabled: the `unpack-selfhosted-mac` job boots the arm64 AVD,
installs the ORIGINAL apk and dumps exactly as above; `rebuild` and
**Boot test** follow automatically.

After the dump: the `rebuild` job (or the local commands above) produce
`youcine-1.17.6-unpacked.apk`, and **Boot test (unpacked APK)** verifies
on an arm64 emulator (self-hosted Mac) that the real
`com.mobile.brasiltv.*` UI boots with screenshots and logcat evidence.

---

## RESULT: unpacked (2026-09-07, run 34133100459)

The definitive pipeline that worked end-to-end, entirely on GitHub's
**free arm64 runners** (`ubuntu-24.04-arm`, public repo = unlimited
minutes):

1. **redroid Android 11 container** (`redroid/redroid:11.0.0-latest`,
   native arm64 - NO ndk_translation, NO qemu/goldfish surface at all).
   `build.prop` is patched BEFORE first boot (`docker create` ->
   `docker cp` -> `docker start`), replace-only: `ro.debuggable=0`,
   `ro.secure=0` (root adbd), `user`/`release-keys` Samsung SM-G991B
   identity on the partition-scoped `ro.product.system.*` keys.
   **Never append foreign keys** - init's property-context loader aborts
   (run 34121251995).
2. **adbd root FIRST**, then the runtime verify-and-fix block patches
   the property area (`patch_props.py`) + framework restart for any
   stragglers (`ro.boot.hardware=redroid`, aliases).
3. **Install the ORIGINAL byte-identical APK + launch** - the iJiami
   stub decrypts and the real app runs (SplashAty -> DMCAAty; the
   environment gate that blocked every x86_64 emulator run never fires
   on native redroid).
4. **SIGSTOP + targeted extraction of ART's `[anon:dalvik-DEX data]`
   containers** (`unpack/dexdata_extract.py` + `tools/memread.c`, a
   static `pread64` helper compiled on the runner): each decrypted dex
   spans SEVERAL map entries - big `r--p` pieces interleaved with small
   `-wxp` (no read bit!) pieces; `/proc/<pid>/mem` reads use
   `FOLL_FORCE`, so the whole span reads as one contiguous range. The
   toybox `dd` sweep silently produced nothing at those addresses -
   `pread64` is the reliable reader.
5. **Checksum repair** (`validate_and_extract_dex.py`): the packer
   decrypts in place, so the runtime pages differ from the original
   adler32/SHA-1. Repair order is critical: SHA-1 first (covers
   `[32:end]`), then adler (covers `[12:end]`, including the fresh
   SHA-1 field).
6. **Rebuild** (apktool: real Application class restored, packer assets
   dropped, 5 recovered `classes*.dex` swapped in) -> zipalign ->
   apksigner -> published to the **`unpacked-1.17.6` Release** ->
   **Boot test** chained.

Five dexes recovered (11.9 / 11.5 / 10.9 / 6.3 / 0.6 MB); Jadx 1.5.6
decompiles them (2,596 classes in the first alone). Full evidence chain
in the `dumps-redroid` artifacts of runs 34133100459+.

What did NOT work (documented so nobody retries blind alleys):
- x86_64 emulator + any prop spoof: the translated app never launched
  cleanly (`am start` deadlock) and the qemu-signal hunt was a red
  herring - run 34084986538 proved qemu signals are not the gate.
- BlackDex sandbox on redroid: hidden-API unseal fixed
  (`settings put global hidden_api_policy 1`), but iJiami's NATIVE
  death ladder still SIGKILLs the sandbox ~36 ms in via raw syscalls
  (no Java-level hook can intercept).
- Magic scanning of `/proc/<pid>/mem`: the packer wipes its own buffer
  after class loading; the classes live on ONLY as ART's
  `[anon:dalvik-DEX data]` containers (which magic scans can still
  miss due to the dd high-address quirk - hence pread64).

## The final defense layer (boot-test verdict, corrected 2026-09-08)

### What the rebuild v3-v5 fixes proved

Three real defects kept the rebuilt packer-free APK from reaching the
app's own code. All three were fixed empirically (runs 34164306975,
34166250339, 34166188171):

1. **The DE SDK was never loaded.** `DETool.loadDEso` has ZERO callers
   in the decrypted DEX (the stub `S.sp()` reflects a
   `loadDEso(String,String,String)` overload that does not exist in
   DE SDK 4.3.4 - the real entry is `loadDEso(Context)`; the packer's
   native loader did the job before handing control to the real
   Application). Fix: `unpack/stubs/src/com/youcine/re/
   BootProvider.java` - a ContentProvider (installed by
   `installContentProviders()` BEFORE `Application.onCreate`, the same
   early-init pattern as FacebookInitProvider) that reflectively calls
   `loadDEso` and, on translated runtimes, performs its own
   copy/load/`dowork` with the ABI the linker actually accepts.
2. **The ABI trap.** On the x86_64 emulator the app runs under
   ndk_translation: DETool's `/proc/self/exe` probe picks the HOST
   arch (x86_64) but the translated dlopen namespace only accepts the
   installed `primaryCpuAbi` (arm64-v8a): `dlopen failed: is for
   EM_X86_64 (62) instead of EM_AARCH64 (183)`. The BootProvider
   compares DETool's probe with `primaryCpuAbi` (reflection) /
   `nativeLibraryDir` (public) and rescues the load. Verified in run
   34166250339: `System.load(...) OK` + `DETool.dowork -> true`.
3. **The signature kill-switch.** `App.onCreate` also calls
   `ConfusionUtils.check()`, which spawns the watchdog thread that
   allowlists only the original cert MD5 and fires `HOME +
   System.exit(0)` on re-signed builds (observed in run 34142729238
   logcat 16:21:55.059). Fix: `unpack/patch_confusion_cc.py` rewrites
   `cc()`'s whole insn region as `const/4 v0,1 ; return v0 ; nop-fill`
   (same size, tries=0 - prefix-patching alone leaves misaligned dead
   code that the ART verifier's linear pass rejects, run 34164727188:
   "register index out of range (12 >= 3)").

### Where the app actually stops, and why (the corrected mechanism)

With all three fixes in, the v5 build gets further than ever: every
provider initializes, the real `App.onCreate` runs, ConfusionUtils is
neutralized, the DE SDK initializes (`DE: DECRYPT cost time 14 ms`,
`DE: ms_sm4_001 datapath=... sp_version=1.4`) - and the main thread
still dies at the first iJiami-VMP-protected method:
`App.onCreate:139 -> Aria.init -> SqlHelper.getDb ->
UnsatisfiedLinkError`.

The corrected understanding of the last defense layer (replacing the
earlier "signature-gated DE-SDK registration" hypothesis, which the
v5 run disproved - the DE lib loads and `dowork` returns true, and
`SqlHelper.getDb` stays unregistered):

1. **`libijmDataEncryption.so` is NOT the method registrar.** The DE
   SDK is the **SM4 encrypted-SharedPreferences engine** for the
   vendor-integrated EFS SDK (`com.efs.sdk.*`): its `dowork(key, 1024,
   hash, ...)` initializes the SM4 data path. It works fine on a
   re-signed build (`dowork -> true`).
2. **The ~805 ACC_NATIVE methods** (17 Aria, 424
   `com.mobile.brasiltv.*`, 53 Facebook, EFS, ...) get their JNI
   implementations registered at runtime by **libexec's content-gated
   engine** - the same engine whose ed25519/`signed.bin` check
   requires the byte-exact original APK (see
   03-protections-and-bypass.md, L2). Removing the packer removes the
   only registrar.
3. **The ~45,238 `return-void+nop` extraction stubs** (13,478
   constructors + 31,760 void methods - every `Companion.<init>`,
   anonymous listener, `configView` of every activity...) are bodies
   iJiami extracted at pack time and re-materializes in the in-memory
   DEX pages only as classes load - again from libexec's encrypted
   blobs. The dump captured the boot-path classes already restored
   (that is why `App.onCreate` executes real code) and everything
   else still stubbed: e.g.
   `com.facebook.appevents.AppEvent$SerializationProxyV2$Companion.<init>`
   and `tv.danmaku.ijk.media.player.ExoMediaPlayer$1.<init>` fail the
   verifier with "Constructor returning without calling superclass
   constructor" (already visible as dex2oat rejections in the v3 logs).

**Consequence**: a re-signed packer-free build boots the real app
process through every non-protected layer and stops at the first
VMP-protected method - by design. Full boot requires re-materializing
the ~805 native bodies and ~45k stub bodies, which live only inside
the content-gated packer engine. The research deliverables stand: all
5 decrypted dexes (11.9/11.5/10.9/6.3/0.6 MB, jadx-decompilable,
2,596+ classes) in the `unpacked-1.17.6` release (pristine dump dexes
now pinned in the immutable `dumps-1.17.6` release) and a
reproducible, deterministic GitHub-Actions-native pipeline
(`rebuild-fix.yml` fast loop: sources only from `packed-1.17.6` +
`dumps-1.17.6`, sanity-asserts the patches inside the published APK,
chains the boot test).

### Phase 2 (the only remaining path to a fully booting build)

1. **Frida in the redroid arm64 run of the ORIGINAL apk**: hook
   `RegisterNatives` to capture the full method-to-fnPtr table and
   dump the native bodies; force-load every class (warm-up sweep) so
   libexec re-materializes all ~45k stub bodies in the DEX pages, then
   re-dump. The existing `frida-scripts/` + `unpack/redroid_flow.sh`
   infrastructure is the starting point.
2. Rebuild with the re-dumped dexes; the remaining 805 natives would
   still need a bridge (de-natify with Java bodies for the
   open-source families - Aria/Facebook - and a registrar shim for
   the vendor's own 424).

The **Boot test** workflow encodes the honest verdict: a main-thread
death inside `com.mobile.brasiltv.*`/`com.arialyy.*` code is reported
as `RESEARCH OUTCOME - UNPACK VERIFIED`, and a real `BOOT OK` now
requires main-thread alive + resumed activity + a focused
youcinemobile window (run 34166250339 initially produced a
FALSE-POSITIVE "BOOT OK": the crash handler itself died on a stub
VerifyError, leaving a zombie process with a black window - see the
workflow comments).
