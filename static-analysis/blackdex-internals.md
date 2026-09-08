# BlackDex Internals — Reverse-Engineering Notes (v3.2, 64-bit)

Target of analysis: `blackdex64-v3.2.apk`
(sha256 `173a13f8ccb1c523dab8930aa06d0635196dee753bd61e90c8add5f8a018ba59`,
5,282,538 bytes, GPL-3.0, https://github.com/CodingGay/BlackDex).
Method: apktool full decode (smali + resources) + native-lib ELF/symbol
inspection with `lief`/`strings`. jadx full-Java decompilation was attempted
but the 2-core sandbox could not finish it; all evidence below is from smali,
resource XML and ELF symbols, which is exact ground truth.

- Package: `top.niunaijun.blackdexa64` (app label **BlackDex64**)
- minSdk 21, **targetSdk 30**, `requestLegacyExternalStorage="true"` (ignored
  on R because target is 30)
- `lib/arm64-v8a/` only: `libblackdex.so` (956,936 B), `libblackdex_d.so`
  (313,480 B), `libumeng-spy.so` (239,848 B) — all `ELF aarch64`, NDK r21e
- Assets: `empty.jar`, `junit.jar`, `vm.jar` (used by `VMCore.loadEmptyDex`)
- Built on the **BlackBox/BlackDexCore** virtualization framework
  (`top.niunaijun.blackbox.*`, VirtualApp-style) with 100 proxy stub
  components (`ProxyActivity$P0..P99` in processes `:p0..:p99`,
  `ProxyContentProvider$P0..P99`, `DaemonService` in process `:black`).

---

## 1. UI flow map (what the automation will actually see)

```
WelcomeActivity (LAUNCHER, theme-only splash)
   └─ onCreate → startActivity(MainActivity) → finish()      [no delay, no dialog]
MainActivity (top.niunaijun.blackdex.view.main.MainActivity)
   ├─ RecyclerView id/recyclerView  (LinearLayoutManager, MainAdapter)
   │    row = item_package.xml: LinearLayout(clickable root)
   │          ├─ ImageView  id/icon          48dp
   │          ├─ TextView   id/name          app label (16sp)
   │          └─ TextView   id/packageName   package name
   ├─ StateView  id/stateView  (loading / empty / content)
   ├─ SearchView id/searchView (SimpleSearchView, toolbar menu)
   └─ FloatingActionButton id/fab (folder icon → file-chooser of dump dir)
onCreate: initView() → initViewModel() → initSearchView()
          → BlackDexCore.get().registerDumpMonitor(mMonitor)
initViewModel(): stateView.showLoading() → viewModel.getAppList()
   → posts List<AppInfo> → stateView.showContent(), adapter data set
```

**App list source** — `DexDumpRepository.getAppList()`:
`BlackBoxCore.getPackageManager()` (the *real* system PM, not the fake one)
`.getInstalledApplications(0)`, then per app:
`new File(applicationInfo.sourceDir)` → **`AbiUtils.isSupport(File)`** filter
→ label/icon via the real PM. So the list mirrors the *really installed* apps.

**Abi filter** — `AbiUtils(File)` reads the APK zip and collects which of
`lib/arm64-v8a`, `lib/armeabi`, `lib/armeabi-v7a` exist. `isSupport()`:
no native libs at all → supported; otherwise `BlackBoxCore.is64Bit()`
(`Process.is64Bit()` of the *BlackDex host process*) → app must contain
`lib/arm64-v8a`; 32-bit host → app must contain `armeabi(-v7a)`.
**Consequence for our x86_64 emulator:** BlackDex64 installs as
`primaryCpuAbi=arm64-v8a` and runs as a *translated arm64* process → it is a
64-bit process → Youcine (`lib/arm64-v8a` present) **passes the filter and is
listed**. (This also means only 64-bit-capable targets are listed on
BlackDex64 — the 32-bit BlackDex build is the counterpart.)

**Tapping a row** — `MainActivity$initView$1` (the `setOnItemClick` callback,
installed by `BaseAdapter.onBindViewHolder` on the row root):
closes the search view if open, hides the keyboard, then calls
`viewModel.startDexDump(data.packageName)` **directly**.
**There is NO confirmation dialog** between tap and unpack start.

**From tap to dump (full chain):**

```
MainViewModel.startDexDump(pkg)                      [coroutine on main]
 └─ DexDumpRepository.dumpDex(source, LiveData)
     ├─ post DumpInfo(state=300)          → ProgressDialog shows
     ├─ BlackDexCore.dumpDex(String pkg)
     │    ├─ BlackBoxCore.installPackage(pkg)  → real PM.getPackageInfo(pkg).applicationInfo
     │    │      .sourceDir  (i.e. /data/app/.../base.apk of the REAL installed app)
     │    │      → BPackageManager.installPackageAsUser(sourceDir, InstallOption.installBySystem(), 0)
     │    │      (the sandbox install copies the ORIGINAL, byte-identical APK)
     │    └─ BlackBoxCore.launchApk(pkg)  → BPackageManager.getLaunchIntentForPackage
     │            → BlackBoxCore.startActivity(intent)  → ProxyActivity$P0 in process :p0
     └─ startCountdown(installResult, LiveData)  [GlobalScope coroutine]
          loop while BlackDexCore.isRunning():
             delay(20_000 ms)                       ← single 20 s tick in default mode
             if (!fixCodeItem) break                ← default: break after ONE tick
          if dumpTaskId unchanged:
             BlackDexCore.isExistDexFile(pkg)  (dir.listFiles().length > 0)
               true  → post DumpInfo(200, ".dex files were saved in: <dir>/<pkg>")
               false → post DumpInfo(500, null)  → "Unpack failed" dialog
```

`isRunning()` checks `ActivityManager.getRunningAppProcesses()` for process
names ending in `p0`..`p99` (`top.niunaijun.blackdexa64:p<N>`).
Note the countdown's fixed 20 s tick: **the in-app dialog can appear before
the dump is actually finished** (or after files already exist) — automation
must poll the filesystem, not the dialog.

**Inside the `:p0` virtual process** (`BActivityThread.handleBindApplication`):

```
FileUtils.deleteDir(old install)     → clean sandbox state
VMCore.init(Build.VERSION.SDK_INT)   → native engine init (see §3)
IOCore.get().enableRedirect(context) → I/O rules of the sandbox
fake AppBindData + reflection into ActivityThread
LoadedApk.makeApplication()          → instantiate the TARGET's Application
                                      (iJiami stub attachBaseContext runs HERE)
handleDumpDex(pkg, result, classLoader)
 └─ new Thread: sleep(500 ms)
    └─ VMCore.cookieDumpDex(classLoader, pkg)      [dump +500 ms after makeApplication]
        catch → DumpResult.dumpError(msg) → BDumpManager.noticeMonitor
        after → if dir.listFiles() non-empty: DumpResult.dumpSuccess → noticeMonitor
```

**Back in the UI (MainActivity observer + mMonitor binder):**

| DumpInfo.state / DumpResult | UI effect |
|---|---|
| 300 (`0x12c`) | `ProgressDialog` fragment: TextView `id/title` = **"Unpacking…"**, horizontal ProgressBar `id/progress` (`classes.dex (n/n)` progress via `setProgress(curr,total)`) |
| 200 (`0xc8`) | MaterialDialog title **"Unpack successfully"**, message **".dex files were saved in: \<abs dir\>"**, positive **Confirm** |
| 404 (`0x194`) | MaterialDialog title "Unpack failed", message **"Error: \<msg\>"**, positive Confirm |
| 500 (`0x1f4`) | MaterialDialog title **"Unpack failed"**, message "Unknown error，may be the app is incompatible… open an Issue on GitHub", negative **Github** (opens https://github.com/CodingGay/BlackDex/issues in browser — do NOT tap from automation), positive **Confirm** |

**First-run storage permission (Android 11):**
`PermissionActivity.requestStoragePermission()`:
`BuildCompat.isR()` (SDK ≥ 30) → if `!Environment.isExternalStorageManager()`:
MaterialDialog title **"Permission Required"**, message "This app can not read
and write local files correctly without the required permission.",
negative **Later**, positive **Grant Permission** →
`startActivity(Intent("android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION",
  data=package:top.niunaijun.blackdexa64))` (All-Files-Access settings page).
If already manager: launches the (no-op on R) `WRITE_EXTERNAL_STORAGE`
runtime request. The FAB folder button triggers the same flow.
**Automation must pre-grant** `appops set top.niunaijun.blackdexa64
MANAGE_EXTERNAL_STORAGE allow` (works from adb shell on API 30) or drive the
dialog + settings toggle.

**Settings** (SettingActivity, not needed by automation — defaults are fine):
`save_enable` (default **true** → default dump dir), `hook_dump` (default
**false**), `fix_code_item` / "Deep Unpacking" (default **false**), `save_path`.

## 2. Exact tap sequence + output layout

Recommended automation (implemented in `unpack/blackdex_auto.py`):

1. Pre-grant All-Files-Access:
   `adb shell appops set top.niunaijun.blackdexa64 MANAGE_EXTERNAL_STORAGE allow`
2. `adb shell am force-stop top.niunaijun.blackdexa64`
   (each cold start resets the sandbox: `BlackDexCore.doCreate()` uninstalls
   every virtual package)
3. `adb shell am start -W -n top.niunaijun.blackdexa64/top.niunaijun.blackdex.view.main.MainActivity`
   (MainActivity is **not exported** and has no intent-filter — the shell uid
   holds `START_ANY_ACTIVITY` so `am start` still works; fall back to
   `-n …/top.niunaijun.blackdex.view.base.WelcomeActivity` or
   `monkey -p top.niunaijun.blackdexa64 -c android.intent.category.LAUNCHER 1`)
4. `uiautomator dump` (retry on "could not get idle state") →
   `adb exec-out cat /sdcard/window_dump.xml` → find the node whose
   `text` equals **`com.world.youcinemobile`** (`id/packageName`, unique) or
   the label (**"YouCine"**) → tap center of its row
   (`adb shell input tap X Y`). No confirmation dialog follows.
5. Progress = "Unpacking…" dialog; completion signals per table above.
   If the permission dialog appears, tap "Grant Permission", flip the
   All-Files switch, press BACK.
6. Poll the output directory on the device (do not trust the 20 s dialog):

**Output directory** (`BlackDexLoader$Companion.getDexDumpDir(context)`):

| Android | path | evidence |
|---|---|---|
| R+ (API ≥ 30) | `/storage/emulated/0/Download/dexDump/<package>/` | `File(context.externalCacheDir.parent×4, "Download/dexDump")` — externalCacheDir `/storage/emulated/0/Android/data/<host>/cache` → 4×parent → `/storage/emulated/0` |
| < R | `/storage/emulated/0/Android/data/top.niunaijun.blackdexa64/dump/<package>/` | `File(externalCacheDir.parent, "dump")` |

(No "BlackDexBox" directory exists in v3.2 — that was older BlackDex ≤ 1.x.
A custom path is only settable via the in-app Settings file chooser.)

For Youcine → **`/storage/emulated/0/Download/dexDump/com.world.youcinemobile/`**

**File naming** (from `libblackdex.so` strings): `classes.dex`,
`classes%zu.dex` → `classes.dex`, `classes2.dex`, `classes3.dex`, …
After the dump, `DexUtils.fixDex(file)` (Java) writes a repaired copy
`<name>_fix.dex` next to each file (recomputed file size, checksum and
SHA-1 signature header — `calcChecksum`/`calcSignature("SHA-1")`,
`fixFileSizeHeader`), because dumped in-memory DEX headers are often stale.
So expect both raw and `_fix` files; prefer the `_fix` ones for jadx.
iJiami-packed apps dump as standard DEX; apps shipped as CompactDex are
converted by the native engine (see §3).

## 3. Dump engine strategy per Android version

Two engines, selected by settings; both end in `libblackdex.so`:

**A. Cookie dump (default)** — `VMCore.cookieDumpDex(ClassLoader, pkg)`:

1. `DexFileCompat.getCookies(cl)` — pure reflection:
   `BaseDexClassLoader.pathList` → `dexElements[]` → each `dexFile` →
   `DexFile.mCookie`:
   - `BuildCompat.isM()` (SDK ≥ 23): mCookie is `long[]` → **all** elements
     returned (on ART ≥ 7.0 each element is an `art::DexFile*` handle;
     native side validates).
   - SDK < 23: mCookie is a single `Long`.
2. Output dir mkdirs + `DumpResult` (dir, packageName, total = cookies).
3. Fixed thread pool (`availableProcessors()`), one task per cookie:
   native **`cookieDumpDex(long cookie, String dir, boolean fixCodeItem)`**
   (`_ZN7DexDump13cookieDumpDexEP7_JNIEnvlP8_jstringh` in libblackdex.so).
4. `CountDownLatch.await()` then `DexUtils.fixDex()` on every `*.dex`.

**B. Hook dump (setting `hook_dump`, default off)** —
`AppInstrumentation.callActivityOnCreate`: if `BlackBoxCore.isEnableHookDump()`
→ mkdirs dump dir → reflectively invoke native **`VMCore.hookDumpDex(String dir)`**
before the target activity's `onCreate`. The native side installs hooks on
ART's DexFile/openDexFile path (PLT hooking via the bundled `xhook`
(`Java_com_qiyi_xhook_NativeHandler_*`) + inline hooks via `libblackdex_d.so`,
which is a **Dobby-style assembler/hook library** — symbols
`zz::AssemblerBase`, `CpuFeatures::ClearCache`), dumping every DEX as it is
loaded. Useful for packers that load dex late; riskier (hooks ART internals).

**Version dispatch evidence:**

- Java: `BuildCompat.isM()` (SDK 23) selects mCookie shape;
  `BuildCompat.isR()` (SDK 30 / R preview) selects dump dir + All-Files
  permission flow.
- Native: `BActivityThread` calls **`VMCore.init(Build.VERSION.SDK_INT)`**
  before anything else in the virtual process — the API level is handed to
  the native engine, which carries per-version handling.
- **`libblackdex.so` embeds a private copy of ART itself**, renamed to avoid
  symbol clashes: namespaces `art_lkchan` (`DexFile`, `CompactDexFile`,
  `DexFileLoader`, `DexFileVerifier`, `OatDexFile`, `dex::` containers —
  including `DexFileLoader::GetMultiDexClassesDexName`,
  `CompactDexFile::WriteMagic/CalculateChecksum/GetCodeItemSize/
  GetDequickenedSize`, i.e. **compact-dex → standard dex + de-quickening
  conversion**), `zip_archive_lkchan` (libziparchive), `android_lkchan`
  (android-base logging). Built from the BlackDex `Bcore/src/main/cpp`
  tree (source paths in debug strings). The engine therefore knows the ART
  `DexFile`/`OatDexFile` in-memory layout and walks the cookie directly,
  re-serializing the in-memory DEX (or converting CompactDex) to disk.
- Also present: `VMCore::findMethod`, `loadEmptyDex`, `getCallingUid`,
  `redirectPath*` (I/O sandbox), `hideXposed` (anti-anti-frida for the
  target), `enableSigSegvProtection`/`enableDebug` (xhook NativeHandler).

**API 30 verdict:** BlackDex v3.2 explicitly targets R (targetSdk 30, R dump
dir, All-Files flow, app label localization). The cookie engine reads
`art::DexFile` layouts that are stable across 8.0–12 for the fields used
(begin_, size_, location). API 30 is squarely inside the supported envelope
(BlackDex advertises 5.0–12 support; v3.x 64-bit adds R+ paths).

## 4. ARM-only native risk on the x86_64 API 30 emulator

Our emulator image `system-images;android-30;google_apis_playstore;x86_64`
is a **production build (no root)** whose zygote64 advertises
`abilist=x86_64,arm64-v8a` and ships `libndk_translation` (binary ARM
translation; confirmed in prior runs: "ndk_translation: Initialized NDK
translation (aarch64)"). Risk assessment:

1. **BlackDex64 itself installs as arm64-v8a** (its only ABI) and its UI runs
   translated. Java/UI automation is unaffected by translation — the list,
   dialogs, taps all work. ✅
2. **`libblackdex.so` (dump engine) also runs translated.** It dereferences
   real in-memory ART structures of the host x86_64 ART. Cross-arch layout
   is identical for the same platform build (both LP64, same struct source),
   so struct walking is expected to work; performance of translated code
   scanning/multi-MB re-serialization is the cost (the 20 s countdown and
   our 300 s poll budget account for this). ⚠️ moderate risk, slow.
3. **The critical risk is the target, not the tool.** The BlackBox proxy
   process `:p0` is forked from the translated BlackDex64 process, so the
   iJiami stub's `assets/ijm_lib/arm64-v8a/libexec.so` (SecLLVM,
   self-modifying/JIT code) executes under ndk_translation as well.
   **Prior evidence (Task 1, run 34044920876): exactly this configuration
   failed** — the app died at `s.h.e.l.l.N.al` with `UnsatisfiedLinkError`
   because translated SecLLVM never registered its JNI natives. If that
   repeats inside the sandbox, decryption never happens and the cookie dump
   captures only the 13.6 KB stub `classes.dex`. 🔴 high risk.
4. Mitigating factors vs. the Task 1 failure:
   - BlackDex loads the **byte-identical original APK** (it installs from
     the real `applicationInfo.sourceDir`), so the iJiami content-integrity
     gate that killed all re-signed dump-builds (Task 5) is *not* triggered.
   - No re-signing, no ptrace from our side, no `pm install --abi` tricks —
     the failure surface narrows to "does SecLLVM survive translation".
   - `hideXposed`/sandbox hooks may dodge some environment checks, but they
     do not fix translated self-modifying code.

**Verdict:** the *automation* is deterministic and low-risk (simple two-tap
UI flow, fixed output path, no root needed). The *dump outcome* on
x86_64+ndk_translation is genuinely uncertain, dominated by whether iJiami's
SecLLVM initializes under translation; prior project evidence says it will
not, so expect at minimum the stub dex and treat a 4-DEX result as a pleasant
surprise. The reliable environment for BlackDex + this packer remains a
**native arm64 Android** (real device, or Apple-Silicon emulator with HVF);
BlackDex needs no root there either, which keeps it the best "one-command"
path on real hardware.

## 5. Recommended automation sequence (host side)

```
# preconditions (done by the workflow): emulator booted, BlackDex64 + ORIGINAL
# Youcine APK installed (adb install ycMob_1.17.6_ycsite.apk)
adb shell appops set top.niunaijun.blackdexa64 MANAGE_EXTERNAL_STORAGE allow
python3 unpack/blackdex_auto.py \
    --app-id com.world.youcinemobile --label YouCine \
    --out-dir dumps/blackdex --timeout 300
# then: validate_and_extract_dex.py on dumps/blackdex/com.world.youcinemobile/
# (prefer *_fix.dex; dedupe by sha256; expect 4 real DEX ~10 MB each for Youcine)
```

`blackdex_auto.py` implements: appops pre-grant, force-stop + am start with
LAUNCHER fallback, uiautomator dump retry loop (handles "could not get idle
state"), row matching by package name (unique) or label with variants,
single tap (no confirm dialog exists), generic positive-button dialog
handler (never taps Github/Cancel/Later), All-Files-Access settings fallback,
filesystem polling of `/storage/emulated/0/Download/dexDump/<pkg>` until
stable, and `adb pull` with tar + per-file `exec-out cat` fallbacks. Exit 0
only when ≥1 dumped file was pulled.
