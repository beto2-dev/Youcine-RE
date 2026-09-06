# 02 - iJiami packer

## Stub DEX

`classes.dex` is 13 608 bytes and decompiles (Jadx 1.5.6) to:

- `s.h.e.l.l.S` extends `android.app.Application`
- `s.h.e.l.l.A` extends `android.app.AppComponentFactory` (API 28+)
- `s.h.e.l.l.N` JNI bridge (`System.load` of `libexec.so`)
- `s.h.e.l.l.C` single native `i(int)`

Sources as decompiled: `evidence/stub/`.

## Boot of the shell

1. Manifest `android:name="s.h.e.l.l.S"` and
   `android:appComponentFactory="s.h.e.l.l.A"`.
2. `A.instantiateClassLoader` / `A.instantiateApplication` call `S.l()`
   which copies `assets/ijm_lib/<abi>/libexec.so` into the app files dir
   (CRC32 compared against the zip entry).
3. ABI pick: `Build.SUPPORTED_ABIS`, ELF header of `/system/bin/linker`,
   and `/proc/self/maps` for `libart.so` / `linker64` to distinguish
   32 vs 64 bit. **x86 / x86_64 are first-class.**
4. `N` static initializer `System.load(filesDir + "/libexec.so")`.
5. `N.al(ClassLoader, ApplicationInfo, package, originApp)` (native)
   returns a ClassLoader that sees the decrypted DEX.
6. `N.r` / `N.ra` swap in `com.mobile.brasiltv.app.App`.
7. Optional `S.sp()` -> `DETool.loadDEso(apkPath, filesDir, packageName)`.

## Payload format (`ijiami.dat`)

```
offset 0  u32le   count of encrypted DEX (4)
offset 4  u32le   likely uncompressed total (41140828)
offset 8  32 ASCII hex chars  MD5 (44f6438002be91557b704ba909f62f58)
offset 40 encrypted stream (no plaintext dex\n magic)
```

Full header dump: `evidence/ijiami-dat-header.txt`.

`ijiami.ajm` starts with `indl01` (native inline/VMP blob). `IJMDal.Data`
(85 KiB) and `signed.bin` (118 KiB) are companion integrity/metadata.

## Native

`libexec.so` (x86_64 ~667 KiB) is `BIND_NOW`, depends on `liblog`,
`libandroid`, `libc`, `libm`, `libdl`. Strings include `ptrace`,
`/proc/self/maps`, `ijiami.dat`, ART `DexFile::OpenMemory` /
`DexFileLoader::OpenCommon` symbol names, `/app_dex/`,
`ijiami SecLLVM compiler 1.7.4.20`. JNI symbols are stripped from the
dynamic table (typical SecLLVM); Ghidra headless recovers them.

## Why dynamic dump

There is no `dex\n` magic in `ijiami.dat`. Decryption happens inside
`libexec` using process state (APK path, package name, possibly
signature). The supported method in this lab is:

- let the shell run on an emulator that matches a shipped ABI (x86_64)
- at 2/4/8/15/30 seconds, read `/proc/<pid>/mem` from a **rooted adb**
  shell and slice valid DEX (see `unpack/external_memdump.py`)

Frida hook of `N.al` and `InMemoryDexClassLoader` is the in-process
variant (`frida-scripts/01_unpack_ijiami_dex.js`).
