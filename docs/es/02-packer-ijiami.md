# 02 - Packer iJiami

## DEX stub

`classes.dex` ocupa 13 608 bytes y JADX 1.5.6 lo baja a:

- `s.h.e.l.l.S` extends `Application`
- `s.h.e.l.l.A` extends `AppComponentFactory`
- `s.h.e.l.l.N` puente JNI (`System.load` de `libexec.so`)
- `s.h.e.l.l.C` nativo `i(int)`

Fuentes: `evidence/stub/`.

## Arranque del shell

1. Manifest `android:name="s.h.e.l.l.S"` y
   `android:appComponentFactory="s.h.e.l.l.A"`.
2. `A.instantiateClassLoader` llama `S.l()` y copia
   `assets/ijm_lib/<abi>/libexec.so` al files dir (CRC32 contra el zip).
3. Seleccion de ABI: `Build.SUPPORTED_ABIS`, ELF de `/system/bin/linker`
   y `/proc/self/maps` para 32/64. **x86 / x86_64 son de primera clase.**
4. `N` hace `System.load(filesDir + "/libexec.so")`.
5. `N.al(...)` (nativo) devuelve un ClassLoader con el DEX descifrado.
6. `N.r` / `N.ra` instalan `com.mobile.brasiltv.app.App`.
7. Opcional `S.sp()` -> `DETool.loadDEso`.

## Formato de `ijiami.dat`

```
offset 0  u32le   numero de DEX cifrados (4)
offset 4  u32le   tamano uncompressed probable (41140828)
offset 8  32 chars hex MD5 (44f6438002be91557b704ba909f62f58)
offset 40 stream cifrado (sin magico dex\n)
```

Cabecera: `evidence/ijiami-dat-header.txt`.

`ijiami.ajm` empieza por `indl01`. `IJMDal.Data` y `signed.bin` son
metadatos / integridad.

## Nativo

`libexec.so` x86_64 ~667 KiB, `BIND_NOW`, depende de liblog/libandroid/libc.
Strings: `ptrace`, `/proc/self/maps`, `ijiami.dat`, simbolos ART
`DexFile::OpenMemory`, `/app_dex/`, `ijiami SecLLVM compiler 1.7.4.20`.
La tabla dinamica no exporta JNI (SecLLVM). Ghidra headless los recupera.

## Por que dump dinamico

No hay magico `dex\n` en el payload. La clave usa estado del proceso
(ruta del APK, paquete, firma). Metodo soportado:

- ejecutar el shell en un emulador con ABI presente (x86_64)
- a los 2/4/8/15/30 s leer `/proc/<pid>/mem` desde adb root
  (`unpack/external_memdump.py`)

Frida sobre `N.al` e `InMemoryDexClassLoader` es la variante in-process.
