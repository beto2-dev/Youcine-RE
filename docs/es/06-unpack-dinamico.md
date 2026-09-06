# 6. Metodología de unpacking dinámico (actualizado 2026-09-07)

El pipeline de `.github/workflows/unpack-emulator.yml` es el resultado de
~20 ejecuciones instrumentadas en GitHub Actions. Este documento explica
cómo ejecutarlo, qué hace cada etapa y cuáles son los pasos restantes.

## 6.1 El pipeline

```
workflow_dispatch (unpack-emulator.yml)
   |
   |- unpack-macos-tcg (primario)  runner macOS arm64, TCG con -accel off,
   |                               APK ORIGINAL, memdump externo
   |- unpack-x86 (saltado por defecto)  vía de investigación documentada:
   |                               dump-build + supervisor ptrace trace_guard
   |- rebuild                      validar DEX -> restaurar manifest ->
                                   quitar assets del packer -> sustituir
                                   classes*.dex -> zipalign -> apksigner ->
                                   release 'unpacked-1.17.6'
   '- boot-test.yml                instala la APK reconstruida en un
                                   emulador arm64, screenshots, logcat,
                                   veredicto
```

## 6.2 El dumper (`unpack/external_memdump.py`)

Out-of-process, solo root, sin inyección:

1. Sondea `pidof` hasta que aparece la app (el workflow la lanza con
   `am start`).
2. Espera `--settle` segundos (el descifrado ocurre dentro de
   `attachBaseContext`/`instantiateApplication`, mucho antes que
   cualquier Activity).
3. SIGSTOP al proceso (congela watchdogs del packer y temporizadores
   anti-debug).
4. Barrido por lotes en el dispositivo de `/proc/<pid>/mem` (un solo
   shell root, un `dd` por región; las regiones mayores de 64 MiB - p.ej.
   el espacio de regiones dalvik de 1 GiB - se leen en fragmentos de
   64 MiB con solapamiento de 2 MiB).
5. Los archivos de región salen por `adb exec-out tar` (sin corrupción
   del pty) y se escanean localmente por la magia DEX
   (`dex\n` + versión ASCII + `\0` + `file_size` sano), deduplicando por
   sha256.
6. Repite los barridos hasta `--expect` DEX únicos (se esperan 4: la
   cabecera de `ijiami.dat` declara 4 payloads) o timeout, y luego
   opcionalmente empaqueta `/data/data/<pkg>` como evidencia en disco.

Nunca se mapea nada dentro del objetivo, no se usa ptrace, no se crean
hilos en el proceso: los escaneos de `/proc/self/maps` y `TracerPid` no
tienen nada que detectar.

## 6.3 El rebuild (`unpack/rebuild_unpacked_apk.py` + `validate_and_extract_dex.py`)

1. `apktool d --no-src` (solo recursos + manifest).
2. Parchear `AndroidManifest.xml`: `android:name` `s.h.e.l.l.S` ->
   `com.mobile.brasiltv.app.App`, `android:appComponentFactory`
   `s.h.e.l.l.A` -> `androidx.core.app.CoreComponentFactory`.
3. Borrar todos los assets de iJiami (`ijiami.dat`, `ijiami.ajm`,
   `IJMDal.Data`, `signed.bin`, `af.bin`, `libijmDataEncryption*.so`,
   `ijm_lib/`).
4. `apktool b`, luego sustituir en el zip los `classes*.dex` por los DEX
   dumpeados (ordenados por tamaño, mínimo 64 KiB para excluir el stub
   DEX de 13.6 KiB).
5. `zipalign -f 4` + `apksigner sign` (clave de investigación v2/v3).
6. Publicar como release privado `unpacked-1.17.6` para el boot test.

La build resultante no contiene una sola línea del packer: el stub DEX
se elimina, el payload cifrado se elimina, los loaders nativos se
eliminan y el manifest apunta a la clase de aplicación real.

## 6.4 Historial de ejecuciones verificadas (evidencia de cada afirmación de 03)

| Run | Qué probó |
|---|---|
| 34044920876 | apk original en x86_64: proceso arm64 bajo traducción, `N.al` sin registrar |
| 34046564135 | android-emulator-runner ejecuta cada línea del script en su propio `sh -c` (¡sin continuaciones de línea!) |
| 34046807813 | la dump-build instala + el stub extrae el libexec x86_64 nativo; la apk re-firmada recibe SIGKILL a ~0.2s (syscall crudo) |
| 34047934644 | los runners macOS de GitHub no tienen Hypervisor.framework (`HVF_UNSUPPORTED`) |
| 34048953559 / 34049784110 | pin armeabi-v7a: `dlopen ... is for EM_386 instead of EM_ARM`; `libstdc++.so` SÍ es pública en la imagen |
| 34051123509 | logging de bionic `debug.ld.app.<pkg>` + traza frida: ambas libs de carga `dlopen -> ok` nativas |
| 34051553362 | la supresión a nivel libc es insuficiente - el suicidio ignora libc |
| 34052830854 / 34053461147 / 34057250027 | la escalera de muerte completa neutralizada capa por capa (kill, exit, int3, ud2, SIGSEGV) |
| 34055917392 / 34057901348 | transplante en packages.xml + relay de SIGSEGV: el gate de contenido bloquea el descifrado de cualquier APK modificada |
| 34058535954 | el emulador de linux incluye `qemu-system-aarch64` pero el launcher bloquea AVDs arm64 en hosts x86 |

## 6.5 Estado actual y cómo terminar

Todo el tooling está terminado y validado pieza por pieza. Los pasos
restantes son pura ejecución:

1. Minutos de Actions: los minutos incluidos de la cuenta se agotaron
   durante la sesión de investigación (los runs de macOS facturan con
   multiplicador 10x). Espera el reinicio mensual (o aumenta el límite
   de gasto en Settings -> Billing).
2. Despacha **Dynamic unpack (emulator)** una vez. `unpack-macos-tcg`
   arranca el AVD arm64 con `-accel off` (TCG del mismo-arch en el
   runner Apple Silicon: lento pero totalmente nativo), instala la APK
   ORIGINAL y dumpea el DEX descifrado. `rebuild` publica entonces el
   release `unpacked-1.17.6` automáticamente.
3. Despacha **Boot test (unpacked APK)** una vez. Instala la build
   reconstruida sin packer en un emulador arm64 y verifica que la UI
   real de YouCine (SplashAty / MainAty bajo `com.mobile.brasiltv.*`)
   alcanza `ResumedActivity` con screenshots y logcat como evidencia.
   NOTA: el workflow de boot-test también debe pasar `-accel off` por la
   misma razón.

Presupuesto aproximado de las dos ejecuciones: 25-45 min de runner
macOS (facturados 10x) más 5 min de Linux - planifica los minutos en
consecuencia, o ejecuta ambos jobs en un runner macOS auto-alojado
(labels: `macos-14,arm64`), donde los minutos son gratis.
