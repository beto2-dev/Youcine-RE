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

## 6.5 Estado final: ARM en runners de GitHub es imposible; terminar en hardware real

La matriz definitiva de entornos (todas las entradas probadas
empíricamente):

| Entorno | Veredicto |
|---|---|
| Runner Linux x86_64 + AVD x86_64 | KVM funciona, pero la traducción ARM rompe SecLLVM y el gate de contenido bloquea APKs modificadas |
| Runner Linux x86_64 + AVD arm64 | rechazado por el launcher: `FATAL: Avd's CPU Architecture 'arm64' is not supported ... on x86_64 host` (aunque `qemu-system-aarch64` viene en el paquete) |
| Runner macOS (Apple Silicon) + AVD arm64, cualquier configuración de accel | qemu siempre inicializa HVF; los runners no tienen entitlement de Hypervisor.framework (`HVF error: HV_UNSUPPORTED`) - `-accel off` NO lo evita (probado en los runs 34063246076 y 34068661659) |
| Runner macOS + TCG arm64 | no disponible (ver arriba) |

Dos formas de terminar el dump, ambas a un comando de distancia con las
herramientas de este repo:

### Opción A - un teléfono Android físico (la clásica; recomendada)

Cualquier dispositivo Android ARM real (la plataforma objetivo del
packer - todo es nativo y legítimo):

```bash
# en el teléfono: activa Opciones de desarrollador + Depuración USB, conéctalo
adb devices                                      # confirma que es visible
adb root 2>/dev/null || true                     # opcional; el dumper solo
                                                 # necesita root para leer
                                                 # /proc/pid/mem
adb install -r -g ycMob_1.17.6_ycsite.apk        # APK ORIGINAL
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
adb install -r -g youcine-1.17.6-unpacked.apk    # la build sin packer
```

El teléfono debe estar rooteado para las lecturas de `/proc/<pid>/mem`
(o usa `adb shell su -c ...` - el dumper ya tiene fallback a `su`).

### Opción B - runner macOS auto-alojado

Registra un runner auto-alojado en tu propio Mac (Settings -> Actions
-> Runners; labels `[self-hosted, macOS]`). En hardware real
Hypervisor.framework funciona, así que el emulador arm64 corre a máxima
velocidad. Despacha luego **Dynamic unpack (emulator)** con el input
`run_selfhosted` activado: el job `unpack-selfhosted-mac` arranca el AVD
arm64, instala la APK ORIGINAL y dumpea exactamente como arriba;
`rebuild` y **Boot test** continúan automáticamente.

Tras el dump: el job `rebuild` (o los comandos locales de arriba)
producen `youcine-1.17.6-unpacked.apk`, y **Boot test (unpacked APK)**
verifica en un emulador arm64 (Mac auto-alojado) que la UI real
`com.mobile.brasiltv.*` arranca con screenshots y logcat como evidencia.

---

## RESULTADO: desempaquetado (2026-09-07, run 34133100459)

El pipeline definitivo que funcionó de principio a fin, completamente en
los **runners arm64 gratuitos** de GitHub (`ubuntu-24.04-arm`, repo
público = minutos ilimitados):

1. **Contenedor redroid Android 11** (`redroid/redroid:11.0.0-latest`,
   arm64 nativo - SIN ndk_translation, SIN qemu/goldfish). El
   `build.prop` se parchea ANTES del primer arranque (`docker create` ->
   `docker cp` -> `docker start`), solo reemplazando líneas existentes:
   `ro.debuggable=0`, `ro.secure=0` (adbd root), identidad Samsung
   SM-G991B `user`/`release-keys` en las claves `ro.product.system.*`.
   **Nunca añadir claves foráneas** - el cargador de contextos de init
   aborta (run 34121251995).
2. **adbd root PRIMERO**, después el bloque de verificación/parche en
   runtime del área de propiedades (`patch_props.py`) + reinicio del
   framework para los restos (`ro.boot.hardware=redroid`, alias).
3. **Instalar el APK ORIGINAL byte-idéntico + lanzar** - el stub de
   iJiami descifra y la app real corre (SplashAty -> DMCAAty; la puerta
   de entorno que bloqueó cada run del emulador x86_64 nunca se activa
   en redroid nativo).
4. **SIGSTOP + extracción dirigida de los contenedores
   `[anon:dalvik-DEX data]` de ART** (`unpack/dexdata_extract.py` +
   `tools/memread.c`, un helper estático `pread64` compilado en el
   runner): cada dex descifrado abarca VARIAS entradas del mapa - piezas
   grandes `r--p` intercaladas con piezas pequeñas `-wxp` (¡sin bit de
   lectura!); las lecturas de `/proc/<pid>/mem` usan `FOLL_FORCE`, así
   que el span completo se lee como un rango contiguo. El `dd` de
   toybox producía silenciosamente nada en esas direcciones - `pread64`
   es el lector fiable.
5. **Reparación de checksums** (`validate_and_extract_dex.py`): el
   packer descifra in situ, así que las páginas en runtime difieren del
   adler32/SHA-1 original. El orden es crítico: primero SHA-1 (cubre
   `[32:end]`), después adler (cubre `[12:end]`, incluyendo el campo
   SHA-1 nuevo).
6. **Rebuild** (apktool: clase Application real restaurada, assets del
   packer eliminados, los 5 `classes*.dex` recuperados insertados) ->
   zipalign -> apksigner -> publicado en el **Release
   `unpacked-1.17.6`** -> **Boot test** encadenado.

Cinco dex recuperados (11,9 / 11,5 / 10,9 / 6,3 / 0,6 MB); Jadx 1.5.6
los decompila (2.596 clases solo en el primero). Cadena de evidencia
completa en los artefactos `dumps-redroid` de los runs 34133100459+.

Lo que NO funcionó (documentado para no repetir callejones sin salida):
- Emulador x86_64 + cualquier parche de props: la app traducida nunca
  lanzó limpiamente (`am start` en deadlock) y la caza de señales qemu
  fue una pista falsa - el run 34084986538 demostró que las señales
  qemu NO son la puerta.
- Sandbox de BlackDex en redroid: el desellado de hidden-API se arregló
  (`settings put global hidden_api_policy 1`), pero la escalera de
  muerte NATIVA de iJiami aún mata el sandbox con SIGKILL a los ~36 ms
  vía syscalls crudos (ningún hook a nivel Java puede interceptarlo).
- Escaneo por magia de `/proc/<pid>/mem`: el packer borra su propio
  buffer tras cargar las clases; estas viven SOLO como contenedores
  `[anon:dalvik-DEX data]` de ART.

## La última capa de defensa (veredicto del boot test, corregido 2026-09-08)

### Lo que demostraron los fixes del rebuild v3-v5

Tres defectos reales impedían que el APK reconstruido sin packer
alcanzara el código propio de la app. Los tres se arreglaron
empíricamente (runs 34164306975, 34166250339, 34166188171):

1. **El SDK DE jamás se cargaba.** `DETool.loadDEso` tiene CERO
   llamadores en el DEX descifrado (el stub `S.sp()` refleja una
   sobrecarga `loadDEso(String,String,String)` que no existe en el
   SDK DE 4.3.4 - la entrada real es `loadDEso(Context)`; la carga la
   hacía el loader nativo del packer antes de entregar el control a
   la Application real). Fix:
   `unpack/stubs/src/com/youcine/re/BootProvider.java` - un
   ContentProvider (instalado por `installContentProviders()` ANTES
   de `Application.onCreate`, el mismo patrón de init temprano que
   FacebookInitProvider) que llama `loadDEso` por reflexión y, en
   runtimes traducidos, hace su propia copia/carga/`dowork` con la
   ABI que el linker realmente acepta.
2. **La trampa de ABI.** En el emulador x86_64 la app corre bajo
   ndk_translation: la sonda de DETool (`/proc/self/exe`) elige la
   arquitectura ANFITRIÓN (x86_64) pero el namespace de dlopen
   traducido solo acepta la `primaryCpuAbi` instalada (arm64-v8a):
   `dlopen failed: is for EM_X86_64 (62) instead of EM_AARCH64
   (183)`. El BootProvider compara la sonda de DETool con
   `primaryCpuAbi` (reflexión) / `nativeLibraryDir` (pública) y
   rescata la carga. Verificado en el run 34166250339:
   `System.load(...) OK` + `DETool.dowork -> true`.
3. **El kill-switch de firma.** `App.onCreate` también llama a
   `ConfusionUtils.check()`, que lanza el hilo vigilante que
   allowlistea solo el MD5 del certificado original y dispara `HOME +
   System.exit(0)` en builds re-firmadas (observado en el logcat del
   run 34142729238, 16:21:55.059). Fix: `unpack/patch_confusion_cc.py`
   reescribe TODA la región de insns de `cc()` como `const/4 v0,1 ;
   return v0 ; nop-fill` (mismo tamaño, tries=0 - parchear solo el
   prefijo deja código muerto desalineado que el paso lineal del
   verificador de ART rechaza, run 34164727188: "register index out
   of range (12 >= 3)").

### Dónde se detiene la app realmente, y por qué (mecanismo corregido)

Con los tres fixes, el build v5 llega más lejos que nunca: todos los
providers se inicializan, el `App.onCreate` real se ejecuta,
ConfusionUtils queda neutralizado, el SDK DE se inicializa (`DE:
DECRYPT cost time 14 ms`, `DE: ms_sm4_001 datapath=...
sp_version=1.4`) - y el hilo main sigue muriendo en el primer método
protegido por VMP de iJiami: `App.onCreate:139 -> Aria.init ->
SqlHelper.getDb -> UnsatisfiedLinkError`.

El entendimiento corregido de la última capa de defensa (en sustitución
de la hipótesis anterior de "registro de nativos gated por firma en el
SDK DE", que el run v5 desmintió - la lib DE carga, `dowork` devuelve
true y `SqlHelper.getDb` sigue sin registrarse):

1. **`libijmDataEncryption.so` NO es el registrador de métodos.** El
   SDK DE es el **motor SM4 de SharedPreferences cifradas** del SDK
   EFS integrado por el vendor (`com.efs.sdk.*`): su `dowork(key,
   1024, hash, ...)` inicializa el datapath SM4. Funciona sin
   problemas en un build re-firmado (`dowork -> true`).
2. **Los ~805 métodos ACC_NATIVE** (17 de Aria, 424 de
   `com.mobile.brasiltv.*`, 53 de Facebook, EFS, ...) reciben sus
   implementaciones JNI en runtime por el **motor de libexec con gate
   de contenido** - el mismo cuya comprobación ed25519/`signed.bin`
   exige el APK original byte-exacto (ver 03-protecciones-y-bypass.md,
   L2). Quitar el packer elimina al único registrador.
3. **Los ~45.238 stubs de extracción `return-void+nop`** (13.478
   constructores + 31.760 métodos void - cada `Companion.<init>`,
   listener anónimo, `configView` de cada activity...) son cuerpos que
   iJiami extrajo al empaquetar y re-materializa en las páginas DEX en
   memoria solo conforme se cargan las clases - otra vez desde los
   blobs cifrados de libexec. El dump capturó las clases del
   boot-path ya restauradas (por eso `App.onCreate` ejecuta código
   real) y todo lo demás aún como stub: p. ej.
   `com.facebook.appevents.AppEvent$SerializationProxyV2$Companion.<init>`
   y `tv.danmaku.ijk.media.player.ExoMediaPlayer$1.<init>` fallan el
   verificador con "Constructor returning without calling superclass
   constructor" (ya visible como rechazos de dex2oat en los logs v3).

**Consecuencia**: un build sin packer y re-firmado arranca el proceso
real de la app a través de todas las capas no protegidas y se detiene
en el primer método VMP - por diseño. El boot completo exige
re-materializar los ~805 cuerpos nativos y los ~45k stubs, que viven
únicamente dentro del motor del packer con gate de contenido. Los
entregables de investigación se mantienen: los 5 dex descifrados
(11,9/11,5/10,9/6,3/0,6 MB, decompilables con jadx, 2.596+ clases) en
el release `unpacked-1.17.6` (los dex prístinos del dump ahora
fijados en el release inmutable `dumps-1.17.6`) y un pipeline
reproducible y determinista nativo de GitHub Actions
(`rebuild-fix.yml`, bucle rápido: toma fuentes solo de
`packed-1.17.6` + `dumps-1.17.6`, verifica por aserción los parches
dentro del APK publicado y encadena el boot test).

### Fase 2 (el único camino restante a un build que bootea completo)

1. **Frida en la ejecución redroid arm64 del APK ORIGINAL**: hookear
   `RegisterNatives` para capturar la tabla completa método->fnPtr y
   dumpear los cuerpos nativos; forzar la carga de todas las clases
   (barrido de warm-up) para que libexec re-materialice los ~45k
   stubs en las páginas DEX, y re-dumpear. La infraestructura
   existente (`frida-scripts/` + `unpack/redroid_flow.sh`) es el punto
   de partida.
2. Reconstruir con los dex re-dumpeados; los 805 nativos restantes
   necesitarían un puente (de-natificar con cuerpos Java para las
   familias open source - Aria/Facebook - y un shim registrador para
   los 424 propios del vendor).

El workflow **Boot test** codifica el veredicto honesto: la muerte del
hilo main dentro de código `com.mobile.brasiltv.*`/`com.arialyy.*` se
reporta como `RESEARCH OUTCOME - UNPACK VERIFIED`, y un `BOOT OK` real
ahora exige hilo main vivo + activity resumida + ventana youcinemobile
con foco (el run 34166250339 produjo inicialmente un "BOOT OK"
FALSO-POSITIVO: el crash handler de la propia app murió en un
VerifyError de un stub y dejó un proceso zombi con ventana negra -
ver los comentarios del workflow).

---

## Herramientas de la Fase 2 - IMPLEMENTADAS (2026-09-08)

Todo lo que la Fase 2 necesita ya está en el repo. Despacha el
workflow **Phase 2 - Frida RegisterNatives + warmup + re-dump
(redroid)** (`.github/workflows/frida-redump.yml`) o ejecuta el flujo
localmente en cualquier Linux arm64 con Docker:

```bash
GH_TOKEN=<pat> bash unpack/redroid_frida_flow.sh
```

### Qué ejecuta

`unpack/redroid_frida_flow.sh` levanta el MISMO contenedor redroid
probado que `redroid_flow.sh` (build.prop parcheado antes del primer
boot, adbd root, apk ORIGINAL byte-idéntica instalada) pero en vez de
dumpear le entrega el proceso a Frida:

1. **frida-server 16.6.6 (arm64)** se sube con un nombre de proceso
   ALEATORIZADO (`mon.<hex>`) escuchando en 127.0.0.1:47890 - iJiami
   fingerprinta tanto el nombre binario por defecto como el puerto
   27042 - y se expone al host vía `adb forward tcp:4789`.
2. `unpack/frida_phase2_driver.py` hace spawn de la app GATEADA
   (nunca `am start` - el cargador nativo debe correr instrumentado
   desde la primera instrucción), carga el script guardián
   (`02_bypass_ptrace.js`) más los tres scripts de Fase 2, y luego:
   * `frida-scripts/06_register_natives_table.js` hookea
     `art::JNI<false/true>::RegisterNatives` en libart.so (match por
     símbolo; fallback al slot 215 de la tabla JNIEnv) y registra
     cada registro: clase, nombre del método, firma JNI, fnPtr
     resuelto a módulo+offset. El dedup conserva el ÚLTIMO fnPtr por
     (clase, nombre, firma) - libexec re-registra cuando las clases
     se re-materializan. Salida: `work/phase2/jni_table.json` (+ log
     crudo de eventos `jni_table_events.jsonl`).
   * Detección de ventana silenciosa: cuando no llegan registros
     nuevos durante `REG_QUIET` (12 s), la ola de registros del boot
     terminó.
   * `frida-scripts/08_redump_dex.js` dumpea las imágenes en memoria
     de libexec.so y libijmDataEncryption.so (tag pre-warm-up) - la
     imagen auto-modificada por SecLLVM, no el archivo en disco - más
     un censo en vivo de los spans `[anon:dalvik-DEX data]` (bytes
     legibles, huecos, magic dex + file_size por span).
   * El driver parsea la lista de clases directamente de los 5 DEX
     dumpeados del release `dumps-1.17.6` (parser DEX mínimo:
     string_ids/type_ids/class_defs) y alimenta a
     `frida-scripts/07_class_warmup.js` en lotes de 200:
     `Class.forName(name, true, loader)` sobre una cascada de
     classloaders. Cada clase va aislada en try/catch - un solo stub
     rechazado por el verifier nunca aborta el barrido. Este es el
     warm-up que hace que libexec re-materialice los ~45.238 cuerpos
     de stub extraídos y dispare los registros restantes.
   * Post-warm-up: una segunda ventana silenciosa, re-toma de los
     dumps de módulos (tag `post`), y luego el re-dump
     FUERA-DE-PROCESO autoritativo vía el probado
     `unpack/dexdata_extract.py` (SIGSTOP + pread64 FOLL_FORCE sobre
     las piezas -wxp) + reparación de checksums con
     `unpack/validate_and_extract_dex.py`.
3. Todo cae en `work/phase2/` (jni_table.json, warmup_stats.json,
   redump/ + repaired/ dexes, inproc/ imágenes de módulos,
   summary.json) y se publica al release inmutable `phase2-1.17.6` +
   el artefacto `dumps-phase2`.

El veredicto del workflow espeja la honestidad del boot-test: 0
registros capturados falla el job (`::error::`), una tabla con 0 dexes
re-dumpeados advierte, y `rn_methods >= 1 && redump_dex_count >= 1`
es `PHASE 2 OK`.

### Contra qué se compara el re-dump

`summary.json` reporta el delta a nivel de clases: cuántas clases el
warm-up cargó ok / notfound / fail (verifier), y cuántos contenedores
DEX recuperó el re-dump frente a los cinco de la fase 1. Una Fase 2
exitosa muestra (a) cuerpos de clase más completos (los 45k stubs ya
con código real), y (b) una jni_table cubriendo los ~805 métodos
ACC_NATIVE con sus offsets en libexec - el insumo para el futuro
puente de de-natificación (cuerpos Java para las familias open
source, shim registrador para los 424 propios del vendor).

### ijiami-static - el ataque offline (totalmente estático) a ijiami.dat

`ijiami-static/` (nueva carpeta de primer nivel) persigue el mismo
payload vía descifrado puramente estático, ahora que el gate del dump
en runtime está satisfecho:

* `capture_aes_key.js` - hook Frida sobre cada punto de entrada de
  material de clave AES (openssl `AES_set_*_key`, `EVP_*Init*`,
  mbedtls, rijndael, tiny-AES) en cada módulo a medida que carga, más
  un escaneo de memoria del S-box AES / S-box inverso dentro de
  libexec.so (el AES custom de SecLLVM deja fingerprints de tablas;
  los xrefs de Ghidra a esas direcciones exponen la función de
  key-setup).
* `hunt_key_schedule.py` - escaneo offline de archivos de regiones de
  dumps de memoria buscando key schedules de AES: match por expansión
  hacia adelante, o recurrencia de solo-consistencia con recuperación
  por key schedule INVERSO de la clave original. `--selftest` pasa
  14/14 (vectores FIPS-197).
* `decrypt_ijiami_dat.py` - la matriz de candidatos (claves derivadas
  del header + capturadas + cazadas x ECB/CBC x variantes de IV)
  contra el payload de 9.543.463 bytes, verificado por magic
  DEX/zip/gzip/zlib, densidad de descriptores `Lcom/` y
  re-verificación NRV2B (reusa `static-analysis/nrv2b_ijiami.py`).
  `--selftest` pasa 15/15.
* `analyze_dat.py` - re-deriva el digest de evidencia del header +
  estadísticas de bloques duplicados ECB / entropía (medido en el
  archivo real: 0,222% de bloques de 16 bytes duplicados, entropía
  7,76-7,99, imprimibles 36,2%, un trailer de 15 bytes no-PKCS#7).

Si la clave AES se captura durante un run de Fase 2 (o se caza en los
artefactos de dumps), `decrypt_ijiami_dat.py` produce los cuatro
payloads totalmente offline - una validación cruzada e independiente
del dump en runtime y el único camino que no necesita para nada el
motor del packer.

## Fase 3 - el puente de-natify (r4, 2026-09-09)

### Lo que probo el boot-test 34282297861

Con la r3 puesta (cuerpos REAL del SqlHelper, `NativeJni.<clinit>`
guardado), el build booteable seguia muriendo dos veces:

1. **Hilo principal**: `java.lang.VerifyError: Verifier rejected class
   da.w: void da.w.<init>(java.lang.String) failed to verify:
   Constructor returning without calling superclass constructor` en
   `SplashAty.getMPresenter -> kotlin.jvm.internal.m.x -> m.w`. `da.w`
   es una subclase de `RuntimeException` cuyo cuerpo de ctor es el stub
   `return-void + 3x nop` del packer - y **no tiene flag native**, asi
   que ni el camino STUB del de-natify ni la super-llamada r3 (solo
   ctors nativos) le aplicaron jamas.
2. **Hilo handlerRanger**: `NullPointerException: RangerResult.getRes()`
   sobre null - `NativeJni$v.run` llamo al stub de-natificado
   `NativeJni.d(...)` (devuelve null), Gson parseo null, y el NPE mato
   el proceso 840 ms despues del crash principal.

### La escala del problema de stubs sin materializar

Un censo raw-DEX de los 5 ganadores booteables (a nivel de opcodes: un
ctor real siempre contiene un invoke-direct/-super 0x6f/0x70/0x75/0x76):
**6.529 constructores** en 6.059 clases conservan cuerpos stub - el
warm-up cubrio 21.600 de 32.459 clases de la app; las ~11k clases
restantes (los chunks "abort was called" / agente roto del sweep) nunca
dispararon la re-materializacion de libexec. Cada uno de esos ctors es
un VerifyError de carga de clase esperando a ocurrir; `da.w` era solo
el primero en el camino de arranque.

### El fix r4 (denatify_redump.py + framework_ctors.py)

* `DexClassMap` - un parser cross-DEX (tablas de
  string/type/proto/method/class, indices diferenciales por lista)
  construye: la superclase directa de cada clase, cada proto+flags de
  `<init>`, y la lista de ctors malos.
* `unpack/framework_ctors.py` - extrae los protos `<init>` accesibles
  (public/protected, no abstract) de cada clase del framework desde
  `android.jar`. El jar del SDK trae `.class` de Java (javac necesita
  bytecode), asi que el parser recorre el constant pool; los
  descriptores de metodo comparten la gramatica de los protos DEX, sin
  traduccion. En capa inferior: una tabla embebida de
  java.lang/atomics + las clases legacy org.apache.http del
  boot-classpath que el jar API-30 elimino.
* `choose_super_call` - resuelve el objetivo de invocacion por ctor
  malo:
  * super in-app: FORWARD con proto exacto (registros de parametros
    reutilizados: `invoke-direct {p0, p1}`; `invoke-direct/range` a
    partir de 5 words o v15), si no NOARG `()V`, si no DEFAULTS
    (null/0/0L sintetizados para el proto accesible mas corto del
    super). Accesibilidad: public, protected, o package-private cuando
    la subclase comparte paquete (las jerarquias ofuscadas de
    rx/retrofit dejan los flags de acceso en solo-ACC_CONSTRUCTOR).
  * super del framework: los mismos tres modos contra la tabla de
    android.jar.
* La super-llamada se **ANTEPONE** al cuerpo stub: el `return-void +
  nops` original queda como codigo muerto inalcanzable que el
  verificador de ART ignora (solo verifica instrucciones alcanzables),
  de modo que las anotaciones, la info `.line` y los bloques `.param`
  sobreviven intactos.
* Trampas de codificacion cubiertas: nibbles de 4 bits del 35c frente
  a `invoke-direct/range`; `move-object/from16` (el move-object simple
  es 12x - ambos registros de 4 bits); `const/16` mas alla de v15;
  frames `.registers` convertidos a locales efectivos; pares de
  registros wide (J/D).
* Los ctors stub con flag native reciben la misma super-llamada
  resuelta dentro de su cuerpo default sintetizado (la r3 inyectaba
  `Object.<init>`, que solo verifica cuando Object ES la superclase
  directa).
* **BLINDAJE DE RUN**: `NativeJni$v.run()` se renombra a
  `run$shielded` y un wrapper sintetizado `run()V` delega dentro de
  `try/catch Throwable` - una excepcion no capturada en CUALQUIER hilo
  mata todo el proceso Android, asi que el hilo del SDK ahora degrada
  en silencio.

### Verificacion (dura, por DEX de salida)

conteo de clases igual, conteo de metodos igual (+1 por wrapper de run
blindado), natives restantes == exactamente el set KEEP, ctors sin
super restantes == la lista "left" (0 en los ganadores 1.17.6 con la
tabla del framework). Totales: 8 natives REAL + 778 stubbed, 19
conservados, 1 clinit guardado, 1 hilo blindado, 6.529 fixes de ctor
(1.522 forward / 3.969 noarg / 1.038 defaults / 0 left).
