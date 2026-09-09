# Youcine-RE

Laboratorio de ingenieria inversa de **YouCine** (`com.world.youcinemobile`)
version **1.17.6**.

El sample analizado usa el packer comercial **iJiami (AiJiami)**: un DEX stub
de 14 KiB (`s.h.e.l.l.S` / `s.h.e.l.l.A`), multi-DEX cifrado en
`assets/ijiami.dat`, cargador nativo `libexec.so` compilado con
**SecLLVM 1.7.4.20** y un sidecar de cifrado de datos
(`com.ijm.dataencryption.DETool`).

- **Autores del RE:** beto-2dev, ChapzoMods
- **Licencia:** GNU GPL 3.0 (`LICENSE`)
- **Idiomas:** [English](README.md) · [Espanol](README.es.md) · [中文](README.zh.md) · [Français](README.fr.md)
- **Alcance:** metodologia para quitar el packer, mapa de protecciones,
  inventario de SDKs, separacion cliente/servidor, pipelines en emulador

Este repositorio contiene **herramientas, scripts y documentacion**. **No**
incluye APKs, DEX volcados ni el codigo original de la aplicacion. Los samples
viven en **Releases privadas**.

## Sample analizado

| Campo | Valor |
|---|---|
| Archivo | `ycMob_1.17.6_ycsite.apk` |
| Paquete | `com.world.youcinemobile` |
| Version | 1.17.6 (11706) |
| min / target SDK | 19 / 33 |
| SHA-256 | `28d028d75c89e6ab90c8b7e57a32c42355ac5ae2e388ea1e541bd003cae10d83` |
| DEX stub | `classes.dex` 13608 bytes |
| DEX cifrado | `assets/ijiami.dat` 9543463 bytes, cabecera **4** payloads |
| Application real | `com.mobile.brasiltv.app.App` |
| Application shell | `s.h.e.l.l.S` |
| Component factory | `s.h.e.l.l.A` encapsula `androidx.core.app.CoreComponentFactory` |
| Firma | auto-firmado `C=86, ST=GD, L=SZ, O=XXL, OU=OTT, CN=xxl` |
| Familia | Mismo prefijo `com.mobile.brasiltv.*` que Magis / Xuper / Brasil TV, rebrand YouCine, packer iJiami en lugar de SecNeo |

## Herramientas

| Herramienta | Version | Rol |
|---|---|---|
| Jadx | 1.5.6 | stub DEX a Java |
| Apktool | 2.12.1 | manifest, recursos, rebuild |
| Ghidra | 12.1.3 (headless, JDK 21) | `libexec.so` / JNI |
| androguard | 4.x | parseo del APK |
| Frida | 16.6.x | dump in-process opcional |
| Emulador Android | API 30 x86_64 (dump), API 33 arm64 (boot) | GitHub Actions |
| GitHub Actions | ubuntu-latest, macos-14 | unpack + boot + Ghidra |

`tools/setup_env.sh` instala el entorno en `TOOLS_DIR`. Todas las rutas se
configuran por variables de entorno; no hay rutas de maquina fijas.

## Cliente vs servidor

**Cliente (se puede desempaquetar / parchear)**

- Shell iJiami, DEX cifrado, anti-debug de `libexec` (`ptrace`, `/proc/self/maps`)
- Extractor de ABI (`assets/ijm_lib/<abi>/libexec.so`, incluye **x86_64**)
- Sidecar de cifrado, integridad `signed.bin` / ed25519
- UI, ijkplayer, Aria, Cast, HPPlay/LeLink, Firebase, Umeng, AdMob, Facebook SDK
- Hosts rotativos en `strings.xml` (portal, EPG, upgrade, avisos, ads, H5)

**Servidor (no desaparece al quitar el packer)**

- Portal de catalogo / VOD / live
- EPG, force-upgrade / kill-switch de version, avisos, config de ads
- Cuenta, VIP, bind de dispositivo, canjes, pagos
- Emision de URLs de stream (no estan en el DEX stub)

Quitar iJiami produce un build de investigacion que **arranca**
`com.mobile.brasiltv.app.App`. Los entitlements y las URLs de CDN siguen
saliendo de los hosts del portal.

## Pipeline de unpack

1. Scan estatico: `SAMPLE_APK=... python3 static-analysis/apk_quickscan.py`
2. Action **Dynamic unpack (emulator)** -> job `unpack-macos-tcg`: AVD
   arm64-v8a con `-accel off` (TCG del mismo-arch en el runner Apple
   Silicon - ejecucion ARM NATIVA total), APK ORIGINAL empacada,
   `SplashAty` y dump fuera de proceso de `/proc/<pid>/mem` (sin
   inyeccion, sin ptrace, sin agente in-process -> indetectable para el
   anti-debug del packer).
3. `unpack/rebuild_unpacked_apk.py` restaura la Application real, borra
   assets del packer, sustituye `classes*.dex`, alinea, firma y publica
   el release privado `unpacked-1.17.6`.
4. Action **Boot test**: APK desempaquetado en emulador arm64 verificando
   que la UI real `com.mobile.brasiltv.*` arranca (screenshots + logcat +
   dumpsys).
5. Action **Fase 2 (Frida RegisterNatives + warm-up + re-dump,
   redroid)**: corre la APK ORIGINAL empacada bajo Frida en el mismo
   contenedor redroid - captura la tabla JNI completa
   (`frida-scripts/06_register_natives_table.js`), fuerza la carga de
   todas las clases de los DEX dumpeados (`07_class_warmup.js`) para
   que libexec re-materialice los ~45k stubs extraidos, re-dumpea los
   contenedores DEX y la imagen en memoria de libexec
   (`08_redump_dex.js` + `unpack/dexdata_extract.py`) y publica todo al
   release `phase2-1.17.6`. La carpeta `ijiami-static/` ataca el mismo
   payload totalmente offline: captura/caza de clave AES + descifrado
   estatico de `assets/ijiami.dat`.

## Estado (2026-09-08)

Cada herramienta del pipeline esta terminada y validada pieza por pieza a
lo largo de ~30 ejecuciones instrumentadas en CI; ver
[docs/es/03-protecciones-y-bypass.md](docs/es/03-protecciones-y-bypass.md)
para el mapa completo capa por capa (trampa de ABI/traduccion, SecLLVM,
gate de integridad de contenido, la escalera de muerte
raw-syscall/int3/ud2/SIGSEGV y su neutralizacion en
`unpack/trace_guard.c`).

El rebuild sin packer ahora arranca la app REAL hasta donde fisicamente
es posible (rebuild v5, bucle rapido `rebuild-fix.yml`): un
`com.youcine.re.BootProvider` carga el SDK DE de iJiami (motor SM4 de
prefs) antes de `Application.onCreate` - incluido el rescate de ABI bajo
ndk_translation - el kill-switch de firma embebido (`ConfusionUtils.cc`)
queda neutralizado por cirugia DEX minima, y el proceso recorre todas las
capas no protegidas hasta el primer metodo VMP de iJiami
(`SqlHelper.getDb`) - ese era el estado antes de la fase 3. El puente
de-natify de fase 3 (r4-r8: super-llamadas de ctor resueltas, cuerpos
vendor-synth, natives auto-registrados conservados, super-llamadas de
lifecycle) cerro despues esa brecha: el veredicto estricto BOOT OK ya
pasa en el build booteable (UI real resumida Y enfocada, cero FATAL). Ver el
veredicto corregido en
[docs/es/06-unpack-dinamico.md](docs/es/06-unpack-dinamico.md).

La conclusion empirica de la investigacion en CI: **los invitados ARM son
imposibles en los runners alojados de GitHub** (el launcher de Linux
rechaza AVDs arm64 en hosts x86; los runners de macOS fuerzan HVF y
carecen del entitlement - incluso con `-accel off`). El dump se termina
por tanto en hardware real, a un comando de distancia:

* **Un telefono Android rooteado** (recomendado, la via clasica):

  ```bash
  adb install -r -g ycMob_1.17.6_ycsite.apk
  adb shell am start -n com.world.youcinemobile/com.mobile.brasiltv.activity.SplashAty
  python3 unpack/external_memdump.py --app com.world.youcinemobile \
      --out-dir dumped/youcine --expect 4 --timeout 600 --settle 3
  python3 unpack/validate_and_extract_dex.py --dump-dir dumped/youcine \
      --out-dir dexs --min-size 65536
  python3 unpack/rebuild_unpacked_apk.py --apk ycMob_1.17.6_ycsite.apk \
      --dump-dir dexs --out youcine-1.17.6-unpacked.apk \
      --keystore re.keystore --storepass android
  ```

* **Tu propio Mac como runner auto-alojado** (labels
  `[self-hosted, macOS]`): despacha **Dynamic unpack (emulator)** con el
  input `run_selfhosted` activado; `rebuild` y **Boot test** corren
  entonces automaticamente de principio a fin.

Detalles completos: [docs/es/06-unpack-dinamico.md](docs/es/06-unpack-dinamico.md).

Los scripts Frida en `frida-scripts/` son la via in-process. `libexec` usa
`ptrace`; si el agente muere, el memdump sigue siendo valido.

## Fase 2 (implementada 2026-09-08)

La capa de captura Frida para la ultima linea de defensa esta lista:

* `unpack/frida_phase2_driver.py` + `unpack/redroid_frida_flow.sh` +
  `.github/workflows/frida-redump.yml` - corrida Frida spawn-gateada de
  la APK ORIGINAL en redroid arm64 nativo (frida-server renombrado en
  puerto no estandar), captura de la tabla RegisterNatives, barrido de
  warm-up de clases desde los DEX de `dumps-1.17.6`, re-dump
  post-warm-up con reparacion de checksums e imagenes en memoria del
  libexec.so / libijmDataEncryption.so auto-modificado por SecLLVM.
  Salida: release `phase2-1.17.6` (jni_table.json + dexes re-dumpeados
  + imagenes de modulos).
* `ijiami-static/` - el ataque AES offline contra `ijiami.dat`:
  captura de clave en runtime, caza de key schedules en dumps de
  memoria (con recuperacion por key schedule inverso) y un
  descifrador de matriz de candidatos verificado contra salida
  DEX/NRV2B. Self-tests en verde (14/14, 15/15).

Ejecutalo: despacha **Phase 2 - Frida RegisterNatives + warmup +
re-dump (redroid)**, o localmente `GH_TOKEN=<pat> bash
unpack/redroid_frida_flow.sh`. Metodologia completa en
[docs/es/06-unpack-dinamico.md](docs/es/06-unpack-dinamico.md).

### Resultado de la Fase 2 (run 34193490749)

El re-dump FUNCIONA: el warm-up cargo 41.852 clases, los snapshots
SIGSTOP intercalados capturaron los 5 layouts DEX **con los cuerpos de
los stubs de extraccion ya materializados en su sitio** (hasta 941 KB
de codigo real reescrito por DEX) y `validate_and_extract_dex.py`
reparo todos los checksums - 16 archivos de snapshot en el release
`phase2-1.17.6`. El barrido observe-only de RegisterNatives solo vive
dentro del proceso objetivo (la escalera de muerte del packer lo mato
6 s despues de iniciar los dumps de modulos post-warmup), asi que el
driver ahora persiste `jni_table.json` en el primer instante en que la
tabla existe (mid-warmup), no solo al final del pipeline.

**APK booteable de investigacion**: `unpack/dedup_redump.py` elige el
snapshot mas materializado de cada layout DEX (el que mas difiere del
baseline pristino de `dumps-1.17.6`) y el workflow **Booteable
research APK** reconstruye la APK sin packer alrededor de esos 5 DEX -
los mismos cuerpos que la propia app ejecuta, es decir, YouCine +
codigo estaticamente descifrado - publicando el release
`booteable-1.17.6` y encadenando el boot test: RESEARCH OUTCOME
verificado en CI (instala, los providers se instalan, App.onCreate
ejecuta codigo real materializado hasta la linea 139, el SDK DE
carga; muere en el primer metodo ACC_NATIVE natificado por el packer
- el arranque completo necesita el puente de-natify de fase 3).
SOLO PARA INVESTIGACION.

## Fase 3 - el puente de-natify (r4, 2026-09-09)

El boot-test 34282297861 acoto los dos procesos-asesinos restantes
despues de los fixes r3, y la r4 elimina ambos en la capa smali:

1. **Los 6.529 CONSTRUCTORES stub de extraccion sin materializar.**
   El warm-up de fase 2 cargo 21.600 de 32.459 clases de la app; el
   resto conservo los cuerpos `return-void + nop` del packer en
   declaraciones `<init>` *no nativas*, asi que la super-llamada r3
   (que solo toco ctors con flag native) nunca les aplico - y el
   verificador de ART rechaza cada uno al cargar la clase
   (`VerifyError: da.w.<init>(String) ... Constructor returning
   without calling superclass constructor`, muriendo en
   `SplashAty.getMPresenter`). `unpack/denatify_redump.py` ahora
   ANTEPONE una super-llamada resuelta a cada uno: la superclase
   directa sale de las tablas de clases de los DEX (mas
   `unpack/framework_ctors.py`, un extractor de android.jar que
   produce los protos `<init>` accesibles de cada clase del framework
   - el jar del SDK trae `.class` de Java, asi que el parser recorre
   el constant pool). FORWARD de los registros de parametros cuando
   el proto coincide exacto (`da.w(String) -> RuntimeException
   (String)`), llamada `()V` cuando el super tiene ctor sin args, y
   defaults sintetizados (null/0/0L) para superctores solo-con-args
   (lambdas de Kotlin, las jerarquias package-private de
   rx/retrofit). Las instrucciones stub restantes quedan como codigo
   muerto inalcanzable que el verificador ignora, de modo que las
   anotaciones, la info `.line` y los bloques `.param` sobreviven
   intactos. Las trampas de formato estan cubiertas (listas de
   registros de 4 bits del 35c frente a `invoke-direct/range`,
   `move-object/from16`, `const/16` mas alla de v15, frames
   `.registers`). Verificado por DEX: 0 ctors sin super quedan en la
   salida.
2. **El NPE del hilo handlerRanger.** Los stubs de-natificados de
   `com.titan.ranger.NativeJni` devuelven null, asi que
   `NativeJni$v.run -> Gson.fromJson(null) -> RangerResult.getRes()`
   lanzo en el hilo `handlerRanger` - y una excepcion no capturada en
   CUALQUIER hilo mata todo el proceso Android. El `run()` original se
   renombra a `run$shielded` y un wrapper sintetizado `run()V`
delega dentro de `try/catch Throwable`: el hilo del SDK degrada en
silencio en lugar de matar la app.

Totales en los ganadores 1.17.6: 8 natives REAL + 778 stubbed, 19 JNI
genuina conservada, 1 `<clinit>` guardado, 1 hilo blindado, 6.529
fixes de ctor (1.522 forward / 3.969 sin-args / 1.038 defaults / 0
left). El workflow **Booteable research APK** corre toda la cadena en
CI y el boot test encadenado reporta el veredicto. SOLO PARA
INVESTIGACION.

### r5-r8 y el primer BOOT OK de la historia del proyecto

Cuatro iteraciones de CI mas pelaron las capas restantes: la r5
des-kill-eo `JniHandler` (la app lo maneja desde `App.onCreate:128`
a traves del wrapper ofuscado g9.*); la r6 agrego la politica
VENDOR-SYNTH (`unpack/vendor_bodies.json`) - cuerpos reconstruidos
para los natives VMP del camino de arranque, empezando por
`SplashAty.configView = s6(this,this) + y4` (el contrato del
presenter esta totalmente materializado); la r7 extendio KEEP a los
natives de SDKs auto-registrados (org/android/spdy, com/umeng/umzid,
com/uc/crashsdk, tv/danmaku/ijk) cuyas libs propias hacen
RegisterNatives al cargar - stubearlos hacia que ART abortara con
'NoSuchMethodError: no native method'; la r8 antepuso el
`invoke-super` exigido por el framework a 96 overrides stub de
onCreate/onDestroy/onPostCreate (SuperNotCalledException si no).
Resultado (boot tests 34302418568 + 34302915196): **BOOT OK - la UI
real de YouCine (SplashAty -> DMCAAty) resumida Y enfocada, hilo
principal vivo en t=85 s, cero excepciones FATAL** - el veredicto
estricto introducido tras el falso-positivo v5. Salvedad de
investigacion: los ~600 cuerpos sin materializar y los ~424 natives
VMP del vendor son stubs o reconstrucciones - la UI arranca y
sostiene, la semantica profunda monta sobre la cobertura de
materializacion de la fase 2. Metodologia completa en
[docs/es/06-unpack-dinamico.md](docs/es/06-unpack-dinamico.md).

## Documentacion

Tabla equivalente en [README.md](README.md). Mapa maquina:
`evidence/findings.json`. Stub Jadx: `evidence/stub/`.

## Releases (privadas)

| Tag | Contenido |
|---|---|
| `packed-1.17.6` | Muestra original empaquetada (material de analisis) |
| `dumps-1.17.6` | DEX pristinos del dump fase 1 (checksums reparados) |
| `phase2-1.17.6` | Evidencia fase 2: snapshots del re-dump, jni_table, imagenes de modulos |
| `unpacked-1.17.6` | APK de investigacion sin shell iJiami (DEX fase 1, cuerpos stub) |
| `booteable-1.17.6` | **APK booteable de investigacion: DEX fase 2 materializados + de-natify r4-r8 - BOOT OK (UI real SplashAty->DMCAAty resumida Y enfocada, cero FATAL)** |

## Legal

Investigacion educativa: analisis de packer, metodologia de malware-analysis,
clasificacion de SDKs. No se distribuye contenido audiovisual, no se eluden
entitlements de pago y no se publica el bytecode original del vendor.
Ver [docs/es/07-legal.md](docs/es/07-legal.md).

## Hasta aqui nuestra investigacion (2026-09-09)

Muchisimas gracias a **ChapzoMods** por apoyar tanto este proyecto - las
iteraciones r4-r8 y la maquinaria de evidencia del boot-test fueron trabajo
de los dos, y este hito es tan suyo como mio.

Ya completamos lo que queriamos: **desempaquetar la APK y lograr que al
menos corra, aunque no completamente**. El build `booteable-1.17.6` arranca
la UI real de YouCine (BOOT OK, cero excepciones FATAL) con el packer
eliminado por completo; la funcionalidad mas profunda depende de la
cobertura de materializacion documentada arriba, y ahi la dejamos.

Si alguien quiere tomar este codigo para modificarlo, extenderlo o
continuar la investigacion, por favor siga las reglas de la licencia
(GNU GPL 3.0 - ver `LICENSE` y [docs/es/07-legal.md](docs/es/07-legal.md)).

Muchas gracias a todos.

— beto2-dev
