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
- **Idiomas:** [English](README.md) · [Espanol](README.es.md)
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

## Estado (2026-09-07)

Cada herramienta del pipeline esta terminada y validada pieza por pieza a
lo largo de ~20 ejecuciones instrumentadas en CI; ver
[docs/es/03-protecciones-y-bypass.md](docs/es/03-protecciones-y-bypass.md)
para el mapa completo capa por capa (trampa de ABI/traduccion, SecLLVM,
gate de integridad de contenido, la escalera de muerte
raw-syscall/int3/ud2/SIGSEGV y su neutralizacion en
`unpack/trace_guard.c`).

Quedan dos cosas, ambas pura ejecucion:

* **Los minutos de GitHub Actions** de la cuenta se agotaron durante la
  sesion de investigacion (los jobs de macOS facturan 10x). Tras el
  reinicio mensual - o al subir el limite de gasto - despacha
  **Dynamic unpack (emulator)** una vez y luego **Boot test (unpacked
  APK)** una vez; ambos completan automaticamente.
* La ejecucion final del dump cuesta unos 25-45 min de runner macOS
  (multiplicador 10x). Un runner macOS auto-alojado (labels
  `macos-14,arm64`) ejecuta los mismos workflows gratis.dor **arm64** (ijkplayer
   y Ranger JNI no traen x86_64) + logcat y captura.

Los scripts Frida en `frida-scripts/` son la via in-process. `libexec` usa
`ptrace`; si el agente muere, el memdump sigue siendo valido.

## Documentacion

Tabla equivalente en [README.md](README.md). Mapa maquina:
`evidence/findings.json`. Stub Jadx: `evidence/stub/`.

## Legal

Investigacion educativa: analisis de packer, metodologia de malware-analysis,
clasificacion de SDKs. No se distribuye contenido audiovisual, no se eluden
entitlements de pago y no se publica el bytecode original del vendor.
Ver [docs/es/07-legal.md](docs/es/07-legal.md).
