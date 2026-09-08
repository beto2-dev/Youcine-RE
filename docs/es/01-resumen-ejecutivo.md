# 01 - Resumen ejecutivo

## Objetivo

YouCine mobile 1.17.6 (`com.world.youcinemobile`), distribuido como
`ycMob_1.17.6_ycsite.apk` (42 877 511 bytes).

SHA-256: `28d028d75c89e6ab90c8b7e57a32c42355ac5ae2e388ea1e541bd003cae10d83`.

El nombre visible es YouCine. Por dentro es el arbol
`com.mobile.brasiltv.*` de Magis TV / Xuper TV / Brasil TV: mismas
activities (`SplashAty`, `MainAty`, `PlayAty`), mismo patron de hosts
portal/EPG/upgrade, packer distinto (iJiami aqui, SecNeo en Xuper-RE).

## Packer

| Elemento | Hallazgo |
|---|---|
| Vendor | iJiami (AiJiami) |
| Stub | 14 KiB `classes.dex` con `S`, `A`, `N`, `C` en `s.h.e.l.l` |
| Payload cifrado | `assets/ijiami.dat` (9.5 MiB), count **4**, MD5 ASCII `44f6438002be91557b704ba909f62f58` |
| Loader nativo | `assets/ijm_lib/<abi>/libexec.so` + `libexecmain.so` (armeabi, arm64, x86, x86_64) |
| Compilador | `ijiami SecLLVM compiler 1.7.4.20` |
| AJM | `assets/ijiami.ajm` magico `indl01` |
| Cifrado de datos | `S.sp()` -> `com.ijm.dataencryption.DETool.loadDEso` |
| Application real | **`com.mobile.brasiltv.app.App`** |

`libexec` x86_64 viaja en el APK: el emulador x86_64 puede descifrar DEX
sin traduccion ARM. Las librerias de playback son solo ARM: el **boot**
del APK desempaquetado usa AVD arm64.

## Protecciones vs entitlements

Quitar iJiami es operacion de **cliente**. No fabrica tokens VIP, no
apaga el kill-switch de upgrade y no inventa URLs de stream. Eso es
**servidor**, en hosts rotativos de `strings.xml`.

## Pipeline

El analisis estatico (este repo) ya identifico packer, Application
original, SDKs y mapa de hosts. Unpack dinamico y boot corren en
GitHub Actions.

## Autores

beto-2dev, ChapzoMods. Licencia GPL-3.0.
