# 07 - Legal y alcance

Youcine-RE es un repositorio **privado** bajo **GNU GPL 3.0**.
Autores: **beto-2dev** y **ChapzoMods**.

## Dentro de alcance

- Identificar packers comerciales (iJiami) y documentar su carga.
- Clasificar SDKs y permisos al estilo malware-analysis.
- Separar controles tecnicos de cliente de entitlements de servidor.
- Pipelines reproducibles de emulador para volcar DEX en laboratorio.

## Fuera de alcance

- Redistribuir bytecode, assets o catalogos del vendor.
- Eludir VIP de pago, bind de dispositivo o DRM de terceros.
- Publicar un "mod" de consumo.
- Meter tokens de GitHub, keystores o SAMPLE_URL en git.

## Samples

El APK packed solo vive como asset de **release privada**, referenciado
por SHA-256. Los DEX volcados y APKs reconstruidos son artifacts de CI
con retencion corta, no fuente.

Las clases stub en `evidence/stub/` son 14 KiB de pegamento del packer.

## Marcas

YouCine, Magis, iJiami, Google, Facebook y demas nombres pertenecen a
sus titulares. El uso aqui es descriptivo.
