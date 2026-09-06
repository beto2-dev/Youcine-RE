# 07 - Legal and scope

Youcine-RE is a **private** research repository published under
**GNU GPL 3.0**. Authors: **beto-2dev** and **ChapzoMods**.

## In scope

- Identifying commercial packers (iJiami) and documenting how they load.
- Malware-analysis style classification of SDKs and permissions.
- Distinguishing client-side technical controls from server-side
  entitlements.
- Building reproducible emulator pipelines for dumping decrypted DEX
  in a lab.

## Out of scope

- Redistributing vendor bytecode, assets, or media catalogs.
- Circumventing paid VIP, device-bind, or DRM of third-party streams.
- Shipping a consumer "mod" store listing.
- Embedding GitHub tokens, keystores, or SAMPLE_URL in git.

## Samples

The packed APK is stored only as a **private release** asset, referenced
by SHA-256. Dumped DEX and rebuilt APKs are CI artifacts with short
retention, not source.

Decompiled stub classes in `evidence/stub/` are 14 KiB of packer glue
required to explain the loader; they are not the application.

## Trademark

YouCine, Magis, iJiami, Google, Facebook and other names belong to
their owners. Use here is descriptive.
