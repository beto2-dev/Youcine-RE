# 03 - Protecciones y bypass

Notas de bypass solo para builds de **laboratorio** en emulador.

| ID | Capa | Que hace | Respuesta en el lab |
|---|---|---|---|
| Shell iJiami | cliente | Sustituye Application y AppComponentFactory | Tras el dump, Application `com.mobile.brasiltv.app.App` y factory `androidx.core.app.CoreComponentFactory` |
| DEX cifrado | cliente | 4 payloads en `ijiami.dat` | Memdump + zip-replace `classes*.dex` |
| SecLLVM / AJM | cliente | Ofuscacion nativa de `libexec` | Ghidra; no hace falta para arrancar Java |
| ptrace | cliente | Anti-debug | Dump fuera de proceso; replace de `ptrace` como respaldo |
| `/proc/self/maps` | cliente | Deteccion 64-bit | El memdump no inyecta |
| Sidecar DETool | cliente | `.so` extra de assets | Se borra con el packer |
| `signed.bin` + ed25519 | cliente | Integridad | Se descarta; el APK se re-firma |
| `allowBackup=false` | politica | Bloquea `adb backup` | Parche opcional |
| `usesCleartextTraffic=true` | politica | Permite HTTP | Util para capturar portal |
| Force upgrade | **servidor** | `upgrade_main` / `version_forbidden_*` | Lo decide el host |
| VIP / bind | **servidor** | LoginAty, DeviceManageAty | Fuera del packer |
| JNI de playback ARM | ABI | ijkplayer, Ranger | Dump en x86_64; boot en arm64 |

## Checklist de rebuild

1. DEX validos (magico `dex\n03x\0`, `file_size` coherente).
2. Application y factory restaurados.
3. Borrar assets iJiami y smali `s/h/e/l/l`.
4. Conservar ijkplayer, Ranger, Cast, Firebase, Umeng.
5. zipalign 4 y apksigner con keystore de laboratorio.
