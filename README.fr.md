# Youcine-RE

Laboratoire complet de rétro-ingénierie pour **YouCine** (`com.world.youcinemobile`) version **1.17.6**.

L'échantillon packé utilise le packer commercial **iJiami (AiJiami)** : un DEX stub de 14 KiB (`s.h.e.l.l.S` / `s.h.e.l.l.A`), un multi-DEX chiffré dans `assets/ijiami.dat`, un chargeur natif `libexec.so` compilé avec **SecLLVM 1.7.4.20**, et un sidecar de chiffrement de données (`com.ijm.dataencryption.DETool`).

- **RE authors / 作者 / Auteurs :** beto-2dev, ChapzoMods
- **中文翻译 / Translation française :** ChapzoMods
- **Licence :** GNU GPL 3.0 (`LICENSE`)
- **Languages / 语言 / Langues :** [English](README.md) · [Espanol](README.es.md) · [中文](README.zh.md) · [Français](README.fr.md)
- **Périmètre :** méthodologie de retrait du packer, cartographie des protections, inventaire des SDK, répartition client/serveur, pipelines sur émulateur

Ce dépôt contient **les outils, scripts et documentation produits durant la recherche**. Il ne contient **pas** d'APK, de DEX dumpés, ni de code source original de l'application. Les échantillons vivent dans des **Releases GitHub privées**.

## Échantillon (analysé)

| Champ | Valeur |
|---|---|
| Fichier | `ycMob_1.17.6_ycsite.apk` |
| Package | `com.world.youcinemobile` |
| Version | 1.17.6 (11706) |
| min / target SDK | 19 / 33 |
| SHA-256 | `28d028d75c89e6ab90c8b7e57a32c42355ac5ae2e388ea1e541bd003cae10d83` |
| DEX stub | `classes.dex` 13608 octets |
| DEX chiffré | `assets/ijiami.dat` 9543463 octets, compteur d'en-tête **4** |
| Application réelle | `com.mobile.brasiltv.app.App` |
| Application shell | `s.h.e.l.l.S` |
| Fabrique de composants | `s.h.e.l.l.A` encapsulant `androidx.core.app.CoreComponentFactory` |
| Signataire | auto-signé `C=86, ST=GD, L=SZ, O=XXL, OU=OTT, CN=xxl` |
| Famille | Même lignée `com.mobile.brasiltv.*` que Magis / Xuper / Brasil TV, rebaptisée YouCine, packée avec iJiami au lieu de SecNeo |

## Outils

| Outil | Version | Rôle |
|---|---|---|
| Jadx | 1.5.6 | DEX stub vers Java |
| Apktool | 2.12.1 | manifest, ressources, reconstruction |
| Ghidra | 12.1.3 (headless, JDK 21) | `libexec.so` / JNI |
| androguard | 4.x | parsing de l'APK |
| Frida | 16.6.x | dump in-process optionnel |
| Émulateur Android | API 30 x86_64 (dump), API 33 arm64 (démarrage) | GitHub Actions + KVM / Apple Silicon |
| GitHub Actions | ubuntu-latest, macos-14 | dépackage + démarrage + Ghidra |

`tools/setup_env.sh` télécharge JDK 21, Ghidra 12.1.3, Jadx 1.5.6, Apktool et platform-tools dans `TOOLS_DIR` (par défaut `./tools`). Chaque chemin peut être redéfini via des variables d'environnement ; les scripts ne codent en dur aucun emplacement machine.

## Client vs serveur

**Client (peut être dépacké / patché localement)**

- Shell iJiami, DEX chiffré, anti-débogage de `libexec` (`ptrace`, `/proc/self/maps`)
- Extracteur d'ABI (`assets/ijm_lib/<abi>/libexec.so`, y compris **x86_64**)
- Sidecar de chiffrement de données, intégrité `signed.bin` / ed25519
- UI, ijkplayer, Aria, Cast, HPPlay/LeLink, Firebase, Umeng, AdMob, Facebook SDK
- Hôtes rotatifs embarqués dans `strings.xml` (portail, EPG, mise à jour, avis, publicités, H5)

**Serveur (ne disparaît pas lorsqu'on retire le packer)**

- Portail de catalogue / VOD / live (`portal_main` / `portal_backup`)
- EPG, mise à jour forcée / kill-switch de version, avis, configuration des publicités
- Compte, VIP, association d'appareil, échange de codes, paiements
- Émission des URL de flux (pas dans le DEX stub)

Retirer iJiami produit un build de recherche qui **démarre l'application originale `com.mobile.brasiltv.app.App`**. Les droits d'accès et les URL CDN proviennent toujours des hôtes du portail.

## Pipeline de dépackage

1. Scan statique : `SAMPLE_APK=... python3 static-analysis/apk_quickscan.py`
2. L'action GitHub **Dynamic unpack (emulator)** -> job `unpack-macos-tcg` : démarre un AVD arm64-v8a avec `-accel off` (TCG à architecture identique sur le runner Apple Silicon — exécution ARM entièrement NATIVE), installe l'APK packée **ORIGINALE**, lance `SplashAty` et réalise le dump des DEX déchiffrés hors processus depuis `/proc/<pid>/mem` (sans injection, sans ptrace, sans agent in-process -> indétectable par l'anti-débogage du packer).
3. `unpack/rebuild_unpacked_apk.py` restaure la classe Application réelle, retire les assets du packer, remplace `classes*.dex` dans le zip, applique zipalign, signe et publie la Release privée `unpacked-1.17.6`.
4. L'action GitHub **Boot test (unpacked APK)** installe le build sans packer sur un émulateur arm64 et vérifie que l'UI réelle `com.mobile.brasiltv.*` démarre (captures d'écran + logcat + dumpsys).
5. L'action GitHub **Phase 2 (Frida RegisterNatives + warm-up + re-dump, redroid)** exécute l'APK packée ORIGINALE sous Frida dans le même conteneur redroid : capture de la table d'enregistrement JNI complète (`frida-scripts/06_register_natives_table.js`), chargement forcé de toutes les classes des DEX dumpées (`07_class_warmup.js`) afin que libexec re-matérialise les ~45k corps de stub extraits, puis re-dump des conteneurs DEX et de l'image mémoire de libexec (`08_redump_dex.js` + `unpack/dexdata_extract.py`), et publication de l'ensemble vers la Release `phase2-1.17.6`. Le dossier `ijiami-static/` attaque le même payload entièrement hors ligne : capture/recherche de clé AES + déchiffrement statique de `assets/ijiami.dat`.

## État (2026-09-08)

Chaque outil du pipeline est terminé et validé pièce par pièce à travers ~30 exécutions CI instrumentées ; voir [docs/en/03-protections-and-bypass.md](docs/en/03-protections-and-bypass.md) pour la cartographie complète couche par couche (piège d'ABI/traduction, SecLLVM, gate d'intégrité du contenu, l'échelle de mort raw-syscall/int3/ud2/SIGSEGV et sa neutralisation dans `unpack/trace_guard.c`).

Le rebuild sans packer démarre désormais la VRAIE application aussi loin que physiquement possible (rebuild v5, boucle rapide `rebuild-fix.yml`) : un `com.youcine.re.BootProvider` charge le SDK DE de iJiami (moteur SM4 de prefs) avant `Application.onCreate` — y compris le sauvetage d'ABI sous ndk_translation — le kill-switch de signature embarqué (`ConfusionUtils.cc`) est neutralisé par une chirurgie DEX minimale, et le processus parcourt toutes les couches non protégées jusqu'à la première méthode iJiami-VMP (`SqlHelper.getDb`). Le démarrage complet est impossible sans le moteur à gate de contenu du packer : les ~805 corps ACC_NATIVE et les ~45k stubs d'extraction ne sont matérialisés que par libexec au runtime. Voir le verdict corrigé dans [docs/en/06-dynamic-unpack.md](docs/en/06-dynamic-unpack.md).

La conclusion empirique de la recherche menée sur le CI hébergé : **les invités ARM sont impossibles sur les runners hébergés par GitHub** (le lanceur Linux refuse les AVD arm64 sur les hôtes x86 ; les runners macOS imposent HVF et ne disposent pas de l'entitlement requis — même avec `-accel off`). Le dump s'achève donc sur du matériel réel, à une commande de distance :

* **Un téléphone Android rooté** (recommandé, la voie classique) :

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

* **Votre propre Mac en tant que runner auto-hébergé** (labels `[self-hosted, macOS]`) : déclenchez **Dynamic unpack (emulator)** avec l'input `run_selfhosted` activé ; `rebuild` et **Boot test** s'exécutent alors automatiquement de bout en bout.

Détails complets : [docs/en/06-dynamic-unpack.md](docs/en/06-dynamic-unpack.md).

Itération rapide : le workflow **Rebuild fix (fast loop)** régénère le build de manière déterministe à partir des Releases immuables `packed-1.17.6` + `dumps-1.17.6` et enchaîne le test de démarrage.

Les scripts Frida sous `frida-scripts/` demeurent une alternative in-process. `libexec` appelle `ptrace` ; si l'agent est tué, la voie du memdump reste fonctionnelle.

## Phase 2 (implémentée le 2026-09-08)

La couche de capture Frida pour la dernière ligne de défense est en place :

* `unpack/frida_phase2_driver.py` + `unpack/redroid_frida_flow.sh` +
  `.github/workflows/frida-redump.yml` — exécution Frida spawn-gated de
  l'APK ORIGINALE en redroid arm64 natif (frida-server renommé sur un port
  non standard), capture de la table RegisterNatives, balayage de warm-up
  des classes depuis les DEX de `dumps-1.17.6`, re-dump post-warm-up avec
  réparation des checksums et images mémoire du libexec.so /
  libijmDataEncryption.so auto-modifié par SecLLVM. Sortie : Release
  `phase2-1.17.6` (jni_table.json + DEX re-dumpées + images de modules).
* `ijiami-static/` — l'attaque AES hors ligne contre `ijiami.dat` :
  capture de clé à l'exécution, chasse aux key schedules dans les dumps
  mémoire (avec récupération par key schedule inverse) et un décrypteur à
  matrice de candidats vérifié contre la sortie DEX/NRV2B. Auto-tests au
  vert (14/14, 15/15).

Exécution : déclenchez **Phase 2 - Frida RegisterNatives + warmup +
re-dump (redroid)**, ou en local `GH_TOKEN=<pat> bash
unpack/redroid_frida_flow.sh`. Méthodologie complète dans
[docs/en/06-dynamic-unpack.md](docs/en/06-dynamic-unpack.md).

## Documentation

Les documents détaillés sont disponibles en anglais et en espagnol.

| Documentation |
|---|
| [01 Executive summary](docs/en/01-executive-summary.md) |
| [02 iJiami packer](docs/en/02-packer-ijiami.md) |
| [03 Protections](docs/en/03-protections-and-bypass.md) |
| [04 SDKs](docs/en/04-sdks.md) |
| [05 Client vs server](docs/en/05-client-vs-server.md) |
| [06 Dynamic unpack](docs/en/06-dynamic-unpack.md) |
| [07 Legal](docs/en/07-legal.md) |

Carte lisible par machine : `evidence/findings.json`. Sources du stub issues de Jadx : `evidence/stub/`.

## Releases (privées)

| Tag | Contenu |
|---|---|
| `packed-1.17.6` | Échantillon packé original (matériel d'analyse) |
| `unpacked-1.17.6` | APK de recherche avec le shell iJiami retiré (après un dump réussi) |

## Juridique

Recherche en sécurité à but éducatif uniquement : analyse de packers, méthodologie d'analyse de maliciels, classification des SDK. Les auteurs ne fournissent ni médias protégés par le droit d'auteur, ni contournement de droits payants, ni redistribution du bytecode de l'éditeur. Voir [docs/en/07-legal.md](docs/en/07-legal.md).
