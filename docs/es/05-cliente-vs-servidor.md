# 05 - Cliente vs servidor

El packer solo oculta bytecode de **cliente**. Despues del dump la app
sigue hablando con hosts de primer nivel. Esos hosts, no iJiami, imponen
VIP, bind y kill-switch.

## Nombres de servidor embebidos (config de cliente)

Snapshot 1.17.6 en `res/values/strings.xml`. Los hosts rotan.

| Clave | Host |
|---|---|
| portal_main | jbfnl.phdelbotq.com |
| portal_backup | hrvxm.zgyhovdmu.com |
| epg_main | pre.itgfgdz.com |
| epg_backup | pre.utedbr.com |
| upgrade_main | wposj.liegmzoct.com |
| upgrade_backup | uahtw.ydahseguj.com |
| notice_main | dqnuv.ytuhckpdi.com |
| notice_backup | bjria.boqdnwzfk.com |
| ad_main | afjhl.maqywglrp.com |
| ad_backup | wfqco.ejkgtuqwa.com |
| h5_main | h5.youcine.pro |

`assets/domain_test.json` es un mapa placeholder (`"xx"`) de los mismos
roles. market/diamond/dccore se esperan en el DEX cifrado o en la
respuesta del portal.

## Siempre cliente

UI, player, descargas, descubrimiento de cast, packer, integridad local,
SDKs de telemetria, AdMob, meta de afiliado `LINK_ID=L21907`.

## Siempre servidor

Tokens, flags VIP, JSON de catalogo, EPG, URLs de media firmadas, pagos,
force-upgrade, revocacion remota de sesion.

## Implicacion

Un APK sin packer sirve para **instrumentar** el trafico del portal
(script de unpin en `frida-scripts/03_ssl_unpinning.js`). No sustituye
esas APIs.
