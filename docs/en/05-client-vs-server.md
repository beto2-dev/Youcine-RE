# 05 - Client vs server

The packer only hides **client** bytecode. After a successful dump, the
app still speaks to first-party hosts. Those hosts, not iJiami, enforce
VIP, device bind and kill-switches.

## Embedded in resources (client config of server names)

Values from `res/values/strings.xml` of 1.17.6. Hosts rotate; treat as
a snapshot.

| Key | Host |
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

`assets/domain_test.json` is a placeholder map (`"xx"`) of the same
roles (upgrade, portal, epg, market, diamond, notice, dccore,
datacollect, ad). Real URLs for market/diamond/dccore are expected
inside the encrypted DEX or returned by portal.

Other client-visible endpoints: `http://dwonload.youcine.net/dw`
(typo in original), Firebase/Google/Facebook as in the SDK chapter.

## Always client

UI, player, download manager, cast discovery, packer, local integrity,
analytics SDKs, AdMob rendering, the affiliate meta `LINK_ID=L21907` /
`LINK_VALUE=...`.

## Always server

Authentication cookies/tokens, VIP flags, catalog JSON, EPG, signed
media URLs, payments, force-upgrade decisions, device session revoke
(`dialog_desc_token_invalid` lists remote logout).

## Analysis implication

A packer-free APK is the right artifact to **instrument** portal traffic
(TLS unpin script is in `frida-scripts/03_ssl_unpinning.js`). It is not
a substitute for those APIs.
