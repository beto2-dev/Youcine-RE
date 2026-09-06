# 04 - SDK inventory

Derived from zip properties files, native sonames, manifest components
and `strings.xml`. None of this required decrypted DEX.

## Packer / integrity

- iJiami SecLLVM + `libexec` / `libexecmain`
- `libed25519.so` (verify)
- `assets/signed.bin`

## Playback / download / cast

- ijkplayer 4.4 (`libijkplayer`, `libijkffmpeg`, `libijksdl`) - path
  string `/master_ijk_4.4/android/ijkplayer/...`
- Aria (`assets/aria_config.xml`)
- `libranger-jni.so` (~7.7 MiB arm64) - media/TLS stack (Mozilla CA
  bundle + `MediaReaderHook`)
- Google Cast (`CastOptionsProvider`)
- HPPlay / LeLink (`com.hpplay.sdk`, `assets/hpplay`, `assets/lelink_config`)

## Google / Meta

- Firebase project `youcinemobile` (`1:771252312300:android:59fcb5cf6080703f66adc9`)
  Analytics, Crashlytics NDK, FCM, Dynamic Links (`youcinemobile.page.link`),
  In-App Messaging
- AdMob `ca-app-pub-8403581247282419~2129662664`
- Google Sign-In client
  `771252312300-0ndcanas41p726n0hsb3b4r2qrhpdu0b.apps.googleusercontent.com`
- Facebook app `1167846391661277`, client token in `strings.xml`

## China vendor stack (push / crash / DNS)

- Umeng push (`UMENG_APPKEY` `68b7aaa3ec2b5b6f883069bb`) + `libumeng-spy.so`
- Taobao ACCS / Agoo (`com.taobao.accs.ChannelService`)
- Alibaba `libcrashsdk.so`, `libtnet-3.1.14.so`
- Qiniu HTTP DNS (`com.qiniu.android.dns.NetworkReceiver`)

## AndroidX / RenderScript

- Multidex version file present (legacy)
- `libRSSupport.so`, `librsjni.so` (RenderScript, likely image pipeline)

## Deep links

- `sxl://www.youcine.com`
- `https://youcinemobile.page.link`

Support mailbox in resources: `youcinesuporte@gmail.com`.
