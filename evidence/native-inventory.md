# Native inventory (1.17.6)

ABIs in `lib/`: `armeabi-v7a`, `arm64-v8a` only.

| SONAME | Role |
|---|---|
| libijkplayer.so / libijkffmpeg.so / libijksdl.so | ijkplayer 4.4 |
| libranger-jni.so | media/TLS stack (~7.7 MiB arm64) |
| libcast-jni.so | Google Cast |
| libed25519.so | signatures |
| libumeng-spy.so | Umeng device fingerprint |
| libcrashsdk.so / libtnet-3.1.14.so | Alibaba crash / net |
| libcrashlytics*.so | Firebase Crashlytics NDK |
| libc++_shared.so | LLVM C++ |
| libRSSupport.so / librsjni*.so | RenderScript |

Packer natives live under **assets**, not `lib/`:

| Path | ABI |
|---|---|
| assets/ijm_lib/*/libexec.so | armeabi, arm64-v8a, x86, x86_64 |
| assets/ijm_lib/*/libexecmain.so | same |
| assets/libijmDataEncryption*.so | armeabi, arm64, x86, x86_64 |
