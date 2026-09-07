# Youcine-RE

针对 **YouCine**（`com.world.youcinemobile`）**1.17.6** 版本的完整逆向工程实验室。

加壳样本使用商业加壳器 **iJiami (AiJiami)**：14 KiB 的桩 DEX（`s.h.e.l.l.S` / `s.h.e.l.l.A`）、加密存放于 `assets/ijiami.dat` 的 multi-DEX、以 **SecLLVM 1.7.4.20** 编译的原生加载器 `libexec.so`，以及一个数据加密 sidecar（`com.ijm.dataencryption.DETool`）。

- **RE authors / 作者 / Auteurs :** beto-2dev, ChapzoMods
- **中文翻译 / Translation française :** ChapzoMods
- **许可证：** GNU GPL 3.0（`LICENSE`）
- **Languages / 语言 / Langues :** [English](README.md) · [Espanol](README.es.md) · [中文](README.zh.md) · [Français](README.fr.md)
- **范围：** 脱壳方法论、防护映射图、SDK 清单、客户端/服务端划分、模拟器流水线

本仓库包含**研究期间产出的工具、脚本与文档**，其中**不**包含 APK、转储出的 DEX 或应用程序的原始源码。样本存放于**私有 GitHub Releases**。

## 样本（已分析）

| 字段 | 值 |
|---|---|
| 文件 | `ycMob_1.17.6_ycsite.apk` |
| 包名 | `com.world.youcinemobile` |
| 版本 | 1.17.6 (11706) |
| min / target SDK | 19 / 33 |
| SHA-256 | `28d028d75c89e6ab90c8b7e57a32c42355ac5ae2e388ea1e541bd003cae10d83` |
| 桩 DEX | `classes.dex` 13608 字节 |
| 加密 DEX | `assets/ijiami.dat` 9543463 字节，头部计数 **4** |
| 真实 Application | `com.mobile.brasiltv.app.App` |
| 壳 Application | `s.h.e.l.l.S` |
| 组件工厂 | `s.h.e.l.l.A` 包装 `androidx.core.app.CoreComponentFactory` |
| 签名 | 自签名 `C=86, ST=GD, L=SZ, O=XXL, OU=OTT, CN=xxl` |
| 家族 | 与 Magis / Xuper / Brasil TV 同属 `com.mobile.brasiltv.*` 血统，品牌重塑为 YouCine，以 iJiami 而非 SecNeo 加壳 |

## 工具

| 工具 | 版本 | 用途 |
|---|---|---|
| Jadx | 1.5.6 | 桩 DEX 转 Java |
| Apktool | 2.12.1 | manifest、资源、重建 |
| Ghidra | 12.1.3 (headless, JDK 21) | `libexec.so` / JNI |
| androguard | 4.x | APK 解析 |
| Frida | 16.6.x | 可选的进程内转储 |
| Android 模拟器 | API 30 x86_64（转储）、API 33 arm64（启动） | GitHub Actions + KVM / Apple Silicon |
| GitHub Actions | ubuntu-latest, macos-14 | 脱壳 + 启动 + Ghidra |

`tools/setup_env.sh` 会把 JDK 21、Ghidra 12.1.3、Jadx 1.5.6、Apktool 和 platform-tools 下载到 `TOOLS_DIR`（默认为 `./tools`）。所有路径都可通过环境变量覆盖；脚本不会硬编码任何机器路径。

## 客户端与服务端的划分

**客户端（可在本地脱壳 / 打补丁）**

- iJiami 壳、加密 DEX、`libexec` 的反调试（`ptrace`、`/proc/self/maps`）
- ABI 提取器（`assets/ijm_lib/<abi>/libexec.so`，含 **x86_64**）
- 数据加密 sidecar、`signed.bin` / ed25519 完整性校验
- UI、ijkplayer、Aria、Cast、HPPlay/LeLink、Firebase、Umeng、AdMob、Facebook SDK
- `strings.xml` 中内嵌的轮换主机（门户、EPG、升级、公告、广告、H5）

**服务端（无法通过剥离加壳器移除）**

- 目录 / VOD / 直播门户（`portal_main` / `portal_backup`）
- EPG、强制升级 / 版本自毁开关（kill-switch）、公告、广告配置
- 账户、VIP、设备绑定、兑换、支付
- 流 URL 的签发（不在桩 DEX 中）

剥离 iJiami 后得到的是一个研究性构建，能够**启动原始的 `com.mobile.brasiltv.app.App`**。观看权益与 CDN URL 仍然来自门户主机。

## 脱壳流水线

1. 静态扫描：`SAMPLE_APK=... python3 static-analysis/apk_quickscan.py`
2. GitHub Action **Dynamic unpack (emulator)** -> 任务 `unpack-macos-tcg`：以 `-accel off` 启动 arm64-v8a AVD（Apple Silicon runner 上的同架构 TCG——完全原生的 ARM 执行），安装**原始**加壳 APK，启动 `SplashAty`，并从 `/proc/<pid>/mem` 进程外转储解密后的 DEX（无注入、无 ptrace、无进程内代理 -> 壳的反调试无法察觉）。
3. `unpack/rebuild_unpacked_apk.py` 恢复真实的 Application 类、丢弃加壳器的 assets、以 zip 方式替换 `classes*.dex`、执行 zipalign 对齐、签名，并发布私有 Release `unpacked-1.17.6`。
4. GitHub Action **Boot test (unpacked APK)** 将脱壳重建后的构建安装到 arm64 模拟器上，验证真实的 `com.mobile.brasiltv.*` UI 能够启动（截图 + logcat + dumpsys）。
5. GitHub Action **Phase 2（Frida RegisterNatives + warm-up + re-dump，redroid）** 在同一个 redroid 容器中以 Frida 运行 ORIGINAL 原始加壳 APK：捕获完整的 JNI 注册表（`frida-scripts/06_register_natives_table.js`），强制加载已转储 DEX 中的所有类（`07_class_warmup.js`），使 libexec 重新物化约 45k 个被抽取的桩方法体，随后重新转储 DEX 容器及 libexec 的内存镜像（`08_redump_dex.js` + `unpack/dexdata_extract.py`），并将全部产物发布到 `phase2-1.17.6` Release。`ijiami-static/` 文件夹则完全离线攻击同一载荷：AES 密钥捕获/搜寻 + `assets/ijiami.dat` 的静态解密。

## 状态（2026-09-08）

流水线中的每一个工具都已完成，并在约 30 次带插桩的 CI 运行中逐项通过验证；完整的逐层映射图（ABI/转译陷阱、SecLLVM、内容完整性门控、raw-syscall/int3/ud2/SIGSEGV 死亡阶梯及其在 `unpack/trace_guard.c` 中的解除方案）请参见 [docs/en/03-protections-and-bypass.md](docs/en/03-protections-and-bypass.md)。

脱壳后的重建版本如今已将**真实**应用启动到物理上可能的极限（rebuild v5，`rebuild-fix.yml` 快速循环）：`com.youcine.re.BootProvider` 会在 `Application.onCreate` 之前加载 iJiami 的 DE SDK（SM4 prefs 引擎）——包括 ndk_translation 情形下的 ABI 补救——内嵌的签名自毁开关（`ConfusionUtils.cc`）通过最小化的 DEX 手术予以解除，进程随后逐一执行所有未受保护的层，直至第一个 iJiami-VMP 方法（`SqlHelper.getDb`）。若缺少加壳器的内容门控引擎，完整启动便无从实现：约 805 个 ACC_NATIVE 方法体和约 4.5 万个提取桩，只有 libexec 才会在运行时将其物化。修正后的结论见 [docs/en/06-dynamic-unpack.md](docs/en/06-dynamic-unpack.md)。

这项基于托管 CI 的研究得出的经验性结论是：**ARM 客户机在 GitHub 托管 runner 上无法实现**（Linux 启动器拒绝在 x86 宿主机上运行 arm64 AVD；macOS runner 强制启用 HVF，且缺少所需的 entitlement——即便加上 `-accel off` 也一样）。因此，转储改在真实硬件上收尾，只差一条命令：

* **一台已 root 的 Android 手机**（推荐，经典路径）：

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

* **把你自己的 Mac 用作自托管 runner**（标签 `[self-hosted, macOS]`）：在启用 `run_selfhosted` 输入的情况下派发 **Dynamic unpack (emulator)**；随后 `rebuild` 与 **Boot test** 会自动端到端运行。

完整细节见 [docs/en/06-dynamic-unpack.md](docs/en/06-dynamic-unpack.md)。

快速迭代：**Rebuild fix (fast loop)** 工作流从不可变的 `packed-1.17.6` + `dumps-1.17.6` Release 出发，以确定性方式重新推导出构建，并串接执行启动测试。

`frida-scripts/` 下的 Frida 脚本仍可作为进程内替代方案。`libexec` 会调用 `ptrace`；即使代理被杀死，内存转储路径依然有效。

## Phase 2（于 2026-09-08 实现）

针对最后一道防线的 Frida 捕获层已经就位：

* `unpack/frida_phase2_driver.py` + `unpack/redroid_frida_flow.sh` +
  `.github/workflows/frida-redump.yml` —— 在原生 arm64 redroid 中以 spawn 门控方式用 Frida 运行 ORIGINAL 原始 APK（重命名后的 frida-server 监听非标准端口），完成 RegisterNatives 表捕获、基于 `dumps-1.17.6` DEX 的全类 warm-up 扫描、带校验和修复的 warm-up 后重新转储，以及被 SecLLVM 自修改的 libexec.so / libijmDataEncryption.so 的内存镜像。输出：`phase2-1.17.6` Release（jni_table.json + 重新转储的 DEX + 模块镜像）。
* `ijiami-static/` —— 针对 `ijiami.dat` 的离线 AES 攻击：运行时密钥捕获、内存转储中的密钥表（key schedule）搜寻（含逆密钥表恢复），以及经 DEX/NRV2B 输出验证的候选矩阵解密器。自测通过（14/14、15/15）。

运行方式：派发 **Phase 2 - Frida RegisterNatives + warmup +
re-dump (redroid)** 工作流，或本地执行 `GH_TOKEN=<pat> bash
unpack/redroid_frida_flow.sh`。完整方法论见
[docs/en/06-dynamic-unpack.md](docs/en/06-dynamic-unpack.md)。

## 文档

文档正文目前提供英文与西班牙语版本。

| 文档 |
|---|
| [01 Executive summary](docs/en/01-executive-summary.md) |
| [02 iJiami packer](docs/en/02-packer-ijiami.md) |
| [03 Protections](docs/en/03-protections-and-bypass.md) |
| [04 SDKs](docs/en/04-sdks.md) |
| [05 Client vs server](docs/en/05-client-vs-server.md) |
| [06 Dynamic unpack](docs/en/06-dynamic-unpack.md) |
| [07 Legal](docs/en/07-legal.md) |

机器可读的映射数据：`evidence/findings.json`。来自 Jadx 的桩源码：`evidence/stub/`。

## Releases（私有）

| 标签 | 内容 |
|---|---|
| `packed-1.17.6` | 原始加壳样本（分析材料） |
| `unpacked-1.17.6` | 移除 iJiami 壳后的研究性 APK（成功转储之后） |

## 法律声明

仅限教育性安全研究：加壳器分析、恶意软件分析方法论、SDK 分类。作者不提供受版权保护的媒体内容，不提供付费权益的绕过手段，也不重新分发厂商字节码。详见 [docs/en/07-legal.md](docs/en/07-legal.md)。
