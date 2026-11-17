---
name: apk-reverse
description: Android APK 逆向。当目标只给了一个 APK/安装包，或需要分析 APP 的接口、签名算法、硬编码密钥、风控/证书校验/root 检测，以及重打包、Frida 动态 Hook、.so 分流时使用。覆盖 jadx/apktool/aapt/adb/frida/objection 的完整静态+动态链路；无真机时给出静态+流量模拟的替代路径。
tags:
  cwe: [CWE-312, CWE-321, CWE-295, CWE-489, CWE-798, CWE-926, CWE-1104]
  attack: [T1409, T1426, T1430, T1516, T1521]
  class: [mobile, android, reverse, forensics]
---

# APK 逆向 · 内部版作业规范

黑灰产分发常只给一个 APK / 安装包。本技能负责把包拆开，拿到底层的东西：
**接口、签名算法、密钥、风控逻辑**，并把这些作为证据固定下来。

## 与本平台的衔接（先读这段）

| 场景 | 用平台能力 |
|---|---|
| 样本本身是证据 | `save_evidence` 存档原始 APK 并登记 SHA-256（先哈希，再解包） |
| 接口/密钥/结论 | `record_fact` 落库（类名、方法、算法、密钥位置） |
| 后端接口测试 | 逆向拿到接口后转 `http_probe` / `auth_request` / `diff_responses` |
| 流量还原 | 平台流量捕获（默认开）或 mitmproxy；`traffic` 里看请求 |
| 已知组件 CVE | `search_vulns` / `scan_with_nuclei`（服务端） |

## 环境事实（服务器形态）

- 工具链由 `install.sh` / Docker 镜像 / 宿主环境页装好：`java`、`apktool`、`aapt`、
  `adb`、`jadx`、`frida`、`objection`。
- **服务器通常没有真机/模拟器**：
  - 有设备（USB/远程 adb，例如 `adb connect 127.0.0.1:7555`）→ 走真机动态链路；
  - 无设备 → **静态为主 + 流量模拟**：jadx/apktool 读逻辑，接口用平台流量捕获/代理验证，
    不做需要真机的 Hook（写清「需要设备后才能完成」）。
- 不在服务器上装模拟器；需要动态验证时向用户要设备或授权环境。

## 自带脚本（优先用）

| 脚本 | 用途 |
|---|---|
| `scripts/decode.sh` | 一次跑 jadx + apktool，输出 package/java_files/smali_dirs/so_files 摘要 |
| `scripts/frida-run.sh` | 设备/进程列举、spawn/attach 注入，避免 `-f/-n/-U` 混用出错 |
| `scripts/rebuild-sign-install.sh` | `apktool b` → zipalign → apksigner → 可选 `adb install` |

```bash
bash scripts/decode.sh -ApkPath /data/sample/app.apk -Clean
bash scripts/frida-run.sh -Usb -ListProcesses
bash scripts/rebuild-sign-install.sh -ProjectDir apktool_out -Install -Reinstall -DeviceSerial 127.0.0.1:7555
```

一行命令直接调用即可，不必封装：`adb devices`、`adb logcat`、`frida-ps -U`、
`jadx --version`、`apktool --version`。

## 工作流

### 1. Triage（先定性，不动手）

1. 原始包先 `sha256sum app.apk` → `save_evidence`（证据链起点）。
2. `jadx -d jadx_out app.apk` 出 Java；`apktool d app.apk -o apktool_out` 出 smali+资源。
3. 先看：`AndroidManifest.xml`（权限/导出组件/主入口/debuggable/allowBackup）、
   `package`、`application`、`lib/**/*.so` 是否存在、包名与签名（`apksigner verify --print-certs`）。
4. 威胁形态速查：透明/隐藏图标（`aapt dump badging` 看 label/icon）、
   Magisk/脚本格机特征、持久化路径（`service.d`/`priv-app`）——**特征与 URL 入证，不执行**。

### 2. Java 逻辑（jadx）

从 `jadx_out` 读：MainActivity/Application、登录、网络、加密、风控、SDK 初始化。
关键词：`login` `sign` `encrypt` `cipher` `token` `root` `certificate` `trust`
`okhttp` `retrofit` `webview` `baseUrl` `api` `secret` `accessKey`。

产出三样东西：**接口清单**（完整 URL/path/参数）、**签名/加密算法**（smali 级还原到可复算）、
**硬编码凭据**（AK/SK/token/appSecret，全文落 fact，报告里掩码）。

### 3. Smali 与资源层（apktool）

jadx 不完整/混淆重/需要 patch 时切 `apktool_out`：`smali*/`、`res/values/strings.xml`、
`AndroidManifest.xml`。可 patch：`android:exported`、`debuggable`、root 检测返回值、
登录校验、证书校验分支。

### 4. 重打包（仅在需要时）

```bash
apktool b apktool_out -o rebuilt.apk
# 对齐 + 签名 + 安装（调试 keystore 自动生成并复用）
bash scripts/rebuild-sign-install.sh -ProjectDir apktool_out -Install -Reinstall
```

**边界**：重打包只用于授权样本的**分析验证**；改包后的产物不得用于投放/二次分发。

### 5. 动态 Hook（有设备才做）

先 Java 层，再 native：
- Hook 登录/签名/加密：`javax.crypto`、`MessageDigest`、`OkHttp`/`Retrofit` 拦截器；
- 绕过：root 检测、SSL pinning、调试检测（objection 一条命令先试：
  `objection -g com.example.app explore` → `android sslpinning disable`）；
- 原则：先打印参数与返回值，再决定是否改返回值。

脚本与可复用脚本模板见 `references/frida-cookbook.md`、`references/frida-bypass-kit.md`。

### 6. `.so` 分流

Java 只是 JNI 包装 / 核心签名在 native / `System.loadLibrary()` 后逻辑消失 / 校验在 `.so`
→ 立刻切 native：先 `strings`、`readelf -s`、radare2 快速 triage；深入反编译用
`ida-reverse` 或 Ghidra。APK 内的 `.so` 可 `unzip -j` 取出单独存档。

### 7. 后端接口验证（主战场）

逆向只是拿钥匙。拿到接口后用平台工具直接打授权域名：
未授权/越权（换 id/token）/注入/逻辑；签名算法可复算后自己构造请求。
按取证口径**可以导出样本与数据**，但要分批控速、登记哈希（save_evidence 自动算 SHA-256）。

## 输出要求

至少说明：包名与签名、入口组件、关键逻辑在 Java/smali/`.so` 哪一层、
接口清单、签名/加密算法、硬编码凭据（掩码）、已确认的敏感点
（登录/签名/root/SSL/WebView/JNI）、patch 或 Hook 的具体位置、以及**没做成的事**
（例如无设备导致动态验证未做）。

## 禁止事项

- 不要一上来就改 smali；先看 manifest 与主入口。
- 不要把 jadx 反编译不完整等同于「逻辑不可分析」（换 smali/换工具再判）。
- 不要在 `.so` 明显承载核心逻辑时死磕 Java 层。
- 不逆向/测试授权外的 APP；不绕过付费与版权保护做非测试用途。
- 不执行样本里的任何命令/脚本（`curl|sh`、格机指令）——只提取特征入证。

## 参考文件（按需打开，禁止通读）

| 文件 | 内容 |
|---|---|
| `references/apk-security-checklist.md` | 打包/组件/存储/网络/加密的检查清单 |
| `references/frida-cookbook.md` | 常用 Hook 脚本（Java/native/网络/加密） |
| `references/frida-bypass-kit.md` | 反调试/反 root/SSL pinning 绕过合集 |
| `references/android-advanced.md` | 加固、动态加载、JNI、脱壳等进阶主题 |

## 完成自检

- [ ] 原始 APK 已哈希并 `save_evidence`
- [ ] manifest/入口/导出组件已过一遍
- [ ] 接口清单、签名算法、密钥位置已落 fact
- [ ] 有设备则完成 Hook 验证；无设备则写明缺设备与替代验证
- [ ] patch/Hook 的位置与目的写清楚（可复现）
