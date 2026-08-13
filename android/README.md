# rxshadow-ace Android App（无 root 版）

把 lab-ace 检测套件集成成 APK：victim（labtarget）与全部检测器都是
**本 App 的同 UID 子进程**（`ProcessBuilder` 直接 exec，不经过 su），
借助 Android 同 UID 进程可互读 `/proc/<pid>/maps`、`process_vm_readv`、
状态文件的机制，**不需要 root**。

```
┌─ App 进程（Compose UI，无特权）────────────────────────┐
│  ProcessBuilder（同 uid，无 su）                        │
│   ├─ labtarget 子进程（victim，匿名可执行页 H_A/H_B）    │
│   ├─ ace 子进程（--pid <victim> --state <files> --json）│
│   └─ det_* 子进程（读 victim maps/内存，同 uid）         │
│  状态文件：/data/data/com.rxshadow.ace/files/           │
└─────────────────────────────────────────────────────────┘
```

## 构建

依赖：JDK 17、Android SDK（compileSdk 34）、NDK r27c（或工具链在 PATH）。

```sh
cd android

# 1) 用 NDK 编译 lab-ace 全部二进制并拷入 assets/bin
NDK=/path/to/ndk-r27c ./gradlew buildNative

# 2) 打包 APK
./gradlew assembleDebug
# 产物：app/build/outputs/apk/debug/app-debug.apk

# 3) 安装
adb install app/build/outputs/apk/debug/app-debug.apk
```

`buildNative` 找不到 NDK 时会跳过并警告（APK 内无二进制，App 启动会提示）。

## 无 root 能力边界

| 级别 | 信道 | 说明 |
|---|---|---|
| ✅ 可用 | F0 功能、L1 selfcrc、L2 elfhash(自)、L4 timing、L4 faultcount、L6 selfmod、L7 trampoline、L7 linkmap、L7 procscan(自)、L2 diff | 全进程内自测或同 uid 读 maps（无 SELinux 限制） |
| ⚠️ 降级 | L2 crossread（外部 GUP 读）、L3 pagemap（无 PFN 仅 soft-dirty）、L4 perf、L7 callstack、L7 hwbp | 同 uid ptrace/GUP 受 SELinux（untrusted_app 域）影响，被拦时诚实报 error |
| ❌ 不可用 | L5 kcore / kallsyms / dmesg / sysfs | 需 root，App 显示 error 并跳过权重 |

**设计取舍**：双视图核心证据（自读 CRC 分歧、fault/stime 记账、洞区 PC、
pingpong 时序）全部在 victim 进程内自测产生，不依赖跨进程特权 ——
这就是无 root 版仍有 14 个有效信道的原因。

## 使用

1. **启动实验**：拉起 labtarget 子进程（H 区 + 双 worker 热路径）
2. **全信道检测**：跑 ace（聚合 18 信道 JSON）+ 展示
3. **差分对照**：起第二个 labtarget，`--state2` 差分锁定
4. 仪表盘看总判定（环形评分 + verdict 徽章），信道页展开 hits/note

> 注意：本 App 无法自己"挂 hook"（KPM 加载需 root）。它测的是
> 干净基线 + 若设备已被（root）挂上双视图 hook 时的检测能力。
