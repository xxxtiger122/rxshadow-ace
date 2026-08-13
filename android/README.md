# rxshadow-ace Android App（无 root 版）

把 lab-ace 检测套件集成成 APK。**关键约束**：Android 9+ 的 SELinux
`untrusted_app` 域禁止 exec app 私有目录的 ELF（`app_data_file` 无
execute 权限）—— 所以不采用"子进程 exec 二进制"方案，而是把 lab-ace
全部 C 逻辑编译进 **libace.so（CMake）**，App 进程内通过 **JNI** 直接
调用（dlopen 合法）：victim 与检测都在 App 进程内运行，**不需要 root、
不需要 exec、不需要 fork**。

```
┌─ App 进程（Compose UI，无特权）───────────────────────────┐
│  libace.so（JNI，System.loadLibrary）                     │
│   ├─ lab_target_start/stop  → victim（H_A/H_B + worker    │
│   │    + 记账/自读时序自测线程，观测线程写状态文件）        │
│   ├─ det_*_run ×18          → 进程内检测（自读/GUP 自读/  │
│   │    maps 自读，JSON 契约输出）                          │
│   └─ Kotlin 聚合：F0 + 18 信道按 ace.c 权重表融合          │
│  状态文件：/data/data/com.rxshadow.ace/files/             │
└────────────────────────────────────────────────────────────┘
```

C 源由 gradle `syncAceSources` 任务构建时从仓库根同步到
`app/src/main/cpp/ace-src/`（AGP 要求 CMake 源在 cpp/ 内，单一来源）。

## 构建

依赖：JDK 17、Android SDK（compileSdk 34）、NDK r27c（gradle 会自动下载
若 SDK 已装 platform 34 + NDK 27.0.12077973）。

```sh
cd android
./gradlew assembleDebug
# 产物：app/build/outputs/apk/debug/app-debug.apk
adb install app/build/outputs/apk/debug/app-debug.apk
```

> CI（.github/workflows/release.yml）在 tag push 时自动构建并发布 Release。

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
