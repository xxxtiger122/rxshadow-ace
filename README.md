# rxshadow-ace — 双视图 hook 的对抗面（实验对象 + ACE 检测套件）

一个 VA 两份物理页的「无痕」是相对的。本仓库是 **rxshadow**
（[github.com/xxxtiger122/rxshadow](https://github.com/xxxtiger122/rxshadow)，
ARM64 内核态双视图 KPM）的**对抗面**：一个整合的实验对象（labtarget）
+ 一套从用户态检测内核态 hook 的 ACE（Anti-Cheat-Engine 式）检测器
+ 聚合引擎。检测思路吸收自看雪 2026 hook 系列帖文（出处映射见下文）。

```
labtarget（受害者，被挂对象）
   │ 自报双视图 CRC / 调用值 / 延迟 / PFN / fork 子视图 / 记账
   │ 自测 mincore / mmap 占位 / ucontext PC / pingpong（状态文件协议）
   ▼
det_* ×18（每个只打一个观测信道，输出统一 JSON 契约）
   ▼
ace（F0 功能信道 + 加权融合 + 判决 + stealth index）
```

## 依赖与关联

- **host 验证**：仅需 gcc/make（`make test`，无需手机、无需 rxshadow 内核模块）
- **真机实验**：需要 rxshadow KPM（`ksud kpm load rxshadow.kpm`）+ Android NDK
  工具链（`aarch64-linux-android28-clang`）+ 已解锁研究机（OnePlus/GKI 6.6）
- **许可**：GPL-2.0（与 rxshadow 一致）

## 快速开始

**host 验证（本机 CI，不需要手机）**：

```sh
make test   # host 5 场景验证（clean/cave/brk/split/diff），无需手机
```

**真机（OnePlus / GKI 6.6 / ksud）**：

```sh
NDK=/path/to/ndk-r27c ./build-lab-ace.sh      # 产物 bin/arm64/
adb push bin/arm64 /data/local/tmp/lab-ace/
adb push ace_run.sh /data/local/tmp/lab-ace/
adb shell su -c 'chmod +x /data/local/tmp/lab-ace/*'

# 干净基线
adb shell su -c 'cd /data/local/tmp/lab-ace && sh ace_run.sh'
# 挂 hook 后检测（attach+map+cave）
adb shell su -c 'cd /data/local/tmp/lab-ace && RX_HOOK=1 sh ace_run.sh'
# 追加写语义审计（会销毁 hook，务必最后跑）
adb shell su -c 'cd /data/local/tmp/lab-ace && RX_HOOK=1 RX_SELFMOD=1 sh ace_run.sh'
```

**Android App（无 root 版）**：`android/` 目录是完整 Android Studio 工程，
victim 与检测器都是 App 的同 UID 子进程，无需 root。构建：

```sh
cd android
NDK=/path/to/ndk-r27c ./gradlew buildNative && ./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

能力边界与使用见 `android/README.md`。

## 检测矩阵（det → 针对的检测方法/机制）

### 执行语义信道（打 hook 的行为本身）

| 检测器 | 信道 | 针对的机制 | 用户态信号 | 真机预期 |
|---|---|---|---|---|
| `det_selfcrc` | L1 自完整性 | Cave 常驻后**进程自己读代码**看到 shadow（页内 `B`/洞内字节） | 自读 CRC 相对启动基线漂移，GUP CRC 仍等于基线 | 挂后 `hooked` |
| `det_elfhash` | L2 ELF 完整性 | 传统 Inline Hook 改字节（看雪 277402 Hunter 主力检测）；对双视图=GUP 隐藏验证器 | 磁盘文件段 checksum vs GUP 读内存段 checksum | 传统 hook 必杀；双视图挂后 `clean`（GUP 隐藏生效） |
| `det_crossread` | L2 跨进程读 | `follow_page_pte` 隐藏窗：GUP 读返回 original `page*` | 独立 GUP 读 ≠ victim 自报自读 CRC；`--tries 64` 高频采样抓跷跷板/NPT 影子页暴露窗 | 挂后 `hooked`（最直接证据） |
| `det_pagemap` | L3 页表/PFN | 双 PFN 本质：shadow 是第二张物理页；fork 隐藏=子不继承 shadow | 父/子进程同一 VA 的 pagemap PFN 分歧；采样稳定性 | fork 后父/子 PFN 不同 |
| `det_timing` | L4 时序 | BRK ≈401ns/op vs Cave ≈4.5ns/op vs 干净 ≈2-5ns（290304 评论：扫描耗时/时间差）；VMEXIT 开销（NPT/EPT 帖） | H_A/H_B 延迟比 + getpid syscall 延迟 + `lat_read_a_ns` 读页耗时 | 挂后 ratio 拉高 |
| `det_faultcount` | L4 记账 | 异常驱动 hook 的 fault/stime 记账（292226"最危险检测线"）：每次命中进内核 → minflt 暴涨、stime 上升；读窗翻页"读 fault 收费"（290304）；信号泄漏（292066）；**Cave 洞区 PC**（292354 canonical-PC 映射缺陷） | minflt_delta/轮、stime 占比、SIGTRAP/SEGV/ILL 计数、uctx_pc_cave（PC 落 H_A 页尾洞区 = Cave 插桩执行）、pingpong read+call 最优耗时 | 挂后 minflt/stime 暴涨；cave 后洞区 PC 命中 |
| `det_perf` | L4 perf 记账 | perf 性能侧信道（290718/292066 评论）：BRK/跷跷板命中 = 每次 1+ fault；跨核 TLB shootdown IPI 是唯一跨进程可见信道（292226） | perf_event_open 统计 victim page-faults/cycles 速率；/proc/vmstat pgfault 差分；/proc/interrupts TLB IPI 差分；smaps RSS/Shared 记账 | BRK/跷跷板命中；Cave 稳态不命中（设计目标） |
| `det_diff` | L2 差分对照 | GUP 隐藏窗骗"外部读"骗不了"进程自读"（290718 自读 CRC 检测化）：两个同构 victim 构成对照实验 | A 自读 ≠ B 自读 且 GUP 一致 → 差分锁定被挂侧 | 双 victim 场景命中（`--state2`） |
| `det_selfmod` | L6 写语义 | 写 GUP 停到 original → retire（释放 shadow） | 向 H_A 写 MOV W0,#7 后调用值应变 7、双视图收敛；不变 = hook 存活 | 写后收敛=设计内；不收敛=异常 |

### 执行面信道（打 hook 的内存形态，看雪 290718）

| 检测器 | 信道 | 针对的机制 | 用户态信号 | 真机预期 |
|---|---|---|---|---|
| `det_trampoline` | L7 可执行内存审计 | 传统 hook 的跳板 + DBI 代码必须存在于"匿名+可执行"内存（290718"必死于 Trampoline 扫描"） | 遍历 maps 找非白名单匿名可执行页，与 `anon_exec_base` 基线对比（rxshadow shadow 页在内核，用户态看不到 → 不命中） | 传统 hook/Frida 命中；双视图不命中 |
| `det_callstack` | L7 执行流审计 | 指针漫游/栈回溯（290718）：hook 的执行面（shadow/跳板）在匿名可执行区 | ptrace 读各线程 PC/LR，沿 FP 链回溯 ≤48 帧，返回地址指向**白名单外**匿名可执行/未登记区（H 区自带命中已排除；PAC/TBI 高位已剥离） | trampoline/DBI/幽灵代码命中；双视图执行面复用原 VA → 天然不命中 |
| `det_hwbp` | L7 硬件断点审计 | ptrace 五步杀（290718）：HWBP 占调试寄存器 + 超限设置应 -ENOSPC | 读 ARM64 NT_ARM_HW_BREAK/WATCH 寄存器 enabled 位；试设第 17 个断点 | HWBP hook 命中 |
| `det_procscan` | L7 进程审计 | Hunter（277402）：沙箱/注入器多起进程 + TracerPid + 注入路径指纹 | /proc 同 UID 进程、TracerPid、maps 里 frida/zygisk/xposed 关键词 | 注入器命中 |
| `det_linkmap` | L7 地址空间语义 | "能执行却不在 link_map"=幽灵代码（290871/292066）；匿名可执行映射必须可归属 | 遍历 victim maps 找不可归属的匿名可执行段（白名单=H 区页）；自身 dl_iterate_phdr 自检 | 幽灵内存/trampoline 命中 |

### 内核态痕迹信道

| 检测器 | 信道 | 针对的机制 | 用户态信号 | 真机预期 |
|---|---|---|---|---|
| `det_kallsyms` | L5 符号布局 | KPM 模块本体 | /proc/modules、/sys/module/rxshadow、符号越界 | 加载即 `hooked` |
| `det_kcore` | L5 内核内存 | syscall 层 inline hook；BRK 模式文本 patch | /proc/kcore 读 sys_call_table 校验条目域；挂钩目标前导 BRK 扫描 | 备选信道 |
| `det_dmesg` | L5 内核日志 | rxshadow `logkd` 留痕、ksud/kpm 加载日志 | dmesg 强特征词（rxshadow/kpm/ksud/kernelpatch） | 加载后命中 |
| `det_sysfs` | L5 系统指纹 | KPM 管理面静态痕迹 | /sys/module、/data/adb/ksud、cmdline、KernelPatch 接口 | 有 ksud 即 suspect |

`ace` 内置 **F0 功能信道**：victim 热路径调用值偏离预期（42→99）是最强功能
证据，不依赖任何检测器。

## 判决语义

- 每信道输出统一契约：`{"det","channel","verdict","score","hits","note"}`，
  verdict ∈ clean(0)/suspect(1)/hooked(2)/error(3)，score = 0-100 hook 置信度。
- ace 加权融合（error/skip 信道权重不参与）：F0:25 selfcrc:20 elfhash:15
  crossread:20 diff:12 pagemap:15 timing:10 faultcount:10 perf:8 selfmod:10
  procscan:5 trampoline:12 callstack:15 hwbp:5 linkmap:5 kallsyms/kcore/dmesg/sysfs:2 各
- 总判定：<15 clean，15-49 suspect，≥50 hooked；退出码 0/1/2/3 一致。
- **stealth index** = 对 hook 无感（报 clean）的信道数 —— 即 rxshadow 侧
  的"存活信道"，是双视图方案在当前实现下的无痕边界。
- `--det selfcrc,crossread` 只跑指定信道；`--weight timing:20` 改权重；
  `--with-selfmod` 追加写审计（会销毁 hook）；`--state2 <path>` 自动启用
  det_diff 差分对照（需第二个 labtarget 实例）。

## 实验对象 labtarget

```
labtarget [--list] [--verify <va> <expect> <iters>] [--interval <ms>] [--state <p>]
```

- **H 区**：匿名可执行页 H_A（可挂，42→99 模式）/ H_B（控制，永不挂）
- **S 区**：`aligned(4096)` 静态函数 alpha/beta/gamma（真实代码表面，
  自检/基线/时序用；rxshadow `map` 只查 4K leaf present，file-backed 页
  理论可挂，真机未验证 —— 包络外路径留给后续）
- 双 worker 热路径：持续调用 H_A/H_B，统计 mis + 延迟 min/p50/p99
- 双视图 CRC：自读（shadow 视图）vs `process_vm_readv` 自 GUP（original 视图）
- flag 文件：`rxlab_ace_{stop,dofork,domprotect,doverify}`（目录与状态文件同）
- 状态协议：`pid va_a va_b va_alpha/beta/gamma expected_a call_a call_b
  tot_a mis_a crc_self0_a crc_self_a crc_gup_a crc_self_b pfn_a pfn_b
  lat_{a,b}_{min,p50,p99} lat_read_a_ns child_pid child_call_a
  child_crc_self_a hooked anon_exec_base_bytes
  minflt_delta majflt_delta sig_{trap,segv,ill} uctx_pc_{ok,anon}
  pingpong_ns stime_ns utime_ns mincore_ok mincore_cave
  mmap_probe_{fail,n}`
- 记账自观测（292226 时序侧信道）：主循环每轮采样 /proc/self/stat 的
  minflt 增量；每 5 轮自投递 SIGUSR1 检查 ucontext PC 是否落在 H 区
  （Cave canonical-PC 映射缺陷检测）；pingpong 线程交替"读代码页+执行"
  制造 PTE 跷跷板测最优耗时（seesaw 模式 read 触发异常翻页 → 变慢）
- 地址空间语义自测（290718/292066）：mincore 盲探 H_A 全页 + 页尾 cave
  洞区驻留；H_A 附近 ±32MB 随机 mmap 探测幽灵占位（MAP_FIXED_NOREPLACE
  失败率）——二者都必须在 victim 进程内做（mincore/mmap 作用于自身
  地址空间），状态文件上报由 det_* 消费

## host 模拟（CI 验证阶梯第 1 级）

`host/sim_hook.{c,sh}` 在 x86_64 上模拟 rxshadow 的用户态症状：

| 模式 | 模拟内容 | host 上应命中 |
|---|---|---|
| clean | 无修改 | 全 clean |
| cave | 入口 `jmp rel32` → 页尾洞 `mov eax,99; ret` | F0 + selfcrc + timing + faultcount |
| brk | 首字节 `int3`（真 SIGTRAP + longjmp 逃生） | F0（调用异常） |
| split | 状态文件自报分裂视图 | crossread/selfcrc |
| diff | 双 sim_hook（A clean vs B split）+ `--state2` | det_diff 差分锁定 |

**验证阶梯**：host 4/4 全过 ≠ 真机有效。L2（GUP 跨进程读）、L3（PFN）、
L7 callstack/hwbp（ptrace）在容器里受 ptrace/pagemap 限制会诚实降级为
error —— 真机 root 下才有意义。真实 labtarget 干净基线在 host 上
score=0，7 信道全绿无误报。

## 检测方法来源（看雪帖文 → 本套件信道映射）

| 帖文 | 提供的检测思路 | 落入的信道 |
|---|---|---|
| 292226 双视图(上) 十三、时序侧信道 | min-of-N 计时、**stime 记账**（最危险线）、代码页顺序读诱饵、跨核 IPI | det_timing / det_faultcount / labtarget 记账自观测 |
| 292261 双视图(下) 视图矩阵 | GUP 隐藏、pagemap PFN 跳变、**SOFT_DIRTY 一致性**、mprotect 规范化器泄漏、EL1 uaccess | det_crossread / det_pagemap(P4) / det_selfmod |
| 292354 Shadow Cave | Cave 时序侧信道（低 SNR 统计）、**ucontext PC canonical 映射**、观测者效应 | det_faultcount(uctx_pc_anon) / det_timing |
| 290718 无痕 Hook 感悟 | 栈回溯/指针漫游、Trampoline 扫描、ArtMethod 指针、ptrace 五步杀、Ghost Mem | det_callstack / det_trampoline / det_hwbp |
| 290304 shadow 内存 hook | CRC 完整性、**扫描耗时/时间差**（评论区） | det_selfcrc / det_faultcount(pingpong) |
| 290871 零字节修改 hook | pagemap PFN 对比、smaps RSS、dl_iterate_phdr、UXN 位审计 | det_pagemap / det_elfhash |
| 292066 框架避坑指北 | VMA-less 一致性矛盾、mincore 盲探、fork 继承缺失、信号泄漏、页权限探测 | det_callstack(ghost) / det_procscan |
| 292175 wxshadow 复刻心得 | GUP/进程/ptrace/VMA walk 隐蔽面 | det_crossread |
| 277402 Hunter 环境检测 | **ELF checksum**、匿名内存 ELF magic、多进程检测、ISO 线程、fd 反查 | det_elfhash / det_trampoline / det_procscan |
| 273759/281889 设备指纹 | ArtMethod 入口、指令对比法、字段多路交叉、GKI 侧信道统计 | det_elfhash / det_timing / det_kallsyms |
| 291859 NPT | 影子页暴露窗压缩、每核独立 NPT、RDTSC 补偿（反检测） | det_crossread(--tries) / det_timing |
| 291981 VT EPT | EPT HIDE INT3、ARK 读页触发事件、BE 检测 VT | det_crossread / det_pagemap |
| 291266 Frida 无痕 | Frida 特征持久化、默认 hook 面指纹、zygote 污染 | det_procscan / det_elfhash |
| 286746/288477 游戏保护 | local lib 双哈希、libc 段连续性、自实现 libc 反 hook | det_elfhash / det_trampoline |
| 277637/273838 风控 | 边界值采集、多路交叉校验、查杀分离 | ace 融合哲学 |

## 思维发散：还能有哪些检测点（未实现，按可实现性标注）

从三组帖文（290718/292066/292175 内核无痕 hook 系、292226/292261/292354
双视图工程系、291859/291981 NPT/EPT 系）继续发散：

**用户态可直接实现（增补到套件的最优先候选）**
1. **read+call 乒乓放大统计化**：单线程乒乓已实现（pingpong_ns），可升级为
   "线程 A 持续调用 + 线程 B 持续读同一页"制造高频 PTE 切换 + TLB 刷新风暴，
   对延迟抖动分布建模（290871 8 节 22k/s panic 场景同型）。
2. **卸载窗口竞态**：unhook 后 I-cache 残留指令仍可执行数条（290871 8.2），
   快速循环调用可抓到"已卸载但仍在执行 ghost 代码"的窗口——在
   `ksud kpm control rxshadow unmap` 后立即打 H_A。
3. **/proc/pid/stat 线程级记账**：现有 stime 是进程级 getrusage；BRK 命中在
   具体线程，读 `/proc/self/task/<tid>/stat` 的 utime/stime 做线程粒度差分
   更锐利（vtime 记账下每次异常往返被精确计入）。
4. **PFN 反查（root）**：/proc/kpagecount + /proc/kpageflags 按 PFN 反查：
   被用户 PTE 引用但无对应 VMA/file mapping 的物理页 = 幽灵页；shadow
   backing 是内核匿名页却出现在用户地址空间。
5. **swap 换出换入语义**：file-backed 代码页 swap 换出再读回，内容应仍是
   original；shadow 是匿名页，换出/换入行为、smaps Private/Shared 计数
   与 original 不同——对 .text 页挂钩的通用验证器。
6. **信号观测泛化**：SIGTRAP/SIGSEGV/SIGILL handler 之外，统计
   `waitid(WNOWAIT)`/`ptrace(PTRACE_GETSIGINFO)` 看到的信号流（292066
   L1496 SIGTRAP 泄漏的泛化）。

**理论可行、工程困难（文档化，弱特征仅作风险评分）**
7. **Cave 时序侧信道低 SNR 统计**（292354 五）：Δbranch/重定位指令/观测
   store/dmb 改变缓存占用与流水线压力——需长窗口 + 线程亲和性 + 负载
   控制才能看到分布变化；录屏/温控降频/GC 噪声同量级，产品化必误伤。
8. **FFT 周期分析**：NPT 5ms 复位线程、rescue/漂移收编会在 stime/IPI 留
   周期分量（291859 9.1）；对 stime/IPI 时间序列做 FFT 提取周期。
9. **缓存属性侧信道**：ghost/shadow PTE 属性填错（uncached/shareability）
   有明显慢速特征——290871 4.3 特意继承邻居页模板反证 cache 行为可观测；
   ARM64 用 DC CVAU + 计时做 flush+reload 区分 shadow/original 物理页。
10. **记账差异**：cgroup memory.usage 与 smaps 汇总不一致 = 物理占用与
    记账不符（内核匿名页不计 RSS）；BTI landing pad 校验（GP 页跳入非
    landing pad 触发 BTITrap）；MTE 标签探测 shadow backing 野指针。

**需内核/EL2 权限（超出"用户态检测"范围，留给反作弊驱动）**
11. **kprobe do_page_fault/do_mem_abort** 统计特定 VA 异常频率与 ESR 类型
    分布（290871 L86 承认 PTE.UXN 可见的同一视角）；PTE↔VMA 权限一致性
    矩阵扫描；内核驱动遍历页表审计 PTE.UXN。
12. **跨核 IPI 停顿观测**（292226 L445）：flush_tlb_mm/kick_all_cpus_sync
    是全核旁路事件——需 perf uncore/中断向量采样，用户态只能看
    /proc/interrupts 汇总计数（det_perf 已做差分版）。

**已被作者承认不可检测/需换威胁模型**
13. **rx 段尾部 padding 隐藏**（290718 评论）：linker 分配的额外字节内容
    任意，CRC 无法区分——作者声称无检测手段。
14. **云端行为基线（Vacnet 类）**：进程外 AI 统计模型捕捉宏观行为偏移，
    与进程内检测正交；「无痕」= 所有观察信道 hook 前后行为一致，按此
    定义无痕 hook 不存在，攻防活在"让对方付不起确认成本"的区间
    （292226 十三 无痕不可达论）。

## 已知限制（与 rxshadow README 的诚实边界一致）

1. **威胁模型**：victim 是自报诚实进程。检测的是"内核态 hook 对进程
   自我观察的污染"，不是用户态篡改（用户态篡改者会谎报状态文件）。
2. L1 自读漂移在 **Cave 语义重定义**下正是设计行为（README：进程对自己
   `.text` 做 CRC 会看到 hook）——所以单靠 L1 只能证明"自己读不到自己"，
   要靠 L2/L3 交叉确认双视图。
3. pagemap PFN 在 rxshadow 挂了 `pte_to_pagemap_entry` 后会**谎报回
   original**——L3 单读看不出，但"L1/L2 已分裂而 L3 仍报 original PFN"
   这个不一致本身就是伪装证据（ace 交叉）。
4. `det_selfmod` 会销毁 H_A 的 hook（写 retire 语义），务必最后跑。
5. L5 信道检测的是"KPM 加载痕迹"，不是页表级隐身；一个隐藏模块加载
   路径的 rootkit 可绕过 L5，但 L1-L4/L7 打的是执行语义本身。
6. **L7 信道对 labtarget 的自带 H 区会命中**：`det_trampoline` 用
   `anon_exec_base` 基线抵消 labtarget 自带的 2 块匿名可执行页；
   `det_callstack` 对"正在调用 H_A 的工作线程"会报执行流在匿名区——
   这是**真实观测**（lab 场景的 H 区本来就在匿名可执行页里），
   解读时注意区分"实验对象自带"与"hook 引入"。
7. 真机阈值（timing ratio、getpid 基线）需按设备校准一次再固化。
8. `det_callstack`/`det_hwbp` 的 ptrace attach 是侵入操作，会短暂置位
   victim 的 TracerPid（`det_procscan` 排在它们之前跑即不受影响）。
9. **ARM64 PAC 帧处理**（真机修复）：`paciasp` 会把 LR 签名后存栈，
   `[FP+8]` 读出的返回地址高 16 位是 PAC 码/tag → 原实现误判为 ghost
   （干净基线误报 hooked 92）。`det_callstack` 已改为 `classify_strip`：
   判 ghost 时先剥高 16 位再重分类——PAC 垃圾帧落回真实 .text 不算命中，
   真 VMA-less 幽灵地址（低 48 位内）不受影响。`det_callstack --selftest`
   可回归验证剥离逻辑（host 已纳入 make test）。
10. **H 区白名单**（真机修复）：labtarget 的 worker 线程本来就调用 H_A
    （匿名可执行页），外部 ptrace 采样必然命中 → 干净基线误报。
    `det_callstack` 从状态文件读 va_a/va_b/alpha/beta/gamma 构成白名单，
   白名单内命中计 `hwl_anon` 背景、不计分。注意语义：**双视图 hook 的
    执行面复用原 VA**（shadow 是同一 VA 的第二物理页），用户态 PC 永远
    落在 H_A 区间 → callstack 信道对 rxshadow 天然无信号；它检测的是
    trampoline/DBI/Frida 这类"新增可执行 VA"的 hook。
11. **Cave 洞区 PC 检测**：labtarget 自投递 SIGUSR1 改为 `pthread_kill`
    到 H_A worker 线程（主线程不执行 H_A 无意义）。正常 H_A 只有 8 字节
    （MOV W0,#42; RET），PC 只可能是 offset 0/4；PC 落在页尾洞区
    （offset ≥ 4096-64）= Cave 洞内插桩代码正在执行 —— `uctx_pc_cave`
    计数，det_faultcount 判 hooked 95。`uctx_pc_anon`（H_A 常规偏移）
    是 worker 自带调用背景，不计命中。
