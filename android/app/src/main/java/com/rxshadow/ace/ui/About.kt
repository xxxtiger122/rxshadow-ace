package com.rxshadow.ace.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun About() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("rxshadow-ace", style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold, color = C_PRIMARY)
        Text("v1.0 · GPL-2.0 · 无 root", style = MaterialTheme.typography.bodySmall,
            color = C_TEXT_DIM)

        Card(shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = C_SURFACE)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("这是什么", fontWeight = FontWeight.Bold)
                Text(
                    "「一个 VA 两份物理页」的 ARM64 内核态双视图 hook（rxshadow）的对抗面：\n" +
                        "整合实验对象 + 18 信道 ACE 检测套件。本 App 是**无 root 版** —— " +
                        "victim 与全部检测器都是本 App 的同 UID 子进程，借助 Android 同 UID " +
                        "进程可互读 /proc/maps、process_vm_readv、ptrace 的机制，不需要任何提权。",
                    fontSize = 13.sp, color = C_TEXT_DIM,
                )
            }
        }

        Card(shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = C_SURFACE)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("无 root 能力边界", fontWeight = FontWeight.Bold)
                Text(
                    "可用：自完整性 / ELF 完整性 / 双视图跨读 / 时序 / 记账(fault+stime) / " +
                        "写语义 / 可执行内存审计 / 地址空间语义 / 进程审计 / 差分对照\n" +
                        "降级：pagemap（无 PFN，仅 soft-dirty）/ perf（仅自身）/ " +
                        "callstack、hwbp（同 uid attach，受 SELinux 影响）\n" +
                        "不可用：kcore / kallsyms 地址 / dmesg / sysfs KPM 指纹（需 root，诚实报 error）",
                    fontSize = 12.sp, color = C_TEXT_DIM,
                )
            }
        }

        Card(shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = C_SURFACE)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("使用流程", fontWeight = FontWeight.Bold)
                Text(
                    "1. 启动实验 → 后台拉起 labtarget（匿名可执行页 H_A/H_B + 热路径 worker）\n" +
                        "2. 全信道检测 → 18 信道扫描，给出总判定 + 每信道明细\n" +
                        "3. 差分对照 → 起第二个 victim，双实例差分锁定被挂侧\n" +
                        "4. 信道页展开看 hits/note，日志页看原始状态流",
                    fontSize = 12.sp, color = C_TEXT_DIM, fontFamily = FontFamily.Monospace,
                )
            }
        }

        Card(shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = C_SURFACE)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("检测思路来源", fontWeight = FontWeight.Bold)
                Text(
                    "看雪 2026 hook 系列：290304 / 290718 / 290871 / 292066 / 292175 / " +
                        "292226 / 292261 / 292354 / 291859 / 291981 / 277402 等\n" +
                        "关联：github.com/xxxtiger122/rxshadow（内核态 KPM，本套件的被挂对象）",
                    fontSize = 12.sp, color = C_TEXT_DIM,
                )
            }
        }

        Text(
            "仅用于你自己的研究设备与授权目标。",
            fontSize = 11.sp, color = C_TEXT_DIM,
        )
    }
}
