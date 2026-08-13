package com.rxshadow.ace

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * JNI 绑定：App 进程内运行 lab-ace（无 root、无 exec、无 fork）
 *
 * Android untrusted_app 域禁止 exec app 私有 ELF（SELinux），因此
 * lab-ace 全部 C 逻辑编译进 libace.so，由本层直接调用：
 *   - victim = App 进程内（lab_target_start/stop，JNI 线程跑观测循环）
 *   - 检测 = 进程内调 det_*_run（同进程，GUP 自读 / maps 自读全可用）
 *   - 聚合 = Kotlin 侧按 ace.c 权重表融合（App 内无法复用 ace 的 fork/exec）
 */
object AceNative {
    init {
        System.loadLibrary("ace")
    }

    external fun startVictim(state: String, interval: Int): Int
    external fun stopVictim()
    external fun runDet(state: String, detName: String): String
    external fun runDiff(state: String, state2: String): String
}

class AceEngine(private val ctx: Context) {

    companion object {
        private const val STATE = "rxlab_ace.state"
        private const val STATE2 = "rxlab_ace2.state"

        // 全信道（selfmod 单独按钮，会改写 H_A 字节）
        val DETECTORS: List<Pair<String, String>> = listOf(
            "det_selfcrc" to "L1 自完整性",
            "det_elfhash" to "L2 ELF 完整性",
            "det_crossread" to "L2 双视图跨读",
            "det_pagemap" to "L3 页表审计",
            "det_timing" to "L4 时序",
            "det_faultcount" to "L4 记账",
            "det_perf" to "L4 perf",
            "det_procscan" to "L7 进程审计",
            "det_trampoline" to "L7 可执行内存",
            "det_callstack" to "L7 执行流",
            "det_hwbp" to "L7 硬件断点",
            "det_linkmap" to "L7 地址空间",
            "det_kallsyms" to "L5 符号布局",
            "det_kcore" to "L5 内核内存",
            "det_dmesg" to "L5 内核日志",
            "det_sysfs" to "L5 系统指纹",
        )

        // 权重表（与 ace.c g_dets 完全一致；error/skip 权重不参与）
        private val WEIGHTS = mapOf(
            "f0" to 25,
            "det_selfcrc" to 20, "det_elfhash" to 15, "det_crossread" to 20,
            "det_pagemap" to 15, "det_timing" to 10, "det_faultcount" to 10,
            "det_perf" to 8, "det_procscan" to 5, "det_trampoline" to 12,
            "det_callstack" to 15, "det_hwbp" to 5, "det_linkmap" to 5,
            "det_kallsyms" to 2, "det_kcore" to 2, "det_dmesg" to 2,
            "det_sysfs" to 2,
        )
    }

    private val stateFile: File get() = File(ctx.filesDir, STATE)
    private val state2File: File get() = File(ctx.filesDir, STATE2)
    var lastError: String? = null
        private set

    private var started = false

    val binariesReady: Boolean get() = true // JNI .so 由 APK 自带

    /** 启动 victim（App 进程内，JNI 观测线程写状态文件） */
    fun startVictim(): Boolean {
        stopVictim()
        stateFile.delete()
        return try {
            val rc = AceNative.startVictim(stateFile.absolutePath, 700)
            if (rc != 0) {
                lastError = "victim 初始化失败 rc=$rc"
                false
            } else {
                started = true
                true
            }
        } catch (e: Throwable) {
            lastError = "启动 victim 失败: ${e.message}"
            false
        }
    }

    fun stopVictim() {
        runCatching { AceNative.stopVictim() }
        started = false
    }

    fun victimAlive(): Boolean = started

    /** 读 victim 状态文件（轮询用） */
    fun readState(): VictimState? {
        val f = stateFile
        if (!f.exists()) return null
        return runCatching { VictimState.parse(f.readText()) }.getOrNull()
    }

    fun readStateRaw(): String? = stateFile.takeIf { it.exists() }?.readText()

    fun readVictimLog(maxBytes: Int = 8000): String {
        // JNI 模式无独立日志文件；返回状态文件内容作近似
        return readStateRaw()?.takeLast(maxBytes) ?: ""
    }

    /** 执行一次检测：F0 + 全信道（JNI 逐信道）+ 聚合；diff 模式追加差分 */
    fun runAce(diffMode: Boolean = false): Pair<AceAggregate, List<DetResult>>? {
        val state = readState() ?: run {
            lastError = "victim 未启动或无状态文件，先启动实验"
            return null
        }
        val results = mutableListOf<DetResult>()
        // F0 功能信道（与 ace.c f0_run 一致）
        results += f0Run(state)
        // 逐信道 JNI 检测
        DETECTORS.forEach { (name, _) ->
            runCatching {
                val json = AceNative.runDet(stateFile.absolutePath, name)
                parseDetLine(json.trim().lineSequence().firstOrNull { it.startsWith("{") })
            }.getOrNull()?.let { results += it }
        }
        // diff 模式：差分对照
        if (diffMode && state2File.exists()) {
            runCatching {
                val json = AceNative.runDiff(stateFile.absolutePath, state2File.absolutePath)
                parseDetLine(json.trim().lineSequence().firstOrNull { it.startsWith("{") })
            }.getOrNull()?.let { results += it }
        }
        val agg = aggregate(results)
        return agg to results
    }

    /** 单信道检测（信道页刷新用） */
    fun runDet(name: String): DetResult? {
        val state = readState() ?: return null
        return runCatching {
            val json = AceNative.runDet(stateFile.absolutePath, name)
            parseDetLine(json.trim().lineSequence().firstOrNull { it.startsWith("{") })
        }.getOrNull()
    }

    /** 启动第二个 victim（差分对照，App 进程内双实例） */
    fun startVictim2(): Boolean {
        state2File.delete()
        // 库当前为单实例；简化：第二个实例用状态文件拷贝占位，真实差分
        // 需要 libace 支持双实例 —— v1 在 JNI 层跑第二个 lab_target_start
        // 前先 stop 主实例会丢状态；此处用主实例状态文件复制作对照基线
        return try {
            val src = stateFile
            if (src.exists()) {
                src.copyTo(state2File, overwrite = true)
                // 让观测线程再写一轮，保证两份状态一致可比
                Thread.sleep(800)
                true
            } else {
                lastError = "主 victim 未运行"
                false
            }
        } catch (e: Exception) {
            lastError = "启动 victim2 失败: ${e.message}"
            false
        }
    }

    // ---------------- F0 + 聚合（与 ace.c 一致） ----------------

    private fun f0Run(state: VictimState): DetResult {
        return when {
            state.misA > 0 -> DetResult("f0", "F0-functional", Verdict.HOOKED, 100, null,
                "功能信道：${state.misA}/${state.totA} 次调用返回值偏离预期 ${state.expectedA}（热路径被替换）")
            state.callA != state.expectedA -> DetResult("f0", "F0-functional", Verdict.HOOKED, 95, null,
                "功能信道：call_a=${state.callA} != expected=${state.expectedA}")
            state.hooked -> DetResult("f0", "F0-functional", Verdict.SUSPECT, 55, null,
                "功能信道：调用值正常但 victim 自报 hooked=1（双视图分裂）")
            else -> DetResult("f0", "F0-functional", Verdict.CLEAN, 0, null,
                "功能信道：call_a=${state.callA} == expected=${state.expectedA}，${state.totA} 次调用无偏离")
        }
    }

    private fun aggregate(results: List<DetResult>): AceAggregate {
        var totalW = 0.0
        var acc = 0.0
        var live = 0
        var hooked = 0
        var clean = 0
        results.forEach { r ->
            val w = WEIGHTS[r.det] ?: return@forEach
            if (r.verdict == Verdict.ERROR) return@forEach
            totalW += w
            acc += r.score * w
            live++
            when (r.verdict) {
                Verdict.HOOKED -> hooked++
                Verdict.CLEAN -> clean++
                else -> {}
            }
        }
        val score = if (totalW > 0) (acc / totalW).toInt() else 0
        val verdict = when {
            score >= 50 -> Verdict.HOOKED
            score >= 15 -> Verdict.SUSPECT
            else -> Verdict.CLEAN
        }
        return AceAggregate(verdict, score, live, hooked, clean,
            if (verdict == Verdict.CLEAN) "全部信道未见 hook 特征" else "存在可疑信道，展开信道页看明细")
    }

    private fun parseDetLine(line: String?): DetResult? {
        if (line == null || !line.startsWith("{")) return null
        return try {
            val o = JSONObject(line)
            DetResult(
                det = o.optString("det", "?"),
                channel = o.optString("channel", "?"),
                verdict = Verdict.from(o.optString("verdict")),
                score = o.optInt("score", 0),
                hits = o.optString("hits").takeIf { it.isNotEmpty() },
                note = o.optString("note").takeIf { it.isNotEmpty() },
            )
        } catch (e: Exception) {
            null
        }
    }
}
