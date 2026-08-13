package com.rxshadow.ace

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * ACE 引擎（无 root 版）
 *
 * 架构：victim（labtarget）与全部检测器都是本 App fork 出的子进程，
 * 与 App 同 UID —— Android 允许同 UID 进程互相读 /proc/<pid>/maps、
 * process_vm_readv / ptrace attach（yama ptrace_scope=1 同 uid 放行，
 * SELinux 同域放行），因此**不需要 root**。
 *
 * 状态文件在 app 私有目录（filesDir），无权限问题。
 * L5 内核信道（kcore/kallsyms/dmesg/sysfs）无 root 时由 det 自行降级为 error。
 */
class AceEngine(private val ctx: Context) {

    companion object {
        private const val BIN_DIR = "bin"
        private const val STATE = "rxlab_ace.state"
        private const val STATE2 = "rxlab_ace2.state"
        private const val LOG = "labtarget.log"

        // 无 root 时可用的检测器（L5 四件套 + callstack/hwbp 的 ptrace 依赖另算）
        val DETECTORS: List<Pair<String, String>> = listOf(
            "det_selfcrc" to "L1 自完整性",
            "det_elfhash" to "L2 ELF 完整性",
            "det_crossread" to "L2 双视图跨读",
            "det_pagemap" to "L3 页表审计",
            "det_timing" to "L4 时序",
            "det_faultcount" to "L4 记账",
            "det_perf" to "L4 perf",
            "det_selfmod" to "L6 写语义",
            "det_procscan" to "L7 进程审计",
            "det_trampoline" to "L7 可执行内存",
            "det_callstack" to "L7 执行流",
            "det_hwbp" to "L7 硬件断点",
            "det_linkmap" to "L7 地址空间",
        )
    }

    private val binDir: File get() = File(ctx.filesDir, BIN_DIR)
    private val stateFile: File get() = File(ctx.filesDir, STATE)
    private val state2File: File get() = File(ctx.filesDir, STATE2)

    private var victimProcess: Process? = null
    var lastError: String? = null
        private set

    /** 解压 assets/bin → filesDir/bin 并 chmod 755（首次启动） */
    fun ensureBinaries() {
        val dir = binDir
        if (!dir.exists()) dir.mkdirs()
        ctx.assets.list("bin")?.forEach { name ->
            val out = File(dir, name)
            if (!out.exists() || out.length() == 0L) {
                ctx.assets.open("bin/$name").use { input ->
                    out.outputStream().use { input.copyTo(it) }
                }
                out.setExecutable(true, false)
                out.setReadable(true, false)
            }
        }
    }

    val binariesReady: Boolean
        get() = File(binDir, "labtarget").exists() && File(binDir, "ace").exists()

    /** 启动 victim（labtarget 子进程） */
    fun startVictim(): Boolean {
        stopVictim()
        stateFile.delete()
        val pb = ProcessBuilder(
            File(binDir, "labtarget").absolutePath,
            "--state", stateFile.absolutePath,
            "--interval", "700",
        ).redirectErrorStream(true).redirectOutput(File(ctx.filesDir, LOG))
        return try {
            victimProcess = pb.start()
            true
        } catch (e: Exception) {
            lastError = "启动 victim 失败: ${e.message}"
            false
        }
    }

    fun stopVictim() {
        victimProcess?.let { p ->
            runCatching { p.destroy() }
            runCatching { p.waitFor(2, TimeUnit.SECONDS) }
            runCatching { p.destroyForcibly() }
        }
        victimProcess = null
    }

    fun victimAlive(): Boolean = victimProcess?.isAlive == true

    /** 读 victim 状态文件（轮询用） */
    fun readState(): VictimState? {
        val f = stateFile
        if (!f.exists()) return null
        return runCatching { VictimState.parse(f.readText()) }.getOrNull()
    }

    /** 读原始状态文本（日志页） */
    fun readStateRaw(): String? = stateFile.takeIf { it.exists() }?.readText()

    /** 读 labtarget 日志尾部 */
    fun readVictimLog(maxBytes: Int = 8000): String {
        val f = File(ctx.filesDir, LOG)
        if (!f.exists()) return ""
        val text = f.readText()
        return text.takeLast(maxBytes)
    }

    /** 执行一次检测：全部信道（ace 聚合） + 可选差分（--state2） */
    fun runAce(diffMode: Boolean = false): Pair<AceAggregate, List<DetResult>>? {
        val state = readState() ?: run {
            lastError = "victim 未运行或无状态文件，先启动实验"
            return null
        }
        val cmd = mutableListOf(
            File(binDir, "ace").absolutePath,
            "--pid", state.pid.toString(),
            "--state", stateFile.absolutePath,
            "--json",
        )
        if (diffMode) {
            cmd += listOf("--state2", state2File.absolutePath)
        }
        val out = exec(cmd) ?: return null
        return parseAceOutput(out)
    }

    /** 执行单个检测器（信道明细刷新） */
    fun runDet(name: String): DetResult? {
        val state = readState() ?: return null
        val cmd = listOf(
            File(binDir, name).absolutePath,
            "--pid", state.pid.toString(),
            "--state", stateFile.absolutePath,
            "--json",
        )
        val out = exec(cmd) ?: return null
        return parseDetLine(out.trim().lineSequence().firstOrNull { it.startsWith("{") })
    }

    /** 启动第二个 victim（差分对照） */
    fun startVictim2(): Boolean {
        state2File.delete()
        val pb = ProcessBuilder(
            File(binDir, "labtarget").absolutePath,
            "--state", state2File.absolutePath,
            "--interval", "700",
        ).redirectErrorStream(true).redirectOutput(File(ctx.filesDir, "labtarget2.log"))
        return try {
            pb.start()
            true
        } catch (e: Exception) {
            lastError = "启动 victim2 失败: ${e.message}"
            false
        }
    }

    // ---------------- 内部 ----------------

    /** 执行子进程（同 uid，无需 su），返回 stdout 全文 */
    private fun exec(cmd: List<String>, timeoutSec: Long = 30): String? {
        return try {
            val p = ProcessBuilder(cmd)
                .redirectErrorStream(true)
                .start()
            val out = p.inputStream.bufferedReader().readText()
            if (!p.waitFor(timeoutSec, TimeUnit.SECONDS)) {
                p.destroyForcibly()
                lastError = "检测器超时: ${cmd.firstOrNull()}"
                return null
            }
            out
        } catch (e: Exception) {
            lastError = "执行失败 ${cmd.firstOrNull()}: ${e.message}"
            null
        }
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

    /** 解析 ace 输出：逐行找 det JSON 与 aggregate JSON */
    private fun parseAceOutput(out: String): Pair<AceAggregate, List<DetResult>>? {
        var agg: AceAggregate? = null
        val dets = mutableListOf<DetResult>()
        out.lineSequence().forEach { line ->
            if (!line.startsWith("{")) return@forEach
            try {
                val o = JSONObject(line)
                when (o.optString("det")) {
                    "ace" -> {
                        agg = AceAggregate(
                            verdict = Verdict.from(o.optString("verdict")),
                            score = o.optInt("score", 0),
                            channelsLive = o.optInt("channels_live", 0),
                            channelsHooked = o.optInt("channels_hooked", 0),
                            channelsClean = o.optInt("channels_clean", 0),
                            note = o.optString("note"),
                        )
                    }
                    else -> parseDetLine(line)?.let { dets += it }
                }
            } catch (_: Exception) {
            }
        }
        val a = agg ?: run {
            lastError = "ace 输出无聚合结果"
            return null
        }
        return a to dets
    }
}
