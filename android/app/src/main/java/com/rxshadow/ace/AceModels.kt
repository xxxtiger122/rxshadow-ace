package com.rxshadow.ace

/** 统一判决契约（对应 ace_common.h） */
enum class Verdict(val key: String) {
    CLEAN("clean"),
    SUSPECT("suspect"),
    HOOKED("hooked"),
    ERROR("error");

    companion object {
        fun from(s: String?): Verdict = when (s) {
            "clean" -> CLEAN
            "suspect" -> SUSPECT
            "hooked" -> HOOKED
            else -> ERROR
        }
    }
}

/** 单个信道检测结果（对应 det_* --json 输出） */
data class DetResult(
    val det: String,
    val channel: String,
    val verdict: Verdict,
    val score: Int,
    val hits: String?,
    val note: String?,
) {
    /** 信道短名（去掉 L1- 等前缀） */
    val shortChannel: String
        get() = channel.substringAfter('-', channel)
}

/** ace 聚合结果（对应 ace --json 的 aggregate 行） */
data class AceAggregate(
    val verdict: Verdict,
    val score: Int,
    val channelsLive: Int,
    val channelsHooked: Int,
    val channelsClean: Int,
    val note: String,
)

/** victim 状态文件（labtarget 状态协议） */
data class VictimState(
    val pid: Int = -1,
    val vaA: String = "",
    val callA: Long = -1,
    val expectedA: Long = 42,
    val misA: Long = 0,
    val totA: Long = 0,
    val crcSelfA: String = "",
    val crcGupA: String = "",
    val pfnA: String = "",
    val hooked: Boolean = false,
    val minfltDelta: Long = 0,
    val stimeRatio: Double = 0.0,
    val uctxPcCave: Long = 0,
    val pingpongNs: Long = 0,
    val latAP50: Long = 0,
    val latBP50: Long = 0,
    val childPid: Int = -1,
    val childCallA: Long = -1,
) {
    val latencyRatio: Double
        get() = if (latBP50 > 0) latAP50.toDouble() / latBP50 else 0.0

    companion object {
        fun parse(text: String): VictimState {
            val m = hashMapOf<String, String>()
            text.lineSequence().forEach { line ->
                val idx = line.indexOf('=')
                if (idx > 0) m[line.substring(0, idx).trim()] = line.substring(idx + 1).trim()
            }
            fun l(k: String, d: Long = -1) = m[k]?.toLongOrNull() ?: d
            return VictimState(
                pid = l("pid", -1).toInt(),
                vaA = m["va_a"] ?: "",
                callA = l("call_a"),
                expectedA = l("expected_a", 42),
                misA = l("mis_a", 0),
                totA = l("tot_a", 0),
                crcSelfA = m["crc_self_a"] ?: "",
                crcGupA = m["crc_gup_a"] ?: "",
                pfnA = m["pfn_a"] ?: "",
                hooked = (m["hooked"] ?: "0") == "1",
                minfltDelta = l("minflt_delta", 0),
                stimeRatio = (m["stime_ns"]?.toDoubleOrNull() ?: 0.0) /
                    ((m["stime_ns"]?.toDoubleOrNull() ?: 0.0) +
                        (m["utime_ns"]?.toDoubleOrNull() ?: 0.0) + 1.0),
                uctxPcCave = l("uctx_pc_cave", 0),
                pingpongNs = l("pingpong_ns", 0),
                latAP50 = l("lat_a_p50", 0),
                latBP50 = l("lat_b_p50", 0),
                childPid = l("child_pid", -1).toInt(),
                childCallA = l("child_call_a", -1),
            )
        }
    }
}
