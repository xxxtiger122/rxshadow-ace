package com.rxshadow.ace.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rxshadow.ace.AceAggregate
import com.rxshadow.ace.Verdict
import com.rxshadow.ace.VictimState

/** verdict → 颜色 */
fun verdictColor(v: Verdict): Color = when (v) {
    Verdict.CLEAN -> C_CLEAN
    Verdict.SUSPECT -> C_SUSPECT
    Verdict.HOOKED -> C_HOOKED
    Verdict.ERROR -> C_TEXT_DIM
}

fun verdictLabel(v: Verdict): String = when (v) {
    Verdict.CLEAN -> "干净"
    Verdict.SUSPECT -> "可疑"
    Verdict.HOOKED -> "已挂钩"
    Verdict.ERROR -> "不可用"
}

fun verdictEn(v: Verdict): String = when (v) {
    Verdict.CLEAN -> "CLEAN"
    Verdict.SUSPECT -> "SUSPECT"
    Verdict.HOOKED -> "HOOKED"
    Verdict.ERROR -> "ERROR"
}

// ---------------- 仪表盘 ----------------

@Composable
fun Dashboard(
    agg: AceAggregate?,
    state: VictimState?,
    victimAlive: Boolean,
    binariesReady: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onRunAce: () -> Unit,
    onRunDiff: () -> Unit,
    busy: Boolean,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("双视图 Hook 检测", style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold)
        Text("rxshadow-ace · 无 root · 18 信道", style = MaterialTheme.typography.bodySmall,
            color = C_TEXT_DIM)

        // 总判定卡
        VerdictCard(agg, state, victimAlive, binariesReady)

        // 操作按钮
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = onStart,
                enabled = binariesReady && !busy && !victimAlive,
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = C_SURFACE2),
            ) {
                Icon(Icons.Default.PlayArrow, null, Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("启动实验")
            }
            Button(
                onClick = onStop,
                enabled = victimAlive && !busy,
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = C_SURFACE2),
            ) {
                Icon(Icons.Default.Stop, null, Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("停止")
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = onRunAce,
                enabled = victimAlive && !busy,
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = C_PRIMARY),
            ) {
                Icon(Icons.Default.Security, null, Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("全信道检测", color = Color.Black, fontWeight = FontWeight.Bold)
            }
            Button(
                onClick = onRunDiff,
                enabled = victimAlive && !busy,
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = C_SURFACE2),
            ) {
                Icon(Icons.Default.CompareArrows, null, Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("差分对照")
            }
        }
        if (busy) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }

        // victim 状态卡
        if (state != null) {
            VictimCard(state)
        }
    }
}

@Composable
private fun VerdictCard(
    agg: AceAggregate?,
    state: VictimState?,
    victimAlive: Boolean,
    binariesReady: Boolean,
) {
    val v = agg?.verdict
    val score = agg?.score ?: 0
    val color = if (v != null) verdictColor(v) else C_TEXT_DIM
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = C_SURFACE),
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // 环形评分
            Box(contentAlignment = Alignment.Center, modifier = Modifier.size(96.dp)) {
                Canvas(modifier = Modifier.fillMaxSize()) {
                    drawArc(
                        color = color.copy(alpha = 0.18f),
                        startAngle = -90f, sweepAngle = 360f,
                        useCenter = false,
                        style = Stroke(width = 9.dp.toPx(), cap = StrokeCap.Round),
                    )
                    drawArc(
                        color = color,
                        startAngle = -90f, sweepAngle = 360f * score / 100f,
                        useCenter = false,
                        style = Stroke(width = 9.dp.toPx(), cap = StrokeCap.Round),
                    )
                }
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("$score", fontSize = 26.sp, fontWeight = FontWeight.Bold,
                        color = color, fontFamily = FontFamily.Monospace)
                    Text("/100", fontSize = 10.sp, color = C_TEXT_DIM)
                }
            }
            Spacer(Modifier.width(18.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    if (v != null) verdictEn(v) else "未检测",
                    fontSize = 26.sp, fontWeight = FontWeight.Black, color = color,
                    fontFamily = FontFamily.Monospace,
                )
                Text(if (v != null) verdictLabel(v) else "先启动实验再跑检测",
                    style = MaterialTheme.typography.bodyMedium, color = C_TEXT_DIM)
                Spacer(Modifier.height(8.dp))
                if (agg != null) {
                    Text(
                        "stealth ${agg.channelsClean}/${agg.channelsLive} 信道无感 · ${agg.channelsHooked} 命中",
                        fontSize = 12.sp, color = C_TEXT_DIM,
                    )
                } else if (!binariesReady) {
                    Text("native 二进制缺失（构建时未跑 buildNative）", fontSize = 12.sp, color = C_SUSPECT)
                } else if (!victimAlive) {
                    Text("victim 未运行", fontSize = 12.sp, color = C_TEXT_DIM)
                }
                if (agg != null && agg.note.isNotBlank()) {
                    Text(agg.note, fontSize = 11.sp, color = C_TEXT_DIM,
                        maxLines = 2)
                }
            }
        }
    }
}

@Composable
private fun VictimCard(state: VictimState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = C_SURFACE),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("实验对象（victim）", style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold)
            Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                Metric("pid", state.pid.toString())
                Metric("call_a", "${state.callA}${if (state.callA != state.expectedA) " ≠ ${state.expectedA}" else ""}",
                    warn = state.callA != state.expectedA)
                Metric("延迟比", "%.2f".format(state.latencyRatio),
                    warn = state.latencyRatio >= 1.5)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                Metric("crc_self", state.crcSelfA)
                Metric("crc_gup", state.crcGupA,
                    warn = state.crcSelfA.isNotBlank() && state.crcSelfA != state.crcGupA)
                Metric("洞区PC", state.uctxPcCave.toString(),
                    warn = state.uctxPcCave > 0)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                Metric("minflt", state.minfltDelta.toString(), warn = state.minfltDelta > 1000)
                Metric("pingpong", "${state.pingpongNs}ns", warn = state.pingpongNs > 500)
                if (state.childPid > 0)
                    Metric("child", "${state.childPid} → ${state.childCallA}")
            }
        }
    }
}

@Composable
private fun Metric(label: String, value: String, warn: Boolean = false) {
    Column {
        Text(label, fontSize = 10.sp, color = C_TEXT_DIM)
        Text(value, fontSize = 13.sp, fontFamily = FontFamily.Monospace,
            color = if (warn) C_HOOKED else C_TEXT, fontWeight = if (warn) FontWeight.Bold else FontWeight.Normal)
    }
}
