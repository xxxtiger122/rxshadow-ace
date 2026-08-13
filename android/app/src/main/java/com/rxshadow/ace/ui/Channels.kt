package com.rxshadow.ace.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rxshadow.ace.DetResult
import com.rxshadow.ace.Verdict

private val channelIcons = mapOf(
    "f0" to Icons.Default.Bolt,
    "selfcrc" to Icons.Default.Fingerprint,
    "elfhash" to Icons.Default.BlurOn,
    "crossread" to Icons.Default.ReadMore,
    "pagemap" to Icons.Default.GridOn,
    "timing" to Icons.Default.Timer,
    "faultcount" to Icons.Default.ReceiptLong,
    "perf" to Icons.Default.ShowChart,
    "selfmod" to Icons.Default.Edit,
    "procscan" to Icons.Default.AccountTree,
    "trampoline" to Icons.Default.Memory,
    "callstack" to Icons.Default.AccountTree,
    "hwbp" to Icons.Default.AdsClick,
    "linkmap" to Icons.Default.Link,
    "kallsyms" to Icons.Default.Settings,
    "kcore" to Icons.Default.Dns,
    "dmesg" to Icons.Default.Article,
    "sysfs" to Icons.Default.Storage,
)

@Composable
fun Channels(results: List<DetResult>, onRefresh: () -> Unit, refreshing: Boolean) {
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("检测信道", style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold)
            IconButton(onClick = onRefresh, enabled = !refreshing) {
                Icon(Icons.Default.Refresh, null)
            }
        }
        Text("每个信道打一个观测面，error = 当前权限下不可用",
            style = MaterialTheme.typography.bodySmall, color = C_TEXT_DIM)

        if (results.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("跑一次全信道检测后展示明细", color = C_TEXT_DIM)
            }
            return@Column
        }

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxSize(),
        ) {
            items(results, key = { it.det }) { r ->
                ChannelCard(r)
            }
        }
    }
}

@Composable
private fun ChannelCard(r: DetResult) {
    var expanded by remember { mutableStateOf(false) }
    val color = verdictColor(r.verdict)
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = C_SURFACE),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded }
                .padding(12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // 图标
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(color.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        channelIcons[r.det.removePrefix("det_")] ?: Icons.Default.Hub,
                        null, tint = color, modifier = Modifier.size(20.dp),
                    )
                }
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(r.shortChannel, fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp)
                    Text(r.det.removePrefix("det_"), fontSize = 10.sp, color = C_TEXT_DIM,
                        fontFamily = FontFamily.Monospace)
                }
                // 分数条 + 徽章
                Column(horizontalAlignment = Alignment.End) {
                    Text(verdictEn(r.verdict), fontSize = 11.sp, fontWeight = FontWeight.Bold,
                        color = color, fontFamily = FontFamily.Monospace)
                    Spacer(Modifier.height(3.dp))
                    if (r.verdict != Verdict.ERROR) {
                        LinearProgressIndicator(
                            progress = { r.score / 100f },
                            modifier = Modifier.width(90.dp).height(5.dp),
                            color = color,
                            trackColor = color.copy(alpha = 0.15f),
                        )
                    } else {
                        Text("—", color = C_TEXT_DIM, fontSize = 11.sp)
                    }
                }
            }
            if (expanded) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp),
                    color = C_SURFACE2)
                if (r.note != null) {
                    Text(r.note, fontSize = 12.sp, color = C_TEXT)
                }
                if (r.hits != null) {
                    Spacer(Modifier.height(4.dp))
                    Text(r.hits, fontSize = 10.sp, color = C_TEXT_DIM,
                        fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}
