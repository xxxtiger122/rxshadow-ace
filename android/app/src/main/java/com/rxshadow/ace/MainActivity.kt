package com.rxshadow.ace

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.ListAlt
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rxshadow.ace.ui.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
class MainActivity : ComponentActivity() {

    private val engine by lazy { AceEngine(applicationContext) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AceTheme {
                val scope = rememberCoroutineScope()
                var tab by remember { mutableStateOf(0) }
                var agg by remember { mutableStateOf<AceAggregate?>(null) }
                var dets by remember { mutableStateOf<List<DetResult>>(emptyList()) }
                var state by remember { mutableStateOf<VictimState?>(null) }
                var victimAlive by remember { mutableStateOf(false) }
                var binariesReady by remember { mutableStateOf(false) }
                var busy by remember { mutableStateOf(false) }
                var victimLog by remember { mutableStateOf("") }
                var stateRaw by remember { mutableStateOf<String?>(null) }

                // 初始化：解压 native 二进制
                LaunchedEffect(Unit) {
                    withContext(Dispatchers.IO) {
                        runCatching { engine.ensureBinaries() }
                    }
                    binariesReady = engine.binariesReady
                    if (!binariesReady) {
                        Toast.makeText(
                            this@MainActivity,
                            "native 二进制缺失：构建时需先跑 ./gradlew buildNative",
                            Toast.LENGTH_LONG,
                        ).show()
                    }
                }

                // 轮询 victim 状态（2s）
                LaunchedEffect(Unit) {
                    while (true) {
                        victimAlive = engine.victimAlive()
                        state = withContext(Dispatchers.IO) { engine.readState() }
                        victimLog = withContext(Dispatchers.IO) { engine.readVictimLog() }
                        stateRaw = withContext(Dispatchers.IO) { engine.readStateRaw() }
                        delay(2000)
                    }
                }

                Scaffold(
                    containerColor = Color(0xFF0D1117),
                    bottomBar = {
                        // 自定义底部导航（避开 material3 NavigationBar 的
                        // experimental API 兼容性问题）
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(60.dp)
                                .background(C_SURFACE),
                        ) {
                            TabItem("仪表盘", Icons.Default.Dashboard, 0, tab) { tab = it }
                            TabItem("信道", Icons.Default.ListAlt, 1, tab) { tab = it }
                            TabItem("日志", Icons.Default.Terminal, 2, tab) { tab = it }
                            TabItem("关于", Icons.Default.Info, 3, tab) { tab = it }
                        }
                    },
                ) { padding ->
                    Box(Modifier.padding(padding)) {
                        when (tab) {
                            0 -> Dashboard(
                                agg = agg, state = state,
                                victimAlive = victimAlive,
                                binariesReady = binariesReady,
                                busy = busy,
                                onStart = {
                                    busy = true
                                    scope.launchSafe {
                                        val ok = withContext(Dispatchers.IO) { engine.startVictim() }
                                        if (!ok) Toast.makeText(this@MainActivity,
                                            engine.lastError ?: "启动失败", Toast.LENGTH_LONG).show()
                                        busy = false
                                    }
                                },
                                onStop = { scope.launchSafe { engine.stopVictim() } },
                                onRunAce = {
                                    if (busy) return@Dashboard
                                    busy = true
                                    scope.launchSafe {
                                        val r = withContext(Dispatchers.IO) { engine.runAce() }
                                        if (r != null) {
                                            agg = r.first
                                            dets = r.second
                                        } else {
                                            Toast.makeText(this@MainActivity,
                                                engine.lastError ?: "检测失败", Toast.LENGTH_LONG).show()
                                        }
                                        busy = false
                                    }
                                },
                                onRunDiff = {
                                    if (busy) return@Dashboard
                                    busy = true
                                    scope.launchSafe {
                                        val ok2 = withContext(Dispatchers.IO) { engine.startVictim2() }
                                        if (ok2) {
                                            delay(1500)
                                            val r = withContext(Dispatchers.IO) { engine.runAce(diffMode = true) }
                                            if (r != null) { agg = r.first; dets = r.second }
                                        }
                                        busy = false
                                    }
                                },
                            )
                            1 -> Channels(
                                results = dets,
                                onRefresh = {
                                    if (busy) return@Channels
                                    busy = true
                                    scope.launchSafe {
                                        val r = withContext(Dispatchers.IO) { engine.runAce() }
                                        if (r != null) { agg = r.first; dets = r.second }
                                        busy = false
                                    }
                                },
                                refreshing = busy,
                            )
                            2 -> Logs(victimLog, stateRaw) {
                                scope.launchSafe {
                                    victimLog = withContext(Dispatchers.IO) { engine.readVictimLog() }
                                    stateRaw = withContext(Dispatchers.IO) { engine.readStateRaw() }
                                }
                            }
                            3 -> About()
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        engine.stopVictim()
        super.onDestroy()
    }
}

@Composable
private fun TabItem(
    label: String,
    icon: ImageVector,
    index: Int,
    current: Int,
    onSelect: (Int) -> Unit,
) {
    val selected = current == index
    val color = if (selected) C_PRIMARY else C_TEXT_DIM
    Column(
        modifier = Modifier
            .weight(1f)
            .fillMaxHeight()
            .clickable { onSelect(index) }
            .background(if (selected) C_PRIMARY.copy(alpha = 0.10f) else Color.Transparent),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(icon, null, tint = color, modifier = Modifier.size(22.dp))
        Spacer(Modifier.height(2.dp))
        Text(label, fontSize = 11.sp, color = color)
    }
}

/** 轻量协程包装：异常吞掉避免崩溃 */
private fun kotlinx.coroutines.CoroutineScope.launchSafe(block: suspend () -> Unit) {
    launch {
        try {
            block()
        } catch (_: Exception) {
        }
    }
}
