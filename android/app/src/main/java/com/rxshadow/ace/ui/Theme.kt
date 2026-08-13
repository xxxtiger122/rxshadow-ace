package com.rxshadow.ace.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// 深色科技风：近黑背景 + 青色主调 + 黄/红风险色
val C_BG = Color(0xFF0D1117)
val C_SURFACE = Color(0xFF161B22)
val C_SURFACE2 = Color(0xFF1F2630)
val C_PRIMARY = Color(0xFF00E5FF)   // 青
val C_CLEAN = Color(0xFF00E676)     // 绿
val C_SUSPECT = Color(0xFFFFC400)   // 黄
val C_HOOKED = Color(0xFFFF5252)    // 红
val C_TEXT = Color(0xFFE6EDF3)
val C_TEXT_DIM = Color(0xFF8B949E)

private val AceColorScheme = darkColorScheme(
    primary = C_PRIMARY,
    background = C_BG,
    surface = C_SURFACE,
    surfaceVariant = C_SURFACE2,
    onPrimary = Color.Black,
    onBackground = C_TEXT,
    onSurface = C_TEXT,
    onSurfaceVariant = C_TEXT_DIM,
    error = C_HOOKED,
)

@Composable
fun AceTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = AceColorScheme, content = content)
}
