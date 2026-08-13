/*
 * det_selfcrc.c — L1 自完整性信道
 *
 * 原理：rxshadow Cave 常驻后，受害者"自己读代码"看到的是 shadow 页
 *       （入口是页内 B / 洞内字节），而启动时的原始字节在 crc_self0_a。
 *       自我视图相对基线漂移 + GUP 视图仍等于基线 = hook 存在。
 *
 * 威胁模型：受害者是我们自己的 lab 进程（诚实自报）。本信道检测
 *       内核态 hook 对"进程自我观察"的污染，不是检测用户态篡改。
 *
 * 用法：det_selfcrc [--state <path>] [--json] [--quiet]
 * 依赖状态 key：va_a crc_self0_a crc_self_a crc_gup_a crc_self_b crc_gup_b
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ace_common.h"

static const char *g_state;
static int g_json;

int main(int argc, char **argv)
{
    int i;
    uint64_t va_a;
    unsigned long crc0, crc_self, crc_gup, crc_self_b, crc_gup_b;
    ace_verdict v = V_CLEAN;
    int score = 0;
    char hits[512] = "";
    char note[512] = "";
    const char *mode;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--state") && i + 1 < argc)
            g_state = argv[++i];
        else if (!strcmp(argv[i], "--json"))
            g_json = 1;
        else if (!strcmp(argv[i], "--quiet")) { /* 由 ace 统一输出 */
        }
    }
    if (!g_state)
        g_state = ace_default_state_path();

    va_a = ace_state_get_u64(g_state, "va_a", 0);
    crc0 = ace_state_get_u64(g_state, "crc_self0_a", 0);
    crc_self = ace_state_get_u64(g_state, "crc_self_a", 0);
    crc_gup = ace_state_get_u64(g_state, "crc_gup_a", 0);
    crc_self_b = ace_state_get_u64(g_state, "crc_self_b", 0);
    crc_gup_b = ace_state_get_u64(g_state, "crc_gup_b", 0);
    mode = ace_state_get(g_state, "mode");

    if (va_a == 0 || crc0 == 0) {
        ace_emit(stdout, "selfcrc", "L1-self-integrity", V_ERROR, 0, "",
                 "状态文件缺少 va_a/crc_self0_a（labtarget 未运行或未写盘）",
                 g_json);
        return 1;
    }

    snprintf(hits, sizeof(hits),
             "crc_self0=0x%08lx crc_self=0x%08lx crc_gup=0x%08lx "
             "crc_self_b=0x%08lx crc_gup_b=0x%08lx",
             crc0, crc_self, crc_gup, crc_self_b, crc_gup_b);

    if (crc_self == crc0 && crc_gup == crc0) {
        v = V_CLEAN;
        score = 0;
        snprintf(note, sizeof(note), "自我视图与基线一致，无漂移");
    } else if (crc_self != crc0 && crc_gup == crc0) {
        /* 自我看到变化、GUP 仍看到原始 —— Cave/跷跷板双视图特征 */
        v = V_HOOKED;
        score = 92;
        snprintf(note, sizeof(note),
                 "自我视图 CRC 相对基线漂移且 GUP 视图仍为原始字节："
                 "双视图分裂（shadow cave / seesaw 特征）");
    } else if (crc_self == crc_gup && crc_self != crc0) {
        v = V_SUSPECT;
        score = 35;
        snprintf(note, sizeof(note),
                 "两视图一致但都偏离基线：页面被外部重写（GUP 写 / "
                 "selfmod 测试 / 正常自修改）—— 非双视图 hook，但需人工确认");
    } else {
        v = V_SUSPECT;
        score = 55;
        snprintf(note, sizeof(note), "两视图都偏离基线且互不一致：状态异常");
    }

    /* 控制页 H_B 不应有任何漂移 */
    if (crc_self_b != crc_gup_b) {
        v = V_SUSPECT;
        if (score < 60)
            score = 60;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；H_B 控制页自身也分裂（crc_self_b!=crc_gup_b），"
                 "hook 可能已污染控制页或 GUP 隐藏全局失效");
    }

    if (mode && !strcmp(mode, "hooked") && score < 80 && crc_self != crc0)
        score = score < 80 ? 80 : score;

    ace_emit(stdout, "selfcrc", "L1-self-integrity", v, score, hits, note, g_json);
    return (int)v;
}
