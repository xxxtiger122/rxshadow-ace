/*
 * det_diff.c — L2 差分对照信道（双 victim）
 *
 * 发散自 290718 的"进程对自己 .text 做 CRC 会看到 hook"：GUP 隐藏窗
 * 只能骗"外部读"（/proc/pid/mem、process_vm_readv 都返回 original），
 * 骗不了"被挂进程自己的自读"——Cave 下 victim 自读看到 shadow。
 *
 * 于是两个同构 labtarget 实例天然构成对照实验：
 *   A（被挂）  crc_self_a = shadow 字节 CRC
 *   B（干净）  crc_self_a = original 字节 CRC
 *   A、B 的 crc_gup_a 应该相同（GUP 隐藏统一返回 original）
 *
 * 判据：
 *   A.crc_self != B.crc_self 且 A.crc_gup == B.crc_gup  → A 被挂（差分锁定）
 *   A.crc_self != B.crc_self 且 A.crc_gup != B.crc_gup → 双方字节都不同
 *     （一侧 GUP 隐藏失效 / 页被写，需人工）
 *   两侧各自 self!=gup → 双侧都被挂
 *
 * 用法：det_diff --pid <A> --state2 <B的状态文件> [--pid2 <B>] [--json]
 * 注意：需要跑两个 labtarget（第二个用 --state 指定不同路径）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "ace_common.h"

static const char *g_state;
static const char *g_state2;
static int g_json;

static void read_victim(const char *path, uint32_t *self_a, uint32_t *gup_a,
                        uint32_t *self0_a, long *call_a, uint64_t *va_a)
{
    *self_a = (uint32_t)ace_state_get_u64(path, "crc_self_a", 0);
    *gup_a = (uint32_t)ace_state_get_u64(path, "crc_gup_a", 0);
    *self0_a = (uint32_t)ace_state_get_u64(path, "crc_self0_a", 0);
    *call_a = ace_state_get_l(path, "call_a", -1);
    *va_a = ace_state_get_u64(path, "va_a", 0);
}

static int det_impl_main(int argc, char **argv)
{
    int i;
    ace_verdict v = V_ERROR;
    int score = 0;
    char hits[512] = "";
    char note[512] = "";
    uint32_t a_self, a_gup, a_self0, b_self, b_gup, b_self0;
    long a_call, b_call;
    uint64_t a_va, b_va;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--state") && i + 1 < argc)
            g_state = argv[++i];
        else if (!strcmp(argv[i], "--state2") && i + 1 < argc)
            g_state2 = argv[++i];
        else if (!strcmp(argv[i], "--json"))
            g_json = 1;
    }
    if (!g_state)
        g_state = ace_default_state_path();
    if (!g_state2) {
        ace_emit(stdout, "diff", "L2-differential", V_ERROR, 0, "",
                 "缺少 --state2（第二个 labtarget 的状态文件）", g_json);
        return 1;
    }

    read_victim(g_state, &a_self, &a_gup, &a_self0, &a_call, &a_va);
    read_victim(g_state2, &b_self, &b_gup, &b_self0, &b_call, &b_va);

    if (!a_va || !b_va) {
        ace_emit(stdout, "diff", "L2-differential", V_ERROR, 0, "",
                 "任一状态文件缺失 va_a（两个 labtarget 都要运行）", g_json);
        return 1;
    }

    snprintf(hits, sizeof(hits),
             "A{va=0x%llx self=0x%08x gup=0x%08x self0=0x%08x call=%ld} "
             "B{va=0x%llx self=0x%08x gup=0x%08x self0=0x%08x call=%ld}",
             (unsigned long long)a_va, a_self, a_gup, a_self0, a_call,
             (unsigned long long)b_va, b_self, b_gup, b_self0, b_call);

    if (a_self == b_self) {
        /* 两侧自读一致 */
        if (a_self == a_gup && b_self == b_gup) {
            v = V_CLEAN;
            score = 0;
            snprintf(note, sizeof(note),
                     "双 victim 自读/双视图全部一致：无任何一侧被挂");
        } else {
            v = V_SUSPECT;
            score = 50;
            snprintf(note, sizeof(note),
                     "双 victim 自读一致但各自 self!=gup：两侧同时双视图分裂"
                     "（或被全局 GUP 伪装污染）");
        }
    } else if (a_gup == b_gup) {
        /* 自读分歧 + GUP 一致 → 有且仅有一侧被挂（GUP 隐藏统一原始） */
        v = V_HOOKED;
        score = 92;
        if (a_self != a_gup) {
            snprintf(note, sizeof(note),
                     "差分锁定：A 自读 0x%08x≠B 自读 0x%08x，而 GUP 一致"
                     " 0x%08x → A 被挂（A.self!=A.gup 双视图分裂）",
                     a_self, b_self, a_gup);
        } else {
            snprintf(note, sizeof(note),
                     "差分锁定：B 自读 0x%08x≠A 自读 0x%08x，而 GUP 一致"
                     " 0x%08x → B 被挂", b_self, a_self, a_gup);
        }
    } else {
        v = V_SUSPECT;
        score = 60;
        snprintf(note, sizeof(note),
                 "双 victim 自读分歧且 GUP 也不一致：GUP 隐藏失效或页被"
                 "外部改写（如 det_selfmod 已写 H_A），需人工确认");
    }

    /* 功能证据强化 */
    if (a_call != b_call && a_gup == b_gup) {
        if (score < 85)
            score = 85;
        v = V_HOOKED;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；功能差分 call_a=%ld vs %ld 不一致",
                 a_call, b_call);
    }

    ace_emit(stdout, "diff", "L2-differential", v, score, hits, note, g_json);
    return (int)v;
}

/* ===== 库入口（det_libify.py 生成，diff 特例带 state2） ===== */
#include <stdio.h>
#include <unistd.h>

int det_diff_run(const char *state_path, const char *state2_path,
               char *json_out, size_t outsz)
{
    FILE *f = fmemopen(json_out, outsz, "w");
    int saved, rc;
    char *fake[] = { (char *)"det_diff", (char *)"--state",
                      (char *)state_path, (char *)"--state2",
                      (char *)state2_path, (char *)"--json", NULL };
    if (!f)
        return 3;
    saved = dup(STDOUT_FILENO);
    dup2(fileno(f), STDOUT_FILENO);
    fflush(stdout);
    rc = det_impl_main(6, fake);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    fclose(f);
    return rc;
}

#ifndef ACE_AS_LIB
int main(int argc, char **argv)
{
    return det_impl_main(argc, argv);
}
#endif
