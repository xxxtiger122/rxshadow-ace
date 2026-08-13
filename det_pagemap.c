/*
 * det_pagemap.c — L3 页表 / 物理页信道
 *
 * 原理：rxshadow 的双视图本质是"同一个 VA 被指向第二张物理页（shadow）"。
 *       /proc/<pid>/pagemap 暴露每页 PFN（root 且 CAP_SYS_ADMIN 时）。
 *       三个针对性探测：
 *
 *   P1 fork 分歧：labtarget 派生子进程（fork 隐藏 = 子不继承 shadow）。
 *       父进程被 map 后，父的 va_a PFN = shadow PFN，子的 va_a PFN = original
 *       PFN。同一 VA 在两个活进程里的 PFN 不同 = 双物理页的直接证据。
 *
 *   P2 静态页基线：alpha/beta/gamma 页 PFN 稳定（file-backed，不可挂），
 *       多次采样必须一致。
 *
 *   P3 一致性交叉：若 pagemap 报的 PFN"看起来是 original"，但 L1/L2 已
 *       发现双视图分裂 → pagemap 正在被 rxshadow 的 pte_to_pagemap_entry
 *       钩子谎报（伪装本身也是证据，标 suspect 并交给 ace 交叉）。
 *
 * 用法：det_pagemap --pid <pid> [--child <pid>] [--state <path>] [--json]
 * 依赖状态 key：pid child_pid va_a va_b
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "ace_common.h"

static const char *g_state;
static int g_json;
static pid_t g_pid = -1, g_child = -1;

static int read_pfn(pid_t pid, uint64_t va, uint64_t *pfn, int *present)
{
    if (ace_pagemap_pfn(pid, va, pfn, present) != 0) {
        fprintf(stderr, "  pagemap: /proc/%d/pagemap 不可读（需 root+CAP_SYS_ADMIN）\n",
                (int)pid);
        return -1;
    }
    if (!*present) {
        fprintf(stderr, "  pagemap: va=0x%llx 未驻留（present=0）\n",
                (unsigned long long)va);
        return -1;
    }
    if (*pfn == 0) {
        fprintf(stderr, "  pagemap: va=0x%llx PFN=0 —— 内核未暴露 PFN"
                "（无 CAP_SYS_ADMIN 或 CONFIG_PROC_PAGE_MONITOR 限制）\n",
                (unsigned long long)va);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int i;
    uint64_t va_a = 0, va_b = 0;
    uint64_t pfn_pa = 0, pfn_ca = 0, pfn_pb = 0;
    int pres_pa = 0, pres_ca = 0, pres_pb = 0;
    ace_verdict v = V_CLEAN;
    int score = 0;
    char hits[512] = "";
    char note[512] = "";
    int pfn_available = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            g_pid = (pid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--child") && i + 1 < argc)
            g_child = (pid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--state") && i + 1 < argc)
            g_state = argv[++i];
        else if (!strcmp(argv[i], "--json"))
            g_json = 1;
    }
    if (!g_state)
        g_state = ace_default_state_path();

    if (g_pid < 0)
        g_pid = (pid_t)ace_state_get_l(g_state, "pid", -1);
    if (g_child < 0)
        g_child = (pid_t)ace_state_get_l(g_state, "child_pid", -1);
    if (g_pid <= 0 || kill(g_pid, 0) != 0) {
        ace_emit(stdout, "pagemap", "L3-pagemap-PFN", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }
    va_a = ace_state_get_u64(g_state, "va_a", 0);
    va_b = ace_state_get_u64(g_state, "va_b", 0);
    if (!va_a) {
        ace_emit(stdout, "pagemap", "L3-pagemap-PFN", V_ERROR, 0, "",
                 "状态文件缺少 va_a", g_json);
        return 1;
    }

    /* P1：父 / 子 va_a PFN */
    if (read_pfn(g_pid, va_a, &pfn_pa, &pres_pa) == 0)
        pfn_available = 1;
    if (g_child > 0 && kill(g_child, 0) == 0) {
        if (read_pfn(g_child, va_a, &pfn_ca, &pres_ca) == 0)
            pfn_available = 1;
    } else {
        g_child = -1;
    }
    /* P2：控制页 */
    if (va_b)
        read_pfn(g_pid, va_b, &pfn_pb, &pres_pb);

    snprintf(hits, sizeof(hits),
             "pid=%d va_a=0x%llx pfn=0x%llx%s"
             "%schild=%d child_va_a=0x%llx pfn=0x%llx%s",
             (int)g_pid, (unsigned long long)va_a, (unsigned long long)pfn_pa,
             pres_pa ? "" : "(absent)",
             g_child > 0 ? " " : "",
             g_child > 0 ? (int)g_child : 0,
             g_child > 0 ? (unsigned long long)va_a : (unsigned long long)0,
             g_child > 0 ? (unsigned long long)pfn_ca : (unsigned long long)0);

    if (!pfn_available) {
        ace_emit(stdout, "pagemap", "L3-pagemap-PFN", V_ERROR, 0, hits,
                 "PFN 不可读（权限），本信道跳过", g_json);
        return 1;
    }

    if (g_child > 0) {
        if (pfn_pa != pfn_ca) {
            v = V_HOOKED;
            score = 90;
            snprintf(note, sizeof(note),
                     "同一 VA 在父/子进程 PFN 不同（父=0x%llx 子=0x%llx）："
                     "父进程该页被改指第二物理页（shadow）", 
                     (unsigned long long)pfn_pa, (unsigned long long)pfn_ca);
        } else {
            snprintf(note, sizeof(note),
                     "父/子 va_a 同一 PFN=0x%llx，未发现页表级分歧",
                     (unsigned long long)pfn_pa);
        }
    } else {
        snprintf(note, sizeof(note), "无存活子进程，仅报告父进程 PFN 状态");
    }

    /* P3：伪装的交叉信号（交给 ace 综合，这里只标 suspect） */
    if (pfn_pa == 0 && pres_pa) {
        v = V_SUSPECT;
        if (score < 50)
            score = 50;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；pfn=0 但 present=1：PFN 被隐藏");
    }
    /* P4：SOFT_DIRTY / flag 一致性（292261：合成 shadow PTE 必须继承
     * SOFT_DIRTY，否则被 hook 页与同 VMA 其他页 flags 不一致即暴露） */
    {
        uint64_t e_a = 0, e_nb = 0;
        if (ace_pagemap_entry(g_pid, va_a, &e_a) == 0 && va_b &&
            ace_pagemap_entry(g_pid, va_b, &e_nb) == 0) {
            uint64_t fl_a = e_a & 0x7F80000000000000ull; /* 高位 flag 位 */
            uint64_t fl_b = e_nb & 0x7F80000000000000ull;
            int sd_a = (int)((e_a >> 55) & 1), sd_b = (int)((e_nb >> 55) & 1);
            (void)fl_a;
            (void)fl_b;
            if (sd_a != sd_b) {
                v = V_SUSPECT;
                if (score < 60)
                    score = 60;
                snprintf(note + strlen(note), sizeof(note) - strlen(note),
                         "；SOFT_DIRTY 不一致（H_A=%d H_B=%d）：shadow PTE "
                         "未继承 SOFT_DIRTY，页表伪装被同 VMA 对比暴露",
                         sd_a, sd_b);
            }
        }
    }
    /* PFN 对拍稳定性：3 次采样必须稳定 */
    {
        int t;
        uint64_t p2 = 0;
        int p2p = 0;
        for (t = 0; t < 3; t++) {
            uint64_t e;
            if (ace_pagemap_entry(g_pid, va_a, &e) == 0) {
                uint64_t cur = e & ((1ull << 55) - 1);
                if (t == 0)
                    p2 = cur, p2p = (int)((e >> 63) & 1);
                else if (cur != p2) {
                    v = V_SUSPECT;
                    if (score < 55)
                        score = 55;
                    snprintf(note + strlen(note), sizeof(note) - strlen(note),
                             "；pagemap 采样不稳定（0x%llx→0x%llx）："
                             "翻页窗竞态或伪装钩子", (unsigned long long)p2,
                             (unsigned long long)cur);
                    break;
                }
            }
            usleep(20000);
        }
        (void)p2p;
    }

    ace_emit(stdout, "pagemap", "L3-pagemap-PFN", v, score, hits, note, g_json);
    return (int)v;
}
