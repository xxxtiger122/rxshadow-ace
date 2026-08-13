/*
 * det_faultcount.c — L4 记账信道（fault / stime / 信号泄漏）
 *
 * 源自看雪 292226（时序侧信道，作者自评"最危险检测线"）：
 *   1. 异常驱动 hook（BRK/XOL/跷跷板翻页）每次命中都在内核态同步处理，
 *      按标准记账计入目标任务：page fault 计数暴涨、stime 上升。
 *      纯计算/校验函数 stime 期望为零 —— 零容忍校验。
 *   2. 读窗翻转的"读 fault 收费"：顺序读代码页，被 hook 页每页贡献
 *      一次 fault（290304 评论区时间差检测的量化版）。
 *   3. 信号泄漏（292066 评论）：高频 HWBP/BRK 极端场景漏泄 SIGTRAP。
 *   4. ucontext PC 观测（292354）：异步信号若观察到非 canonical PC
 *      （cave 洞内地址）即暴露插桩 —— labtarget 自投递 SIGUSR1 自检。
 *
 * 双信道：
 *   A. 消费 labtarget 状态文件自报（minflt_delta / stime / 信号计数）
 *   B. 独立读 /proc/<pid>/stat 的 minflt 字段两次差分（不信任自报）
 *
 * 用法：det_faultcount --pid <pid> [--state <path>] [--json]
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
static pid_t g_pid = -1;

/* 独立读 /proc/<pid>/stat 的 minflt（field 10）/ majflt（field 12） */
static int stat_minflt(pid_t pid, unsigned long *minflt, unsigned long *majflt)
{
    char path[64];
    char *buf;
    char *p;
    int i;
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    buf = ace_read_file(path, NULL);
    if (!buf)
        return -1;
    p = strrchr(buf, ')');
    if (!p) {
        free(buf);
        return -1;
    }
    {
        char *f = p + 2;
        for (i = 3; i <= 12; i++) {
            char *tok = f;
            while (*f && *f != ' ')
                f++;
            if (*f == ' ')
                *f++ = 0;
            if (i == 10 && minflt)
                *minflt = strtoul(tok, NULL, 10);
            else if (i == 12 && majflt)
                *majflt = strtoul(tok, NULL, 10);
        }
    }
    free(buf);
    return 0;
}

static int det_impl_main(int argc, char **argv)
{
    int i;
    char hits[1024] = "";
    char note[512] = "";
    ace_verdict v = V_CLEAN;
    int score = 0;
    unsigned long mf1 = 0, mf2 = 0, mj1 = 0;
    long minflt_delta = -1, stime = -1, utime = -1;
    long sig_trap = 0, sig_segv = 0, sig_ill = 0, uctx_anon = 0, uctx_cave = 0,
         pingpong = 0;
    double stime_ratio = 0.0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            g_pid = (pid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--state") && i + 1 < argc)
            g_state = argv[++i];
        else if (!strcmp(argv[i], "--json"))
            g_json = 1;
    }
    if (!g_state)
        g_state = ace_default_state_path();
    if (g_pid < 0)
        g_pid = (pid_t)ace_state_get_l(g_state, "pid", -1);
    if (g_pid <= 0 || kill(g_pid, 0) != 0) {
        ace_emit(stdout, "faultcount", "L4-accounting", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }

    /* B: 独立 minflt 差分（1 秒窗口） */
    if (stat_minflt(g_pid, &mf1, &mj1) == 0) {
        usleep(1000000);
        if (stat_minflt(g_pid, &mf2, NULL) == 0) {
            /* 独立差分（不与自报混用） */
        }
    }

    /* A: 状态文件自报 */
    minflt_delta = ace_state_get_l(g_state, "minflt_delta", -1);
    stime = ace_state_get_l(g_state, "stime_ns", -1);
    utime = ace_state_get_l(g_state, "utime_ns", -1);
    sig_trap = ace_state_get_l(g_state, "sig_trap", 0);
    sig_segv = ace_state_get_l(g_state, "sig_segv", 0);
    sig_ill = ace_state_get_l(g_state, "sig_ill", 0);
    uctx_anon = ace_state_get_l(g_state, "uctx_pc_anon", 0);
    uctx_cave = ace_state_get_l(g_state, "uctx_pc_cave", 0);
    pingpong = ace_state_get_l(g_state, "pingpong_ns", 0);

    if (stime > 0 && utime >= 0 && stime + utime > 0)
        stime_ratio = (double)stime / (double)(stime + utime);

    snprintf(hits, sizeof(hits),
             "self_minflt_delta=%ld stime_ratio=%.4f sig{trap=%ld segv=%ld ill=%ld} "
             "uctx{pc_anon=%ld pc_cave=%ld} pingpong_ns=%ld | indep_minflt_delta=%lu",
             minflt_delta, stime_ratio, sig_trap, sig_segv, sig_ill,
             uctx_anon, uctx_cave, pingpong,
             (unsigned long)(mf2 > mf1 ? mf2 - mf1 : 0));

    /* 判决 */
    if (uctx_cave > 0) {
        /* 异步信号观测到 PC 在 H_A 页尾洞区：Cave 洞内代码正在执行 */
        v = V_HOOKED;
        score = 95;
        snprintf(note, sizeof(note),
                 "ucontext PC %ld 次落在 H_A 页尾洞区（正常 H_A 只有 8 字节"
                 "入口代码）：Cave 插桩执行证据", uctx_cave);
    } else if (minflt_delta > 1000) {
        /* 每轮（~1s）超千次 minor fault：异常驱动 hook 的读/执行 fault 风暴 */
        v = V_HOOKED;
        score = 90;
        snprintf(note, sizeof(note),
                 "minflt_delta=%ld/轮：读窗/跷跷板翻页的 fault 计费特征", minflt_delta);
    } else if (stime_ratio > 0.05 && stime > 50000000) {
        /* stime 占比超 5% 且绝对量 >50ms：异常处理记账（292226 最危险线） */
        v = V_HOOKED;
        score = 85;
        snprintf(note, sizeof(note),
                 "stime 占比 %.1f%%（stime=%ldns）：内核态异常处理被计入目标",
                 stime_ratio * 100.0, stime);
    } else if (sig_trap > 0 || sig_segv > 0 || sig_ill > 0) {
        v = V_HOOKED;
        score = 80;
        snprintf(note, sizeof(note),
                 "信号泄漏：trap=%ld segv=%ld ill=%ld（BRK/HWBP 极端场景）",
                 sig_trap, sig_segv, sig_ill);
    } else if (uctx_anon > 0) {
        /* worker 自带调用 H_A 时被信号打断会命中 uctx_pc_anon —— 背景统计，
         * 不计命中（洞区 uctx_pc_cave 才是 Cave 执行证据） */
        snprintf(note, sizeof(note),
                 "记账正常（uctx_pc_anon=%ld 为 worker 自带 H_A 调用背景）",
                 uctx_anon);
        v = V_CLEAN;
        score = 0;
    } else if (pingpong > 500) {
        v = V_SUSPECT;
        score = 45;
        snprintf(note, sizeof(note),
                 "pingpong read+call 最优耗时 %ldns：读触发异常翻页（跷跷板特征）",
                 pingpong);
    } else {
        snprintf(note, sizeof(note),
                 "记账正常：minflt_delta=%ld stime_ratio=%.4f 无信号泄漏",
                 minflt_delta, stime_ratio);
    }

    ace_emit(stdout, "faultcount", "L4-accounting", v, score, hits, note, g_json);
    return (int)v;
}

/* ===== 库入口（JNI / 无 root App 内嵌模式，det_libify.py 生成） =====
 * 将 stdout 重定向到内存 buffer，伪造 argv 复用 impl_main。
 * 无 exec / 无 fork：App 进程内直接调用（Android untrusted_app 域
 * 禁止 exec app 私有 ELF，但 dlopen .so + 进程内调用完全合法）。 */
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>

int det_faultcount_run(const char *state_path, char *json_out, size_t outsz)
{
    FILE *f = fmemopen(json_out, outsz, "w");
    int saved, rc;
    char *fake[] = { (char *)"det_faultcount", (char *)"--state",
                      (char *)state_path, (char *)"--json", NULL };
    if (!f)
        return 3;
    saved = dup(STDOUT_FILENO);
    dup2(fileno(f), STDOUT_FILENO);
    fflush(stdout);
    rc = det_impl_main(4, fake);
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
