/*
 * det_timing.c — L4 时序信道
 *
 * 原理：rxshadow 两种执行语义的稳态代价不同（真机 README）：
 *         BRK/XOL      ≈ 401ns/op（每次命中进 EL1）
 *         Shadow Cave  ≈ 4.5ns/op（页内 B，不进内核）
 *         干净调用      ≈ 2-5ns/op
 *       同一进程里 H_A（可挂）与 H_B（控制，同结构）的延迟比是最干净
 *       的对照：干净时 ≈1.0；Cave 拉高；BRK 拉高两个数量级。
 *
 *       检测器同时独立测自己的 getpid() 系统调用延迟（5000 次），
 *       捕获系统调用派发层的 inline hook（rxshadow 目前不挂 syscall，
 *       这是留给未来/其他 rootkit 的针对性信道）。
 *
 * 用法：det_timing --pid <pid> [--state <path>] [--json]
 * 依赖状态 key：pid lat_a_min lat_a_p50 lat_a_p99 lat_b_* mis_a tot_a
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include "ace_common.h"

#define SC_N 5000

static const char *g_state;
static int g_json;
static pid_t g_pid = -1;

static int det_impl_main(int argc, char **argv)
{
    int i;
    uint64_t la_min, la_p50, la_p99, lb_min, lb_p50, lb_p99;
    long mis_a = 0, tot_a = 0;
    ace_verdict v = V_CLEAN;
    int score = 0;
    char hits[512] = "";
    char note[512] = "";
    double ratio_p50 = 0.0, rs_ratio = 0.0;
    uint64_t sc_min = 0, sc_p50 = 0, sc_p99 = 0;
    long rs_a_min = -1, rs_a_p50 = -1, rs_b_min = -1, rs_b_p50 = -1;

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
        ace_emit(stdout, "timing", "L4-timing", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }

    la_min = ace_state_get_u64(g_state, "lat_a_min", 0);
    la_p50 = ace_state_get_u64(g_state, "lat_a_p50", 0);
    la_p99 = ace_state_get_u64(g_state, "lat_a_p99", 0);
    lb_min = ace_state_get_u64(g_state, "lat_b_min", 0);
    lb_p50 = ace_state_get_u64(g_state, "lat_b_p50", 0);
    lb_p99 = ace_state_get_u64(g_state, "lat_b_p99", 0);
    mis_a = ace_state_get_l(g_state, "mis_a", -1);
    tot_a = ace_state_get_l(g_state, "tot_a", 0);

    /* 自读时序（290304 时间差 / 292226 读诱饵）：H_A vs H_B 全页顺序读 */
    rs_a_min = ace_state_get_l(g_state, "read_scan_a_min", -1);
    rs_a_p50 = ace_state_get_l(g_state, "read_scan_a_p50", -1);
    rs_b_min = ace_state_get_l(g_state, "read_scan_b_min", -1);
    rs_b_p50 = ace_state_get_l(g_state, "read_scan_b_p50", -1);
    if (rs_a_p50 > 0 && rs_b_p50 > 0)
        rs_ratio = (double)rs_a_p50 / (double)rs_b_p50;

    /* 独立系统调用计时 */
    {
        static uint64_t sc[SC_N];
        long j;
        for (j = 0; j < SC_N; j++) {
            uint64_t t0 = ace_now_ns();
            syscall(SYS_getpid);
            sc[j] = ace_now_ns() - t0;
        }
        sc_min = ace_min_of(sc, SC_N);
        sc_p50 = ace_percentile(sc, SC_N, 0.50);
        sc_p99 = ace_percentile(sc, SC_N, 0.99);
    }

    if (lb_p50)
        ratio_p50 = (double)la_p50 / (double)lb_p50;

    snprintf(hits, sizeof(hits),
             "lat_a min=%llu p50=%llu p99=%llu ns | lat_b min=%llu p50=%llu "
             "p99=%llu ns | ratio_p50=%.2f | read_scan_a min=%ld p50=%ld ns "
             "read_scan_b min=%ld p50=%ld ns rs_ratio=%.2f | getpid min=%llu "
             "p50=%llu p99=%llu ns",
             (unsigned long long)la_min, (unsigned long long)la_p50,
             (unsigned long long)la_p99, (unsigned long long)lb_min,
             (unsigned long long)lb_p50, (unsigned long long)lb_p99, ratio_p50,
             rs_a_min, rs_a_p50, rs_b_min, rs_b_p50, rs_ratio,
             (unsigned long long)sc_min, (unsigned long long)sc_p50,
             (unsigned long long)sc_p99);

    if (!la_p50 || !lb_p50) {
        ace_emit(stdout, "timing", "L4-timing", V_ERROR, 0, hits,
                 "延迟数据未就绪（labtarget 采样窗口为空）", g_json);
        return 1;
    }

    /* 判决：热路径 vs 控制页 */
    if (ratio_p50 >= 3.0 || la_p50 >= 300) {
        v = V_HOOKED;
        score = 85;
        snprintf(note, sizeof(note),
                 "H_A/H_B 延迟比 %.2f（H_A p50=%llu ns）：BRK/XOL 级开销特征"
                 "（>300ns 或 >3x）", ratio_p50, (unsigned long long)la_p50);
    } else if (ratio_p50 >= 1.5) {
        v = V_SUSPECT;
        score = 45;
        snprintf(note, sizeof(note),
                 "H_A/H_B 延迟比 %.2f：Cave 级开销特征（页内 B + 洞内跳转）",
                 ratio_p50);
    } else {
        snprintf(note, sizeof(note),
                 "H_A/H_B 延迟比 %.2f：与干净基线一致", ratio_p50);
    }

    /* 自读时序：全页顺序读 H_A vs H_B（读窗翻转/跷跷板每页付一次 fault） */
    if (rs_ratio >= 3.0 || rs_a_p50 > 5000) {
        if (score < 80)
            score = 80;
        v = V_HOOKED;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；自读时序 H_A p50=%ldns vs H_B p50=%ldns（比 %.2f）："
                 "读窗翻转/跷跷板翻页的扫描耗时特征（290304 时间差）",
                 rs_a_p50, rs_b_p50, rs_ratio);
    } else if (rs_ratio >= 1.5) {
        if (score < 40)
            score = 40;
        if (v == V_CLEAN)
            v = V_SUSPECT;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；自读时序比 %.2f 偏高（读页路径有异常开销）", rs_ratio);
    }

    /* 独立 syscall 层信号（次要证据） */
    if (sc_p50 > 5000) {
        if (score < 70)
            score = 70;
        if (v == V_CLEAN)
            v = V_SUSPECT;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；getpid p50=%llu ns 异常（>5us）：syscall 派发层疑似被挂",
                 (unsigned long long)sc_p50);
    }

    /* 功能层：调用值异常是强信号（42→99 的实验室形态） */
    if (mis_a > 0) {
        if (score < 90)
            score = 90;
        v = V_HOOKED;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；功能验证：%ld/%ld 次调用返回值偏离预期（调用被替换）",
                 mis_a, tot_a);
    }

    ace_emit(stdout, "timing", "L4-timing", v, score, hits, note, g_json);
    return (int)v;
}

/* ===== 库入口（JNI / 无 root App 内嵌模式，det_libify.py 生成） =====
 * 将 stdout 重定向到内存 buffer，伪造 argv 复用 impl_main。
 * 无 exec / 无 fork：App 进程内直接调用（Android untrusted_app 域
 * 禁止 exec app 私有 ELF，但 dlopen .so + 进程内调用完全合法）。 */
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>

int det_timing_run(const char *state_path, char *json_out, size_t outsz)
{
    FILE *f = fmemopen(json_out, outsz, "w");
    int saved, rc;
    char *fake[] = { (char *)"det_timing", (char *)"--state",
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
