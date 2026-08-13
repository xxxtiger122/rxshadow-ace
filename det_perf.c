/*
 * det_perf.c — L4 perf/系统计数信道
 *
 * 源自看雪 290718 L2511（"高频调用不会被 perf 性能侧信道检测到？"）、
 * 292066 L1476（perf 统计 instructions/cycles/cache miss）、
 * 290871 L50（实测 267,735 次 fault/30s 信号强度）：
 *
 *   P1 perf_event_open 跨进程统计 victim：PERF_COUNT_SW_PAGE_FAULTS /
 *      PERF_COUNT_SW_CPU_CLOCK / PERF_COUNT_HW_CPU_CYCLES，窗口差分。
 *      异常驱动 hook（BRK/跷跷板翻页）每次命中至少 1 次 fault → 计数暴涨。
 *      （perf_event_open 对其它进程需 CAP_PERFMON/root；受限则降级）
 *   P2 /proc/vmstat pgfault 系统级差分（root）：全局 fault 风暴可观测。
 *   P3 /proc/interrupts TLB shootdown IPI 差分（292226 L445：跨核 TLB
 *      同步是唯一跨进程可见的信道；翻页通道收尾有全核 flush）。
 *   P4 smaps RSS 记账（290871 L242）：被挂页的 shadow 是内核匿名页，
 *      RSS 不涨但物理占用变化——RSS/共享页计数与基线不一致即异常。
 *
 * 用法：det_perf --pid <pid> [--state <path>] [--json]
 * 依赖状态 key：pid（其它字段仅辅助）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include "ace_common.h"

#ifndef SYS_perf_event_open
#define SYS_perf_event_open 241 /* arm64 */
#endif

static const char *g_state;
static int g_json;
static pid_t g_pid = -1;

static int perf_fd(pid_t pid, uint32_t type, uint64_t config)
{
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 1;
    attr.exclude_kernel = 0;
    attr.exclude_hv = 1;
    return (int)syscall(SYS_perf_event_open, &attr, pid, -1, -1,
                        PERF_FLAG_FD_CLOEXEC);
}

static long perf_read(int fd)
{
    long v = -1;
    if (fd >= 0 && read(fd, &v, sizeof(v)) == sizeof(v))
        return v;
    return -1;
}

/* /proc/vmstat 某个计数器的值 */
static unsigned long vmstat_get(const char *key)
{
    char *buf = ace_read_file("/proc/vmstat", NULL);
    char *line, *save = NULL;
    unsigned long v = 0;
    if (!buf)
        return 0;
    for (line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char k[64];
        unsigned long x;
        if (sscanf(line, "%63s %lu", k, &x) == 2 && !strcmp(k, key)) {
            v = x;
            break;
        }
    }
    free(buf);
    return v;
}

/* /proc/interrupts 里 TLB/IPI 类计数的总和 */
static unsigned long long irq_tlb_total(void)
{
    char *buf = ace_read_file("/proc/interrupts", NULL);
    unsigned long long sum = 0;
    char *line, *save = NULL;
    if (!buf)
        return 0;
    for (line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (strcasestr(line, "tlb") || strcasestr(line, "ipi") ||
            strcasestr(line, "reschedule") || strcasestr(line, "function")) {
            char *p = line;
            while (*p && *p != ':')
                p++;
            if (*p == ':') {
                p++;
                while (*p) {
                    unsigned long long v = 0;
                    while (*p == ' ')
                        p++;
                    if (*p < '0' || *p > '9')
                        break;
                    v = strtoull(p, &p, 10);
                    sum += v;
                }
            }
        }
    }
    free(buf);
    return sum;
}

/* smaps 汇总 Rss / Shared */
static void smaps_total(pid_t pid, unsigned long *rss, unsigned long *shared)
{
    char path[64];
    char *buf;
    char *line, *save = NULL;
    unsigned long r = 0, s = 0;
    snprintf(path, sizeof(path), "/proc/%d/smaps", (int)pid);
    buf = ace_read_file(path, NULL);
    if (!buf)
        return;
    for (line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        unsigned long v;
        if (sscanf(line, "Rss: %lu kB", &v) == 1)
            r += v;
        else if (sscanf(line, "Shared_Clean: %lu kB", &v) == 1 ||
                 sscanf(line, "Shared_Dirty: %lu kB", &v) == 1)
            s += v;
    }
    free(buf);
    if (rss) *rss = r;
    if (shared) *shared = s;
}

static int det_impl_main(int argc, char **argv)
{
    int i;
    ace_verdict v = V_CLEAN;
    int score = 0;
    char hits[1024] = "";
    char note[512] = "";
    int fd_pf = -1, fd_clk = -1, fd_cyc = -1;
    long pf0 = -1, pf1 = -1, clk0 = -1, clk1 = -1, cyc0 = -1, cyc1 = -1;
    unsigned long vm0 = 0, vm1 = 0;
    unsigned long long irq0 = 0, irq1 = 0;
    unsigned long rss0 = 0, sh0 = 0, rss1 = 0, sh1 = 0;
    double pf_rate = 0.0, clk_delta_ms = 0.0;
    int perf_ok = 0;

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
        ace_emit(stdout, "perf", "L4-perf-accounting", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }

    /* ---- P1: perf_event_open ---- */
    fd_pf = perf_fd(g_pid, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);
    fd_clk = perf_fd(g_pid, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);
    fd_cyc = perf_fd(g_pid, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
    if (fd_pf >= 0) {
        perf_ok = 1;
        ioctl(fd_pf, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd_pf, PERF_EVENT_IOC_ENABLE, 0);
        if (fd_clk >= 0) {
            ioctl(fd_clk, PERF_EVENT_IOC_RESET, 0);
            ioctl(fd_clk, PERF_EVENT_IOC_ENABLE, 0);
        }
        if (fd_cyc >= 0) {
            ioctl(fd_cyc, PERF_EVENT_IOC_RESET, 0);
            ioctl(fd_cyc, PERF_EVENT_IOC_ENABLE, 0);
        }
    }

    /* ---- P2/P3/P4: 系统级采样 ---- */
    vm0 = vmstat_get("pgfault");
    irq0 = irq_tlb_total();
    smaps_total(g_pid, &rss0, &sh0);

    usleep(1000000); /* 1s 窗口：victim 热路径持续活动 */

    if (perf_ok) {
        ioctl(fd_pf, PERF_EVENT_IOC_DISABLE, 0);
        pf1 = perf_read(fd_pf);
        if (fd_clk >= 0) {
            ioctl(fd_clk, PERF_EVENT_IOC_DISABLE, 0);
            clk1 = perf_read(fd_clk);
        }
        if (fd_cyc >= 0) {
            ioctl(fd_cyc, PERF_EVENT_IOC_DISABLE, 0);
            cyc1 = perf_read(fd_cyc);
        }
    }
    vm1 = vmstat_get("pgfault");
    irq1 = irq_tlb_total();
    smaps_total(g_pid, &rss1, &sh1);

    if (fd_pf >= 0)
        close(fd_pf);
    if (fd_clk >= 0)
        close(fd_clk);
    if (fd_cyc >= 0)
        close(fd_cyc);

    if (perf_ok && pf1 > 0 && clk1 > 0) {
        pf_rate = (double)pf1 * 1e9 / (double)clk1; /* faults/sec */
        clk_delta_ms = (double)clk1 / 1e6;
    }

    snprintf(hits, sizeof(hits),
             "perf_ok=%d pf=%ld clk_ns=%ld cyc=%ld (%.1f pf/s) "
             "vmstat_pgfault_delta=%lu irq_tlb_delta=%llu "
             "smaps_rss_delta=%ldkB shared_delta=%ldkB",
             perf_ok, pf1, clk1, cyc1, pf_rate, vm1 - vm0,
             irq1 - irq0,
             (long)(rss1 - rss0), (long)(sh1 - sh0));

    if (!perf_ok && vm1 == vm0) {
        ace_emit(stdout, "perf", "L4-perf-accounting", V_ERROR, 0, hits,
                 "perf 与 vmstat 均不可读（权限/容器限制），信道降级", g_json);
        return 1;
    }

    /* 判决：page-fault 速率是主信号（BRK/跷跷板命中=每次 1+ fault）*/
    if (perf_ok && pf_rate > 500) {
        v = V_HOOKED;
        score = 85;
        snprintf(note, sizeof(note),
                 "victim page-fault 速率 %.0f/s：异常驱动 hook 特征"
                 "（干净代码执行近零 fault）", pf_rate);
    } else if (vm1 - vm0 > 20000) {
        v = V_SUSPECT;
        score = 55;
        snprintf(note, sizeof(note),
                 "系统级 pgfault 增量 %lu/1s：全局异常风暴",
                 vm1 - vm0);
    } else if (perf_ok && pf_rate > 100) {
        v = V_SUSPECT;
        score = 40;
        snprintf(note, sizeof(note),
                 "victim page-fault 速率 %.0f/s：偏高，需对照基线",
                 pf_rate);
    } else {
        snprintf(note, sizeof(note),
                 "fault 速率正常（Cave 稳态零异常是设计目标）");
    }

    /* 次级证据：TLB shootdown IPI 差分 */
    if (irq1 - irq0 > 500) {
        if (score < 50)
            score = 50;
        if (v == V_CLEAN)
            v = V_SUSPECT;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；TLB shootdown IPI 增量 %llu/1s（翻页通道旁路）",
                 irq1 - irq0);
    }

    ace_emit(stdout, "perf", "L4-perf-accounting", v, score, hits, note, g_json);
    return (int)v;
}

/* ===== 库入口（JNI / 无 root App 内嵌模式，det_libify.py 生成） =====
 * 将 stdout 重定向到内存 buffer，伪造 argv 复用 impl_main。
 * 无 exec / 无 fork：App 进程内直接调用（Android untrusted_app 域
 * 禁止 exec app 私有 ELF，但 dlopen .so + 进程内调用完全合法）。 */
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>

int det_perf_run(const char *state_path, char *json_out, size_t outsz)
{
    FILE *f = fmemopen(json_out, outsz, "w");
    int saved, rc;
    char *fake[] = { (char *)"det_perf", (char *)"--state",
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
