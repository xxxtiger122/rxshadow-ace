/*
 * det_crossread.c — L2 跨进程读（GUP）信道
 *
 * 原理：rxshadow 对读 GUP（process_vm_readv / /proc/pid/mem / ptrace）
 *       开"隐藏窗"——短窗内把 PTE 翻回 original、读走后再翻回 shadow，
 *       （0.4.x 优先 skip_origin 直接返回 original page*）。于是：
 *
 *         受害者自读（自我视图）   → shadow 字节（Cave：页内 B/洞内代码）
 *         det_crossread GUP 读     → original 字节
 *
 *       两路 CRC 不一致 = 一 VA 两物理页的直接用户态证据。
 *
 * 独立性：本检测器不信任受害者的任何自报，自己通过 GUP 实际读页。
 * 用法：det_crossread --pid <pid> [--state <path>] [--json]
 * 依赖状态 key：pid va_a va_b crc_self_a crc_self_b crc_self_alpha
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/uio.h>
#include "ace_common.h"

#define RD_N 32
#define TRIES_DEFAULT 3

static const char *g_state;
static int g_json;
static pid_t g_pid = -1;
static int g_tries = TRIES_DEFAULT; /* 高频采样抓暴露窗（NPT 影子页短窗） */

/* GUP 读 32 字节：先 process_vm_readv，失败退回 /proc/pid/mem */
static int gup_read(pid_t pid, uint64_t va, uint8_t *out)
{
    struct iovec local, remote;
    ssize_t nr;
    int i;

    local.iov_base = out;
    local.iov_len = RD_N;
    remote.iov_base = (void *)(uintptr_t)va;
    remote.iov_len = RD_N;
    nr = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (nr == RD_N)
        return 0;

    {
        char path[64];
        int fd;
        snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
        fd = open(path, O_RDONLY);
        if (fd < 0)
            return -1;
        nr = pread(fd, out, RD_N, (off_t)va);
        close(fd);
        if (nr == RD_N)
            return 0;
    }
    /* 部分读取：逐 8 字节拼（GUP 窗竞态时可能半页翻回） */
    for (i = 0; i < RD_N / 8; i++) {
        uint64_t w = 0;
        ssize_t n;
        struct iovec l2 = { &w, 8 }, r2 = { (void *)(uintptr_t)(va + i * 8), 8 };
        n = process_vm_readv(pid, &l2, 1, &r2, 1, 0);
        if (n != 8)
            return -1;
        memcpy(out + i * 8, &w, 8);
    }
    return 0;
}

/* 返回 0=样本一致(未见分裂)，1=分裂/不稳定，-1=读失败 */
static int probe_split(pid_t pid, uint64_t va, uint32_t *crc_self_ref,
                       uint32_t *crc_gup_own)
{
    uint8_t buf[RD_N];
    int t;
    int split = 0;
    int n_unstable = 0;
    for (t = 0; t < g_tries; t++) {
        uint32_t c;
        if (gup_read(pid, va, buf) != 0)
            return -1;
        c = ace_crc32(buf, RD_N);
        if (t == 0)
            *crc_gup_own = c;
        else if (c != *crc_gup_own)
            split = 1, n_unstable++; /* 采样不稳定：窗口竞态/翻页 */
    }
    return split;
}

int main(int argc, char **argv)
{
    int i;
    uint64_t va_a = 0, va_b = 0;
    uint32_t crc_self_a = 0, crc_self_b = 0, crc_self_alpha = 0;
    uint32_t crc_gup_a = 0, crc_gup_b = 0, crc_gup_alpha = 0;
    int split_a, split_b, split_alpha;
    ace_verdict v = V_CLEAN;
    int score = 0;
    char hits[512] = "";
    char note[512] = "";
    long pid_state;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            g_pid = (pid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--state") && i + 1 < argc)
            g_state = argv[++i];
        else if (!strcmp(argv[i], "--json"))
            g_json = 1;
        else if (!strcmp(argv[i], "--tries") && i + 1 < argc) {
            g_tries = atoi(argv[++i]);
            if (g_tries < 1)
                g_tries = 1;
            if (g_tries > 1024)
                g_tries = 1024;
        }
    }
    if (!g_state)
        g_state = ace_default_state_path();

    pid_state = ace_state_get_l(g_state, "pid", -1);
    if (g_pid < 0)
        g_pid = (pid_t)pid_state;
    if (g_pid <= 0) {
        ace_emit(stdout, "crossread", "L2-cross-read-GUP", V_ERROR, 0, "",
                 "缺少目标 pid（--pid 或状态文件）", g_json);
        return 1;
    }
    if (kill(g_pid, 0) != 0) {
        ace_emit(stdout, "crossread", "L2-cross-read-GUP", V_ERROR, 0, "",
                 "目标进程不存在或不可达", g_json);
        return 1;
    }

    va_a = ace_state_get_u64(g_state, "va_a", 0);
    va_b = ace_state_get_u64(g_state, "va_b", 0);
    crc_self_a = (uint32_t)ace_state_get_u64(g_state, "crc_self_a", 0);
    crc_self_b = (uint32_t)ace_state_get_u64(g_state, "crc_self_b", 0);
    crc_self_alpha = (uint32_t)ace_state_get_u64(g_state, "crc_self_alpha", 0);

    if (va_a == 0) {
        ace_emit(stdout, "crossread", "L2-cross-read-GUP", V_ERROR, 0, "",
                 "状态文件缺少 va_a", g_json);
        return 1;
    }

    /* 独立 GUP 探测 */
    split_a = probe_split(g_pid, va_a, &crc_self_a, &crc_gup_a);
    split_b = va_b ? probe_split(g_pid, va_b, &crc_self_b, &crc_gup_b) : -1;
    split_alpha = -1;
    {
        uint64_t va_alpha = ace_state_get_u64(g_state, "va_alpha", 0);
        if (va_alpha)
            split_alpha = probe_split(g_pid, va_alpha, &crc_self_alpha,
                                      &crc_gup_alpha);
    }

    snprintf(hits, sizeof(hits),
             "va_a=0x%llx self_crc=0x%08x gup_crc=0x%08x%s"
             "%sva_b=0x%llx self_crc=0x%08x gup_crc=0x%08x%s",
             (unsigned long long)va_a, crc_self_a, crc_gup_a,
             split_a < 0 ? " gup_read=fail" : (split_a ? " gup_unstable" : ""),
             va_b ? " " : "",
             (unsigned long long)va_b, crc_self_b, crc_gup_b,
             split_b < 0 ? " gup_read=fail" : (split_b ? " gup_unstable" : ""));

    if (split_a < 0 || (va_b && split_b < 0)) {
        ace_emit(stdout, "crossread", "L2-cross-read-GUP", V_ERROR, score,
                 hits, "GUP 读取失败（权限/ptrace 受限）", g_json);
        return 1;
    }

    /* H_A：受害者自视图 vs 独立 GUP 视图 */
    if (crc_self_a != crc_gup_a) {
        v = V_HOOKED;
        score = 95;
        snprintf(note, sizeof(note),
                 "H_A 双视图分裂：受害者自读 0x%08x，GUP 读到 0x%08x —— "
                 "一 VA 两物理页的直接证据（Cave/跷跷板）", crc_self_a, crc_gup_a);
    } else {
        snprintf(note, sizeof(note), "H_A 双视图一致（自读==GUP），未见分裂");
    }
    if (split_a) {
        v = V_SUSPECT;
        if (score < 60)
            score = 60;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；GUP 读自身不稳定（翻页窗竞态）");
    }

    /* H_B 控制页：应该永远一致 */
    if (va_b && crc_self_b != crc_gup_b) {
        v = V_SUSPECT;
        if (score < 60)
            score = 60;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；H_B 控制页也分裂：hook 已超出 H_A 或 GUP 隐藏失效");
    }

    /* alpha 静态页：GUP 一致性（file-backed 页目前不可挂，应永远一致） */
    if (split_alpha >= 0 && crc_self_alpha != crc_gup_alpha) {
        v = V_SUSPECT;
        if (score < 70)
            score = 70;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；alpha 静态页分裂：file-backed 页也被挂或页被改");
    }

    ace_emit(stdout, "crossread", "L2-cross-read-GUP", v, score, hits, note, g_json);
    return (int)v;
}
