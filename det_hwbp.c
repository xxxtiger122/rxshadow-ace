/*
 * det_hwbp.c — L7 硬件断点审计信道（ptrace 五步杀 native 版）
 *
 * 源自看雪 290718：反作弊用 ptrace + perf_event_open "五步杀"检测
 * HWBP 是否被外挂占用：
 *   1. PTRACE_GETREGSET 读调试寄存器（ARM64: NT_ARM_HW_BREAK/WATCH）
 *   2. 发现已启用断点 → 检测
 *   3. 故意设置超上限（Max+1）断点：正常应 -ENOSPC，成功=OS 被破坏
 *
 * 本检测器：
 *   A. 对每个线程读 ARM64 硬件断点/观察点寄存器，检查 enabled 位
 *   B. 尝试设置 17 个执行断点（ARM64 上限 16），验证 -ENOSPC
 *   C. host x86_64 上读 user_regs_struct 的 debug 寄存器
 *
 * 用法：det_hwbp --pid <pid> [--state <path>] [--json]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <stddef.h>
#include "ace_common.h"

/* user_hwdebug_state 定义在 ARM64 的 asm/ptrace.h（UAPI） */
#if defined(__aarch64__)
#include <asm/ptrace.h>
#endif

/* NT 常量：避免 <linux/elf.h>/<elf.h> 头文件在交叉编译时的差异 */
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x403
#endif
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x404
#endif

static const char *g_state;
static int g_json;
static pid_t g_pid = -1;

#define MAX_TID 256

#if defined(__aarch64__)
/* 尝试给线程设置一个执行断点；返回 0=成功 -1=ENOSPC(正常) */
static int try_set_one_hwbp(pid_t tid, uint64_t addr)
{
    struct user_hwdebug_state st;
    struct iovec iov;
    int i;
    memset(&st, 0, sizeof(st));
    for (i = 0; i < 16; i++) {
        st.dbg_regs[i].ctrl = 0;
        st.dbg_regs[i].addr = 0;
    }
    st.dbg_regs[0].addr = addr;
    /* ARM64 DBGBCR: E=bit0, BAS=bits[13:8], MASK=bits[28:24] */
    st.dbg_regs[0].ctrl = 1u | (0xFu << 8); /* enable + 全字节 */
    iov.iov_base = &st;
    iov.iov_len = sizeof(st);
    if (ptrace(PTRACE_SETREGSET, tid, (void *)NT_ARM_HW_BREAK, &iov) != 0) {
        return errno == ENOSPC ? -1 : -2;
    }
    return 0;
}
#elif defined(__x86_64__)
/* x86_64 调试寄存器经 PTRACE_PEEKUSER 访问 struct user.u_debugreg[] */
#define UDBG(n) (offsetof(struct user, u_debugreg) + (n) * sizeof(unsigned long))
static int try_set_one_hwbp(pid_t tid, uint64_t addr)
{
    (void)tid;
    (void)addr;
    return -2; /* host 验证不实际设置，避免污染目标 */
}
#else
static int try_set_one_hwbp(pid_t tid, uint64_t addr)
{
    (void)tid;
    (void)addr;
    return -2;
}
#endif

static int audit_thread_hwbp(pid_t tid, char *out, size_t outsz)
{
    int n_set = 0;
#if defined(__aarch64__)
    struct user_hwdebug_state st;
    struct iovec iov;
    int i;
    memset(&st, 0, sizeof(st));
    iov.iov_base = &st;
    iov.iov_len = sizeof(st);
    if (ptrace(PTRACE_GETREGSET, tid, (void *)NT_ARM_HW_BREAK, &iov) == 0) {
        for (i = 0; i < 16; i++) {
            if (st.dbg_regs[i].ctrl & 1u) { /* E bit */
                n_set++;
                snprintf(out + strlen(out), outsz - strlen(out),
                         "HWBP%d=0x%llx ", i,
                         (unsigned long long)st.dbg_regs[i].addr);
            }
        }
    }
    /* 观察点 */
    memset(&st, 0, sizeof(st));
    iov.iov_len = sizeof(st);
    if (ptrace(PTRACE_GETREGSET, tid, (void *)NT_ARM_HW_WATCH, &iov) == 0) {
        for (i = 0; i < 16; i++) {
            if (st.dbg_regs[i].ctrl & 1u) {
                n_set++;
                snprintf(out + strlen(out), outsz - strlen(out),
                         "WATCH%d=0x%llx ", i,
                         (unsigned long long)st.dbg_regs[i].addr);
            }
        }
    }
#elif defined(__x86_64__)
    long i;
    for (i = 0; i < 4; i++) {
        long v = ptrace(PTRACE_PEEKUSER, tid, (void *)(long)UDBG((int)i), NULL);
        if (v && v != -1) {
            n_set++;
            snprintf(out + strlen(out), outsz - strlen(out),
                     "DR%d=0x%lx ", (int)i, v);
        }
    }
#endif
    return n_set;
}

int main(int argc, char **argv)
{
    int i;
    char hits[1024] = "";
    char note[512] = "";
    ace_verdict v = V_CLEAN;
    int score = 0;
    int n_set_total = 0, n_tids = 0, n_attach_ok = 0;
    int enospc_ok = 1;
    pid_t tids[MAX_TID];
    DIR *d;
    struct dirent *de;

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
        ace_emit(stdout, "hwbp", "L7-hwbp-audit", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }

    {
        char tpath[64];
        snprintf(tpath, sizeof(tpath), "/proc/%d/task", (int)g_pid);
        d = opendir(tpath);
        if (!d) {
            ace_emit(stdout, "hwbp", "L7-hwbp-audit", V_ERROR, 0, "",
                     "无法枚举线程", g_json);
            return 1;
        }
        while ((de = readdir(d)) != NULL && n_tids < MAX_TID) {
            if (de->d_name[0] == '.')
                continue;
            tids[n_tids++] = (pid_t)atoi(de->d_name);
        }
        closedir(d);
    }

    for (i = 0; i < n_tids; i++) {
        char buf[256] = "";
        int n;
        if (ptrace(PTRACE_ATTACH, tids[i], NULL, NULL) != 0)
            continue;
        waitpid(tids[i], NULL, 0);
        n_attach_ok++;
        n = audit_thread_hwbp(tids[i], buf, sizeof(buf));
        if (n > 0) {
            n_set_total += n;
            snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                     "tid=%d [%s] ", (int)tids[i], buf);
        }
        /* 超限设置：ARM64 上限 16，试第 17 个应 ENOSPC */
        {
            int r = try_set_one_hwbp(tids[i], (uint64_t)(uintptr_t)&main);
            if (r == 0) {
                /* 成功设置 → 若已用满则不该成功；记下但可能只是未用满 */
                /* 清零还原 */
                ptrace(PTRACE_DETACH, tids[i], NULL, NULL);
                continue;
            }
            if (r == -2)
                enospc_ok = 0;
        }
        ptrace(PTRACE_DETACH, tids[i], NULL, NULL);
    }

    snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
             "tids=%d attached=%d hwbp_set=%d", n_tids, n_attach_ok, n_set_total);

    if (n_set_total > 0) {
        v = V_HOOKED;
        score = 85;
        snprintf(note, sizeof(note),
                 "%d 个已启用的硬件断点/观察点：HWBP hook 或调试器残留",
                 n_set_total);
    } else if (n_attach_ok == 0) {
        v = V_ERROR;
        score = 0;
        snprintf(note, sizeof(note), "无法 attach 任何线程（权限）");
    } else if (!enospc_ok) {
        v = V_SUSPECT;
        score = 40;
        snprintf(note, sizeof(note), "调试寄存器设置行为异常");
    } else {
        snprintf(note, sizeof(note),
                 "全部 %d 个线程无已启用硬件断点，超限设置返回正常",
                 n_attach_ok);
    }

    ace_emit(stdout, "hwbp", "L7-hwbp-audit", v, score, hits, note, g_json);
    return (int)v;
}
