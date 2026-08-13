/*
 * det_trampoline.c — L7 可执行内存审计信道（Trampoline 扫描）
 *
 * 源自看雪 290718：传统 Inline Hook 的致命伤是跳板（trampoline）必须
 * 存在于一块"匿名 + 可执行"的内存里。顶级反作弊遍历 /proc/self/maps，
 * 只要发现"未归属任何白名单 SO 且带 x 权限的匿名内存"即判定外挂。
 *
 * 对 rxshadow：labtarget 的 H 区（匿名可执行页）就是这种形态 ——
 * 双视图方案保护了"代码字节不可见"，但不保护"多了一块可执行内存"
 * 这个事实。本信道打的就是这个观测面。
 *
 * 基线：victim 自带匿名可执行页（如 labtarget H 区）经
 *       anon_exec_base_bytes 抵消 —— 超出基线的字节才算 hook 引入。
 *       相邻同权限匿名页会被内核合并成一个 VMA，所以按字节数对比。
 *
 * 白名单（不判异常的匿名可执行段）：
 *   [vdso] [vvar] [vsyscall] — 内核映射
 *   dalvik-jit-code-cache*    — Android ART JIT
 *
 * 用法：det_trampoline --pid <pid> [--state <path>] [--json]
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

struct xmap {
    uint64_t start, end;
    char perms[8];
    char path[256];
};

static int is_whitelisted(const char *path)
{
    if (!path || !path[0])
        return 0;
    if (!strcmp(path, "[vdso]") || !strcmp(path, "[vvar]") ||
        !strcmp(path, "[vsyscall]"))
        return 1;
    if (strstr(path, "dalvik-jit-code-cache"))
        return 1; /* ART JIT */
    if (strstr(path, "jit-cache") || strstr(path, "jit-zygote-cache"))
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    int i;
    struct xmap maps[512];
    int nmap = 0;
    char *buf = NULL;
    char *line, *save = NULL;
    int n_anon_exec = 0, n_anon_exec_nw = 0;
    uint64_t anon_nw_bytes = 0, anon_bytes = 0;
    long base_bytes = 0;
    char hits[2048] = "";
    char note[512] = "";
    ace_verdict v = V_CLEAN;
    int score = 0;

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
        ace_emit(stdout, "trampoline", "L7-exec-memory-audit", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }
    base_bytes = ace_state_get_l(g_state, "anon_exec_base_bytes", 0);

    {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/maps", (int)g_pid);
        buf = ace_read_file(path, NULL);
    }
    if (!buf) {
        ace_emit(stdout, "trampoline", "L7-exec-memory-audit", V_ERROR, 0, "",
                 "maps 不可读", g_json);
        return 1;
    }
    for (line = strtok_r(buf, "\n", &save); line && nmap < 512;
         line = strtok_r(NULL, "\n", &save)) {
        struct xmap *m = &maps[nmap];
        char p[8];
        uint64_t a, b;
        char path[256] = "";
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %255s",
                   (unsigned long long *)&a, (unsigned long long *)&b,
                   p, path) >= 3) {
            m->start = a;
            m->end = b;
            snprintf(m->perms, sizeof(m->perms), "%s", p);
            snprintf(m->path, sizeof(m->path), "%s", path);
            nmap++;
        }
    }
    free(buf);

    for (i = 0; i < nmap; i++) {
        struct xmap *m = &maps[i];
        if (strchr(m->perms, 'x') && !m->path[0]) {
            /* 匿名 + 可执行 */
            anon_bytes += m->end - m->start;
            n_anon_exec++;
            if (!is_whitelisted(m->path)) {
                anon_nw_bytes += m->end - m->start;
                if (n_anon_exec_nw <= 8)
                    snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                             "anon_r-x[0x%llx-0x%llx %lluKB %s] ",
                             (unsigned long long)m->start,
                             (unsigned long long)m->end,
                             (unsigned long long)((m->end - m->start) / 1024),
                             m->perms);
                n_anon_exec_nw++;
            }
        }
    }
    /* 基线抵消：victim 自带（labtarget H 区）不算 hook 引入 */
    if (anon_nw_bytes > (uint64_t)base_bytes)
        n_anon_exec_nw = 1; /* 超出基线的匿名可执行字节 = hook 引入 */
    else
        n_anon_exec_nw = 0;

    snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
             "anon_exec_total=%d anon_exec_bytes=%llu base_bytes=%ld",
             n_anon_exec, (unsigned long long)anon_bytes, base_bytes);

    if (n_anon_exec_nw > 0) {
        v = V_HOOKED;
        score = 75 + (n_anon_exec_nw > 1 ? 15 : 0);
        snprintf(note, sizeof(note),
                 "匿名可执行字节超出基线（%llu > %ld）：trampoline/DBI 跳板"
                 "形态（Frida、inline hook 跳板都长这样）",
                 (unsigned long long)anon_nw_bytes, base_bytes);
    } else if (n_anon_exec > 0) {
        /* 全部在基线内：victim 自带（labtarget H 区）→ clean */
        v = V_CLEAN;
        score = 0;
        snprintf(note, sizeof(note),
                 "%d 块匿名可执行页（%llu 字节）全部在基线内（victim 自带 H 区）",
                 n_anon_exec, (unsigned long long)anon_bytes);
    } else {
        snprintf(note, sizeof(note), "无可疑匿名可执行页");
    }

    ace_emit(stdout, "trampoline", "L7-exec-memory-audit", v, score, hits, note, g_json);
    return (int)v;
}
