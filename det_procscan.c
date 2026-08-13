/*
 * det_procscan.c — L7 进程/线程审计信道
 *
 * 源自看雪 277402（Hunter）：沙箱/注入器会在主进程之外多起进程，
 * 检测 /proc 下是否出现"不属于本进程的可疑 PID"。结合：
 *   P1 TracerPid 审计：/proc/<pid>/status 的 TracerPid != 0 = 被调试/
 *      ptrace 注入中（内核态 hook 的 GUP/执行面常借助 ptrace 调试器）
 *   P2 同 UID 额外进程：与 victim 同 UID 的兄弟进程（注入器形态）
 *   P3 注入路径指纹：maps 里出现 frida/zygisk/riru/xposed/lsposed 等
 *   P4 线程数异常：task 数远超预期
 *
 * 注意：det_callstack / det_hwbp 会短暂设置 TracerPid —— 本检测器应
 *       在它们之前或之后独立运行；ace 默认顺序 procscan 在 callstack 前。
 * 用法：det_procscan --pid <pid> [--state <path>] [--json]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include "ace_common.h"

static const char *g_state;
static int g_json;
static pid_t g_pid = -1;

static const char *inject_markers[] = {
    "frida", "gadget", "zygisk", "riru", "xposed", "lsposed",
    "whale", "sandhook", "epic", "dex2oat", "magisk", NULL
};

int main(int argc, char **argv)
{
    int i;
    char hits[2048] = "";
    char note[512] = "";
    ace_verdict v = V_CLEAN;
    int score = 0;
    long tracer = -1;
    int n_tids = 0, n_extra_proc = 0, n_marker = 0;
    char uid_buf[32] = "";
    long victim_uid = -1;

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
        ace_emit(stdout, "procscan", "L7-proc-audit", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }

    /* P1: TracerPid + UID */
    {
        char path[64];
        char *buf;
        char *line, *save = NULL;
        snprintf(path, sizeof(path), "/proc/%d/status", (int)g_pid);
        buf = ace_read_file(path, NULL);
        if (buf) {
            for (line = strtok_r(buf, "\n", &save); line;
                 line = strtok_r(NULL, "\n", &save)) {
                if (!strncmp(line, "TracerPid:", 10)) {
                    tracer = strtol(line + 10, NULL, 10);
                } else if (!strncmp(line, "Uid:", 4)) {
                    sscanf(line + 4, "%s", uid_buf);
                    victim_uid = strtol(uid_buf, NULL, 10);
                }
            }
            free(buf);
        }
        if (tracer > 0)
            snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                     "TracerPid=%ld ", tracer);
    }

    /* P2: 同 UID 额外进程（UID==0 时无隔离意义——容器/root 环境跳过） */
    if (victim_uid > 0) {
        DIR *d = opendir("/proc");
        struct dirent *de;
        if (d) {
            while ((de = readdir(d)) != NULL) {
                pid_t p;
                char spath[64];
                char *sbuf;
                char *line, *save = NULL;
                if (de->d_name[0] < '0' || de->d_name[0] > '9')
                    continue;
                p = (pid_t)atoi(de->d_name);
                if (p == g_pid)
                    continue;
                snprintf(spath, sizeof(spath), "/proc/%s/status", de->d_name);
                sbuf = ace_read_file(spath, NULL);
                if (!sbuf)
                    continue;
                for (line = strtok_r(sbuf, "\n", &save); line;
                     line = strtok_r(NULL, "\n", &save)) {
                    char ub[32] = "";
                    if (!strncmp(line, "Uid:", 4)) {
                        sscanf(line + 4, "%s", ub);
                        if (strtol(ub, NULL, 10) == victim_uid) {
                            n_extra_proc++;
                            if (n_extra_proc <= 6) {
                                char comm[64] = "";
                                char cp[80];
                                snprintf(cp, sizeof(cp), "/proc/%d/comm", (int)p);
                                {
                                    FILE *cf = fopen(cp, "r");
                                    if (cf) {
                                        fgets(comm, sizeof(comm), cf);
                                        fclose(cf);
                                    }
                                }
                                snprintf(hits + strlen(hits),
                                         sizeof(hits) - strlen(hits),
                                         "extra_proc=%d(%s) ", (int)p, comm);
                            }
                        }
                        break;
                    }
                }
                free(sbuf);
            }
            closedir(d);
        }
    }

    /* P3: 注入路径指纹 */
    {
        char path[64];
        char *buf;
        snprintf(path, sizeof(path), "/proc/%d/maps", (int)g_pid);
        buf = ace_read_file(path, NULL);
        if (buf) {
            for (i = 0; inject_markers[i]; i++) {
                if (strstr(buf, inject_markers[i])) {
                    n_marker++;
                    snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                             "marker=%s ", inject_markers[i]);
                }
            }
            free(buf);
        }
    }

    /* P4: 线程数 */
    {
        char tpath[64];
        DIR *d;
        struct dirent *de;
        snprintf(tpath, sizeof(tpath), "/proc/%d/task", (int)g_pid);
        d = opendir(tpath);
        if (d) {
            while ((de = readdir(d)) != NULL) {
                if (de->d_name[0] != '.')
                    n_tids++;
            }
            closedir(d);
        }
        snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                 "tids=%d", n_tids);
    }

    if (tracer > 0) {
        v = V_HOOKED;
        score = 90;
        snprintf(note, sizeof(note),
                 "TracerPid=%ld：进程正被 ptrace（调试器/注入器/GUP 助手）",
                 tracer);
    } else if (n_marker > 0) {
        v = V_HOOKED;
        score = 80;
        snprintf(note, sizeof(note),
                 "maps 含 %d 个注入框架指纹（frida/zygisk/xposed...）", n_marker);
    } else if (n_extra_proc > 0) {
        v = V_SUSPECT;
        score = 45;
        snprintf(note, sizeof(note),
                 "%d 个同 UID 额外进程（沙箱/注入器形态）", n_extra_proc);
    } else {
        snprintf(note, sizeof(note),
                 "无 TracerPid、无注入指纹、无同 UID 额外进程（tids=%d）",
                 n_tids);
    }

    ace_emit(stdout, "procscan", "L7-proc-audit", v, score, hits, note, g_json);
    return (int)v;
}
