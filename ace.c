/*
 * ace.c — ACE 聚合引擎
 *
 * 职责：
 *   F0 功能信道（内置）：直接读 labtarget 状态，调用值偏离预期
 *       （42→99）是最强的功能证据，不依赖任何检测器。
 *   调度：按权重运行 det_* 检测器（子进程，--json），解析统一契约。
 *   融合：加权平均 → 总判定（clean/suspect/hooked）+ 每信道明细 +
 *        stealth index（rxshadow 侧的存活信道数，即"无痕度"）。
 *
 * 权重（可 --weight <det>:<w> 覆盖）：
 *   F0 功能 25 / selfcrc 20 / elfhash 15 / crossread 20 / pagemap 15 /
 *   timing 10 / selfmod 10（默认不跑：会销毁 hook）/ procscan 5 /
 *   trampoline 12 / callstack 15 / hwbp 5 / kallsyms 2 / kcore 2 /
 *   dmesg 2 / sysfs 2
 *
 * 用法：
 *   ace [--pid <pid>] [--state <path>] [--json] [--out <file>]
 *       [--det <name>[,<name>...]] [--with-selfmod] [--weight <det>:<w>]
 * 退出码：0 clean / 1 suspect / 2 hooked / 3 error
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "ace_common.h"

#define DET_MAX 16

struct det {
    const char *name;
    const char *channel;
    int weight;
    int run;           /* 本次是否运行 */
    ace_verdict v;
    int score;
    char hits[2048];
    char note[512];
    int skipped;
};

static struct det g_dets[] = {
    { "det_selfcrc",    "L1-self-integrity",    20, 1, V_ERROR, 0, "", "", 0 },
    { "det_elfhash",    "L2-elf-integrity",     15, 1, V_ERROR, 0, "", "", 0 },
    { "det_crossread",  "L2-cross-read-GUP",    20, 1, V_ERROR, 0, "", "", 0 },
    { "det_pagemap",    "L3-pagemap-PFN",       15, 1, V_ERROR, 0, "", "", 0 },
    { "det_timing",     "L4-timing",            10, 1, V_ERROR, 0, "", "", 0 },
    { "det_faultcount", "L4-accounting",        10, 1, V_ERROR, 0, "", "", 0 },
    { "det_perf",       "L4-perf-accounting",    8, 1, V_ERROR, 0, "", "", 0 },
    { "det_diff",       "L2-differential",      12, 0, V_ERROR, 0, "", "", 0 },
    { "det_selfmod",    "L6-write-semantics",   10, 0, V_ERROR, 0, "", "", 0 },
    { "det_procscan",   "L7-proc-audit",         5, 1, V_ERROR, 0, "", "", 0 },
    { "det_trampoline", "L7-exec-memory-audit", 12, 1, V_ERROR, 0, "", "", 0 },
    { "det_callstack",  "L7-exec-flow-audit",   15, 1, V_ERROR, 0, "", "", 0 },
    { "det_hwbp",       "L7-hwbp-audit",         5, 1, V_ERROR, 0, "", "", 0 },
    { "det_linkmap",    "L7-addrspace-semantics", 5, 1, V_ERROR, 0, "", "", 0 },
    { "det_kallsyms",   "L5-kallsyms-layout",    2, 1, V_ERROR, 0, "", "", 0 },
    { "det_kcore",      "L5-kcore-audit",        2, 1, V_ERROR, 0, "", "", 0 },
    { "det_dmesg",      "L5-dmesg-forensics",    2, 1, V_ERROR, 0, "", "", 0 },
    { "det_sysfs",      "L5-sysfs-fingerprint",  2, 1, V_ERROR, 0, "", "", 0 },
};
#define NDET ((int)(sizeof(g_dets) / sizeof(g_dets[0])))

static const char *g_state;
static const char *g_state2;
static int g_json;
static FILE *g_out;
static pid_t g_pid = -1;
static int g_f0_score = 0;
static ace_verdict g_f0_v = V_CLEAN;
static char g_f0_note[512] = "";

static struct det *find_det(const char *name)
{
    int i;
    for (i = 0; i < NDET; i++)
        if (!strcmp(g_dets[i].name, name))
            return &g_dets[i];
    if (!strncmp(name, "det_", 4))
        return NULL;
    for (i = 0; i < NDET; i++)
        if (!strncmp(g_dets[i].name, "det_", 4) &&
            !strcmp(g_dets[i].name + 4, name))
            return &g_dets[i];
    return NULL;
}

/* ---- F0 功能信道 ---- */
static void f0_run(void)
{
    long mis_a = ace_state_get_l(g_state, "mis_a", -1);
    long call_a = ace_state_get_l(g_state, "call_a", -1);
    long expected = ace_state_get_l(g_state, "expected_a", 42);
    long tot_a = ace_state_get_l(g_state, "tot_a", 0);
    int hooked = (int)ace_state_get_l(g_state, "hooked", 0);

    if (mis_a < 0 && call_a < 0) {
        g_f0_v = V_ERROR;
        g_f0_score = 0;
        snprintf(g_f0_note, sizeof(g_f0_note),
                 "状态文件缺失（labtarget 未运行？）");
        return;
    }
    if (mis_a > 0) {
        g_f0_v = V_HOOKED;
        g_f0_score = 100;
        snprintf(g_f0_note, sizeof(g_f0_note),
                 "功能信道：%ld/%ld 次调用返回值偏离预期 %ld（热路径被替换）",
                 mis_a, tot_a, expected);
    } else if (call_a != expected) {
        g_f0_v = V_HOOKED;
        g_f0_score = 95;
        snprintf(g_f0_note, sizeof(g_f0_note),
                 "功能信道：call_a=%ld != expected=%ld", call_a, expected);
    } else if (hooked) {
        g_f0_v = V_SUSPECT;
        g_f0_score = 55;
        snprintf(g_f0_note, sizeof(g_f0_note),
                 "功能信道：调用值正常但 victim 自报 hooked=1（双视图分裂）");
    } else {
        g_f0_v = V_CLEAN;
        g_f0_score = 0;
        snprintf(g_f0_note, sizeof(g_f0_note),
                 "功能信道：call_a=%ld == expected=%ld，%ld 次调用无偏离",
                 call_a, expected, tot_a);
    }
}

/* ---- 子进程运行一个检测器，解析 JSON ---- */
static void run_det(struct det *d)
{
    int pipefd[2];
    pid_t pid;
    char buf[16384];
    size_t got = 0;
    ssize_t n;
    int status;
    char *p;

    if (pipe(pipefd) != 0) {
        d->skipped = 1;
        return;
    }
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        d->skipped = 1;
        return;
    }
    if (pid == 0) {
        char *av[8];
        int ai = 0;
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        av[ai++] = (char *)d->name;
        if (g_pid > 0) {
            av[ai++] = (char *)"--pid";
            {
                static char pbuf[32];
                snprintf(pbuf, sizeof(pbuf), "%d", (int)g_pid);
                av[ai++] = pbuf;
            }
        }
        av[ai++] = (char *)"--state";
        av[ai++] = (char *)g_state;
        if (g_state2 && !strcmp(d->name, "det_diff")) {
            av[ai++] = (char *)"--state2";
            av[ai++] = (char *)g_state2;
        }
        av[ai++] = (char *)"--json";
        av[ai] = NULL;
        execvp(d->name, av);
        _exit(127);
    }
    close(pipefd[1]);
    while (got < sizeof(buf) - 1 &&
           (n = read(pipefd[0], buf + got, sizeof(buf) - 1 - got)) > 0)
        got += (size_t)n;
    buf[got] = 0;
    close(pipefd[0]);
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
        d->skipped = 1;
        snprintf(d->note, sizeof(d->note), "检测器二进制不存在");
        return;
    }
    /* 解析契约字段 */
    p = strstr(buf, "\"verdict\":\"");
    if (p) {
        p += 11;
        if (!strncmp(p, "clean", 5))
            d->v = V_CLEAN;
        else if (!strncmp(p, "suspect", 7))
            d->v = V_SUSPECT;
        else if (!strncmp(p, "hooked", 6))
            d->v = V_HOOKED;
        else
            d->v = V_ERROR;
    }
    p = strstr(buf, "\"score\":");
    if (p)
        d->score = atoi(p + 8);
    p = strstr(buf, "\"hits\":\"");
    if (p) {
        char *end = strchr(p + 8, '"');
        size_t n2 = end ? (size_t)(end - (p + 8)) : 0;
        if (n2 > sizeof(d->hits) - 1)
            n2 = sizeof(d->hits) - 1;
        memcpy(d->hits, p + 8, n2);
        d->hits[n2] = 0;
    }
    p = strstr(buf, "\"note\":\"");
    if (p) {
        char *end = strchr(p + 8, '"');
        size_t n2 = end ? (size_t)(end - (p + 8)) : 0;
        if (n2 > sizeof(d->note) - 1)
            n2 = sizeof(d->note) - 1;
        memcpy(d->note, p + 8, n2);
        d->note[n2] = 0;
    }
    if (d->v == V_ERROR && !d->note[0])
        snprintf(d->note, sizeof(d->note), "检测器异常退出 status=%d", status);
}

int main(int argc, char **argv)
{
    int i;
    const char *out_path = NULL;
    long f0_w = 25;
    long double total_w = 0, acc = 0;
    int n_live = 0;
    int exit_clean = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            g_pid = (pid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--state") && i + 1 < argc)
            g_state = argv[++i];
        else if (!strcmp(argv[i], "--state2") && i + 1 < argc) {
            g_state2 = argv[++i];
            /* 差分对照需要第二个 victim 状态 → 自动启用 det_diff */
            {
                struct det *d = find_det("diff");
                if (d)
                    d->run = 1;
            }
        }
        else if (!strcmp(argv[i], "--json"))
            g_json = 1;
        else if (!strcmp(argv[i], "--out") && i + 1 < argc)
            out_path = argv[++i];
        else if (!strcmp(argv[i], "--with-selfmod")) {
            struct det *d = find_det("selfmod");
            if (d)
                d->run = 1;
        } else if (!strcmp(argv[i], "--det") && i + 1 < argc) {
            char *tok, *save = NULL;
            for (tok = strtok_r(argv[++i], ",", &save); tok;
                 tok = strtok_r(NULL, ",", &save)) {
                struct det *d = find_det(tok);
                if (d)
                    d->run = 1;
            }
        } else if (!strcmp(argv[i], "--weight") && i + 1 < argc) {
            char name[64];
            int w;
            if (sscanf(argv[++i], "%63[^:]:%d", name, &w) == 2) {
                struct det *d = find_det(name);
                if (d)
                    d->weight = w;
            }
        }
    }
    if (!g_state)
        g_state = ace_default_state_path();
    if (g_pid < 0)
        g_pid = (pid_t)ace_state_get_l(g_state, "pid", -1);

    g_out = out_path ? fopen(out_path, "w") : stdout;
    if (!g_out) {
        fprintf(stderr, "ace: 无法写 --out %s\n", out_path);
        return 3;
    }

    f0_run();

    for (i = 0; i < NDET; i++)
        if (g_dets[i].run)
            run_det(&g_dets[i]);

    /* ---- 融合（F0 + 检测器；error/skip 的权重不参与） ---- */
    if (g_f0_v != V_ERROR) {
        total_w += f0_w;
        acc += (long double)g_f0_score * f0_w;
        n_live++;
    }
    for (i = 0; i < NDET; i++) {
        struct det *d = &g_dets[i];
        if (!d->run || d->skipped || d->v == V_ERROR)
            continue;
        total_w += d->weight;
        acc += (long double)d->score * d->weight;
        n_live++;
    }
    if (total_w == 0) {
        if (g_json)
            fprintf(g_out, "{\"det\":\"ace\",\"verdict\":\"error\",\"score\":0,"
                           "\"note\":\"无可融合信道\"}\n");
        else
            fprintf(g_out, "[ace] 无可融合信道（全部 error/skip）\n");
        if (g_out != stdout)
            fclose(g_out);
        return 3;
    }

    {
        int score = (int)(acc / total_w);
        ace_verdict v = ace_score_verdict(score);
        int stealth = 0, caught = 0;
        char table[4096] = "";

        for (i = 0; i < NDET; i++) {
            struct det *d = &g_dets[i];
            if (d->run && d->v != V_ERROR && !d->skipped) {
                if (d->v == V_HOOKED)
                    caught++;
                else if (d->v == V_CLEAN)
                    stealth++;
            }
        }
        if (g_f0_v == V_HOOKED)
            caught++;
        else if (g_f0_v == V_CLEAN)
            stealth++;

        snprintf(table, sizeof(table),
                 "F0-functional score=%d %s\n", g_f0_score,
                 ace_verdict_str(g_f0_v));
        for (i = 0; i < NDET; i++) {
            struct det *d = &g_dets[i];
            if (!d->run) {
                snprintf(table + strlen(table), sizeof(table) - strlen(table),
                         "%s (disabled)\n", d->channel);
            } else if (d->skipped || d->v == V_ERROR) {
                snprintf(table + strlen(table), sizeof(table) - strlen(table),
                         "%s (error: %s)\n", d->channel,
                         d->note[0] ? d->note : "unavailable");
            } else {
                snprintf(table + strlen(table), sizeof(table) - strlen(table),
                         "%s score=%d %s%s%s\n", d->channel, d->score,
                         ace_verdict_str(d->v),
                         d->hits[0] ? " hits=[" : "",
                         d->hits[0] ? d->hits : "");
                if (d->hits[0])
                    snprintf(table + strlen(table),
                             sizeof(table) - strlen(table), "]");
                if (d->note[0])
                    snprintf(table + strlen(table),
                             sizeof(table) - strlen(table), "  note: %s",
                             d->note);
            }
        }

        if (g_json) {
            fprintf(g_out, "{\"det\":\"ace\",\"channel\":\"aggregate\",");
            ace_json_field_verdict(g_out, "verdict", v);
            ace_json_field_int(g_out, "score", score);
            ace_json_field_int(g_out, "channels_live", n_live);
            ace_json_field_int(g_out, "channels_hooked", caught);
            ace_json_field_int(g_out, "channels_clean", stealth);
            fprintf(g_out, "\"note\":\"%s\"}\n", g_f0_note);
        } else {
            fprintf(g_out,
                    "===== ACE 汇总 =====\n"
                    "总体判定 : %s (score=%d/100, %d 信道存活, %d 命中, %d 干净)\n"
                    "stealth  : %d 个信道对 hook 无感（rxshadow 存活信道数）\n"
                    "--- 明细 ---\n%s--- F0 ---\n%s\n",
                    ace_verdict_str(v), score, n_live, caught, stealth,
                    stealth, table, g_f0_note);
        }
        exit_clean = (int)v;
    }

    if (g_out != stdout)
        fclose(g_out);
    return exit_clean;
}
