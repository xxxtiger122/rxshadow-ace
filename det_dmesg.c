/*
 * det_dmesg.c — L5 内核日志取证信道
 *
 * rxshadow / KernelPatch / ksud 加载或活动时会在 dmesg 留痕
 * （rxshadow 自己 logkd 输出 "rxshadow: ..."，KernelPatch 加载有
 *   "kpatch"/"KernelPatch" 字样，ksud 有 kpm 加载日志）。
 *
 * 用法：det_dmesg [--json]
 * 来源：dmesg 命令 → 回退 /dev/kmsg（root 直读）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "ace_common.h"

static const char *pat_strong[] = {
    "rxshadow", "kpm", "ksud", "kernelpatch", "kpatch", NULL
};
static const char *pat_weak[] = {
    "follow_page_pte", "pte_to_pagemap", "dup_mmap", "change_protection",
    "zap_page_range", "move_page_tables", "fault_info", NULL
};

int main(int argc, char **argv)
{
    int g_json = 0;
    int i;
    char *buf = NULL;
    size_t len = 0;
    char hits[2048] = "";
    char note[512] = "";
    int strong = 0, weak = 0, nshown = 0;
    FILE *p;

    for (i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--json"))
            g_json = 1;

    p = popen("dmesg 2>/dev/null | tail -n 2000", "r");
    if (p) {
        char chunk[8192];
        size_t got = 0, cap = 1 << 20;
        buf = malloc(cap);
        if (buf) {
            while (got + sizeof(chunk) < cap &&
                   (len = fread(chunk, 1, sizeof(chunk), p)) > 0) {
                memcpy(buf + got, chunk, len);
                got += len;
            }
            buf[got] = 0;
        }
        pclose(p);
        if (buf)
            len = got;
    }
    if (!buf) {
        /* 回退：/dev/kmsg（root） */
        int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            char chunk[8192];
            ssize_t n;
            size_t got = 0, cap = 1 << 20;
            buf = malloc(cap);
            while (buf && got + sizeof(chunk) < cap &&
                   (n = read(fd, chunk, sizeof(chunk))) > 0) {
                memcpy(buf + got, chunk, (size_t)n);
                got += (size_t)n;
            }
            if (buf) {
                buf[got] = 0;
                len = got;
            }
            close(fd);
        }
    }
    if (!buf || len == 0) {
        ace_emit(stdout, "dmesg", "L5-dmesg-forensics", V_ERROR, 0, "",
                 "dmesg 不可读（权限/容器）", g_json);
        free(buf);
        return 1;
    }

    {
        char *line, *save = NULL;
        for (line = strtok_r(buf, "\n", &save); line;
             line = strtok_r(NULL, "\n", &save)) {
            int hit = 0;
            for (i = 0; pat_strong[i]; i++) {
                if (strcasestr(line, pat_strong[i])) {
                    strong++;
                    hit = 1;
                    break;
                }
            }
            if (!hit) {
                for (i = 0; pat_weak[i]; i++) {
                    if (strcasestr(line, pat_weak[i])) {
                        weak++;
                        hit = 1;
                        break;
                    }
                }
            }
            if (hit && nshown < 12) {
                size_t l = strlen(line);
                if (l > 160)
                    l = 160;
                snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                         "[%.*s] ", (int)l, line);
                nshown++;
            }
        }
    }
    free(buf);

    if (strong) {
        snprintf(note, sizeof(note),
                 "dmesg 含 %d 条 rxshadow/kpm/ksud/KernelPatch 痕迹（强特征）",
                 strong);
        ace_emit(stdout, "dmesg", "L5-dmesg-forensics", V_HOOKED, 88,
                 hits, note, g_json);
        return 2;
    }
    if (weak) {
        snprintf(note, sizeof(note),
                 "dmesg 含 %d 条 hook 目标名痕迹（弱特征，需人工确认）", weak);
        ace_emit(stdout, "dmesg", "L5-dmesg-forensics", V_SUSPECT, 45,
                 hits, note, g_json);
        return 1;
    }
    ace_emit(stdout, "dmesg", "L5-dmesg-forensics", V_CLEAN, 0, hits,
             "dmesg 无 hook 相关痕迹", g_json);
    return 0;
}
