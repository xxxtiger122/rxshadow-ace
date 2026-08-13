/*
 * det_kallsyms.c — L5 内核符号布局信道
 *
 * 针对性检查：
 *   K1 模块指纹：/proc/kallsyms 里 [rxshadow] 模块符号、/proc/modules 里
 *      rxshadow 条目 —— KPM 本体加载的直接证据（用户态能看到的最高置信）。
 *   K2 文本布局：所有内核文本符号（T/t 类型）地址必须落在 [_stext,_etext]
 *      内；任何落在模块区/洞里的文本符号都异常。
 *   K3 挂钩目标驻留：列出 rxshadow 已知挂钩目标符号（do_mem_abort、
 *      follow_page_pte 等）是否存在及其地址，供 kcore 信道交叉。
 *
 * 注意：kptr_restrict=1/2 时地址全 0，K2/K3 降级为"不可用"，K1 仍有效。
 * 用法：det_kallsyms [--json]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ace_common.h"

static const char *hook_targets[] = {
    "do_mem_abort", "follow_page_pte", "follow_page_mask", "follow_page",
    "pte_to_pagemap_entry", "exit_mmap", "change_protection",
    "zap_page_range_single", "move_page_tables", "do_vmi_munmap",
    "uprobe_start_dup_mmap", "uprobe_end_dup_mmap", "dup_mmap", NULL
};

int main(int argc, char **argv)
{
    int g_json = 0;
    int i;
    char *buf;
    size_t len;
    char *line, *save = NULL;
    unsigned long long stext = 0, etext = 0;
    int text_out_of_range = 0;
    int mod_rxshadow = 0;
    char hits[1024] = "";
    char note[512] = "";
    int kallsyms_restricted = 0;
    ace_verdict v = V_CLEAN;
    int score = 0;

    for (i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--json"))
            g_json = 1;

    /* ---- K1a: /proc/modules 模块指纹 ---- */
    {
        FILE *f = fopen("/proc/modules", "r");
        char mline[512];
        if (f) {
            while (fgets(mline, sizeof(mline), f)) {
                char name[128];
                if (sscanf(mline, "%127s", name) == 1 &&
                    strstr(mline, "rxshadow") != NULL) {
                    mod_rxshadow = 1;
                    snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                             "proc_modules=[%s]", mline);
                }
            }
            fclose(f);
        }
    }
    /* K1b: /sys/module 目录指纹 */
    if (ace_file_exists("/sys/module/rxshadow")) {
        mod_rxshadow = 1;
        snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                 "sys_module_dir=[/sys/module/rxshadow] ");
    }

    /* ---- /proc/kallsyms 布局 ---- */
    buf = ace_read_file("/proc/kallsyms", &len);
    if (buf) {
        unsigned long long addr;
        char type;
        char name[256];
        char mod[128] = "";
        int any_addr = 0;

        {
            int hit[16] = {0};
            int nhit = 0;
            for (i = 0; hook_targets[i]; i++)
                nhit++;
            for (line = strtok_r(buf, "\n", &save); line;
                 line = strtok_r(NULL, "\n", &save)) {
                int j;
                mod[0] = 0;
                if (sscanf(line, "%llx %c %255s %127s", &addr, &type, name,
                           mod) < 3)
                    continue;
                if (addr)
                    any_addr = 1;
                if (!strcmp(name, "_stext"))
                    stext = addr;
                else if (!strcmp(name, "_etext"))
                    etext = addr;
                else if (strstr(name, "rxshadow") || strstr(mod, "rxshadow"))
                    mod_rxshadow = 1;

                for (j = 0; j < nhit && j < 16; j++) {
                    if (!hit[j] && !strcmp(name, hook_targets[j])) {
                        hit[j] = 1;
                        snprintf(hits + strlen(hits),
                                 sizeof(hits) - strlen(hits),
                                 "%s=0x%llx ", name, addr);
                    }
                }

                if (addr && (type == 'T' || type == 't') && !mod[0] &&
                    stext && etext && (addr < stext || addr > etext)) {
                    text_out_of_range++;
                    if (text_out_of_range <= 5)
                        snprintf(hits + strlen(hits),
                                 sizeof(hits) - strlen(hits),
                                 "oob=%s@0x%llx ", name, addr);
                }
            }
        }
        if (!any_addr)
            kallsyms_restricted = 1;
        free(buf);
    } else {
        kallsyms_restricted = 1;
    }

    if (mod_rxshadow) {
        v = V_HOOKED;
        score = 100;
        snprintf(note, sizeof(note),
                 "内核模块 rxshadow 已加载（/proc/modules 或 /sys/module）"
                 "—— KPM 本体在用户态可见");
    } else if (kallsyms_restricted && !text_out_of_range) {
        snprintf(note, sizeof(note), "kallsyms 受限（kptr_restrict），仅模块指纹有效");
    } else {
        snprintf(note, sizeof(note), "未发现 rxshadow 模块；kallsyms 布局正常");
    }
    if (text_out_of_range) {
        if (score < 80)
            score = 80;
        v = V_HOOKED;
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "；%d 个内核文本符号越界", text_out_of_range);
    }

    ace_emit(stdout, "kallsyms", "L5-kallsyms-layout", v, score, hits, note, g_json);
    return (int)v;
}
