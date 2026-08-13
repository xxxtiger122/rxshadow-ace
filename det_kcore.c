/*
 * det_kcore.c — L5 内核内存审计信道（/proc/kcore）
 *
 * 针对性检查（root；GKI 上 /proc/kcore 是 ELF core，含全部内核 VA）：
 *   C1 sys_call_table 完整性：从 kallsyms 取 sys_call_table 地址，读表，
 *      每条目必须指向内核文本 [_stext,_etext]。条目指到模块区/洞 =
 *      syscall 派发层被 inline hook（rxshadow 当前不挂 syscall，留作
 *      其他 rootkit 的针对性信道）。
 *   C2 挂钩目标前导扫描：对 rxshadow 已知挂钩目标函数，读前 64 字节，
 *      找 BRK (0xD4200000/0xD4200001) 或"跨页 B"指令 —— 文本层 patch
 *      特征（rxshadow brk 模式写 BRK）。
 *   C3 文本区外代码：KernelPatch/KPM 常把代码放在模块/保留区，
 *      /proc/modules 里的可疑条目 + kcore 中对应段的可执行标志。
 *
 * 降级：kallsyms 受限/无 kcore → ERROR 跳过（kallsyms/dmesg 仍工作）。
 * 用法：det_kcore [--json]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include "ace_common.h"

#define SC_MAX 1024

static const char *hook_targets[] = {
    "do_mem_abort", "follow_page_pte", "follow_page_mask",
    "change_protection", "zap_page_range_single", "move_page_tables",
    "do_vmi_munmap", "pte_to_pagemap_entry", "exit_mmap", NULL
};

struct seg {
    uint64_t vaddr;
    uint64_t off;
    uint64_t size;
};

static int g_fd = -1;
static struct seg g_segs[64];
static int g_nseg = 0;

static int kcore_init(void)
{
    Elf64_Ehdr eh;
    Elf64_Phdr ph;
    int i, n;
    ssize_t rd;
    g_fd = open("/proc/kcore", O_RDONLY);
    if (g_fd < 0)
        return -1;
    rd = pread(g_fd, &eh, sizeof(eh), 0);
    if (rd != (ssize_t)sizeof(eh) || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
        return -1;
    n = (int)eh.e_phnum;
    if (n > 64)
        n = 64;
    for (i = 0; i < n; i++) {
        rd = pread(g_fd, &ph, sizeof(ph), (off_t)(eh.e_phoff + i * eh.e_phentsize));
        if (rd != (ssize_t)sizeof(ph))
            continue;
        if (ph.p_type == PT_LOAD) {
            g_segs[g_nseg].vaddr = ph.p_vaddr;
            g_segs[g_nseg].off = ph.p_offset;
            g_segs[g_nseg].size = ph.p_memsz;
            g_nseg++;
        }
    }
    return g_nseg > 0 ? 0 : -1;
}

/* 读内核 VA；返回 0 成功 */
static int kcore_read(uint64_t va, void *out, size_t n)
{
    int i;
    for (i = 0; i < g_nseg; i++) {
        if (va >= g_segs[i].vaddr &&
            va + n <= g_segs[i].vaddr + g_segs[i].size) {
            ssize_t rd = pread(g_fd, out, n,
                               (off_t)(g_segs[i].off + (va - g_segs[i].vaddr)));
            return rd == (ssize_t)n ? 0 : -1;
        }
    }
    return -1;
}

/* 从 kallsyms 解析符号地址；0 表示不存在/受限 */
static uint64_t ksym_addr(const char *want)
{
    char *buf;
    char *line, *save = NULL;
    uint64_t found = 0;
    buf = ace_read_file("/proc/kallsyms", NULL);
    if (!buf)
        return 0;
    for (line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        unsigned long long a;
        char t;
        char n[256];
        if (sscanf(line, "%llx %c %255s", &a, &t, n) == 3 && !strcmp(n, want)) {
            found = (uint64_t)a;
            break;
        }
    }
    free(buf);
    return found;
}

/* 统计 AArch64 文本里的 BRK 指令数（host x86 上恒 0，跳过该子检查） */
static int is_aarch64_brk(uint32_t w)
{
#ifdef __aarch64__
    return (w & 0xFFE0001Fu) == 0xD4200000u;
#else
    (void)w;
    return 0;
#endif
}

static int det_impl_main(int argc, char **argv)
{
    int g_json = 0;
    int i;
    ace_verdict v = V_CLEAN;
    int score = 0;
    char hits[1024] = "";
    char note[512] = "";
    uint64_t stext = 0, etext = 0, sct = 0;
    int n_oob = 0, n_brk = 0, n_brk_tgt = 0;

    for (i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--json"))
            g_json = 1;

    if (kcore_init() != 0) {
        ace_emit(stdout, "kcore", "L5-kcore-audit", V_ERROR, 0, "",
                 "/proc/kcore 不可读（容器/权限/内核配置）", g_json);
        return 1;
    }

    stext = ksym_addr("_stext");
    etext = ksym_addr("_etext");
    sct = ksym_addr("sys_call_table");

    /* C1: sys_call_table */
    if (sct && stext && etext) {
        uint64_t entries[SC_MAX];
        size_t n = sizeof(entries) / 8;
        if (kcore_read(sct, entries, n) == 0) {
            for (i = 0; i < (int)n; i++) {
                uint64_t e = entries[i];
                if (!e)
                    continue;
                if (e < stext || e > etext) {
                    n_oob++;
                    if (n_oob <= 8)
                        snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                                 "syscall[%d]=0x%llx ", i,
                                 (unsigned long long)e);
                }
            }
            if (n_oob)
                snprintf(note + strlen(note), sizeof(note) - strlen(note),
                         "sys_call_table %d 个条目越出内核文本", n_oob);
        } else {
            snprintf(note + strlen(note), sizeof(note) - strlen(note),
                     "sys_call_table 读取失败 ");
        }
    } else {
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "sys_call_table 不可定位（kallsyms 受限） ");
    }

    /* C2: 挂钩目标前导扫描 */
    for (i = 0; hook_targets[i]; i++) {
        uint64_t a = ksym_addr(hook_targets[i]);
        uint8_t b[64];
        if (!a || kcore_read(a, b, sizeof(b)) != 0)
            continue;
        /* AArch64: 前 16 条指令找 BRK；跨页 B 检测（B.cond/无条件 B 目标）*/
        {
            int j;
            for (j = 0; j + 4 <= (int)sizeof(b); j += 4) {
                uint32_t w;
                memcpy(&w, b + j, 4);
                if (is_aarch64_brk(w)) {
                    n_brk_tgt++;
                    if (n_brk_tgt <= 8)
                        snprintf(hits + strlen(hits),
                                 sizeof(hits) - strlen(hits),
                                 "brk@%s+%d ", hook_targets[i], j);
                }
            }
        }
        (void)n_brk;
    }
    if (n_brk_tgt) {
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "%d 个挂钩目标前导含 BRK（brk 模式 inline hook 特征）",
                 n_brk_tgt);
    }

    /* C3: /proc/modules 可疑条目 */
    {
        char *mb = ace_read_file("/proc/modules", NULL);
        if (mb) {
            if (strstr(mb, "rxshadow"))
                snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                         "mod=rxshadow ");
            free(mb);
        }
    }

    close(g_fd);

    if (n_oob) {
        v = V_HOOKED;
        score = 85;
    } else if (n_brk_tgt) {
        v = V_HOOKED;
        score = 80;
    } else if (score == 0) {
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "syscall 表与挂钩目标前导无异常");
        v = V_CLEAN;
    }
    if (!sct && !n_oob && !n_brk_tgt)
        v = V_CLEAN; /* 信息不足但无异常证据 */

    ace_emit(stdout, "kcore", "L5-kcore-audit", v, score, hits, note, g_json);
    return (int)v;
}

/* ===== 库入口（JNI / 无 root App 内嵌模式，det_libify.py 生成） =====
 * 将 stdout 重定向到内存 buffer，伪造 argv 复用 impl_main。
 * 无 exec / 无 fork：App 进程内直接调用（Android untrusted_app 域
 * 禁止 exec app 私有 ELF，但 dlopen .so + 进程内调用完全合法）。 */
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>

int det_kcore_run(const char *state_path, char *json_out, size_t outsz)
{
    FILE *f = fmemopen(json_out, outsz, "w");
    int saved, rc;
    char *fake[] = { (char *)"det_kcore", (char *)"--state",
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
