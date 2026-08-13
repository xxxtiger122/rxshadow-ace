/*
 * sim_hook.c — host 侧 hook 场景模拟器（ACE 套件的 CI 验证靶）
 *
 * 本机（无真机/KPM）无法产生真正的双物理页，但可以模拟 rxshadow
 * 在用户态可见的全部"症状"，用来验证检测器逻辑与 ace 聚合：
 *
 *   clean  不做任何修改 → 所有检测器应报 clean
 *   cave   把 H_A 入口替换成跳页尾洞的 jmp（洞内 mov eax,99; ret），
 *          页尾 64 字节本来就是 padding → 等价于 Cave 的自视图污染
 *   brk    把 H_A 首字节写 0xCC（int3）→ 调用触发 SIGTRAP，主程序
 *          捕获后报告 —— 验证功能信道对"调用异常"的响应
 *   split  在状态文件里"自报"分裂视图（crc_self != 真实页字节），
 *          模拟 victim 自读看到 shadow 而 GUP 读不到的场景 ——
 *          验证 crossread/selfcrc 对状态文件的解析与判决
 *
 * 用法：
 *   sim_hook clean|split [--state <path>] [--interval-ms <n>]
 *   sim_hook cave|brk  [--state <path>] [--interval-ms <n>]
 *
 * 退出：cave/brk 模式下持续运行，SIGTERM 退出。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include "ace_common.h"

static volatile int g_stop = 0;
static void sighandler(int sig) { (void)sig; g_stop = 1; }

/* brk 模式：int3 触发 SIGTRAP，SIG_IGN 对 trap 无效，须 longjmp 逃生 */
static sigjmp_buf g_brk_jb;
static void brk_handler(int sig)
{
    (void)sig;
    siglongjmp(g_brk_jb, 1);
}

/* 模拟状态写入（复用 labtarget 的 key 集合） */
static void write_state(const char *path, uint64_t va_a, uint64_t va_b,
                        uint32_t crc_self0, uint32_t crc_self, uint32_t crc_gup,
                        long call_a, long call_b, uint64_t pfn_a, uint64_t pfn_b,
                        long mis_a, long tot_a, int hooked, int sim_split,
                        uint64_t lat_a, uint64_t lat_b, long minflt_delta,
                        long stime_ms, long pingpong_ns, long uctx_cave)
{
    char tmp[512];
    FILE *f;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    f = fopen(tmp, "w");
    if (!f)
        return;
    fprintf(f, "pid=%d\n", (int)getpid());
    fprintf(f, "mode=%s\n", hooked ? "hooked" : "clean");
    fprintf(f, "va_a=0x%llx\n", (unsigned long long)va_a);
    fprintf(f, "va_b=0x%llx\n", (unsigned long long)va_b);
    fprintf(f, "va_alpha=0x0\nva_beta=0x0\nva_gamma=0x0\n");
    fprintf(f, "expected_a=42\n");
    fprintf(f, "call_a=%ld\n", call_a);
    fprintf(f, "call_b=%ld\n", call_b);
    fprintf(f, "tot_a=%ld\n", tot_a);
    fprintf(f, "mis_a=%ld\n", mis_a);
    fprintf(f, "tot_b=%ld\nmis_b=0\n", tot_a);
    fprintf(f, "crc_self0_a=0x%08x\n", crc_self0);
    fprintf(f, "crc_self_a=0x%08x\n", crc_self);
    fprintf(f, "crc_gup_a=0x%08x\n", crc_gup);
    fprintf(f, "crc_self_b=0x%08x\n", crc_gup);
    fprintf(f, "crc_gup_b=0x%08x\n", crc_gup);
    fprintf(f, "crc_self_alpha=0x0\n");
    fprintf(f, "pfn_a=0x%llx\n", (unsigned long long)pfn_a);
    fprintf(f, "pfn_b=0x%llx\n", (unsigned long long)pfn_b);
    fprintf(f, "lat_a_min=%llu\nlat_a_p50=%llu\nlat_a_p99=%llu\n",
            (unsigned long long)lat_a, (unsigned long long)lat_a,
            (unsigned long long)(lat_a * 3));
    fprintf(f, "lat_b_min=%llu\nlat_b_p50=%llu\nlat_b_p99=%llu\n",
            (unsigned long long)lat_b, (unsigned long long)lat_b,
            (unsigned long long)(lat_b * 3));
    fprintf(f, "child_pid=0\nchild_call_a=-1\nchild_crc_self_a=0\n");
    fprintf(f, "hooked=%d\n", hooked ? 1 : 0);
    fprintf(f, "lat_read_a_ns=2000\n");
    /* 自读时序模拟：异常驱动（minflt 大）→ 读窗翻转使 H_A 全页读变慢 */
    if (minflt_delta > 1000) {
        fprintf(f, "read_scan_a_min=38000\nread_scan_a_p50=40000\n");
        fprintf(f, "read_scan_b_min=1900\nread_scan_b_p50=2000\n");
    } else {
        fprintf(f, "read_scan_a_min=1900\nread_scan_a_p50=2000\n");
        fprintf(f, "read_scan_b_min=1900\nread_scan_b_p50=2000\n");
    }
    fprintf(f, "anon_exec_base_bytes=8192\n"); /* sim_hook 2×4KB 匿名可执行页 */
    /* 记账自观测模拟（292226）：fault 风暴 / stime / 信号 / ucontext / pingpong */
    fprintf(f, "minflt_delta=%ld\n", minflt_delta);
    fprintf(f, "majflt_delta=0\n");
    fprintf(f, "sig_trap=0\nsig_segv=0\nsig_ill=0\n");
    fprintf(f, "uctx_pc_ok=5\nuctx_pc_anon=0\n");
    fprintf(f, "uctx_pc_cave=%ld\n", uctx_cave);
    fprintf(f, "pingpong_ns=%ld\n", pingpong_ns);
    fprintf(f, "mincore_ok=1\nmincore_cave=1\n");
    fprintf(f, "mmap_probe_fail=0\nmmap_probe_n=16\n");
    fprintf(f, "stime_ns=%ld\n", stime_ms * 1000000L);
    fprintf(f, "utime_ns=200000000\n");
    fclose(f);
    rename(tmp, path);
    (void)sim_split;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "clean";
    const char *state = NULL;
    int interval = 1000;
    int i;
    uint8_t *page_a, *page_b;
    int (*fn_a)(void);
    int (*fn_b)(void);
    uint32_t crc0, crc_self;
    uint64_t pfn_a = 0, pfn_b = 0;

    for (i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--state") && i + 1 < argc)
            state = argv[++i];
        else if (!strcmp(argv[i], "--interval-ms") && i + 1 < argc)
            interval = atoi(argv[++i]);
    }
    if (!state)
        state = ace_default_state_path();

    page_a = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    page_b = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page_a == MAP_FAILED || page_b == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    /* x86_64: mov eax,42 ; ret */
    page_a[0] = 0xB8; page_a[1] = 42; page_a[2] = 0; page_a[3] = 0;
    page_a[4] = 0; page_a[5] = 0xC3;
    page_b[0] = 0xB8; page_b[1] = 42; page_b[2] = 0; page_b[3] = 0;
    page_b[4] = 0; page_b[5] = 0xC3;

    /* 原始字节基线必须在任何 patch 之前算（crc_self0 语义） */
    crc0 = ace_crc32(page_a, 32);

    /* 模拟 patch 必须在 mprotect(RX) 之前做（RX 页写入 = SIGSEGV） */
    if (!strcmp(mode, "cave")) {
        /* 入口 5 字节 jmp rel32 → 页尾洞；洞内 mov eax,99; ret */
        int32_t rel;
        uint8_t *cave = page_a + 4096 - 16;
        cave[0] = 0xB8; cave[1] = 99; cave[2] = 0; cave[3] = 0;
        cave[4] = 0; cave[5] = 0xC3;
        rel = (int32_t)(cave - (page_a + 5));
        page_a[0] = 0xE9;
        memcpy(page_a + 1, &rel, 4);
    } else if (!strcmp(mode, "brk")) {
        page_a[0] = 0xCC; /* int3 */
    }

    mprotect(page_a, 4096, PROT_READ | PROT_EXEC);
    mprotect(page_b, 4096, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *)page_a, (char *)page_a + 8);
    __builtin___clear_cache((char *)page_b, (char *)page_b + 8);
    fn_a = (int (*)(void))page_a;
    fn_b = (int (*)(void))page_b;

    signal(SIGTERM, sighandler);
    signal(SIGINT, sighandler);
    printf("S sim_hook mode=%s pid=%d va_a=0x%llx\n", mode, (int)getpid(),
           (unsigned long long)(uintptr_t)page_a);

    while (!g_stop) {
        long ca = -1, cb = -1, mis = 0;
        int hooked = 0;
        uint32_t crc_self_cur = ace_crc32(page_a, 32);
        uint32_t crc_gup = crc0; /* 无内核模块：GUP 与自读相同（真实页）*/
        uint32_t crc_self_rpt = crc_self_cur;
        (void)crc_self;

        if (!strcmp(mode, "split")) {
            /* 模拟 victim 自报分裂：自读 CRC 谎报成"shadow"版本 */
            crc_self_rpt = crc0 ^ 0xDEADBEEF;
            hooked = 1;
        } else {
            if (!strcmp(mode, "cave")) {
                ca = fn_a();       /* 99 */
                cb = fn_b();       /* 42 */
                mis = (ca == 42) ? 0 : 1;
                crc_gup = crc0;    /* 模拟 GUP 隐藏：外部仍读 original */
                hooked = (ca != 42) || (crc_self_cur != crc0);
            } else if (!strcmp(mode, "brk")) {
                /* int3 → SIGTRAP：捕获并记 mis（BRK 命中语义） */
                struct sigaction sa;
                memset(&sa, 0, sizeof(sa));
                sa.sa_handler = brk_handler;
                sigaction(SIGTRAP, &sa, NULL);
                if (sigsetjmp(g_brk_jb, 1) == 0) {
                    fn_a();
                    ca = 42; /* 未触发 trap：不应发生 */
                } else {
                    ca = 99; /* BRK 命中 */
                }
                mis = 1;
                crc_gup = crc0;
                hooked = 1;
            } else {
                ca = fn_a();
                cb = fn_b();
                crc_gup = crc0;
                crc_self_rpt = crc_self_cur;
                hooked = (crc_self_cur != crc0) || (ca != 42);
            }
        }

        ace_pagemap_pfn(getpid(), (uint64_t)(uintptr_t)page_a, &pfn_a, NULL);
        ace_pagemap_pfn(getpid(), (uint64_t)(uintptr_t)page_b, &pfn_b, NULL);

        write_state(state, (uint64_t)(uintptr_t)page_a,
                    (uint64_t)(uintptr_t)page_b, crc0, crc_self_rpt, crc_gup,
                    ca, cb, pfn_a, pfn_b, mis, 10000, hooked,
                    0 /* sim_split（split 模式经 crc_self_rpt 模拟）*/,
                    !strcmp(mode, "cave") ? 18 : (!strcmp(mode, "brk") ? 400 : 6),
                    5,
                    (strcmp(mode, "clean") != 0) ? 50000 : 5,  /* minflt_delta */
                    (strcmp(mode, "clean") != 0) ? 600 : 0,     /* stime_ms */
                    (strcmp(mode, "clean") != 0) ? 400 : 30,   /* pingpong_ns */
                    (strcmp(mode, "clean") != 0) ? 3 : 0);     /* uctx_pc_cave */
        printf("S call_a=%ld call_b=%ld mis=%ld crc_self=0x%08x crc_gup=0x%08x "
               "hooked=%d\n", ca, cb, mis, crc_self_rpt, crc_gup, hooked);
        usleep((useconds_t)interval * 1000);
    }
    unlink(state);
    return 0;
}
