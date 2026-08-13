/*
 * labtarget.c — rxshadow 实验对象（ACE 套件的靶子/受害者）
 *
 * 相对 lab/rxlab*.c 的升级：一个进程内同时提供
 *   [H 区]  匿名可执行页 H_A（可挂，42→99 模式）/ H_B（控制，永不挂）
 *   [S 区]  静态 aligned(4096) 函数页 alpha/beta/gamma（真实代码表面，
 *           自检/基线/时序用；rxshadow 包络扩到 file-backed 后可挂）
 *   [观测]  双视图 CRC（自读 vs GUP 读）、调用返回值、延迟分布 min/p50/p99、
 *           PFN、fork 子进程视图 —— 全部经状态文件协议对外暴露
 *   [场景]  多线程热路径、fork、mprotect 重挂、--verify 一键断言
 *
 * 用法：
 *   labtarget                   持续运行（热路径 + 观测 + 状态文件）
 *   labtarget --list           打印各页 VA/PFN，供 rxctl 脚本取地址
 *   labtarget --verify <va> <expect> <iters>   批量调用断言（exit 0/2）
 *   labtarget --interval <ms>  观测周期（默认 1000）
 *   labtarget --state <path>   状态文件路径（默认 RX_ACE_STATE/平台默认）
 *
 * flag 文件（目录与状态文件相同）：
 *   rxlab_ace_stop       正常退出
 *   rxlab_ace_dofork     派生子进程并持续报告其视图（fork 隐藏检测）
 *   rxlab_ace_domprotect H_A RX→RWX→RX 后重查调用值（mprotect resync 检测）
 *   rxlab_ace_doverify   立即跑一次自验证并打印
 *
 * 构建：Android NDK（aarch64-linux-android28-clang）或 host gcc 均可。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <time.h>
#include "ace_common.h"

/* ============ 常量 ============ */
#define H_PAGE_N   2          /* H_A, H_B */
#define CRC_WIN    32         /* 每视图 CRC 字节数 */
#define SAMP_N     4096       /* 延迟采样环形缓冲 */
#define SAMP_DIV   8          /* 每 8 次调用采 1 样 */
#define EXPECT_A   42
#define ALPHA_MAGIC 0x414C504841ULL   /* "ALPHA" */
#define BETA_MAGIC  0x42455441ULL     /* "BETA" */
#define GAMMA_MAGIC 0x47414D4D41ULL   /* "GAMMA" */

/* ============ 页面代码生成 ============ */
#ifdef __aarch64__
/* MOV W0,#imm16 ; RET */
static uint32_t mov_w0(unsigned imm)
{
    return 0x52800000u | ((imm & 0xFFFF) << 5);
}
static void write_h_code(uint8_t *p, uint32_t imm)
{
    uint32_t *w = (uint32_t *)p;
    w[0] = mov_w0(imm);
    w[1] = 0xD65F03C0u; /* RET */
}
#else
/* x86_64: B8 imm32 ; C3 (mov eax,imm ; ret) */
static void write_h_code(uint8_t *p, uint32_t imm)
{
    p[0] = 0xB8;
    p[1] = (uint8_t)(imm & 0xFF);
    p[2] = (uint8_t)((imm >> 8) & 0xFF);
    p[3] = (uint8_t)((imm >> 16) & 0xFF);
    p[4] = (uint8_t)((imm >> 24) & 0xFF);
    p[5] = 0xC3;
}
#endif

/* ============ 静态对齐函数页（S 区） ============ */
__attribute__((noinline, aligned(4096)))
long target_alpha(long seed)
{
    volatile long s = seed;
    return s * 0x100000001B3L + (long)ALPHA_MAGIC;
}

__attribute__((noinline, aligned(4096)))
long target_beta(long seed)
{
    volatile long s = seed;
    return s * 0x100000001B3L + (long)BETA_MAGIC;
}

__attribute__((noinline, aligned(4096)))
long target_gamma(long seed)
{
    volatile long s = seed;
    return s * 0x100000001B3L + (long)GAMMA_MAGIC;
}

/* ============ 全局状态 ============ */
static const char *g_state_path;
static char g_flag_dir[256];
static int g_interval_ms = 1000;

static uint8_t *h_pages[H_PAGE_N];
static long h_expected = EXPECT_A;

static volatile long g_tot_a, g_mis_a, g_tot_b, g_mis_b;
static uint64_t g_lat_a[SAMP_N], g_lat_b[SAMP_N];
static volatile size_t g_lat_n_a, g_lat_n_b;
static volatile int g_stop = 0;

static pid_t g_child_pid = -1;
static volatile long g_child_call = -1;
static volatile long g_child_crc = -1;

/* ===== 记账自观测（292226 时序侧信道：异常处理计入 fault/stime） ===== */
static volatile unsigned long g_minflt_prev = 0;
static volatile unsigned long g_minflt_delta = 0;
static volatile unsigned long g_majflt_delta = 0;
static volatile long g_sig_trap = 0, g_sig_segv = 0, g_sig_ill = 0;
static volatile long g_uctx_pc_ok = 0, g_uctx_pc_anon = 0, g_uctx_pc_unknown = 0;
static volatile long g_uctx_pc_cave = 0; /* Cave 洞区 PC（插桩执行证据） */
static volatile long g_pingpong_ns = 0;
static volatile long g_mincore_ok = -1;   /* 自测：H_A 全页 mincore 驻留 */
static volatile long g_mincore_cave = -1; /* 页尾 64B（cave 洞区）驻留 */
static volatile long g_mmap_probe_fail = 0; /* 占位探测失败次数 */
static volatile long g_mmap_probe_n = 0;    /* 占位探测总次数 */

static void fault_handler(int sig, siginfo_t *si, void *uc)
{
    (void)si;
    (void)uc;
    if (sig == SIGTRAP)
        g_sig_trap++;
    else if (sig == SIGSEGV)
        g_sig_segv++;
    else if (sig == SIGILL)
        g_sig_ill++;
}

/* SIGUSR1 自投递：异步信号 ucontext PC 分类（Cave canonical-PC 映射缺陷检测）
 * 正常 H_A 代码只有 8 字节（MOV W0,#42; RET），PC 只可能是页首 offset 0/4；
 * PC 落在页尾洞区（offset >= 4096-64）= Cave 洞内代码正在执行 —— 强证据。
 */
static void usr1_handler(int sig, siginfo_t *si, void *uc)
{
    uint64_t pc = 0;
    uint64_t va_a, va_b;
    (void)sig;
    (void)si;
#if defined(__aarch64__)
    {
        ucontext_t *u = uc;
        pc = (uint64_t)u->uc_mcontext.pc;
    }
#elif defined(__x86_64__)
    {
        ucontext_t *u = uc;
        pc = (uint64_t)u->uc_mcontext.gregs[REG_RIP];
    }
#endif
    va_a = (uint64_t)(uintptr_t)h_pages[0];
    va_b = (uint64_t)(uintptr_t)h_pages[1];
    if (pc >= va_a && pc < va_a + 4096) {
        if (pc >= va_a + 4096 - 64)
            g_uctx_pc_cave++; /* 洞区：Cave 插桩执行 */
        else
            g_uctx_pc_anon++; /* H_A 常规偏移（worker 自带调用） */
    } else if (pc >= va_b && pc < va_b + 4096) {
        g_uctx_pc_anon++; /* H_B 控制页（无 hook，正常） */
    } else {
        g_uctx_pc_ok++;
    }
}

/* 采样 minflt/majflt 增量（/proc/self/stat field 10/12） */
static void sample_faults(void)
{
    char path[64];
    char *buf;
    char *p;
    unsigned long minflt = 0, majflt = 0;
    int i;
    snprintf(path, sizeof(path), "/proc/self/stat");
    buf = ace_read_file(path, NULL);
    if (!buf)
        return;
    /* comm 可能含空格，跳过右括号后的字段 */
    p = strrchr(buf, ')');
    if (p) {
        char *f = p + 2; /* ") " 之后是 field 3 */
        for (i = 3; i <= 12; i++) {
            char *tok = f;
            while (*f && *f != ' ')
                f++;
            if (*f == ' ')
                *f++ = 0;
            if (i == 10)
                minflt = strtoul(tok, NULL, 10);
            else if (i == 12)
                majflt = strtoul(tok, NULL, 10);
        }
    }
    free(buf);
    if (g_minflt_prev) {
        g_minflt_delta = minflt - g_minflt_prev;
        g_majflt_delta = majflt; /* majflt 增量不追踪（极少）*/
    }
    g_minflt_prev = minflt;
}

static void sighandler(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* ============ 工具 ============ */
static void flag_path(char *out, size_t n, const char *name)
{
    snprintf(out, n, "%s/rxlab_ace_%s", g_flag_dir, name);
}

static int flag_pending(const char *name)
{
    char p[256];
    flag_path(p, sizeof(p), name);
    return access(p, F_OK) == 0;
}

static void flag_clear(const char *name)
{
    char p[256];
    flag_path(p, sizeof(p), name);
    unlink(p);
}

static void state_write(void)
{
    char tmp[300], *t;
    FILE *f;
    uint64_t lat_a[SAMP_N], lat_b[SAMP_N];
    size_t na, nb, i;
    uint64_t pfn_a = 0, pfn_b = 0;
    int pa = 0, pb = 0;
    int hooked;
    long ca, cb;

    snprintf(tmp, sizeof(tmp), "%s.tmp", g_state_path);
    f = fopen(tmp, "w");
    if (!f)
        return;

    ca = h_pages[0] ? *(volatile long *)&g_mis_a : 0;
    cb = h_pages[1] ? *(volatile long *)&g_mis_b : 0;
    (void)ca; (void)cb;

    /* 采样快照（滚动窗口） */
    na = *(volatile size_t *)&g_lat_n_a;
    nb = *(volatile size_t *)&g_lat_n_b;
    if (na > SAMP_N) na = SAMP_N;
    if (nb > SAMP_N) nb = SAMP_N;
    for (i = 0; i < na; i++) lat_a[i] = g_lat_a[i];
    for (i = 0; i < nb; i++) lat_b[i] = g_lat_b[i];

    ace_pagemap_pfn(getpid(), (uint64_t)(uintptr_t)h_pages[0], &pfn_a, &pa);
    ace_pagemap_pfn(getpid(), (uint64_t)(uintptr_t)h_pages[1], &pfn_b, &pb);

    {
        uint32_t crc0 = 0, crc_self = 0, crc_gup = 0, crc_b = 0;
        int (*fna)(void) = (int (*)(void))h_pages[0];
        int (*fnb)(void) = (int (*)(void))h_pages[1];
        struct iovec local, remote;
        uint8_t gupbuf[CRC_WIN];
        ssize_t nr;
        long calla, callb;
        uint64_t t0, t1;

        /* 读页耗时（时间差检测：seesaw 模式逐页读触发异常 → 暴涨） */
        {
            volatile uint8_t sink = 0;
            size_t j;
            t0 = ace_now_ns();
            for (j = 0; j < 4096; j += 64)
                sink += h_pages[0][j];
            t1 = ace_now_ns();
            (void)sink;
        }

        crc0 = ace_crc32(h_pages[0], CRC_WIN);
        crc_self = ace_crc32(h_pages[0], CRC_WIN);
        local.iov_base = gupbuf;
        local.iov_len = sizeof(gupbuf);
        remote.iov_base = h_pages[0];
        remote.iov_len = sizeof(gupbuf);
        nr = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        crc_gup = nr == (ssize_t)sizeof(gupbuf)
                      ? ace_crc32(gupbuf, sizeof(gupbuf)) : 0xFFFFFFFFu;
        crc_b = ace_crc32(h_pages[1], CRC_WIN);

        calla = fna ? fna() : -1;
        callb = fnb ? fnb() : -1;

        hooked = (calla != h_expected) || (crc_self != crc_gup);

        fprintf(f, "pid=%d\n", (int)getpid());
        fprintf(f, "mode=%s\n", hooked ? "hooked" : "clean");
        fprintf(f, "va_a=0x%llx\n", (unsigned long long)(uintptr_t)h_pages[0]);
        fprintf(f, "va_b=0x%llx\n", (unsigned long long)(uintptr_t)h_pages[1]);
        fprintf(f, "va_alpha=0x%llx\n", (unsigned long long)(uintptr_t)&target_alpha);
        fprintf(f, "va_beta=0x%llx\n", (unsigned long long)(uintptr_t)&target_beta);
        fprintf(f, "va_gamma=0x%llx\n", (unsigned long long)(uintptr_t)&target_gamma);
        fprintf(f, "expected_a=%ld\n", h_expected);
        fprintf(f, "call_a=%ld\n", calla);
        fprintf(f, "call_b=%ld\n", callb);
        fprintf(f, "tot_a=%ld\n", *(volatile long *)&g_tot_a);
        fprintf(f, "mis_a=%ld\n", *(volatile long *)&g_mis_a);
        fprintf(f, "tot_b=%ld\n", *(volatile long *)&g_tot_b);
        fprintf(f, "mis_b=%ld\n", *(volatile long *)&g_mis_b);
        fprintf(f, "crc_self0_a=0x%08x\n", crc0);
        fprintf(f, "crc_self_a=0x%08x\n", crc_self);
        fprintf(f, "crc_gup_a=0x%08x\n", crc_gup);
        fprintf(f, "crc_self_b=0x%08x\n", crc_b);
        fprintf(f, "crc_gup_b=0x%08x\n", crc_b); /* 控制页无 hook，两视图同 */
        fprintf(f, "crc_self_alpha=0x%08x\n",
                ace_crc32((const void *)((uintptr_t)&target_alpha & ~(uintptr_t)0xFFF), CRC_WIN));
        fprintf(f, "pfn_a=0x%llx\n", (unsigned long long)pfn_a);
        fprintf(f, "pfn_b=0x%llx\n", (unsigned long long)pfn_b);
        fprintf(f, "lat_a_min=%llu\n",
                (unsigned long long)(na ? ace_min_of(lat_a, na) : 0));
        fprintf(f, "lat_a_p50=%llu\n",
                (unsigned long long)(na ? ace_percentile(lat_a, na, 0.50) : 0));
        fprintf(f, "lat_a_p99=%llu\n",
                (unsigned long long)(na ? ace_percentile(lat_a, na, 0.99) : 0));
        fprintf(f, "lat_b_min=%llu\n",
                (unsigned long long)(nb ? ace_min_of(lat_b, nb) : 0));
        fprintf(f, "lat_b_p50=%llu\n",
                (unsigned long long)(nb ? ace_percentile(lat_b, nb, 0.50) : 0));
        fprintf(f, "lat_b_p99=%llu\n",
                (unsigned long long)(nb ? ace_percentile(lat_b, nb, 0.99) : 0));
        fprintf(f, "child_pid=%d\n", (int)g_child_pid);
        fprintf(f, "child_call_a=%ld\n", *(volatile long *)&g_child_call);
        fprintf(f, "child_crc_self_a=0x%08lx\n", *(volatile long *)&g_child_crc);
        fprintf(f, "hooked=%d\n", hooked ? 1 : 0);
        fprintf(f, "lat_read_a_ns=%llu\n", (unsigned long long)(t1 - t0));
        fprintf(f, "anon_exec_base_bytes=%d\n", H_PAGE_N * 4096); /* H 区=实验对象自带基线 */
        /* 记账自观测（292226）：fault 增量 / 信号泄漏 / ucontext PC / pingpong */
        fprintf(f, "minflt_delta=%lu\n", *(volatile unsigned long *)&g_minflt_delta);
        fprintf(f, "majflt_delta=%lu\n", *(volatile unsigned long *)&g_majflt_delta);
        fprintf(f, "sig_trap=%ld\n", *(volatile long *)&g_sig_trap);
        fprintf(f, "sig_segv=%ld\n", *(volatile long *)&g_sig_segv);
        fprintf(f, "sig_ill=%ld\n", *(volatile long *)&g_sig_ill);
        fprintf(f, "uctx_pc_ok=%ld\n", *(volatile long *)&g_uctx_pc_ok);
        fprintf(f, "uctx_pc_anon=%ld\n", *(volatile long *)&g_uctx_pc_anon);
        fprintf(f, "uctx_pc_cave=%ld\n", *(volatile long *)&g_uctx_pc_cave);
        fprintf(f, "pingpong_ns=%ld\n", *(volatile long *)&g_pingpong_ns);
        fprintf(f, "mincore_ok=%ld\n", *(volatile long *)&g_mincore_ok);
        fprintf(f, "mincore_cave=%ld\n", *(volatile long *)&g_mincore_cave);
        fprintf(f, "mmap_probe_fail=%ld\n", *(volatile long *)&g_mmap_probe_fail);
        fprintf(f, "mmap_probe_n=%ld\n", *(volatile long *)&g_mmap_probe_n);
        {
            struct rusage ru;
            if (getrusage(RUSAGE_SELF, &ru) == 0) {
                fprintf(f, "stime_ns=%llu\n",
                        (unsigned long long)(ru.ru_stime.tv_sec * 1000000000ull +
                                             ru.ru_stime.tv_usec * 1000ull));
                fprintf(f, "utime_ns=%llu\n",
                        (unsigned long long)(ru.ru_utime.tv_sec * 1000000000ull +
                                             ru.ru_utime.tv_usec * 1000ull));
            }
        }
    }
    fclose(f);
    rename(tmp, g_state_path);

    printf("S pid=%d va_a=0x%llx call_a=%ld call_b=%ld mis_a=%ld "
           "crc_self_a=0x%08x crc_gup_a=0x%08x pfn_a=0x%llx hooked=%d\n",
           (int)getpid(), (unsigned long long)(uintptr_t)h_pages[0],
           (long)((int (*)(void))h_pages[0])(), (long)((int (*)(void))h_pages[1])(),
           *(volatile long *)&g_mis_a,
           ace_crc32(h_pages[0], CRC_WIN),
           ace_crc32(h_pages[0], CRC_WIN),
           (unsigned long long)pfn_a, hooked ? 1 : 0);
}

/* ============ 热路径 worker ============ */
struct worker_arg {
    int idx;              /* 0=H_A 1=H_B */
    int (*fn)(void);
    long expect;
    volatile long *tot, *mis;
    uint64_t *lat;
    volatile size_t *lat_n;
};

static void *worker_main(void *arg)
{
    struct worker_arg *w = arg;
    long i = 0;

    while (!g_stop) {
        uint64_t t0, t1, d;
        long r;
        t0 = ace_now_ns();
        r = w->fn();
        t1 = ace_now_ns();
        d = t1 - t0;
        (*w->tot)++;
        if (r != w->expect)
            (*w->mis)++;
        if ((i++ % SAMP_DIV) == 0) {
            size_t n = *(volatile size_t *)w->lat_n;
            if (n < SAMP_N)
                w->lat[n] = d;
            *(volatile size_t *)w->lat_n = n + 1;
        }
    }
    return NULL;
}

/* ============ fork 子进程（fork 隐藏观测） ============ */
static void child_loop(void)
{
    while (!g_stop) {
        g_child_call = ((int (*)(void))h_pages[0])();
        g_child_crc = (long)ace_crc32(h_pages[0], CRC_WIN);
        state_write();
        usleep(400000);
    }
    _exit(0);
}

/* ============ pingpong 放大（read+call 交替 → PTE 跷跷板） ============ */
static void *pingpong_main(void *arg)
{
    (void)arg;
    while (!g_stop) {
        uint64_t t0, t1, best = ~0ull;
        volatile uint32_t sink = 0;
        int i;
        for (i = 0; i < 64; i++) {
            t0 = ace_now_ns();
            sink += *(volatile uint32_t *)h_pages[0]; /* 读代码页 */
            ((int (*)(void))h_pages[0])();            /* 执行 */
            t1 = ace_now_ns();
            if (t1 - t0 < best)
                best = t1 - t0;
        }
        (void)sink;
        g_pingpong_ns = (long)best;
        usleep(200000);
    }
    return NULL;
}

/* ============ 地址空间语义自测 ============
 * mincore 盲探（290718）：mincore 只查自己的地址空间，跨进程不可用，
 * 由 victim 自测——正常驻留页全页驻留；VMA-less 幽灵内存/被隐藏映射
 * 的页内偏移会报未映射。页尾 64B 是 rxshadow cave 洞区，单独探测。
 *
 * mmap 占位探测（292066 L185）：幽灵 PTE 占 VA 但无 VMA 时，get_unmapped_area
 * 按 VMA 选址，后续普通 mmap 可能撞上被占 VA 返回 -ENOMEM。在 H_A 附近
 * 反复随机 mmap 小段，统计失败率。
 */
static void *addrsem_main(void *arg)
{
    (void)arg;
    while (!g_stop) {
        unsigned char vec[4096];
        unsigned char vec_cave[64];
        void *p;
        int ok_full = 0, ok_cave = 0;

        /* mincore 全页：4096 页对齐（mincore 按页对齐要求） */
        {
            uintptr_t base = (uintptr_t)h_pages[0] & ~(uintptr_t)0xFFF;
            if (mincore((void *)base, 4096, vec) == 0) {
                int all = 1, i;
                for (i = 0; i < 4096; i++)
                    if (!(vec[i] & 1)) {
                        all = 0;
                        break;
                    }
                ok_full = all;
            }
            /* 页尾 cave 洞区 64B（对齐到该页） */
            if (mincore((void *)(base + 4096 - 64), 64, vec_cave) == 0) {
                int all = 1, i;
                for (i = 0; i < 64; i++)
                    if (!(vec_cave[i] & 1)) {
                        all = 0;
                        break;
                    }
                ok_cave = all;
            }
        }
        g_mincore_ok = ok_full;
        g_mincore_cave = ok_cave;

        /* mmap 占位探测：H_A 页对齐地址附近 ±32MB 随机探测 */
        {
            long tries = 8, fails = 0, k;
            uintptr_t ha = (uintptr_t)h_pages[0] & ~(uintptr_t)0xFFF;
            for (k = 0; k < tries; k++) {
                long off = (long)(((uintptr_t)rand() % (64u * 1024 * 1024)) - 32u * 1024 * 1024);
                off &= ~(long)0xFFF;
                p = mmap((void *)(ha + (uintptr_t)off), 4096,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                         -1, 0);
                if (p == MAP_FAILED)
                    fails++;
                else
                    munmap(p, 4096);
            }
            g_mmap_probe_fail += fails;
            g_mmap_probe_n += tries;
        }
        usleep(800000);
    }
    return NULL;
}

/* ============ 主循环动作 ============ */
static void do_fork(void)
{
    pid_t p;
    flag_clear("dofork");
    if (g_child_pid > 0)
        return;
    p = fork();
    if (p == 0) {
        /* 子进程：自己的视图（父被挂时子应是 42/original） */
        child_loop();
    } else if (p > 0) {
        g_child_pid = p;
        printf("F forked child pid=%d\n", (int)p);
    }
}

static void do_mprotect(void)
{
    long r;
    flag_clear("domprotect");
    if (mprotect(h_pages[0], 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        printf("M mprotect(RWX) failed errno=%d\n", errno);
        return;
    }
    if (mprotect(h_pages[0], 4096, PROT_READ | PROT_EXEC) != 0) {
        printf("M mprotect(RX) failed errno=%d\n", errno);
        return;
    }
    __builtin___clear_cache((char *)h_pages[0], (char *)h_pages[0] + 8);
    r = ((int (*)(void))h_pages[0])();
    printf("M after mprotect R->RWX->RX call_a=%ld (hook 应仍在: 99)\n", r);
}

/* ============ 验证 / 列表模式 ============ */
static int verify_va(uint64_t va, long expect, long iters)
{
    int (*fn)(void) = NULL;
    const char *name = "?";
    uint64_t page = va & ~(uint64_t)0xFFF;
    long ok = 0, mis = 0, i;
    uint64_t *samp = malloc(sizeof(uint64_t) * 4096);
    uint32_t word;

    if (!samp)
        return 1;
    if (page == ((uint64_t)(uintptr_t)h_pages[0] & ~(uint64_t)0xFFF)) {
        fn = (int (*)(void))h_pages[0];
        name = "H_A";
    } else if (page == ((uint64_t)(uintptr_t)h_pages[1] & ~(uint64_t)0xFFF)) {
        fn = (int (*)(void))h_pages[1];
        name = "H_B";
    } else if (page == ((uint64_t)(uintptr_t)&target_alpha & ~(uint64_t)0xFFF)) {
        fn = (int (*)(void))(uintptr_t)&target_alpha;
        name = "alpha";
    } else if (page == ((uint64_t)(uintptr_t)&target_beta & ~(uint64_t)0xFFF)) {
        fn = (int (*)(void))(uintptr_t)&target_beta;
        name = "beta";
    } else if (page == ((uint64_t)(uintptr_t)&target_gamma & ~(uint64_t)0xFFF)) {
        fn = (int (*)(void))(uintptr_t)&target_gamma;
        name = "gamma";
    }
    if (!fn) {
        fprintf(stderr, "E verify: va 0x%llx 不在本进程已知页面\n",
                (unsigned long long)va);
        free(samp);
        return 1;
    }
    for (i = 0; i < iters; i++) {
        uint64_t t0, t1;
        long r;
        t0 = ace_now_ns();
        r = fn();
        t1 = ace_now_ns();
        samp[i & 4095] = t1 - t0;
        if (r == expect)
            ok++;
        else
            mis++;
    }
    word = *(volatile uint32_t *)(uintptr_t)(page);
    {
        uint64_t tmp[4096];
        size_t n = iters < 4096 ? (size_t)iters : 4096;
        memcpy(tmp, samp, n * sizeof(uint64_t));
        printf("V verify %s va=0x%llx expect=%ld iters=%ld ok=%ld mis=%ld "
               "word=0x%08x lat_min=%llu p50=%llu p99=%llu\n",
               name, (unsigned long long)va, expect, iters, ok, mis, word,
               (unsigned long long)ace_min_of(tmp, n),
               (unsigned long long)ace_percentile(tmp, n, 0.50),
               (unsigned long long)ace_percentile(tmp, n, 0.99));
    }
    free(samp);
    return mis ? 2 : 0;
}

static int list_pages(void)
{
    uint64_t pfn_a = 0, pfn_b = 0;
    int pa = 0, pb = 0;
    ace_pagemap_pfn(getpid(), (uint64_t)(uintptr_t)h_pages[0], &pfn_a, &pa);
    ace_pagemap_pfn(getpid(), (uint64_t)(uintptr_t)h_pages[1], &pfn_b, &pb);
    printf("L pid=%d va_a=0x%llx va_b=0x%llx va_alpha=0x%llx va_beta=0x%llx "
           "va_gamma=0x%llx pfn_a=0x%llx pfn_b=0x%llx\n",
           (int)getpid(),
           (unsigned long long)(uintptr_t)h_pages[0],
           (unsigned long long)(uintptr_t)h_pages[1],
           (unsigned long long)(uintptr_t)&target_alpha,
           (unsigned long long)(uintptr_t)&target_beta,
           (unsigned long long)(uintptr_t)&target_gamma,
           (unsigned long long)pfn_a, (unsigned long long)pfn_b);
    return 0;
}

/* ============ main ============ */
int main(int argc, char **argv)
{
    struct worker_arg wa, wb;
    pthread_t th_a, th_b, th_pp, th_as;
    int i;
    const char *state = NULL;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--list")) {
            /* 需要先建页再列 */
            break;
        } else if (!strcmp(argv[i], "--state") && i + 1 < argc) {
            state = argv[++i];
        } else if (!strcmp(argv[i], "--interval") && i + 1 < argc) {
            g_interval_ms = atoi(argv[++i]);
            if (g_interval_ms < 100)
                g_interval_ms = 100;
        }
    }
    g_state_path = state ? state : ace_default_state_path();
    {
        const char *slash = strrchr(g_state_path, '/');
        if (slash) {
            size_t n = (size_t)(slash - g_state_path);
            if (n >= sizeof(g_flag_dir))
                n = sizeof(g_flag_dir) - 1;
            memcpy(g_flag_dir, g_state_path, n);
            g_flag_dir[n] = 0;
        } else {
            strncpy(g_flag_dir, ".", sizeof(g_flag_dir) - 1);
        }
    }

    /* H 区：匿名可执行页 */
    for (i = 0; i < H_PAGE_N; i++) {
        h_pages[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (h_pages[i] == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        write_h_code(h_pages[i], i == 0 ? EXPECT_A : 0x2A); /* H_B 也返回 42 */
        if (mprotect(h_pages[i], 4096, PROT_READ | PROT_EXEC) != 0 &&
            mprotect(h_pages[i], 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            perror("mprotect");
            return 1;
        }
        __builtin___clear_cache((char *)h_pages[i], (char *)h_pages[i] + 8);
    }

    /* 单次模式 */
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--list")) {
            return list_pages();
        } else if (!strcmp(argv[i], "--verify") && i + 3 < argc) {
            uint64_t va = strtoull(argv[i + 1], NULL, 0);
            long expect = strtol(argv[i + 2], NULL, 0);
            long iters = strtol(argv[i + 3], NULL, 0);
            return verify_va(va, expect, iters);
        }
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGTERM, sighandler);
    signal(SIGINT, sighandler);

    /* 记账自观测：意外信号统计 + SIGUSR1 ucontext PC 检查 */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = fault_handler;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigaction(SIGTRAP, &sa, NULL);
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
        sa.sa_sigaction = usr1_handler;
        sigaction(SIGUSR1, &sa, NULL);
    }

    /* 热路径 worker */
    memset(&wa, 0, sizeof(wa));
    wa.idx = 0;
    wa.fn = (int (*)(void))h_pages[0];
    wa.expect = h_expected;
    wa.tot = &g_tot_a;
    wa.mis = &g_mis_a;
    wa.lat = g_lat_a;
    wa.lat_n = &g_lat_n_a;
    memset(&wb, 0, sizeof(wb));
    wb.idx = 1;
    wb.fn = (int (*)(void))h_pages[1];
    wb.expect = h_expected;
    wb.tot = &g_tot_b;
    wb.mis = &g_mis_b;
    wb.lat = g_lat_b;
    wb.lat_n = &g_lat_n_b;

    /* pingpong 放大线程（read+call 交替）+ 地址空间语义自测线程 */
    pthread_create(&th_a, NULL, worker_main, &wa);
    pthread_create(&th_b, NULL, worker_main, &wb);
    pthread_create(&th_pp, NULL, pingpong_main, NULL);
    pthread_create(&th_as, NULL, addrsem_main, NULL);

    printf("T labtarget pid=%d va_a=0x%llx va_b=0x%llx state=%s\n",
           (int)getpid(),
           (unsigned long long)(uintptr_t)h_pages[0],
           (unsigned long long)(uintptr_t)h_pages[1], g_state_path);

    /* 观测主循环 */
    {
        int rounds = 0;
        while (!g_stop) {
            if (flag_pending("stop")) {
                flag_clear("stop");
                g_stop = 1;
                break;
            }
            if (flag_pending("dofork"))
                do_fork();
            if (flag_pending("domprotect"))
                do_mprotect();
            if (flag_pending("doverify")) {
                flag_clear("doverify");
                verify_va((uint64_t)(uintptr_t)h_pages[0], h_expected, 4096);
            }
            sample_faults();
            if ((rounds++ % 5) == 0)
                pthread_kill(th_a, SIGUSR1); /* 投递给 H_A worker：ucontext PC 自检
                                              * （worker 正在执行 H_A，PC 落洞区 =
                                              *  Cave 插桩执行证据；主线程不跑 H_A） */
            state_write();
            usleep((useconds_t)g_interval_ms * 1000);
        }
    }

    g_stop = 1;
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGTERM);
        waitpid(g_child_pid, NULL, 0);
    }
    pthread_join(th_a, NULL);
    pthread_join(th_b, NULL);
    pthread_join(th_pp, NULL);
    pthread_join(th_as, NULL);
    unlink(g_state_path);
    flag_clear("stop");
    flag_clear("dofork");
    flag_clear("domprotect");
    flag_clear("doverify");
    printf("T labtarget exit\n");
    return 0;
}
