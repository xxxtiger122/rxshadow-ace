/*
 * det_callstack.c — L7 执行流审计信道（栈回溯 / 指针漫游）
 *
 * 源自看雪 290718：防守方不扫指令，直接"指针漫游"——检查入口指针 /
 * 调用栈里的返回地址，凡指向"查无此人的幽灵内存 / 匿名可执行区"即检测。
 * 这是从用户态检测内核态 hook 的**执行流证据**：双视图 hook 的执行面
 * （shadow 页）必然落在匿名可执行区，被挂线程的 PC/LR/回溯帧会命中。
 *
 * 实现：
 *   1. 收集目标全部线程（/proc/<pid>/task）
 *   2. ptrace attach 每个线程，PTRACE_GETREGSET 读 PC/LR/FP
 *      （ARM64: user_pt_regs.regs[29]=FP x[30]=LR regs[32]=PC）
 *   3. 沿 FP 链回溯 ≤48 帧（[FP]=父FP，[FP+8]=返回地址，ARM64 ABI）
 *   4. 每个地址对照 maps 分类：匿名可执行区 / 白名单 / 正常文件段
 * 判定：PC/LR/回溯帧落在非白名单匿名可执行区 → HOOKED
 *
 * 注意：ptrace attach 是侵入操作，运行期间目标 TracerPid 会短暂置位；
 *       det_procscan 若同时跑，请排在 callstack 之后。
 * 用法：det_callstack --pid <pid> [--state <path>] [--json]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>
#include "ace_common.h"

#if defined(__aarch64__)
#include <asm/ptrace.h>
#endif

static const char *g_state;
static int g_json;
static pid_t g_pid = -1;

#define MAX_FRAME 48
#define MAX_TID 256

struct xseg {
    uint64_t start, end;
    char perms[8];
    char path[256];
    int anon_exec;   /* 匿名 + x */
    int whitelisted; /* vdso/JIT 等 */
};

static struct xseg g_segs[512];
static int g_nseg = 0;

/* victim 自带可执行页白名单（H 区 + 静态函数页，来自状态文件）：
 * 双视图 hook 的执行面复用原 VA（shadow 是同一 VA 的第二物理页），
 * 用户态 PC 永远落在 H_A 的 VA 区间 —— 这类命中是"实验对象自带"，
 * 不是 hook 引入，必须排除，否则干净基线就误报。
 * 白名单外的匿名可执行命中（trampoline/DBI/Frida 新增 VA）才是信号。 */
static uint64_t g_wl[8];
static int g_wl_n = 0;

static void load_whitelist(const char *state)
{
    static const char *keys[] = { "va_a", "va_b", "va_alpha", "va_beta",
                                  "va_gamma", NULL };
    int i;
    for (i = 0; keys[i] && g_wl_n < 8; i++) {
        uint64_t v = ace_state_get_u64(state, keys[i], 0);
        if (v)
            g_wl[g_wl_n++] = v & ~(uint64_t)0xFFF;
    }
}

static int in_whitelist(uint64_t page)
{
    int i;
    for (i = 0; i < g_wl_n; i++)
        if (g_wl[i] == page)
            return 1;
    return 0;
}

static void load_maps(pid_t pid)
{
    char path[64];
    char *buf;
    char *line, *save = NULL;
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    buf = ace_read_file(path, NULL);
    if (!buf)
        return;
    for (line = strtok_r(buf, "\n", &save); line && g_nseg < 512;
         line = strtok_r(NULL, "\n", &save)) {
        struct xseg *s = &g_segs[g_nseg];
        char p[8], ph[256] = "";
        uint64_t a, b;
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %255s",
                   (unsigned long long *)&a, (unsigned long long *)&b, p, ph) >= 3) {
            s->start = a;
            s->end = b;
            snprintf(s->perms, sizeof(s->perms), "%s", p);
            snprintf(s->path, sizeof(s->path), "%s", ph);
            s->anon_exec = (strchr(p, 'x') && !ph[0]) ? 1 : 0;
            s->whitelisted = (!strcmp(ph, "[vdso]") || !strcmp(ph, "[vvar]") ||
                              !strcmp(ph, "[vsyscall]") ||
                              strstr(ph, "dalvik-jit-code-cache") ||
                              strstr(ph, "jit-cache")) ? 1 : 0;
            g_nseg++;
        }
    }
    free(buf);
}

/* 地址分类：0=正常文件段 1=匿名可执行 2=白名单 3=未登记(幽灵) */
static int classify(uint64_t addr)
{
    int i;
    for (i = 0; i < g_nseg; i++) {
        struct xseg *s = &g_segs[i];
        if (addr >= s->start && addr < s->end) {
            if (s->anon_exec)
                return s->whitelisted ? 2 : 1;
            return 0;
        }
    }
    return 3; /* 不在任何 VMA：幽灵内存（290718 Ghost Mem 形态）*/
}

/* PAC/TBI 剥离分类：
 * ARM64 开启 PAC（paciasp 签名 LR）+ TBI 后，栈上 [FP+8] 的返回地址
 * 高 16 位是签名码/tag，地址整体超出所有 VMA → 被 classify 误判为
 * ghost（干净基线就误报 hooked 92）。
 * 修复：先按原值分类；判 ghost 时剥高 16 位（48 位用户 VA 掩码）重分类
 * —— PAC 垃圾帧剥后落回真实 .text/.so → 不算命中；真 VMA-less 幽灵
 * 地址本身在低 48 位内，剥后不变 → 仍 ghost → 正确命中。
 */
static uint64_t strip_high(uint64_t a)
{
    return a & 0x0000FFFFFFFFFFFFull;
}

/* 返回：0=正常文件段 1=匿名可执行 2=白名单(内核区) 3=ghost 4=H 区白名单 */
static int classify_strip(uint64_t addr)
{
    int c = classify(addr);
    if (c == 3) {
        uint64_t s = strip_high(addr);
        if (s != addr) {
            int c2 = classify(s);
            if (c2 != 3)
                c = c2;
        }
    }
    if (c == 1 && in_whitelist(addr & ~(uint64_t)0xFFF))
        return 4; /* victim 自带 H 区：不计命中 */
    return c;
}

static int read_vm(pid_t pid, uint64_t addr, void *out, size_t n)
{
    char path[64];
    int fd;
    ssize_t rd;
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    rd = pread(fd, out, n, (off_t)addr);
    close(fd);
    return rd == (ssize_t)n ? 0 : -1;
}

/* 单线程回溯；返回命中的匿名可执行/幽灵地址数（H 区白名单计 hwl 不计命中） */
static volatile int g_hwl = 0;
static int backtrace_thread(pid_t pid, pid_t tid, char *out, size_t outsz)
{
    struct iovec iov;
    int n_hit = 0;
    uint64_t pc, lr, fp;
    uint64_t cur;
    int f;

#if defined(__aarch64__)
    struct user_pt_regs regs;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) != 0)
        return -1;
    pc = regs.pc;
    lr = regs.regs[30];
    fp = regs.regs[29];
#elif defined(__x86_64__)
    struct user_regs_struct regs;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) != 0)
        return -1;
    pc = regs.rip;
    lr = 0;
    fp = regs.rbp;
#else
    return -1;
#endif

    {
        char *o = out;
        size_t n = 0;
        int c;
        c = classify_strip(pc);
        if (c == 1 || c == 3) {
            n_hit++;
            n += snprintf(o + n, outsz - n, "PC=0x%llx(%s) ", (unsigned long long)pc,
                          c == 1 ? "anon-exec" : "ghost");
        } else if (c == 4) {
            g_hwl++;
        }
        if (lr) {
            c = classify_strip(lr);
            if (c == 1 || c == 3) {
                n_hit++;
                n += snprintf(o + n, outsz - n, "LR=0x%llx(%s) ",
                              (unsigned long long)lr, c == 1 ? "anon-exec" : "ghost");
            } else if (c == 4) {
                g_hwl++;
            }
        }
    }
    /* FP 链回溯（PAC 剥离：栈上 LR 是 paciasp 签名值，next_fp/ret 均 strip） */
    cur = strip_high(fp);
    for (f = 0; f < MAX_FRAME && cur && cur > 0x1000 && cur < 0x7ffffffff000ULL; f++) {
        uint64_t next_fp, ret;
        if (read_vm(pid, cur, &next_fp, 8) != 0)
            break;
        if (read_vm(pid, cur + 8, &ret, 8) != 0)
            break;
        next_fp = strip_high(next_fp);
        {
            int c = classify_strip(ret);
            if (c == 1 || c == 3) {
                n_hit++;
                {
                    char *o = out + strlen(out);
                    snprintf(o, outsz - (size_t)(o - out), "F%d=0x%llx(%s) ", f,
                             (unsigned long long)ret, c == 1 ? "anon-exec" : "ghost");
                }
            } else if (c == 4) {
                g_hwl++;
            }
        }
        if (next_fp <= cur)
            break; /* 链终止（PAC 剥离后仍单调递减才是有效链） */
        cur = next_fp;
    }
    return n_hit;
}

int main(int argc, char **argv)
{
    int i;
    char hits[2048] = "";
    char note[512] = "";
    ace_verdict v = V_CLEAN;
    int score = 0;
    int total_hit = 0, n_tids = 0, n_attach_ok = 0;
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
        else if (!strcmp(argv[i], "--selftest")) {
            /* PAC/TBI 剥离逻辑自检（host 可跑，不依赖目标进程） */
            uint64_t base = 0x7f1234567890ull;
            uint64_t p16 = base | 0xDEAD000000000000ull; /* 16 位 PAC 码 */
            uint64_t p8 = base | 0xDE00000000000000ull;  /* 高字节 tag/PAC */
            int ok = (strip_high(p16) == base) &&
                     (strip_high(p8) == base) &&
                     (strip_high(base) == base) &&
                     (classify_strip(base) == 3); /* 无 maps 时 base 仍是 ghost */
            printf("selftest PAC-strip: %s\n"
                   "  base=0x%llx strip(p16)=0x%llx strip(p8)=0x%llx\n",
                   ok ? "ok" : "FAIL",
                   (unsigned long long)base,
                   (unsigned long long)strip_high(p16),
                   (unsigned long long)strip_high(p8));
            return ok ? 0 : 1;
        }
    }
    if (!g_state)
        g_state = ace_default_state_path();
    if (g_pid < 0)
        g_pid = (pid_t)ace_state_get_l(g_state, "pid", -1);
    if (g_pid <= 0 || kill(g_pid, 0) != 0) {
        ace_emit(stdout, "callstack", "L7-exec-flow-audit", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }
    load_maps(g_pid);
    if (g_nseg == 0) {
        ace_emit(stdout, "callstack", "L7-exec-flow-audit", V_ERROR, 0, "",
                 "maps 解析失败", g_json);
        return 1;
    }
    load_whitelist(g_state);

    {
        char tpath[64];
        snprintf(tpath, sizeof(tpath), "/proc/%d/task", (int)g_pid);
        d = opendir(tpath);
        if (!d) {
            ace_emit(stdout, "callstack", "L7-exec-flow-audit", V_ERROR, 0, "",
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
        int n;
        char buf[512] = "";
        if (ptrace(PTRACE_ATTACH, tids[i], NULL, NULL) != 0)
            continue;
        waitpid(tids[i], NULL, 0);
        n_attach_ok++;
        n = backtrace_thread(g_pid, tids[i], buf, sizeof(buf));
        if (n > 0) {
            total_hit += n;
            snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                     "tid=%d [%s] ", (int)tids[i], buf);
        }
        ptrace(PTRACE_DETACH, tids[i], NULL, NULL);
    }

    snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
             "tids=%d attached=%d hwl_anon=%d", n_tids, n_attach_ok, g_hwl);

    if (total_hit > 0) {
        v = V_HOOKED;
        score = 92;
        snprintf(note, sizeof(note),
                 "%d 处执行流/返回地址落在白名单外的匿名可执行区或未登记内存："
                 "trampoline/DBI/幽灵代码（H 区自带命中 %d 处已排除）",
                 total_hit, g_hwl);
    } else if (n_attach_ok == 0) {
        v = V_ERROR;
        score = 0;
        snprintf(note, sizeof(note), "无法 attach 任何线程（权限）");
    } else {
        snprintf(note, sizeof(note),
                 "执行流均在白名单段内（H 区自带命中 %d 处已排除，双视图"
                 "执行面复用原 VA 对该信道天然不可见）", g_hwl);
    }

    ace_emit(stdout, "callstack", "L7-exec-flow-audit", v, score, hits, note, g_json);
    return (int)v;
}
