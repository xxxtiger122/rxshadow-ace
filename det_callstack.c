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

/* 单线程回溯；返回命中的匿名可执行/幽灵地址数 */
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
        c = classify(pc);
        if (c == 1 || c == 3) {
            n_hit++;
            n += snprintf(o + n, outsz - n, "PC=0x%llx(%s) ", (unsigned long long)pc,
                          c == 1 ? "anon-exec" : "ghost");
        }
        if (lr) {
            c = classify(lr);
            if (c == 1 || c == 3) {
                n_hit++;
                n += snprintf(o + n, outsz - n, "LR=0x%llx(%s) ",
                              (unsigned long long)lr, c == 1 ? "anon-exec" : "ghost");
            }
        }
    }
    /* FP 链回溯 */
    cur = fp;
    for (f = 0; f < MAX_FRAME && cur && cur > 0x1000 && cur < 0x7ffffffff000ULL; f++) {
        uint64_t next_fp, ret;
        if (read_vm(pid, cur, &next_fp, 8) != 0)
            break;
        if (read_vm(pid, cur + 8, &ret, 8) != 0)
            break;
        {
            int c = classify(ret);
            if (c == 1 || c == 3) {
                n_hit++;
                {
                    char *o = out + strlen(out);
                    snprintf(o, outsz - (size_t)(o - out), "F%d=0x%llx(%s) ", f,
                             (unsigned long long)ret, c == 1 ? "anon-exec" : "ghost");
                }
            }
        }
        if (next_fp <= cur)
            break; /* 链终止 */
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
             "tids=%d attached=%d", n_tids, n_attach_ok);

    if (total_hit > 0) {
        v = V_HOOKED;
        score = 92;
        snprintf(note, sizeof(note),
                 "%d 处执行流/返回地址落在匿名可执行区或未登记内存："
                 "执行面（shadow/跳板）在用户态可见", total_hit);
    } else if (n_attach_ok == 0) {
        v = V_ERROR;
        score = 0;
        snprintf(note, sizeof(note), "无法 attach 任何线程（权限）");
    } else {
        snprintf(note, sizeof(note),
                 "全部 %d 个线程执行流均在白名单可执行段内", n_attach_ok);
    }

    ace_emit(stdout, "callstack", "L7-exec-flow-audit", v, score, hits, note, g_json);
    return (int)v;
}
