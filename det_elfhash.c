/*
 * det_elfhash.c — L2 ELF 完整性信道（磁盘 vs 内存段 checksum）
 *
 * 源自看雪 277402（Hunter 主力检测）：遍历 /proc/<pid>/maps 找可执行段，
 * 读内存字节算 checksum，与磁盘文件同 offset 字节算的 checksum 对比。
 * 这是传统 Inline Hook 的必杀检测（改了字节就露馅）。
 *
 * 对 rxshadow 双视图的特殊语义：
 *   - 检测器走 GUP 读（process_vm_readv）→ rxshadow 隐藏窗返回 original
 *     → checksum 匹配 → clean（本信道验证"GUP 隐藏生效"）
 *   - 若 GUP 隐藏失效 / 未挂 follow_page_pte / 传统 inline hook 共存
 *     → 读到被改字节 → mismatch → HOOKED（GUP 隐藏被击穿）
 *   - 受害者自读（self-read）走 shadow → 由 L1/selfcrc + labtarget 内部
 *     checksum 覆盖（victim 自报 crc_self vs 磁盘基准）
 *
 * 用法：det_elfhash --pid <pid> [--state <path>] [--json] [--seg-bytes <n>]
 * 默认每段对比前 64KB（覆盖 prologue hook 区）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include "ace_common.h"

static const char *g_state;
static int g_json;
static pid_t g_pid = -1;
static size_t g_seg_bytes = 65536;

struct xseg {
    uint64_t start, end;
    uint64_t foff;
    char path[256];
};

static struct xseg g_segs[512];
static int g_nseg = 0;

/* GUP 读 victim 内存 */
static int gup_read(pid_t pid, uint64_t va, uint8_t *out, size_t n)
{
    struct iovec local, remote;
    ssize_t nr;
    local.iov_base = out;
    local.iov_len = n;
    remote.iov_base = (void *)(uintptr_t)va;
    remote.iov_len = n;
    nr = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (nr == (ssize_t)n)
        return 0;
    {
        char path[64];
        int fd;
        snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
        fd = open(path, O_RDONLY);
        if (fd < 0)
            return -1;
        nr = pread(fd, out, n, (off_t)va);
        close(fd);
        if (nr == (ssize_t)n)
            return 0;
    }
    return -1;
}

/* 读磁盘文件 offset 处 */
static int disk_read(const char *path, uint64_t off, uint8_t *out, size_t n)
{
    int fd = open(path, O_RDONLY);
    ssize_t nr;
    if (fd < 0)
        return -1;
    nr = pread(fd, out, n, (off_t)off);
    close(fd);
    return nr == (ssize_t)n ? 0 : -1;
}

int main(int argc, char **argv)
{
    int i;
    char hits[2048] = "";
    char note[512] = "";
    ace_verdict v = V_CLEAN;
    int score = 0;
    int n_mismatch = 0, n_checked = 0, n_unreadable = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            g_pid = (pid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--state") && i + 1 < argc)
            g_state = argv[++i];
        else if (!strcmp(argv[i], "--json"))
            g_json = 1;
        else if (!strcmp(argv[i], "--seg-bytes") && i + 1 < argc)
            g_seg_bytes = (size_t)strtoul(argv[++i], NULL, 0);
    }
    if (!g_state)
        g_state = ace_default_state_path();
    if (g_pid < 0)
        g_pid = (pid_t)ace_state_get_l(g_state, "pid", -1);
    if (g_pid <= 0 || kill(g_pid, 0) != 0) {
        ace_emit(stdout, "elfhash", "L2-elf-integrity", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }

    {
        char path[64];
        char *buf;
        char *line, *save = NULL;
        snprintf(path, sizeof(path), "/proc/%d/maps", (int)g_pid);
        buf = ace_read_file(path, NULL);
        if (!buf) {
            ace_emit(stdout, "elfhash", "L2-elf-integrity", V_ERROR, 0, "",
                     "maps 不可读", g_json);
            return 1;
        }
        for (line = strtok_r(buf, "\n", &save); line && g_nseg < 512;
             line = strtok_r(NULL, "\n", &save)) {
            struct xseg *s = &g_segs[g_nseg];
            char p[8], ph[256] = "";
            uint64_t a, b, o;
            if (sscanf(line, "%llx-%llx %7s %llx %*s %*s %255s",
                       (unsigned long long *)&a, (unsigned long long *)&b, p,
                       (unsigned long long *)&o, ph) >= 4) {
                if (strchr(p, 'x') && ph[0] && ph[0] != '[') {
                    s->start = a;
                    s->end = b;
                    s->foff = o;
                    snprintf(s->path, sizeof(s->path), "%s", ph);
                    g_nseg++;
                }
            }
        }
        free(buf);
    }

    for (i = 0; i < g_nseg; i++) {
        struct xseg *s = &g_segs[i];
        size_t n = g_seg_bytes;
        uint8_t *mbuf = malloc(n);
        uint8_t *dbuf = malloc(n);
        uint32_t mcrc, dcrc;
        if (!mbuf || !dbuf) {
            free(mbuf);
            free(dbuf);
            continue;
        }
        if (s->end - s->start < n)
            n = (size_t)(s->end - s->start);
        if (gup_read(g_pid, s->start, mbuf, n) != 0) {
            n_unreadable++;
            free(mbuf);
            free(dbuf);
            continue;
        }
        if (disk_read(s->path, s->foff, dbuf, n) != 0) {
            n_unreadable++;
            free(mbuf);
            free(dbuf);
            continue;
        }
        mcrc = ace_crc32(mbuf, n);
        dcrc = ace_crc32(dbuf, n);
        n_checked++;
        if (mcrc != dcrc) {
            n_mismatch++;
            if (n_mismatch <= 6) {
                const char *bn = strrchr(s->path, '/');
                snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                         "MISMATCH %s+0x%llx mem=0x%08x disk=0x%08x ",
                         bn ? bn + 1 : s->path, (unsigned long long)s->foff,
                         mcrc, dcrc);
            }
        }
        free(mbuf);
        free(dbuf);
    }

    snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
             "segments_checked=%d mismatches=%d unreadable=%d",
             n_checked, n_mismatch, n_unreadable);

    if (n_checked == 0) {
        v = V_ERROR;
        snprintf(note, sizeof(note), "无可对比可执行段（目标无文件映射或全部不可读）");
    } else if (n_mismatch > 0) {
        v = V_HOOKED;
        score = 95;
        snprintf(note, sizeof(note),
                 "%d/%d 个可执行段内存与磁盘不一致：inline hook / "
                 "GUP 隐藏失效（双视图方案此处应一致）", n_mismatch, n_checked);
    } else {
        snprintf(note, sizeof(note),
                 "%d 个可执行段内存与磁盘一致：GUP 视图未被篡改"
                 "（传统 hook 不存在或双视图 GUP 隐藏生效）", n_checked);
    }

    ace_emit(stdout, "elfhash", "L2-elf-integrity", v, score, hits, note, g_json);
    return (int)v;
}
