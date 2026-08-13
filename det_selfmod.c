/*
 * det_selfmod.c — L6 写语义信道（GUP 写审计）
 *
 * 原理：rxshadow 的写路径语义（0.3.8，真机验证）：
 *       /proc/<pid>/mem 写（FOLL_FORCE GUP）→ 写 GUP 停到 original，
 *       拿到 page 后 retire（释放 shadow、PTE 回 original、不把 shadow
 *       写回去）→ 之后调用返回新字节的值。
 *
 *       本检测器向受害者的 H_A 页首写入一条已知指令（默认 MOV W0,#7，
 *       即 ARM64 0x528000E0 / x86_64 B8 07 00 00 00），然后核对：
 *         - 调用返回值应变为 7（retire 生效）
 *         - 自视图 CRC 应收敛到新字节（crc_self == crc_gup == 新字节）
 *       若调用值不变或自视图仍为旧字节 → shadow 未 retire / hook 存活。
 *
 * 注意：本检测器会**销毁** H_A 上的 hook（retire 语义）——务必最后跑。
 * 用法：det_selfmod --pid <pid> [--write <hex32>] [--state <path>] [--json]
 * 依赖状态 key：pid va_a crc_self_a crc_gup_a call_a
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/uio.h>
#include "ace_common.h"

static const char *g_state;
static int g_json;
static pid_t g_pid = -1;

/* 写入值：默认 MOV W0,#7；--write 可覆盖（小端 hex） */
static uint32_t g_word = 0;

static uint32_t default_write_word(void)
{
#ifdef __aarch64__
    return 0x528000E0u; /* MOV W0,#7 */
#else
    return 0x00000007u; /* x86 同构（B8 07 00 00 00 的 imm 部分单独处理）*/
#endif
}

static int mem_write(pid_t pid, uint64_t va, const uint8_t *buf, size_t n)
{
    char path[64];
    int fd;
    ssize_t wr;
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    wr = pwrite(fd, buf, n, (off_t)va);
    close(fd);
    return wr == (ssize_t)n ? 0 : -2;
}

int main(int argc, char **argv)
{
    int i;
    uint64_t va_a = 0;
    uint32_t crc_self_before = 0, crc_gup_before = 0;
    long call_before = 0;
    ace_verdict v = V_ERROR;
    int score = 0;
    char hits[512] = "";
    char note[512] = "";
    uint8_t w[8];
    size_t wn;
    int wrc;
    int ok = 0;

    g_word = default_write_word();
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            g_pid = (pid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--write") && i + 1 < argc)
            g_word = (uint32_t)strtoul(argv[++i], NULL, 0);
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
        ace_emit(stdout, "selfmod", "L6-write-semantics", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }
    va_a = ace_state_get_u64(g_state, "va_a", 0);
    if (!va_a) {
        ace_emit(stdout, "selfmod", "L6-write-semantics", V_ERROR, 0, "",
                 "状态文件缺少 va_a", g_json);
        return 1;
    }
    crc_self_before = (uint32_t)ace_state_get_u64(g_state, "crc_self_a", 0);
    crc_gup_before = (uint32_t)ace_state_get_u64(g_state, "crc_gup_a", 0);
    call_before = ace_state_get_l(g_state, "call_a", -1);

#ifdef __aarch64__
    w[0] = (uint8_t)(g_word & 0xFF);
    w[1] = (uint8_t)((g_word >> 8) & 0xFF);
    w[2] = (uint8_t)((g_word >> 16) & 0xFF);
    w[3] = (uint8_t)((g_word >> 24) & 0xFF);
    wn = 4;
#else
    w[0] = 0xB8;
    w[1] = (uint8_t)(g_word & 0xFF);
    w[2] = (uint8_t)((g_word >> 8) & 0xFF);
    w[3] = (uint8_t)((g_word >> 16) & 0xFF);
    w[4] = (uint8_t)((g_word >> 24) & 0xFF);
    w[5] = 0xC3;
    wn = 6;
#endif

    wrc = mem_write(g_pid, va_a, w, wn);
    if (wrc != 0) {
        ace_emit(stdout, "selfmod", "L6-write-semantics", V_ERROR, 0, "",
                 wrc == -2 ? "GUP 写被拒（部分写入）：PTE 权限异常"
                           : "无法打开 /proc/pid/mem 写入",
                 g_json);
        return 1;
    }

    /* 等 victim 工作线程观察到新值 */
    usleep(1200000);

    {
        long call_after = ace_state_get_l(g_state, "call_a", -1);
        uint32_t crc_self_after =
            (uint32_t)ace_state_get_u64(g_state, "crc_self_a", 0);
        uint32_t crc_gup_after =
            (uint32_t)ace_state_get_u64(g_state, "crc_gup_a", 0);

        snprintf(hits, sizeof(hits),
                 "wrote=0x%08x before{call=%ld crc_self=0x%08x crc_gup=0x%08x} "
                 "after{call=%ld crc_self=0x%08x crc_gup=0x%08x}",
                 g_word, call_before, crc_self_before, crc_gup_before,
                 call_after, crc_self_after, crc_gup_after);

        if (call_after == (long)g_word) {
            /* 写后调用即新值：retire 生效，hook 已被销毁 —— 设计内行为 */
            if (crc_self_after == crc_gup_after) {
                v = V_CLEAN;
                score = 0;
                snprintf(note, sizeof(note),
                         "GUP 写生效且双视图收敛（retire 语义正常）："
                         "hook 已按设计被写销毁");
                ok = 1;
            } else {
                v = V_SUSPECT;
                score = 40;
                snprintf(note, sizeof(note),
                         "调用值已更新但双视图未收敛（crc_self!=crc_gup）："
                         "retire 后仍有影子残留");
            }
        } else {
            if (call_after == call_before) {
                v = V_HOOKED;
                score = 88;
                snprintf(note, sizeof(note),
                         "GUP 写后调用值不变（%ld）：shadow 未 retire，"
                         "hook 抗住了 FOLL_FORCE 写 —— 写路径隐藏异常",
                         call_after);
            } else {
                v = V_SUSPECT;
                score = 60;
                snprintf(note, sizeof(note),
                         "调用值变成 %ld（预期 %ld）：写被重定向到其他视图",
                         call_after, (long)g_word);
            }
        }
        if (!ok && crc_self_after == crc_self_before && crc_gup_after == crc_gup_before) {
            /* 双视图字节都没变但调用变了：值注入型 hook（改 pt_regs） */
            if (score < 75)
                score = 75;
            if (v == V_CLEAN)
                v = V_SUSPECT;
            snprintf(note + strlen(note), sizeof(note) - strlen(note),
                     "；页面字节未变而调用值改变：疑似寄存器注入型 hook");
        }
    }

    ace_emit(stdout, "selfmod", "L6-write-semantics", v, score, hits, note, g_json);
    return (int)v;
}
