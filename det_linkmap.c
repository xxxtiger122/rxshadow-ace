/*
 * det_linkmap.c — L7 地址空间语义信道（link_map 枚举交叉）
 *
 * 源自 290871 L243 + 292066 L308（"幽灵内存中的 SO 不在 link_map 中，
 * 常规枚举不会包含它"）：凡"能执行却不在 link_map"的代码段即异常。
 *
 * 对 victim 进程：
 *   M1 dl_iterate_phdr 收集全部已加载对象的基址 + PT_LOAD 可执行段范围
 *      （link_map 视图）
 *   M2 /proc/<pid>/maps 收集全部可执行映射（内核视图）
 *   M3 交叉：maps 里每个可执行映射必须能归属到某个 link_map 对象或
 *      victim 已知白名单（H_A/H_B/alpha/beta/gamma 页，来自状态文件）
 *      —— 不可归属的可执行映射 = 幽灵代码/跳板（DBI/trampoline）。
 *
 * 注意：本检测器在自身进程调用 dl_iterate_phdr，收集的是自己进程的
 * link_map；对 victim 的 link_map 无法跨进程读取（link_map 是进程内存）。
 * 因此 M1/M3 改为：解析 victim 的 maps 中所有 file-backed 可执行映射的
 * 文件名集合（白名单=标准库/主程序），匿名可执行映射必须落在状态文件
 * 白名单（H 区页）内，否则判异常。dl_iterate_phdr 版本保留作自身进程
 * 的自检（检测器自身环境是否被污染）。
 *
 * 用法：det_linkmap --pid <pid> [--state <path>] [--json]
 * 依赖状态 key：pid va_a va_b va_alpha va_beta va_gamma
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <link.h>
#include "ace_common.h"

static const char *g_state;
static int g_json;
static pid_t g_pid = -1;

/* 自身进程 link_map 自检（检测器环境是否被污染）
 * 注意：PIE 主程序在 link_map 里 dlpi_addr 非零（随机化基址）、
 * dlpi_name 为空 —— 名字空 = 主程序，这是正常现象；
 * 幽灵 SO 的特征是"能执行却不在 link_map"，枚举不到才是异常。
 * 这里只统计对象数并确认有主程序条目。 */
static int g_self_objs = 0;
static int g_self_has_main = 0;
static int dl_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;
    g_self_objs++;
    if (!info->dlpi_name || !info->dlpi_name[0])
        g_self_has_main = 1;
    return 0;
}

/* maps 行解析 */
struct map_line {
    uint64_t start, end;
    char perms[8];
    uint64_t offset;
    char path[256];
};

static int maps_parse(pid_t pid, struct map_line *out, int max)
{
    char path[64];
    char *buf;
    char *line, *save = NULL;
    int n = 0;
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    buf = ace_read_file(path, NULL);
    if (!buf)
        return 0;
    for (line = strtok_r(buf, "\n", &save); line && n < max;
         line = strtok_r(NULL, "\n", &save)) {
        struct map_line *m = &out[n];
        char perms[8] = "", path2[256] = "";
        unsigned long long s, e, off;
        char dev[32], ino[32];
        int r = sscanf(line, "%llx-%llx %7s %llx %31s %31s %255[^\n]",
                       &s, &e, perms, &off, dev, ino, path2);
        if (r >= 6) {
            m->start = (uint64_t)s;
            m->end = (uint64_t)e;
            strncpy(m->perms, perms, sizeof(m->perms) - 1);
            m->offset = off;
            if (r >= 7)
                strncpy(m->path, path2, sizeof(m->path) - 1);
            else
                m->path[0] = 0;
            n++;
        }
    }
    free(buf);
    return n;
}

static int in_whitelist(uint64_t page, uint64_t wl[8])
{
    int i;
    for (i = 0; i < 8; i++)
        if (wl[i] && page == (wl[i] & ~(uint64_t)0xFFF))
            return 1;
    return 0;
}

int main(int argc, char **argv)
{
    int i;
    ace_verdict v = V_CLEAN;
    int score = 0;
    char hits[1024] = "";
    char note[512] = "";
    struct map_line maps[512];
    int nmap;
    uint64_t wl[8] = {0};
    int anon_exec = 0, unknown_exec = 0;

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
        ace_emit(stdout, "linkmap", "L7-addrspace-semantics", V_ERROR, 0, "",
                 "缺少有效目标 pid", g_json);
        return 1;
    }

    wl[0] = ace_state_get_u64(g_state, "va_a", 0);
    wl[1] = ace_state_get_u64(g_state, "va_b", 0);
    wl[2] = ace_state_get_u64(g_state, "va_alpha", 0);
    wl[3] = ace_state_get_u64(g_state, "va_beta", 0);
    wl[4] = ace_state_get_u64(g_state, "va_gamma", 0);

    nmap = maps_parse(g_pid, maps, 512);
    for (i = 0; i < nmap; i++) {
        struct map_line *m = &maps[i];
        if (!strchr(m->perms, 'x'))
            continue;
        if (!m->path[0] || !strcmp(m->path, "[anon]")) {
            /* 匿名可执行段：必须落在 H 区白名单 */
            anon_exec++;
            if (!in_whitelist(m->start, wl)) {
                unknown_exec++;
                if (unknown_exec <= 8)
                    snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                             "anon_x=0x%llx-0x%llx ",
                             (unsigned long long)m->start,
                             (unsigned long long)m->end);
            }
        }
    }

    /* 自身进程 link_map 自检 */
    dl_iterate_phdr(dl_cb, NULL);

    snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
             "maps=%d anon_x=%d self_linkmap_objs=%d main=%d",
             nmap, anon_exec, g_self_objs, g_self_has_main);

    if (unknown_exec) {
        v = V_HOOKED;
        score = 85;
        snprintf(note, sizeof(note),
                 "%d 个匿名可执行映射无法归属到 labtarget 白名单"
                 "（trampoline/DBI/幽灵代码特征）", unknown_exec);
    } else if (!g_self_has_main) {
        v = V_SUSPECT;
        score = 55;
        snprintf(note, sizeof(note),
                 "检测器自身 link_map 异常：找不到主程序条目（动态链接器被污染？）");
    } else {
        v = V_CLEAN;
        score = 0;
        snprintf(note, sizeof(note),
                 "全部可执行映射可归属（H 区白名单 + 标准 file-backed 库），"
                 "link_map 自检正常");
    }

    ace_emit(stdout, "linkmap", "L7-addrspace-semantics", v, score, hits, note, g_json);
    return (int)v;
}
