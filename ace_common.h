/*
 * ace_common.h — lab-ace 共享基础库
 *
 * 所有 lab-ace 程序（labtarget / det_* / ace）的公共设施：
 *   - 判决模型（verdict + 0-100 置信分）
 *   - 统一的 JSON 输出契约（ace 引擎靠它聚合）
 *   - CRC32 / 高精度计时（ARM64 CNTVCT_EL0，host 回退 clock_gettime）
 *   - pagemap PFN 读取、状态文件解析
 *
 * 构建：Android NDK 或 host gcc 均可（无内核头依赖）。
 */
#ifndef ACE_COMMON_H
#define ACE_COMMON_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>

/* ---------- 判决模型 ----------
 * score 是 0-100 的「存在 hook 的置信度」，verdict 由 score 映射：
 *   0-14  CLEAN   15-49 SUSPECT  50-100 HOOKED  读取失败/无权限 = ERROR
 */
typedef enum {
    V_CLEAN = 0,
    V_SUSPECT = 1,
    V_HOOKED = 2,
    V_ERROR = 3
} ace_verdict;

static const char *ace_verdict_str(ace_verdict v)
{
    switch (v) {
    case V_CLEAN:   return "clean";
    case V_SUSPECT: return "suspect";
    case V_HOOKED:  return "hooked";
    default:        return "error";
    }
}

static ace_verdict ace_score_verdict(int score)
{
    if (score >= 50) return V_HOOKED;
    if (score >= 15) return V_SUSPECT;
    return V_CLEAN;
}

/* ---------- JSON 输出契约 ----------
 * {"det":"selfcrc","channel":"L1-self-integrity","verdict":"hooked",
 *  "score":95,"hits":[{"k":"crc_self","v":"..."}],"note":"..."}
 */
static void ace_json_begin(FILE *f, const char *det, const char *channel)
{
    fprintf(f, "{\"det\":\"%s\",\"channel\":\"%s\",", det, channel);
}

static void ace_json_field_str(FILE *f, const char *k, const char *v)
{
    fprintf(f, "\"%s\":\"%s\",", k, v);
}

static void ace_json_field_u64(FILE *f, const char *k, uint64_t v)
{
    fprintf(f, "\"%s\":%llu,", k, (unsigned long long)v);
}

static void ace_json_field_int(FILE *f, const char *k, long v)
{
    fprintf(f, "\"%s\":%ld,", k, v);
}

static void ace_json_field_dbl(FILE *f, const char *k, double v)
{
    fprintf(f, "\"%s\":%.2f,", k, v);
}

static void ace_json_field_verdict(FILE *f, const char *k, ace_verdict v)
{
    fprintf(f, "\"%s\":\"%s\",", k, ace_verdict_str(v));
}

static void ace_json_end(FILE *f)
{
    fprintf(f, "}\n");
}

/* ---------- CRC32（zlib poly，表驱动，端无关） ---------- */
static uint32_t ace_crc32(const void *data, size_t n)
{
    static uint32_t tab[256];
    static int init = 0;
    const uint8_t *p = data;
    uint32_t c = 0xFFFFFFFFu;
    size_t i;
    if (!init) {
        for (i = 0; i < 256; i++) {
            uint32_t x = (uint32_t)i;
            int b;
            for (b = 0; b < 8; b++)
                x = (x & 1) ? (x >> 1) ^ 0xEDB88320u : (x >> 1);
            tab[i] = x;
        }
        init = 1;
    }
    for (i = 0; i < n; i++)
        c = tab[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ---------- 高精度计时 ----------
 * ARM64：CNTVCT_EL0（EL0 可读），按 CNTFRQ_EL0 换算 ns。
 * host（x86/arm 非 Android）：clock_gettime(MONOTONIC_RAW)。
 */
static uint64_t ace_cntfrq = 0;

static uint64_t ace_now_ns(void)
{
#ifdef __aarch64__
    uint64_t t;
    if (ace_cntfrq == 0) {
        asm volatile("mrs %0, cntfrq_el0" : "=r"(ace_cntfrq));
        if (ace_cntfrq == 0)
            ace_cntfrq = 1000000000ull; /* 兜底 1GHz */
    }
    asm volatile("mrs %0, cntvct_el0" : "=r"(t));
    return (t * 1000000000ull) / ace_cntfrq;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

/* 有序样本的百分位（样本会被原地排序） */
static uint64_t ace_percentile(uint64_t *s, size_t n, double pct)
{
    size_t i, j;
    uint64_t t;
    if (n == 0)
        return 0;
    /* 插入排序（样本量小） */
    for (i = 1; i < n; i++) {
        t = s[i];
        j = i;
        while (j > 0 && s[j - 1] > t) {
            s[j] = s[j - 1];
            j--;
        }
        s[j] = t;
    }
    return s[(size_t)((double)(n - 1) * pct)];
}

static uint64_t ace_min_of(uint64_t *s, size_t n)
{
    uint64_t m = ~0ull;
    size_t i;
    for (i = 0; i < n; i++)
        if (s[i] < m)
            m = s[i];
    return m;
}

/* ---------- pagemap ----------
 * 返回 0 成功；-1 文件打不开/读不到。present 位 63，PFN 位 0-54。
 * Android GKI：root 有 CAP_SYS_ADMIN 才给 PFN；普通进程 pfn 恒 0。
 */
static int ace_pagemap_entry(pid_t pid, uint64_t va, uint64_t *entry)
{
    char path[64];
    int fd;
    off_t off;
    ssize_t n;
    if (!entry)
        return -1;
    snprintf(path, sizeof(path), "/proc/%d/pagemap", (int)pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    off = (off_t)((va >> 12) * 8);
    n = pread(fd, entry, 8, off);
    close(fd);
    return n == 8 ? 0 : -1;
}

static int ace_pagemap_pfn(pid_t pid, uint64_t va, uint64_t *pfn, int *present)
{
    uint64_t e = 0;
    if (ace_pagemap_entry(pid, va, &e) != 0)
        return -1;
    if (present)
        *present = (int)((e >> 63) & 1);
    if (pfn)
        *pfn = e & ((1ull << 55) - 1);
    return 0;
}

/* ---------- 状态文件 ----------
 * labtarget 周期性原子写出的 key=value 文件。路径优先级：
 *   1. RX_ACE_STATE 环境变量  2. Android /data/local/tmp   3. /tmp
 */
static const char *ace_default_state_path(void)
{
    static char buf[256];
    const char *env = getenv("RX_ACE_STATE");
    if (env && env[0])
        return env;
    if (access("/data/local/tmp", W_OK) == 0)
        snprintf(buf, sizeof(buf), "/data/local/tmp/rxlab_ace.state");
    else
        snprintf(buf, sizeof(buf), "/tmp/rxlab_ace.state");
    return buf;
}

static char *ace_state_get(const char *path, const char *key)
{
    FILE *f;
    char line[512];
    size_t klen = strlen(key);
    if (!path)
        path = ace_default_state_path();
    f = fopen(path, "r");
    if (!f)
        return NULL;
    while (fgets(line, sizeof(line), f)) {
        char *eq;
        line[strcspn(line, "\r\n")] = 0;
        if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
            eq = line + klen + 1;
            fclose(f);
            return strdup(eq);
        }
    }
    fclose(f);
    return NULL;
}

static long ace_state_get_l(const char *path, const char *key, long dflt)
{
    char *v = ace_state_get(path, key);
    long r;
    if (!v)
        return dflt;
    r = strtol(v, NULL, 0);
    free(v);
    return r;
}

static uint64_t ace_state_get_u64(const char *path, const char *key, uint64_t dflt)
{
    char *v = ace_state_get(path, key);
    uint64_t r;
    if (!v)
        return dflt;
    r = strtoull(v, NULL, 0);
    free(v);
    return r;
}

/* ---------- 杂项 ---------- */
static int ace_file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

/* procfs 伪文件（maps/kallsyms/modules）ftell 恒 0，必须动态读取 */
static char *ace_read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    size_t cap = 16384, len = 0;
    if (!f)
        return NULL;
    buf = malloc(cap + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    for (;;) {
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0)
            break;
        if (len == cap) {
            char *nb;
            cap *= 2;
            nb = realloc(buf, cap + 1);
            if (!nb)
                break;
            buf = nb;
        }
    }
    buf[len] = 0;
    fclose(f);
    if (out_len)
        *out_len = len;
    return buf;
}

/* JSON 字符串转义（hits/note 可能含引号/换行/反斜杠） */
static void ace_json_escape(FILE *f, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    fputc('"', f);
    for (; *p; p++) {
        switch (*p) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (*p < 0x20)
                fprintf(f, "\\u%04x", *p);
            else
                fputc(*p, f);
        }
    }
    fputc('"', f);
}

/* 统一判决输出：人类可读 + JSON（--json 时只出 JSON） */
static void ace_emit(FILE *out, const char *det, const char *channel,
                     ace_verdict v, int score, const char *hits, const char *note,
                     int json_only)
{
    if (json_only) {
        fprintf(out, "{\"det\":\"%s\",\"channel\":\"%s\","
                     "\"verdict\":\"%s\",\"score\":%d",
                det, channel, ace_verdict_str(v), score);
        if (hits && hits[0]) {
            fputs(",\"hits\":", out);
            ace_json_escape(out, hits);
        }
        if (note && note[0]) {
            fputs(",\"note\":", out);
            ace_json_escape(out, note);
        }
        fputs("}\n", out);
    } else {
        fprintf(out, "[%s] %s verdict=%s score=%d\n", det, channel,
                ace_verdict_str(v), score);
        if (hits && hits[0])
            fprintf(out, "  hits: %s\n", hits);
        if (note && note[0])
            fprintf(out, "  note: %s\n", note);
    }
}

#endif /* ACE_COMMON_H */
