/*
 * det_sysfs.c — L5 系统指纹信道
 *
 * 检查 KPM / 内核修改在用户态可见的所有静态痕迹：
 *   S1 /sys/module/rxshadow 目录（KPM 常以模块形态挂载）
 *   S2 /proc/modules 条目
 *   S3 ksud（KernelSU-Next/SukiSU 管理器）本体与 kpm 列表
 *   S4 /proc/cmdline 的 kp/kpm/susfs 启动参数
 *   S5 KernelPatch 控制接口（/sys/kernel/kp* / /proc/kp* / /sys/fs/kp*）
 *   S6 /proc/version 定制内核特征
 *
 * 用法：det_sysfs [--json]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include "ace_common.h"

static int det_impl_main(int argc, char **argv)
{
    int g_json = 0;
    int i;
    char hits[1024] = "";
    char note[512] = "";
    ace_verdict v = V_CLEAN;
    int score = 0;
    int have_ksud = 0, have_kp_iface = 0, cmdline_hit = 0, mod_hit = 0;

    for (i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--json"))
            g_json = 1;

    /* S1/S2: 模块痕迹 */
    if (ace_file_exists("/sys/module/rxshadow")) {
        mod_hit = 1;
        snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                 "sys_module_rxshadow=yes ");
    }
    {
        char *mb = ace_read_file("/proc/modules", NULL);
        if (mb) {
            if (strstr(mb, "rxshadow")) {
                mod_hit = 1;
                snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                         "proc_modules_rxshadow=yes ");
            }
            free(mb);
        }
    }

    /* S3: ksud */
    if (ace_file_exists("/data/adb/ksud") ||
        ace_file_exists("/data/adb/ksud-next") ||
        ace_file_exists("/data/adb/ksud-ksu") ||
        ace_file_exists("/data/adb/ksu")) {
        have_ksud = 1;
        snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                 "ksud_bin=/data/adb/ksud ");
    }
    if (have_ksud) {
        FILE *p = popen("ksud kpm list 2>/dev/null", "r");
        if (p) {
            char out[1024] = "";
            size_t n = fread(out, 1, sizeof(out) - 1, p);
            out[n] = 0;
            pclose(p);
            if (n > 0) {
                snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                         "ksud_kpm_list=[%s] ", out);
                if (strcasestr(out, "rxshadow"))
                    mod_hit = 1;
            }
        }
    }

    /* S4: cmdline */
    {
        char *cl = ace_read_file("/proc/cmdline", NULL);
        if (cl) {
            if (strcasestr(cl, "kp") || strcasestr(cl, "kpm") ||
                strcasestr(cl, "susfs") || strcasestr(cl, "ksud")) {
                cmdline_hit = 1;
                snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                         "cmdline_kp=yes ");
            }
            free(cl);
        }
    }

    /* S5: KernelPatch 接口 */
    {
        static const char *paths[] = {
            "/sys/kernel/kp", "/sys/kernel/kp_patched",
            "/proc/kp", "/sys/fs/kp", "/sys/kernel/kpatch", NULL
        };
        for (i = 0; paths[i]; i++) {
            if (ace_file_exists(paths[i])) {
                have_kp_iface = 1;
                snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                         "kp_iface=%s ", paths[i]);
            }
        }
    }

    /* S6: 版本串 */
    {
        char *ver = ace_read_file("/proc/version", NULL);
        if (ver) {
            char *p = strcasestr(ver, "ksu") ? strcasestr(ver, "ksu") :
                      (strcasestr(ver, "kpatch") ? strcasestr(ver, "kpatch") : NULL);
            if (p) {
                snprintf(hits + strlen(hits), sizeof(hits) - strlen(hits),
                         "version_hint=%.64s ", p);
                cmdline_hit = 1;
            }
            free(ver);
        }
    }

    if (mod_hit) {
        v = V_HOOKED;
        score = 100;
        snprintf(note, sizeof(note),
                 "rxshadow KPM 模块在用户态可见（/sys/module 或 /proc/modules 或 ksud kpm list）");
    } else if (have_ksud || have_kp_iface) {
        v = V_SUSPECT;
        score = 40;
        snprintf(note, sizeof(note),
                 "设备带 ksud/KernelPatch 管理面（可加载 KPM 的环境），"
                 "但未发现 rxshadow 本体");
    } else if (cmdline_hit) {
        v = V_SUSPECT;
        score = 30;
        snprintf(note, sizeof(note), "启动参数/版本串含 KPM 特征");
    } else {
        snprintf(note, sizeof(note), "系统指纹干净（无 KPM 管理面痕迹）");
    }

    ace_emit(stdout, "sysfs", "L5-sysfs-fingerprint", v, score, hits, note, g_json);
    return (int)v;
}

/* ===== 库入口（JNI / 无 root App 内嵌模式，det_libify.py 生成） =====
 * 将 stdout 重定向到内存 buffer，伪造 argv 复用 impl_main。
 * 无 exec / 无 fork：App 进程内直接调用（Android untrusted_app 域
 * 禁止 exec app 私有 ELF，但 dlopen .so + 进程内调用完全合法）。 */
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>

int det_sysfs_run(const char *state_path, char *json_out, size_t outsz)
{
    FILE *f = fmemopen(json_out, outsz, "w");
    int saved, rc;
    char *fake[] = { (char *)"det_sysfs", (char *)"--state",
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
