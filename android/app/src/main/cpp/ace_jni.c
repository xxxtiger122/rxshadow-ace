/*
 * ace_jni.c — JNI 绑定：无 root App 进程内运行 victim + 检测
 *
 * Android untrusted_app 域禁止 exec app 私有 ELF（SELinux），但
 * dlopen 本 App 的 .so + 进程内直接调用完全合法。本层把 lab-ace
 * 的 C 逻辑（lab_target_start/stop + det_*_run）暴露给 Kotlin。
 *
 * 聚合（ace）在 Kotlin 侧实现：Kotlin 逐个调 runDet 拿 JSON，
 * 按与 ace.c 一致的权重表融合（App 进程内无法复用 ace 的 fork/exec）。
 */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

/* ---- 从 lab-ace C 源导入的库入口 ---- */
extern int lab_target_start(const char *state_path, int interval_ms);
extern void lab_target_stop(void);

extern int det_selfcrc_run(const char *s, char *o, size_t n);
extern int det_elfhash_run(const char *s, char *o, size_t n);
extern int det_crossread_run(const char *s, char *o, size_t n);
extern int det_pagemap_run(const char *s, char *o, size_t n);
extern int det_timing_run(const char *s, char *o, size_t n);
extern int det_faultcount_run(const char *s, char *o, size_t n);
extern int det_perf_run(const char *s, char *o, size_t n);
extern int det_selfmod_run(const char *s, char *o, size_t n);
extern int det_procscan_run(const char *s, char *o, size_t n);
extern int det_trampoline_run(const char *s, char *o, size_t n);
extern int det_callstack_run(const char *s, char *o, size_t n);
extern int det_hwbp_run(const char *s, char *o, size_t n);
extern int det_linkmap_run(const char *s, char *o, size_t n);
extern int det_kallsyms_run(const char *s, char *o, size_t n);
extern int det_kcore_run(const char *s, char *o, size_t n);
extern int det_dmesg_run(const char *s, char *o, size_t n);
extern int det_sysfs_run(const char *s, char *o, size_t n);
extern int det_diff_run(const char *s1, const char *s2, char *o, size_t n);

#define OUTSZ 16384

static const char *jstr(JNIEnv *env, jstring js)
{
    static char buf[1024];
    const char *p;
    if (!js)
        return NULL;
    p = (*env)->GetStringUTFChars(env, js, NULL);
    if (!p)
        return NULL;
    snprintf(buf, sizeof(buf), "%s", p);
    (*env)->ReleaseStringUTFChars(env, js, p);
    return buf;
}

static jstring newjstr(JNIEnv *env, const char *s)
{
    return (*env)->NewStringUTF(env, s ? s : "");
}

JNIEXPORT jint JNICALL
Java_com_rxshadow_ace_AceNative_startVictim(JNIEnv *env, jclass clazz,
                                            jstring state, jint interval)
{
    (void)clazz;
    return lab_target_start(jstr(env, state), (int)interval);
}

JNIEXPORT void JNICALL
Java_com_rxshadow_ace_AceNative_stopVictim(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    lab_target_stop();
}

/* 单信道检测：按名称分发到 det_*_run，返回 JSON 契约字符串 */
JNIEXPORT jstring JNICALL
Java_com_rxshadow_ace_AceNative_runDet(JNIEnv *env, jclass clazz,
                                       jstring state, jstring detName)
{
    static char out[OUTSZ];
    const char *name = jstr(env, detName);
    const char *sp = jstr(env, state);
    int rc = 3;

    (void)clazz;
    memset(out, 0, sizeof(out));
    if (!sp || !name)
        return newjstr(env, "{\"det\":\"?\",\"channel\":\"?\",\"verdict\":\"error\",\"score\":0}");

#define DISP(n) if (!strcmp(name, #n)) rc = n##_run(sp, out, sizeof(out) - 1)
    DISP(det_selfcrc);   DISP(det_elfhash);   DISP(det_crossread);
    DISP(det_pagemap);   DISP(det_timing);    DISP(det_faultcount);
    DISP(det_perf);      DISP(det_selfmod);   DISP(det_procscan);
    DISP(det_trampoline);DISP(det_callstack); DISP(det_hwbp);
    DISP(det_linkmap);   DISP(det_kallsyms);  DISP(det_kcore);
    DISP(det_dmesg);     DISP(det_sysfs);
#undef DISP

    if (rc == 3 && !out[0])
        snprintf(out, sizeof(out),
                 "{\"det\":\"%s\",\"channel\":\"?\",\"verdict\":\"error\","
                 "\"score\":0,\"note\":\"unknown detector\"}", name);
    return newjstr(env, out);
}

/* 差分对照：det_diff_run(state, state2) */
JNIEXPORT jstring JNICALL
Java_com_rxshadow_ace_AceNative_runDiff(JNIEnv *env, jclass clazz,
                                        jstring state, jstring state2)
{
    static char out[OUTSZ];
    const char *s1 = jstr(env, state);
    const char *s2 = jstr(env, state2);
    int rc;
    (void)clazz;
    memset(out, 0, sizeof(out));
    if (!s1 || !s2)
        return newjstr(env, "{\"det\":\"diff\",\"verdict\":\"error\",\"score\":0}");
    rc = det_diff_run(s1, s2, out, sizeof(out) - 1);
    (void)rc;
    return newjstr(env, out);
}
