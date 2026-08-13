/* lib_test.c — host 验证 det_*_run 库入口（JNI 前置验证） */
#include <stdio.h>
#include <string.h>

extern int det_selfcrc_run(const char *state, char *out, size_t n);
extern int det_timing_run(const char *state, char *out, size_t n);
extern int det_faultcount_run(const char *state, char *out, size_t n);
extern int det_diff_run(const char *s1, const char *s2, char *out, size_t n);

int main(int argc, char **argv)
{
    char buf[8192];
    int rc;
    if (argc < 2) {
        fprintf(stderr, "usage: lib_test <state> [state2]\n");
        return 1;
    }
    memset(buf, 0, sizeof(buf));
    rc = det_selfcrc_run(argv[1], buf, sizeof(buf) - 1);
    printf("[selfcrc] rc=%d out=%s\n", rc, buf);
    memset(buf, 0, sizeof(buf));
    rc = det_timing_run(argv[1], buf, sizeof(buf) - 1);
    printf("[timing] rc=%d out=%.200s\n", rc, buf);
    if (argc >= 3) {
        memset(buf, 0, sizeof(buf));
        rc = det_diff_run(argv[1], argv[2], buf, sizeof(buf) - 1);
        printf("[diff] rc=%d out=%.200s\n", rc, buf);
    }
    return 0;
}
