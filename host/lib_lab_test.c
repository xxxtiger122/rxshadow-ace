/* lib_lab_test.c — 库模式端到端：lab_target_start → 状态文件 → det_run → stop */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int lab_target_start(const char *state, int interval_ms);
extern void lab_target_stop(void);
extern int det_selfcrc_run(const char *state, char *out, size_t n);

int main(int argc, char **argv)
{
    const char *state = argc > 1 ? argv[1] : "/tmp/rxlab_ace.state";
    char buf[8192];
    int rc;

    if (lab_target_start(state, 500) != 0) {
        fprintf(stderr, "start FAIL\n");
        return 1;
    }
    printf("started, waiting for state...\n");
    usleep(1200000);
    memset(buf, 0, sizeof(buf));
    rc = det_selfcrc_run(state, buf, sizeof(buf) - 1);
    printf("selfcrc rc=%d out=%.160s\n", rc, buf);
    lab_target_stop();
    printf("stopped\n");
    return rc == 3 ? 1 : 0;
}
