#!/usr/bin/env python3
"""det_libify.py — 把 det_*.c 从 main() 程序改造成「库入口 + main 包装」

对每个文件：
1. `int main(int argc, char **argv)` → `static int det_impl_main(int argc, char **argv)`
2. 文件末尾追加：
   - `int det_xxx_run(const char *state, char *json_out, size_t outsz)`：
     fmemopen + dup2 重定向 stdout → 伪造 argv[--state <path> --json] → 调 impl_main
   - `int main(...)` → 调 impl_main（命令行模式不变）

特殊处理：det_diff 的 run 入口带 state2。
"""
import re, pathlib

ROOT = pathlib.Path("/opt/data/rxshadow/lab-ace")
FILES = [
    "det_selfcrc.c", "det_elfhash.c", "det_crossread.c", "det_pagemap.c",
    "det_timing.c", "det_faultcount.c", "det_perf.c", "det_selfmod.c",
    "det_procscan.c", "det_trampoline.c", "det_callstack.c", "det_hwbp.c",
    "det_linkmap.c", "det_kallsyms.c", "det_kcore.c", "det_dmesg.c",
    "det_sysfs.c",
]

def libify(path: pathlib.Path):
    src = path.read_text(encoding="utf-8")
    name = path.stem  # det_selfcrc
    new_src, n = re.subn(r"\bint main\(int argc, char \*\*argv\)",
                         "static int det_impl_main(int argc, char **argv)", src)
    if n != 1:
        print(f"WARN {name}: main 匹配 {n} 处")
    extra = f"""
/* ===== 库入口（JNI / 无 root App 内嵌模式，det_libify.py 生成） =====
 * 将 stdout 重定向到内存 buffer，伪造 argv 复用 impl_main。
 * 无 exec / 无 fork：App 进程内直接调用（Android untrusted_app 域
 * 禁止 exec app 私有 ELF，但 dlopen .so + 进程内调用完全合法）。 */
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>

int {name}_run(const char *state_path, char *json_out, size_t outsz)
{{
    FILE *f = fmemopen(json_out, outsz, "w");
    int saved, rc;
    char *fake[] = {{ (char *)"{name}", (char *)"--state",
                      (char *)state_path, (char *)"--json", NULL }};
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
}}

int main(int argc, char **argv)
{{
    return det_impl_main(argc, argv);
}}
"""
    new_src += extra
    path.write_text(new_src, encoding="utf-8")
    print(f"OK   {name}")

def libify_diff(path: pathlib.Path):
    src = path.read_text(encoding="utf-8")
    name = path.stem
    new_src, n = re.subn(r"\bint main\(int argc, char \*\*argv\)",
                         "static int det_impl_main(int argc, char **argv)", src)
    extra = f"""
/* ===== 库入口（det_libify.py 生成，diff 特例带 state2） ===== */
#include <stdio.h>
#include <unistd.h>

int {name}_run(const char *state_path, const char *state2_path,
               char *json_out, size_t outsz)
{{
    FILE *f = fmemopen(json_out, outsz, "w");
    int saved, rc;
    char *fake[] = {{ (char *)"{name}", (char *)"--state",
                      (char *)state_path, (char *)"--state2",
                      (char *)state2_path, (char *)"--json", NULL }};
    if (!f)
        return 3;
    saved = dup(STDOUT_FILENO);
    dup2(fileno(f), STDOUT_FILENO);
    fflush(stdout);
    rc = det_impl_main(6, fake);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    fclose(f);
    return rc;
}}

int main(int argc, char **argv)
{{
    return det_impl_main(argc, argv);
}}
"""
    new_src += extra
    path.write_text(new_src, encoding="utf-8")
    print(f"OK   {name}")

for f in FILES:
    libify(ROOT / f)
libify_diff(ROOT / "det_diff.c")
print("=== 完成 ===")
