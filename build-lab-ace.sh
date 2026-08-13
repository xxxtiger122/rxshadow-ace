#!/bin/sh
# build-lab-ace.sh — 真机（Android NDK）构建 rxshadow-ace 套件
#
# 依赖：Android NDK（r27c，README 同款），aarch64-linux-android28-clang 在 PATH
# 用法：
#   NDK=/path/to/ndk-r27c ./build-lab-ace.sh
#   或先把 NDK 工具链目录加进 PATH
#
# 产物：bin/arm64/{labtarget,det_*,ace,sim_hook}
set -e

CC=${CC:-aarch64-linux-android28-clang}
if [ -n "${NDK:-}" ]; then
    TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
    CC="$TC/aarch64-linux-android28-clang"
fi
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "找不到 $CC —— 请设 NDK= 或把 NDK 工具链加进 PATH" >&2
    exit 1
fi

cd "$(dirname "$0")"
OUT=bin/arm64
mkdir -p "$OUT"
CFLAGS="-O0 -g -Wall -std=gnu11 -pthread -fPIE -fno-inline"

for f in labtarget det_selfcrc det_crossread det_pagemap det_timing \
         det_faultcount det_selfmod det_kallsyms det_kcore det_dmesg \
         det_sysfs det_elfhash det_trampoline det_callstack det_hwbp \
         det_procscan det_perf det_diff det_linkmap ace; do
    echo "  CC  $f"
    "$CC" $CFLAGS -o "$OUT/$f" "$f.c"
done
echo "  CC  sim_hook"
"$CC" $CFLAGS -o "$OUT/sim_hook" host/sim_hook.c

echo "== 产物 =="
ls -la "$OUT"
echo
echo "部署："
echo "  adb push $OUT /data/local/tmp/lab-ace/"
echo "  adb push ace_run.sh /data/local/tmp/lab-ace/"
echo "  adb shell su -c 'chmod +x /data/local/tmp/lab-ace/*'"
echo "  adb shell su -c 'cd /data/local/tmp/lab-ace && RX_HOOK=1 sh ace_run.sh'"
