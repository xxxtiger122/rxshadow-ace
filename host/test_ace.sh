#!/bin/sh
# test_ace.sh — host 侧验证脚本（验证阶梯第 1 级：编译 + 逻辑 + 判决）
#
# 场景矩阵：
#   clean  → 全信道应 CLEAN，ace 总判定 clean
#   cave   → selfcrc/crossread 应 HOOKED，ace 总判定 hooked
#   brk    → 功能信道应命中（调用异常），ace 总判定 hooked
#   split  → crossread/selfcrc 应命中（模拟 victim 自报分裂），ace 判定 hooked
#
# 用法：PATH=bin/host:$PATH sh host/test_ace.sh
set -u

BIN="${BIN:-$(pwd)/bin/host}"
ST="${TMPDIR:-/tmp}/rxlab_ace.state"
PASS=0
FAIL=0

run_scenario() {
    mode="$1"
    expect_verdict="$2"
    rm -f "$ST" "$ST.tmp"
    "$BIN/sim_hook" "$mode" --state "$ST" --interval-ms 500 >/dev/null 2>&1 &
    SIM_PID=$!
    sleep 1.2
    if [ ! -s "$ST" ]; then
        echo "FAIL[$mode] sim_hook 未写出状态文件"
        kill $SIM_PID 2>/dev/null
        FAIL=$((FAIL+1))
        return
    fi
    OUT=$("$BIN/ace" --pid "$SIM_PID" --state "$ST" 2>&1)
    RC=$?
    kill $SIM_PID 2>/dev/null
    wait $SIM_PID 2>/dev/null
    VERDICT=$(echo "$OUT" | grep "总体判定" | sed 's/.*总体判定 : \([a-z]*\).*/\1/')
    if [ "$VERDICT" = "$expect_verdict" ]; then
        echo "PASS[$mode] 总判定=$VERDICT (rc=$RC)"
        PASS=$((PASS+1))
    else
        echo "FAIL[$mode] 期望 $expect_verdict 实际 $VERDICT (rc=$RC)"
        echo "----- ace 输出 -----"
        echo "$OUT"
        FAIL=$((FAIL+1))
    fi
    rm -f "$ST" "$ST.tmp"
}

echo "== ACE host 验证（$(uname -m)）=="
run_scenario clean  clean
run_scenario cave   hooked
run_scenario brk    hooked
run_scenario split  hooked

# differential：双 victim 差分（A=clean, B=split 自报分裂）
ST2="${TMPDIR:-/tmp}/rxlab_ace2.state"
rm -f "$ST" "$ST.tmp" "$ST2" "$ST2.tmp"
"$BIN/sim_hook" clean --state "$ST" --interval-ms 500 >/dev/null 2>&1 &
SIM_A=$!
"$BIN/sim_hook" split --state "$ST2" --interval-ms 500 >/dev/null 2>&1 &
SIM_B=$!
sleep 1.2
if [ -s "$ST" ] && [ -s "$ST2" ]; then
    OUT=$("$BIN/ace" --pid "$SIM_A" --state "$ST" --state2 "$ST2" 2>&1)
    RC=$?
    VERDICT=$(echo "$OUT" | grep "总体判定" | sed 's/.*总体判定 : \([a-z]*\).*/\1/')
    DIFF_HIT=$(echo "$OUT" | grep "L2-differential" | grep -c hooked)
    DIFF_LINE=$(echo "$OUT" | grep "L2-differential" | head -1)
    if [ "$DIFF_HIT" -ge 1 ]; then
        echo "PASS[diff] det_diff 差分锁定（A clean vs B split）：$DIFF_LINE"
        PASS=$((PASS+1))
    else
        echo "FAIL[diff] det_diff 未命中（期望 hooked）"
        echo "$OUT"
        FAIL=$((FAIL+1))
    fi
else
    echo "FAIL[diff] sim_hook 未写出状态文件"
    FAIL=$((FAIL+1))
fi
kill $SIM_A $SIM_B 2>/dev/null
wait $SIM_A $SIM_B 2>/dev/null
rm -f "$ST" "$ST.tmp" "$ST2" "$ST2.tmp"

echo "== 结果: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]
