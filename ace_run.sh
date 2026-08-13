#!/system/bin/sh
# ace_run.sh — 真机端到端编排（OnePlus / GKI 6.6 / ksud）
#
# 用法（adb shell su）：
#   ace_run.sh                干净基线：只跑 labtarget + ACE（不挂 hook）
#   RX_HOOK=1 ace_run.sh      自动 attach + hook + map + cave 后跑 ACE
#   RX_HOOK=1 RX_VA=<va> RX_HEX=<hex> ace_run.sh  指定页/洞内容
#   RX_SELFMOD=1 ace_run.sh   末尾追加写语义审计（会销毁 hook）
#
# 输出：/data/local/tmp/ace_report.txt + 终端表格
set -u

DIR=/data/local/tmp
ST=$DIR/rxlab_ace.state
BIN=$DIR/lab-ace
FLAG=$DIR/rxlab_ace_stop

kill_lab() {
    [ -f "$ST" ] && PID=$(grep '^pid=' "$ST" | cut -d= -f2)
    [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null
    rm -f "$ST" "$ST.tmp" "$FLAG"
}

echo "== lab-ace: 启动 labtarget =="
kill_lab
"$BIN/labtarget" --state "$ST" --interval 800 >"$DIR/labtarget.log" 2>&1 &
for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "$ST" ] && break
    sleep 0.3
done
PID=$(grep '^pid=' "$ST" 2>/dev/null | cut -d= -f2)
if [ -z "${PID:-}" ]; then
    echo "ERROR: labtarget 未写出状态文件"; exit 1
fi
echo "labtarget pid=$PID"

if [ "${RX_HOOK:-0}" = "1" ]; then
    echo "== hooking: attach $PID + map + cave =="
    ksud kpm control rxshadow "attach $PID" || echo "WARN attach"
    ksud kpm control rxshadow hook        || echo "WARN hook"
    VA=${RX_VA:-$(grep '^va_a=' "$ST" | cut -d= -f2)}
    HEX=${RX_HEX:-600c8052}
    echo "map $VA / cave $VA $HEX"
    ksud kpm control rxshadow "map $VA"   || echo "WARN map"
    sleep 0.5
    ksud kpm control rxshadow "cave $VA $HEX" || echo "WARN cave"
    sleep 1
    ksud kpm control rxshadow probe       || echo "WARN probe"
fi

echo "== ACE 检测 =="
ARGS="--pid $PID --state $ST"
[ "${RX_SELFMOD:-0}" = "1" ] && ARGS="$ARGS --with-selfmod"
"$BIN/ace" $ARGS --out "$DIR/ace_report.txt" || RC=$?
echo "ace 退出码=${RC:-0}（0=clean 1=suspect 2=hooked）"
echo "完整报告: $DIR/ace_report.txt"

# 清理：默认退出 labtarget（保留 hook 状态可由 rxctl 另行操作）
touch "$FLAG"
sleep 1
kill_lab
