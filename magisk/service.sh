#!/system/bin/sh
# late_start service 阶段：拉起 ksv-agent
#
# agent 自己用 inotify 盯着模块目录，模块被删（卸载）时它会自行退出，
# 所以这里不需要 uninstall.sh。

MODDIR=${0%/*}
BIN="$MODDIR/bin/ksv-agent"
LOG="/tmp/ksv-agent.log"
# /tmp 万一不可写就退回 /data/local/tmp
[ -w /tmp ] || LOG="/data/local/tmp/ksv-agent.log"

# 等系统起来（最多 60 秒）
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 60 ]; do
  i=$((i + 1))
  sleep 1
done

# 日志轮转，避免无限增长
[ -f "$LOG" ] && mv -f "$LOG" "$LOG.old"

# 已在运行就不重复拉起
if ! pidof ksv-agent >/dev/null 2>&1; then
  setsid "$BIN" >>"$LOG" 2>&1 </dev/null &
fi
