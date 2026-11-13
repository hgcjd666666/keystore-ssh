#!/system/bin/sh
# late_start service 阶段：拉起 ksv-agent
#
# agent 自己用 inotify 盯着模块目录，模块被删（卸载）时它会自行退出，
# 所以这里不需要 uninstall.sh。

MODDIR=${0%/*}
BIN="$MODDIR/bin/ksv-agent"
APK="$MODDIR/app.apk"
PKG=com.dsh.keystore
LOG="$MODDIR/ksv-agent.log"

# 等系统起来（最多 60 秒）：太早的话 getprop/pm 还用不了
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 60 ]; do
  i=$((i + 1))
  sleep 1
done

# 日志轮转，避免无限增长
[ -f "$LOG" ] && mv -f "$LOG" "$LOG.old"

# 模块里带了 APK 且尚未安装时补装一份
# （先拷到 /data/local/tmp，否则 pm 以 shell 身份读不到 /data/adb 下的文件）
if [ -f "$APK" ] && ! pm list packages 2>/dev/null | grep -qx "package:$PKG"; then
  TMP=/data/local/tmp/ksv-install.apk
  if cp -f "$APK" "$TMP"; then
    chmod 644 "$TMP"
    pm install -r "$TMP" >>"$LOG" 2>&1
    rm -f "$TMP"
  fi
fi

# 已在运行就不重复拉起
if ! pidof ksv-agent >/dev/null 2>&1; then
  setsid "$BIN" >>"$LOG" 2>&1 </dev/null &
fi
