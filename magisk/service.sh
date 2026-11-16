#!/system/bin/sh
# late_start service 阶段：拉起 ksv-agent
#
# 等 boot_completed、日志文件、单实例检查都已经在 ksv-agent 自己里，
# 这里只负责把路径传进去（路径全部由启动参数决定，程序里没有默认值）。
#
# 模块卸载后本来就要重启，所以这里不需要 uninstall.sh。

MODDIR=${0%/*}

setsid "$MODDIR/bin/ksv-agent" \
  -s /tmp/ksv-agent.sock \
  -l /tmp/ksv-agent.log &
