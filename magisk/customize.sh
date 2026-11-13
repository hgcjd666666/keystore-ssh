#!/system/bin/sh
# Magisk / KernelSU 安装时回调（此时模块文件已解压到 $MODPATH）

ui_print "- 调一下权限"

# 解压后的默认权限一律是 0644，agent 和脚本要放开执行位
if type set_perm >/dev/null 2>&1; then
  set_perm_recursive "$MODPATH" 0 0 0755 0644
  set_perm "$MODPATH/service.sh" 0 0 0755
  [ -f "$MODPATH/bin/ksv-agent" ] && set_perm "$MODPATH/bin/ksv-agent" 0 0 0755
else
  chmod 0755 "$MODPATH/service.sh" "$MODPATH/bin/ksv-agent" 2>/dev/null
fi

ui_print "- 重启后自己就起来了"
