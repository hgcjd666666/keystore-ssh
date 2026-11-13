#!/usr/bin/env bash
# 把 PC 侧桥接装成 systemd 用户服务：开机自启，自动在局域网里找手机
#
# 用法:
#   ./install.sh            # 安装并启动
#   ./install.sh uninstall  # 停掉并删除
set -euo pipefail
cd "$(dirname "$0")"

UNIT=ksv-serve.service
UNIT_DIR="$HOME/.config/systemd/user"
DEST="$HOME/.local/share/keystore-ssh"
SOCK="${KSV_SOCK:-$HOME/.ssh/phone-agent.sock}"

if [ "${1:-}" = "uninstall" ]; then
    systemctl --user disable --now "$UNIT" 2>/dev/null || true
    rm -f "$UNIT_DIR/$UNIT"
    systemctl --user daemon-reload
    rm -rf "$DEST" "$SOCK"
    echo "已卸载 $UNIT"
    exit 0
fi

PY=$(command -v python3) || { echo "找不到 python3" >&2; exit 1; }

mkdir -p "$DEST" "$UNIT_DIR" "$(dirname "$SOCK")"
install -m 0755 phone-agent.py "$DEST/phone-agent.py"

cat > "$UNIT_DIR/$UNIT" <<EOF
[Unit]
Description=KeystoreSSH 手机 agent 桥接
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PY $DEST/phone-agent.py serve --host auto --sock $SOCK
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now "$UNIT"

# 没开 linger 的话，注销后服务会被 systemd 收掉
loginctl enable-linger "$USER" 2>/dev/null || \
    echo "（提示：sudo loginctl enable-linger $USER 可以让服务在未登录时也活着）"

sleep 1
systemctl --user --no-pager status "$UNIT" | head -8 || true

cat <<EOF

装好了。用之前先指一下 agent：
  export SSH_AUTH_SOCK=$SOCK

然后 ssh 就行，手机那边会弹指纹。
EOF
