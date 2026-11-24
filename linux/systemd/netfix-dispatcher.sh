#!/bin/sh
# NetFix NetworkManager dispatcher script
# Automatically restarts netfix-dpi.service on network change to apply network-specific strategies.

INTERFACE="$1"
ACTION="$2"

# Ignore virtual/tunnel/bridge/loopback interfaces
case "$INTERFACE" in
    lo|docker*|br-*|veth*|virbr*|tun*|tap*|wg*|dummy*) exit 0 ;;
esac

case "$ACTION" in
    up|connectivity-change)
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet netfix-dpi.service; then
            logger -t netfix-dispatcher "Network change detected on $INTERFACE ($ACTION); restarting netfix-dpi.service"
            systemctl restart netfix-dpi.service
        fi
        ;;
    *)
        exit 0
        ;;
esac
