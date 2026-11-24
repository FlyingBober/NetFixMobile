#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="/usr/local/bin"
PURGE=0

usage() {
    cat <<'EOF'
NetFix Linux Headless uninstaller

Usage:
  ./linux/uninstall.sh [options]

Options:
  --purge            Also remove /etc/netfix, /var/lib/netfix, reset DNS/hosts, and delete user 'netfix'
  --bin-dir <dir>    Installed bin directory (default: /usr/local/bin)
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge)
            PURGE=1
            shift
            ;;
        --bin-dir)
            [[ $# -ge 2 ]] || { echo "error: --bin-dir requires a path" >&2; exit 2; }
            BIN_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

run_as_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

CTL_BIN="${BIN_DIR}/netfixctl"
TG_BIN="${BIN_DIR}/netfix-tgproxy"

if [[ -x "${CTL_BIN}" ]]; then
    UNINSTALL_ARGS=(uninstall)
    if [[ "${PURGE}" -eq 1 ]]; then
        UNINSTALL_ARGS+=(--purge)
    fi
    run_as_root "${CTL_BIN}" "${UNINSTALL_ARGS[@]}"
else
    if command -v systemctl >/dev/null 2>&1; then
        run_as_root systemctl disable --now netfix-dpi.service netfix-tgproxy.service netfix.target 2>/dev/null || true
    fi
    run_as_root rm -f /etc/systemd/system/netfix-dpi.service /etc/systemd/system/netfix-tgproxy.service /etc/systemd/system/netfix.target
    run_as_root rm -f /etc/NetworkManager/dispatcher.d/90-netfix.sh
    run_as_root rm -f /usr/local/libexec/netfix/nfqws /usr/local/libexec/netfix/ciadpi
    run_as_root rmdir /usr/local/libexec/netfix 2>/dev/null || true
    if [[ "${PURGE}" -eq 1 ]]; then
        run_as_root rm -rf /etc/netfix /var/lib/netfix
    fi
    if command -v systemctl >/dev/null 2>&1; then
        run_as_root systemctl daemon-reload || true
    fi
fi

run_as_root rm -f "${CTL_BIN}" "${TG_BIN}"

if [[ "${PURGE}" -eq 1 ]] && id netfix >/dev/null 2>&1; then
    if command -v userdel >/dev/null 2>&1; then
        run_as_root userdel netfix 2>/dev/null || true
    fi
fi

echo "NetFix Linux uninstalled (purge=${PURGE})."
