#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="/usr/local/bin"
FROM_LOCAL=""
SKIP_DOWNLOAD=0
NO_BUILD=0
DO_ENABLE=0
DO_START=0

usage() {
    cat <<'EOF'
NetFixLinux Installer (CLI / Daemons + optional Desktop GUI)

Usage:
  ./install.sh [options]

Options:
  --from-local <dir>   Pass pre-downloaded nfqws/ciadpi directory to `netfixctl setup`
  --skip-download      Do not download missing nfqws/ciadpi binaries from GitHub
  --no-build           Install prebuilt binaries without compiling
  --enable             Enable systemd autostart (`netfixctl enable all`)
  --start              Start services after setup (`netfixctl start all`)
  --bin-dir <dir>      Target bin directory (default: /usr/local/bin)
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-local)
            [[ $# -ge 2 ]] || { echo "error: --from-local requires a path" >&2; exit 2; }
            FROM_LOCAL="$2"
            shift 2
            ;;
        --skip-download)
            SKIP_DOWNLOAD=1
            shift
            ;;
        --no-build)
            NO_BUILD=1
            shift
            ;;
        --enable)
            DO_ENABLE=1
            shift
            ;;
        --start)
            DO_START=1
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

run_as_builder() {
    if [[ "${EUID}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        sudo -u "${SUDO_USER}" -H "$@"
    else
        "$@"
    fi
}

run_as_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

find_prebuilt_binaries() {
    if [[ -x "${SCRIPT_DIR}/bin/netfixctl" && -x "${SCRIPT_DIR}/bin/netfix-tgproxy" ]]; then
        CTL_BIN="${SCRIPT_DIR}/bin/netfixctl"
        TG_BIN="${SCRIPT_DIR}/bin/netfix-tgproxy"
        [[ -x "${SCRIPT_DIR}/bin/netfixlinux-gui" ]] && GUI_BIN="${SCRIPT_DIR}/bin/netfixlinux-gui"
        return 0
    elif [[ -x "${SCRIPT_DIR}/netfixctl" && -x "${SCRIPT_DIR}/netfix-tgproxy" ]]; then
        CTL_BIN="${SCRIPT_DIR}/netfixctl"
        TG_BIN="${SCRIPT_DIR}/netfix-tgproxy"
        [[ -x "${SCRIPT_DIR}/netfixlinux-gui" ]] && GUI_BIN="${SCRIPT_DIR}/netfixlinux-gui"
        return 0
    elif [[ -x "${SCRIPT_DIR}/target/release/netfixctl" && -x "${SCRIPT_DIR}/target/release/netfix-tgproxy" ]]; then
        CTL_BIN="${SCRIPT_DIR}/target/release/netfixctl"
        TG_BIN="${SCRIPT_DIR}/target/release/netfix-tgproxy"
        [[ -x "${SCRIPT_DIR}/target/release/netfixlinux-gui" ]] && GUI_BIN="${SCRIPT_DIR}/target/release/netfixlinux-gui"
        return 0
    fi
    return 1
}

CTL_BIN=""
TG_BIN=""
GUI_BIN=""

if [[ "${NO_BUILD}" -eq 0 ]]; then
    if find_prebuilt_binaries; then
        echo "[1/4] Found prebuilt release binaries in directory, skipping compilation..."
    elif run_as_builder bash -lc 'command -v cargo >/dev/null 2>&1'; then
        echo "[1/4] Building release binaries with cargo..."
        run_as_builder bash -lc "cd '$SCRIPT_DIR' && cargo build --release --workspace --locked"
        find_prebuilt_binaries || true
    elif command -v docker >/dev/null 2>&1 && docker image inspect netfix-rust-ci:latest >/dev/null 2>&1; then
        echo "[1/4] Building release binaries with Docker (netfix-rust-ci:latest)..."
        REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
        BUILD_UID="$(id -u)"
        BUILD_GID="$(id -g)"
        if [[ "${EUID}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
            BUILD_UID="$(id -u "${SUDO_USER}")"
            BUILD_GID="$(id -g "${SUDO_USER}")"
        fi
        mkdir -p /tmp/netfix-cargo-cache
        chown "${BUILD_UID}:${BUILD_GID}" /tmp/netfix-cargo-cache 2>/dev/null || true
        docker run --rm --user "${BUILD_UID}:${BUILD_GID}" \
            -e HOME=/tmp -e CARGO_HOME=/tmp/cargo \
            -v "${REPO_ROOT}:/work" \
            -v /tmp/netfix-cargo-cache:/tmp/cargo \
            -w /work/linux netfix-rust-ci:latest \
            cargo build --release --workspace --locked
        find_prebuilt_binaries || true
    else
        echo "error: neither cargo nor Docker image 'netfix-rust-ci:latest' found." >&2
        echo "Install Rust (https://rustup.rs) or build with --no-build after compiling." >&2
        exit 1
    fi
else
    echo "[1/4] Skipping build (--no-build)..."
    find_prebuilt_binaries || true
fi

if [[ -z "${CTL_BIN}" || -z "${TG_BIN}" || ! -x "${CTL_BIN}" || ! -x "${TG_BIN}" ]]; then
    echo "error: release binaries not found at bin/, target/release/ or root." >&2
    exit 1
fi

echo "[2/4] Stopping running NetFix services (if active) and installing binaries to ${BIN_DIR}..."
if command -v systemctl >/dev/null 2>&1; then
    run_as_root systemctl stop netfix-dpi.service netfix-tgproxy.service 2>/dev/null || true
fi
run_as_root install -d -m 0755 "${BIN_DIR}"
run_as_root install -m 0755 "${CTL_BIN}" "${BIN_DIR}/netfixctl"
run_as_root install -m 0755 "${TG_BIN}" "${BIN_DIR}/netfix-tgproxy"

if [[ -n "${GUI_BIN}" && -x "${GUI_BIN}" ]]; then
    echo "    Installing NetFixLinux Desktop GUI..."
    run_as_root install -m 0755 "${GUI_BIN}" "${BIN_DIR}/netfixlinux-gui"

    DESKTOP_SRC="${SCRIPT_DIR}/share/applications/dev.flyingbober.netfixlinux.desktop"
    [[ -f "${DESKTOP_SRC}" ]] || DESKTOP_SRC="${SCRIPT_DIR}/crates/netfixlinux-gui/assets/dev.flyingbober.netfixlinux.desktop"
    if [[ -f "${DESKTOP_SRC}" ]]; then
        run_as_root install -d -m 0755 /usr/share/applications
        TMP_DESKTOP="$(mktemp)"
        sed "s|^Exec=.*|Exec=${BIN_DIR}/netfixlinux-gui|" "${DESKTOP_SRC}" > "${TMP_DESKTOP}"
        run_as_root install -m 0644 "${TMP_DESKTOP}" /usr/share/applications/dev.flyingbober.netfixlinux.desktop
        rm -f "${TMP_DESKTOP}"
    fi

    POLICY_SRC="${SCRIPT_DIR}/share/polkit-1/actions/dev.flyingbober.netfixlinux.policy"
    [[ -f "${POLICY_SRC}" ]] || POLICY_SRC="${SCRIPT_DIR}/crates/netfixlinux-gui/assets/dev.flyingbober.netfixlinux.policy"
    if [[ -f "${POLICY_SRC}" ]]; then
        run_as_root install -d -m 0755 /usr/share/polkit-1/actions
        run_as_root install -m 0644 "${POLICY_SRC}" /usr/share/polkit-1/actions/dev.flyingbober.netfixlinux.policy
    fi

    for size in 32x32 128x128 512x512; do
        ICON_SRC="${SCRIPT_DIR}/share/icons/hicolor/${size}/apps/dev.flyingbober.netfixlinux.png"
        [[ -f "${ICON_SRC}" ]] || ICON_SRC="${SCRIPT_DIR}/crates/netfixlinux-gui/icons/${size}.png"
        if [[ -f "${ICON_SRC}" ]]; then
            run_as_root install -d -m 0755 "/usr/share/icons/hicolor/${size}/apps"
            run_as_root install -m 0644 "${ICON_SRC}" "/usr/share/icons/hicolor/${size}/apps/dev.flyingbober.netfixlinux.png"
        fi
    done
fi

echo "[3/4] Running netfixctl setup..."
SETUP_ARGS=(setup)
if [[ -n "${FROM_LOCAL}" ]]; then
    SETUP_ARGS+=(--from-local "${FROM_LOCAL}")
elif [[ -x "${SCRIPT_DIR}/engines/nfqws" || -x "${SCRIPT_DIR}/engines/ciadpi" ]]; then
    SETUP_ARGS+=(--from-local "${SCRIPT_DIR}/engines")
fi
if [[ "${SKIP_DOWNLOAD}" -eq 1 ]]; then
    SETUP_ARGS+=(--skip-download)
fi
run_as_root "${BIN_DIR}/netfixctl" "${SETUP_ARGS[@]}"

echo "[4/4] Finalizing systemd state..."
if [[ "${DO_ENABLE}" -eq 1 ]]; then
    run_as_root "${BIN_DIR}/netfixctl" enable all
fi
if [[ "${DO_START}" -eq 1 ]]; then
    run_as_root "${BIN_DIR}/netfixctl" start all
fi

echo
echo "NetFixLinux installed successfully."
echo "Next steps:"
if [[ -x "${BIN_DIR}/netfixlinux-gui" ]]; then
    echo "  - Launch GUI:           ${BIN_DIR}/netfixlinux-gui"
fi
echo "  - Check status:         sudo netfixctl status"
echo "  - Auto-pick DPI rules:  sudo netfixctl scan --engine nfqws --apply"
echo "  - Enable & start:       sudo netfixctl enable all && sudo netfixctl start all"
echo "  - Telegram proxy link:  sudo netfixctl tg link"
