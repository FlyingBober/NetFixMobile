#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

VERSION=""
ARCH="$(uname -m)"
DIST_DIR="${SCRIPT_DIR}/dist"
DO_TAR=0
DO_DEB=0
DO_RPM=0

usage() {
    cat <<'EOF'
NetFix Linux Packaging Script

Usage:
  ./linux/package.sh [options]

Options:
  --version <ver>    Package version (default: parsed from Cargo.toml or '0.1.0')
  --arch <arch>      Architecture: x86_64, aarch64 (default: host uname -m)
  --dist-dir <dir>   Output directory (default: linux/dist)
  --tar              Build .tar.gz archive
  --deb              Build .deb package
  --rpm              Build .rpm package
  --all              Build all available package formats
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            [[ $# -ge 2 ]] || { echo "error: --version requires an argument" >&2; exit 2; }
            VERSION="$2"
            shift 2
            ;;
        --arch)
            [[ $# -ge 2 ]] || { echo "error: --arch requires an argument" >&2; exit 2; }
            ARCH="$2"
            shift 2
            ;;
        --dist-dir)
            [[ $# -ge 2 ]] || { echo "error: --dist-dir requires an argument" >&2; exit 2; }
            DIST_DIR="$2"
            shift 2
            ;;
        --tar)
            DO_TAR=1
            shift
            ;;
        --deb)
            DO_DEB=1
            shift
            ;;
        --rpm)
            DO_RPM=1
            shift
            ;;
        --all)
            DO_TAR=1
            DO_DEB=1
            DO_RPM=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "${DO_TAR}" -eq 0 && "${DO_DEB}" -eq 0 && "${DO_RPM}" -eq 0 ]]; then
    DO_TAR=1
    DO_DEB=1
    DO_RPM=1
fi

if [[ -z "${VERSION}" ]]; then
    VERSION=$(grep -m1 '^version = ' "${SCRIPT_DIR}/crates/netfixctl/Cargo.toml" | cut -d'"' -f2 || true)
    [[ -n "${VERSION}" ]] || VERSION="0.1.0"
fi
VERSION="${VERSION#v}"

# Architecture mapping
case "${ARCH}" in
    x86_64|amd64)
        PKG_ARCH="x86_64"
        DEB_ARCH="amd64"
        RPM_ARCH="x86_64"
        ;;
    aarch64|arm64)
        PKG_ARCH="aarch64"
        DEB_ARCH="arm64"
        RPM_ARCH="aarch64"
        ;;
    *)
        PKG_ARCH="${ARCH}"
        DEB_ARCH="${ARCH}"
        RPM_ARCH="${ARCH}"
        ;;
esac

CTL_BIN=""
TG_BIN=""
if [[ -x "${SCRIPT_DIR}/target/release/netfixctl" && -x "${SCRIPT_DIR}/target/release/netfix-tgproxy" ]]; then
    CTL_BIN="${SCRIPT_DIR}/target/release/netfixctl"
    TG_BIN="${SCRIPT_DIR}/target/release/netfix-tgproxy"
elif [[ -x "${SCRIPT_DIR}/bin/netfixctl" && -x "${SCRIPT_DIR}/bin/netfix-tgproxy" ]]; then
    CTL_BIN="${SCRIPT_DIR}/bin/netfixctl"
    TG_BIN="${SCRIPT_DIR}/bin/netfix-tgproxy"
else
    echo "error: release binaries not found at target/release/ or bin/. Build them first." >&2
    exit 1
fi

mkdir -p "${DIST_DIR}"
BUILD_TMP="$(mktemp -d -t netfix-pkg-XXXXXX)"
trap 'rm -rf "${BUILD_TMP}"' EXIT

echo "=== Packaging NetFix v${VERSION} (${PKG_ARCH}) ==="
echo "Output directory: ${DIST_DIR}"

# 1. Build .tar.gz
if [[ "${DO_TAR}" -eq 1 ]]; then
    echo "--> Building tar.gz release bundle..."
    TAR_DIR_NAME="netfix-v${VERSION}-linux-${PKG_ARCH}"
    TAR_STAGE="${BUILD_TMP}/${TAR_DIR_NAME}"
    mkdir -p "${TAR_STAGE}/bin" "${TAR_STAGE}/systemd" "${TAR_STAGE}/presets/hostlists"

    cp -p "${CTL_BIN}" "${TAR_STAGE}/bin/netfixctl"
    cp -p "${TG_BIN}" "${TAR_STAGE}/bin/netfix-tgproxy"
    cp -p "${SCRIPT_DIR}/systemd/netfix-dpi.service" "${TAR_STAGE}/systemd/"
    cp -p "${SCRIPT_DIR}/systemd/netfix-tgproxy.service" "${TAR_STAGE}/systemd/"
    cp -p "${SCRIPT_DIR}/systemd/netfix.target" "${TAR_STAGE}/systemd/"
    cp -p "${SCRIPT_DIR}/systemd/netfix-dispatcher.sh" "${TAR_STAGE}/systemd/"
    cp -p "${SCRIPT_DIR}/presets/hostlists/default.txt" "${TAR_STAGE}/presets/hostlists/"
    cp -p "${SCRIPT_DIR}/presets/strategies-nfqws.toml" "${TAR_STAGE}/presets/" 2>/dev/null || true
    cp -p "${SCRIPT_DIR}/presets/strategies-ciadpi.toml" "${TAR_STAGE}/presets/" 2>/dev/null || true
    cp -p "${SCRIPT_DIR}/install.sh" "${TAR_STAGE}/"
    cp -p "${SCRIPT_DIR}/uninstall.sh" "${TAR_STAGE}/"
    cp -p "${SCRIPT_DIR}/README.md" "${TAR_STAGE}/" 2>/dev/null || true

    TAR_FILE="${DIST_DIR}/netfix-v${VERSION}-linux-${PKG_ARCH}.tar.gz"
    tar -czf "${TAR_FILE}" -C "${BUILD_TMP}" "${TAR_DIR_NAME}"
    echo "    Created: ${TAR_FILE}"
fi

# 2. Build .deb package (requires dpkg-deb)
if [[ "${DO_DEB}" -eq 1 ]]; then
    if command -v dpkg-deb >/dev/null 2>&1; then
        echo "--> Building .deb package (dpkg-deb)..."
        DEB_STAGE="${BUILD_TMP}/deb_stage"
        mkdir -p "${DEB_STAGE}/DEBIAN" \
                 "${DEB_STAGE}/usr/bin" \
                 "${DEB_STAGE}/lib/systemd/system" \
                 "${DEB_STAGE}/etc/NetworkManager/dispatcher.d" \
                 "${DEB_STAGE}/etc/netfix/hostlists" \
                 "${DEB_STAGE}/etc/netfix/presets" \
                 "${DEB_STAGE}/usr/share/doc/netfix"

        cp -p "${CTL_BIN}" "${DEB_STAGE}/usr/bin/netfixctl"
        cp -p "${TG_BIN}" "${DEB_STAGE}/usr/bin/netfix-tgproxy"
        cp -p "${SCRIPT_DIR}/systemd/netfix-dpi.service" "${DEB_STAGE}/lib/systemd/system/"
        cp -p "${SCRIPT_DIR}/systemd/netfix-tgproxy.service" "${DEB_STAGE}/lib/systemd/system/"
        cp -p "${SCRIPT_DIR}/systemd/netfix.target" "${DEB_STAGE}/lib/systemd/system/"
        cp -p "${SCRIPT_DIR}/systemd/netfix-dispatcher.sh" "${DEB_STAGE}/etc/NetworkManager/dispatcher.d/90-netfix.sh"
        cp -p "${SCRIPT_DIR}/presets/hostlists/default.txt" "${DEB_STAGE}/etc/netfix/hostlists/"
        cp -p "${SCRIPT_DIR}/presets/strategies-nfqws.toml" "${DEB_STAGE}/etc/netfix/presets/" 2>/dev/null || true
        cp -p "${SCRIPT_DIR}/presets/strategies-ciadpi.toml" "${DEB_STAGE}/etc/netfix/presets/" 2>/dev/null || true
        cp -p "${SCRIPT_DIR}/README.md" "${DEB_STAGE}/usr/share/doc/netfix/" 2>/dev/null || true

        chmod 0755 "${DEB_STAGE}/usr/bin/netfixctl" "${DEB_STAGE}/usr/bin/netfix-tgproxy" "${DEB_STAGE}/etc/NetworkManager/dispatcher.d/90-netfix.sh"
        chmod 0644 "${DEB_STAGE}/lib/systemd/system/"* "${DEB_STAGE}/etc/netfix/hostlists/"*

        # Control file
        cat <<EOF > "${DEB_STAGE}/DEBIAN/control"
Package: netfix
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: NetFix Team <support@netfix.dev>
Depends: systemd, iproute2
Suggests: nftables, iptables
Description: NetFix Linux headless client
 Systemd services for DPI bypass (nfqws/ciadpi) and Telegram MTProto-over-WebSocket proxy.
EOF

        # conffiles
        cat <<EOF > "${DEB_STAGE}/DEBIAN/conffiles"
/etc/netfix/hostlists/default.txt
EOF

        # postinst
        cat <<'EOF' > "${DEB_STAGE}/DEBIAN/postinst"
#!/bin/sh
set -e

if ! getent group netfix >/dev/null 2>&1; then
    groupadd -r netfix
fi

if ! getent passwd netfix >/dev/null 2>&1; then
    useradd -r -g netfix -d /var/lib/netfix -s /sbin/nologin -c "NetFix system user" netfix 2>/dev/null || \
    useradd -r -g netfix -d /var/lib/netfix -s /bin/false -c "NetFix system user" netfix
fi

mkdir -p /etc/netfix /var/lib/netfix /var/lib/netfix/tgproxy /usr/local/libexec/netfix
chmod 0750 /etc/netfix /var/lib/netfix
chmod 0700 /var/lib/netfix/tgproxy
chown -R root:netfix /etc/netfix /var/lib/netfix

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

exit 0
EOF
        chmod 0755 "${DEB_STAGE}/DEBIAN/postinst"

        # prerm
        cat <<'EOF' > "${DEB_STAGE}/DEBIAN/prerm"
#!/bin/sh
set -e

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop netfix-dpi.service netfix-tgproxy.service 2>/dev/null || true
    systemctl disable netfix-dpi.service netfix-tgproxy.service netfix.target 2>/dev/null || true
fi

exit 0
EOF
        chmod 0755 "${DEB_STAGE}/DEBIAN/prerm"

        # postrm
        cat <<'EOF' > "${DEB_STAGE}/DEBIAN/postrm"
#!/bin/sh
set -e

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

if [ "$1" = "purge" ]; then
    rm -rf /var/lib/netfix
    if getent passwd netfix >/dev/null 2>&1; then
        userdel netfix 2>/dev/null || true
    fi
fi

exit 0
EOF
        chmod 0755 "${DEB_STAGE}/DEBIAN/postrm"

        DEB_FILE="${DIST_DIR}/netfix_${VERSION}_${DEB_ARCH}.deb"
        dpkg-deb --build "${DEB_STAGE}" "${DEB_FILE}" >/dev/null
        echo "    Created: ${DEB_FILE}"
    else
        echo "--> Skipping .deb (dpkg-deb not found)"
    fi
fi

# 3. Build .rpm package (requires rpmbuild)
if [[ "${DO_RPM}" -eq 1 ]]; then
    if command -v rpmbuild >/dev/null 2>&1; then
        echo "--> Building .rpm package (rpmbuild)..."
        RPM_TOP="${BUILD_TMP}/rpmbuild"
        mkdir -p "${RPM_TOP}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
        RPM_STAGE="${BUILD_TMP}/rpm_stage"

        mkdir -p "${RPM_STAGE}/usr/bin" \
                 "${RPM_STAGE}/lib/systemd/system" \
                 "${RPM_STAGE}/etc/NetworkManager/dispatcher.d" \
                 "${RPM_STAGE}/etc/netfix/hostlists" \
                 "${RPM_STAGE}/etc/netfix/presets" \
                 "${RPM_STAGE}/usr/share/doc/netfix"

        cp -p "${CTL_BIN}" "${RPM_STAGE}/usr/bin/netfixctl"
        cp -p "${TG_BIN}" "${RPM_STAGE}/usr/bin/netfix-tgproxy"
        cp -p "${SCRIPT_DIR}/systemd/netfix-dpi.service" "${RPM_STAGE}/lib/systemd/system/"
        cp -p "${SCRIPT_DIR}/systemd/netfix-tgproxy.service" "${RPM_STAGE}/lib/systemd/system/"
        cp -p "${SCRIPT_DIR}/systemd/netfix.target" "${RPM_STAGE}/lib/systemd/system/"
        cp -p "${SCRIPT_DIR}/systemd/netfix-dispatcher.sh" "${RPM_STAGE}/etc/NetworkManager/dispatcher.d/90-netfix.sh"
        cp -p "${SCRIPT_DIR}/presets/hostlists/default.txt" "${RPM_STAGE}/etc/netfix/hostlists/"
        cp -p "${SCRIPT_DIR}/presets/strategies-nfqws.toml" "${RPM_STAGE}/etc/netfix/presets/" 2>/dev/null || true
        cp -p "${SCRIPT_DIR}/presets/strategies-ciadpi.toml" "${RPM_STAGE}/etc/netfix/presets/" 2>/dev/null || true
        cp -p "${SCRIPT_DIR}/README.md" "${RPM_STAGE}/usr/share/doc/netfix/" 2>/dev/null || true

        chmod 0755 "${RPM_STAGE}/usr/bin/netfixctl" "${RPM_STAGE}/usr/bin/netfix-tgproxy" "${RPM_STAGE}/etc/NetworkManager/dispatcher.d/90-netfix.sh"
        chmod 0644 "${RPM_STAGE}/lib/systemd/system/"* "${RPM_STAGE}/etc/netfix/hostlists/"*

        # Tar source for rpmbuild
        tar -czf "${RPM_TOP}/SOURCES/netfix-${VERSION}.tar.gz" -C "${RPM_STAGE}" .

        SPEC_FILE="${RPM_TOP}/SPECS/netfix.spec"
        cat <<EOF > "${SPEC_FILE}"
%global debug_package %{nil}
%define _build_id_links none

Name:           netfix
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        NetFix Linux headless client
License:        MIT or Apache-2.0
URL:            https://github.com/FlyingBober/NetFixMobile
Source0:        netfix-${VERSION}.tar.gz
BuildArch:      ${RPM_ARCH}

Requires:       systemd, iproute
Suggests:       nftables, iptables

%description
Systemd services for DPI bypass (nfqws/ciadpi) and Telegram MTProto-over-WebSocket proxy.

%prep
%setup -c -T
tar -xzf %{SOURCE0}

%build
# Pre-built release binaries

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}/

%pre
if ! getent group netfix >/dev/null 2>&1; then
    groupadd -r netfix
fi
if ! getent passwd netfix >/dev/null 2>&1; then
    useradd -r -g netfix -d /var/lib/netfix -s /sbin/nologin -c "NetFix system user" netfix 2>/dev/null || \
    useradd -r -g netfix -d /var/lib/netfix -s /bin/false -c "NetFix system user" netfix
fi

%post
mkdir -p /etc/netfix /var/lib/netfix /var/lib/netfix/tgproxy /usr/local/libexec/netfix
chmod 0750 /etc/netfix /var/lib/netfix
chmod 0700 /var/lib/netfix/tgproxy
chown -R root:netfix /etc/netfix /var/lib/netfix
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

%preun
if [ "\$1" = "0" ]; then
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl stop netfix-dpi.service netfix-tgproxy.service 2>/dev/null || true
        systemctl disable netfix-dpi.service netfix-tgproxy.service netfix.target 2>/dev/null || true
    fi
fi

%postun
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
if [ "\$1" = "0" ]; then
    rm -rf /var/lib/netfix
    if getent passwd netfix >/dev/null 2>&1; then
        userdel netfix 2>/dev/null || true
    fi
fi

%files
/usr/bin/netfixctl
/usr/bin/netfix-tgproxy
/lib/systemd/system/netfix-dpi.service
/lib/systemd/system/netfix-tgproxy.service
/lib/systemd/system/netfix.target
/etc/NetworkManager/dispatcher.d/90-netfix.sh
%config(noreplace) /etc/netfix/hostlists/default.txt
/etc/netfix/presets/strategies-nfqws.toml
/etc/netfix/presets/strategies-ciadpi.toml
%doc /usr/share/doc/netfix/README.md

%changelog
* Sun Nov 22 2026 NetFix Team <support@netfix.dev> - ${VERSION}-1
- Initial release of NetFix Linux headless client
EOF

        rpmbuild -bb --define "_topdir ${RPM_TOP}" "${SPEC_FILE}" >/dev/null
        GENERATED_RPM=$(find "${RPM_TOP}/RPMS" -name "*.rpm" -type f | head -n1)
        if [[ -f "${GENERATED_RPM}" ]]; then
            RPM_DEST="${DIST_DIR}/netfix-${VERSION}-1.${RPM_ARCH}.rpm"
            mv "${GENERATED_RPM}" "${RPM_DEST}"
            echo "    Created: ${RPM_DEST}"
        fi
    else
        echo "--> Skipping .rpm (rpmbuild not found)"
    fi
fi

# 4. Generate SHA256SUMS
echo "--> Generating SHA256 checksums..."
(
    cd "${DIST_DIR}"
    sha256sum netfix* > SHA256SUMS.txt 2>/dev/null || true
)
echo "    Created: ${DIST_DIR}/SHA256SUMS.txt"
echo
echo "Packaging complete! Artifacts in ${DIST_DIR}:"
ls -lh "${DIST_DIR}"
