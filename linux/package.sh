#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

VERSION=""
VERSION_EXPLICIT=0
ARCH="$(uname -m)"
DIST_DIR="${SCRIPT_DIR}/dist"
ENGINES_DIR=""
FETCH_ENGINES=1
DO_TAR=0
DO_DEB=0
DO_RPM=0
BUILD_CORE=1
BUILD_GUI=0

usage() {
    cat <<'EOF'
NetFixLinux Packaging Script

Produces two independent package variants:
  - netfixlinux-core : CLI + daemons + systemd units + DPI engines (headless, no GUI)
  - netfixlinux      : Complete desktop bundle (GUI + CLI + daemons + systemd + Polkit + DPI engines)

Usage:
  ./linux/package.sh [options]

Options:
  --version <ver>      Package version (default: parsed from Cargo.toml or '0.1.0')
  --arch <arch>        Architecture: x86_64, aarch64 (default: host uname -m)
  --dist-dir <dir>     Output directory (default: linux/dist)
  --engines-dir <dir>  Directory with pre-fetched nfqws and ciadpi binaries for <arch>
  --fetch-engines      Download nfqws & ciadpi for <arch> via fetch-engines.py (default)
  --no-engines         Do not bundle nfqws & ciadpi binaries inside packages
  --tar                Build .tar.gz archive
  --deb                Build .deb package
  --rpm                Build .rpm package
  --all                Build all package formats (.tar.gz, .deb, .rpm)
  --core               Build only netfixlinux-core (CLI/daemons only, default)
  --headless           Alias for --core
  --gui                Build only netfixlinux (all-in-one GUI + daemons)
  --with-gui           Build both netfixlinux-core and netfixlinux
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            [[ $# -ge 2 ]] || { echo "error: --version requires an argument" >&2; exit 2; }
            VERSION="$2"
            VERSION_EXPLICIT=1
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
        --engines-dir)
            [[ $# -ge 2 ]] || { echo "error: --engines-dir requires a path" >&2; exit 2; }
            ENGINES_DIR="$2"
            FETCH_ENGINES=0
            shift 2
            ;;
        --fetch-engines)
            FETCH_ENGINES=1
            shift
            ;;
        --no-engines)
            FETCH_ENGINES=0
            ENGINES_DIR=""
            shift
            ;;
        --tar) DO_TAR=1; shift ;;
        --deb) DO_DEB=1; shift ;;
        --rpm) DO_RPM=1; shift ;;
        --all) DO_TAR=1; DO_DEB=1; DO_RPM=1; shift ;;
        --core|--headless) BUILD_CORE=1; BUILD_GUI=0; shift ;;
        --gui) BUILD_CORE=0; BUILD_GUI=1; shift ;;
        --with-gui) BUILD_CORE=1; BUILD_GUI=1; shift ;;
        -h|--help) usage; exit 0 ;;
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

resolve_bin() {
    local name="$1"
    if [[ -x "${SCRIPT_DIR}/target/release/${name}" ]]; then
        printf '%s\n' "${SCRIPT_DIR}/target/release/${name}"
    elif [[ -x "${SCRIPT_DIR}/bin/${name}" ]]; then
        printf '%s\n' "${SCRIPT_DIR}/bin/${name}"
    else
        echo "error: release binary '${name}' not found in target/release/ or bin/. Build it first." >&2
        exit 1
    fi
}

CTL_BIN="$(resolve_bin netfixctl)"
TG_BIN="$(resolve_bin netfix-tgproxy)"
GUI_BIN=""
if [[ "${BUILD_GUI}" -eq 1 ]]; then
    GUI_BIN="$(resolve_bin netfixlinux-gui)"
fi

mkdir -p "${DIST_DIR}"
BUILD_TMP="$(mktemp -d -t netfix-pkg-XXXXXX)"
trap 'rm -rf "${BUILD_TMP}"' EXIT

if [[ -z "${ENGINES_DIR}" && "${FETCH_ENGINES}" -eq 1 ]]; then
    echo "--> Fetching nfqws and ciadpi engines for ${PKG_ARCH}..."
    ENGINES_DIR="${BUILD_TMP}/engines"
    python3 "${SCRIPT_DIR}/fetch-engines.py" --arch "${PKG_ARCH}" --out-dir "${ENGINES_DIR}"
fi

HAS_ENGINES=0
if [[ -n "${ENGINES_DIR}" ]]; then
    if [[ ! -x "${ENGINES_DIR}/nfqws" || ! -x "${ENGINES_DIR}/ciadpi" ]]; then
        echo "error: engines directory '${ENGINES_DIR}' must contain executable 'nfqws' and 'ciadpi'" >&2
        exit 1
    fi
    HAS_ENGINES=1
fi

stage_tar_bundle() {
    local stage_dir="$1"
    local with_gui="$2"

    mkdir -p "${stage_dir}/bin" "${stage_dir}/systemd" "${stage_dir}/presets/hostlists"
    cp -p "${CTL_BIN}" "${stage_dir}/bin/netfixctl"
    cp -p "${TG_BIN}" "${stage_dir}/bin/netfix-tgproxy"
    cp -p "${SCRIPT_DIR}/systemd/netfix-dpi.service" "${stage_dir}/systemd/"
    cp -p "${SCRIPT_DIR}/systemd/netfix-tgproxy.service" "${stage_dir}/systemd/"
    cp -p "${SCRIPT_DIR}/systemd/netfix.target" "${stage_dir}/systemd/"
    cp -p "${SCRIPT_DIR}/systemd/netfix-dispatcher.sh" "${stage_dir}/systemd/"
    cp -p "${SCRIPT_DIR}/presets/hostlists/default.txt" "${stage_dir}/presets/hostlists/"
    cp -p "${SCRIPT_DIR}/presets/strategies-nfqws.toml" "${stage_dir}/presets/" 2>/dev/null || true
    cp -p "${SCRIPT_DIR}/presets/strategies-ciadpi.toml" "${stage_dir}/presets/" 2>/dev/null || true
    cp -p "${SCRIPT_DIR}/install.sh" "${stage_dir}/"
    cp -p "${SCRIPT_DIR}/uninstall.sh" "${stage_dir}/"
    cp -p "${SCRIPT_DIR}/README.md" "${stage_dir}/" 2>/dev/null || true

    if [[ "${HAS_ENGINES}" -eq 1 ]]; then
        mkdir -p "${stage_dir}/engines"
        cp -p "${ENGINES_DIR}/nfqws" "${stage_dir}/engines/nfqws"
        cp -p "${ENGINES_DIR}/ciadpi" "${stage_dir}/engines/ciadpi"
        chmod 0755 "${stage_dir}/engines/nfqws" "${stage_dir}/engines/ciadpi"
    fi

    if [[ "${with_gui}" -eq 1 ]]; then
        mkdir -p "${stage_dir}/share/applications" \
                 "${stage_dir}/share/polkit-1/actions" \
                 "${stage_dir}/share/icons/hicolor/32x32/apps" \
                 "${stage_dir}/share/icons/hicolor/128x128/apps" \
                 "${stage_dir}/share/icons/hicolor/512x512/apps"
        cp -p "${GUI_BIN}" "${stage_dir}/bin/netfixlinux-gui"
        cp -p "${SCRIPT_DIR}/crates/netfixlinux-gui/assets/dev.flyingbober.netfixlinux.desktop" "${stage_dir}/share/applications/"
        cp -p "${SCRIPT_DIR}/crates/netfixlinux-gui/assets/dev.flyingbober.netfixlinux.policy" "${stage_dir}/share/polkit-1/actions/"
        cp -p "${SCRIPT_DIR}/crates/netfixlinux-gui/icons/32x32.png" "${stage_dir}/share/icons/hicolor/32x32/apps/dev.flyingbober.netfixlinux.png"
        cp -p "${SCRIPT_DIR}/crates/netfixlinux-gui/icons/128x128.png" "${stage_dir}/share/icons/hicolor/128x128/apps/dev.flyingbober.netfixlinux.png"
        cp -p "${SCRIPT_DIR}/crates/netfixlinux-gui/icons/512x512.png" "${stage_dir}/share/icons/hicolor/512x512/apps/dev.flyingbober.netfixlinux.png"
    fi
}

stage_unix_pkg_root() {
    local root_dir="$1"
    local pkg_name="$2"
    local with_gui="$3"

    mkdir -p "${root_dir}/usr/bin" \
             "${root_dir}/lib/systemd/system" \
             "${root_dir}/etc/NetworkManager/dispatcher.d" \
             "${root_dir}/etc/netfix/hostlists" \
             "${root_dir}/etc/netfix/presets" \
             "${root_dir}/usr/share/doc/${pkg_name}"

    cp -p "${CTL_BIN}" "${root_dir}/usr/bin/netfixctl"
    cp -p "${TG_BIN}" "${root_dir}/usr/bin/netfix-tgproxy"
    cp -p "${SCRIPT_DIR}/systemd/netfix-dpi.service" "${root_dir}/lib/systemd/system/"
    cp -p "${SCRIPT_DIR}/systemd/netfix-tgproxy.service" "${root_dir}/lib/systemd/system/"
    cp -p "${SCRIPT_DIR}/systemd/netfix.target" "${root_dir}/lib/systemd/system/"
    sed -i 's|/usr/local/bin/|/usr/bin/|g' \
        "${root_dir}/lib/systemd/system/netfix-dpi.service" \
        "${root_dir}/lib/systemd/system/netfix-tgproxy.service"

    cp -p "${SCRIPT_DIR}/systemd/netfix-dispatcher.sh" "${root_dir}/etc/NetworkManager/dispatcher.d/90-netfix.sh"
    cp -p "${SCRIPT_DIR}/presets/hostlists/default.txt" "${root_dir}/etc/netfix/hostlists/"
    cp -p "${SCRIPT_DIR}/presets/strategies-nfqws.toml" "${root_dir}/etc/netfix/presets/" 2>/dev/null || true
    cp -p "${SCRIPT_DIR}/presets/strategies-ciadpi.toml" "${root_dir}/etc/netfix/presets/" 2>/dev/null || true
    cp -p "${SCRIPT_DIR}/README.md" "${root_dir}/usr/share/doc/${pkg_name}/" 2>/dev/null || true

    chmod 0755 "${root_dir}/usr/bin/netfixctl" "${root_dir}/usr/bin/netfix-tgproxy" "${root_dir}/etc/NetworkManager/dispatcher.d/90-netfix.sh"
    chmod 0644 "${root_dir}/lib/systemd/system/"* "${root_dir}/etc/netfix/hostlists/"* "${root_dir}/etc/netfix/presets/"* 2>/dev/null || true

    if [[ "${HAS_ENGINES}" -eq 1 ]]; then
        mkdir -p "${root_dir}/usr/local/libexec/netfix"
        cp -p "${ENGINES_DIR}/nfqws" "${root_dir}/usr/local/libexec/netfix/nfqws"
        cp -p "${ENGINES_DIR}/ciadpi" "${root_dir}/usr/local/libexec/netfix/ciadpi"
        chmod 0755 "${root_dir}/usr/local/libexec/netfix/nfqws" "${root_dir}/usr/local/libexec/netfix/ciadpi"
    fi

    if [[ "${with_gui}" -eq 1 ]]; then
        mkdir -p "${root_dir}/usr/share/applications" \
                 "${root_dir}/usr/share/polkit-1/actions" \
                 "${root_dir}/usr/share/icons/hicolor/32x32/apps" \
                 "${root_dir}/usr/share/icons/hicolor/128x128/apps" \
                 "${root_dir}/usr/share/icons/hicolor/512x512/apps"

        cp -p "${GUI_BIN}" "${root_dir}/usr/bin/netfixlinux-gui"
        cp -p "${SCRIPT_DIR}/crates/netfixlinux-gui/assets/dev.flyingbober.netfixlinux.desktop" "${root_dir}/usr/share/applications/"
        cp -p "${SCRIPT_DIR}/crates/netfixlinux-gui/assets/dev.flyingbober.netfixlinux.policy" "${root_dir}/usr/share/polkit-1/actions/"
        cp -p "${SCRIPT_DIR}/crates/netfixlinux-gui/icons/32x32.png" "${root_dir}/usr/share/icons/hicolor/32x32/apps/dev.flyingbober.netfixlinux.png"
        cp -p "${SCRIPT_DIR}/crates/netfixlinux-gui/icons/128x128.png" "${root_dir}/usr/share/icons/hicolor/128x128/apps/dev.flyingbober.netfixlinux.png"
        cp -p "${SCRIPT_DIR}/crates/netfixlinux-gui/icons/512x512.png" "${root_dir}/usr/share/icons/hicolor/512x512/apps/dev.flyingbober.netfixlinux.png"

        chmod 0755 "${root_dir}/usr/bin/netfixlinux-gui"
        chmod 0644 "${root_dir}/usr/share/applications/"* \
                   "${root_dir}/usr/share/polkit-1/actions/"* \
                   "${root_dir}/usr/share/icons/hicolor/"*"/apps/"*
    fi
}

build_deb_pkg() {
    local pkg_name="$1"
    local pkg_ver="$2"
    local with_gui="$3"

    if ! command -v dpkg-deb >/dev/null 2>&1; then
        echo "--> Skipping ${pkg_name} .deb (dpkg-deb not found)"
        return 0
    fi

    echo "--> Building ${pkg_name} .deb package (dpkg-deb)..."
    local deb_stage="${BUILD_TMP}/deb_stage_${pkg_name}"
    mkdir -p "${deb_stage}/DEBIAN"
    stage_unix_pkg_root "${deb_stage}" "${pkg_name}" "${with_gui}"

    local depends="systemd, iproute2"
    local extra_fields=""
    local summary="NetFixLinux Core (CLI & system daemons)"
    local desc="Systemd services for DPI bypass (nfqws/ciadpi) and Telegram MTProto-over-WebSocket proxy."
    if [[ "${with_gui}" -eq 1 ]]; then
        depends="systemd, iproute2, libgtk-3-0, libwebkit2gtk-4.1-0 | libwebkit2gtk-4.0-37, libayatana-appindicator3-1 | libappindicator3-1"
        extra_fields=$'Provides: netfixlinux-core\nConflicts: netfixlinux-core, netfix\nReplaces: netfixlinux-core, netfix'
        summary="NetFixLinux Desktop Client (all-in-one GUI + daemons)"
        desc="Complete desktop GUI client, CLI (netfixctl), systemd services for DPI bypass (nfqws/ciadpi), and Telegram proxy."
    else
        extra_fields=$'Conflicts: netfixlinux, netfix\nReplaces: netfix'
    fi

    cat <<EOF > "${deb_stage}/DEBIAN/control"
Package: ${pkg_name}
Version: ${pkg_ver}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: NetFixLinux Team <support@netfixlinux.dev>
Depends: ${depends}
Suggests: nftables, iptables
${extra_fields}
Description: ${summary}
 ${desc}
EOF

    cat <<EOF > "${deb_stage}/DEBIAN/conffiles"
/etc/netfix/hostlists/default.txt
EOF

    cat <<'EOF' > "${deb_stage}/DEBIAN/postinst"
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

if [ -x /usr/bin/netfixctl ]; then
    /usr/bin/netfixctl setup --skip-download --skip-units >/dev/null 2>&1 || true
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

exit 0
EOF
    chmod 0755 "${deb_stage}/DEBIAN/postinst"

    cat <<'EOF' > "${deb_stage}/DEBIAN/prerm"
#!/bin/sh
set -e

if [ "$1" = "remove" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop netfix-dpi.service netfix-tgproxy.service 2>/dev/null || true
    systemctl disable netfix-dpi.service netfix-tgproxy.service netfix.target 2>/dev/null || true
fi

exit 0
EOF
    chmod 0755 "${deb_stage}/DEBIAN/prerm"

    cat <<'EOF' > "${deb_stage}/DEBIAN/postrm"
#!/bin/sh
set -e

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

if [ "$1" = "purge" ]; then
    rm -rf /var/lib/netfix /etc/netfix
    if getent passwd netfix >/dev/null 2>&1; then
        userdel netfix 2>/dev/null || true
    fi
fi

exit 0
EOF
    chmod 0755 "${deb_stage}/DEBIAN/postrm"

    local deb_file="${DIST_DIR}/${pkg_name}_${pkg_ver}_${DEB_ARCH}.deb"
    dpkg-deb --root-owner-group --build "${deb_stage}" "${deb_file}" >/dev/null
    echo "    Created: ${deb_file}"
}

build_rpm_pkg() {
    local pkg_name="$1"
    local pkg_ver="$2"
    local with_gui="$3"

    if ! command -v rpmbuild >/dev/null 2>&1; then
        echo "--> Skipping ${pkg_name} .rpm (rpmbuild not found)"
        return 0
    fi

    echo "--> Building ${pkg_name} .rpm package (rpmbuild)..."
    local rpm_top="${BUILD_TMP}/rpmbuild_${pkg_name}"
    mkdir -p "${rpm_top}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    local rpm_stage="${BUILD_TMP}/rpm_stage_${pkg_name}"
    stage_unix_pkg_root "${rpm_stage}" "${pkg_name}" "${with_gui}"

    tar -czf "${rpm_top}/SOURCES/${pkg_name}-${pkg_ver}.tar.gz" -C "${rpm_stage}" .

    local requires_line="Requires:       systemd, iproute"
    local rel_lines=$'Conflicts:      netfixlinux, netfix\nObsoletes:      netfix < %{version}'
    local summary="NetFixLinux Core (CLI & system daemons)"
    local desc="Systemd services for DPI bypass (nfqws/ciadpi) and Telegram MTProto-over-WebSocket proxy."
    local files_engines=""
    local files_gui=""

    if [[ "${HAS_ENGINES}" -eq 1 ]]; then
        files_engines=$'/usr/local/libexec/netfix/nfqws\n/usr/local/libexec/netfix/ciadpi'
    fi

    if [[ "${with_gui}" -eq 1 ]]; then
        requires_line="Requires:       systemd, iproute, gtk3, (webkit2gtk4.1 or webkit2gtk3), (libayatana-appindicator-gtk3 or libappindicator-gtk3)"
        rel_lines=$'Provides:       netfixlinux-core = %{version}-%{release}\nConflicts:      netfixlinux-core, netfix\nObsoletes:      netfix < %{version}'
        summary="NetFixLinux Desktop Client (all-in-one GUI + daemons)"
        desc=$'Complete NetFixLinux Desktop Client (fork of NetFix Mobile by rupleide).\nBundles GUI, CLI (netfixctl), systemd services for DPI bypass (nfqws/ciadpi), and Telegram proxy.'
        files_gui=$'/usr/bin/netfixlinux-gui\n/usr/share/applications/dev.flyingbober.netfixlinux.desktop\n/usr/share/polkit-1/actions/dev.flyingbober.netfixlinux.policy\n/usr/share/icons/hicolor/32x32/apps/dev.flyingbober.netfixlinux.png\n/usr/share/icons/hicolor/128x128/apps/dev.flyingbober.netfixlinux.png\n/usr/share/icons/hicolor/512x512/apps/dev.flyingbober.netfixlinux.png'
    fi

    local spec_file="${rpm_top}/SPECS/${pkg_name}.spec"
    cat <<EOF > "${spec_file}"
%global debug_package %{nil}
%define _build_id_links none

Name:           ${pkg_name}
Version:        ${pkg_ver}
Release:        1%{?dist}
Summary:        ${summary}
License:        GPL-3.0-only
URL:            https://github.com/FlyingBober/NetFixMobile
Source0:        ${pkg_name}-${pkg_ver}.tar.gz

${requires_line}
Suggests:       nftables, iptables
${rel_lines}

%description
${desc}

%prep
%setup -c -T
tar -xzf %{SOURCE0}

%build

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
if [ -x /usr/bin/netfixctl ]; then
    /usr/bin/netfixctl setup --skip-download --skip-units >/dev/null 2>&1 || true
fi
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
%doc /usr/share/doc/${pkg_name}/README.md
${files_engines}
${files_gui}

%changelog
* Wed Nov 25 2026 NetFixLinux Team <support@netfixlinux.dev> - ${pkg_ver}-1
- Package ${pkg_name} v${pkg_ver}
EOF

    rpmbuild --target "${RPM_ARCH}" -bb --define "_topdir ${rpm_top}" "${spec_file}" >/dev/null
    local generated_rpm
    generated_rpm=$(find "${rpm_top}/RPMS" -name "*.rpm" -type f | head -n1)
    if [[ -f "${generated_rpm}" ]]; then
        local rpm_dest="${DIST_DIR}/${pkg_name}-${pkg_ver}-1.${RPM_ARCH}.rpm"
        mv "${generated_rpm}" "${rpm_dest}"
        echo "    Created: ${rpm_dest}"
    fi
}

package_variant() {
    local pkg_name="$1"
    local pkg_ver="$2"
    local with_gui="$3"

    echo "=== Packaging ${pkg_name} v${pkg_ver} (${PKG_ARCH}) ==="
    echo "Output directory: ${DIST_DIR}"

    if [[ "${DO_TAR}" -eq 1 ]]; then
        echo "--> Building ${pkg_name} tar.gz release bundle..."
        local tar_dir_name="${pkg_name}-v${pkg_ver}-linux-${PKG_ARCH}"
        local tar_stage="${BUILD_TMP}/${tar_dir_name}"
        stage_tar_bundle "${tar_stage}" "${with_gui}"
        local tar_file="${DIST_DIR}/${tar_dir_name}.tar.gz"
        tar -czf "${tar_file}" -C "${BUILD_TMP}" "${tar_dir_name}"
        echo "    Created: ${tar_file}"
    fi

    if [[ "${DO_DEB}" -eq 1 ]]; then
        build_deb_pkg "${pkg_name}" "${pkg_ver}" "${with_gui}"
    fi

    if [[ "${DO_RPM}" -eq 1 ]]; then
        build_rpm_pkg "${pkg_name}" "${pkg_ver}" "${with_gui}"
    fi
}

if [[ "${BUILD_CORE}" -eq 1 ]]; then
    package_variant "netfixlinux-core" "${VERSION}" 0
fi

if [[ "${BUILD_GUI}" -eq 1 ]]; then
    if [[ "${VERSION_EXPLICIT}" -eq 1 ]]; then
        GUI_VERSION="${VERSION}"
    else
        GUI_VERSION=$(grep -m1 '^version = ' "${SCRIPT_DIR}/crates/netfixlinux-gui/Cargo.toml" | cut -d'"' -f2 || true)
        [[ -n "${GUI_VERSION}" ]] || GUI_VERSION="${VERSION}"
    fi
    GUI_VERSION="${GUI_VERSION#v}"
    package_variant "netfixlinux" "${GUI_VERSION}" 1
fi

echo "--> Generating SHA256 checksums..."
(
    cd "${DIST_DIR}"
    sha256sum netfixlinux* > SHA256SUMS.txt 2>/dev/null || true
)
echo "    Created: ${DIST_DIR}/SHA256SUMS.txt"
echo
echo "Packaging complete! Artifacts in ${DIST_DIR}:"
ls -lh "${DIST_DIR}"
