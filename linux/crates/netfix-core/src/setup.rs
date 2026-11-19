use std::fs::{OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::config::{ensure_parent_dir, write_atomic_with_mode};
use crate::firewall::{is_executable_file, which_binary};
use crate::{NetfixConfig, NetfixError, DEFAULT_LIBEXEC_DIR, DEFAULT_STATE_DIR};

pub const NETFIX_DPI_SERVICE_UNIT: &str = include_str!("../../../systemd/netfix-dpi.service");
pub const NETFIX_TGPROXY_SERVICE_UNIT: &str =
    include_str!("../../../systemd/netfix-tgproxy.service");
pub const NETFIX_TARGET_UNIT: &str = include_str!("../../../systemd/netfix.target");
pub const DEFAULT_HOSTLIST_TXT: &str = include_str!("../../../presets/hostlists/default.txt");

const ZAPRET_RELEASE_API: &str = "https://api.github.com/repos/bol-van/zapret/releases/latest";
const BYEDPI_RELEASE_API: &str = "https://api.github.com/repos/hufrea/byedpi/releases/latest";
const METADATA_TIMEOUT: Duration = Duration::from_secs(20);
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DOWNLOAD_READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DOWNLOAD_ATTEMPTS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupPaths {
    pub etc_dir: PathBuf,
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
    pub tgproxy_state_dir: PathBuf,
    pub libexec_dir: PathBuf,
    pub systemd_dir: PathBuf,
}

impl SetupPaths {
    pub fn system() -> Self {
        Self::with_prefix(Path::new("/"))
    }

    pub fn with_prefix(prefix: &Path) -> Self {
        let etc_dir = prefix.join("etc/netfix");
        let state_dir = prefix.join(DEFAULT_STATE_DIR.trim_start_matches('/'));
        Self {
            config_path: etc_dir.join("config.toml"),
            etc_dir,
            tgproxy_state_dir: state_dir.join("tgproxy"),
            state_dir,
            libexec_dir: prefix.join(DEFAULT_LIBEXEC_DIR.trim_start_matches('/')),
            systemd_dir: prefix.join("etc/systemd/system"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetupOptions {
    pub from_local: Option<PathBuf>,
    pub skip_download: bool,
    pub prefix: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDiscovery {
    pub nfqws: Option<PathBuf>,
    pub ciadpi: Option<PathBuf>,
    pub nft: Option<PathBuf>,
    pub iptables: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupReport {
    pub config_created: bool,
    pub config_path: PathBuf,
    pub units_installed: Vec<PathBuf>,
    pub nfqws_path: Option<PathBuf>,
    pub ciadpi_path: Option<PathBuf>,
    pub nft_path: Option<PathBuf>,
    pub iptables_path: Option<PathBuf>,
    pub daemon_reloaded: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubAsset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GithubRelease {
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

/// Computes the SHA-256 digest of `path` and verifies it matches `expected_hex` (case-insensitive).
pub fn verify_sha256(path: &Path, expected_hex: &str) -> Result<(), NetfixError> {
    let expected = expected_hex.trim().to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NetfixError::InvalidInput(format!(
            "invalid SHA-256 hex digest '{expected_hex}'"
        )));
    }

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let actual = hex::encode(hasher.finalize());
    if actual != expected {
        return Err(NetfixError::Runtime(format!(
            "SHA-256 mismatch for {}: expected {expected}, got {actual}",
            path.display()
        )));
    }

    Ok(())
}

/// Inspects `libexec_dir` and `PATH` for `nfqws`, `ciadpi`, `nft`, and `iptables`.
pub fn discover_tools(libexec_dir: &Path) -> ToolDiscovery {
    ToolDiscovery {
        nfqws: find_engine_in(libexec_dir, "nfqws"),
        ciadpi: find_engine_in(libexec_dir, "ciadpi"),
        nft: which_binary("nft"),
        iptables: which_binary("iptables"),
    }
}

fn find_engine_in(libexec_dir: &Path, name: &str) -> Option<PathBuf> {
    let local = libexec_dir.join(name);
    if is_executable_file(&local) {
        return Some(local);
    }
    which_binary(name)
}

/// Returns the canonical `useradd` argument vector for creating the unprivileged `netfix` system user.
pub fn useradd_netfix_args() -> &'static [&'static str] {
    &[
        "--system",
        "--no-create-home",
        "--home-dir",
        DEFAULT_STATE_DIR,
        "--shell",
        "/usr/sbin/nologin",
        "netfix",
    ]
}

/// Ensures the unprivileged `netfix` system user/group exists and returns `(uid, gid)`.
pub fn ensure_netfix_system_user() -> Result<(u32, u32), NetfixError> {
    if let Some(pair) = lookup_netfix_uid_gid() {
        return Ok(pair);
    }

    if which_binary("useradd").is_some() {
        let out = Command::new("useradd").args(useradd_netfix_args()).output()?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && !stderr.contains("already exists") {
            return Err(NetfixError::Runtime(format!(
                "failed to create 'netfix' system user: {}",
                stderr.trim()
            )));
        }
    } else if which_binary("adduser").is_some() {
        let out = Command::new("adduser")
            .args([
                "--system",
                "--group",
                "--no-create-home",
                "--home",
                DEFAULT_STATE_DIR,
                "netfix",
            ])
            .output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(NetfixError::Runtime(format!(
                "failed to create 'netfix' system user via adduser: {}",
                stderr.trim()
            )));
        }
    } else {
        return Err(NetfixError::Runtime(
            "cannot create 'netfix' system user: neither useradd nor adduser is installed".into(),
        ));
    }

    lookup_netfix_uid_gid().ok_or_else(|| {
        NetfixError::Runtime("'netfix' system user/group was not found after creation".into())
    })
}

/// Applies `root:netfix` ownership to `/etc/netfix` and `config.toml`, and `netfix:netfix`
/// ownership to `/var/lib/netfix/tgproxy`.
pub fn apply_system_ownership(
    paths: &SetupPaths,
    netfix_uid: u32,
    netfix_gid: u32,
) -> Result<(), NetfixError> {
    chown_path(&paths.etc_dir, 0, netfix_gid)?;
    if paths.config_path.exists() {
        chown_path(&paths.config_path, 0, netfix_gid)?;
    }
    chown_path(&paths.tgproxy_state_dir, netfix_uid, netfix_gid)?;
    let secret_file = paths.tgproxy_state_dir.join("secret");
    if secret_file.exists() {
        chown_path(&secret_file, netfix_uid, netfix_gid)?;
    }
    Ok(())
}

/// When running as root (`euid == 0`), ensures `<secret_path>` (if present) is owned by `netfix:netfix`
/// so the unprivileged `netfix-tgproxy.service` can always read it.
pub fn chown_secret_to_netfix_if_root(secret_path: &Path) -> Result<(), NetfixError> {
    if unsafe { libc::geteuid() != 0 } || !secret_path.exists() {
        return Ok(());
    }
    if let Some((uid, gid)) = lookup_netfix_uid_gid() {
        chown_path(secret_path, uid, gid)?;
    }
    Ok(())
}

/// Provisions NetFix directories, default config (with pre-generated `tgproxy.secret`), and `systemd` unit files.
pub fn provision_layout(
    paths: &SetupPaths,
    is_system: bool,
) -> Result<(bool, Vec<PathBuf>), NetfixError> {
    let netfix_ids = if is_system {
        crate::require_root("provision NetFix directories and systemd units")?;
        Some(ensure_netfix_system_user()?)
    } else {
        None
    };

    create_dir_with_mode(&paths.etc_dir, 0o750)?;
    let hostlists_dir = paths.etc_dir.join("hostlists");
    create_dir_with_mode(&hostlists_dir, 0o755)?;
    let default_hostlist = hostlists_dir.join("default.txt");
    if !default_hostlist.exists() {
        write_atomic_with_mode(&default_hostlist, DEFAULT_HOSTLIST_TXT.as_bytes(), 0o644)?;
    }
    create_dir_with_mode(&paths.state_dir, 0o755)?;
    create_dir_with_mode(&paths.tgproxy_state_dir, 0o750)?;
    create_dir_with_mode(&paths.libexec_dir, 0o755)?;
    create_dir_with_mode(&paths.systemd_dir, 0o755)?;

    let mut config_created = false;
    if !paths.config_path.exists() {
        let mut cfg = NetfixConfig::default();
        cfg.ensure_secret();
        cfg.save(&paths.config_path)?;
        config_created = true;
    }

    if let Some((uid, gid)) = netfix_ids {
        apply_system_ownership(paths, uid, gid)?;
    }

    let unit_specs = [
        ("netfix-dpi.service", NETFIX_DPI_SERVICE_UNIT),
        ("netfix-tgproxy.service", NETFIX_TGPROXY_SERVICE_UNIT),
        ("netfix.target", NETFIX_TARGET_UNIT),
    ];
    let mut units_installed = Vec::with_capacity(unit_specs.len());
    for (filename, body) in unit_specs {
        let dest = paths.systemd_dir.join(filename);
        ensure_parent_dir(&dest)?;
        write_atomic_with_mode(&dest, body.as_bytes(), 0o644)?;
        units_installed.push(dest);
    }

    Ok((config_created, units_installed))
}

/// Installs `nfqws` and/or `ciadpi` binaries from a local directory into `libexec_dir`.
/// If `<name>.sha256` or `SHA256SUMS` exists in `local_dir`, verifies SHA-256 before copying.
pub fn install_from_local_dir(
    local_dir: &Path,
    libexec_dir: &Path,
) -> Result<Vec<PathBuf>, NetfixError> {
    if !local_dir.is_dir() {
        return Err(NetfixError::InvalidInput(format!(
            "--from-local path is not a directory: {}",
            local_dir.display()
        )));
    }

    create_dir_with_mode(libexec_dir, 0o755)?;
    let mut installed = Vec::new();

    for name in ["nfqws", "ciadpi"] {
        let src = local_dir.join(name);
        if !src.is_file() {
            continue;
        }
        if let Some(expected) = find_local_sha256(local_dir, name)? {
            verify_sha256(&src, &expected)?;
        }
        let dest = libexec_dir.join(name);
        let bytes = std::fs::read(&src)?;
        write_executable_atomic(&dest, &bytes)?;
        installed.push(dest);
    }

    if installed.is_empty() {
        return Err(NetfixError::MissingEngine(format!(
            "no 'nfqws' or 'ciadpi' binary found in {}",
            local_dir.display()
        )));
    }

    Ok(installed)
}

/// Runs full NetFix setup: directory provisioning, config generation, unit installation,
/// optional engine installation (`--from-local` or upstream release download), and `daemon-reload`.
pub async fn run_setup(opts: &SetupOptions) -> Result<SetupReport, NetfixError> {
    let is_system = opts.prefix.is_none();
    if is_system {
        crate::require_root("run netfix setup")?;
    }

    let paths = match &opts.prefix {
        Some(prefix) => SetupPaths::with_prefix(prefix),
        None => SetupPaths::system(),
    };

    let (config_created, units_installed) = provision_layout(&paths, is_system)?;
    let mut warnings = Vec::new();

    if let Some(ref local_dir) = opts.from_local {
        install_from_local_dir(local_dir, &paths.libexec_dir)?;
    } else if !opts.skip_download {
        let current = discover_tools(&paths.libexec_dir);
        if current.nfqws.is_none() {
            download_engine_from_github("nfqws", ZAPRET_RELEASE_API, &paths.libexec_dir).await?;
        }
        if current.ciadpi.is_none() {
            download_engine_from_github("ciadpi", BYEDPI_RELEASE_API, &paths.libexec_dir).await?;
        }
    }

    let tools = discover_tools(&paths.libexec_dir);
    if tools.nfqws.is_none() {
        warnings.push("nfqws binary not found in /usr/local/libexec/netfix or PATH".into());
    }
    if tools.ciadpi.is_none() {
        warnings.push("ciadpi binary not found in /usr/local/libexec/netfix or PATH".into());
    }
    if tools.nft.is_none() && tools.iptables.is_none() {
        warnings.push("neither nft nor iptables found in PATH".into());
    }

    let daemon_reloaded = if is_system {
        reload_systemd_daemon()?
    } else {
        false
    };

    Ok(SetupReport {
        config_created,
        config_path: paths.config_path,
        units_installed,
        nfqws_path: tools.nfqws,
        ciadpi_path: tools.ciadpi,
        nft_path: tools.nft,
        iptables_path: tools.iptables,
        daemon_reloaded,
        warnings,
    })
}

/// Returns architecture substring hints for matching release assets and archive paths.
pub fn arch_hints_for(arch: &str) -> &'static [&'static str] {
    match arch {
        "x86_64" => &["linux-x86_64", "x86_64", "amd64", "x64"],
        "aarch64" => &["linux-arm64", "aarch64", "arm64"],
        "arm" => &["linux-arm", "armv7l", "armv7", "armhf", "arm"],
        _ => &[],
    }
}

/// Extracts `engine_name` (e.g. `nfqws` or `ciadpi`) from an in-memory `.tar.gz` archive,
/// preferring paths matching `arch_hints` and installing atomically to `dest_path` with mode `0755`.
pub fn extract_engine_from_targz(
    archive_bytes: &[u8],
    engine_name: &str,
    arch_hints: &[&str],
    dest_path: &Path,
) -> Result<(), NetfixError> {
    let gz = GzDecoder::new(archive_bytes);
    let mut archive = Archive::new(gz);
    let entries = archive.entries().map_err(|e| {
        NetfixError::Runtime(format!("failed to read tar.gz entries for {engine_name}: {e}"))
    })?;

    let mut best_score = i32::MIN;
    let mut best_bytes: Option<Vec<u8>> = None;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| {
            NetfixError::Runtime(format!("corrupt tar.gz entry for {engine_name}: {e}"))
        })?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| NetfixError::Runtime(format!("invalid tar entry path: {e}")))?
            .to_path_buf();
        let path_str = path.to_string_lossy().to_ascii_lowercase();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let exact_name = file_name == engine_name;
        let prefixed_name = file_name.starts_with(&format!("{engine_name}-"));
        if !exact_name && !prefixed_name {
            continue;
        }
        const SKIP_SUFFIXES: &[&str] = &[
            ".sha256",
            ".sha256sum",
            ".sig",
            ".asc",
            ".exe",
            ".txt",
            ".md",
        ];
        if SKIP_SUFFIXES.iter().any(|suffix| file_name.ends_with(suffix)) {
            continue;
        }

        let mut score = if exact_name { 100 } else { 50 };
        if !arch_hints.is_empty() {
            if let Some((idx, _)) = arch_hints
                .iter()
                .enumerate()
                .find(|(_, hint)| path_str.contains(&hint.to_ascii_lowercase()))
            {
                score += 1000 - (idx as i32) * 10;
            } else if path_contains_foreign_arch(&path_str, arch_hints) {
                continue;
            }
        }

        if score > best_score {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            if !buf.is_empty() {
                best_score = score;
                best_bytes = Some(buf);
            }
        }
    }

    let bytes = best_bytes.ok_or_else(|| {
        NetfixError::MissingEngine(format!(
            "tar.gz archive did not contain a compatible '{engine_name}' binary"
        ))
    })?;

    write_executable_atomic(dest_path, &bytes)
}

fn path_contains_foreign_arch(path_lower: &str, arch_hints: &[&str]) -> bool {
    const KNOWN_ARCH_TOKENS: &[&str] = &[
        "x86_64", "amd64", "x64", "aarch64", "arm64", "armv7", "armv6", "armhf", "mips",
        "riscv", "ppc", "s390", "i386", "i686", "x86", "darwin", "macos", "windows", "win32",
        "win64", "freebsd", "openbsd",
    ];
    KNOWN_ARCH_TOKENS.iter().any(|tok| {
        path_lower.contains(tok)
            && !arch_hints
                .iter()
                .any(|h| h.to_ascii_lowercase().contains(tok))
    })
}

fn create_dir_with_mode(path: &Path, mode: u32) -> Result<(), NetfixError> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, Permissions::from_mode(mode))?;
    Ok(())
}

fn write_executable_atomic(dest: &Path, bytes: &[u8]) -> Result<(), NetfixError> {
    ensure_parent_dir(dest)?;
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let file_name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "engine".to_string());
    let tmp_name = format!(".{file_name}.tmp.{}", rand::random::<u64>());
    let tmp_path = match parent {
        Some(dir) => dir.join(tmp_name),
        None => PathBuf::from(tmp_name),
    };

    let write_res = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&tmp_path)?;
        std::fs::set_permissions(&tmp_path, Permissions::from_mode(0o755))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err.into());
    }

    if let Err(err) = std::fs::rename(&tmp_path, dest) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err.into());
    }
    Ok(())
}

fn find_local_sha256(dir: &Path, binary_name: &str) -> Result<Option<String>, NetfixError> {
    let sidecar = dir.join(format!("{binary_name}.sha256"));
    if sidecar.is_file() {
        let raw = std::fs::read_to_string(&sidecar)?;
        if let Some(token) = raw.split_whitespace().next() {
            return Ok(Some(token.to_string()));
        }
    }

    for sums_name in ["SHA256SUMS", "sha256sums.txt"] {
        let sums_path = dir.join(sums_name);
        if sums_path.is_file() {
            let raw = std::fs::read_to_string(&sums_path)?;
            if let Some(digest) = parse_sha256sum_for(&raw, binary_name) {
                return Ok(Some(digest));
            }
        }
    }

    Ok(None)
}

pub(crate) fn parse_sha256sum_for(content: &str, target_name: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let digest = parts.next()?;
        let file = parts.next()?.trim_start_matches('*');
        let base = Path::new(file)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(file);
        if base == target_name || file == target_name {
            return Some(digest.to_string());
        }
    }
    None
}

fn lookup_netfix_uid_gid() -> Option<(u32, u32)> {
    if let (Some(uid), Some(gid)) = (
        lookup_passwd_id("/etc/passwd", "netfix"),
        lookup_passwd_id("/etc/group", "netfix"),
    ) {
        return Some((uid, gid));
    }

    let out = Command::new("getent")
        .args(["passwd", "netfix"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout);
    let mut fields = line.trim().split(':');
    let _name = fields.next()?;
    let _pw = fields.next()?;
    let uid = fields.next()?.parse::<u32>().ok()?;
    let gid = fields.next()?.parse::<u32>().ok()?;
    Some((uid, gid))
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<(), NetfixError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| NetfixError::InvalidInput("path contains interior NUL byte".into()))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) };
    if rc != 0 {
        return Err(NetfixError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn lookup_passwd_id(file: &str, name: &str) -> Option<u32> {
    let content = std::fs::read_to_string(file).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split(':');
        if fields.next()? != name {
            continue;
        }
        let _pw = fields.next()?;
        return fields.next()?.parse::<u32>().ok();
    }
    None
}

fn reload_systemd_daemon() -> Result<bool, NetfixError> {
    if !Path::new("/run/systemd/system").exists() || which_binary("systemctl").is_none() {
        return Ok(false);
    }
    let out = Command::new("systemctl").arg("daemon-reload").output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(NetfixError::Runtime(format!(
            "systemctl daemon-reload failed: {}",
            stderr.trim()
        )));
    }
    Ok(true)
}

pub fn select_github_asset<'a>(
    assets: &'a [GithubAsset],
    engine: &str,
    arch: &str,
) -> Option<&'a GithubAsset> {
    let arch_tokens = arch_hints_for(arch);

    let is_excluded = |lower: &str| {
        lower.contains("windows")
            || lower.contains("win32")
            || lower.contains("win64")
            || lower.contains("darwin")
            || lower.contains("macos")
            || lower.contains("android")
            || lower.ends_with(".sha256")
            || lower.ends_with(".sig")
            || lower.ends_with(".asc")
    };

    if engine == "nfqws" {
        if let Some(asset) = assets.iter().find(|a| {
            let lower = a.name.to_ascii_lowercase();
            !is_excluded(&lower)
                && !lower.contains("openwrt")
                && lower.starts_with("zapret-")
                && (lower.ends_with(".tar.gz") || lower.ends_with(".tgz"))
        }) {
            return Some(asset);
        }
    }

    if let Some(asset) = assets.iter().find(|a| {
        let lower = a.name.to_ascii_lowercase();
        !is_excluded(&lower)
            && arch_tokens.iter().any(|tok| lower.contains(tok))
            && (lower.ends_with(".tar.gz") || lower.ends_with(".tgz"))
    }) {
        return Some(asset);
    }

    assets.iter().find(|a| {
        let lower = a.name.to_ascii_lowercase();
        !is_excluded(&lower)
            && (lower.contains(engine) || arch_tokens.iter().any(|tok| lower.contains(tok)))
    })
}

fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![err.to_string()];
    let mut cur = err.source();
    while let Some(src) = cur {
        let msg = src.to_string();
        if parts.last().map(String::as_str) != Some(msg.as_str()) {
            parts.push(msg);
        }
        cur = src.source();
    }
    parts.join(": ")
}

fn build_download_client() -> Result<reqwest::Client, NetfixError> {
    reqwest::Client::builder()
        .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
        .read_timeout(DOWNLOAD_READ_TIMEOUT)
        .user_agent("netfixctl/0.1")
        .build()
        .map_err(|e| {
            NetfixError::Runtime(format!(
                "failed to create HTTP client: {}",
                format_error_chain(&e)
            ))
        })
}

fn parse_content_range_total(
    header_val: Option<&str>,
    expected_start: usize,
) -> Option<(usize, Option<usize>)> {
    let raw = header_val?.trim();
    let rest = raw.strip_prefix("bytes ")?.trim();
    let (range_part, total_part) = rest.split_once('/')?;
    let (start_s, _end_s) = range_part.split_once('-')?;
    let start: usize = start_s.trim().parse().ok()?;
    if start != expected_start {
        return None;
    }
    let total = if total_part.trim() == "*" {
        None
    } else {
        Some(total_part.trim().parse().ok()?)
    };
    Some((start, total))
}

async fn download_bytes_with_resume(
    client: &reqwest::Client,
    url: &str,
    asset_name: &str,
) -> Result<Vec<u8>, NetfixError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut expected_total: Option<usize> = None;
    let mut last_err: Option<String> = None;

    for attempt in 1..=MAX_DOWNLOAD_ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(Duration::from_millis(500 * (attempt as u64 - 1))).await;
        }

        let mut req = client.get(url);
        if !buf.is_empty() {
            req = req.header(reqwest::header::RANGE, format!("bytes={}-", buf.len()));
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(format!(
                    "failed to download {asset_name} (attempt {attempt}/{MAX_DOWNLOAD_ATTEMPTS}): {}",
                    format_error_chain(&e)
                ));
                continue;
            }
        };

        if !buf.is_empty() && resp.status() == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
            if expected_total.is_some_and(|total| buf.len() == total) {
                return Ok(buf);
            }
            buf.clear();
            expected_total = None;
            last_err = Some(format!(
                "range not satisfiable for {asset_name} (attempt {attempt}/{MAX_DOWNLOAD_ATTEMPTS}), restarting"
            ));
            continue;
        }

        let mut resp = match resp.error_for_status() {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(format!(
                    "download failed for {asset_name} (attempt {attempt}/{MAX_DOWNLOAD_ATTEMPTS}): {}",
                    format_error_chain(&e)
                ));
                continue;
            }
        };

        let status = resp.status();
        let remaining_len = resp.content_length().and_then(|n| usize::try_from(n).ok());
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            let cr = resp
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok());
            match parse_content_range_total(cr, buf.len()) {
                Some((start, total_opt)) => {
                    if let Some(total) = total_opt.or_else(|| remaining_len.map(|rem| start + rem))
                    {
                        expected_total = Some(total);
                    }
                }
                None => {
                    buf.clear();
                    expected_total = None;
                    last_err = Some(format!(
                        "invalid Content-Range for {asset_name} (attempt {attempt}/{MAX_DOWNLOAD_ATTEMPTS}), restarting"
                    ));
                    continue;
                }
            }
        } else {
            buf.clear();
            expected_total = remaining_len;
            if let Some(total) = expected_total {
                buf.reserve(total);
            }
        }

        let mut stream_failed = false;
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => buf.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => {
                    last_err = Some(format!(
                        "failed reading {asset_name} (attempt {attempt}/{MAX_DOWNLOAD_ATTEMPTS}): {}",
                        format_error_chain(&e)
                    ));
                    stream_failed = true;
                    break;
                }
            }
        }

        if stream_failed {
            continue;
        }

        if let Some(total) = expected_total {
            if buf.len() < total {
                last_err = Some(format!(
                    "truncated download for {asset_name}: received {} of {total} bytes (attempt {attempt}/{MAX_DOWNLOAD_ATTEMPTS})",
                    buf.len()
                ));
                continue;
            }
        }

        return Ok(buf);
    }

    Err(NetfixError::Runtime(last_err.unwrap_or_else(|| {
        format!("failed reading {asset_name} after {MAX_DOWNLOAD_ATTEMPTS} attempts")
    })))
}

async fn download_engine_from_github(
    engine: &str,
    api_url: &str,
    libexec_dir: &Path,
) -> Result<PathBuf, NetfixError> {
    let metadata_client = reqwest::Client::builder()
        .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
        .timeout(METADATA_TIMEOUT)
        .user_agent("netfixctl/0.1")
        .build()
        .map_err(|e| {
            NetfixError::Runtime(format!(
                "failed to create HTTP client: {}",
                format_error_chain(&e)
            ))
        })?;

    let release: GithubRelease = metadata_client
        .get(api_url)
        .send()
        .await
        .map_err(|e| {
            NetfixError::Runtime(format!(
                "failed to fetch {engine} release metadata from {api_url} (hint: use --from-local <dir> or --skip-download): {}",
                format_error_chain(&e)
            ))
        })?
        .error_for_status()
        .map_err(|e| {
            NetfixError::Runtime(format!(
                "GitHub API error for {engine}: {}",
                format_error_chain(&e)
            ))
        })?
        .json()
        .await
        .map_err(|e| {
            NetfixError::Runtime(format!(
                "invalid release JSON for {engine}: {}",
                format_error_chain(&e)
            ))
        })?;

    let arch = std::env::consts::ARCH;
    let asset = select_github_asset(&release.assets, engine, arch).ok_or_else(|| {
        NetfixError::MissingEngine(format!(
            "no compatible {engine} release asset found for architecture {arch}"
        ))
    })?;

    let download_client = build_download_client()?;
    let bytes =
        download_bytes_with_resume(&download_client, &asset.browser_download_url, &asset.name)
            .await?;

    if let Some(expected_sha) =
        resolve_release_sha256(&metadata_client, &release.assets, asset).await?
    {
        let tmp_dir = TempWorkDir::create("netfix-sha256")?;
        let tmp_file = sanitized_tmp_asset_path(tmp_dir.path(), &asset.name, engine);
        std::fs::write(&tmp_file, &bytes)?;
        verify_sha256(&tmp_file, &expected_sha)?;
    }

    let dest = libexec_dir.join(engine);
    let lower = asset.name.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        extract_engine_from_targz(&bytes, engine, arch_hints_for(arch), &dest)?;
    } else {
        write_executable_atomic(&dest, &bytes)?;
    }

    Ok(dest)
}

/// Selects exact `<target>.sha256` / `<target>.sha256sum` sidecars first, followed by
/// multi-entry checksum manifests (never selecting an unrelated asset's `.sha256` sidecar).
pub fn select_checksum_candidates<'a>(
    assets: &'a [GithubAsset],
    target_asset_name: &str,
) -> Vec<&'a GithubAsset> {
    let sidecar_sha256 = format!("{target_asset_name}.sha256");
    let sidecar_sha256sum = format!("{target_asset_name}.sha256sum");
    let mut exact = Vec::new();
    let mut manifests = Vec::new();

    for asset in assets {
        if asset.name == sidecar_sha256 || asset.name == sidecar_sha256sum {
            exact.push(asset);
            continue;
        }
        let lower = asset.name.to_ascii_lowercase();
        let is_other_sidecar = lower.ends_with(".sha256") || lower.ends_with(".sha256sum");
        if is_other_sidecar {
            continue;
        }
        if lower.contains("sha256sum")
            || lower.contains("checksum")
            || lower == "sha256"
            || lower == "sha256.txt"
        {
            manifests.push(asset);
        }
    }

    exact.extend(manifests);
    exact
}

async fn resolve_release_sha256(
    client: &reqwest::Client,
    assets: &[GithubAsset],
    target_asset: &GithubAsset,
) -> Result<Option<String>, NetfixError> {
    if let Some(ref digest) = target_asset.digest {
        if let Some(hex_part) = digest.strip_prefix("sha256:") {
            return Ok(Some(hex_part.to_string()));
        }
    }

    let sidecar_sha256 = format!("{}.sha256", target_asset.name);
    let sidecar_sha256sum = format!("{}.sha256sum", target_asset.name);

    for sum_asset in select_checksum_candidates(assets, &target_asset.name) {
        let body = client
            .get(&sum_asset.browser_download_url)
            .send()
            .await
            .map_err(|e| NetfixError::Runtime(format!("failed to fetch checksum file: {e}")))?
            .error_for_status()
            .map_err(|e| NetfixError::Runtime(format!("checksum download failed: {e}")))?
            .text()
            .await
            .map_err(|e| NetfixError::Runtime(format!("failed reading checksum file: {e}")))?;

        if let Some(found) = parse_sha256sum_for(&body, &target_asset.name) {
            return Ok(Some(found));
        }
        if sum_asset.name == sidecar_sha256 || sum_asset.name == sidecar_sha256sum {
            if let Some(first) = body.split_whitespace().next() {
                return Ok(Some(first.to_string()));
            }
        }
    }

    Ok(None)
}

fn sanitized_tmp_asset_path(tmp_dir: &Path, asset_name: &str, fallback: &str) -> PathBuf {
    let safe_name = Path::new(asset_name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .unwrap_or(fallback);
    tmp_dir.join(safe_name)
}

struct TempWorkDir(PathBuf);

impl TempWorkDir {
    fn create(prefix: &str) -> Result<Self, NetfixError> {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, Permissions::from_mode(0o700))?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempWorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExitCode;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::os::unix::fs::MetadataExt;
    use tar::{Builder, Header};

    fn build_targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(encoder);
        for (path, content) in entries {
            let mut header = Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, path, *content).unwrap();
        }
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn test_verify_sha256_matches_and_rejects_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bin");
        std::fs::write(&file, b"hello").unwrap();
        let good = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_sha256(&file, good).is_ok());
        assert!(verify_sha256(&file, &good.to_ascii_uppercase()).is_ok());
        assert!(verify_sha256(&file, "0000").is_err());
        let bad = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            verify_sha256(&file, bad).unwrap_err().exit_code(),
            ExitCode::Runtime
        );
    }

    #[test]
    fn test_useradd_netfix_args_are_valid_non_login_system_user() {
        let args = useradd_netfix_args();
        assert!(args.contains(&"--system"));
        assert!(args.contains(&"--no-create-home"));
        assert!(args.contains(&"/usr/sbin/nologin"));
        assert_eq!(args.last().copied(), Some("netfix"));
    }

    #[test]
    fn test_provision_layout_creates_dirs_config_and_units_with_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let paths = SetupPaths::with_prefix(dir.path());

        let (created, units) = provision_layout(&paths, false).unwrap();
        assert!(created);
        assert_eq!(units.len(), 3);

        let etc_mode = std::fs::metadata(&paths.etc_dir).unwrap().mode() & 0o777;
        assert_eq!(etc_mode, 0o750, "expected /etc/netfix mode 0750, got {:o}", etc_mode);

        let cfg_mode = std::fs::metadata(&paths.config_path).unwrap().mode() & 0o777;
        assert_eq!(cfg_mode, 0o640, "expected config.toml mode 0640, got {:o}", cfg_mode);

        let loaded = NetfixConfig::load(&paths.config_path).unwrap();
        assert_eq!(loaded.tgproxy.secret.len(), 32);
        assert!(loaded.tgproxy.secret.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(paths.tgproxy_state_dir.is_dir());
        assert!(paths.libexec_dir.is_dir());

        let hostlists_dir = paths.etc_dir.join("hostlists");
        assert!(hostlists_dir.is_dir());
        let hostlists_mode = std::fs::metadata(&hostlists_dir).unwrap().mode() & 0o777;
        assert_eq!(
            hostlists_mode, 0o755,
            "expected /etc/netfix/hostlists mode 0755, got {:o}",
            hostlists_mode
        );

        let default_hostlist = hostlists_dir.join("default.txt");
        assert!(default_hostlist.is_file());
        let hostlist_mode = std::fs::metadata(&default_hostlist).unwrap().mode() & 0o777;
        assert_eq!(
            hostlist_mode, 0o644,
            "expected /etc/netfix/hostlists/default.txt mode 0644, got {:o}",
            hostlist_mode
        );
        assert_eq!(
            std::fs::read_to_string(&default_hostlist).unwrap(),
            include_str!("../../../presets/hostlists/default.txt")
        );

        // Existing config.toml and hostlists/default.txt must not be overwritten on second run.
        std::fs::write(&default_hostlist, "custom.example.com\n").unwrap();
        let mut modified = loaded.clone();
        modified.tgproxy.port = 2443;
        modified.save(&paths.config_path).unwrap();
        let (created_again, _) = provision_layout(&paths, false).unwrap();
        assert!(!created_again);
        assert_eq!(NetfixConfig::load(&paths.config_path).unwrap().tgproxy.port, 2443);
        assert_eq!(
            std::fs::read_to_string(&default_hostlist).unwrap(),
            "custom.example.com\n"
        );

        let dpi_unit = std::fs::read_to_string(paths.systemd_dir.join("netfix-dpi.service")).unwrap();
        assert!(dpi_unit.contains("ExecStart=/usr/local/bin/netfixctl dpi-run"));
        assert!(dpi_unit.contains("ExecStopPost=/usr/local/bin/netfixctl dpi-cleanup"));
        assert!(dpi_unit.contains("Restart=on-failure"));
        assert!(
            dpi_unit.contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID")
        );

        let tg_unit =
            std::fs::read_to_string(paths.systemd_dir.join("netfix-tgproxy.service")).unwrap();
        assert!(tg_unit.contains("User=netfix"));
        assert!(tg_unit.contains("Group=netfix"));
        assert!(tg_unit.contains("ExecStart=/usr/local/bin/netfix-tgproxy --config /etc/netfix/config.toml"));
        assert!(tg_unit.contains("NoNewPrivileges=yes"));
        assert!(tg_unit.contains("ProtectSystem=strict"));
        assert!(tg_unit.contains("ReadWritePaths=/var/lib/netfix/tgproxy"));

        let target_unit = std::fs::read_to_string(paths.systemd_dir.join("netfix.target")).unwrap();
        assert!(target_unit.contains("Wants=netfix-dpi.service netfix-tgproxy.service"));
    }

    #[test]
    fn test_extract_engine_from_targz_extracts_matching_arch_with_0755_and_rejects_missing() {
        let dir = tempfile::tempdir().unwrap();

        let zapret_tgz = build_targz(&[
            ("zapret-v70/binaries/linux-arm64/nfqws", b"arm64-bin"),
            ("zapret-v70/binaries/linux-x86_64/nfqws", b"x86_64-nfqws-bin"),
        ]);
        let nfqws_dest = dir.path().join("libexec/nfqws");
        extract_engine_from_targz(&zapret_tgz, "nfqws", arch_hints_for("x86_64"), &nfqws_dest)
            .unwrap();
        assert_eq!(std::fs::read(&nfqws_dest).unwrap(), b"x86_64-nfqws-bin");
        assert_eq!(std::fs::metadata(&nfqws_dest).unwrap().mode() & 0o777, 0o755);

        let byedpi_tgz = build_targz(&[("ciadpi-x86_64", b"x86_64-ciadpi-bin")]);
        let ciadpi_dest = dir.path().join("libexec/ciadpi");
        extract_engine_from_targz(&byedpi_tgz, "ciadpi", arch_hints_for("x86_64"), &ciadpi_dest)
            .unwrap();
        assert_eq!(std::fs::read(&ciadpi_dest).unwrap(), b"x86_64-ciadpi-bin");
        assert_eq!(std::fs::metadata(&ciadpi_dest).unwrap().mode() & 0o777, 0o755);

        let empty_tgz = build_targz(&[("README.md", b"docs")]);
        let missing_err = extract_engine_from_targz(
            &empty_tgz,
            "nfqws",
            arch_hints_for("x86_64"),
            &dir.path().join("libexec/missing"),
        )
        .unwrap_err();
        assert_eq!(missing_err.exit_code(), ExitCode::MissingEngine);

        let non_binary_prefixed_tgz = build_targz(&[
            ("ciadpi-x86_64.sha256", b"deadbeef"),
            ("ciadpi-x86_64.sha256sum", b"deadbeef"),
            ("ciadpi-x86_64.sig", b"sig"),
            ("ciadpi-x86_64.asc", b"asc"),
            ("ciadpi-x86_64.exe", b"mz"),
            ("ciadpi-notes.txt", b"notes"),
            ("ciadpi-readme.md", b"md"),
        ]);
        let skip_err = extract_engine_from_targz(
            &non_binary_prefixed_tgz,
            "ciadpi",
            arch_hints_for("x86_64"),
            &dir.path().join("libexec/skipped"),
        )
        .unwrap_err();
        assert_eq!(skip_err.exit_code(), ExitCode::MissingEngine);
    }

    #[test]
    fn test_install_from_local_dir_verifies_sha256_and_sets_0755() {
        let dir = tempfile::tempdir().unwrap();
        let src_dir = dir.path().join("local");
        let libexec = dir.path().join("libexec");
        std::fs::create_dir_all(&src_dir).unwrap();

        let nfqws_src = src_dir.join("nfqws");
        std::fs::write(&nfqws_src, b"hello").unwrap();
        std::fs::write(
            src_dir.join("nfqws.sha256"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  nfqws\n",
        )
        .unwrap();

        let installed = install_from_local_dir(&src_dir, &libexec).unwrap();
        assert_eq!(installed, vec![libexec.join("nfqws")]);
        let mode = std::fs::metadata(libexec.join("nfqws")).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o755);

        // Corrupt checksum fails and does not overwrite binary.
        std::fs::write(
            src_dir.join("nfqws.sha256"),
            "0000000000000000000000000000000000000000000000000000000000000000  nfqws\n",
        )
        .unwrap();
        let err = install_from_local_dir(&src_dir, &libexec).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::Runtime);
    }

    #[test]
    fn test_select_github_asset_picks_matching_linux_archive() {
        let zapret_assets = vec![
            GithubAsset {
                name: "zapret-v70-openwrt-embedded.tar.gz".into(),
                browser_download_url: "https://example.test/openwrt.tar.gz".into(),
                digest: None,
            },
            GithubAsset {
                name: "zapret-v70.tar.gz".into(),
                browser_download_url: "https://example.test/zapret-v70.tar.gz".into(),
                digest: Some("sha256:abcd".into()),
            },
        ];
        assert_eq!(
            select_github_asset(&zapret_assets, "nfqws", "x86_64")
                .unwrap()
                .name,
            "zapret-v70.tar.gz"
        );

        let byedpi_assets = vec![
            GithubAsset {
                name: "byedpi-16-aarch64.tar.gz".into(),
                browser_download_url: "https://example.test/arm64.tar.gz".into(),
                digest: None,
            },
            GithubAsset {
                name: "byedpi-16-x86_64.tar.gz".into(),
                browser_download_url: "https://example.test/x86_64.tar.gz".into(),
                digest: None,
            },
        ];
        assert_eq!(
            select_github_asset(&byedpi_assets, "ciadpi", "x86_64")
                .unwrap()
                .name,
            "byedpi-16-x86_64.tar.gz"
        );
        assert_eq!(
            select_github_asset(&byedpi_assets, "ciadpi", "aarch64")
                .unwrap()
                .name,
            "byedpi-16-aarch64.tar.gz"
        );
    }

    #[test]
    fn test_select_checksum_candidates_ignores_other_arch_sidecar() {
        let assets = vec![
            GithubAsset {
                name: "byedpi-aarch64.tar.gz.sha256".into(),
                browser_download_url: "https://example.test/aarch64.sha256".into(),
                digest: None,
            },
            GithubAsset {
                name: "SHA256SUMS".into(),
                browser_download_url: "https://example.test/SHA256SUMS".into(),
                digest: None,
            },
            GithubAsset {
                name: "byedpi-x86_64.tar.gz.sha256".into(),
                browser_download_url: "https://example.test/x86_64.sha256".into(),
                digest: None,
            },
        ];

        let candidates: Vec<&str> = select_checksum_candidates(&assets, "byedpi-x86_64.tar.gz")
            .into_iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(
            candidates,
            vec!["byedpi-x86_64.tar.gz.sha256", "SHA256SUMS"]
        );
        assert!(!candidates.contains(&"byedpi-aarch64.tar.gz.sha256"));
    }

    #[tokio::test]
    async fn test_system_setup_requires_root_when_unprivileged() {
        if unsafe { libc::geteuid() == 0 } {
            return;
        }
        let err = run_setup(&SetupOptions {
            from_local: None,
            skip_download: true,
            prefix: None,
        })
        .await
        .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::PermissionDenied);
    }

    #[test]
    fn test_sanitized_tmp_asset_path_strips_traversal_components() {
        let dir = Path::new("/tmp/netfix-sha256-test");
        assert_eq!(
            sanitized_tmp_asset_path(dir, "../../etc/cron.d/evil.tar.gz", "nfqws"),
            dir.join("evil.tar.gz")
        );
        assert_eq!(
            sanitized_tmp_asset_path(dir, "/abs/path/byedpi.tgz", "ciadpi"),
            dir.join("byedpi.tgz")
        );
        assert_eq!(
            sanitized_tmp_asset_path(dir, "..", "ciadpi"),
            dir.join("ciadpi")
        );
    }

    #[tokio::test]
    async fn test_download_bytes_with_resume_recovers_after_mid_stream_drop() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let payload: Vec<u8> = (0..100u8).collect();
        let payload_srv = payload.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // Attempt 1: send headers claiming 100 bytes, send 40 bytes, drop connection.
            let (mut s1, _) = listener.accept().await.unwrap();
            let mut req1 = [0u8; 1024];
            let _ = s1.read(&mut req1).await.unwrap();
            s1.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            s1.write_all(&payload_srv[..40]).await.unwrap();
            s1.shutdown().await.ok();
            drop(s1);

            // Attempt 2: expect Range: bytes=40-, send 206 Partial Content with remaining 60 bytes.
            let (mut s2, _) = listener.accept().await.unwrap();
            let mut req2 = [0u8; 2048];
            let n = s2.read(&mut req2).await.unwrap();
            let req_str = String::from_utf8_lossy(&req2[..n]).to_ascii_lowercase();
            assert!(req_str.contains("range: bytes=40-"), "missing range header: {req_str}");
            s2.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 60\r\nContent-Range: bytes 40-99/100\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            s2.write_all(&payload_srv[40..]).await.unwrap();
            s2.shutdown().await.ok();
        });

        let client = build_download_client().unwrap();
        let url = format!("http://{addr}/zapret.tar.gz");
        let got = download_bytes_with_resume(&client, &url, "zapret.tar.gz")
            .await
            .unwrap();
        assert_eq!(got, payload);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_download_bytes_with_resume_restarts_cleanly_on_200_ignore_range() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let payload: Vec<u8> = (0..80u8).collect();
        let payload_srv = payload.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut s1, _) = listener.accept().await.unwrap();
            let mut req1 = [0u8; 1024];
            let _ = s1.read(&mut req1).await.unwrap();
            s1.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 80\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            s1.write_all(&payload_srv[..20]).await.unwrap();
            drop(s1);

            let (mut s2, _) = listener.accept().await.unwrap();
            let mut req2 = [0u8; 2048];
            let _ = s2.read(&mut req2).await.unwrap();
            s2.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 80\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            s2.write_all(&payload_srv).await.unwrap();
            s2.shutdown().await.ok();
        });

        let client = build_download_client().unwrap();
        let url = format!("http://{addr}/byedpi.tar.gz");
        let got = download_bytes_with_resume(&client, &url, "byedpi.tar.gz")
            .await
            .unwrap();
        assert_eq!(got, payload);
        server.await.unwrap();
    }
}
