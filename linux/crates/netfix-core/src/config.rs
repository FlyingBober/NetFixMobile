use std::collections::BTreeMap;
use std::fs::{OpenOptions, Permissions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::NetfixError;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/netfix/config.toml";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/netfix";
pub const DEFAULT_LIBEXEC_DIR: &str = "/usr/local/libexec/netfix";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DpiEngineKind {
    #[default]
    Nfqws,
    Ciadpi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CiadpiMode {
    #[default]
    Socks5,
    Transparent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpsetMode {
    #[default]
    Any,
    Loaded,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    #[default]
    System,
    Cloudflare,
    Google,
    Quad9,
    Adguard,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub active_network_override: Option<String>,
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            active_network_override: None,
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkStrategy {
    pub nfqws: Option<String>,
    pub ciadpi: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DpiConfig {
    pub enabled: bool,
    pub engine: DpiEngineKind,
    pub ciadpi_mode: CiadpiMode,
    pub socks_bind: String,
    pub socks_port: u16,
    pub transparent_port: u16,
    pub nfqueue_num: u16,
    pub fwmark: u32,
    pub game_filter: bool,
    pub ipset_mode: IpsetMode,
    #[serde(default)]
    pub ipset_v4: Vec<String>,
    #[serde(default)]
    pub ipset_v6: Vec<String>,
    pub active_strategy_nfqws: String,
    pub active_strategy_ciadpi: String,
    pub hostlist_path: Option<String>,
    pub network_strategies: BTreeMap<String, NetworkStrategy>,
}

impl Default for DpiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            engine: DpiEngineKind::Nfqws,
            ciadpi_mode: CiadpiMode::Socks5,
            socks_bind: "127.0.0.1".to_string(),
            socks_port: 1080,
            transparent_port: 11080,
            nfqueue_num: 200,
            fwmark: 0x4000_0000,
            game_filter: false,
            ipset_mode: IpsetMode::Any,
            ipset_v4: Vec::new(),
            ipset_v6: Vec::new(),
            active_strategy_nfqws: "--filter-tcp=80,443 --dpi-desync=fake,multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6".to_string(),
            active_strategy_ciadpi: "-o1 -d1 -a1 -At,r,s -s1 -d1 -s5+s -s10+s -s15+s -s20+s -r1+s -S -a1 -As -s1 -d1 -s5+s -s10+s -s15+s -s20+s -S -a1".to_string(),
            hostlist_path: None,
            network_strategies: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TgProxyConfig {
    pub enabled: bool,
    pub bind_ip: String,
    pub port: u16,
    pub secret: String,
    pub pool_size: usize,
    pub dc_ips: String,
    pub cf_enabled: bool,
    pub cf_priority: bool,
    pub pinned_cf_domain: String,
    pub cf_front_ips: Vec<String>,
    pub cf_plain_first: bool,
    pub tls_verify: bool,
    pub cache_dir: String,
}

impl Default for TgProxyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_ip: "127.0.0.1".to_string(),
            port: 1443,
            secret: String::new(),
            pool_size: 4,
            dc_ips: "2:149.154.167.220,4:149.154.167.220".to_string(),
            cf_enabled: true,
            cf_priority: true,
            pinned_cf_domain: String::new(),
            cf_front_ips: Vec::new(),
            cf_plain_first: false,
            tls_verify: true,
            cache_dir: "/var/lib/netfix/tgproxy".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub mode: DnsMode,
    pub custom_servers: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            mode: DnsMode::System,
            custom_servers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetfixConfig {
    pub general: GeneralConfig,
    pub dpi: DpiConfig,
    pub tgproxy: TgProxyConfig,
    pub dns: DnsConfig,
}

impl NetfixConfig {
    pub fn default_path() -> PathBuf {
        PathBuf::from(DEFAULT_CONFIG_PATH)
    }

    pub fn resolve_path(cli_override: Option<&Path>) -> PathBuf {
        if let Some(p) = cli_override {
            return p.to_path_buf();
        }
        if let Ok(env_path) = std::env::var("NETFIX_CONFIG") {
            let trimmed = env_path.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
        Self::default_path()
    }

    pub fn load(path: &Path) -> Result<Self, NetfixError> {
        let raw = std::fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), NetfixError> {
        self.validate()?;
        let content = toml::to_string_pretty(self)?;
        ensure_parent_dir(path)?;
        write_atomic(path, content.as_bytes())?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), NetfixError> {
        if !self.tgproxy.secret.is_empty() && !is_valid_mtproto_secret(&self.tgproxy.secret) {
            return Err(NetfixError::InvalidInput(
                "tgproxy.secret must be empty or 32 hexadecimal characters".into(),
            ));
        }

        if self.dpi.socks_port == 0 {
            return Err(NetfixError::InvalidInput(
                "dpi.socks_port must be in 1..=65535".into(),
            ));
        }
        if self.dpi.transparent_port == 0 {
            return Err(NetfixError::InvalidInput(
                "dpi.transparent_port must be in 1..=65535".into(),
            ));
        }
        if self.dpi.fwmark == 0 {
            return Err(NetfixError::InvalidInput(
                "dpi.fwmark must be non-zero".into(),
            ));
        }
        if self.tgproxy.port == 0 {
            return Err(NetfixError::InvalidInput(
                "tgproxy.port must be in 1..=65535".into(),
            ));
        }

        if self.dpi.socks_bind.parse::<IpAddr>().is_err() {
            return Err(NetfixError::InvalidInput(format!(
                "dpi.socks_bind is not a valid IP address: {}",
                self.dpi.socks_bind
            )));
        }
        if self.tgproxy.bind_ip.parse::<IpAddr>().is_err() {
            return Err(NetfixError::InvalidInput(format!(
                "tgproxy.bind_ip is not a valid IP address: {}",
                self.tgproxy.bind_ip
            )));
        }

        if self.tgproxy.pool_size == 0 {
            return Err(NetfixError::InvalidInput(
                "tgproxy.pool_size must be at least 1".into(),
            ));
        }

        for ip in &self.tgproxy.cf_front_ips {
            if ip.parse::<IpAddr>().is_err() {
                return Err(NetfixError::InvalidInput(format!(
                    "tgproxy.cf_front_ips contains invalid IP address: {ip}"
                )));
            }
        }

        for srv in &self.dns.custom_servers {
            if srv.parse::<IpAddr>().is_err() {
                return Err(NetfixError::InvalidInput(format!(
                    "dns.custom_servers contains invalid IP address: {srv}"
                )));
            }
        }

        Ok(())
    }

    pub fn ensure_secret(&mut self) -> String {
        if is_valid_mtproto_secret(&self.tgproxy.secret) {
            return self.tgproxy.secret.clone();
        }
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let secret = hex::encode(bytes);
        self.tgproxy.secret = secret.clone();
        secret
    }
}

pub fn normalize_network_key(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed.to_string()
    }
}

fn is_valid_mtproto_secret(secret: &str) -> bool {
    secret.len() == 32 && secret.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn ensure_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with_mode(path, bytes, 0o640)
}

fn is_in_place_fallback_errno(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EXDEV | libc::EBUSY))
}

pub(crate) fn write_atomic_with_mode(
    path: &Path,
    bytes: &[u8],
    default_mode: u32,
) -> std::io::Result<()> {
    let existing_meta = match std::fs::metadata(path) {
        Ok(meta) => Some((meta.mode() & 0o7777, meta.uid(), meta.gid())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    let target_mode = existing_meta.map(|(m, _, _)| m).unwrap_or(default_mode);

    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".to_string());
    let tmp_name = format!(".{file_name}.tmp.{}", rand::random::<u64>());
    let tmp_path = match parent {
        Some(dir) => dir.join(tmp_name),
        None => PathBuf::from(tmp_name),
    };

    let write_tmp = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(target_mode)
            .open(&tmp_path)?;
        if let Some((_, uid, gid)) = existing_meta {
            preserve_ownership(&tmp_path, uid, gid)?;
        }
        std::fs::set_permissions(&tmp_path, Permissions::from_mode(target_mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_tmp {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    match std::fs::rename(&tmp_path, path) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = std::fs::remove_file(&tmp_path);
            if is_in_place_fallback_errno(&err) {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(target_mode)
                    .open(path)?;
                std::fs::set_permissions(path, Permissions::from_mode(target_mode))?;
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            } else {
                Err(err)
            }
        }
    }
}

fn preserve_ownership(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path contains interior NUL byte",
        )
    })?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EPERM) {
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExitCode;

    #[test]
    fn test_invalid_nonempty_secret_rejected() {
        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.secret = "not-valid-hex".into();
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::InvalidInput);
    }

    #[test]
    fn test_wrong_length_hex_secret_rejected() {
        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.secret = "0123456789abcdef".into();
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::InvalidInput);
    }

    #[test]
    fn test_empty_secret_valid_and_generates_32_hex() {
        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.secret.clear();
        assert!(cfg.validate().is_ok());
        let sec = cfg.ensure_secret();
        assert_eq!(sec.len(), 32);
        assert!(hex::decode(&sec).is_ok());
        assert_eq!(cfg.tgproxy.secret, sec);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_network_key_normalization() {
        assert_eq!(normalize_network_key("My Home Wi-Fi! (5G)"), "my_home_wi-fi_5g");
        assert_eq!(normalize_network_key("___eth0___"), "eth0");
        assert_eq!(normalize_network_key("!!!"), "default");
    }

    #[test]
    fn test_defaults_and_port_ip_validation() {
        let cfg = NetfixConfig::default();
        assert_eq!(NetfixConfig::default_path(), Path::new("/etc/netfix/config.toml"));
        assert_eq!(cfg.dpi.nfqueue_num, 200);
        assert_eq!(cfg.dpi.fwmark, 0x4000_0000);
        assert_eq!(cfg.dpi.socks_bind, "127.0.0.1");
        assert_eq!(cfg.dpi.socks_port, 1080);
        assert_eq!(cfg.dpi.transparent_port, 11080);
        assert!(!cfg.dpi.game_filter);
        assert_eq!(cfg.dpi.ipset_mode, IpsetMode::Any);
        assert_eq!(cfg.tgproxy.bind_ip, "127.0.0.1");
        assert_eq!(cfg.tgproxy.port, 1443);
        assert_eq!(cfg.tgproxy.pool_size, 4);
        assert_eq!(cfg.tgproxy.dc_ips, "2:149.154.167.220,4:149.154.167.220");
        assert!(cfg.tgproxy.cf_enabled);
        assert!(cfg.tgproxy.cf_priority);
        assert!(!cfg.tgproxy.cf_plain_first);
        assert!(cfg.tgproxy.tls_verify);
        assert_eq!(cfg.dns.mode, DnsMode::System);
        assert!(cfg.validate().is_ok());

        let mut bad_port = NetfixConfig::default();
        bad_port.tgproxy.port = 0;
        assert_eq!(bad_port.validate().unwrap_err().exit_code(), ExitCode::InvalidInput);

        let mut bad_ip = NetfixConfig::default();
        bad_ip.tgproxy.bind_ip = "not-an-ip".into();
        assert_eq!(bad_ip.validate().unwrap_err().exit_code(), ExitCode::InvalidInput);
    }

    #[test]
    fn test_zero_fwmark_rejected_with_invalid_input() {
        let mut cfg = NetfixConfig::default();
        cfg.dpi.fwmark = 0;
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::InvalidInput);
    }

    #[test]
    fn test_config_roundtrip_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        let mut cfg = NetfixConfig::default();
        cfg.ensure_secret();
        cfg.dpi.network_strategies.insert(
            normalize_network_key("Office Wi-Fi"),
            NetworkStrategy {
                nfqws: Some("--dpi-desync=fake".into()),
                ciadpi: Some("-o1 -d1 -a1".into()),
            },
        );
        cfg.save(&path).unwrap();

        let loaded = NetfixConfig::load(&path).unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn test_save_sets_0640_on_new_file_and_preserves_existing_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let cfg = NetfixConfig::default();
        cfg.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o640, "expected 0640, got {:o}", mode);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut updated = cfg;
        updated.tgproxy.port = 2443;
        updated.save(&path).unwrap();
        let preserved_mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(preserved_mode, 0o600, "expected preserved 0600, got {:o}", preserved_mode);
    }

    #[test]
    fn test_is_in_place_fallback_errno_matches_exdev_and_ebusy_only() {
        assert!(is_in_place_fallback_errno(
            &std::io::Error::from_raw_os_error(libc::EXDEV)
        ));
        assert!(is_in_place_fallback_errno(
            &std::io::Error::from_raw_os_error(libc::EBUSY)
        ));
        assert!(!is_in_place_fallback_errno(
            &std::io::Error::from_raw_os_error(libc::EACCES)
        ));
        assert!(!is_in_place_fallback_errno(&std::io::Error::new(
            std::io::ErrorKind::Other,
            "no errno",
        )));
    }
}
