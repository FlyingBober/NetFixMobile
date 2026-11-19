pub mod config;
pub mod dns;
pub mod dpi;
pub mod firewall;
pub mod hosts;
pub mod scanner;
pub mod setup;
pub mod strategy;
pub mod tg;

pub use config::{
    normalize_network_key, CiadpiMode, DnsConfig, DnsMode, DpiConfig, DpiEngineKind,
    GeneralConfig, IpsetMode, NetfixConfig, NetworkStrategy, TgProxyConfig, DEFAULT_CONFIG_PATH,
    DEFAULT_LIBEXEC_DIR, DEFAULT_STATE_DIR,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Ok = 0,
    Runtime = 1,
    InvalidInput = 2,
    PermissionDenied = 3,
    MissingEngine = 4,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code as i32
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetfixError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("missing engine binary: {0}")]
    MissingEngine(String),
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl NetfixError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidInput(_) => ExitCode::InvalidInput,
            Self::PermissionDenied(_) => ExitCode::PermissionDenied,
            Self::MissingEngine(_) => ExitCode::MissingEngine,
            Self::Io(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                ExitCode::PermissionDenied
            }
            Self::Runtime(_) | Self::Io(_) => ExitCode::Runtime,
        }
    }
}

/// Checks that the current process has effective UID 0 (`root`), returning
/// `NetfixError::PermissionDenied` otherwise.
pub fn require_root(action: &str) -> Result<(), NetfixError> {
    if unsafe { libc::geteuid() == 0 } {
        Ok(())
    } else {
        Err(NetfixError::PermissionDenied(format!(
            "root privileges (euid 0) are required to {action}"
        )))
    }
}

impl From<toml::de::Error> for NetfixError {
    fn from(err: toml::de::Error) -> Self {
        Self::InvalidInput(format!("TOML parse error: {err}"))
    }
}

impl From<toml::ser::Error> for NetfixError {
    fn from(err: toml::ser::Error) -> Self {
        Self::Runtime(format!("TOML serialize error: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_permission_denied_maps_to_permission_denied_exit_code() {
        let err = NetfixError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(err.exit_code(), ExitCode::PermissionDenied);
        assert_eq!(err.exit_code().as_i32(), 3);

        let other = NetfixError::Io(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(other.exit_code(), ExitCode::Runtime);
    }
}
