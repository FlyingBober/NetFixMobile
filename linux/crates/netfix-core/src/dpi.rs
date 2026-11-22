use std::ffi::OsStr;
use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::sync::watch;

use crate::firewall::{
    cleanup_table, detect_backend, is_executable_file, which_binary, FirewallGuard, FirewallKind,
    FirewallSpec,
};
use crate::strategy::{expand_sni, sanitize_ciadpi_args, sanitize_nfqws_args};
use crate::{
    CiadpiMode, DpiEngineKind, NetfixConfig, NetfixError, DEFAULT_LIBEXEC_DIR,
};

pub const DEFAULT_FIREWALL_TABLE: &str = "netfix";
pub const DEFAULT_HOSTLIST_PATH: &str = "/etc/netfix/hostlists/default.txt";
const DEFAULT_FAKE_SNI: &str = "google.com";
const FALLBACK_UNPRIVILEGED_UID: u32 = 65534;
const FALLBACK_UNPRIVILEGED_GID: u32 = 65534;
const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Managed DPI engine child process and optional firewall guard.
#[derive(Debug)]
pub struct DpiRunner {
    engine: DpiEngineKind,
    child: tokio::process::Child,
    firewall: Option<FirewallGuard>,
    bound_port: Option<u16>,
}

impl DpiRunner {
    /// Starts the configured DPI engine and applies firewall rules when required.
    pub fn start_service(cfg: &NetfixConfig) -> Result<Self, NetfixError> {
        cfg.validate()?;
        if requires_root(cfg) && !is_root() {
            return Err(NetfixError::PermissionDenied(
                "root privileges (euid 0 / CAP_NET_ADMIN) are required for nfqws or ciadpi transparent mode".into(),
            ));
        }

        let strategy = resolve_active_strategy(cfg);
        match cfg.dpi.engine {
            DpiEngineKind::Nfqws => {
                let bin = find_engine_binary("nfqws")?;
                let cmd = build_nfqws_command(cfg, &bin, strategy, cfg.dpi.nfqueue_num)?;
                let kind = detect_backend()?;
                let spec = FirewallSpec::from_config(
                    cfg,
                    DEFAULT_FIREWALL_TABLE,
                    cfg.dpi.ipset_v4.clone(),
                    cfg.dpi.ipset_v6.clone(),
                    None,
                )?
                .ok_or_else(|| {
                    NetfixError::InvalidInput("nfqws requires an active firewall spec".into())
                })?;
                let guard = FirewallGuard::new(kind, spec);
                Self::spawn_command(DpiEngineKind::Nfqws, cmd, Some(guard), None)
            }
            DpiEngineKind::Ciadpi => {
                let bin = find_engine_binary("ciadpi")?;
                match cfg.dpi.ciadpi_mode {
                    CiadpiMode::Socks5 => {
                        let port = resolve_free_port(&cfg.dpi.socks_bind, cfg.dpi.socks_port);
                        let cmd = build_ciadpi_command(cfg, &bin, strategy, port, false)?;
                        Self::spawn_command(DpiEngineKind::Ciadpi, cmd, None, Some(port))
                    }
                    CiadpiMode::Transparent => {
                        let port = resolve_free_port("127.0.0.1", cfg.dpi.transparent_port);
                        let (drop_uid, drop_gid) = resolve_unprivileged_uid_gid();
                        let mut cmd = build_ciadpi_command(cfg, &bin, strategy, port, true)?;
                        cmd.uid(drop_uid);
                        cmd.gid(drop_gid);

                        let kind = detect_backend()?;
                        let mut spec = FirewallSpec::from_config(
                            cfg,
                            DEFAULT_FIREWALL_TABLE,
                            vec![],
                            vec![],
                            Some(drop_uid),
                        )?
                        .ok_or_else(|| {
                            NetfixError::InvalidInput(
                                "ciadpi transparent mode requires an active firewall spec".into(),
                            )
                        })?;
                        if spec.transparent_port != port {
                            spec.transparent_port = port;
                            spec.validate()?;
                        }
                        let guard = FirewallGuard::new(kind, spec);
                        Self::spawn_command(DpiEngineKind::Ciadpi, cmd, Some(guard), Some(port))
                    }
                }
            }
        }
    }

    /// Applies any attached firewall guard and spawns the prepared engine command.
    pub fn spawn_command(
        engine: DpiEngineKind,
        std_cmd: Command,
        firewall: Option<FirewallGuard>,
        bound_port: Option<u16>,
    ) -> Result<Self, NetfixError> {
        if let Some(ref guard) = firewall {
            guard.apply()?;
        }

        let mut cmd = tokio::process::Command::from(std_cmd);
        cmd.stdin(Stdio::null());
        cmd.kill_on_drop(true);

        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                drop(firewall);
                return Err(NetfixError::Io(err));
            }
        };

        Ok(Self {
            engine,
            child,
            firewall,
            bound_port,
        })
    }

    pub fn engine(&self) -> DpiEngineKind {
        self.engine
    }

    pub fn bound_port(&self) -> Option<u16> {
        self.bound_port
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, NetfixError> {
        self.child.try_wait().map_err(NetfixError::Io)
    }

    /// Waits for either child exit or shutdown notification, cleaning up on stop.
    pub async fn wait_or_shutdown(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), NetfixError> {
        loop {
            if *shutdown.borrow() {
                return self.stop().await;
            }

            tokio::select! {
                res = self.child.wait() => {
                    let guard = self.firewall.take();
                    drop(guard);
                    return match res {
                        Ok(status) if status.success() => Ok(()),
                        Ok(status) => Err(NetfixError::Runtime(format!(
                            "{} exited unexpectedly with {status}",
                            engine_binary_name(self.engine)
                        ))),
                        Err(err) => Err(NetfixError::Io(err)),
                    };
                }
                changed = shutdown.changed() => {
                    match changed {
                        Ok(()) if !*shutdown.borrow() => continue,
                        Ok(()) | Err(_) => return self.stop().await,
                    }
                }
            }
        }
    }

    /// Gracefully stops the child process (SIGTERM -> 2s -> SIGKILL) and drops the firewall guard.
    pub async fn stop(mut self) -> Result<(), NetfixError> {
        let stop_res = terminate_child(&mut self.child).await;
        let guard = self.firewall.take();
        drop(guard);
        stop_res
    }
}

/// Locates a DPI engine binary in `/usr/local/libexec/netfix`, then `PATH` / fallback bin dirs.
pub fn find_engine_binary(name: &str) -> Result<PathBuf, NetfixError> {
    if name.is_empty() {
        return Err(NetfixError::MissingEngine(
            "empty DPI engine binary name".into(),
        ));
    }

    let path_env = std::env::var_os("PATH");
    if let Some(found) =
        find_engine_binary_in(name, Path::new(DEFAULT_LIBEXEC_DIR), path_env.as_deref())
    {
        return Ok(found);
    }

    if !name.contains('/') {
        if let Some(found) = which_binary(name) {
            return Ok(found);
        }
    }

    Err(NetfixError::MissingEngine(format!(
        "engine binary '{name}' not found in {DEFAULT_LIBEXEC_DIR} or PATH"
    )))
}

fn find_engine_binary_in(
    name: &str,
    libexec_dir: &Path,
    path_env: Option<&OsStr>,
) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }

    if name.contains('/') {
        let direct = Path::new(name);
        return is_executable_file(direct).then(|| direct.to_path_buf());
    }

    let libexec_candidate = libexec_dir.join(name);
    if is_executable_file(&libexec_candidate) {
        return Some(libexec_candidate);
    }

    if let Some(path_var) = path_env {
        for dir in std::env::split_paths(path_var) {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}

/// Checks whether `preferred` is bindable on `bind_ip`, otherwise resolves an ephemeral free port.
pub fn resolve_free_port(bind_ip: &str, preferred: u16) -> u16 {
    if preferred != 0 && TcpListener::bind((bind_ip, preferred)).is_ok() {
        return preferred;
    }
    if let Ok(listener) = TcpListener::bind((bind_ip, 0)) {
        if let Ok(addr) = listener.local_addr() {
            return addr.port();
        }
    }
    preferred
}

/// Resolves the active strategy string, detected network key, and whether it came from a network-specific profile.
pub fn resolve_strategy_for_config(cfg: &NetfixConfig) -> (&str, String, bool) {
    let net_key = crate::network::detect_active_network_key(cfg);
    if let Some(net_strat) = cfg.dpi.network_strategies.get(&net_key) {
        let override_strat = match cfg.dpi.engine {
            DpiEngineKind::Nfqws => net_strat.nfqws.as_deref(),
            DpiEngineKind::Ciadpi => net_strat.ciadpi.as_deref(),
        };
        if let Some(s) = override_strat.map(str::trim).filter(|s| !s.is_empty()) {
            return (s, net_key, true);
        }
    }

    let fallback = match cfg.dpi.engine {
        DpiEngineKind::Nfqws => cfg.dpi.active_strategy_nfqws.as_str(),
        DpiEngineKind::Ciadpi => cfg.dpi.active_strategy_ciadpi.as_str(),
    };
    (fallback, net_key, false)
}

/// Resolves the active strategy string for the configured engine and detected network.
pub fn resolve_active_strategy(cfg: &NetfixConfig) -> &str {
    resolve_strategy_for_config(cfg).0
}

/// Builds a sanitized `nfqws` command with pinned `--qnum` and `--dpi-desync-fwmark`.
pub fn build_nfqws_command(
    cfg: &NetfixConfig,
    bin: &Path,
    strategy: &str,
    qnum: u16,
) -> Result<Command, NetfixError> {
    build_nfqws_command_with_hostlist(
        cfg,
        bin,
        strategy,
        qnum,
        Some(Path::new(DEFAULT_HOSTLIST_PATH)),
    )
}

/// Builds a sanitized `nfqws` command with an injectable default hostlist path.
pub fn build_nfqws_command_with_hostlist(
    cfg: &NetfixConfig,
    bin: &Path,
    strategy: &str,
    qnum: u16,
    default_hostlist: Option<&Path>,
) -> Result<Command, NetfixError> {
    let sanitized = sanitize_nfqws_args(strategy)?;
    let mut cmd = Command::new(bin);
    cmd.arg(format!("--qnum={qnum}"));
    cmd.arg(format!("--dpi-desync-fwmark=0x{:08x}", cfg.dpi.fwmark));

    let has_uid_override = sanitized.iter().any(|arg| {
        arg == "--uid"
            || arg.starts_with("--uid=")
            || arg == "--user"
            || arg.starts_with("--user=")
    });
    if !has_uid_override {
        let (drop_uid, drop_gid) = resolve_unprivileged_uid_gid();
        cmd.arg(format!("--uid={drop_uid}:{drop_gid}"));
    }

    let has_hostlist = sanitized
        .iter()
        .any(|arg| arg == "--hostlist" || arg.starts_with("--hostlist="));
    if !has_hostlist {
        if let Some(hostlist) = cfg
            .dpi
            .hostlist_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if hostlist != DEFAULT_HOSTLIST_PATH || Path::new(hostlist).is_file() {
                cmd.arg(format!("--hostlist={hostlist}"));
            }
        } else if let Some(default_path) = default_hostlist.filter(|p| p.is_file()) {
            cmd.arg(format!("--hostlist={}", default_path.display()));
        }
    }

    cmd.args(&sanitized);
    Ok(cmd)
}

/// Builds a sanitized `ciadpi` command with pinned `--ip`, `--port`, optional `--transparent`, and `{sni}` expansion.
pub fn build_ciadpi_command(
    cfg: &NetfixConfig,
    bin: &Path,
    strategy: &str,
    port: u16,
    transparent: bool,
) -> Result<Command, NetfixError> {
    if port == 0 {
        return Err(NetfixError::InvalidInput(
            "ciadpi port must be in 1..=65535".into(),
        ));
    }

    let sanitized = sanitize_ciadpi_args(strategy)?;
    let expanded = expand_sni(&sanitized, DEFAULT_FAKE_SNI);
    let bind_ip = if transparent {
        "127.0.0.1"
    } else {
        cfg.dpi.socks_bind.as_str()
    };

    let mut cmd = Command::new(bin);
    cmd.args(["--ip", bind_ip, "--port", &port.to_string()]);
    if transparent {
        cmd.arg("--transparent");
    }
    cmd.args(&expanded);
    Ok(cmd)
}

/// Runs the configured DPI service until the child exits or `shutdown` triggers.
pub async fn run_dpi_service(
    cfg: &NetfixConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<(), NetfixError> {
    cfg.validate()?;
    if !cfg.dpi.enabled {
        return Ok(());
    }
    if requires_root(cfg) && !is_root() {
        return Err(NetfixError::PermissionDenied(
            "root privileges (euid 0 / CAP_NET_ADMIN) are required for nfqws or ciadpi transparent mode".into(),
        ));
    }
    if *shutdown.borrow() {
        return Ok(());
    }

    let runner = DpiRunner::start_service(cfg)?;
    runner.wait_or_shutdown(shutdown).await
}

/// Unconditionally cleans up NetFix DPI firewall tables/chains after verifying root privileges.
pub fn cleanup_dpi_firewall(cfg: &NetfixConfig) -> Result<(), NetfixError> {
    let _ = cfg;
    cleanup_dpi_firewall_with(
        || crate::require_root("clean up DPI firewall rules"),
        detect_backend,
        cleanup_table,
    )
}

fn cleanup_dpi_firewall_with<R, D, C>(
    require_root_fn: R,
    detect_fn: D,
    cleanup_fn: C,
) -> Result<(), NetfixError>
where
    R: FnOnce() -> Result<(), NetfixError>,
    D: FnOnce() -> Result<FirewallKind, NetfixError>,
    C: FnOnce(FirewallKind, &str) -> Result<(), NetfixError>,
{
    require_root_fn()?;
    let kind = detect_fn()?;
    match cleanup_fn(kind, DEFAULT_FIREWALL_TABLE) {
        Ok(()) => Ok(()),
        Err(err) if is_missing_table_or_chain_error(&err) => Ok(()),
        Err(err) => Err(err),
    }
}

fn is_missing_table_or_chain_error(err: &NetfixError) -> bool {
    match err {
        NetfixError::Runtime(msg) => {
            let lower = msg.to_ascii_lowercase();
            lower.contains("no such file or directory")
                || lower.contains("does not exist")
                || lower.contains("no chain/target/match")
        }
        _ => false,
    }
}

fn requires_root(cfg: &NetfixConfig) -> bool {
    match cfg.dpi.engine {
        DpiEngineKind::Nfqws => true,
        DpiEngineKind::Ciadpi => cfg.dpi.ciadpi_mode == CiadpiMode::Transparent,
    }
}

pub(crate) fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn engine_binary_name(engine: DpiEngineKind) -> &'static str {
    match engine {
        DpiEngineKind::Nfqws => "nfqws",
        DpiEngineKind::Ciadpi => "ciadpi",
    }
}

fn resolve_unprivileged_uid_gid() -> (u32, u32) {
    let passwd = std::fs::read_to_string("/etc/passwd").ok();
    resolve_unprivileged_uid_gid_from_passwd(passwd.as_deref())
}

fn resolve_unprivileged_uid_gid_from_passwd(passwd: Option<&str>) -> (u32, u32) {
    if let Some(contents) = passwd {
        if let Some(pair) = parse_passwd_uid_gid(contents, "netfix") {
            return pair;
        }
        if let Some(pair) = parse_passwd_uid_gid(contents, "nobody") {
            return pair;
        }
    }
    (FALLBACK_UNPRIVILEGED_UID, FALLBACK_UNPRIVILEGED_GID)
}

fn parse_passwd_uid_gid(contents: &str, username: &str) -> Option<(u32, u32)> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split(':');
        let Some(name) = fields.next() else {
            continue;
        };
        if name != username {
            continue;
        }
        let _pw = fields.next()?;
        let uid = fields.next()?.parse::<u32>().ok()?;
        let gid = fields.next()?.parse::<u32>().ok()?;
        return Some((uid, gid));
    }
    None
}

async fn terminate_child(child: &mut tokio::process::Child) -> Result<(), NetfixError> {
    let Some(pid) = child.id() else {
        return Ok(());
    };
    if let Ok(pid_t) = libc::pid_t::try_from(pid) {
        if pid_t > 0 {
            unsafe {
                libc::kill(pid_t, libc::SIGTERM);
            }
        }
    }

    match tokio::time::timeout(GRACEFUL_STOP_TIMEOUT, child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(NetfixError::Io(err)),
        Err(_) => {
            child.kill().await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CiadpiMode, DpiEngineKind, ExitCode, NetfixConfig, NetworkStrategy};
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn write_executable_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn test_build_nfqws_command_pins_qnum_and_fwmark() {
        let cfg = NetfixConfig::default();
        let cmd = build_nfqws_command(
            &cfg,
            Path::new("/usr/bin/nfqws"),
            "--qnum=1 --dpi-desync=fake",
            200,
        )
        .unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--qnum=200".into()));
        assert!(args.contains(&"--dpi-desync-fwmark=0x40000000".into()));
        assert!(args.contains(&"--dpi-desync=fake".into()));
        assert!(!args.contains(&"--qnum=1".into()));
        assert!(args.iter().any(|a| a.starts_with("--uid=")));

        let custom_uid = build_nfqws_command(
            &cfg,
            Path::new("/usr/bin/nfqws"),
            "--uid=1000:1000 --dpi-desync=fake",
            200,
        )
        .unwrap();
        let custom_args: Vec<_> = custom_uid
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            custom_args.iter().filter(|a| a.starts_with("--uid=")).count(),
            1
        );
        assert!(custom_args.contains(&"--uid=1000:1000".into()));
    }

    #[test]
    fn test_build_nfqws_command_adds_hostlist_unless_overridden() {
        let mut cfg = NetfixConfig::default();
        cfg.dpi.hostlist_path = Some("/etc/netfix/hostlist.txt".into());

        let cmd = build_nfqws_command(
            &cfg,
            Path::new("/usr/bin/nfqws"),
            "--dpi-desync=fake",
            200,
        )
        .unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--hostlist=/etc/netfix/hostlist.txt".into()));

        let custom = build_nfqws_command(
            &cfg,
            Path::new("/usr/bin/nfqws"),
            "--hostlist=/tmp/custom.txt --dpi-desync=fake",
            200,
        )
        .unwrap();
        let custom_args: Vec<_> = custom
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(!custom_args.contains(&"--hostlist=/etc/netfix/hostlist.txt".into()));
        assert!(custom_args.contains(&"--hostlist=/tmp/custom.txt".into()));
    }

    #[test]
    fn test_build_nfqws_command_with_default_hostlist_guards_existence() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("default.txt");
        std::fs::write(&existing, "youtube.com\n").unwrap();
        let missing = dir.path().join("missing.txt");

        let cfg = NetfixConfig::default();

        let with_existing = build_nfqws_command_with_hostlist(
            &cfg,
            Path::new("/usr/bin/nfqws"),
            "--dpi-desync=fake",
            200,
            Some(&existing),
        )
        .unwrap();
        let existing_args: Vec<_> = with_existing
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(existing_args.contains(&format!("--hostlist={}", existing.display())));

        let with_missing = build_nfqws_command_with_hostlist(
            &cfg,
            Path::new("/usr/bin/nfqws"),
            "--dpi-desync=fake",
            200,
            Some(&missing),
        )
        .unwrap();
        let missing_args: Vec<_> = with_missing
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(!missing_args.iter().any(|a| a.starts_with("--hostlist")));

        let overridden = build_nfqws_command_with_hostlist(
            &cfg,
            Path::new("/usr/bin/nfqws"),
            "--hostlist=/tmp/override.txt --dpi-desync=fake",
            200,
            Some(&existing),
        )
        .unwrap();
        let overridden_args: Vec<_> = overridden
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(overridden_args.contains(&"--hostlist=/tmp/override.txt".into()));
        assert!(!overridden_args.contains(&format!("--hostlist={}", existing.display())));
    }

    #[test]
    fn test_cleanup_dpi_firewall_runs_unconditionally_and_ignores_missing_table() {
        use std::cell::RefCell;

        let cleaned = RefCell::new(Vec::<(FirewallKind, String)>::new());
        let res = cleanup_dpi_firewall_with(
            || Ok(()),
            || Ok(FirewallKind::Nftables),
            |kind, table| {
                cleaned.borrow_mut().push((kind, table.to_string()));
                Ok(())
            },
        );
        assert!(res.is_ok());
        assert_eq!(
            *cleaned.borrow(),
            vec![(FirewallKind::Nftables, DEFAULT_FIREWALL_TABLE.to_string())]
        );

        let missing_ignored = cleanup_dpi_firewall_with(
            || Ok(()),
            || Ok(FirewallKind::Nftables),
            |_, _| Err(NetfixError::Runtime("Error: No such file or directory".into())),
        );
        assert!(missing_ignored.is_ok());

        let other_err = cleanup_dpi_firewall_with(
            || Ok(()),
            || Ok(FirewallKind::Nftables),
            |_, _| Err(NetfixError::Runtime("unexpected netlink failure".into())),
        )
        .unwrap_err();
        assert_eq!(other_err.exit_code(), ExitCode::Runtime);
    }

    #[test]
    fn test_missing_engine_returns_exit_code_4() {
        let err = find_engine_binary("definitely-missing-engine-xyz").unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::MissingEngine);
    }

    #[test]
    fn test_find_engine_binary_prefers_libexec_over_path() {
        let dir = tempfile::tempdir().unwrap();
        let libexec = dir.path().join("libexec");
        let path_dir = dir.path().join("bin");
        std::fs::create_dir_all(&libexec).unwrap();
        std::fs::create_dir_all(&path_dir).unwrap();

        let expected_libexec = write_executable_script(&libexec, "nfqws", "#!/bin/sh\nexit 0\n");
        let expected_path = write_executable_script(&path_dir, "nfqws", "#!/bin/sh\nexit 0\n");

        let path_os = OsStr::new(path_dir.to_str().unwrap());
        assert_eq!(
            find_engine_binary_in("nfqws", &libexec, Some(path_os)).unwrap(),
            expected_libexec
        );

        std::fs::remove_file(&expected_libexec).unwrap();
        assert_eq!(
            find_engine_binary_in("nfqws", &libexec, Some(path_os)).unwrap(),
            expected_path
        );
    }

    #[test]
    fn test_resolve_free_port_moves_when_bound() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let busy = listener.local_addr().unwrap().port();
        let free = resolve_free_port("127.0.0.1", busy);
        assert_ne!(free, busy);
        assert_ne!(free, 0);

        drop(listener);
        let available = TcpListener::bind("127.0.0.1:0").unwrap();
        let preferred = available.local_addr().unwrap().port();
        drop(available);
        assert_eq!(resolve_free_port("127.0.0.1", preferred), preferred);
    }

    #[test]
    fn test_build_ciadpi_command_socks5_and_transparent_and_sni() {
        let mut cfg = NetfixConfig::default();
        cfg.dpi.socks_bind = "127.0.0.2".into();

        let socks = build_ciadpi_command(
            &cfg,
            Path::new("/usr/bin/ciadpi"),
            "--ip 0.0.0.0 -p 9999 -n {sni} -o1",
            1080,
            false,
        )
        .unwrap();
        let socks_args: Vec<_> = socks
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            socks_args,
            vec!["--ip", "127.0.0.2", "--port", "1080", "-n", "google.com", "-o1"]
        );

        let trans = build_ciadpi_command(
            &cfg,
            Path::new("/usr/bin/ciadpi"),
            "-i 0.0.0.0 --port=9999 -o1",
            11080,
            true,
        )
        .unwrap();
        let trans_args: Vec<_> = trans
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            trans_args,
            vec!["--ip", "127.0.0.1", "--port", "11080", "--transparent", "-o1"]
        );

        let zero_port = build_ciadpi_command(&cfg, Path::new("/usr/bin/ciadpi"), "-o1", 0, false)
            .unwrap_err();
        assert_eq!(zero_port.exit_code(), ExitCode::InvalidInput);
    }

    #[test]
    fn test_resolve_unprivileged_uid_gid_prefers_netfix_then_nobody_then_65534() {
        let with_netfix = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nnetfix:x:998:997:NetFix:/var/lib/netfix:/usr/sbin/nologin\n";
        assert_eq!(
            resolve_unprivileged_uid_gid_from_passwd(Some(with_netfix)),
            (998, 997)
        );

        let without_netfix = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
        assert_eq!(
            resolve_unprivileged_uid_gid_from_passwd(Some(without_netfix)),
            (65534, 65534)
        );

        assert_eq!(
            resolve_unprivileged_uid_gid_from_passwd(None),
            (65534, 65534)
        );
    }

    #[test]
    fn test_resolve_active_strategy_uses_network_override_then_default() {
        let mut cfg = NetfixConfig::default();
        cfg.dpi.engine = DpiEngineKind::Nfqws;
        cfg.dpi.active_strategy_nfqws = "--dpi-desync=fake".into();
        cfg.dpi.active_strategy_ciadpi = "-o1".into();
        cfg.dpi.network_strategies.insert(
            "home_wi-fi".into(),
            NetworkStrategy {
                nfqws: Some("--dpi-desync=disorder2".into()),
                ciadpi: Some("-s1".into()),
            },
        );

        assert_eq!(resolve_active_strategy(&cfg), "--dpi-desync=fake");

        cfg.general.active_network_override = Some("Home Wi-Fi".into());
        assert_eq!(resolve_active_strategy(&cfg), "--dpi-desync=disorder2");

        cfg.dpi.engine = DpiEngineKind::Ciadpi;
        assert_eq!(resolve_active_strategy(&cfg), "-s1");
    }

    #[tokio::test]
    async fn test_privilege_checks_for_non_root() {
        if is_root() {
            return;
        }

        let mut cfg = NetfixConfig::default();
        cfg.dpi.engine = DpiEngineKind::Nfqws;
        let (_tx, rx) = watch::channel(false);
        assert_eq!(
            run_dpi_service(&cfg, rx.clone())
                .await
                .unwrap_err()
                .exit_code(),
            ExitCode::PermissionDenied
        );
        assert_eq!(
            cleanup_dpi_firewall(&cfg).unwrap_err().exit_code(),
            ExitCode::PermissionDenied
        );

        cfg.dpi.engine = DpiEngineKind::Ciadpi;
        cfg.dpi.ciadpi_mode = CiadpiMode::Transparent;
        assert_eq!(
            run_dpi_service(&cfg, rx.clone())
                .await
                .unwrap_err()
                .exit_code(),
            ExitCode::PermissionDenied
        );
        assert_eq!(
            cleanup_dpi_firewall(&cfg).unwrap_err().exit_code(),
            ExitCode::PermissionDenied
        );

        cfg.dpi.ciadpi_mode = CiadpiMode::Socks5;
        assert_eq!(
            cleanup_dpi_firewall(&cfg).unwrap_err().exit_code(),
            ExitCode::PermissionDenied
        );
        if find_engine_binary("ciadpi").is_err() {
            let err = run_dpi_service(&cfg, rx.clone()).await.unwrap_err();
            assert_eq!(err.exit_code(), ExitCode::MissingEngine);
        }

        cfg.dpi.enabled = false;
        assert_eq!(
            cleanup_dpi_firewall(&cfg).unwrap_err().exit_code(),
            ExitCode::PermissionDenied
        );
        assert!(run_dpi_service(&cfg, rx).await.is_ok());
    }

    #[tokio::test]
    async fn test_runner_unexpected_exit_returns_runtime_error() {
        let dir = tempfile::tempdir().unwrap();
        let fail_script = write_executable_script(
            dir.path(),
            "fail-fast.sh",
            "#!/bin/sh\nexit 42\n",
        );
        let (_tx, rx) = watch::channel(false);
        let runner = DpiRunner::spawn_command(
            DpiEngineKind::Nfqws,
            Command::new(&fail_script),
            None,
            None,
        )
        .unwrap();
        let err = runner.wait_or_shutdown(rx).await.unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::Runtime);
    }

    #[tokio::test]
    async fn test_runner_graceful_sigterm_and_sigkill_fallback() {
        let dir = tempfile::tempdir().unwrap();

        let term_script = write_executable_script(
            dir.path(),
            "term-graceful.sh",
            "#!/bin/sh\ntrap 'exit 0' TERM\nwhile true; do sleep 0.05; done\n",
        );
        let (tx, rx) = watch::channel(false);
        let runner = DpiRunner::spawn_command(
            DpiEngineKind::Ciadpi,
            Command::new(&term_script),
            None,
            None,
        )
        .unwrap();
        let handle = tokio::spawn(runner.wait_or_shutdown(rx));
        tokio::time::sleep(Duration::from_millis(80)).await;
        let start = std::time::Instant::now();
        tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "expected graceful SIGTERM exit well before 2s"
        );

        let ignore_term_script = write_executable_script(
            dir.path(),
            "term-ignored.sh",
            "#!/bin/sh\ntrap '' TERM\nwhile true; do sleep 0.05; done\n",
        );
        let (tx2, rx2) = watch::channel(false);
        let runner2 = DpiRunner::spawn_command(
            DpiEngineKind::Ciadpi,
            Command::new(&ignore_term_script),
            None,
            None,
        )
        .unwrap();
        let handle2 = tokio::spawn(runner2.wait_or_shutdown(rx2));
        tokio::time::sleep(Duration::from_millis(80)).await;
        let start2 = std::time::Instant::now();
        tx2.send(true).unwrap();
        handle2.await.unwrap().unwrap();
        assert!(
            start2.elapsed() >= Duration::from_millis(1900),
            "expected SIGKILL fallback after ~2s SIGTERM timeout"
        );
    }
}
