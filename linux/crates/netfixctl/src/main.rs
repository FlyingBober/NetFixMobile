mod qr;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand, ValueEnum};
use netfix_core::dpi::{find_engine_binary, resolve_strategy_for_config};
use netfix_core::hosts::{
    MANAGED_BEGIN, MANAGED_END, SYSTEM_HOSTS_BACKUP_PATH, SYSTEM_HOSTS_PATH,
};
use netfix_core::network::{
    detect_active_network_key, detect_current_network_info, NetworkInfo,
};
use netfix_core::scanner::ScanPhase;
use netfix_core::setup::{
    chown_secret_to_netfix_if_root, run_setup, run_uninstall, SetupOptions, SetupReport,
    UninstallOptions, UninstallReport,
};
use netfix_core::{
    dns, dpi, hosts, normalize_network_key, scanner, tg, CiadpiMode, DnsMode, DpiEngineKind,
    ExitCode, NetfixConfig, NetfixError,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

const DPI_SERVICE: &str = "netfix-dpi.service";
const TG_SERVICE: &str = "netfix-tgproxy.service";

#[derive(Debug, Parser)]
#[command(name = "netfixctl", about = "NetFix Linux headless control CLI")]
pub struct Cli {
    /// Override config file path (defaults to NETFIX_CONFIG or /etc/netfix/config.toml)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Emit machine-readable JSON output
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceTarget {
    All,
    Dpi,
    Tg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DpiEngineArg {
    Nfqws,
    Ciadpi,
}

impl From<DpiEngineArg> for DpiEngineKind {
    fn from(arg: DpiEngineArg) -> Self {
        match arg {
            DpiEngineArg::Nfqws => Self::Nfqws,
            DpiEngineArg::Ciadpi => Self::Ciadpi,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DnsModeArg {
    System,
    Cloudflare,
    Google,
    Quad9,
    Adguard,
    Custom,
}

impl From<DnsModeArg> for DnsMode {
    fn from(arg: DnsModeArg) -> Self {
        match arg {
            DnsModeArg::System => Self::System,
            DnsModeArg::Cloudflare => Self::Cloudflare,
            DnsModeArg::Google => Self::Google,
            DnsModeArg::Quad9 => Self::Quad9,
            DnsModeArg::Adguard => Self::Adguard,
            DnsModeArg::Custom => Self::Custom,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Provision NetFix directories, config, systemd units, and DPI engines
    Setup {
        #[arg(long, value_name = "DIR")]
        from_local: Option<PathBuf>,
        #[arg(long)]
        skip_download: bool,
    },
    /// Start NetFix systemd service(s)
    Start {
        #[arg(value_enum, default_value_t = ServiceTarget::All)]
        target: ServiceTarget,
    },
    /// Stop NetFix systemd service(s)
    Stop {
        #[arg(value_enum, default_value_t = ServiceTarget::All)]
        target: ServiceTarget,
    },
    /// Restart NetFix systemd service(s)
    Restart {
        #[arg(value_enum, default_value_t = ServiceTarget::All)]
        target: ServiceTarget,
    },
    /// Enable autostart at boot for NetFix systemd service(s)
    Enable {
        #[arg(value_enum, default_value_t = ServiceTarget::All)]
        target: ServiceTarget,
    },
    /// Disable autostart at boot for NetFix systemd service(s)
    Disable {
        #[arg(value_enum, default_value_t = ServiceTarget::All)]
        target: ServiceTarget,
    },
    /// Remove NetFix systemd units and engines (use --purge to also remove config, state, and DNS/hosts changes)
    Uninstall {
        #[arg(long)]
        purge: bool,
    },
    /// Inspect NetFix service and configuration status
    Status {
        #[arg(value_enum, default_value_t = ServiceTarget::All)]
        target: ServiceTarget,
    },
    /// Auto-scan DPI bypass strategies and optionally apply the winner
    Scan {
        #[arg(long, value_enum)]
        engine: Option<DpiEngineArg>,
        #[arg(long)]
        no_discord: bool,
        #[arg(long)]
        ech: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Apply custom DPI strategy arguments to current network profile and start/restart DPI
    Apply {
        #[arg(value_name = "ARGS")]
        args: String,
    },
    /// Probe Telegram DC1-DC5 and Cloudflare proxy domains
    DcCheck,
    /// Manage network-specific strategy profiles and inspect current network
    Network {
        #[command(subcommand)]
        action: Option<NetworkAction>,
    },
    /// Manage system DNS configuration
    Dns {
        #[command(subcommand)]
        action: Option<DnsAction>,
    },
    /// Manage NetFix block in /etc/hosts
    Hosts {
        #[command(subcommand)]
        action: Option<HostsAction>,
    },
    /// Telegram proxy deep link, QR code, and Cloudflare pinning helpers
    Tg {
        #[command(subcommand)]
        action: TgAction,
    },
    /// Internal systemd entrypoint: run DPI service and firewall guard
    DpiRun,
    /// Internal systemd entrypoint: clean up DPI firewall tables/chains
    DpiCleanup,
}

#[derive(Debug, Subcommand)]
pub enum NetworkAction {
    /// Show current detected network, active engine, and resolved strategy
    Current,
    /// List all saved network profiles and strategies
    List,
    /// Switch network profile override ('auto' to restore auto-detection)
    Switch {
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum DnsAction {
    /// Apply a DNS mode (system|cloudflare|google|quad9|adguard|custom [servers...])
    Set {
        #[arg(value_enum)]
        mode: DnsModeArg,
        #[arg(value_name = "SERVER")]
        servers: Vec<String>,
    },
    /// Restore original system DNS configuration
    Reset,
    /// Show current DNS status
    Status,
}

#[derive(Debug, Subcommand)]
pub enum HostsAction {
    /// Apply entries from a hosts file inside the NetFix managed block
    Apply {
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Restore /etc/hosts from backup or strip the NetFix managed block
    Reset,
    /// Show /etc/hosts managed block status
    Status,
}

#[derive(Debug, Subcommand)]
pub enum TgAction {
    /// Print the tg://proxy deep link
    Link,
    /// Print a terminal QR code for the tg://proxy deep link
    Qr,
    /// Pin a Cloudflare proxy domain or reset to 'auto'
    PinCf {
        #[arg(value_name = "DOMAIN_OR_AUTO")]
        domain: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceState {
    Active,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnabledState {
    Enabled,
    Disabled,
    Static,
    Masked,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub unit: String,
    pub active: ServiceState,
    pub enabled: EnabledState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpiStatusSummary {
    pub service: ServiceStatus,
    pub enabled_in_config: bool,
    pub engine: DpiEngineKind,
    pub ciadpi_mode: CiadpiMode,
    pub active_strategy: String,
    pub engine_binary_found: bool,
    pub strategy_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TgStatusSummary {
    pub service: ServiceStatus,
    pub enabled_in_config: bool,
    pub bind_ip: String,
    pub port: u16,
    pub cf_enabled: bool,
    pub pinned_cf_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    pub target: ServiceTarget,
    pub config_path: String,
    pub config_exists: bool,
    pub dpi: Option<DpiStatusSummary>,
    pub tgproxy: Option<TgStatusSummary>,
    pub dns_mode: DnsMode,
    pub network: NetworkInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HostsStatusReport {
    path: String,
    backup_exists: bool,
    managed_block_present: bool,
    entry_count: usize,
    entries: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceActionReport {
    action: &'static str,
    target: ServiceTarget,
    units: Vec<&'static str>,
    ok: bool,
}

#[derive(Debug, Clone, Serialize)]
struct JsonErrorPayload<'a> {
    error: &'a str,
    exit_code: i32,
}

#[tokio::main]
async fn main() {
    let raw_json = raw_args_want_json();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            use clap::error::ErrorKind;
            match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    print!("{err}");
                    std::process::exit(ExitCode::Ok.as_i32());
                }
                _ => {
                    if raw_json {
                        let msg = err.to_string();
                        emit_json_error(msg.trim(), ExitCode::InvalidInput.as_i32());
                    } else {
                        eprint!("{err}");
                    }
                    std::process::exit(ExitCode::InvalidInput.as_i32());
                }
            }
        }
    };

    let json = cli.json;
    if let Err(err) = dispatch(cli).await {
        let code = err.exit_code().as_i32();
        if json {
            emit_json_error(&err.to_string(), code);
        } else {
            eprintln!("netfixctl: {err}");
        }
        std::process::exit(code);
    }
}

fn raw_args_want_json() -> bool {
    std::env::args_os().any(|arg| arg == "--json")
}

fn format_json_error(message: &str, exit_code: i32) -> String {
    let payload = JsonErrorPayload {
        error: message,
        exit_code,
    };
    serde_json::to_string(&payload).unwrap_or_else(|_| {
        format!(r#"{{"error":"serialization failed","exit_code":{exit_code}}}"#)
    })
}

fn emit_json_error(message: &str, exit_code: i32) {
    eprintln!("{}", format_json_error(message, exit_code));
}

async fn dispatch(cli: Cli) -> Result<(), NetfixError> {
    let json = cli.json;
    let config_path = NetfixConfig::resolve_path(cli.config.as_deref());
    let explicit_config = cli.config.is_some();

    match cli.command {
        Commands::Setup {
            from_local,
            skip_download,
        } => {
            let report = run_setup(&SetupOptions {
                from_local,
                skip_download,
                prefix: None,
            })
            .await?;
            print_setup_report(&report, json)?;
        }
        Commands::Start { target } => handle_service_action("start", target, json)?,
        Commands::Stop { target } => handle_service_action("stop", target, json)?,
        Commands::Restart { target } => handle_service_action("restart", target, json)?,
        Commands::Enable { target } => handle_service_action("enable", target, json)?,
        Commands::Disable { target } => handle_service_action("disable", target, json)?,
        Commands::Uninstall { purge } => {
            let report = run_uninstall(&UninstallOptions {
                purge,
                prefix: None,
            })?;
            print_uninstall_report(&report, json)?;
        }
        Commands::Status { target } => {
            let (cfg, exists) = load_config_for_inspection(&config_path, explicit_config)?;
            let report = build_status_report(target, &config_path, exists, &cfg);
            print_status_report(&report, json)?;
        }
        Commands::Scan {
            engine,
            no_discord,
            ech,
            apply,
        } => {
            cmd_scan(
                &config_path,
                explicit_config,
                engine,
                no_discord,
                ech,
                apply,
                json,
            )
            .await?;
        }
        Commands::Apply { args } => {
            if args.trim().is_empty() {
                return Err(NetfixError::InvalidInput("strategy args cannot be empty".into()));
            }
            let (mut cfg, _) = load_config_for_inspection(&config_path, explicit_config)?;
            let engine = cfg.dpi.engine;
            apply_winning_strategy(&mut cfg, engine, &args);
            cfg.save(&config_path)?;
            if is_systemd_unit_active(DPI_SERVICE) {
                run_systemctl(&["restart", DPI_SERVICE])?;
            } else {
                run_systemctl(&["start", DPI_SERVICE])?;
            }
            if json {
                print_json(&serde_json::json!({ "ok": true, "strategy": args }))?;
            } else {
                println!("Applied strategy: {args}");
            }
        }
        Commands::DcCheck => {
            let (cfg, _) = load_config_for_inspection(&config_path, explicit_config)?;
            let report = tg::probe_dc_and_cf(&cfg).await;
            print_dc_check_report(&report, json)?;
        }
        Commands::Network { action } => {
            handle_network(action.unwrap_or(NetworkAction::Current), &config_path, explicit_config, json)?;
        }
        Commands::Dns { action } => {
            handle_dns(action.unwrap_or(DnsAction::Status), &config_path, explicit_config, json)?;
        }
        Commands::Hosts { action } => {
            handle_hosts(action.unwrap_or(HostsAction::Status), json)?;
        }
        Commands::Tg { action } => {
            handle_tg(action, &config_path, explicit_config, json)?;
        }
        Commands::DpiRun => {
            let cfg = NetfixConfig::load(&config_path)?;
            let (tx, rx) = watch::channel(false);
            let signal_task = tokio::spawn(wait_for_shutdown(tx));
            let res = dpi::run_dpi_service(&cfg, rx).await;
            signal_task.abort();
            res?;
        }
        Commands::DpiCleanup => {
            let (cfg, _) = load_config_for_inspection(&config_path, false)?;
            dpi::cleanup_dpi_firewall(&cfg)?;
        }
    }

    Ok(())
}

async fn cmd_scan(
    config_path: &Path,
    explicit_config: bool,
    engine: Option<DpiEngineArg>,
    no_discord: bool,
    ech: bool,
    apply: bool,
    json: bool,
) -> Result<(), NetfixError> {
    let (mut cfg, _) = load_config_for_inspection(config_path, explicit_config)?;
    let chosen_engine = engine.map(Into::into).unwrap_or(cfg.dpi.engine);

    let (tx, rx) = watch::channel(false);
    let signal_task = tokio::spawn(wait_for_shutdown(tx));

    let was_active = is_systemd_unit_active(DPI_SERVICE);
    if was_active {
        if let Err(err) = run_systemctl(&["stop", DPI_SERVICE]) {
            signal_task.abort();
            return Err(err);
        }
    }

    let scan_res = scanner::scan_strategies_cancellable(
        &cfg,
        chosen_engine,
        !no_discord,
        ech,
        rx,
        |progress| {
            if !json {
                let phase_label = match progress.phase {
                    ScanPhase::Quick => "quick",
                    ScanPhase::Final => "final",
                };
                eprintln!(
                    "[{phase_label} {}/{}] {} -> {}/{} sites{}",
                    progress.index + 1,
                    progress.total.max(1),
                    progress.strategy_name,
                    progress.passed,
                    progress.site_total,
                    progress
                        .score
                        .map(|s| format!(" (score {s:.1})"))
                        .unwrap_or_default()
                );
            }
        },
    )
    .await;
    signal_task.abort();

    let report = finish_scan_and_restart(
        scan_res,
        was_active,
        apply,
        chosen_engine,
        &mut cfg,
        |updated| updated.save(config_path),
        || run_systemctl(&["start", DPI_SERVICE]),
    )?;

    print_scan_report(&report, apply, json)?;
    Ok(())
}

fn finish_scan_and_restart<S, R>(
    scan_res: Result<scanner::ScanReport, NetfixError>,
    was_active: bool,
    apply: bool,
    chosen_engine: DpiEngineKind,
    cfg: &mut NetfixConfig,
    mut save_cfg: S,
    mut start_service: R,
) -> Result<scanner::ScanReport, NetfixError>
where
    S: FnMut(&NetfixConfig) -> Result<(), NetfixError>,
    R: FnMut() -> Result<(), NetfixError>,
{
    let mut outcome = scan_res;
    if let Ok(ref report) = outcome {
        if apply {
            if let Some(ref winner) = report.winner {
                apply_winning_strategy(cfg, chosen_engine, &winner.args);
                if let Err(err) = save_cfg(cfg) {
                    outcome = Err(err);
                }
            }
        }
    }

    let restart_res = if was_active {
        start_service()
    } else {
        Ok(())
    };

    match outcome {
        Ok(report) => {
            restart_res?;
            Ok(report)
        }
        Err(err) => {
            let _ = restart_res;
            Err(err)
        }
    }
}

fn load_config_for_inspection(
    path: &Path,
    explicit_config: bool,
) -> Result<(NetfixConfig, bool), NetfixError> {
    match std::fs::metadata(path) {
        Ok(_) => Ok((NetfixConfig::load(path)?, true)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if explicit_config {
                Err(NetfixError::Io(err))
            } else {
                Ok((NetfixConfig::default(), false))
            }
        }
        Err(err) => Err(NetfixError::Io(err)),
    }
}

fn units_for_target(target: ServiceTarget) -> Vec<&'static str> {
    match target {
        ServiceTarget::All => vec![DPI_SERVICE, TG_SERVICE],
        ServiceTarget::Dpi => vec![DPI_SERVICE],
        ServiceTarget::Tg => vec![TG_SERVICE],
    }
}

fn handle_service_action(
    action: &'static str,
    target: ServiceTarget,
    json: bool,
) -> Result<(), NetfixError> {
    let units = units_for_target(target);
    let mut args = Vec::with_capacity(units.len() + 1);
    args.push(action);
    args.extend(units.iter().copied());
    run_systemctl(&args)?;

    if json {
        let payload = ServiceActionReport {
            action,
            target,
            units,
            ok: true,
        };
        print_json(&payload)?;
    } else {
        println!("{action}: {}", units.join(", "));
    }
    Ok(())
}

fn run_systemctl(args: &[&str]) -> Result<(), NetfixError> {
    let output = Command::new("systemctl").args(args).output().map_err(|err| {
        NetfixError::Runtime(format!("failed to execute systemctl {}: {err}", args.join(" ")))
    })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("permission denied")
        || lower.contains("access denied")
        || lower.contains("interactive authentication required")
    {
        return Err(NetfixError::PermissionDenied(stderr.trim().to_string()));
    }
    Err(NetfixError::Runtime(format!(
        "systemctl {} failed: {}",
        args.join(" "),
        if stderr.trim().is_empty() {
            format!("exit code {:?}", output.status.code())
        } else {
            stderr.trim().to_string()
        }
    )))
}

fn is_systemd_unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn query_systemd_unit(unit: &str) -> ServiceStatus {
    let active = match Command::new("systemctl").args(["is-active", unit]).output() {
        Ok(out) => parse_service_state(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => ServiceState::Unknown,
    };
    let enabled = match Command::new("systemctl").args(["is-enabled", unit]).output() {
        Ok(out) => parse_enabled_state(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => EnabledState::Unknown,
    };
    ServiceStatus {
        unit: unit.to_string(),
        active,
        enabled,
    }
}

fn parse_service_state(raw: &str) -> ServiceState {
    match raw.trim() {
        "active" => ServiceState::Active,
        "inactive" => ServiceState::Inactive,
        "failed" => ServiceState::Failed,
        "activating" => ServiceState::Activating,
        "deactivating" => ServiceState::Deactivating,
        _ => ServiceState::Unknown,
    }
}

fn parse_enabled_state(raw: &str) -> EnabledState {
    match raw.trim() {
        "enabled" | "enabled-runtime" => EnabledState::Enabled,
        "disabled" => EnabledState::Disabled,
        "static" => EnabledState::Static,
        "masked" | "masked-runtime" => EnabledState::Masked,
        _ => EnabledState::Unknown,
    }
}

fn build_status_report(
    target: ServiceTarget,
    config_path: &Path,
    config_exists: bool,
    cfg: &NetfixConfig,
) -> StatusReport {
    build_status_report_with_querier(target, config_path, config_exists, cfg, query_systemd_unit)
}

fn build_status_report_with_querier(
    target: ServiceTarget,
    config_path: &Path,
    config_exists: bool,
    cfg: &NetfixConfig,
    mut query: impl FnMut(&str) -> ServiceStatus,
) -> StatusReport {
    let (active_strategy, strategy_key, is_custom) = resolve_strategy_for_config(cfg);
    let dpi = matches!(target, ServiceTarget::All | ServiceTarget::Dpi).then(|| {
        let bin_name = match cfg.dpi.engine {
            DpiEngineKind::Nfqws => "nfqws",
            DpiEngineKind::Ciadpi => "ciadpi",
        };
        DpiStatusSummary {
            service: query(DPI_SERVICE),
            enabled_in_config: cfg.dpi.enabled,
            engine: cfg.dpi.engine,
            ciadpi_mode: cfg.dpi.ciadpi_mode,
            active_strategy: active_strategy.to_string(),
            engine_binary_found: find_engine_binary(bin_name).is_ok(),
            strategy_source: if is_custom {
                format!("profile '{strategy_key}'")
            } else {
                "default".to_string()
            },
        }
    });

    let tgproxy = matches!(target, ServiceTarget::All | ServiceTarget::Tg).then(|| TgStatusSummary {
        service: query(TG_SERVICE),
        enabled_in_config: cfg.tgproxy.enabled,
        bind_ip: cfg.tgproxy.bind_ip.clone(),
        port: cfg.tgproxy.port,
        cf_enabled: cfg.tgproxy.cf_enabled,
        pinned_cf_domain: cfg.tgproxy.pinned_cf_domain.clone(),
    });

    let network = detect_current_network_info(cfg);

    StatusReport {
        target,
        config_path: config_path.display().to_string(),
        config_exists,
        dpi,
        tgproxy,
        dns_mode: cfg.dns.mode,
        network,
    }
}

fn apply_winning_strategy(cfg: &mut NetfixConfig, engine: DpiEngineKind, strategy: &str) {
    cfg.dpi.engine = engine;
    match engine {
        DpiEngineKind::Nfqws => cfg.dpi.active_strategy_nfqws = strategy.to_string(),
        DpiEngineKind::Ciadpi => cfg.dpi.active_strategy_ciadpi = strategy.to_string(),
    }

    let net_key = detect_active_network_key(cfg);
    let entry = cfg.dpi.network_strategies.entry(net_key).or_default();
    match engine {
        DpiEngineKind::Nfqws => entry.nfqws = Some(strategy.to_string()),
        DpiEngineKind::Ciadpi => entry.ciadpi = Some(strategy.to_string()),
    }
}

fn handle_network(
    action: NetworkAction,
    config_path: &Path,
    explicit_config: bool,
    json: bool,
) -> Result<(), NetfixError> {
    let (mut cfg, _) = load_config_for_inspection(config_path, explicit_config)?;
    match action {
        NetworkAction::Current => {
            let info = detect_current_network_info(&cfg);
            let (strat, key, is_custom) = resolve_strategy_for_config(&cfg);
            if json {
                print_json(&serde_json::json!({
                    "network": info,
                    "engine": cfg.dpi.engine,
                    "active_strategy": strat,
                    "strategy_source": if is_custom { "network_profile" } else { "default" },
                    "strategy_profile": key,
                }))?;
            } else {
                println!("Current network key: {}", info.key);
                if let Some(ref ssid) = info.ssid {
                    println!("Wi-Fi SSID: {ssid}");
                }
                if let Some(ref conn) = info.connection_name {
                    println!("Connection: {conn}");
                }
                if let Some(ref iface) = info.interface {
                    println!("Interface: {iface}");
                }
                println!(
                    "Profile mode: {}",
                    if info.is_override {
                        "override"
                    } else {
                        "auto-detected"
                    }
                );
                println!("Engine: {:?}", cfg.dpi.engine);
                println!(
                    "Active strategy: {strat} ({})",
                    if is_custom {
                        format!("profile '{key}'")
                    } else {
                        "default fallback".to_string()
                    }
                );
            }
        }
        NetworkAction::List => {
            let info = detect_current_network_info(&cfg);
            if json {
                print_json(&serde_json::json!({
                    "current_network": info.key,
                    "profiles": cfg.dpi.network_strategies,
                }))?;
            } else {
                println!("Saved network profiles in {}:", config_path.display());
                if cfg.dpi.network_strategies.is_empty() {
                    println!("  (no custom network profiles saved yet; run 'netfixctl scan --apply' to save one)");
                } else {
                    for (k, v) in &cfg.dpi.network_strategies {
                        let is_cur = if k == &info.key { " [active]" } else { "" };
                        println!("- {k}{is_cur}:");
                        if let Some(ref s) = v.nfqws {
                            println!("    nfqws:  {s}");
                        }
                        if let Some(ref s) = v.ciadpi {
                            println!("    ciadpi: {s}");
                        }
                    }
                }
            }
        }
        NetworkAction::Switch { profile } => {
            let trimmed = profile.trim();
            if trimmed == "auto" {
                cfg.general.active_network_override = None;
                cfg.save(config_path)?;
                println!("Reset active network profile override to auto-detection.");
            } else {
                let norm = normalize_network_key(trimmed);
                cfg.general.active_network_override = Some(norm.clone());
                cfg.save(config_path)?;
                println!("Switched active network profile override to '{norm}'.");
            }
            if is_systemd_unit_active(DPI_SERVICE) {
                println!("Restarting netfix-dpi.service to apply new network strategy...");
                let _ = Command::new("systemctl")
                    .args(["restart", DPI_SERVICE])
                    .status();
            }
        }
    }
    Ok(())
}

fn handle_dns(
    action: DnsAction,
    config_path: &Path,
    explicit_config: bool,
    json: bool,
) -> Result<(), NetfixError> {
    let (mut cfg, _) = load_config_for_inspection(config_path, explicit_config)?;
    match action {
        DnsAction::Status => {
            let status = dns::dns_status(&cfg)?;
            print_dns_status(&status, json)?;
        }
        DnsAction::Set { mode, servers } => {
            let dns_mode: DnsMode = mode.into();
            if dns_mode != DnsMode::Custom && !servers.is_empty() {
                return Err(NetfixError::InvalidInput(
                    "custom server arguments are only valid with 'custom' DNS mode".into(),
                ));
            }
            let _ = dns::servers_for_mode(dns_mode, &servers)?;
            cfg.dns.mode = dns_mode;
            cfg.dns.custom_servers = if dns_mode == DnsMode::Custom {
                servers
            } else {
                Vec::new()
            };
            dns::apply_dns(&cfg)?;
            cfg.save(config_path)?;
            let status = dns::dns_status(&cfg)?;
            print_dns_status(&status, json)?;
        }
        DnsAction::Reset => {
            dns::reset_dns()?;
            if config_path.exists() {
                cfg.dns.mode = DnsMode::System;
                cfg.dns.custom_servers.clear();
                cfg.save(config_path)?;
            }
            let status = dns::dns_status(&cfg)?;
            print_dns_status(&status, json)?;
        }
    }
    Ok(())
}

fn handle_hosts(action: HostsAction, json: bool) -> Result<(), NetfixError> {
    match action {
        HostsAction::Apply { file } => {
            let raw = std::fs::read_to_string(&file)?;
            let entries: Vec<String> = raw
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect();
            hosts::apply_system_hosts(&entries)?;
        }
        HostsAction::Reset => {
            hosts::reset_system_hosts()?;
        }
        HostsAction::Status => {}
    }

    let report = read_hosts_status(Path::new(SYSTEM_HOSTS_PATH), Path::new(SYSTEM_HOSTS_BACKUP_PATH))?;
    print_hosts_status(&report, json)
}

fn read_hosts_status(
    hosts_path: &Path,
    backup_path: &Path,
) -> Result<HostsStatusReport, NetfixError> {
    let content = match std::fs::read_to_string(hosts_path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err.into()),
    };

    let _ = hosts::strip_managed_block(&content)?;

    let mut in_block = false;
    let mut found = false;
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == MANAGED_BEGIN {
            in_block = true;
            found = true;
            continue;
        }
        if trimmed == MANAGED_END {
            in_block = false;
            continue;
        }
        if in_block {
            entries.push(line.to_string());
        }
    }

    Ok(HostsStatusReport {
        path: hosts_path.display().to_string(),
        backup_exists: backup_path.exists(),
        managed_block_present: found,
        entry_count: entries.len(),
        entries,
    })
}

fn handle_tg(
    action: TgAction,
    config_path: &Path,
    explicit_config: bool,
    json: bool,
) -> Result<(), NetfixError> {
    let (mut cfg, _) = load_config_for_inspection(config_path, explicit_config)?;
    match action {
        TgAction::Link => {
            let (url, server, port, secret) =
                build_tg_link(&cfg, Path::new(tg::DEFAULT_TGPROXY_STATE_DIR))?;
            if json {
                print_json(&serde_json::json!({
                    "url": url,
                    "server": server,
                    "port": port,
                    "secret": secret,
                }))?;
            } else {
                println!("{url}");
            }
        }
        TgAction::Qr => {
            let (url, _, _, _) = build_tg_link(&cfg, Path::new(tg::DEFAULT_TGPROXY_STATE_DIR))?;
            let qr_art = qr::render_qr_utf8(&url).map_err(NetfixError::Runtime)?;
            if json {
                print_json(&serde_json::json!({
                    "url": url,
                    "qr": qr_art,
                }))?;
            } else {
                print!("{qr_art}");
                println!("{url}");
            }
        }
        TgAction::PinCf { domain } => {
            let normalized = parse_pin_cf_domain(&domain)?;
            cfg.tgproxy.pinned_cf_domain = normalized.clone();
            cfg.save(config_path)?;
            if json {
                print_json(&serde_json::json!({
                    "pinned_cf_domain": normalized,
                }))?;
            } else if normalized.is_empty() {
                println!("Cloudflare domain pinning reset to auto");
            } else {
                println!("Pinned Cloudflare domain: {normalized}");
            }
        }
    }
    Ok(())
}

fn build_tg_link(
    cfg: &NetfixConfig,
    state_dir: &Path,
) -> Result<(String, String, u16, String), NetfixError> {
    let secret = tg::resolve_or_persist_secret(cfg, state_dir)?;
    if cfg.tgproxy.secret.trim().is_empty() {
        chown_secret_to_netfix_if_root(&state_dir.join("secret"))?;
    }
    let server = match cfg.tgproxy.bind_ip.parse::<IpAddr>() {
        Ok(ip) if ip.is_unspecified() => "127.0.0.1".to_string(),
        _ => cfg.tgproxy.bind_ip.clone(),
    };
    let url = tg::build_tg_proxy_url(&server, cfg.tgproxy.port, &secret);
    Ok((url, server, cfg.tgproxy.port, secret))
}

fn parse_pin_cf_domain(raw: &str) -> Result<String, NetfixError> {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("auto") {
        return Ok(String::new());
    }
    if trimmed.is_empty()
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
        || trimmed.contains('/')
        || trimmed.contains(':')
    {
        return Err(NetfixError::InvalidInput(format!(
            "invalid Cloudflare domain '{raw}' (expected hostname or 'auto')"
        )));
    }
    Ok(trimmed.trim_end_matches('.').to_ascii_lowercase())
}

async fn wait_for_shutdown(tx: watch::Sender<bool>) {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match sigterm.as_mut() {
                Some(s) => {
                    let _ = s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        } => {}
    }
    let _ = tx.send(true);
}

fn print_json<T: Serialize>(value: &T) -> Result<(), NetfixError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| NetfixError::Runtime(format!("JSON serialization failed: {e}")))?;
    println!("{text}");
    Ok(())
}

fn print_setup_report(report: &SetupReport, json: bool) -> Result<(), NetfixError> {
    if json {
        return print_json(report);
    }
    println!(
        "Config: {} ({})",
        report.config_path.display(),
        if report.config_created {
            "created"
        } else {
            "existing"
        }
    );
    println!("Units installed: {}", report.units_installed.len());
    println!(
        "nfqws: {}",
        report
            .nfqws_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "missing".into())
    );
    println!(
        "ciadpi: {}",
        report
            .ciadpi_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "missing".into())
    );
    println!(
        "systemd daemon-reload: {}",
        if report.daemon_reloaded { "ok" } else { "skipped" }
    );
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

fn print_uninstall_report(report: &UninstallReport, json: bool) -> Result<(), NetfixError> {
    if json {
        return print_json(report);
    }
    println!("Units removed: {}", report.units_removed.len());
    println!("Engines removed: {}", report.engines_removed.len());
    println!("Config removed: {}", report.config_removed);
    println!("State removed: {}", report.state_removed);
    if report.dns_reset {
        println!("DNS reset: ok");
    }
    if report.hosts_reset {
        println!("Hosts reset: ok");
    }
    println!(
        "systemd daemon-reload: {}",
        if report.daemon_reloaded { "ok" } else { "skipped" }
    );
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

fn print_status_report(report: &StatusReport, json: bool) -> Result<(), NetfixError> {
    if json {
        return print_json(report);
    }
    println!(
        "Config: {} ({})",
        report.config_path,
        if report.config_exists {
            "present"
        } else {
            "default (not yet created)"
        }
    );
    println!(
        "Network profile: {} ({})",
        report.network.key,
        if report.network.is_override {
            "override"
        } else {
            "auto-detected"
        }
    );
    if let Some(ref dpi) = report.dpi {
        println!(
            "DPI ({}): active={:?}, enabled={:?}, engine={:?}, mode={:?}, binary={}, strategy={} [{}]",
            dpi.service.unit,
            dpi.service.active,
            dpi.service.enabled,
            dpi.engine,
            dpi.ciadpi_mode,
            if dpi.engine_binary_found {
                "found"
            } else {
                "missing"
            },
            dpi.active_strategy,
            dpi.strategy_source
        );
    }
    if let Some(ref tgproxy) = report.tgproxy {
        println!(
            "TG Proxy ({}): active={:?}, enabled={:?}, listen={}:{}, cf={}, pinned={}",
            tgproxy.service.unit,
            tgproxy.service.active,
            tgproxy.service.enabled,
            tgproxy.bind_ip,
            tgproxy.port,
            tgproxy.cf_enabled,
            if tgproxy.pinned_cf_domain.is_empty() {
                "auto"
            } else {
                &tgproxy.pinned_cf_domain
            }
        );
    }
    println!("DNS mode: {:?}", report.dns_mode);
    Ok(())
}

fn print_scan_report(
    report: &scanner::ScanReport,
    applied: bool,
    json: bool,
) -> Result<(), NetfixError> {
    if json {
        return print_json(report);
    }
    println!(
        "Scan complete ({:?}): tested {} strategies, {} finalists",
        report.engine,
        report.entries.len(),
        report.finalist_count
    );
    match &report.winner {
        Some(winner) => {
            println!(
                "Winner: {} (score={:.1}, full={}/{}) {}",
                winner.name,
                winner.score,
                winner.full_passed.unwrap_or(0),
                winner.full_total.unwrap_or(0),
                if applied { "[applied]" } else { "" }
            );
            println!("Args: {}", winner.args);
        }
        None => println!("No working strategy found."),
    }
    Ok(())
}

fn print_dc_check_report(report: &tg::DcCheckReport, json: bool) -> Result<(), NetfixError> {
    if json {
        return print_json(report);
    }
    println!("Telegram DC probes:");
    for dc in &report.dc_results {
        println!(
            "  DC{} ({}): reachable={}, tcp={}, wss={}, latency={} ({})",
            dc.dc,
            dc.ip,
            dc.reachable,
            dc.tcp_ok,
            dc.wss_ok,
            dc.latency_ms
                .map(|m| format!("{m}ms"))
                .unwrap_or_else(|| "-".into()),
            dc.detail
        );
    }
    println!("Cloudflare proxy domains:");
    for cf in &report.cf_results {
        println!(
            "  {:<30} {:?}  {} ({})",
            cf.domain,
            cf.state,
            cf.latency_ms
                .map(|m| format!("{m}ms"))
                .unwrap_or_else(|| "-".into()),
            cf.detail
        );
    }
    Ok(())
}

fn print_dns_status(status: &dns::DnsStatus, json: bool) -> Result<(), NetfixError> {
    if json {
        return print_json(status);
    }
    println!("DNS backend: {:?}", status.backend);
    println!("DNS mode: {:?}", status.mode);
    println!(
        "Configured servers: {}",
        if status.configured_servers.is_empty() {
            "system".into()
        } else {
            status.configured_servers.join(", ")
        }
    );
    println!(
        "Active /etc/resolv.conf servers: {}",
        if status.active_servers.is_empty() {
            "none".into()
        } else {
            status.active_servers.join(", ")
        }
    );
    println!(
        "Drop-in exists: {}, Backup exists: {}",
        status.dropin_exists, status.backup_exists
    );
    Ok(())
}

fn print_hosts_status(status: &HostsStatusReport, json: bool) -> Result<(), NetfixError> {
    if json {
        return print_json(status);
    }
    println!(
        "Hosts file: {} (managed_block={}, entries={}, backup={})",
        status.path, status.managed_block_present, status.entry_count, status.backup_exists
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parses_status_json_and_scan_flags() {
        let cli = Cli::try_parse_from(["netfixctl", "--json", "status", "dpi"]).unwrap();
        assert!(cli.json);
        assert!(matches!(
            cli.command,
            Commands::Status {
                target: ServiceTarget::Dpi
            }
        ));

        let scan_cli = Cli::try_parse_from([
            "netfixctl",
            "scan",
            "--engine",
            "ciadpi",
            "--no-discord",
            "--ech",
            "--apply",
            "--json",
        ])
        .unwrap();
        assert!(scan_cli.json);
        assert!(matches!(
            scan_cli.command,
            Commands::Scan {
                engine: Some(DpiEngineArg::Ciadpi),
                no_discord: true,
                ech: true,
                apply: true,
            }
        ));
    }

    #[test]
    fn test_cli_parses_setup_dns_hosts_tg_and_internal_commands() {
        let setup = Cli::try_parse_from([
            "netfixctl",
            "setup",
            "--from-local",
            "/opt/bins",
            "--skip-download",
        ])
        .unwrap();
        assert!(matches!(
            setup.command,
            Commands::Setup {
                from_local: Some(_),
                skip_download: true
            }
        ));

        let dns_set =
            Cli::try_parse_from(["netfixctl", "dns", "set", "custom", "1.1.1.1", "8.8.8.8"])
                .unwrap();
        assert!(matches!(
            dns_set.command,
            Commands::Dns {
                action: Some(DnsAction::Set {
                    mode: DnsModeArg::Custom,
                    ..
                })
            }
        ));

        let hosts_apply =
            Cli::try_parse_from(["netfixctl", "hosts", "apply", "/tmp/hosts.txt"]).unwrap();
        assert!(matches!(
            hosts_apply.command,
            Commands::Hosts {
                action: Some(HostsAction::Apply { .. })
            }
        ));

        let tg_pin = Cli::try_parse_from(["netfixctl", "tg", "pin-cf", "auto"]).unwrap();
        assert!(matches!(
            tg_pin.command,
            Commands::Tg {
                action: TgAction::PinCf { .. }
            }
        ));

        assert!(matches!(
            Cli::try_parse_from(["netfixctl", "dpi-run"]).unwrap().command,
            Commands::DpiRun
        ));
        assert!(matches!(
            Cli::try_parse_from(["netfixctl", "dpi-cleanup"])
                .unwrap()
                .command,
            Commands::DpiCleanup
        ));
        assert!(matches!(
            Cli::try_parse_from(["netfixctl", "enable", "tg"])
                .unwrap()
                .command,
            Commands::Enable {
                target: ServiceTarget::Tg
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["netfixctl", "disable"])
                .unwrap()
                .command,
            Commands::Disable {
                target: ServiceTarget::All
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["netfixctl", "uninstall", "--purge"])
                .unwrap()
                .command,
            Commands::Uninstall { purge: true }
        ));
        assert!(matches!(
            Cli::try_parse_from(["netfixctl", "network", "current"])
                .unwrap()
                .command,
            Commands::Network {
                action: Some(NetworkAction::Current)
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["netfixctl", "network", "list"])
                .unwrap()
                .command,
            Commands::Network {
                action: Some(NetworkAction::List)
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["netfixctl", "network", "switch", "home_wifi"])
                .unwrap()
                .command,
            Commands::Network {
                action: Some(NetworkAction::Switch { .. })
            }
        ));
    }

    #[test]
    fn test_status_report_serializes_cleanly_without_systemctl() {
        let mut cfg = NetfixConfig::default();
        cfg.dpi.engine = DpiEngineKind::Ciadpi;
        cfg.tgproxy.port = 2443;
        cfg.dns.mode = DnsMode::Cloudflare;

        let report = build_status_report_with_querier(
            ServiceTarget::All,
            Path::new("/tmp/config.toml"),
            true,
            &cfg,
            |unit| ServiceStatus {
                unit: unit.to_string(),
                active: ServiceState::Unknown,
                enabled: EnabledState::Unknown,
            },
        );

        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(json["target"], "all");
        assert_eq!(json["config_exists"], true);
        assert_eq!(json["dns_mode"], "cloudflare");
        assert_eq!(json["dpi"]["service"]["active"], "unknown");
        assert_eq!(json["dpi"]["engine"], "ciadpi");
        assert_eq!(json["tgproxy"]["port"], 2443);
        assert!(json["network"]["key"].is_string());

        // Also ensure real query_systemd_unit does not panic even when systemctl is absent/inactive.
        let real = query_systemd_unit("netfix-nonexistent.service");
        assert_eq!(real.unit, "netfix-nonexistent.service");
    }

    #[test]
    fn test_json_error_payload_and_exit_code_mapping() {
        let payload: serde_json::Value =
            serde_json::from_str(&format_json_error("missing engine", 4)).unwrap();
        assert_eq!(payload["error"], "missing engine");
        assert_eq!(payload["exit_code"], 4);

        assert_eq!(
            NetfixError::InvalidInput("bad".into()).exit_code().as_i32(),
            2
        );
        assert_eq!(
            NetfixError::PermissionDenied("root".into())
                .exit_code()
                .as_i32(),
            3
        );
        assert_eq!(
            NetfixError::MissingEngine("nfqws".into())
                .exit_code()
                .as_i32(),
            4
        );
        assert_eq!(NetfixError::Runtime("net".into()).exit_code().as_i32(), 1);
    }

    #[test]
    fn test_tg_link_reuses_persisted_secret_from_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.secret.clear();
        cfg.tgproxy.bind_ip = "0.0.0.0".into();
        cfg.tgproxy.port = 1443;

        let (url1, server1, port1, sec1) = build_tg_link(&cfg, dir.path()).unwrap();
        let (url2, _, _, sec2) = build_tg_link(&cfg, dir.path()).unwrap();
        assert_eq!(server1, "127.0.0.1");
        assert_eq!(port1, 1443);
        assert_eq!(sec1, sec2);
        assert_eq!(url1, url2);
        assert_eq!(url1, format!("tg://proxy?server=127.0.0.1&port=1443&secret=dd{sec1}"));
    }

    #[test]
    fn test_pin_cf_domain_validation_and_apply_winning_strategy() {
        assert_eq!(parse_pin_cf_domain("auto").unwrap(), "");
        assert_eq!(
            parse_pin_cf_domain("Example.Workers.Dev.").unwrap(),
            "example.workers.dev"
        );
        assert_eq!(
            parse_pin_cf_domain("https://bad.dev").unwrap_err().exit_code(),
            ExitCode::InvalidInput
        );

        let mut cfg = NetfixConfig::default();
        cfg.general.active_network_override = Some("Office Wi-Fi".into());
        apply_winning_strategy(&mut cfg, DpiEngineKind::Nfqws, "--dpi-desync=disorder2");
        assert_eq!(cfg.dpi.active_strategy_nfqws, "--dpi-desync=disorder2");
        assert_eq!(
            cfg.dpi.network_strategies["office_wi-fi"].nfqws.as_deref(),
            Some("--dpi-desync=disorder2")
        );
    }

    #[test]
    fn test_read_hosts_status_counts_managed_entries() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_file = dir.path().join("hosts");
        let backup_file = dir.path().join("hosts.bak");
        std::fs::write(
            &hosts_file,
            "127.0.0.1 localhost\n# BEGIN NETFIX MANAGED\n1.2.3.4 a.test\n5.6.7.8 b.test\n# END NETFIX MANAGED\n",
        )
        .unwrap();
        std::fs::write(&backup_file, "127.0.0.1 localhost\n").unwrap();

        let status = read_hosts_status(&hosts_file, &backup_file).unwrap();
        assert!(status.backup_exists);
        assert!(status.managed_block_present);
        assert_eq!(status.entry_count, 2);
    }

    #[test]
    fn test_load_config_for_inspection_propagates_permission_denied() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() == 0 } {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        let cfg_path = locked.join("config.toml");
        std::fs::write(&cfg_path, "").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = load_config_for_inspection(&cfg_path, false).unwrap_err();
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));
        assert_eq!(err.exit_code(), ExitCode::PermissionDenied);
    }

    #[test]
    fn test_route_interface_parsers_and_network_key_fallback() {
        use netfix_core::network::{parse_ip_route_get_dev, parse_proc_net_route_default_iface};
        assert_eq!(
            parse_ip_route_get_dev("1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.42 uid 1000"),
            Some("wlan0".to_string())
        );
        assert_eq!(parse_ip_route_get_dev("RTNETLINK answers: Network is unreachable"), None);

        let proc_route = "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\neth0\t0001A8C0\t00000000\t0001\n";
        assert_eq!(
            parse_proc_net_route_default_iface(proc_route),
            Some("eth0".to_string())
        );
        assert_eq!(
            parse_proc_net_route_default_iface("Iface\tDestination\neth0\t0001A8C0\n"),
            None
        );
        assert_eq!(
            parse_proc_net_route_default_iface(
                "Iface\tDestination\tGateway\n\nshort\nwlan0\t00000000\t0101A8C0\n"
            ),
            Some("wlan0".to_string())
        );

        let mut cfg = NetfixConfig::default();
        cfg.general.active_network_override = Some("   ".into());
        let key = detect_active_network_key(&cfg);
        assert!(!key.is_empty());
    }

    #[test]
    fn test_finish_scan_and_restart_always_restarts_service_on_cancel_or_save_error() {
        let sample_report = || scanner::ScanReport {
            engine: DpiEngineKind::Nfqws,
            include_discord: true,
            include_ech: false,
            quick_total: 1,
            full_total: 1,
            finalist_count: 1,
            winner: Some(scanner::StrategyScanEntry {
                name: "win".into(),
                category: "general".into(),
                args: "--dpi-desync=fake".into(),
                quick_passed: 1,
                quick_total: 1,
                full_passed: Some(1),
                full_total: Some(1),
                stream: None,
                score: 100.0,
            }),
            entries: vec![],
        };

        // 1. Save error when was_active == true must still restart service and return save error.
        let mut cfg = NetfixConfig::default();
        let mut restarted = false;
        let err = finish_scan_and_restart(
            Ok(sample_report()),
            true,
            true,
            DpiEngineKind::Nfqws,
            &mut cfg,
            |_| Err(NetfixError::PermissionDenied("read-only etc".into())),
            || {
                restarted = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(restarted, "service must restart even if cfg.save fails");
        assert_eq!(err.exit_code(), ExitCode::PermissionDenied);

        // 2. Cancelled scan when was_active == true must still restart service and return scan error.
        let mut cfg2 = NetfixConfig::default();
        let mut restarted2 = false;
        let err2 = finish_scan_and_restart(
            Err(NetfixError::Runtime("scan cancelled by signal".into())),
            true,
            true,
            DpiEngineKind::Nfqws,
            &mut cfg2,
            |_| unreachable!("save must not be called when scan failed"),
            || {
                restarted2 = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(restarted2, "service must restart even if scan is cancelled");
        assert_eq!(err2.exit_code(), ExitCode::Runtime);

        // 3. When was_active == false, service must NOT be started.
        let mut cfg3 = NetfixConfig::default();
        let mut restarted3 = false;
        let ok = finish_scan_and_restart(
            Ok(sample_report()),
            false,
            true,
            DpiEngineKind::Nfqws,
            &mut cfg3,
            |_| Ok(()),
            || {
                restarted3 = true;
                Ok(())
            },
        );
        assert!(ok.is_ok());
        assert!(!restarted3);
    }
}
