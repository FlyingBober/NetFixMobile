use std::fmt::Write as _;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{CiadpiMode, DpiEngineKind, IpsetMode, NetfixConfig, NetfixError};

const MAX_NFT_TABLE_LEN: usize = 64;
const MAX_IPTABLES_CHAIN_LEN: usize = 28;
const FALLBACK_BIN_DIRS: &[&str] = &[
    "/usr/sbin",
    "/sbin",
    "/usr/bin",
    "/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallKind {
    Nftables,
    Iptables,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallMode {
    Nfqws,
    CiadpiTransparent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallSpec {
    pub table_name: String,
    pub mode: FirewallMode,
    pub nfqueue_num: u16,
    pub fwmark: u32,
    pub game_filter: bool,
    pub ipset_mode: IpsetMode,
    pub ipset_v4: Vec<String>,
    pub ipset_v6: Vec<String>,
    pub transparent_port: u16,
    pub excluded_uid: Option<u32>,
}

impl FirewallSpec {
    pub fn for_nfqws(
        table_name: impl Into<String>,
        nfqueue_num: u16,
        fwmark: u32,
        game_filter: bool,
        ipset_mode: IpsetMode,
        ipset_v4: Vec<String>,
        ipset_v6: Vec<String>,
    ) -> Self {
        Self {
            table_name: table_name.into(),
            mode: FirewallMode::Nfqws,
            nfqueue_num,
            fwmark,
            game_filter,
            ipset_mode,
            ipset_v4,
            ipset_v6,
            transparent_port: 0,
            excluded_uid: None,
        }
    }

    pub fn for_ciadpi_transparent(
        table_name: impl Into<String>,
        transparent_port: u16,
        excluded_uid: u32,
    ) -> Self {
        Self {
            table_name: table_name.into(),
            mode: FirewallMode::CiadpiTransparent,
            nfqueue_num: 0,
            fwmark: 0,
            game_filter: false,
            ipset_mode: IpsetMode::Any,
            ipset_v4: Vec::new(),
            ipset_v6: Vec::new(),
            transparent_port,
            excluded_uid: Some(excluded_uid),
        }
    }

    pub fn from_config(
        cfg: &NetfixConfig,
        table_name: impl Into<String>,
        ipset_v4: Vec<String>,
        ipset_v6: Vec<String>,
        excluded_uid: Option<u32>,
    ) -> Result<Option<Self>, NetfixError> {
        if !cfg.dpi.enabled {
            return Ok(None);
        }

        let spec = match cfg.dpi.engine {
            DpiEngineKind::Nfqws => Self::for_nfqws(
                table_name,
                cfg.dpi.nfqueue_num,
                cfg.dpi.fwmark,
                cfg.dpi.game_filter,
                cfg.dpi.ipset_mode,
                ipset_v4,
                ipset_v6,
            ),
            DpiEngineKind::Ciadpi => match cfg.dpi.ciadpi_mode {
                CiadpiMode::Socks5 => return Ok(None),
                CiadpiMode::Transparent => Self {
                    table_name: table_name.into(),
                    mode: FirewallMode::CiadpiTransparent,
                    nfqueue_num: 0,
                    fwmark: 0,
                    game_filter: false,
                    ipset_mode: IpsetMode::Any,
                    ipset_v4: Vec::new(),
                    ipset_v6: Vec::new(),
                    transparent_port: cfg.dpi.transparent_port,
                    excluded_uid,
                },
            },
        };

        spec.validate()?;
        Ok(Some(spec))
    }

    pub fn validate(&self) -> Result<(), NetfixError> {
        validate_identifier(&self.table_name, "firewall table name", MAX_NFT_TABLE_LEN)?;

        for entry in &self.ipset_v4 {
            validate_cidr::<Ipv4Addr>(entry, "IPv4", 32)?;
        }
        for entry in &self.ipset_v6 {
            validate_cidr::<Ipv6Addr>(entry, "IPv6", 128)?;
        }
        if self.ipset_mode == IpsetMode::Loaded
            && self.ipset_v4.is_empty()
            && self.ipset_v6.is_empty()
        {
            return Err(NetfixError::InvalidInput(
                "ipset_mode 'loaded' requires at least one entry in ipset_v4 or ipset_v6".into(),
            ));
        }

        if self.mode == FirewallMode::CiadpiTransparent {
            if self.transparent_port == 0 {
                return Err(NetfixError::InvalidInput(
                    "transparent_port must be in 1..=65535".into(),
                ));
            }
            if self.excluded_uid.is_none() {
                return Err(NetfixError::InvalidInput(
                    "ciadpi transparent mode requires excluded_uid to prevent redirect loops"
                        .into(),
                ));
            }
        }

        Ok(())
    }
}

pub struct NftablesBackend;

impl NftablesBackend {
    pub fn try_render_script(spec: &FirewallSpec) -> Result<String, NetfixError> {
        spec.validate()?;
        let mut out = String::new();
        let _ = writeln!(out, "add table inet {}", spec.table_name);
        let _ = writeln!(out, "delete table inet {}", spec.table_name);
        let _ = writeln!(out, "add table inet {} {{", spec.table_name);

        match spec.mode {
            FirewallMode::Nfqws => render_nft_nfqws(&mut out, spec),
            FirewallMode::CiadpiTransparent => render_nft_ciadpi_transparent(&mut out, spec),
        }

        let _ = writeln!(out, "}}");
        Ok(out)
    }

    pub fn render_script(spec: &FirewallSpec) -> String {
        Self::try_render_script(spec).expect("valid FirewallSpec")
    }

    pub fn try_render_cleanup(table_name: &str) -> Result<String, NetfixError> {
        validate_identifier(table_name, "firewall table name", MAX_NFT_TABLE_LEN)?;
        Ok(format!(
            "add table inet {table_name}\ndelete table inet {table_name}\n"
        ))
    }

    pub fn render_cleanup(table_name: &str) -> String {
        Self::try_render_cleanup(table_name).expect("valid nftables table name")
    }
}

pub struct IptablesBackend;

impl IptablesBackend {
    pub fn chain_name(table_name: &str) -> String {
        if table_name == "netfix" {
            "NETFIX_DPI".to_string()
        } else if table_name.starts_with("NETFIX_") {
            table_name.to_string()
        } else if let Some(rest) = table_name.strip_prefix("netfix_") {
            format!("NETFIX_{}", rest.to_ascii_uppercase())
        } else {
            format!("NETFIX_{}", table_name.to_ascii_uppercase())
        }
    }

    pub fn try_render_commands(spec: &FirewallSpec) -> Result<Vec<Vec<String>>, NetfixError> {
        spec.validate()?;
        let chain = Self::chain_name(&spec.table_name);
        validate_identifier(&chain, "iptables chain name", MAX_IPTABLES_CHAIN_LEN)?;

        let mut cmds = Vec::new();
        match spec.mode {
            FirewallMode::Nfqws => {
                let in_chain = format!("{chain}_IN");
                validate_identifier(&in_chain, "iptables chain name", MAX_IPTABLES_CHAIN_LEN)?;
                push_nfqws_family_commands(&mut cmds, "iptables", &chain, &in_chain, spec, &spec.ipset_v4);
                push_nfqws_family_commands(&mut cmds, "ip6tables", &chain, &in_chain, spec, &spec.ipset_v6);
            }
            FirewallMode::CiadpiTransparent => {
                cmds.push(ipt_cmd("iptables", &["-t", "nat", "-N", &chain]));
                cmds.push(ipt_cmd(
                    "iptables",
                    &["-t", "nat", "-A", &chain, "-d", "127.0.0.0/8", "-j", "RETURN"],
                ));
                let uid = spec
                    .excluded_uid
                    .expect("validated excluded_uid for CiadpiTransparent");
                let uid_str = uid.to_string();
                cmds.push(ipt_cmd(
                    "iptables",
                    &[
                        "-t",
                        "nat",
                        "-A",
                        &chain,
                        "-m",
                        "owner",
                        "--uid-owner",
                        &uid_str,
                        "-j",
                        "RETURN",
                    ],
                ));
                let port_str = spec.transparent_port.to_string();
                cmds.push(ipt_cmd(
                    "iptables",
                    &[
                        "-t",
                        "nat",
                        "-A",
                        &chain,
                        "-p",
                        "tcp",
                        "-m",
                        "multiport",
                        "--dports",
                        "80,443",
                        "-j",
                        "REDIRECT",
                        "--to-ports",
                        &port_str,
                    ],
                ));
                cmds.push(ipt_cmd("iptables", &["-t", "nat", "-A", "OUTPUT", "-j", &chain]));

                cmds.push(ipt_cmd("iptables", &["-t", "filter", "-N", &chain]));
                cmds.push(ipt_cmd(
                    "iptables",
                    &[
                        "-t", "filter", "-A", &chain, "-p", "udp", "--dport", "443", "-j", "REJECT",
                    ],
                ));
                cmds.push(ipt_cmd(
                    "iptables",
                    &["-t", "filter", "-A", "OUTPUT", "-j", &chain],
                ));

                cmds.push(ipt_cmd("ip6tables", &["-t", "filter", "-N", &chain]));
                cmds.push(ipt_cmd(
                    "ip6tables",
                    &[
                        "-t", "filter", "-A", &chain, "-p", "tcp", "-m", "multiport", "--dports",
                        "80,443", "-j", "REJECT",
                    ],
                ));
                cmds.push(ipt_cmd(
                    "ip6tables",
                    &[
                        "-t", "filter", "-A", &chain, "-p", "udp", "-m", "multiport", "--dports",
                        "80,443", "-j", "REJECT",
                    ],
                ));
                cmds.push(ipt_cmd(
                    "ip6tables",
                    &["-t", "filter", "-A", "OUTPUT", "-j", &chain],
                ));
            }
        }

        Ok(cmds)
    }

    pub fn render_commands(spec: &FirewallSpec) -> Vec<Vec<String>> {
        Self::try_render_commands(spec).expect("valid FirewallSpec")
    }

    pub fn try_render_cleanup_commands(chain: &str) -> Result<Vec<Vec<String>>, NetfixError> {
        validate_identifier(chain, "iptables chain name", MAX_IPTABLES_CHAIN_LEN)?;
        let in_chain = format!("{chain}_IN");
        let has_in_chain = in_chain.len() <= MAX_IPTABLES_CHAIN_LEN;

        let mut cmds = Vec::new();
        for tool in ["iptables", "ip6tables"] {
            cmds.push(ipt_cmd(tool, &["-t", "mangle", "-D", "OUTPUT", "-j", chain]));
            cmds.push(ipt_cmd(tool, &["-t", "mangle", "-F", chain]));
            cmds.push(ipt_cmd(tool, &["-t", "mangle", "-X", chain]));

            if has_in_chain {
                cmds.push(ipt_cmd(
                    tool,
                    &["-t", "mangle", "-D", "PREROUTING", "-j", &in_chain],
                ));
                cmds.push(ipt_cmd(tool, &["-t", "mangle", "-F", &in_chain]));
                cmds.push(ipt_cmd(tool, &["-t", "mangle", "-X", &in_chain]));
            }

            cmds.push(ipt_cmd(tool, &["-t", "nat", "-D", "OUTPUT", "-j", chain]));
            cmds.push(ipt_cmd(tool, &["-t", "nat", "-F", chain]));
            cmds.push(ipt_cmd(tool, &["-t", "nat", "-X", chain]));

            cmds.push(ipt_cmd(tool, &["-t", "filter", "-D", "OUTPUT", "-j", chain]));
            cmds.push(ipt_cmd(tool, &["-t", "filter", "-F", chain]));
            cmds.push(ipt_cmd(tool, &["-t", "filter", "-X", chain]));
        }

        Ok(cmds)
    }

    pub fn render_cleanup_commands(chain: &str) -> Vec<Vec<String>> {
        Self::try_render_cleanup_commands(chain).expect("valid iptables chain name")
    }
}

#[derive(Debug)]
pub struct FirewallGuard {
    kind: FirewallKind,
    spec: FirewallSpec,
    active: AtomicBool,
}

impl FirewallGuard {
    pub fn new(kind: FirewallKind, spec: FirewallSpec) -> Self {
        Self {
            kind,
            spec,
            active: AtomicBool::new(false),
        }
    }

    pub fn kind(&self) -> FirewallKind {
        self.kind
    }

    pub fn spec(&self) -> &FirewallSpec {
        &self.spec
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    pub fn disarm(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    pub fn apply(&self) -> Result<(), NetfixError> {
        self.apply_with(&SystemFirewallRunner)
    }

    pub fn cleanup(&self) -> Result<(), NetfixError> {
        self.cleanup_with(&SystemFirewallRunner)
    }

    fn apply_with(&self, runner: &dyn FirewallRunner) -> Result<(), NetfixError> {
        self.spec.validate()?;
        match self.kind {
            FirewallKind::Nftables => {
                let script = NftablesBackend::try_render_script(&self.spec)?;
                self.active.store(true, Ordering::SeqCst);
                if let Err(err) = runner.run_nft(&script) {
                    let _ = self.cleanup_with(runner);
                    self.active.store(false, Ordering::SeqCst);
                    return Err(err);
                }
                Ok(())
            }
            FirewallKind::Iptables => {
                let cmds = IptablesBackend::try_render_commands(&self.spec)?;
                let chain = IptablesBackend::chain_name(&self.spec.table_name);
                let _ = runner.run_iptables_cleanup(&chain);

                self.active.store(true, Ordering::SeqCst);
                for args in &cmds {
                    if let Err(err) = runner.run_iptables(args) {
                        let _ = self.cleanup_with(runner);
                        self.active.store(false, Ordering::SeqCst);
                        return Err(err);
                    }
                }
                Ok(())
            }
        }
    }

    fn cleanup_with(&self, runner: &dyn FirewallRunner) -> Result<(), NetfixError> {
        cleanup_table_with(self.kind, &self.spec.table_name, runner)?;
        self.active.store(false, Ordering::SeqCst);
        Ok(())
    }
}

/// Removes NetFix firewall tables/chains for `table_name` using `kind`.
pub fn cleanup_table(kind: FirewallKind, table_name: &str) -> Result<(), NetfixError> {
    cleanup_table_with(kind, table_name, &SystemFirewallRunner)
}

fn cleanup_table_with(
    kind: FirewallKind,
    table_name: &str,
    runner: &dyn FirewallRunner,
) -> Result<(), NetfixError> {
    validate_identifier(table_name, "firewall table name", MAX_NFT_TABLE_LEN)?;
    match kind {
        FirewallKind::Nftables => {
            let script = NftablesBackend::try_render_cleanup(table_name)?;
            runner.run_nft(&script)?;
        }
        FirewallKind::Iptables => {
            let chain = IptablesBackend::chain_name(table_name);
            runner.run_iptables_cleanup(&chain)?;
        }
    }
    Ok(())
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        if self.active.load(Ordering::SeqCst) {
            if let Err(err) = self.cleanup() {
                eprintln!(
                    "netfix firewall cleanup failed for '{}': {err}",
                    self.spec.table_name
                );
            }
        }
    }
}

pub fn detect_backend() -> Result<FirewallKind, NetfixError> {
    detect_backend_with(|bin| which_binary(bin).is_some())
}

fn detect_backend_with<F>(has_binary: F) -> Result<FirewallKind, NetfixError>
where
    F: Fn(&str) -> bool,
{
    if has_binary("nft") {
        Ok(FirewallKind::Nftables)
    } else if has_binary("iptables") {
        Ok(FirewallKind::Iptables)
    } else {
        Err(NetfixError::MissingEngine(
            "neither 'nft' nor 'iptables' binary found in PATH or /usr/sbin".into(),
        ))
    }
}

pub fn which_binary(name: &str) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }

    let direct = Path::new(name);
    if name.contains('/') {
        return is_executable_file(direct).then(|| direct.to_path_buf());
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }

    for dir in FALLBACK_BIN_DIRS {
        let candidate = Path::new(dir).join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }

    None
}

pub(crate) fn is_executable_file(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111) != 0,
        Err(_) => false,
    }
}

fn validate_identifier(name: &str, kind: &str, max_len: usize) -> Result<(), NetfixError> {
    if name.is_empty() || name.len() > max_len {
        return Err(NetfixError::InvalidInput(format!(
            "{kind} must be 1..={max_len} characters: '{name}'"
        )));
    }
    let bytes = name.as_bytes();
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return Err(NetfixError::InvalidInput(format!(
            "{kind} must start with an ASCII letter or '_': '{name}'"
        )));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
    {
        return Err(NetfixError::InvalidInput(format!(
            "{kind} contains disallowed characters: '{name}'"
        )));
    }
    Ok(())
}

fn validate_cidr<A: std::str::FromStr>(
    entry: &str,
    family: &str,
    max_prefix: u8,
) -> Result<(), NetfixError> {
    if entry.is_empty() || entry.chars().any(char::is_whitespace) {
        return Err(NetfixError::InvalidInput(format!(
            "invalid {family} address/CIDR '{entry}'"
        )));
    }
    match entry.split_once('/') {
        Some((addr_str, prefix_str)) => {
            if addr_str.parse::<A>().is_err() {
                return Err(NetfixError::InvalidInput(format!(
                    "invalid {family} address in CIDR '{entry}'"
                )));
            }
            if prefix_str.is_empty()
                || !prefix_str.bytes().all(|b| b.is_ascii_digit())
                || prefix_str.parse::<u8>().map_or(true, |p| p > max_prefix)
            {
                return Err(NetfixError::InvalidInput(format!(
                    "invalid {family} prefix length in CIDR '{entry}'"
                )));
            }
        }
        None => {
            if entry.parse::<A>().is_err() {
                return Err(NetfixError::InvalidInput(format!(
                    "invalid {family} address '{entry}'"
                )));
            }
        }
    }
    Ok(())
}

fn render_nft_nfqws(out: &mut String, spec: &FirewallSpec) {
    if spec.ipset_mode == IpsetMode::Loaded {
        if !spec.ipset_v4.is_empty() {
            render_nft_set(out, "netfix_ipset_v4", "ipv4_addr", &spec.ipset_v4);
        }
        if !spec.ipset_v6.is_empty() {
            render_nft_set(out, "netfix_ipset_v6", "ipv6_addr", &spec.ipset_v6);
        }
    }

    render_nft_nfqws_chain(out, "output", "output", "dport", "daddr", spec);
    render_nft_nfqws_chain(out, "prerouting", "prerouting", "sport", "saddr", spec);
}

fn render_nft_set(out: &mut String, name: &str, addr_type: &str, entries: &[String]) {
    let _ = writeln!(out, "    set {name} {{");
    let _ = writeln!(out, "        type {addr_type}");
    let _ = writeln!(out, "        flags interval");
    let _ = writeln!(out, "        elements = {{ {} }}", entries.join(", "));
    let _ = writeln!(out, "    }}");
}

fn render_nft_nfqws_chain(
    out: &mut String,
    chain_name: &str,
    hook: &str,
    port_dir: &str,
    addr_dir: &str,
    spec: &FirewallSpec,
) {
    let _ = writeln!(out, "    chain {chain_name} {{");
    let _ = writeln!(
        out,
        "        type filter hook {hook} priority mangle; policy accept;"
    );

    let mark_prefix = format!(
        "meta mark & 0x{:08x} == 0 ct original packets 1-15",
        spec.fwmark
    );

    if spec.ipset_mode == IpsetMode::Loaded {
        if !spec.ipset_v4.is_empty() {
            emit_nft_nfqws_rules(
                out,
                &mark_prefix,
                Some(&format!("ip {addr_dir} @netfix_ipset_v4")),
                port_dir,
                spec.nfqueue_num,
                spec.game_filter,
            );
        }
        if !spec.ipset_v6.is_empty() {
            emit_nft_nfqws_rules(
                out,
                &mark_prefix,
                Some(&format!("ip6 {addr_dir} @netfix_ipset_v6")),
                port_dir,
                spec.nfqueue_num,
                spec.game_filter,
            );
        }
    } else {
        emit_nft_nfqws_rules(
            out,
            &mark_prefix,
            None,
            port_dir,
            spec.nfqueue_num,
            spec.game_filter,
        );
    }

    let _ = writeln!(out, "    }}");
}

fn emit_nft_nfqws_rules(
    out: &mut String,
    mark_prefix: &str,
    ipset_match: Option<&str>,
    port_dir: &str,
    nfqueue_num: u16,
    game_filter: bool,
) {
    let filter = match ipset_match {
        Some(m) => format!("{mark_prefix} {m}"),
        None => mark_prefix.to_string(),
    };
    let _ = writeln!(
        out,
        "        {filter} tcp {port_dir} {{ 80, 443 }} queue num {nfqueue_num} bypass"
    );
    let _ = writeln!(
        out,
        "        {filter} udp {port_dir} 443 queue num {nfqueue_num} bypass"
    );
    if game_filter {
        let _ = writeln!(
            out,
            "        {filter} udp {port_dir} 1024-65535 queue num {nfqueue_num} bypass"
        );
    }
}

fn render_nft_ciadpi_transparent(out: &mut String, spec: &FirewallSpec) {
    let uid = spec
        .excluded_uid
        .expect("validated excluded_uid for CiadpiTransparent");
    let _ = writeln!(out, "    chain nat_output {{");
    let _ = writeln!(
        out,
        "        type nat hook output priority -100; policy accept;"
    );
    let _ = writeln!(out, "        ip daddr 127.0.0.0/8 return");
    let _ = writeln!(
        out,
        "        meta skuid != {uid} ip protocol tcp tcp dport {{ 80, 443 }} redirect to :{}",
        spec.transparent_port
    );
    let _ = writeln!(out, "    }}");

    let _ = writeln!(out, "    chain filter_output {{");
    let _ = writeln!(
        out,
        "        type filter hook output priority filter; policy accept;"
    );
    let _ = writeln!(out, "        udp dport 443 reject");
    let _ = writeln!(out, "        meta nfproto ipv6 tcp dport {{ 80, 443 }} reject");
    let _ = writeln!(out, "        meta nfproto ipv6 udp dport {{ 80, 443 }} reject");
    let _ = writeln!(out, "    }}");
}

fn ipt_cmd(tool: &str, args: &[&str]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len() + 3);
    out.push(tool.to_string());
    out.push("-w".to_string());
    out.push("5".to_string());
    out.extend(args.iter().map(|s| (*s).to_string()));
    out
}

fn push_nfqws_family_commands(
    cmds: &mut Vec<Vec<String>>,
    tool: &str,
    out_chain: &str,
    in_chain: &str,
    spec: &FirewallSpec,
    cidrs: &[String],
) {
    if spec.ipset_mode == IpsetMode::Loaded && cidrs.is_empty() {
        return;
    }

    push_nfqws_chain_rules(
        cmds,
        tool,
        out_chain,
        "OUTPUT",
        "--dport",
        "--dports",
        "-d",
        spec,
        cidrs,
    );
    push_nfqws_chain_rules(
        cmds,
        tool,
        in_chain,
        "PREROUTING",
        "--sport",
        "--sports",
        "-s",
        spec,
        cidrs,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_nfqws_chain_rules(
    cmds: &mut Vec<Vec<String>>,
    tool: &str,
    target_chain: &str,
    hook_chain: &str,
    port_flag: &str,
    ports_flag: &str,
    addr_flag: &str,
    spec: &FirewallSpec,
    cidrs: &[String],
) {
    cmds.push(ipt_cmd(tool, &["-t", "mangle", "-N", target_chain]));

    let mark_spec = format!("0/0x{:08x}", spec.fwmark);
    let qnum = spec.nfqueue_num.to_string();

    let addr_filters: Vec<Option<&str>> = if spec.ipset_mode == IpsetMode::Loaded {
        cidrs.iter().map(|s| Some(s.as_str())).collect()
    } else {
        vec![None]
    };

    for addr in addr_filters {
        let push_rule = |cmds: &mut Vec<Vec<String>>, proto_args: &[&str]| {
            let mut args = vec!["-t", "mangle", "-A", target_chain];
            if let Some(cidr) = addr {
                args.extend([addr_flag, cidr]);
            }
            args.extend_from_slice(proto_args);
            args.extend([
                "-m",
                "mark",
                "--mark",
                &mark_spec,
                "-m",
                "connbytes",
                "--connbytes",
                "1:15",
                "--connbytes-dir",
                "original",
                "--connbytes-mode",
                "packets",
                "-j",
                "NFQUEUE",
                "--queue-num",
                &qnum,
                "--queue-bypass",
            ]);
            cmds.push(ipt_cmd(tool, &args));
        };

        push_rule(cmds, &["-p", "tcp", "-m", "multiport", ports_flag, "80,443"]);
        push_rule(cmds, &["-p", "udp", port_flag, "443"]);
        if spec.game_filter {
            push_rule(cmds, &["-p", "udp", port_flag, "1024:65535"]);
        }
    }

    cmds.push(ipt_cmd(
        tool,
        &["-t", "mangle", "-A", hook_chain, "-j", target_chain],
    ));
}

trait FirewallRunner {
    fn run_nft(&self, script: &str) -> Result<(), NetfixError>;
    fn run_iptables(&self, args: &[String]) -> Result<(), NetfixError>;
    fn run_iptables_cleanup(&self, chain: &str) -> Result<(), NetfixError>;
}

struct SystemFirewallRunner;

impl FirewallRunner for SystemFirewallRunner {
    fn run_nft(&self, script: &str) -> Result<(), NetfixError> {
        run_nft_script(script)
    }

    fn run_iptables(&self, args: &[String]) -> Result<(), NetfixError> {
        run_iptables_command(args)
    }

    fn run_iptables_cleanup(&self, chain: &str) -> Result<(), NetfixError> {
        run_iptables_cleanup(chain)
    }
}

fn run_nft_script(script: &str) -> Result<(), NetfixError> {
    let nft_bin = which_binary("nft")
        .ok_or_else(|| NetfixError::MissingEngine("nft binary not found".into()))?;
    let mut child = Command::new(&nft_bin)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(classify_firewall_command_error("nft", &stderr, output.status.code()))
}

fn run_iptables_command(args: &[String]) -> Result<(), NetfixError> {
    let Some((tool, tool_args)) = args.split_first() else {
        return Err(NetfixError::InvalidInput("empty iptables command".into()));
    };
    let bin = which_binary(tool)
        .ok_or_else(|| NetfixError::MissingEngine(format!("{tool} binary not found")))?;

    let output = Command::new(&bin)
        .args(tool_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(classify_firewall_command_error(tool, &stderr, output.status.code()))
}

fn run_iptables_cleanup(chain: &str) -> Result<(), NetfixError> {
    let cmds = IptablesBackend::try_render_cleanup_commands(chain)?;
    for args in &cmds {
        let Some((tool, tool_args)) = args.split_first() else {
            continue;
        };
        let Some(bin) = which_binary(tool) else {
            return Err(NetfixError::MissingEngine(format!("{tool} binary not found")));
        };
        let output = Command::new(&bin)
            .args(tool_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if is_permission_error(&stderr) {
                return Err(NetfixError::PermissionDenied(format!("{tool}: {stderr}")));
            }
        }
    }
    Ok(())
}

fn classify_firewall_command_error(tool: &str, stderr: &str, code: Option<i32>) -> NetfixError {
    if is_permission_error(stderr) {
        NetfixError::PermissionDenied(format!("{tool} failed: {stderr}"))
    } else {
        NetfixError::Runtime(format!(
            "{tool} exited with {:?}: {}",
            code,
            if stderr.is_empty() {
                "unknown error"
            } else {
                stderr
            }
        ))
    }
}

fn is_permission_error(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("operation not permitted") || lower.contains("permission denied")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CiadpiMode, DpiEngineKind, ExitCode, IpsetMode, NetfixConfig};

    #[test]
    fn test_nftables_nfqws_script_includes_fwmark_bypass_and_game_filter() {
        let spec = FirewallSpec::for_nfqws(
            "netfix",
            200,
            0x4000_0000,
            true,
            IpsetMode::Any,
            vec![],
            vec![],
        );
        let script = NftablesBackend::render_script(&spec);
        assert!(script.contains("table inet netfix"));
        assert!(script.contains("meta mark & 0x40000000 == 0"));
        assert!(script.contains("queue num 200 bypass"));
        assert!(script.contains("udp dport 1024-65535"));
    }

    #[test]
    fn test_nftables_ciadpi_transparent_redirects_tcp_and_rejects_quic() {
        let spec = FirewallSpec::for_ciadpi_transparent("netfix", 11080, 999);
        let script = NftablesBackend::render_script(&spec);
        assert!(script.contains("skuid != 999"));
        assert!(script.contains("redirect to :11080"));
        assert!(script.contains("udp dport 443 reject"));
    }

    #[test]
    fn test_nftables_syntax_valid_via_nft_check() {
        let Some(nft_path) = which_binary("nft") else {
            return;
        };
        let mut scripts: Vec<String> = [
            FirewallSpec::for_nfqws(
                "netfix",
                200,
                0x4000_0000,
                true,
                IpsetMode::Any,
                vec![],
                vec![],
            ),
            FirewallSpec::for_nfqws(
                "netfix_scan",
                201,
                0x4000_0000,
                false,
                IpsetMode::Loaded,
                vec!["1.1.1.0/24".into()],
                vec![],
            ),
            FirewallSpec::for_nfqws(
                "netfix",
                200,
                0x4000_0000,
                true,
                IpsetMode::Loaded,
                vec!["1.1.1.0/24".into(), "8.8.8.8".into()],
                vec!["2606:4700:4700::1111/128".into()],
            ),
            FirewallSpec::for_ciadpi_transparent("netfix", 11080, 999),
        ]
        .iter()
        .map(NftablesBackend::render_script)
        .collect();
        scripts.push(NftablesBackend::render_cleanup("netfix_scan"));

        for script in scripts {
            let mut child = Command::new(&nft_path)
                .args(["-c", "-f", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to spawn nft");
            {
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(script.as_bytes())
                    .unwrap();
            }
            let output = child.wait_with_output().unwrap();
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("Operation not permitted") {
                    eprintln!("skipping nft -c assertion (no CAP_NET_ADMIN): {stderr}");
                    return;
                }
                panic!("nft syntax failed for:\n{script}\nstderr: {stderr}");
            }
        }
    }

    #[test]
    fn test_cleanup_script_handles_missing_table_idempotently() {
        let cleanup = NftablesBackend::render_cleanup("netfix_scan");
        assert!(cleanup.contains("table inet netfix_scan"));
        assert!(cleanup.contains("delete table inet netfix_scan"));
    }

    #[test]
    fn test_iptables_nfqws_commands_with_game_filter_fwmark_and_wait() {
        let spec = FirewallSpec::for_nfqws(
            "netfix",
            200,
            0x4000_0000,
            true,
            IpsetMode::Any,
            vec![],
            vec![],
        );
        let cmds = IptablesBackend::render_commands(&spec);
        assert!(!cmds.is_empty());
        assert!(cmds.iter().all(|c| c.windows(2).any(|w| w == ["-w", "5"])));
        assert!(cmds.iter().any(|c| c[0] == "iptables"));
        assert!(cmds.iter().any(|c| c[0] == "ip6tables"));

        let joined: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        let all = joined.join("\n");
        assert!(all.contains("NETFIX_DPI"));
        assert!(all.contains("--mark 0/0x40000000"));
        assert!(all.contains("NFQUEUE --queue-num 200 --queue-bypass"));
        assert!(all.contains("1024:65535"));
    }

    #[test]
    fn test_iptables_nfqws_with_loaded_ipset() {
        let spec = FirewallSpec::for_nfqws(
            "netfix_scan",
            201,
            0x4000_0000,
            false,
            IpsetMode::Loaded,
            vec!["1.1.1.0/24".into()],
            vec!["2606:4700:4700::1111".into()],
        );
        let cmds = IptablesBackend::render_commands(&spec);
        let joined: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        let all = joined.join("\n");
        assert!(all.contains("NETFIX_SCAN"));
        assert!(all.contains("-d 1.1.1.0/24"));
        assert!(all.contains("-d 2606:4700:4700::1111"));
        assert!(all.contains("--queue-num 201"));
    }

    #[test]
    fn test_iptables_ciadpi_transparent_commands() {
        let spec = FirewallSpec::for_ciadpi_transparent("netfix", 11080, 999);
        let cmds = IptablesBackend::render_commands(&spec);
        let joined: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        let all = joined.join("\n");
        assert!(all.contains("-t nat"));
        assert!(all.contains("127.0.0.0/8 -j RETURN"));
        assert!(all.contains("--uid-owner 999 -j RETURN"));
        assert!(all.contains("REDIRECT --to-ports 11080"));
        assert!(all.contains("-t filter"));
        assert!(all.contains("-p udp --dport 443 -j REJECT"));
        assert!(all.contains("ip6tables"));
    }

    #[test]
    fn test_iptables_cleanup_commands() {
        let cmds = IptablesBackend::render_cleanup_commands("NETFIX_DPI");
        let joined: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        let all = joined.join("\n");
        assert!(cmds.iter().all(|c| c.windows(2).any(|w| w == ["-w", "5"])));
        assert!(all.contains("-D OUTPUT -j NETFIX_DPI"));
        assert!(all.contains("-F NETFIX_DPI"));
        assert!(all.contains("-X NETFIX_DPI"));
    }

    #[test]
    fn test_detect_backend_prefers_nftables_then_iptables_or_errors() {
        assert_eq!(
            detect_backend_with(|b| b == "nft" || b == "iptables").unwrap(),
            FirewallKind::Nftables
        );
        assert_eq!(
            detect_backend_with(|b| b == "iptables").unwrap(),
            FirewallKind::Iptables
        );
        assert_eq!(
            detect_backend_with(|b| b == "nft").unwrap(),
            FirewallKind::Nftables
        );
        let err = detect_backend_with(|_| false).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::MissingEngine);
        assert_eq!(detect_backend().unwrap(), FirewallKind::Nftables);
    }

    #[test]
    fn test_loaded_ipset_with_both_v4_and_v6_empty_rejected_with_invalid_input() {
        let empty_loaded = FirewallSpec::for_nfqws(
            "netfix",
            200,
            0x4000_0000,
            false,
            IpsetMode::Loaded,
            vec![],
            vec![],
        );
        assert_eq!(
            empty_loaded.validate().unwrap_err().exit_code(),
            ExitCode::InvalidInput
        );
        assert_eq!(
            NftablesBackend::try_render_script(&empty_loaded)
                .unwrap_err()
                .exit_code(),
            ExitCode::InvalidInput
        );
        assert_eq!(
            IptablesBackend::try_render_commands(&empty_loaded)
                .unwrap_err()
                .exit_code(),
            ExitCode::InvalidInput
        );

        let v4_only = FirewallSpec::for_nfqws(
            "netfix",
            200,
            0x4000_0000,
            false,
            IpsetMode::Loaded,
            vec!["1.1.1.0/24".into()],
            vec![],
        );
        assert!(v4_only.validate().is_ok());

        let v6_only = FirewallSpec::for_nfqws(
            "netfix",
            200,
            0x4000_0000,
            false,
            IpsetMode::Loaded,
            vec![],
            vec!["2606:4700:4700::1111/128".into()],
        );
        assert!(v6_only.validate().is_ok());
    }

    #[test]
    fn test_malformed_table_chain_and_cidr_rejected_with_invalid_input() {
        let bad_table = FirewallSpec::for_nfqws(
            "netfix; drop",
            200,
            0x4000_0000,
            false,
            IpsetMode::Any,
            vec![],
            vec![],
        );
        assert_eq!(
            NftablesBackend::try_render_script(&bad_table)
                .unwrap_err()
                .exit_code(),
            ExitCode::InvalidInput
        );
        assert_eq!(
            IptablesBackend::try_render_commands(&bad_table)
                .unwrap_err()
                .exit_code(),
            ExitCode::InvalidInput
        );

        let bad_v4 = FirewallSpec::for_nfqws(
            "netfix",
            200,
            0x4000_0000,
            false,
            IpsetMode::Loaded,
            vec!["1.2.3.4/33".into()],
            vec![],
        );
        assert_eq!(
            bad_v4.validate().unwrap_err().exit_code(),
            ExitCode::InvalidInput
        );

        let bad_v6 = FirewallSpec::for_nfqws(
            "netfix",
            200,
            0x4000_0000,
            false,
            IpsetMode::Loaded,
            vec![],
            vec!["2001:db8::1/129".into()],
        );
        assert_eq!(
            bad_v6.validate().unwrap_err().exit_code(),
            ExitCode::InvalidInput
        );

        let bad_port = FirewallSpec::for_ciadpi_transparent("netfix", 0, 999);
        assert_eq!(
            bad_port.validate().unwrap_err().exit_code(),
            ExitCode::InvalidInput
        );

        assert_eq!(
            NftablesBackend::try_render_cleanup("bad\ntable")
                .unwrap_err()
                .exit_code(),
            ExitCode::InvalidInput
        );
        assert_eq!(
            IptablesBackend::try_render_cleanup_commands("WAY_TOO_LONG_IPTABLES_CHAIN_NAME")
                .unwrap_err()
                .exit_code(),
            ExitCode::InvalidInput
        );
    }

    #[test]
    fn test_from_config_maps_nfqws_ciadpi_transparent_and_socks5() {
        let mut cfg = NetfixConfig::default();
        cfg.dpi.engine = DpiEngineKind::Nfqws;
        let spec = FirewallSpec::from_config(&cfg, "netfix", vec![], vec![], None)
            .unwrap()
            .expect("nfqws requires firewall");
        assert_eq!(spec.mode, FirewallMode::Nfqws);
        assert_eq!(spec.nfqueue_num, 200);

        cfg.dpi.engine = DpiEngineKind::Ciadpi;
        cfg.dpi.ciadpi_mode = CiadpiMode::Socks5;
        assert!(FirewallSpec::from_config(&cfg, "netfix", vec![], vec![], None)
            .unwrap()
            .is_none());

        cfg.dpi.ciadpi_mode = CiadpiMode::Transparent;
        let spec = FirewallSpec::from_config(&cfg, "netfix", vec![], vec![], Some(1000))
            .unwrap()
            .expect("transparent ciadpi requires firewall");
        assert_eq!(spec.mode, FirewallMode::CiadpiTransparent);
        assert_eq!(spec.transparent_port, 11080);
        assert_eq!(spec.excluded_uid, Some(1000));
    }

    #[test]
    fn test_firewall_guard_drop_does_not_panic_and_rejects_invalid_spec() {
        let bad_spec = FirewallSpec::for_nfqws(
            "bad;name",
            200,
            0x4000_0000,
            false,
            IpsetMode::Any,
            vec![],
            vec![],
        );
        let guard = FirewallGuard::new(FirewallKind::Nftables, bad_spec);
        assert!(!guard.is_active());
        assert_eq!(guard.apply().unwrap_err().exit_code(), ExitCode::InvalidInput);
        drop(guard);

        let active_invalid = FirewallGuard::new(
            FirewallKind::Nftables,
            FirewallSpec::for_nfqws(
                "bad;name",
                200,
                0x4000_0000,
                false,
                IpsetMode::Any,
                vec![],
                vec![],
            ),
        );
        active_invalid.active.store(true, Ordering::SeqCst);
        // Must log error on drop without panicking.
        drop(active_invalid);
    }

    #[test]
    fn test_ciadpi_transparent_without_excluded_uid_rejected_with_invalid_input() {
        let spec = FirewallSpec {
            table_name: "netfix".into(),
            mode: FirewallMode::CiadpiTransparent,
            nfqueue_num: 0,
            fwmark: 0,
            game_filter: false,
            ipset_mode: IpsetMode::Any,
            ipset_v4: Vec::new(),
            ipset_v6: Vec::new(),
            transparent_port: 11080,
            excluded_uid: None,
        };
        assert_eq!(spec.validate().unwrap_err().exit_code(), ExitCode::InvalidInput);
        assert_eq!(
            NftablesBackend::try_render_script(&spec)
                .unwrap_err()
                .exit_code(),
            ExitCode::InvalidInput
        );
        assert_eq!(
            IptablesBackend::try_render_commands(&spec)
                .unwrap_err()
                .exit_code(),
            ExitCode::InvalidInput
        );

        let mut cfg = NetfixConfig::default();
        cfg.dpi.engine = DpiEngineKind::Ciadpi;
        cfg.dpi.ciadpi_mode = CiadpiMode::Transparent;
        assert_eq!(
            FirewallSpec::from_config(&cfg, "netfix", vec![], vec![], None)
                .unwrap_err()
                .exit_code(),
            ExitCode::InvalidInput
        );
    }

    #[test]
    fn test_firewall_guard_apply_partial_failure_runs_cleanup() {
        use std::cell::RefCell;

        struct FailingRunner {
            fail_iptables_at: usize,
            iptables_calls: RefCell<usize>,
            events: RefCell<Vec<String>>,
            fail_nft_apply: bool,
        }

        impl FirewallRunner for FailingRunner {
            fn run_nft(&self, script: &str) -> Result<(), NetfixError> {
                if self.fail_nft_apply && script.contains("chain ") {
                    self.events.borrow_mut().push("nft_apply_fail".into());
                    return Err(NetfixError::Runtime("simulated nft failure".into()));
                }
                self.events.borrow_mut().push("nft_cleanup".into());
                Ok(())
            }

            fn run_iptables(&self, args: &[String]) -> Result<(), NetfixError> {
                let mut count = self.iptables_calls.borrow_mut();
                *count += 1;
                self.events
                    .borrow_mut()
                    .push(format!("ipt_cmd_{}:{}", *count, args.join(" ")));
                if *count == self.fail_iptables_at {
                    return Err(NetfixError::Runtime("simulated iptables mid-way failure".into()));
                }
                Ok(())
            }

            fn run_iptables_cleanup(&self, chain: &str) -> Result<(), NetfixError> {
                self.events
                    .borrow_mut()
                    .push(format!("ipt_cleanup:{chain}"));
                Ok(())
            }
        }

        let spec = FirewallSpec::for_nfqws(
            "netfix",
            200,
            0x4000_0000,
            false,
            IpsetMode::Any,
            vec![],
            vec![],
        );

        let ipt_runner = FailingRunner {
            fail_iptables_at: 3,
            iptables_calls: RefCell::new(0),
            events: RefCell::new(Vec::new()),
            fail_nft_apply: false,
        };
        let ipt_guard = FirewallGuard::new(FirewallKind::Iptables, spec.clone());
        let err = ipt_guard.apply_with(&ipt_runner).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::Runtime);
        assert!(!ipt_guard.is_active());
        let events = ipt_runner.events.borrow();
        assert_eq!(events.first().map(String::as_str), Some("ipt_cleanup:NETFIX_DPI"));
        assert_eq!(events.last().map(String::as_str), Some("ipt_cleanup:NETFIX_DPI"));
        assert_eq!(
            events.iter().filter(|e| e.starts_with("ipt_cmd_")).count(),
            3
        );

        let nft_runner = FailingRunner {
            fail_iptables_at: 0,
            iptables_calls: RefCell::new(0),
            events: RefCell::new(Vec::new()),
            fail_nft_apply: true,
        };
        let nft_guard = FirewallGuard::new(FirewallKind::Nftables, spec);
        let err = nft_guard.apply_with(&nft_runner).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::Runtime);
        assert!(!nft_guard.is_active());
        assert_eq!(
            *nft_runner.events.borrow(),
            vec!["nft_apply_fail".to_string(), "nft_cleanup".to_string()]
        );
    }
}
