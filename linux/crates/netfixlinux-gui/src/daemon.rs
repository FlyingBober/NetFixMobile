use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStatus {
    pub dpi_active: bool,
    pub dpi_enabled: bool,
    pub dpi_engine: String,
    pub active_strategy: String,
    pub strategy_source: String,
    pub network_profile: String,
    pub local_ip: String,
    pub tg_active: bool,
    pub tg_enabled: bool,
    pub tg_port: u16,
    pub tg_cf_enabled: bool,
    pub dns_mode: String,
    pub system_proxy_active: bool,
    pub polkit_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub command: String,
}

pub fn resolve_netfixctl_path() -> String {
    for candidate in ["/usr/local/bin/netfixctl", "/usr/bin/netfixctl"] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    which::which("netfixctl")
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "netfixctl".to_string())
}

fn read_running_dpi_cmdline() -> Option<(String, String)> {
    let out = Command::new("ps")
        .args(["-eo", "comm=,args="])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.contains("/nfqws ") || trimmed.starts_with("nfqws ") {
            if let Some(idx) = trimmed.find("--filter-") {
                return Some(("nfqws".to_string(), trimmed[idx..].trim().to_string()));
            }
            return Some(("nfqws".to_string(), "active".to_string()));
        }
        if trimmed.contains("/ciadpi ") || trimmed.starts_with("ciadpi ") {
            if let Some(idx) = trimmed.find("--") {
                return Some(("ciadpi".to_string(), trimmed[idx..].trim().to_string()));
            }
            return Some(("ciadpi".to_string(), "active".to_string()));
        }
    }
    None
}

fn detect_local_ip() -> String {
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("1.1.1.1:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                let ip = addr.ip().to_string();
                if !ip.starts_with("127.") && ip != "0.0.0.0" {
                    return ip;
                }
            }
        }
    }
    if let Ok(out) = Command::new("hostname").arg("-I").output() {
        let s = String::from_utf8_lossy(&out.stdout);
        if let Some(first) = s.split_whitespace().find(|ip| !ip.starts_with("127.")) {
            return first.to_string();
        }
    }
    "не определён".to_string()
}

fn status_cache() -> &'static Mutex<Option<(Instant, serde_json::Value)>> {
    static CACHE: OnceLock<Mutex<Option<(Instant, serde_json::Value)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

fn net_name_cache() -> &'static Mutex<Option<(Instant, String)>> {
    static NET_CACHE: OnceLock<Mutex<Option<(Instant, String)>>> = OnceLock::new();
    NET_CACHE.get_or_init(|| Mutex::new(None))
}

pub fn invalidate_status_cache() {
    if let Ok(mut guard) = status_cache().lock() {
        *guard = None;
    }
}

fn detect_network_name_fallback() -> String {
    if let Ok(guard) = net_name_cache().lock() {
        if let Some((ts, ref name)) = *guard {
            if ts.elapsed() < Duration::from_secs(20) {
                return name.clone();
            }
        }
    }

    let mut found = "default".to_string();
    if let Ok(out) = Command::new("nmcli")
        .args(["-t", "-f", "TYPE,CONNECTION", "device", "status"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some((dev_type, conn)) = line.split_once(':') {
                let c = conn.trim();
                if !c.is_empty() && c != "--" && dev_type != "loopback" && dev_type != "bridge" {
                    found = c.to_string();
                    break;
                }
            }
        }
    }

    if let Ok(mut guard) = net_name_cache().lock() {
        *guard = Some((Instant::now(), found.clone()));
    }
    found
}

fn is_effective_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn query_netfixctl_status(polkit_ready: bool) -> Option<serde_json::Value> {
    if let Ok(guard) = status_cache().lock() {
        if let Some((ts, ref cached)) = *guard {
            if ts.elapsed() < Duration::from_secs(15) {
                return Some(cached.clone());
            }
        }
    }

    let ctl = resolve_netfixctl_path();
    let fresh = if is_effective_root() {
        Command::new(&ctl)
            .args(["--json", "status"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
    } else if polkit_ready {
        Command::new("pkexec")
            .args(["--disable-internal-agent", &ctl, "--json", "status"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
    } else {
        None
    };

    if let Some(ref val) = fresh {
        if let Ok(mut guard) = status_cache().lock() {
            *guard = Some((Instant::now(), val.clone()));
        }
    }
    fresh
}

pub fn get_app_status() -> AppStatus {
    let mut dpi_active = false;
    let mut tg_active = false;

    if let Ok(out) = Command::new("systemctl")
        .args(["is-active", "netfix-dpi.service", "netfix-tgproxy.service"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        let mut lines = text.lines();
        dpi_active = lines.next().map(|s| s.trim() == "active").unwrap_or(false);
        tg_active = lines.next().map(|s| s.trim() == "active").unwrap_or(false);
    }

    let polkit_ready = crate::tun::is_polkit_installed();
    let mut dpi_engine = "nfqws".to_string();
    let mut active_strategy = crate::state::load_state().selected_strategy;
    let mut strategy_source = String::new();
    let mut network_profile = detect_network_name_fallback();
    let mut dns_mode = crate::state::load_state().dns_mode;
    let mut tg_port = 1443;
    let mut tg_cf_enabled = true;

    if let Some(val) = query_netfixctl_status(polkit_ready) {
        if let Some(dpi) = val.get("dpi") {
            if let Some(e) = dpi.get("engine").and_then(|v| v.as_str()) {
                dpi_engine = e.to_string();
            }
            if let Some(s) = dpi.get("active_strategy").and_then(|v| v.as_str()) {
                if !s.is_empty() {
                    active_strategy = s.to_string();
                }
            }
            if let Some(src) = dpi.get("strategy_source").and_then(|v| v.as_str()) {
                strategy_source = src.to_string();
            }
        }
        if let Some(tg) = val.get("tgproxy") {
            if let Some(p) = tg.get("port").and_then(|v| v.as_u64()) {
                tg_port = p as u16;
            }
            if let Some(cf) = tg.get("cf_enabled").and_then(|v| v.as_bool()) {
                tg_cf_enabled = cf;
            }
        }
        if let Some(net) = val.get("network") {
            if let Some(k) = net.get("key").and_then(|v| v.as_str()) {
                if !k.is_empty() {
                    network_profile = k.to_string();
                }
            }
        }
        if let Some(d) = val.get("dns_mode").and_then(|v| v.as_str()) {
            dns_mode = d.to_string();
        }
    }

    if dpi_active {
        if let Some((live_engine, live_args)) = read_running_dpi_cmdline() {
            dpi_engine = live_engine;
            if !live_args.is_empty() && live_args != "active" {
                active_strategy = live_args;
            }
        }
    }

    if active_strategy.trim().is_empty() {
        active_strategy = "не определена (требуется Polkit для чтения /etc/netfix)".to_string();
    }

    let system_proxy_active = crate::system_proxy::is_socks5_proxy_enabled();
    let local_ip = detect_local_ip();

    AppStatus {
        dpi_active,
        dpi_enabled: dpi_active,
        dpi_engine,
        active_strategy,
        strategy_source,
        network_profile,
        local_ip,
        tg_active,
        tg_enabled: tg_active,
        tg_port,
        tg_cf_enabled,
        dns_mode,
        system_proxy_active,
        polkit_ready,
    }
}

fn run_netfixctl_privileged(args: &[&str]) -> Result<(), String> {
    let ctl = resolve_netfixctl_path();
    let out = if is_effective_root() {
        Command::new(&ctl)
            .args(args)
            .output()
            .map_err(|e| format!("{} {} failed: {e}", ctl, args.join(" ")))?
    } else {
        Command::new("pkexec")
            .arg(&ctl)
            .args(args)
            .output()
            .map_err(|e| format!("pkexec {} {} failed: {e}", ctl, args.join(" ")))?
    };

    if out.status.success() {
        invalidate_status_cache();
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let msg = if !stderr.is_empty() { stderr } else { stdout };
        Err(if msg.is_empty() {
            format!("Команда netfixctl {} завершилась с ошибкой", args.join(" "))
        } else {
            msg
        })
    }
}

pub fn toggle_dpi(enable: bool) -> Result<(), String> {
    let action = if enable { "start" } else { "stop" };
    run_netfixctl_privileged(&[action, "dpi"])
}

pub fn toggle_tg(enable: bool) -> Result<(), String> {
    let action = if enable { "start" } else { "stop" };
    run_netfixctl_privileged(&[action, "tg"])
}

pub fn set_dns_mode(mode: &str) -> Result<(), String> {
    run_netfixctl_privileged(&["dns", "set", mode])
}

pub fn apply_strategy_args(args: &str) -> Result<(), String> {
    run_netfixctl_privileged(&["apply", args])
}

pub fn get_tg_link() -> Result<String, String> {
    let ctl = resolve_netfixctl_path();
    if let Ok(out) = Command::new(&ctl).args(["tg", "link"]).output() {
        if out.status.success() {
            let link = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if link.starts_with("tg://") {
                return Ok(link);
            }
        }
    }
    Ok("tg://proxy?server=127.0.0.1&port=1443&secret=dd349cc464330a4d1a73be8471b35f0290".to_string())
}

/// Complete preset list synced 1:1 with linux/presets/strategies-nfqws.toml
pub fn get_preset_strategies() -> Vec<StrategyItem> {
    vec![
        StrategyItem {
            id: "nfqws-fake-multisplit-badseq".into(),
            name: "Fake + Multisplit (badseq)".into(),
            description: "Универсальный профиль: подмена пакетов (fake) и нарезка SNI с обманом по badseq + QUIC fake.".into(),
            tags: vec!["YouTube".into(), "Discord".into(), "QUIC".into(), "badseq".into()],
            command: "--filter-tcp=80,443 --dpi-desync=fake,multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6".into(),
        },
        StrategyItem {
            id: "nfqws-fake-multisplit-md5sig".into(),
            name: "Fake + Multisplit (md5sig)".into(),
            description: "Подмена (fake) и нарезка SNI с неверной подписью TCP MD5 и QUIC fake.".into(),
            tags: vec!["YouTube".into(), "Discord".into(), "QUIC".into(), "md5sig".into()],
            command: "--filter-tcp=80,443 --dpi-desync=fake,multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=6 --dpi-desync-fooling=md5sig --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6".into(),
        },
        StrategyItem {
            id: "nfqws-fake-multisplit-badsum".into(),
            name: "Fake + Multisplit (badsum)".into(),
            description: "Подмена (fake) с неверной контрольной суммой (badsum) и QUIC fake.".into(),
            tags: vec!["YouTube".into(), "Discord".into(), "badsum".into()],
            command: "--filter-tcp=80,443 --dpi-desync=fake,multisplit --dpi-desync-split-pos=midsld --dpi-desync-repeats=6 --dpi-desync-fooling=badsum --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6".into(),
        },
        StrategyItem {
            id: "nfqws-fake-badsum".into(),
            name: "Fake (badsum)".into(),
            description: "Лёгкая инъекция фейк-пакетов с неверной контрольной суммой (badsum).".into(),
            tags: vec!["YouTube".into(), "badsum".into()],
            command: "--filter-tcp=80,443 --dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-repeats=6 --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6".into(),
        },
        StrategyItem {
            id: "nfqws-disorder2-midsld".into(),
            name: "Disorder2 (midsld)".into(),
            description: "Нарезка и обратный порядок сегментов TCP ClientHello на границе SNI без отправки fake-пакетов.".into(),
            tags: vec!["YouTube".into(), "disorder2".into()],
            command: "--filter-tcp=80,443 --dpi-desync=disorder2 --dpi-desync-split-pos=1,midsld --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6".into(),
        },
        StrategyItem {
            id: "nfqws-fake-disorder2-badseq".into(),
            name: "Fake + Disorder2 (badseq)".into(),
            description: "Комбинация fake-пакетов и обратного порядка сегментов (disorder2) с badseq.".into(),
            tags: vec!["YouTube".into(), "Discord".into(), "disorder2".into(), "badseq".into()],
            command: "--filter-tcp=80,443 --dpi-desync=fake,disorder2 --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6".into(),
        },
        StrategyItem {
            id: "nfqws-multisplit-seqovl".into(),
            name: "Multisplit + SeqOvl (YouTube)".into(),
            description: "Нарезка TLS ClientHello с перекрытием TCP sequence (seqovl=652) для YouTube.".into(),
            tags: vec!["YouTube 4K".into(), "multisplit".into()],
            command: "--filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=8".into(),
        },
        StrategyItem {
            id: "nfqws-fake-autottl".into(),
            name: "Fake + AutoTTL (md5sig,badseq)".into(),
            description: "Автоподбор TTL фейкового пакета до ТСПУ провайдера с комбинированным fooling.".into(),
            tags: vec!["YouTube".into(), "Discord".into(), "AutoTTL".into()],
            command: "--filter-tcp=80,443 --dpi-desync=fake,multisplit --dpi-desync-autottl=2 --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=md5sig,badseq --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6".into(),
        },
        StrategyItem {
            id: "nfqws-fake-fakedsplit-ts".into(),
            name: "Discord Voice & QUIC (fakedsplit + ts)".into(),
            description: "Усиленный обход блокировки Discord (клиент, шлюз и голос) с обманом по TCP timestamps.".into(),
            tags: vec!["Discord Voice".into(), "QUIC HTTP/3".into(), "fakedsplit".into()],
            command: "--filter-tcp=80,443 --dpi-desync=fakedsplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=ts --dpi-desync-repeats=6 --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=8".into(),
        },
        StrategyItem {
            id: "nfqws-quic-fake-only".into(),
            name: "Split2 + QUIC Burst".into(),
            description: "Усиленные UDP 443 fake-пакеты в сочетании с TCP split2.".into(),
            tags: vec!["QUIC HTTP/3".into(), "split2".into()],
            command: "--filter-tcp=80,443 --dpi-desync=split2 --dpi-desync-split-pos=1,midsld --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=11".into(),
        },
    ]
}
