use std::collections::{HashMap, HashSet};
use std::fs::{OpenOptions, Permissions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

use crate::{NetfixConfig, NetfixError};

pub const DEFAULT_TGPROXY_STATE_DIR: &str = "/var/lib/netfix/tgproxy";
const PROBE_TIMEOUT_SECS: f64 = 5.0;
const CF_PROBE_CONCURRENCY: usize = 4;
const CF_CHECK_DEADLINE: Duration = Duration::from_secs(45);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CfServerState {
    Works,
    Busy,
    Fails,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcProbe {
    pub dc: i32,
    pub ip: String,
    pub tcp_ok: bool,
    pub wss_ok: bool,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfProbe {
    pub domain: String,
    pub state: CfServerState,
    pub latency_ms: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcCheckReport {
    pub dc_results: Vec<DcProbe>,
    pub cf_results: Vec<CfProbe>,
}

/// Builds a `tg://proxy` deep link with a `dd`-prefixed MTProto secret.
pub fn build_tg_proxy_url(ip: &str, port: u16, secret: &str) -> String {
    let formatted_secret = if secret.len() == 34 && secret.starts_with("dd") {
        secret.to_string()
    } else {
        format!("dd{secret}")
    };
    format!("tg://proxy?server={ip}&port={port}&secret={formatted_secret}")
}

/// Resolves the MTProto secret from `cfg` or persists a generated secret in `<state_dir>/secret`.
pub fn resolve_or_persist_secret(
    cfg: &NetfixConfig,
    state_dir: &Path,
) -> Result<String, NetfixError> {
    let configured = cfg.tgproxy.secret.trim();
    if !configured.is_empty() {
        if !is_valid_hex_secret(configured) {
            return Err(NetfixError::InvalidInput(
                "tgproxy.secret must be 32 hexadecimal characters".to_string(),
            ));
        }
        return Ok(configured.to_string());
    }

    let secret_path = state_dir.join("secret");
    match std::fs::read_to_string(&secret_path) {
        Ok(existing) => {
            let trimmed = existing.trim();
            if is_valid_hex_secret(trimmed) {
                return Ok(trimmed.to_string());
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(NetfixError::Io(err)),
    }

    let mut cloned = cfg.clone();
    cloned.tgproxy.secret.clear();
    let secret = cloned.ensure_secret();

    std::fs::create_dir_all(state_dir)?;
    write_secret_atomic(&secret_path, secret.as_bytes())?;
    Ok(secret)
}

fn is_valid_hex_secret(secret: &str) -> bool {
    secret.len() == 32 && secret.bytes().all(|b| b.is_ascii_hexdigit())
}

fn write_secret_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp_name = format!(".secret.tmp.{}", rand::random::<u64>());
    let tmp_path = match parent {
        Some(dir) => dir.join(tmp_name),
        None => std::path::PathBuf::from(tmp_name),
    };

    let write_res = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        std::fs::set_permissions(&tmp_path, Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

/// Probes Telegram DC1-DC5 WebSocket endpoints and Cloudflare proxy domains concurrently.
pub async fn probe_dc_and_cf(cfg: &NetfixConfig) -> DcCheckReport {
    tgwsproxy::config::TLS_VERIFY.store(cfg.tgproxy.tls_verify, Ordering::Relaxed);
    tgwsproxy::cffront::set_front_ips(cfg.tgproxy.cf_front_ips.clone());
    tgwsproxy::cffront::set_plain_first(cfg.tgproxy.cf_plain_first);

    let dc_map = tgwsproxy::proxy::parse_cidr_pool(&cfg.tgproxy.dc_ips);
    let cf_domains = collect_cf_domains(cfg);

    let (dc_results, cf_results) = tokio::join!(
        probe_all_dcs(&dc_map, cfg.tgproxy.tls_verify),
        probe_all_cf(cf_domains)
    );

    DcCheckReport {
        dc_results,
        cf_results,
    }
}

fn resolve_dc_target_ip(dc: i32, configured: &HashMap<i32, String>) -> String {
    if let Some(ip) = configured.get(&dc) {
        if !ip.trim().is_empty() {
            return ip.clone();
        }
    }
    tgwsproxy::config::DC_DEFAULT_IPS
        .get(&dc)
        .copied()
        .unwrap_or_default()
        .to_string()
}

fn collect_cf_domains(cfg: &NetfixConfig) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    let domain = cfg
        .tgproxy
        .pinned_cf_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !domain.is_empty() && seen.insert(domain.clone()) {
        out.push(domain);
    }

    for domain in tgwsproxy::cfproxy::default_cfproxy_domains() {
        if !domain.is_empty() && seen.insert(domain.clone()) {
            out.push(domain);
        }
    }

    out
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn tls_client_config(tls_verify: bool, domain: &str) -> Arc<ClientConfig> {
    static VERIFIED: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static INSECURE: OnceLock<Arc<ClientConfig>> = OnceLock::new();

    if tls_verify && domain.parse::<IpAddr>().is_err() {
        VERIFIED
            .get_or_init(|| {
                let roots = rustls::RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                );
                let cfg = ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                Arc::new(cfg)
            })
            .clone()
    } else {
        INSECURE
            .get_or_init(|| {
                let cfg = ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerify))
                    .with_no_client_auth();
                Arc::new(cfg)
            })
            .clone()
    }
}

#[derive(Debug)]
struct ProbeFailure {
    tcp_ok: bool,
    detail: String,
}

async fn probe_tls_ws_addr(
    addr: SocketAddr,
    domain: &str,
    tls_verify: bool,
    timeout: Duration,
) -> Result<u64, ProbeFailure> {
    let started = Instant::now();

    let tcp = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            return Err(ProbeFailure {
                tcp_ok: false,
                detail: format!("tcp: {err}"),
            });
        }
        Err(_) => {
            return Err(ProbeFailure {
                tcp_ok: false,
                detail: "tcp: timeout".to_string(),
            });
        }
    };

    let sni = ServerName::try_from(domain.to_string()).map_err(|_| ProbeFailure {
        tcp_ok: true,
        detail: format!("invalid SNI domain: {domain}"),
    })?;
    let connector = TlsConnector::from(tls_client_config(tls_verify, domain));

    let tls = match tokio::time::timeout(timeout, connector.connect(sni, tcp)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            return Err(ProbeFailure {
                tcp_ok: true,
                detail: format!("tls: {err}"),
            });
        }
        Err(_) => {
            return Err(ProbeFailure {
                tcp_ok: true,
                detail: "tls: timeout".to_string(),
            });
        }
    };

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    let ws_key = base64::engine::general_purpose::STANDARD.encode(key);
    let req = format!(
        "GET /apiws HTTP/1.1\r\n\
         Host: {domain}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: binary\r\n\r\n"
    );

    match tokio::time::timeout(timeout, write_half.write_all(req.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            return Err(ProbeFailure {
                tcp_ok: true,
                detail: format!("ws write: {err}"),
            });
        }
        Err(_) => {
            return Err(ProbeFailure {
                tcp_ok: true,
                detail: "ws write: timeout".to_string(),
            });
        }
    }

    let mut reader = BufReader::new(read_half);
    let mut status_line = String::new();
    match tokio::time::timeout(timeout, reader.read_line(&mut status_line)).await {
        Ok(Ok(0)) => {
            return Err(ProbeFailure {
                tcp_ok: true,
                detail: "ws: eof".to_string(),
            });
        }
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            return Err(ProbeFailure {
                tcp_ok: true,
                detail: format!("ws read: {err}"),
            });
        }
        Err(_) => {
            return Err(ProbeFailure {
                tcp_ok: true,
                detail: "ws read: timeout".to_string(),
            });
        }
    }

    let status_code = status_line
        .trim_end()
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status_code == 101 {
        Ok(started.elapsed().as_millis() as u64)
    } else {
        Err(ProbeFailure {
            tcp_ok: true,
            detail: format!("http {status_code}"),
        })
    }
}

async fn probe_all_dcs(configured: &HashMap<i32, String>, tls_verify: bool) -> Vec<DcProbe> {
    let mut set = JoinSet::new();
    for dc in 1..=5 {
        let ip = resolve_dc_target_ip(dc, configured);
        set.spawn(async move { probe_single_dc(dc, ip, tls_verify).await });
    }

    let mut results = Vec::with_capacity(5);
    while let Some(res) = set.join_next().await {
        if let Ok(probe) = res {
            results.push(probe);
        }
    }
    results.sort_by_key(|p| p.dc);
    results
}

async fn probe_single_dc(dc: i32, ip: String, tls_verify: bool) -> DcProbe {
    let parsed_ip: IpAddr = match ip.trim().parse() {
        Ok(addr) => addr,
        Err(_) => {
            return DcProbe {
                dc,
                ip,
                tcp_ok: false,
                wss_ok: false,
                reachable: false,
                latency_ms: None,
                detail: "invalid or empty target IP".to_string(),
            };
        }
    };

    let addr = SocketAddr::new(parsed_ip, 443);
    let domains = tgwsproxy::proxy::ws_domains(dc, false);
    let timeout = Duration::from_secs_f64(PROBE_TIMEOUT_SECS);
    let mut any_tcp_ok = false;
    let mut last_detail = "failed".to_string();

    for domain in domains {
        match probe_tls_ws_addr(addr, &domain, tls_verify, timeout).await {
            Ok(ms) => {
                return DcProbe {
                    dc,
                    ip,
                    tcp_ok: true,
                    wss_ok: true,
                    reachable: true,
                    latency_ms: Some(ms),
                    detail: "ok".to_string(),
                };
            }
            Err(fail) => {
                any_tcp_ok |= fail.tcp_ok;
                last_detail = fail.detail;
            }
        }
    }

    DcProbe {
        dc,
        ip,
        tcp_ok: any_tcp_ok,
        wss_ok: false,
        reachable: false,
        latency_ms: None,
        detail: last_detail,
    }
}

async fn probe_all_cf(domains: Vec<String>) -> Vec<CfProbe> {
    let sem = Arc::new(Semaphore::new(CF_PROBE_CONCURRENCY));
    let mut set = JoinSet::new();

    for domain in domains {
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            Some(probe_single_cf(domain).await)
        });
    }

    let mut results = Vec::new();
    let deadline = tokio::time::Instant::now() + CF_CHECK_DEADLINE;
    loop {
        match tokio::time::timeout_at(deadline, set.join_next()).await {
            Ok(Some(Ok(Some(probe)))) => results.push(probe),
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => {
                set.abort_all();
                break;
            }
        }
    }

    results.sort_by(|a, b| {
        a.state
            .cmp(&b.state)
            .then_with(|| {
                a.latency_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&b.latency_ms.unwrap_or(u64::MAX))
            })
            .then_with(|| a.domain.cmp(&b.domain))
    });
    results
}

async fn probe_single_cf(domain: String) -> CfProbe {
    let host = format!("kws2.{domain}");
    let started = Instant::now();
    let (ws_opt, _resolved_ip, err) =
        tgwsproxy::cfproxy::cf_connect_domain(&host, "/apiws", PROBE_TIMEOUT_SECS).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    if let Some(ws) = ws_opt {
        ws.close().await;
        return CfProbe {
            domain,
            state: CfServerState::Works,
            latency_ms: Some(elapsed_ms),
            detail: "ok".to_string(),
        };
    }

    classify_cf_error(domain, elapsed_ms, err)
}

fn classify_cf_error(
    domain: String,
    elapsed_ms: u64,
    err: Option<tgwsproxy::ws::WsError>,
) -> CfProbe {
    match err {
        Some(e) if tgwsproxy::ws::is_http_status_error(&e, 429) => CfProbe {
            domain,
            state: CfServerState::Busy,
            latency_ms: Some(elapsed_ms),
            detail: "http 429".to_string(),
        },
        Some(e) => CfProbe {
            domain,
            state: CfServerState::Fails,
            latency_ms: None,
            detail: e.compact(),
        },
        None => CfProbe {
            domain,
            state: CfServerState::Fails,
            latency_ms: None,
            detail: "failed".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::PrivateKeyDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tgwsproxy::ws::{WsError, WsHandshakeError};

    const TEST_CERT_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0x95, 0x30, 0x82, 0x01, 0x3b, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x48,
        0x1e, 0x6c, 0x3a, 0x7b, 0xa8, 0xc3, 0xed, 0x09, 0xd2, 0x17, 0x23, 0xed, 0x46, 0xed, 0xb6, 0x6e,
        0xfc, 0x83, 0xe7, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x31, 0x39, 0x31,
        0x32, 0x30, 0x35, 0x33, 0x39, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x31, 0x30, 0x32, 0x36,
        0x31, 0x32, 0x30, 0x35, 0x33, 0x39, 0x5a, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x59, 0x30,
        0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xc2, 0x1e, 0x36, 0x25, 0x29, 0x48, 0xfa, 0x3b,
        0x96, 0x5a, 0x68, 0x98, 0x49, 0x92, 0xf9, 0x40, 0x37, 0x0e, 0x03, 0xf3, 0x1a, 0xec, 0xc3, 0xa4,
        0xfb, 0xaa, 0xc7, 0xe6, 0x1d, 0xe2, 0x70, 0xfd, 0xf4, 0x75, 0x50, 0x80, 0x4a, 0x1b, 0xa4, 0x43,
        0xe1, 0x34, 0xc4, 0x53, 0x30, 0xcd, 0x4b, 0x52, 0x17, 0xf9, 0x86, 0xbb, 0x72, 0x23, 0x09, 0x19,
        0x45, 0xd2, 0x08, 0xe8, 0x1a, 0x4f, 0xcf, 0xb0, 0xa3, 0x69, 0x30, 0x67, 0x30, 0x1d, 0x06, 0x03,
        0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x0d, 0x2d, 0x46, 0xfc, 0x78, 0xe6, 0xce, 0x32, 0x5c,
        0x68, 0x55, 0x50, 0xe0, 0x0b, 0x65, 0xf4, 0x5b, 0x7b, 0x44, 0xcc, 0x30, 0x1f, 0x06, 0x03, 0x55,
        0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x0d, 0x2d, 0x46, 0xfc, 0x78, 0xe6, 0xce, 0x32,
        0x5c, 0x68, 0x55, 0x50, 0xe0, 0x0b, 0x65, 0xf4, 0x5b, 0x7b, 0x44, 0xcc, 0x30, 0x0f, 0x06, 0x03,
        0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x14, 0x06,
        0x03, 0x55, 0x1d, 0x11, 0x04, 0x0d, 0x30, 0x0b, 0x82, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
        0x6f, 0x73, 0x74, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
        0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x5b, 0x28, 0x3b, 0xcb, 0x58, 0x62, 0x80, 0x53, 0x59, 0x18,
        0x7f, 0xc0, 0x7b, 0xdf, 0x4d, 0x62, 0xa2, 0x37, 0x5d, 0x43, 0xe4, 0x21, 0x64, 0x5b, 0xa6, 0x8b,
        0xe3, 0x5c, 0x4d, 0x5d, 0x0a, 0x35, 0x02, 0x21, 0x00, 0xa9, 0x22, 0x43, 0x13, 0x1a, 0x73, 0xa2,
        0xfc, 0x3b, 0xf9, 0xc0, 0xf1, 0x78, 0x3e, 0x0a, 0x58, 0xfd, 0x5b, 0xfe, 0x0a, 0x80, 0x36, 0x64,
        0x7b, 0xb0, 0x01, 0xef, 0x09, 0x1c, 0xfc, 0x27, 0x18,
    ];

    const TEST_KEY_DER: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
        0x01, 0x01, 0x04, 0x20, 0x7f, 0x29, 0xbc, 0x4f, 0x23, 0x2d, 0x8e, 0x62, 0xc3, 0xfc, 0x0c, 0x71,
        0xd5, 0x9f, 0x70, 0xa2, 0x2c, 0x03, 0xbd, 0x0b, 0xce, 0x43, 0x69, 0xd9, 0x63, 0x97, 0xf3, 0xe0,
        0x83, 0x70, 0x0f, 0x50, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xc2, 0x1e, 0x36, 0x25, 0x29, 0x48,
        0xfa, 0x3b, 0x96, 0x5a, 0x68, 0x98, 0x49, 0x92, 0xf9, 0x40, 0x37, 0x0e, 0x03, 0xf3, 0x1a, 0xec,
        0xc3, 0xa4, 0xfb, 0xaa, 0xc7, 0xe6, 0x1d, 0xe2, 0x70, 0xfd, 0xf4, 0x75, 0x50, 0x80, 0x4a, 0x1b,
        0xa4, 0x43, 0xe1, 0x34, 0xc4, 0x53, 0x30, 0xcd, 0x4b, 0x52, 0x17, 0xf9, 0x86, 0xbb, 0x72, 0x23,
        0x09, 0x19, 0x45, 0xd2, 0x08, 0xe8, 0x1a, 0x4f, 0xcf, 0xb0,
    ];

    #[test]
    fn test_build_tg_proxy_url_formats_dd_secret() {
        let url = build_tg_proxy_url("127.0.0.1", 1443, "0123456789abcdef0123456789abcdef");
        assert_eq!(
            url,
            "tg://proxy?server=127.0.0.1&port=1443&secret=dd0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_build_tg_proxy_url_does_not_double_prefix_dd_secret() {
        let url = build_tg_proxy_url("127.0.0.1", 1443, "dd0123456789abcdef0123456789abcdef");
        assert_eq!(
            url,
            "tg://proxy?server=127.0.0.1&port=1443&secret=dd0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_dc_check_report_serializes_to_json() {
        let report = DcCheckReport {
            dc_results: vec![DcProbe {
                dc: 2,
                ip: "149.154.167.51".to_string(),
                tcp_ok: true,
                wss_ok: true,
                reachable: true,
                latency_ms: Some(42),
                detail: "ok".to_string(),
            }],
            cf_results: vec![
                CfProbe {
                    domain: "works.co.uk".to_string(),
                    state: CfServerState::Works,
                    latency_ms: Some(55),
                    detail: "ok".to_string(),
                },
                CfProbe {
                    domain: "busy.co.uk".to_string(),
                    state: CfServerState::Busy,
                    latency_ms: Some(70),
                    detail: "http 429".to_string(),
                },
                CfProbe {
                    domain: "fails.co.uk".to_string(),
                    state: CfServerState::Fails,
                    latency_ms: None,
                    detail: "timeout".to_string(),
                },
            ],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["dc_results"][0]["dc"], 2);
        assert_eq!(json["dc_results"][0]["tcp_ok"], true);
        assert_eq!(json["dc_results"][0]["wss_ok"], true);
        assert_eq!(json["dc_results"][0]["reachable"], true);
        assert_eq!(json["cf_results"][0]["state"], "works");
        assert_eq!(json["cf_results"][1]["state"], "busy");
        assert_eq!(json["cf_results"][2]["state"], "fails");
    }

    #[test]
    fn test_resolve_or_persist_secret_persists_with_0600_and_reuses_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("tgproxy-state");
        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.secret.clear();

        let first = resolve_or_persist_secret(&cfg, &state_dir).unwrap();
        assert_eq!(first.len(), 32);
        assert!(hex::decode(&first).is_ok());

        let secret_file = state_dir.join("secret");
        assert!(secret_file.is_file());
        let mode = std::fs::metadata(&secret_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected mode 0600, got {:o}", mode);

        let second = resolve_or_persist_secret(&cfg, &state_dir).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn test_resolve_or_persist_secret_prefers_config_secret_and_regenerates_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("tgproxy-state");

        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.secret = "0123456789abcdef0123456789abcdef".to_string();
        assert_eq!(
            resolve_or_persist_secret(&cfg, &state_dir).unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
        assert!(!state_dir.join("secret").exists());

        cfg.tgproxy.secret.clear();
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("secret"), "corrupted-short").unwrap();
        let regenerated = resolve_or_persist_secret(&cfg, &state_dir).unwrap();
        assert_eq!(regenerated.len(), 32);
        assert!(hex::decode(&regenerated).is_ok());
        assert_eq!(
            resolve_or_persist_secret(&cfg, &state_dir).unwrap(),
            regenerated
        );
    }

    #[test]
    fn test_resolve_dc_target_ip_uses_override_then_default() {
        let map = tgwsproxy::proxy::parse_cidr_pool("2:149.154.167.220,4:149.154.167.220");
        assert_eq!(resolve_dc_target_ip(2, &map), "149.154.167.220");
        assert_eq!(resolve_dc_target_ip(1, &map), "149.154.175.50");
        assert_eq!(resolve_dc_target_ip(5, &map), "149.154.171.5");
    }

    #[test]
    fn test_collect_cf_domains_includes_pinned_first_and_deduplicates() {
        let defaults = tgwsproxy::cfproxy::default_cfproxy_domains();
        assert!(!defaults.is_empty());

        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.pinned_cf_domain = "custom.example.workers.dev.".to_string();
        let collected = collect_cf_domains(&cfg);
        assert_eq!(collected[0], "custom.example.workers.dev");
        assert_eq!(collected.len(), defaults.len() + 1);

        cfg.tgproxy.pinned_cf_domain = defaults[0].clone();
        let deduped = collect_cf_domains(&cfg);
        assert_eq!(deduped[0], defaults[0]);
        assert_eq!(deduped.len(), defaults.len());
    }

    #[test]
    fn test_collect_cf_domains_preserves_pinned_com_domain_verbatim() {
        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.pinned_cf_domain = "  Proxy.Example.COM. ".to_string();
        let collected = collect_cf_domains(&cfg);
        assert_eq!(collected[0], "proxy.example.com");
    }

    #[test]
    fn test_classify_cf_error_maps_429_to_busy_and_others_to_fails() {
        let busy_err = WsError::Handshake(WsHandshakeError {
            status_code: 429,
            status_line: "HTTP/1.1 429 Too Many Requests".to_string(),
            headers: HashMap::new(),
            location: String::new(),
        });
        let busy = classify_cf_error("example.co.uk".to_string(), 88, Some(busy_err));
        assert_eq!(busy.state, CfServerState::Busy);
        assert_eq!(busy.latency_ms, Some(88));
        assert_eq!(busy.detail, "http 429");

        let timeout_fail =
            classify_cf_error("example.co.uk".to_string(), 5000, Some(WsError::Timeout));
        assert_eq!(timeout_fail.state, CfServerState::Fails);
        assert_eq!(timeout_fail.latency_ms, None);
        assert_eq!(timeout_fail.detail, "timeout");
    }

    #[tokio::test]
    async fn test_probe_tls_ws_respects_tls_verify_against_self_signed_server() {
        let cert = CertificateDer::from(TEST_CERT_DER.to_vec());
        let key = PrivateKeyDer::Pkcs8(TEST_KEY_DER.to_vec().into());
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        let mut buf = [0u8; 512];
                        let _ = tls.read(&mut buf).await;
                        let _ = tls
                            .write_all(
                                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                            )
                            .await;
                    }
                });
            }
        });

        let verified_res =
            probe_tls_ws_addr(addr, "localhost", true, Duration::from_secs(2)).await;
        let err = verified_res.unwrap_err();
        assert!(err.tcp_ok, "TCP connect should succeed before TLS verification failure");
        assert!(
            err.detail.starts_with("tls:"),
            "expected TLS verification failure, got: {}",
            err.detail
        );

        let insecure_res =
            probe_tls_ws_addr(addr, "localhost", false, Duration::from_secs(2)).await;
        assert!(
            insecure_res.is_ok(),
            "expected tls_verify=false to complete WS upgrade, got: {:?}",
            insecure_res
        );

        server_task.abort();
    }
}
