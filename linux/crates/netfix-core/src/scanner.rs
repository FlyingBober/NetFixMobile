use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::dpi::{
    build_ciadpi_command, build_nfqws_command, find_engine_binary, is_root, resolve_free_port,
    DpiRunner,
};
use crate::firewall::{detect_backend, FirewallGuard, FirewallSpec};
use crate::strategy::{default_ciadpi_presets, default_nfqws_presets, StrategyPreset};
use crate::{DpiEngineKind, NetfixConfig, NetfixError};

pub const QUICK_SITE_TIMEOUT_MS: u64 = 3_000;
pub const FULL_SITE_TIMEOUT_MS: u64 = 5_000;
pub const MAX_PARALLEL_SITE_CHECKS: usize = 30;
pub const FINALIST_COUNT: usize = 5;
pub const MAX_BODY_BYTES_WITHOUT_LENGTH: usize = 1024 * 1024;
pub const SCAN_PROXY_PORT: u16 = 1082;
pub const PROXY_READY_TIMEOUT_MS: u64 = 1_500;
pub const PROXY_READY_POLL_MS: u64 = 50;
pub const NFQWS_READY_DELAY_MS: u64 = 100;
pub const PAUSE_BETWEEN_STRATEGIES_MS: u64 = 150;
pub const SCAN_NFQWS_TABLE: &str = "netfix_scan";
pub const SCAN_NFQUEUE_NUM: u16 = 201;
pub const ECH_PROBE_HOST: &str = "cloudflare-ech.com";

pub const PROBE_VIDEO_ID: &str = "jNQXAC9IVRw";
pub const CHUNK_BYTES: usize = 131_072;
const PLAYER_URL: &str = "https://www.youtube.com/youtubei/v1/player?prettyPrint=false";
const CLIENT_NAME: &str = "IOS";
const CLIENT_ID: &str = "5";
const CLIENT_VERSION: &str = "20.10.4";
const USER_AGENT: &str =
    "com.google.ios.youtube/20.10.4 (iPhone16,2; U; CPU iOS 18_3_2 like Mac OS X;)";
const MIN_PING_MS: i64 = 20;
const APP_FALLBACK_WAIT_MS: i64 = 4_000;
const FALLBACK_SPEED_WEIGHT: f64 = 0.2;

pub const QUICK_SITES: &[&str] = &[
    "youtube.com",
    "i.ytimg.com",
    "yt3.ggpht.com",
    "youtubei.googleapis.com",
    "manifest.googlevideo.com",
    "rr1---sn-4axm-n8vs.googlevideo.com",
    "rr4---sn-q4flrnsl.googlevideo.com",
    "rr2---sn-q4fl6ndl.googlevideo.com",
    "discord.com",
    "gateway.discord.gg",
    "cdn.discordapp.com",
];

pub const TEST_SITES: &[&str] = &[
    "youtu.be",
    "youtube.com",
    "i.ytimg.com",
    "i9.ytimg.com",
    "yt3.ggpht.com",
    "yt4.ggpht.com",
    "googleapis.com",
    "jnn-pa.googleapis.com",
    "googleusercontent.com",
    "signaler-pa.youtube.com",
    "youtubei.googleapis.com",
    "manifest.googlevideo.com",
    "yt3.googleusercontent.com",
    "rr1---sn-4axm-n8vs.googlevideo.com",
    "rr1---sn-gvnuxaxjvh-o8ge.googlevideo.com",
    "rr1---sn-ug5onuxaxjvh-p3ul.googlevideo.com",
    "rr1---sn-ug5onuxaxjvh-n8v6.googlevideo.com",
    "rr4---sn-q4flrnsl.googlevideo.com",
    "rr10---sn-gvnuxaxjvh-304z.googlevideo.com",
    "rr14---sn-n8v7kn7r.googlevideo.com",
    "rr16---sn-axq7sn76.googlevideo.com",
    "rr1---sn-8ph2xajvh-5xge.googlevideo.com",
    "rr1---sn-gvnuxaxjvh-5gie.googlevideo.com",
    "rr12---sn-gvnuxaxjvh-bvwz.googlevideo.com",
    "rr5---sn-n8v7knez.googlevideo.com",
    "rr1---sn-u5uuxaxjvhg0-ocje.googlevideo.com",
    "rr2---sn-q4fl6ndl.googlevideo.com",
    "rr5---sn-gvnuxaxjvh-n8vk.googlevideo.com",
    "rr4---sn-jvhnu5g-c35d.googlevideo.com",
    "rr1---sn-q4fl6n6y.googlevideo.com",
    "rr2---sn-hgn7ynek.googlevideo.com",
    "rr1---sn-xguxaxjvh-gufl.googlevideo.com",
    "discord.com",
    "gateway.discord.gg",
    "cdn.discordapp.com",
    "media.discordapp.net",
    "discordapp.com",
    "dl.discordapp.net",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanPhase {
    Quick,
    Final,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamProbeResult {
    pub loaded: bool,
    pub first_byte_ms: i64,
    pub speed_kbps: u64,
    pub bytes: usize,
    pub failure: Option<String>,
    pub via_fallback: bool,
}

impl StreamProbeResult {
    pub fn failed(reason: impl Into<String>) -> Self {
        Self {
            loaded: false,
            first_byte_ms: -1,
            speed_kbps: 0,
            bytes: 0,
            failure: Some(reason.into()),
            via_fallback: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanProgress {
    pub phase: ScanPhase,
    pub index: usize,
    pub total: usize,
    pub strategy_name: String,
    pub strategy: String,
    pub passed: usize,
    pub site_total: usize,
    pub stream: Option<StreamProbeResult>,
    pub score: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyScanEntry {
    pub name: String,
    pub category: String,
    pub args: String,
    pub quick_passed: usize,
    pub quick_total: usize,
    pub full_passed: Option<usize>,
    pub full_total: Option<usize>,
    pub stream: Option<StreamProbeResult>,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub engine: DpiEngineKind,
    pub include_discord: bool,
    pub include_ech: bool,
    pub quick_total: usize,
    pub full_total: usize,
    pub finalist_count: usize,
    pub winner: Option<StrategyScanEntry>,
    pub entries: Vec<StrategyScanEntry>,
}

pub struct StreamChunkProbe;

impl StreamChunkProbe {
    pub fn player_request_body(video_id: &str) -> String {
        serde_json::json!({
            "videoId": video_id,
            "context": {
                "client": {
                    "clientName": CLIENT_NAME,
                    "clientVersion": CLIENT_VERSION,
                    "deviceMake": "Apple",
                    "deviceModel": "iPhone16,2",
                    "osName": "iPhone",
                    "osVersion": "18.3.2.22D82",
                    "hl": "en",
                    "gl": "US"
                }
            }
        })
        .to_string()
    }

    pub fn pick_chunk_url(player_json: &str) -> Option<String> {
        let root: serde_json::Value = serde_json::from_str(player_json).ok()?;
        let status = root
            .get("playabilityStatus")
            .and_then(|v| v.get("status"))
            .and_then(|v| v.as_str());
        if status != Some("OK") {
            return None;
        }
        let formats = root
            .get("streamingData")
            .and_then(|v| v.get("adaptiveFormats"))
            .and_then(|v| v.as_array())?;

        let mut best_url: Option<String> = None;
        let mut best_bitrate = u64::MAX;

        for format in formats {
            let Some(obj) = format.as_object() else {
                continue;
            };
            let url = obj.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let length = obj
                .get("contentLength")
                .and_then(parse_json_u64)
                .unwrap_or(0);
            let bitrate = obj
                .get("bitrate")
                .and_then(parse_json_u64)
                .unwrap_or(u64::MAX);
            let is_video = obj
                .get("mimeType")
                .and_then(|v| v.as_str())
                .is_some_and(|m| m.starts_with("video/"));

            if is_video
                && !url.is_empty()
                && length >= CHUNK_BYTES as u64
                && bitrate < best_bitrate
            {
                best_url = Some(url.to_string());
                best_bitrate = bitrate;
            }
        }

        best_url
    }

    pub fn fallback_node_url(chunk_url: &str) -> Option<String> {
        let (_, query) = chunk_url.split_once('?')?;
        let mut params = HashMap::new();
        for pair in query.split('&') {
            let (key, val) = pair.split_once('=').unwrap_or((pair, ""));
            if !key.is_empty() {
                params.insert(key, percent_decode_form(val));
            }
        }
        let backup_node = params
            .get("mn")?
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .nth(1)?;
        let server_index: u32 = params.get("fvip")?.trim().parse().ok()?;
        let after_scheme = chunk_url.split_once("://").map(|(_, rest)| rest)?;
        let path = after_scheme
            .split_once('/')
            .map(|(_, p)| p)
            .unwrap_or("");
        Some(format!(
            "https://rr{server_index}---{backup_node}.googlevideo.com/{path}"
        ))
    }

    pub fn score(reachable: usize, stream: Option<&StreamProbeResult>) -> f64 {
        let hosts_part = reachable as f64 * 100.0;
        let Some(stream) = stream else {
            return hosts_part;
        };
        if !stream.loaded {
            return hosts_part;
        }
        let ping = stream.first_byte_ms.max(MIN_PING_MS) as f64;
        let speed = stream.speed_kbps as f64;
        if stream.via_fallback {
            hosts_part
                + 1000.0 / (ping + APP_FALLBACK_WAIT_MS as f64)
                + speed * 0.5 * FALLBACK_SPEED_WEIGHT
        } else {
            hosts_part + 1000.0 / ping + speed * 0.5
        }
    }

    pub async fn probe(client: &reqwest::Client, timeout: Duration) -> StreamProbeResult {
        Self::probe_with_player_url(client, PLAYER_URL, timeout).await
    }

    async fn probe_with_player_url(
        client: &reqwest::Client,
        player_url: &str,
        timeout: Duration,
    ) -> StreamProbeResult {
        let chunk_url = match request_chunk_url(client, player_url, timeout).await {
            Ok(Some(url)) => url,
            Ok(None) => return StreamProbeResult::failed("player: no stream URL"),
            Err(reason) => return StreamProbeResult::failed(reason),
        };

        let primary = download_chunk(client, &chunk_url, timeout).await;
        if primary.loaded {
            return primary;
        }

        let Some(fallback_url) = Self::fallback_node_url(&chunk_url) else {
            return primary;
        };
        let mut retried = download_chunk(client, &fallback_url, timeout).await;
        if retried.loaded {
            retried.via_fallback = true;
            retried
        } else {
            primary
        }
    }
}

pub fn pick_chunk_url(player_json: &str) -> Option<String> {
    StreamChunkProbe::pick_chunk_url(player_json)
}

pub fn fallback_node_url(chunk_url: &str) -> Option<String> {
    StreamChunkProbe::fallback_node_url(chunk_url)
}

pub fn score(reachable: usize, stream: Option<&StreamProbeResult>) -> f64 {
    StreamChunkProbe::score(reachable, stream)
}

pub fn quick_sites_for(include_ech: bool, include_discord: bool) -> Vec<&'static str> {
    select_sites(QUICK_SITES, include_ech, include_discord)
}

pub fn test_sites_for(include_ech: bool, include_discord: bool) -> Vec<&'static str> {
    select_sites(TEST_SITES, include_ech, include_discord)
}

fn select_sites(
    base: &'static [&'static str],
    include_ech: bool,
    include_discord: bool,
) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = if include_discord {
        base.to_vec()
    } else {
        base.iter()
            .copied()
            .filter(|host| !host.contains("discord"))
            .collect()
    };
    if include_ech {
        out.push(ECH_PROBE_HOST);
    }
    out
}

/// Builds the isolated `netfix_scan` NFQUEUE `201` firewall specification for `nfqws` scans.
pub fn build_scan_firewall_spec(cfg: &NetfixConfig) -> FirewallSpec {
    FirewallSpec::for_nfqws(
        SCAN_NFQWS_TABLE,
        SCAN_NFQUEUE_NUM,
        cfg.dpi.fwmark,
        cfg.dpi.game_filter,
        crate::IpsetMode::Any,
        vec![],
        vec![],
    )
}

/// Scans strategies in two phases (quick screening -> finalist full test + YouTube stream probe).
pub async fn scan_strategies(
    cfg: &NetfixConfig,
    engine: DpiEngineKind,
    include_discord: bool,
    include_ech: bool,
    on_progress: impl Fn(ScanProgress),
) -> Result<ScanReport, NetfixError> {
    let (_tx, rx) = watch::channel(false);
    scan_strategies_cancellable(cfg, engine, include_discord, include_ech, rx, on_progress).await
}

/// Scans strategies in two phases and aborts immediately when `shutdown` becomes `true`.
pub async fn scan_strategies_cancellable(
    cfg: &NetfixConfig,
    engine: DpiEngineKind,
    include_discord: bool,
    include_ech: bool,
    mut shutdown: watch::Receiver<bool>,
    on_progress: impl Fn(ScanProgress),
) -> Result<ScanReport, NetfixError> {
    cfg.validate()?;

    if engine == DpiEngineKind::Nfqws && !is_root() {
        return Err(NetfixError::PermissionDenied(
            "root privileges (euid 0 / CAP_NET_ADMIN) are required to scan nfqws strategies".into(),
        ));
    }
    if *shutdown.borrow() {
        return Err(NetfixError::Runtime("scan cancelled by signal".into()));
    }

    let bin = find_engine_binary(engine_bin_name(engine))?;
    let mut nfqws_guard = if engine == DpiEngineKind::Nfqws {
        let kind = detect_backend()?;
        let spec = build_scan_firewall_spec(cfg);
        let guard = FirewallGuard::new(kind, spec);
        guard.apply()?;
        Some(guard)
    } else {
        None
    };

    let presets = match engine {
        DpiEngineKind::Ciadpi => default_ciadpi_presets(),
        DpiEngineKind::Nfqws => default_nfqws_presets(),
    };

    let quick_urls: Vec<String> = quick_sites_for(include_ech, include_discord)
        .into_iter()
        .map(|host| format!("https://{host}"))
        .collect();
    let full_urls: Vec<String> = test_sites_for(include_ech, include_discord)
        .into_iter()
        .map(|host| format!("https://{host}"))
        .collect();

    let scan_res = scan_presets_with_cancellable(
        cfg,
        engine,
        &bin,
        &presets,
        &quick_urls,
        &full_urls,
        include_discord,
        include_ech,
        Some(PLAYER_URL),
        &mut shutdown,
        &on_progress,
    )
    .await;

    if let Some(guard) = nfqws_guard.take() {
        let cleanup_res = guard.cleanup();
        if scan_res.is_ok() {
            cleanup_res?;
        }
    }

    scan_res
}

#[allow(clippy::too_many_arguments)]
async fn scan_presets_with_cancellable(
    cfg: &NetfixConfig,
    engine: DpiEngineKind,
    bin: &Path,
    presets: &[StrategyPreset],
    quick_urls: &[String],
    full_urls: &[String],
    include_discord: bool,
    include_ech: bool,
    player_url: Option<&str>,
    shutdown: &mut watch::Receiver<bool>,
    on_progress: &impl Fn(ScanProgress),
) -> Result<ScanReport, NetfixError> {
    let quick_timeout = Duration::from_millis(QUICK_SITE_TIMEOUT_MS);
    let full_timeout = Duration::from_millis(FULL_SITE_TIMEOUT_MS);
    let quick_total = quick_urls.len();
    let full_total = full_urls.len();

    let mut entries = Vec::with_capacity(presets.len());

    for (idx, preset) in presets.iter().enumerate() {
        if *shutdown.borrow() {
            return Err(NetfixError::Runtime("scan cancelled by signal".into()));
        }
        let quick_passed = run_with_strategy_cancellable(
            cfg,
            engine,
            bin,
            &preset.args,
            shutdown,
            |proxy_port| {
                let urls = quick_urls;
                async move {
                    let Ok(client) = build_http_client(proxy_port, quick_timeout) else {
                        return 0;
                    };
                    count_fully_reachable_urls(&client, urls, quick_timeout).await
                }
            },
        )
        .await?;

        let entry = StrategyScanEntry {
            name: preset.name.clone(),
            category: preset.category.clone(),
            args: preset.args.clone(),
            quick_passed,
            quick_total,
            full_passed: None,
            full_total: None,
            stream: None,
            score: 0.0,
        };
        on_progress(ScanProgress {
            phase: ScanPhase::Quick,
            index: idx,
            total: presets.len(),
            strategy_name: entry.name.clone(),
            strategy: entry.args.clone(),
            passed: quick_passed,
            site_total: quick_total,
            stream: None,
            score: None,
        });
        entries.push(entry);
    }

    let mut finalist_indices: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.quick_passed > 0)
        .map(|(i, _)| i)
        .collect();
    finalist_indices.sort_by(|&a, &b| entries[b].quick_passed.cmp(&entries[a].quick_passed));
    finalist_indices.truncate(FINALIST_COUNT);
    let finalist_count = finalist_indices.len();

    let mut best_index: Option<usize> = None;
    let mut best_score = 0.0_f64;

    for (pos, &entry_idx) in finalist_indices.iter().enumerate() {
        if *shutdown.borrow() {
            return Err(NetfixError::Runtime("scan cancelled by signal".into()));
        }
        let strategy_args = entries[entry_idx].args.clone();
        let (full_passed, stream) = run_with_strategy_cancellable(
            cfg,
            engine,
            bin,
            &strategy_args,
            shutdown,
            |proxy_port| {
                let urls = full_urls;
                async move {
                    let Ok(client) = build_http_client(proxy_port, full_timeout) else {
                        return (0, None);
                    };
                    let passed = count_fully_reachable_urls(&client, urls, full_timeout).await;
                    let stream_res = match (passed > 0, player_url) {
                        (true, Some(p_url)) => {
                            Some(StreamChunkProbe::probe_with_player_url(&client, p_url, full_timeout).await)
                        }
                        _ => None,
                    };
                    (passed, stream_res)
                }
            },
        )
        .await?;

        let strategy_score = if full_passed > 0 {
            StreamChunkProbe::score(full_passed, stream.as_ref())
        } else {
            0.0
        };

        let entry = &mut entries[entry_idx];
        entry.full_passed = Some(full_passed);
        entry.full_total = Some(full_total);
        entry.stream = stream.clone();
        entry.score = strategy_score;

        if full_passed > 0 && strategy_score > best_score {
            best_score = strategy_score;
            best_index = Some(entry_idx);
        }

        on_progress(ScanProgress {
            phase: ScanPhase::Final,
            index: pos,
            total: finalist_count,
            strategy_name: entry.name.clone(),
            strategy: entry.args.clone(),
            passed: full_passed,
            site_total: full_total,
            stream,
            score: Some(strategy_score),
        });
    }

    let winner = best_index.map(|i| entries[i].clone());

    Ok(ScanReport {
        engine,
        include_discord,
        include_ech,
        quick_total,
        full_total,
        finalist_count,
        winner,
        entries,
    })
}

async fn wait_until_cancelled(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
    std::future::pending::<()>().await;
}

async fn run_with_strategy_cancellable<T, F, Fut>(
    cfg: &NetfixConfig,
    engine: DpiEngineKind,
    bin: &Path,
    strategy: &str,
    shutdown: &mut watch::Receiver<bool>,
    check: F,
) -> Result<T, NetfixError>
where
    T: Default,
    F: FnOnce(Option<u16>) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    if *shutdown.borrow() {
        return Err(NetfixError::Runtime("scan cancelled by signal".into()));
    }

    let (cmd, bound_port) = match engine {
        DpiEngineKind::Ciadpi => {
            let port = resolve_free_port("127.0.0.1", SCAN_PROXY_PORT);
            let mut scan_cfg = cfg.clone();
            scan_cfg.dpi.socks_bind = "127.0.0.1".to_string();
            let Ok(cmd) = build_ciadpi_command(&scan_cfg, bin, strategy, port, false) else {
                return Ok(T::default());
            };
            (cmd, Some(port))
        }
        DpiEngineKind::Nfqws => {
            let Ok(cmd) = build_nfqws_command(cfg, bin, strategy, SCAN_NFQUEUE_NUM) else {
                return Ok(T::default());
            };
            (cmd, None)
        }
    };

    let Ok(mut runner) = DpiRunner::spawn_command(engine, cmd, None, bound_port) else {
        return Ok(T::default());
    };

    let ready_res = tokio::select! {
        biased;
        _ = wait_until_cancelled(shutdown) => Err(NetfixError::Runtime("scan cancelled by signal".into())),
        ready = async {
            match bound_port {
                Some(port) => wait_for_proxy_port(&mut runner, port).await,
                None => wait_for_nfqws_ready(&mut runner).await,
            }
        } => Ok(ready),
    };

    let ready = match ready_res {
        Ok(ready) => ready,
        Err(err) => {
            let _ = runner.stop().await;
            return Err(err);
        }
    };

    let result = if ready {
        tokio::select! {
            biased;
            _ = wait_until_cancelled(shutdown) => {
                let _ = runner.stop().await;
                return Err(NetfixError::Runtime("scan cancelled by signal".into()));
            }
            res = check(bound_port) => res,
        }
    } else {
        T::default()
    };

    let _ = runner.stop().await;
    tokio::select! {
        biased;
        _ = wait_until_cancelled(shutdown) => Err(NetfixError::Runtime("scan cancelled by signal".into())),
        _ = tokio::time::sleep(Duration::from_millis(PAUSE_BETWEEN_STRATEGIES_MS)) => Ok(result),
    }
}

async fn wait_for_proxy_port(runner: &mut DpiRunner, port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_millis(PROXY_READY_TIMEOUT_MS);
    while Instant::now() < deadline {
        if matches!(runner.try_wait(), Ok(Some(_))) {
            return false;
        }
        let connected = tokio::time::timeout(
            Duration::from_millis(100),
            TcpStream::connect(("127.0.0.1", port)),
        )
        .await;
        if matches!(connected, Ok(Ok(_))) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(PROXY_READY_POLL_MS)).await;
    }
    false
}

async fn wait_for_nfqws_ready(runner: &mut DpiRunner) -> bool {
    tokio::time::sleep(Duration::from_millis(NFQWS_READY_DELAY_MS)).await;
    !matches!(runner.try_wait(), Ok(Some(_)))
}

fn build_http_client(
    proxy_port: Option<u16>,
    timeout: Duration,
) -> Result<reqwest::Client, NetfixError> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(timeout)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(10));

    if let Some(port) = proxy_port {
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
            .map_err(|err| NetfixError::Runtime(format!("invalid SOCKS5 proxy: {err}")))?;
        builder = builder.proxy(proxy);
    }

    builder
        .build()
        .map_err(|err| NetfixError::Runtime(format!("failed to build HTTP client: {err}")))
}

async fn count_fully_reachable_urls(
    client: &reqwest::Client,
    urls: &[String],
    timeout: Duration,
) -> usize {
    let sem = Arc::new(Semaphore::new(MAX_PARALLEL_SITE_CHECKS));
    let mut set = JoinSet::new();

    for url in urls {
        let client = client.clone();
        let url = url.clone();
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return false;
            };
            check_url_reachable(&client, &url, timeout).await
        });
    }

    let mut passed = 0usize;
    while let Some(res) = set.join_next().await {
        if matches!(res, Ok(true)) {
            passed += 1;
        }
    }
    passed
}

async fn check_url_reachable(client: &reqwest::Client, url: &str, timeout: Duration) -> bool {
    let fut = async {
        let mut resp = match client
            .get(url)
            .header(reqwest::header::CONNECTION, "close")
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(_) => return false,
        };

        let declared_length = resp.content_length();
        let read_limit = declared_length
            .filter(|&len| len > 0)
            .unwrap_or(MAX_BODY_BYTES_WITHOUT_LENGTH as u64);
        let mut received = 0_u64;

        while received < read_limit {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    received = received.saturating_add(chunk.len() as u64);
                }
                Ok(None) => break,
                Err(_) => return false,
            }
        }

        match declared_length {
            Some(len) if len > 0 => received >= len,
            _ => true,
        }
    };

    tokio::time::timeout(timeout, fut).await.unwrap_or(false)
}

async fn request_chunk_url(
    client: &reqwest::Client,
    player_url: &str,
    timeout: Duration,
) -> Result<Option<String>, String> {
    let body = StreamChunkProbe::player_request_body(PROBE_VIDEO_ID);
    let fut = async {
        let resp = client
            .post(player_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header("X-YouTube-Client-Name", CLIENT_ID)
            .header("X-YouTube-Client-Version", CLIENT_VERSION)
            .header(reqwest::header::CONNECTION, "close")
            .body(body)
            .send()
            .await
            .map_err(|err| format!("player: {err}"))?;

        if !resp.status().is_success() {
            return Ok(None);
        }

        let text = resp
            .text()
            .await
            .map_err(|err| format!("player: {err}"))?;
        Ok(StreamChunkProbe::pick_chunk_url(&text))
    };

    tokio::time::timeout(timeout, fut)
        .await
        .unwrap_or_else(|_| Err("player: timeout".to_string()))
}

async fn download_chunk(
    client: &reqwest::Client,
    chunk_url: &str,
    timeout: Duration,
) -> StreamProbeResult {
    let fut = async {
        let range_header = format!("bytes=0-{}", CHUNK_BYTES - 1);
        let started = Instant::now();
        let mut resp = match client
            .get(chunk_url)
            .header(reqwest::header::RANGE, range_header)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .header(reqwest::header::CONNECTION, "close")
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => return StreamProbeResult::failed(format!("stream: {err}")),
        };

        let status = resp.status();
        if !status.is_success() {
            return StreamProbeResult::failed(format!("HTTP {}", status.as_u16()));
        }

        let mut received = 0usize;
        let mut first_byte_ms = -1_i64;

        while received < CHUNK_BYTES {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    if !chunk.is_empty() && first_byte_ms < 0 {
                        first_byte_ms = started.elapsed().as_millis() as i64;
                    }
                    let needed = CHUNK_BYTES - received;
                    received += chunk.len().min(needed);
                }
                Ok(None) => break,
                Err(err) => {
                    return StreamProbeResult {
                        loaded: false,
                        first_byte_ms: -1,
                        speed_kbps: 0,
                        bytes: received,
                        failure: Some(format!("stream: {err}, received {received} bytes")),
                        via_fallback: false,
                    };
                }
            }
        }

        if received < CHUNK_BYTES {
            return StreamProbeResult {
                loaded: false,
                first_byte_ms,
                speed_kbps: 0,
                bytes: received,
                failure: Some(format!(
                    "truncated at {received} of {CHUNK_BYTES} bytes"
                )),
                via_fallback: false,
            };
        }

        let total_ms = (started.elapsed().as_millis() as u64).max(1);
        let speed_kbps = (received as u64) * 1000 / 1024 / total_ms;
        StreamProbeResult {
            loaded: true,
            first_byte_ms: first_byte_ms.max(0),
            speed_kbps,
            bytes: received,
            failure: None,
            via_fallback: false,
        }
    };

    tokio::time::timeout(timeout, fut)
        .await
        .unwrap_or_else(|_| StreamProbeResult::failed("stream: timeout"))
}

fn engine_bin_name(engine: DpiEngineKind) -> &'static str {
    match engine {
        DpiEngineKind::Nfqws => "nfqws",
        DpiEngineKind::Ciadpi => "ciadpi",
    }
}

fn parse_json_u64(val: &serde_json::Value) -> Option<u64> {
    if let Some(n) = val.as_u64() {
        Some(n)
    } else if let Some(s) = val.as_str() {
        s.trim().parse::<u64>().ok()
    } else {
        None
    }
}

fn percent_decode_form(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{FirewallKind, IptablesBackend, NftablesBackend};
    use crate::ExitCode;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_pick_chunk_url_picks_lowest_bitrate_video_over_128kb() {
        let json = r#"{
          "playabilityStatus": { "status": "OK" },
          "streamingData": { "adaptiveFormats": [
            { "mimeType": "audio/mp4", "bitrate": 64000, "contentLength": "500000", "url": "https://a" },
            { "mimeType": "video/mp4", "bitrate": 500000, "contentLength": "500000", "url": "https://v500" },
            { "mimeType": "video/mp4", "bitrate": 200000, "contentLength": "500000", "url": "https://v200" },
            { "mimeType": "video/mp4", "bitrate": 100000, "contentLength": "1000", "url": "https://too-small" }
          ]}
        }"#;
        assert_eq!(pick_chunk_url(json).as_deref(), Some("https://v200"));
        assert_eq!(
            StreamChunkProbe::pick_chunk_url(json).as_deref(),
            Some("https://v200")
        );
    }

    #[test]
    fn test_pick_chunk_url_rejects_non_ok_playability_and_missing_formats() {
        let unplayable = r#"{
          "playabilityStatus": { "status": "ERROR" },
          "streamingData": { "adaptiveFormats": [
            { "mimeType": "video/mp4", "bitrate": 200000, "contentLength": "500000", "url": "https://v200" }
          ]}
        }"#;
        assert_eq!(pick_chunk_url(unplayable), None);
        assert_eq!(pick_chunk_url("not-json"), None);
    }

    #[test]
    fn test_fallback_node_url_parses_mn_and_fvip() {
        let url = "https://rr1---sn-4axm-n8vs.googlevideo.com/videoplayback?expire=1&mn=sn-4axm-n8vs%2Csn-q4fl6ndl&fvip=2&mime=video%2Fmp4";
        assert_eq!(
            fallback_node_url(url).as_deref(),
            Some("https://rr2---sn-q4fl6ndl.googlevideo.com/videoplayback?expire=1&mn=sn-4axm-n8vs%2Csn-q4fl6ndl&fvip=2&mime=video%2Fmp4")
        );

        let missing_backup =
            "https://rr1---sn-4axm-n8vs.googlevideo.com/videoplayback?mn=sn-4axm-n8vs&fvip=2";
        assert_eq!(fallback_node_url(missing_backup), None);
    }

    #[test]
    fn test_stream_score_matches_android_formula() {
        let ok = StreamProbeResult {
            loaded: true,
            first_byte_ms: 100,
            speed_kbps: 400,
            bytes: 131072,
            failure: None,
            via_fallback: false,
        };
        assert!((score(10, Some(&ok)) - 1210.0).abs() < 0.01);
        assert!((StreamChunkProbe::score(10, Some(&ok)) - 1210.0).abs() < 0.01);

        let fallback = StreamProbeResult {
            loaded: true,
            first_byte_ms: 100,
            speed_kbps: 400,
            bytes: 131072,
            failure: None,
            via_fallback: true,
        };
        assert!((score(10, Some(&fallback)) - 1040.2439).abs() < 0.01);

        let failed = StreamProbeResult::failed("timeout");
        assert!((score(10, Some(&failed)) - 1000.0).abs() < 0.01);
        assert!((score(10, None) - 1000.0).abs() < 0.01);
    }

    #[test]
    fn test_quick_sites_for_and_test_sites_for_flags() {
        let q_default = quick_sites_for(false, true);
        assert_eq!(q_default.len(), 11);
        assert!(q_default.contains(&"discord.com"));
        assert!(!q_default.contains(&ECH_PROBE_HOST));

        let q_ech = quick_sites_for(true, true);
        assert_eq!(q_ech.len(), 12);
        assert!(q_ech.contains(&ECH_PROBE_HOST));

        let q_no_discord_no_ech = quick_sites_for(false, false);
        assert_eq!(q_no_discord_no_ech.len(), 8);
        assert!(!q_no_discord_no_ech.iter().any(|h| h.contains("discord")));
        assert!(!q_no_discord_no_ech.contains(&ECH_PROBE_HOST));

        let q_no_discord_with_ech = quick_sites_for(true, false);
        assert_eq!(q_no_discord_with_ech.len(), 9);
        assert!(!q_no_discord_with_ech.iter().any(|h| h.contains("discord")));
        assert!(q_no_discord_with_ech.contains(&ECH_PROBE_HOST));

        let t_default = test_sites_for(false, true);
        assert_eq!(t_default.len(), 38);
        let t_ech = test_sites_for(true, true);
        assert_eq!(t_ech.len(), 39);
        assert!(t_ech.contains(&ECH_PROBE_HOST));
        let t_no_discord_no_ech = test_sites_for(false, false);
        assert_eq!(t_no_discord_no_ech.len(), 32);
        assert!(!t_no_discord_no_ech.iter().any(|h| h.contains("discord")));
        assert!(!t_no_discord_no_ech.contains(&ECH_PROBE_HOST));
        let t_no_discord_with_ech = test_sites_for(true, false);
        assert_eq!(t_no_discord_with_ech.len(), 33);
        assert!(!t_no_discord_with_ech.iter().any(|h| h.contains("discord")));
        assert!(t_no_discord_with_ech.contains(&ECH_PROBE_HOST));
    }

    #[test]
    fn test_player_request_body_matches_ios_context() {
        let body = StreamChunkProbe::player_request_body(PROBE_VIDEO_ID);
        let val: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(val["videoId"], PROBE_VIDEO_ID);
        assert_eq!(val["context"]["client"]["clientName"], "IOS");
        assert_eq!(val["context"]["client"]["clientVersion"], "20.10.4");
    }

    #[tokio::test]
    async fn test_nfqws_scan_rejects_non_root_with_permission_denied() {
        if unsafe { libc::geteuid() == 0 } {
            return;
        }
        let cfg = NetfixConfig::default();
        let err = scan_strategies(&cfg, DpiEngineKind::Nfqws, true, false, |_| {})
            .await
            .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::PermissionDenied);
    }

    #[test]
    fn test_scan_firewall_spec_uses_netfix_scan_nfqueue_201() {
        let cfg = NetfixConfig::default();
        let spec = build_scan_firewall_spec(&cfg);
        let nft = NftablesBackend::try_render_script(&spec).unwrap();
        assert!(nft.contains("add table inet netfix_scan"));
        assert!(nft.contains("queue num 201 bypass"));

        let nft_cleanup = NftablesBackend::try_render_cleanup(SCAN_NFQWS_TABLE).unwrap();
        assert!(nft_cleanup.contains("delete table inet netfix_scan"));

        let ipt = IptablesBackend::try_render_commands(&spec).unwrap();
        assert!(ipt
            .iter()
            .any(|cmd| cmd.contains(&"NETFIX_SCAN".to_string()) && cmd.contains(&"201".to_string())));

        let guard = FirewallGuard::new(FirewallKind::Nftables, spec);
        assert!(!guard.is_active());
    }

    #[test]
    fn test_scan_firewall_spec_ignores_loaded_ipset_mode_and_emits_queue_201() {
        let mut cfg = NetfixConfig::default();
        cfg.dpi.ipset_mode = crate::IpsetMode::Loaded;

        let spec = build_scan_firewall_spec(&cfg);
        assert_eq!(spec.ipset_mode, crate::IpsetMode::Any);

        let nft = NftablesBackend::try_render_script(&spec).unwrap();
        assert!(
            nft.contains("queue num 201 bypass"),
            "expected nftables scan script to include queue num 201 bypass, got:\n{nft}"
        );

        let ipt = IptablesBackend::try_render_commands(&spec).unwrap();
        assert!(
            ipt.iter()
                .any(|cmd| cmd.windows(2).any(|w| w == ["--queue-num", "201"])),
            "expected iptables scan commands to include --queue-num 201, got: {ipt:?}"
        );
    }

    #[tokio::test]
    async fn test_check_url_reachable_and_stream_probe_offline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");

                    match path {
                        "/ok" => {
                            let _ = sock
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
                                .await;
                        }
                        "/truncated" => {
                            let _ = sock
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort")
                                .await;
                        }
                        "/player" => {
                            let chunk_url = format!("http://{addr}/chunk");
                            let payload = serde_json::json!({
                                "playabilityStatus": { "status": "OK" },
                                "streamingData": { "adaptiveFormats": [{
                                    "mimeType": "video/mp4",
                                    "bitrate": 250000,
                                    "contentLength": "200000",
                                    "url": chunk_url
                                }]}
                            })
                            .to_string();
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                payload.len(),
                                payload
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                        }
                        "/chunk" => {
                            let header = format!(
                                "HTTP/1.1 206 Partial Content\r\nContent-Length: {CHUNK_BYTES}\r\nConnection: close\r\n\r\n"
                            );
                            let _ = sock.write_all(header.as_bytes()).await;
                            let payload = vec![0xAB_u8; CHUNK_BYTES];
                            let _ = sock.write_all(&payload).await;
                        }
                        _ => {
                            let _ = sock
                                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                .await;
                        }
                    }
                });
            }
        });

        let client = build_http_client(None, Duration::from_secs(2)).unwrap();
        let urls = vec![
            format!("http://{addr}/ok"),
            format!("http://{addr}/truncated"),
        ];
        let reached = count_fully_reachable_urls(&client, &urls, Duration::from_secs(2)).await;
        assert_eq!(reached, 1);

        let probe_res = StreamChunkProbe::probe_with_player_url(
            &client,
            &format!("http://{addr}/player"),
            Duration::from_secs(2),
        )
        .await;
        assert!(probe_res.loaded, "expected stream probe success: {probe_res:?}");
        assert_eq!(probe_res.bytes, CHUNK_BYTES);
        assert!(probe_res.first_byte_ms >= 0);
        assert!(!probe_res.via_fallback);

        server.abort();
    }

    #[tokio::test]
    async fn test_two_phase_scan_selects_top_finalists_and_serializes_report() {
        let dir = tempfile::tempdir().unwrap();
        let fake_engine = dir.path().join("fake-engine.sh");
        // Sleeps until killed; exits immediately if "--bad" is passed.
        std::fs::write(
            &fake_engine,
            "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = \"--bad\" ] && exit 1; done\nwhile true; do sleep 0.05; done\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake_engine, Permissions::from_mode(0o755)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                        .await;
                });
            }
        });

        let presets: Vec<StrategyPreset> = (0..7)
            .map(|i| StrategyPreset {
                name: format!("strat-{i}"),
                category: "general".into(),
                args: if i == 0 {
                    "--bad".into()
                } else {
                    format!("--dpi-desync=fake --dpi-desync-repeats={i}")
                },
                description: String::new(),
            })
            .collect();

        let cfg = NetfixConfig::default();
        let quick_urls = vec![format!("http://{addr}/q1")];
        let full_urls = vec![format!("http://{addr}/f1"), format!("http://{addr}/f2")];
        let events: Mutex<Vec<ScanProgress>> = Mutex::new(Vec::new());
        let (_tx, mut shutdown_rx) = watch::channel(false);

        let report = scan_presets_with_cancellable(
            &cfg,
            DpiEngineKind::Nfqws,
            &fake_engine,
            &presets,
            &quick_urls,
            &full_urls,
            true,
            false,
            None,
            &mut shutdown_rx,
            &|p| events.lock().unwrap().push(p),
        )
        .await
        .unwrap();

        server.abort();

        assert_eq!(report.entries.len(), 7);
        assert_eq!(report.entries[0].quick_passed, 0);
        assert_eq!(report.finalist_count, FINALIST_COUNT);
        let winner = report.winner.as_ref().expect("expected winner");
        assert_eq!(winner.full_passed, Some(2));
        assert!((winner.score - 200.0).abs() < 0.01);

        let recorded = events.lock().unwrap();
        assert_eq!(
            recorded.iter().filter(|p| p.phase == ScanPhase::Quick).count(),
            7
        );
        assert_eq!(
            recorded.iter().filter(|p| p.phase == ScanPhase::Final).count(),
            FINALIST_COUNT
        );

        let json_report = serde_json::to_string(&report).unwrap();
        assert!(json_report.contains("\"winner\""));
        let json_progress = serde_json::to_string(&recorded[0]).unwrap();
        assert!(json_progress.contains("\"phase\":\"quick\""));
    }

    #[tokio::test]
    async fn test_scan_cancellable_aborts_immediately_and_stops_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("child.pid");
        let fake_engine = dir.path().join("fake-engine.sh");
        std::fs::write(
            &fake_engine,
            format!(
                "#!/bin/sh\necho $$ > \"{}\"\ntrap 'exit 0' TERM\nwhile true; do sleep 0.05; done\n",
                pid_file.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake_engine, Permissions::from_mode(0o755)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept connections and stall forever to simulate slow site check.
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                held.push(sock);
            }
        });

        let presets: Vec<StrategyPreset> = (0..5)
            .map(|i| StrategyPreset {
                name: format!("strat-{i}"),
                category: "general".into(),
                args: format!("--dpi-desync=fake --dpi-desync-repeats={i}"),
                description: String::new(),
            })
            .collect();

        let cfg = NetfixConfig::default();
        let quick_urls = vec![format!("http://{addr}/slow")];
        let full_urls = vec![format!("http://{addr}/slow")];
        let (tx, mut rx) = watch::channel(false);

        let cancel_task = tokio::spawn(async move {
            for _ in 0..40 {
                if pid_file.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            tokio::time::sleep(Duration::from_millis(120)).await;
            let _ = tx.send(true);
        });

        let started = Instant::now();
        let err = scan_presets_with_cancellable(
            &cfg,
            DpiEngineKind::Nfqws,
            &fake_engine,
            &presets,
            &quick_urls,
            &full_urls,
            true,
            false,
            None,
            &mut rx,
            &|_| {},
        )
        .await
        .unwrap_err();
        let elapsed = started.elapsed();

        let _ = cancel_task.await;
        server.abort();

        assert_eq!(err.exit_code(), ExitCode::Runtime);
        assert!(
            elapsed < Duration::from_secs(5),
            "expected immediate cancellation, took {elapsed:?}"
        );

        let pid_str = std::fs::read_to_string(dir.path().join("child.pid")).unwrap();
        let pid: libc::pid_t = pid_str.trim().parse().unwrap();
        let alive = unsafe { libc::kill(pid, 0) == 0 };
        assert!(!alive, "expected child process {pid} to be stopped on cancellation");
    }
}
