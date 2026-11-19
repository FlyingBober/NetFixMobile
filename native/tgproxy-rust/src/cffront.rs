use crate::config::{now_unix_f64, CFPROXY_DIAL_PHASE_TIMEOUT, DC_FAIL_UNTIL};
use crate::ws::{is_http_status_error, ws_connect_once, ws_connect_plain, RawWebSocket, WsError};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const DIRECT_FAST_TIMEOUT: f64 = 1.8;
pub const DIRECT_FAST_COOLDOWN: f64 = 20.0;
pub const DIRECT_RACE_HEAD_START: Duration = Duration::from_millis(600);

static FRONT_IPS: Lazy<RwLock<Vec<String>>> = Lazy::new(|| RwLock::new(Vec::new()));
static LAST_WORKING_IP: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));
static FAILED_DIRECT_KEYS: Lazy<RwLock<HashSet<(i32, i32)>>> =
    Lazy::new(|| RwLock::new(HashSet::new()));
static CHECKING_DIRECT: Lazy<Mutex<HashSet<(i32, i32)>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

static PLAIN_FIRST: AtomicBool = AtomicBool::new(false);
static DIRECT_FAST_FAIL: AtomicBool = AtomicBool::new(false);

/// Returns whether any validated Cloudflare front IPs are currently configured.
pub fn enabled() -> bool {
    !FRONT_IPS.read().is_empty()
}

/// Returns whether fast-fail mode for direct Telegram DC connections is enabled.
pub fn direct_fast_fail() -> bool {
    DIRECT_FAST_FAIL.load(Ordering::Relaxed)
}

/// Enables or disables fast-fail mode for direct Telegram DC connections.
pub fn set_direct_fast_fail(enabled: bool) {
    DIRECT_FAST_FAIL.store(enabled, Ordering::Relaxed);
}

/// Sets whether `cf_ws_connect` attempts plain HTTP (:80) before TLS (:443).
pub fn set_plain_first(enabled: bool) {
    PLAIN_FIRST.store(enabled, Ordering::Relaxed);
}

/// Replaces the configured Cloudflare front IP list, keeping only valid, unique IP addresses.
pub fn set_front_ips(ips: Vec<String>) {
    let mut seen = HashSet::new();
    let mut valid = Vec::new();
    for raw in ips {
        let trimmed = raw.trim();
        if let Ok(parsed) = trimmed.parse::<IpAddr>() {
            let normalized = parsed.to_string();
            if seen.insert(normalized.clone()) {
                valid.push(normalized);
            }
        }
    }

    {
        let mut last = LAST_WORKING_IP.write();
        if let Some(prev) = last.as_ref() {
            if !valid.iter().any(|ip| ip == prev) {
                *last = None;
            }
        }
    }

    *FRONT_IPS.write() = valid;
}

/// Clears network-dependent front IP and direct-reachability state.
pub fn forget_network_state() {
    FRONT_IPS.write().clear();
    *LAST_WORKING_IP.write() = None;
    FAILED_DIRECT_KEYS.write().clear();
    CHECKING_DIRECT.lock().clear();
}

/// Returns `true` if the given `(dc, is_media)` key has not recently failed direct dial.
pub fn direct_ok(key: (i32, i32)) -> bool {
    !FAILED_DIRECT_KEYS.read().contains(&key)
}

/// Marks the given `(dc, is_media)` key as reachable via direct connection.
pub fn mark_direct_ok(key: (i32, i32)) {
    FAILED_DIRECT_KEYS.write().remove(&key);
}

/// Marks the given `(dc, is_media)` key as failed via direct connection.
pub fn forget_direct_ok(key: (i32, i32)) {
    FAILED_DIRECT_KEYS.write().insert(key);
}

/// Spawns a background probe to check whether direct WS connectivity has recovered for `dc_key`.
pub fn check_direct_in_background(dc_key: (i32, i32), target: String, domains: Vec<String>) {
    if target.is_empty() || domains.is_empty() {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    if !CHECKING_DIRECT.lock().insert(dc_key) {
        return;
    }

    handle.spawn(async move {
        struct CheckingGuard((i32, i32));
        impl Drop for CheckingGuard {
            fn drop(&mut self) {
                CHECKING_DIRECT.lock().remove(&self.0);
            }
        }
        let _guard = CheckingGuard(dc_key);

        let (ws_opt, _, _) =
            crate::proxy::connect_direct_ws(&target, &domains, DIRECT_FAST_TIMEOUT).await;
        if let Some(ws) = ws_opt {
            mark_direct_ok(dc_key);
            ws.close().await;
        } else {
            DC_FAIL_UNTIL
                .write()
                .insert(dc_key, now_unix_f64() + DIRECT_FAST_COOLDOWN);
        }
    });
}

/// Connects to a Cloudflare WebSocket endpoint via `ip`, preferring plain HTTP when `PLAIN_FIRST` is enabled.
pub async fn cf_ws_connect(
    ip: &str,
    domain: &str,
    path: &str,
    timeout: Duration,
) -> Result<RawWebSocket, WsError> {
    let path = if path.is_empty() { "/apiws" } else { path };
    if PLAIN_FIRST.load(Ordering::Relaxed) {
        match ws_connect_plain(ip, domain, path, timeout).await {
            Ok(ws) => return Ok(ws),
            Err(e) if is_http_status_error(&e, 429) => return Err(e),
            Err(_) => {}
        }
    }
    ws_connect_once(ip, domain, path, timeout).await
}

/// Attempts to connect using the last known working Cloudflare front IP.
pub async fn connect_known(domain: &str, path: &str) -> Option<(RawWebSocket, String)> {
    let known = LAST_WORKING_IP.read().clone()?;
    if !FRONT_IPS.read().iter().any(|ip| ip == &known) {
        return None;
    }
    match cf_ws_connect(&known, domain, path, CFPROXY_DIAL_PHASE_TIMEOUT).await {
        Ok(ws) => Some((ws, known)),
        Err(_) => {
            let mut last = LAST_WORKING_IP.write();
            if last.as_deref() == Some(known.as_str()) {
                *last = None;
            }
            None
        }
    }
}

/// Races all configured Cloudflare front IPs up to `CFPROXY_DIAL_PHASE_TIMEOUT` and caches the winner.
pub async fn connect_any(domain: &str, path: &str) -> Option<(RawWebSocket, String)> {
    let ips = FRONT_IPS.read().clone();
    if ips.is_empty() {
        return None;
    }

    let mut set = tokio::task::JoinSet::new();
    for ip in ips {
        let dom = domain.to_string();
        let p = path.to_string();
        set.spawn(async move {
            match cf_ws_connect(&ip, &dom, &p, CFPROXY_DIAL_PHASE_TIMEOUT).await {
                Ok(ws) => Some((ws, ip)),
                Err(_) => None,
            }
        });
    }

    let deadline = tokio::time::Instant::now() + CFPROXY_DIAL_PHASE_TIMEOUT;
    loop {
        match tokio::time::timeout_at(deadline, set.join_next()).await {
            Ok(Some(Ok(Some((ws, ip))))) => {
                *LAST_WORKING_IP.write() = Some(ip.clone());
                set.abort_all();
                return Some((ws, ip));
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => {
                set.abort_all();
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn test_front_ips_and_direct_state_lifecycle() {
        let _guard = TEST_LOCK.lock();
        forget_network_state();
        set_front_ips(vec!["1.0.0.1".into(), "invalid-ip".into()]);
        assert!(enabled());
        let key = (2, 0);
        assert!(direct_ok(key));
        forget_direct_ok(key);
        assert!(!direct_ok(key));
        mark_direct_ok(key);
        assert!(direct_ok(key));
        forget_network_state();
        assert!(!enabled());
    }

    #[test]
    fn test_fast_fail_toggle() {
        let _guard = TEST_LOCK.lock();
        set_direct_fast_fail(true);
        assert!(direct_fast_fail());
        set_direct_fast_fail(false);
        assert!(!direct_fast_fail());
    }

    #[test]
    fn test_check_direct_in_background_outside_runtime_is_safe() {
        let _guard = TEST_LOCK.lock();
        forget_network_state();
        check_direct_in_background((2, 0), "149.154.167.51".into(), vec!["kws2.web.telegram.org".into()]);
        assert!(!CHECKING_DIRECT.lock().contains(&(2, 0)));
    }

    #[test]
    fn test_connect_known_and_any_return_none_when_unconfigured() {
        let _guard = TEST_LOCK.lock();
        forget_network_state();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            assert!(connect_known("example.com", "/apiws").await.is_none());
            assert!(connect_any("example.com", "/apiws").await.is_none());
        });
    }
}
