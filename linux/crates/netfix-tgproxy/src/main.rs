use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use clap::Parser;
use netfix_core::{tg, NetfixConfig, NetfixError};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(name = "netfix-tgproxy", about = "NetFix Telegram MTProto WS proxy daemon")]
struct Cli {
    /// Path to config.toml (defaults to NETFIX_CONFIG or /etc/netfix/config.toml)
    #[arg(long)]
    config: Option<PathBuf>,
}

/// Validates and applies `NetfixConfig` settings into `tgwsproxy` runtime globals.
fn apply_tgproxy_config(
    cfg: &NetfixConfig,
    state_dir: &Path,
) -> Result<(String, HashMap<i32, String>), NetfixError> {
    cfg.validate()?;
    let secret = tg::resolve_or_persist_secret(cfg, state_dir)?;
    let decoded = hex::decode(&secret)
        .map_err(|e| NetfixError::InvalidInput(format!("invalid tgproxy.secret: {e}")))?;
    if decoded.len() != 16 {
        return Err(NetfixError::InvalidInput(
            "tgproxy.secret must decode to 16 bytes".to_string(),
        ));
    }

    let verbose = cfg.general.log_level.eq_ignore_ascii_case("debug")
        || cfg.general.log_level.eq_ignore_ascii_case("trace");
    tgwsproxy::config::init_logging(verbose);

    tgwsproxy::config::TLS_VERIFY.store(cfg.tgproxy.tls_verify, Ordering::Relaxed);

    let pool_size = (cfg.tgproxy.pool_size as i32).clamp(2, 16);
    tgwsproxy::config::POOL_SIZE.store(pool_size, Ordering::Relaxed);

    tgwsproxy::config::CFPROXY_ENABLED.store(cfg.tgproxy.cf_enabled, Ordering::Relaxed);

    let cache_dir = if cfg.tgproxy.cache_dir.trim().is_empty() {
        tg::DEFAULT_TGPROXY_STATE_DIR.to_string()
    } else {
        cfg.tgproxy.cache_dir.trim().to_string()
    };
    let user_domain = cfg.tgproxy.pinned_cf_domain.trim().to_string();
    {
        let mut cf = tgwsproxy::config::CFPROXY.write();
        cf.cache_dir = cache_dir;
        cf.user_domain = user_domain.clone();
        if !user_domain.is_empty() {
            cf.domains = vec![user_domain.clone()];
            cf.active = user_domain;
        }
    }

    *tgwsproxy::config::PROXY_SECRET.write() = secret.clone();

    tgwsproxy::cffront::set_front_ips(cfg.tgproxy.cf_front_ips.clone());
    tgwsproxy::cffront::set_plain_first(cfg.tgproxy.cf_plain_first);
    tgwsproxy::cfproxy::init_cfproxy_domains();

    let dc_opt_map = tgwsproxy::proxy::parse_cidr_pool(&cfg.tgproxy.dc_ips);
    Ok((secret, dc_opt_map))
}

async fn wait_for_shutdown_signal(cancel: CancellationToken) {
    let mut sigterm =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(stream) => Some(stream),
            Err(err) => {
                eprintln!("netfix-tgproxy: failed to register SIGTERM handler: {err}");
                None
            }
        };

    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            if let Err(err) = res {
                eprintln!("netfix-tgproxy: SIGINT listener error: {err}");
            }
        }
        _ = async {
            match sigterm.as_mut() {
                Some(stream) => {
                    let _ = stream.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        } => {}
        _ = cancel.cancelled() => return,
    }

    cancel.cancel();
}

async fn run_daemon(cli: Cli) -> Result<(), NetfixError> {
    let config_path = NetfixConfig::resolve_path(cli.config.as_deref());
    let cfg = NetfixConfig::load(&config_path)?;
    let (_secret, dc_opt_map) =
        apply_tgproxy_config(&cfg, Path::new(tg::DEFAULT_TGPROXY_STATE_DIR))?;

    let bind_ip: IpAddr = cfg.tgproxy.bind_ip.parse().map_err(|err| {
        NetfixError::InvalidInput(format!(
            "invalid tgproxy.bind_ip '{}': {err}",
            cfg.tgproxy.bind_ip
        ))
    })?;
    let bind_addr = SocketAddr::new(bind_ip, cfg.tgproxy.port);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    let cancel = CancellationToken::new();
    let pool = Arc::new(tgwsproxy::proxy::WsPool::new(cancel.clone()));

    let signal_task = tokio::spawn(wait_for_shutdown_signal(cancel.clone()));

    let run_res = tgwsproxy::proxy::run_proxy(
        pool,
        cfg.tgproxy.bind_ip.clone(),
        cfg.tgproxy.port,
        dc_opt_map,
        cancel.clone(),
        listener,
    )
    .await;

    cancel.cancel();
    let _ = signal_task.await;

    for ws in tgwsproxy::proxy::cf_pool_drain() {
        ws.close().await;
    }

    run_res?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(err) = run_daemon(cli).await {
        eprintln!("netfix-tgproxy: {err}");
        std::process::exit(err.exit_code().as_i32());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_smoke_rejects_http_with_404_on_ephemeral_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let pool = std::sync::Arc::new(tgwsproxy::proxy::WsPool::new(cancel.clone()));
        let handle = tokio::spawn(tgwsproxy::proxy::run_proxy(
            pool,
            "127.0.0.1".into(),
            addr.port(),
            Default::default(),
            cancel.clone(),
            listener,
        ));
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // handle_client reads a 64-byte MTProto handshake before inspecting HTTP transport.
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netfix-smoke-test/1.0\r\n\r\n",
        )
        .await
        .unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
            .await
            .unwrap();
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("HTTP/1.1 404 Not Found"));
        cancel.cancel();
        let _ = handle.await;
    }

    #[test]
    fn test_cli_parses_config_flag() {
        let cli = Cli::try_parse_from(["netfix-tgproxy", "--config", "/tmp/custom.toml"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/custom.toml")));

        let default_cli = Cli::try_parse_from(["netfix-tgproxy"]).unwrap();
        assert_eq!(default_cli.config, None);
    }

    #[test]
    fn test_apply_tgproxy_config_applies_settings_and_persists_secret_across_restarts() {
        let state_dir = std::env::temp_dir().join(format!(
            "netfix-tgproxy-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&state_dir);

        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.secret.clear();
        cfg.tgproxy.tls_verify = true;
        cfg.tgproxy.pool_size = 8;
        cfg.tgproxy.cf_enabled = false;
        cfg.tgproxy.pinned_cf_domain = "custom.example.co.uk".to_string();
        cfg.tgproxy.cf_front_ips = vec!["1.0.0.1".to_string()];
        cfg.tgproxy.cf_plain_first = true;
        cfg.tgproxy.cache_dir = state_dir.to_string_lossy().into_owned();

        let (secret, dc_map) = apply_tgproxy_config(&cfg, &state_dir).unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(*tgwsproxy::config::PROXY_SECRET.read(), secret);
        assert!(tgwsproxy::config::TLS_VERIFY.load(Ordering::Relaxed));
        assert_eq!(tgwsproxy::config::POOL_SIZE.load(Ordering::Relaxed), 8);
        assert!(!tgwsproxy::config::CFPROXY_ENABLED.load(Ordering::Relaxed));
        assert!(tgwsproxy::cffront::enabled());
        assert_eq!(
            tgwsproxy::config::CFPROXY.read().cache_dir,
            state_dir.to_string_lossy()
        );
        assert_eq!(
            tgwsproxy::config::CFPROXY.read().user_domain,
            "custom.example.co.uk"
        );
        assert_eq!(dc_map.get(&2).map(String::as_str), Some("149.154.167.220"));

        // Second call with empty config secret simulates daemon restart and must reuse secret.
        let (restarted_secret, _) = apply_tgproxy_config(&cfg, &state_dir).unwrap();
        assert_eq!(restarted_secret, secret);

        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[tokio::test]
    async fn test_wait_for_shutdown_signal_exits_on_cancellation() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(wait_for_shutdown_signal(cancel_clone));
        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }
}
