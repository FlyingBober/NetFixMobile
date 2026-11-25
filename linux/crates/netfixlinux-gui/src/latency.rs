use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyReport {
    pub youtube_ms: Option<u64>,
    pub discord_ms: Option<u64>,
    pub cloudflare_ms: Option<u64>,
    pub telegram_ms: Option<u64>,
}

pub async fn measure_latencies() -> LatencyReport {
    let client = reqwest::Client::builder()
        .no_proxy()
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .timeout(std::time::Duration::from_millis(4000))
        .build()
        .unwrap_or_default();

    let yt_fut = measure_http(&client, "https://www.youtube.com/generate_204");
    let discord_fut = measure_http(&client, "https://discord.com/api/v9/gateway");
    let cf_fut = measure_http(&client, "https://cp.cloudflare.com/generate_204");
    let tg_fut = measure_tcp("149.154.167.51:443");

    let (youtube_ms, discord_ms, cloudflare_ms, telegram_ms) =
        tokio::join!(yt_fut, discord_fut, cf_fut, tg_fut);

    LatencyReport {
        youtube_ms,
        discord_ms,
        cloudflare_ms,
        telegram_ms,
    }
}

async fn measure_http(client: &reqwest::Client, url: &str) -> Option<u64> {
    let start = Instant::now();
    match client.get(url).send().await {
        Ok(res) if res.status().as_u16() < 500 => Some(start.elapsed().as_millis() as u64),
        _ => None,
    }
}

async fn measure_tcp(addr: &str) -> Option<u64> {
    let start = Instant::now();
    match tokio::time::timeout(
        std::time::Duration::from_millis(2500),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_stream)) => Some(start.elapsed().as_millis() as u64),
        _ => None,
    }
}
