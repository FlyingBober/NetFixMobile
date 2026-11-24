use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::config::normalize_network_key;
use crate::NetfixConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInfo {
    pub key: String,
    pub ssid: Option<String>,
    pub connection_name: Option<String>,
    pub interface: Option<String>,
    pub is_override: bool,
}

/// Detects the active network key string (normalized for lookup in `dpi.network_strategies`).
pub fn detect_active_network_key(cfg: &NetfixConfig) -> String {
    detect_current_network_info(cfg).key
}

/// Detects detailed network info (SSID, connection name, interface, override flag).
pub fn detect_current_network_info(cfg: &NetfixConfig) -> NetworkInfo {
    if let Some(ref override_net) = cfg.general.active_network_override {
        let trimmed = override_net.trim();
        if !trimmed.is_empty() {
            let (iface, conn, ssid) = detect_live_network_components();
            return NetworkInfo {
                key: normalize_network_key(trimmed),
                ssid,
                connection_name: conn,
                interface: iface,
                is_override: true,
            };
        }
    }

    let (iface, conn, ssid) = detect_live_network_components();

    let key = if let Some(ref s) = ssid {
        normalize_network_key(s)
    } else if let Some(ref c) = conn {
        normalize_network_key(c)
    } else if let Some(ref i) = iface {
        normalize_network_key(i)
    } else {
        "default".to_string()
    };

    NetworkInfo {
        key,
        ssid,
        connection_name: conn,
        interface: iface,
        is_override: false,
    }
}

fn detect_live_network_components() -> (Option<String>, Option<String>, Option<String>) {
    let mut iface = None;
    let mut conn = None;
    let mut ssid = None;

    // 1. Try NetworkManager wifi active SSID
    if let Ok(out) = Command::new("nmcli")
        .env("LC_ALL", "C")
        .args(["-t", "-f", "active,ssid", "dev", "wifi"])
        .output()
    {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(s) = parse_nmcli_active_ssid(&stdout) {
                ssid = Some(s);
            }
        }
    }

    // 2. Try NetworkManager connected devices
    if let Ok(out) = Command::new("nmcli")
        .env("LC_ALL", "C")
        .args(["-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "dev"])
        .output()
    {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some((dev_name, dev_type, dev_conn)) = parse_nmcli_dev_connected(&stdout) {
                if iface.is_none() {
                    iface = Some(dev_name);
                }
                if conn.is_none() {
                    conn = Some(dev_conn.clone());
                }
                if dev_type == "wifi" && ssid.is_none() {
                    ssid = Some(dev_conn);
                }
            }
        }
    }

    // 3. Fallback: try iw link for wifi SSID if still missing
    if ssid.is_none() {
        if let Some(s) = detect_wifi_ssid_via_iw() {
            ssid = Some(s);
        }
    }

    // 4. Fallback: try iwgetid
    if ssid.is_none() {
        if let Ok(out) = Command::new("iwgetid").arg("-r").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    ssid = Some(s);
                }
            }
        }
    }

    // 5. Fallback: detect default route interface if missing
    if iface.is_none() {
        if let Some(i) = detect_default_route_interface() {
            iface = Some(i);
        }
    }

    (iface, conn, ssid)
}

fn detect_wifi_ssid_via_iw() -> Option<String> {
    let out = Command::new("iw").arg("dev").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Interface ") {
            let iface_name = rest.trim();
            if iface_name.is_empty() {
                continue;
            }
            if let Ok(link_out) = Command::new("iw")
                .args(["dev", iface_name, "link"])
                .output()
            {
                if link_out.status.success() {
                    let link_str = String::from_utf8_lossy(&link_out.stdout);
                    if let Some(s) = parse_iw_link_ssid(&link_str) {
                        return Some(s);
                    }
                }
            }
        }
    }
    None
}

pub fn detect_default_route_interface() -> Option<String> {
    if let Ok(out) = Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
    {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(iface) = parse_ip_route_get_dev(&stdout) {
                return Some(iface);
            }
        }
    }

    if let Ok(route_table) = std::fs::read_to_string("/proc/net/route") {
        return parse_proc_net_route_default_iface(&route_table);
    }

    None
}

pub fn parse_nmcli_active_ssid(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("yes:") {
            let ssid = rest.trim();
            if !ssid.is_empty() {
                return Some(ssid.to_string());
            }
        }
    }
    None
}

pub fn parse_nmcli_dev_connected(output: &str) -> Option<(String, String, String)> {
    let mut primary_match = None;
    for line in output.lines() {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let dev = parts[0].trim();
        let dev_type = parts[1].trim().to_ascii_lowercase();
        let state = parts[2].trim().to_ascii_lowercase();
        let conn = parts[3].trim();

        if state != "connected" {
            continue;
        }

        // Skip virtual or loopback interfaces
        if dev == "lo"
            || dev_type == "loopback"
            || dev_type == "bridge"
            || dev_type == "tun"
            || dev_type == "tap"
            || dev_type == "vpn"
            || dev_type == "wireguard"
            || dev.starts_with("docker")
            || dev.starts_with("br-")
            || dev.starts_with("veth")
            || dev.starts_with("virbr")
        {
            continue;
        }

        if !conn.is_empty() {
            // Wi-Fi or Ethernet preferred
            if dev_type == "wifi" {
                return Some((dev.to_string(), dev_type, conn.to_string()));
            }
            if primary_match.is_none() {
                primary_match = Some((dev.to_string(), dev_type, conn.to_string()));
            }
        }
    }
    primary_match
}

pub fn parse_iw_link_ssid(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("SSID:") {
            let s = rest.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

pub fn parse_ip_route_get_dev(output: &str) -> Option<String> {
    let mut tokens = output.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "dev" {
            return tokens
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
        }
    }
    None
}

pub fn parse_proc_net_route_default_iface(route_table: &str) -> Option<String> {
    for line in route_table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(iface) = fields.next() else {
            continue;
        };
        let Some(dest) = fields.next() else {
            continue;
        };
        if dest == "00000000" && !iface.is_empty() {
            return Some(iface.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nmcli_active_ssid() {
        let sample = "\
no:OtherNet
yes:My_Home_WiFi
no:Guest
";
        assert_eq!(
            parse_nmcli_active_ssid(sample).as_deref(),
            Some("My_Home_WiFi")
        );
        assert_eq!(parse_nmcli_active_ssid("no:Net1\nno:Net2\n"), None);
    }

    #[test]
    fn test_parse_nmcli_dev_connected_filters_virtual() {
        let sample = "\
enp0s13f0u1u3:ethernet:connected:DockStation_Ethernet
br-a17dfbdaf70d:bridge:connected (externally):br-a17dfbdaf70d
lo:loopback:connected (externally):lo
docker0:bridge:connected (externally):docker0
vethb2f6a4c:ethernet:unmanaged:
wlp70s0:wifi:disconnected:
";
        let res = parse_nmcli_dev_connected(sample).unwrap();
        assert_eq!(res.0, "enp0s13f0u1u3");
        assert_eq!(res.1, "ethernet");
        assert_eq!(res.2, "DockStation_Ethernet");

        let wifi_sample = "\
enp0s13f0u1u3:ethernet:connected:DockStation_Ethernet
wlp70s0:wifi:connected:Xiaomi 12 Pro
";
        let wifi_res = parse_nmcli_dev_connected(wifi_sample).unwrap();
        assert_eq!(wifi_res.0, "wlp70s0");
        assert_eq!(wifi_res.1, "wifi");
        assert_eq!(wifi_res.2, "Xiaomi 12 Pro");
    }

    #[test]
    fn test_parse_iw_link_ssid() {
        let sample = "\
Connected to 12:34:56:78:9a:bc (on wlp70s0)
	SSID: Office-Guest-5G
	freq: 5180
	signal: -55 dBm
";
        assert_eq!(parse_iw_link_ssid(sample).as_deref(), Some("Office-Guest-5G"));
        assert_eq!(parse_iw_link_ssid("Not connected.\n"), None);
    }

    #[test]
    fn test_parse_ip_route_get_dev() {
        let sample = "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 1000\n";
        assert_eq!(parse_ip_route_get_dev(sample).as_deref(), Some("eth0"));
        assert_eq!(parse_ip_route_get_dev("invalid format"), None);
    }

    #[test]
    fn test_parse_proc_net_route_default_iface() {
        let sample = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(
            parse_proc_net_route_default_iface(sample).as_deref(),
            Some("wlan0")
        );
    }

    #[test]
    fn test_detect_current_network_info_respects_override() {
        let mut cfg = NetfixConfig::default();
        cfg.general.active_network_override = Some("Special Profile".into());
        let info = detect_current_network_info(&cfg);
        assert_eq!(info.key, "special_profile");
        assert!(info.is_override);
    }
}
