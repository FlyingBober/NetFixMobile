use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopEnv {
    Gnome,
    Kde,
    Generic,
}

pub fn detect_desktop_env() -> DesktopEnv {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_uppercase();
    if desktop.contains("GNOME") || desktop.contains("CINNAMON") || desktop.contains("UNITY") {
        DesktopEnv::Gnome
    } else if desktop.contains("KDE") {
        DesktopEnv::Kde
    } else {
        DesktopEnv::Generic
    }
}

pub fn enable_socks5_proxy(host: &str, port: u16) -> Result<(), String> {
    let env = detect_desktop_env();

    // 1. GNOME / GTK environments via gsettings
    if which::which("gsettings").is_ok() && (env == DesktopEnv::Gnome || env == DesktopEnv::Generic) {
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "host", host])
            .status();
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "port", &port.to_string()])
            .status();
        let status = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "manual"])
            .status()
            .map_err(|e| format!("gsettings failed: {e}"))?;
        if !status.success() {
            return Err("gsettings returned non-zero exit code".to_string());
        }
    }

    // 2. KDE Plasma 5/6 via kwriteconfig
    if env == DesktopEnv::Kde || env == DesktopEnv::Generic {
        let tool = if which::which("kwriteconfig6").is_ok() {
            "kwriteconfig6"
        } else if which::which("kwriteconfig5").is_ok() {
            "kwriteconfig5"
        } else {
            ""
        };

        if !tool.is_empty() {
            let proxy_url = format!("socks://{host}:{port}");
            let _ = Command::new(tool)
                .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1"])
                .status();
            let _ = Command::new(tool)
                .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", &proxy_url])
                .status();

            // Notify KDE daemon of configuration change
            if which::which("qdbus").is_ok() {
                let _ = Command::new("qdbus")
                    .args(["org.kde.kded5", "/kded", "reconfigure"])
                    .status();
                let _ = Command::new("qdbus")
                    .args(["org.kde.kded6", "/kded", "reconfigure"])
                    .status();
            }
        }
    }

    Ok(())
}

pub fn disable_socks5_proxy() -> Result<(), String> {
    let env = detect_desktop_env();

    // 1. GNOME revert
    if which::which("gsettings").is_ok() && (env == DesktopEnv::Gnome || env == DesktopEnv::Generic) {
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "none"])
            .status();
    }

    // 2. KDE Plasma revert
    if env == DesktopEnv::Kde || env == DesktopEnv::Generic {
        let tool = if which::which("kwriteconfig6").is_ok() {
            "kwriteconfig6"
        } else if which::which("kwriteconfig5").is_ok() {
            "kwriteconfig5"
        } else {
            ""
        };

        if !tool.is_empty() {
            let _ = Command::new(tool)
                .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"])
                .status();

            if which::which("qdbus").is_ok() {
                let _ = Command::new("qdbus")
                    .args(["org.kde.kded5", "/kded", "reconfigure"])
                    .status();
                let _ = Command::new("qdbus")
                    .args(["org.kde.kded6", "/kded", "reconfigure"])
                    .status();
            }
        }
    }

    Ok(())
}

pub fn is_socks5_proxy_enabled() -> bool {
    if which::which("gsettings").is_ok() {
        if let Ok(output) = Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy", "mode"])
            .output()
        {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
            if s.contains("manual") {
                return true;
            }
        }
    }

    let tool = if which::which("kreadconfig6").is_ok() {
        "kreadconfig6"
    } else if which::which("kreadconfig5").is_ok() {
        "kreadconfig5"
    } else {
        ""
    };

    if !tool.is_empty() {
        if let Ok(output) = Command::new(tool)
            .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType"])
            .output()
        {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if s == "1" {
                return true;
            }
        }
    }

    false
}
