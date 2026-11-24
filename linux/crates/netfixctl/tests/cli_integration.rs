use std::process::Command;

fn netfixctl_bin() -> &'static str {
    env!("CARGO_BIN_EXE_netfixctl")
}

#[test]
fn test_binary_status_json_and_tg_link_succeed_with_exit_0() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        r#"
[tgproxy]
port = 2443
secret = "0123456789abcdef0123456789abcdef"

[dns]
mode = "cloudflare"
"#,
    )
    .unwrap();

    let status_out = Command::new(netfixctl_bin())
        .args(["--config", cfg_path.to_str().unwrap(), "--json", "status"])
        .output()
        .unwrap();
    assert_eq!(status_out.status.code(), Some(0));
    let status_json: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status_json["target"], "all");
    assert_eq!(status_json["config_exists"], true);
    assert_eq!(status_json["dns_mode"], "cloudflare");
    assert_eq!(status_json["tgproxy"]["port"], 2443);

    let tg_out = Command::new(netfixctl_bin())
        .args(["--config", cfg_path.to_str().unwrap(), "tg", "link"])
        .output()
        .unwrap();
    assert_eq!(tg_out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&tg_out.stdout).trim(),
        "tg://proxy?server=127.0.0.1&port=2443&secret=dd0123456789abcdef0123456789abcdef"
    );
}

#[test]
fn test_binary_invalid_cli_and_bad_config_return_exit_2_with_json_error() {
    let cli_err = Command::new(netfixctl_bin())
        .args(["--json", "--definitely-invalid-flag"])
        .output()
        .unwrap();
    assert_eq!(cli_err.status.code(), Some(2));
    let cli_json: serde_json::Value = serde_json::from_slice(&cli_err.stderr).unwrap();
    assert_eq!(cli_json["exit_code"], 2);

    let dir = tempfile::tempdir().unwrap();
    let bad_cfg = dir.path().join("bad.toml");
    std::fs::write(&bad_cfg, "[tgproxy]\nsecret = \"not-hex\"\n").unwrap();

    let cfg_err = Command::new(netfixctl_bin())
        .args(["--config", bad_cfg.to_str().unwrap(), "--json", "status"])
        .output()
        .unwrap();
    assert_eq!(cfg_err.status.code(), Some(2));
    let cfg_json: serde_json::Value = serde_json::from_slice(&cfg_err.stderr).unwrap();
    assert_eq!(cfg_json["exit_code"], 2);
}

#[test]
fn test_binary_setup_requires_root_exit_3_and_missing_engine_returns_exit_4() {
    if unsafe { libc::geteuid() != 0 } {
        let setup_err = Command::new(netfixctl_bin())
            .args(["--json", "setup", "--skip-download"])
            .output()
            .unwrap();
        assert_eq!(setup_err.status.code(), Some(3));
        let json: serde_json::Value = serde_json::from_slice(&setup_err.stderr).unwrap();
        assert_eq!(json["exit_code"], 3);
    }

    if !std::path::Path::new("/usr/local/libexec/netfix/ciadpi").exists() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        std::fs::write(&cfg_path, "").unwrap();
        let scan_err = Command::new(netfixctl_bin())
            .env("PATH", "/nonexistent")
            .args([
                "--config",
                cfg_path.to_str().unwrap(),
                "--json",
                "scan",
                "--engine",
                "ciadpi",
            ])
            .output()
            .unwrap();
        assert_eq!(scan_err.status.code(), Some(4));
        let json: serde_json::Value = serde_json::from_slice(&scan_err.stderr).unwrap();
        assert_eq!(json["exit_code"], 4);
    }
}
