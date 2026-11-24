# NetFix Linux Headless Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> **Note on Git policy:** Do NOT run `git commit` or `git push` automatically; only commit when explicitly requested by the user.
> **Environment prerequisite:** `rustc` and `cargo` must be installed on the build host before executing `cargo test` / `cargo build`.

**Goal:** Build a Linux headless equivalent of Windows NetFix inside `linux/` on branch `linux-headless`, providing independent `systemd` services for DPI bypass (`nfqws` primary, `ciadpi` secondary) and Telegram MTProto-over-WebSocket proxying (`native/tgproxy-rust`), controlled by a unified `netfixctl` CLI with JSON output for future GUI integration.

**Architecture:** A Rust workspace in `linux/` shares `native/tgproxy-rust` (compiled as both `cdylib` for Android and `rlib` for Linux) and splits responsibilities into `netfix-core` (config, `nftables`/`iptables` firewall rendering, engine orchestration, two-phase strategy scanner, DNS/`/etc/hosts` management, Telegram DC probe), `netfix-tgproxy` (unprivileged Tokio daemon wrapping `tgwsproxy::proxy::run_proxy`), and `netfixctl` (CLI + `systemd` lifecycle runner `dpi-run`/`dpi-cleanup`).

**Tech Stack:** Rust (2021 edition), `tokio`, `reqwest` (rustls), `clap` (derive), `serde`/`toml`/`serde_json`, `nix`/`libc`, `nftables` (`nft`) / `iptables`, `systemd`.

**Spec:** [`docs/superpowers/specs/2026-11-19-linux-headless-design.md`](file:///home/imperator/projects/home/agy/NetFixMobile/docs/superpowers/specs/2026-11-19-linux-headless-design.md)

## Global Constraints

- Keep Android `app/` untouched; place Linux code in `linux/` and keep `native/tgproxy-rust` compatible with Android `cdylib` builds.
- Config path defaults to `/etc/netfix/config.toml` (`0640 root:netfix`), overridable via `--config <path>` or `NETFIX_CONFIG`; state/backups live in `/var/lib/netfix/`; engines live in `/usr/local/libexec/netfix/` or `PATH`.
- Two independent `systemd` units: `netfix-dpi.service` (privileged for `nfqws`/`transparent`) and `netfix-tgproxy.service` (unprivileged user `netfix`), plus `netfix.target`.
- Exit codes for `netfixctl`: `0` success, `1` runtime/network failure, `2` invalid CLI/config, `3` missing privileges, `4` missing engine binary.
- CLI commands `status`, `scan`, `dc-check`, `dns`, `hosts` must support `--json`.

## Review Focus

1. **Orphaned firewall tables on interrupted `dpi-run` or `scan`:** Cleanup must delete `inet netfix` / `inet netfix_scan` idempotently even if the table was never created or partially created.
2. **Corrupted or partial `/etc/hosts` markers:** If `# BEGIN NETFIX MANAGED` appears without a matching `# END NETFIX MANAGED`, `hosts` operations must abort with an error instead of truncating user entries.
3. **Invalid/malformed MTProto `secret` in config:** Empty secret generates a random 32-hex secret; non-empty invalid hex or wrong length must return a config validation error (exit code `2`) instead of silently falling back to `0000...0000`.
4. **Malicious/conflicting flags in user or preset strategy strings:** Sanitizers must strip `--ip`, `--port`, `--qnum`, `--dpi-desync-fwmark`, `--help`, `--version`, `-h`, `-v` and reject shell metacharacters/newlines.
5. **`nft` missing fallback & SSID/interface key normalization:** Firewall selection falls back to `IptablesBackend` when `nft` is unavailable; network keys containing spaces/symbols sanitize cleanly into deterministic TOML keys.

---

### File Structure Map

- Modify: `native/tgproxy-rust/Cargo.toml` — add `rlib` to `crate-type` and `webpki-roots` / `rustls-native-certs` for optional TLS verification.
- Create: `native/tgproxy-rust/src/cffront.rs` — implement `cffront` module expected by `lib.rs`, `proxy.rs`, `cfproxy.rs`.
- Modify: `native/tgproxy-rust/src/config.rs`, `native/tgproxy-rust/src/ws.rs` — add `TLS_VERIFY` atomic toggle and verified `ClientConfig` path.
- Create: `linux/Cargo.toml` — workspace manifest (`crates/netfix-core`, `crates/netfixctl`, `crates/netfix-tgproxy`).
- Create: `linux/crates/netfix-core/src/lib.rs` — crate exports and exit code / error types (`NetfixError`, `ExitCode`).
- Create: `linux/crates/netfix-core/src/config.rs` — `NetfixConfig` TOML load/save, validation, network key normalization, secret generator.
- Create: `linux/crates/netfix-core/src/strategy.rs` — strategy sanitization, `{sni}` substitution, preset loading.
- Create: `linux/crates/netfix-core/src/firewall.rs` — `FirewallBackend`, `NftablesBackend`, `IptablesBackend`, `FirewallGuard`.
- Create: `linux/crates/netfix-core/src/dpi.rs` — `DpiRunner` (`nfqws`, `ciadpi` socks5/transparent), port resolution, signal-safe lifecycle.
- Create: `linux/crates/netfix-core/src/scanner.rs` — two-phase strategy tester (`QUICK_SITES`, `TEST_SITES`, `StreamChunkProbe`) for both `ciadpi` and `nfqws`.
- Create: `linux/crates/netfix-core/src/tg.rs` — `tg://proxy` URI formatter, `dc-check` probe (`DC1–DC5` + Cloudflare domains).
- Create: `linux/crates/netfix-core/src/dns.rs` — `systemd-resolved`, `nmcli`, `/etc/resolv.conf` management with backup/reset.
- Create: `linux/crates/netfix-core/src/hosts.rs` — atomic `# BEGIN NETFIX MANAGED` block manager with backup/reset.
- Create: `linux/crates/netfix-core/src/setup.rs` — binary discovery, SHA-256 verified engine installer, systemd unit installer.
- Create: `linux/crates/netfix-tgproxy/src/main.rs` — unprivileged daemon binary running `tgwsproxy::proxy::run_proxy`.
- Create: `linux/crates/netfixctl/src/main.rs` — `clap` CLI (`setup`, `start`, `stop`, `restart`, `status`, `scan`, `dc-check`, `dns`, `hosts`, `tg`, `dpi-run`, `dpi-cleanup`) with `--json`.
- Create: `linux/presets/strategies-nfqws.toml`, `linux/presets/strategies-ciadpi.toml`, `linux/presets/hostlists/default.txt` — default strategy lists and hostlists.
- Create: `linux/systemd/netfix-dpi.service`, `linux/systemd/netfix-tgproxy.service`, `linux/systemd/netfix.target` — `systemd` unit files.

---

### Task 1: Restore `cffront.rs` and Make `native/tgproxy-rust` Linkable on Linux

**Files:**
- Modify: `native/tgproxy-rust/Cargo.toml:6-36`
- Create: `native/tgproxy-rust/src/cffront.rs`
- Modify: `native/tgproxy-rust/src/config.rs:41-61`
- Modify: `native/tgproxy-rust/src/ws.rs:82-93,546-566`
- Test: `native/tgproxy-rust/src/cffront.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Produces in `tgwsproxy`:
  - `pub mod cffront` with `DIRECT_FAST_TIMEOUT: f64`, `DIRECT_FAST_COOLDOWN: f64`, `DIRECT_RACE_HEAD_START: Duration`, `enabled() -> bool`, `direct_fast_fail() -> bool`, `set_direct_fast_fail(bool)`, `set_front_ips(Vec<String>)`, `set_plain_first(bool)`, `forget_network_state()`, `direct_ok((i32, i32)) -> bool`, `mark_direct_ok((i32, i32))`, `forget_direct_ok((i32, i32))`, `check_direct_in_background((i32, i32), String, Vec<String>)`, `connect_known(&str, &str) -> Option<(RawWebSocket, String)>`, `connect_any(&str, &str) -> Option<(RawWebSocket, String)>`, `cf_ws_connect(&str, &str, &str, Duration) -> Result<RawWebSocket, WsError>`.
  - `config::TLS_VERIFY: AtomicBool` (default `false` for Android FFI compatibility, toggled via `SetTlsVerify(c_int)` or direct store in Rust).

- [ ] **Step 1: Write failing tests in `native/tgproxy-rust/src/cffront.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_front_ips_and_direct_state_lifecycle() {
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
        set_direct_fast_fail(true);
        assert!(direct_fast_fail());
        set_direct_fast_fail(false);
        assert!(!direct_fast_fail());
    }
}
```

- [ ] **Step 2: Run test to verify compilation fails (missing `cffront.rs`)**

Run: `cargo test --manifest-path native/tgproxy-rust/Cargo.toml`
Expected: FAIL with `file not found for module cffront`

- [ ] **Step 3: Update `Cargo.toml`, `config.rs`, `ws.rs`, and implement `cffront.rs`**

- In `native/tgproxy-rust/Cargo.toml`, change `crate-type = ["cdylib"]` to `crate-type = ["cdylib", "rlib"]` and add `webpki-roots = "0.26"`.
- In `native/tgproxy-rust/src/config.rs`, add `pub static TLS_VERIFY: AtomicBool = AtomicBool::new(false);`.
- In `native/tgproxy-rust/src/ws.rs`, add `TLS_CONFIG_VERIFIED: Lazy<Arc<ClientConfig>>` using `webpki_roots::TLS_SERVER_ROOTS` and choose it in `ws_connect_once` when `TLS_VERIFY.load(Ordering::Relaxed)` is `true` and `domain.parse::<IpAddr>().is_err()`.
- Implement `native/tgproxy-rust/src/cffront.rs`:
  - Constants: `DIRECT_FAST_TIMEOUT = 1.8`, `DIRECT_FAST_COOLDOWN = 20.0`, `DIRECT_RACE_HEAD_START = Duration::from_millis(600)`.
  - Global state (`RwLock<Vec<String>>` for valid `IpAddr` front IPs, `RwLock<HashSet<(i32, i32)>>` for failed direct keys, `AtomicBool` for `PLAIN_FIRST` and `DIRECT_FAST_FAIL`, `RwLock<Option<String>>` for last working front IP).
  - `cf_ws_connect(ip, domain, path, timeout)` uses `ws_connect_plain` first if `PLAIN_FIRST` is enabled (falling back to `ws_connect_once`), otherwise `ws_connect_once`.
  - `connect_known` tries last working front IP; `connect_any` races configured front IPs up to `CFPROXY_DIAL_PHASE_TIMEOUT`.

- [ ] **Step 4: Run `tgproxy-rust` unit tests**

Run: `cargo test --manifest-path native/tgproxy-rust/Cargo.toml`
Expected: PASS (all `cffront`, `cfproxy`, `crypto`, and `proxy` tests green)

---

### Task 2: Scaffold `linux/` Workspace, Config, Validation, and Strategy Presets

**Files:**
- Create: `linux/Cargo.toml`
- Create: `linux/crates/netfix-core/Cargo.toml`
- Create: `linux/crates/netfix-core/src/lib.rs`
- Create: `linux/crates/netfix-core/src/config.rs`
- Create: `linux/crates/netfix-core/src/strategy.rs`
- Create: `linux/presets/strategies-nfqws.toml`
- Create: `linux/presets/strategies-ciadpi.toml`
- Create: `linux/presets/hostlists/default.txt`

**Interfaces:**
- Produces in `netfix_core`:
  - `ExitCode` enum (`Ok = 0`, `Runtime = 1`, `InvalidInput = 2`, `PermissionDenied = 3`, `MissingEngine = 4`) and `NetfixError`.
  - `NetfixConfig`: `load(path: &Path) -> Result<Self, NetfixError>`, `save(&self, path: &Path) -> Result<(), NetfixError>`, `validate(&self) -> Result<(), NetfixError>`, `ensure_secret(&mut self) -> String`, `normalize_network_key(raw: &str) -> String`.
  - `DpiEngineKind` (`Nfqws`, `Ciadpi`), `CiadpiMode` (`Socks5`, `Transparent`), `IpsetMode` (`Any`, `Loaded`, `None`), `DnsMode` (`System`, `Cloudflare`, `Google`, `Quad9`, `Adguard`, `Custom`).
  - `strategy::sanitize_ciadpi_args(raw: &str) -> Result<Vec<String>, NetfixError>`, `strategy::sanitize_nfqws_args(raw: &str) -> Result<Vec<String>, NetfixError>`, `strategy::expand_sni(args: &[String], sni: &str) -> Vec<String>`.

- [ ] **Step 1: Write failing tests for config validation, network key normalization, and strategy sanitization**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_nonempty_secret_rejected() {
        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.secret = "not-valid-hex".into();
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::InvalidInput);
    }

    #[test]
    fn test_empty_secret_generates_32_hex() {
        let mut cfg = NetfixConfig::default();
        cfg.tgproxy.secret.clear();
        let sec = cfg.ensure_secret();
        assert_eq!(sec.len(), 32);
        assert!(hex::decode(&sec).is_ok());
    }

    #[test]
    fn test_network_key_normalization() {
        assert_eq!(normalize_network_key("My Home Wi-Fi! (5G)"), "my_home_wi-fi_5g");
    }
}
```
And in `strategy.rs`:
```rust
#[test]
fn test_sanitize_strips_conflicting_flags_and_rejects_newlines() {
    let args = sanitize_ciadpi_args("--ip 0.0.0.0 --port=9999 -o1 -n {sni} --help").unwrap();
    assert_eq!(expand_sni(&args, "google.com"), vec!["-o1", "-n", "google.com"]);
    assert!(sanitize_nfqws_args("--dpi-desync=fake\nrm -rf /").is_err());
    let nfq = sanitize_nfqws_args("--qnum=10 --dpi-desync-fwmark=0x1 --dpi-desync=fake").unwrap();
    assert_eq!(nfq, vec!["--dpi-desync=fake"]);
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core`
Expected: FAIL (workspace/crates do not exist yet)

- [ ] **Step 3: Create workspace, `netfix-core` config/strategy modules, and strategy preset TOMLs**

- Create `linux/Cargo.toml` (`members = ["crates/netfix-core", "crates/netfix-tgproxy", "crates/netfixctl"]`) and `linux/crates/netfix-core/Cargo.toml` (`serde`, `toml`, `serde_json`, `thiserror`, `rand`, `hex`, `reqwest`, `tokio`, `shell-words`).
- Implement `NetfixConfig` with exact spec defaults (`/etc/netfix/config.toml`, `nfqueue_num = 200`, `fwmark = 0x40000000`, `socks_port = 1080`, `transparent_port = 11080`, `tgproxy.port = 1443`, `cf_plain_first = false`, `tls_verify = true`).
- Implement `sanitize_ciadpi_args` (strips `-i`, `--ip`, `-p`, `--port`, `--help`, `-h`, `--version`, `-v` and rejects `\n`/`\r`/`\0`) and `sanitize_nfqws_args` (strips `--qnum`, `--dpi-desync-fwmark`, `--daemon`, `--pidfile` and rejects control characters).
- Populate `linux/presets/strategies-ciadpi.toml` from `StrategyTester.kt` (`defaultStrategies` + `YOUTUBE_VIDEO_STRATEGIES`) and `linux/presets/strategies-nfqws.toml` with curated `zapret` `nfqws` presets (`--dpi-desync=fake,multisplit`, `--dpi-desync=disorder2`, `--dpi-desync=fake --dpi-desync-fooling=badsum`, QUIC fake).

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core`
Expected: PASS

---

### Task 3: Firewall Backends (`NftablesBackend` & `IptablesBackend`)

**Files:**
- Create: `linux/crates/netfix-core/src/firewall.rs`
- Modify: `linux/crates/netfix-core/src/lib.rs` (export `pub mod firewall;`)

**Interfaces:**
- Consumes: `NetfixConfig`, `DpiEngineKind`, `CiadpiMode`, `IpsetMode`, `NetfixError`.
- Produces:
  - `FirewallSpec` (`table_name: String`, `mode: FirewallMode`, `nfqueue_num: u16`, `fwmark: u32`, `game_filter: bool`, `ipset_mode: IpsetMode`, `ipset_v4: Vec<String>`, `ipset_v6: Vec<String>`, `transparent_port: u16`, `excluded_uid: Option<u32>`).
  - `NftablesBackend::render_script(spec: &FirewallSpec) -> String`, `render_cleanup(table_name: &str) -> String`.
  - `IptablesBackend::render_commands(spec: &FirewallSpec) -> Vec<Vec<String>>`, `render_cleanup_commands(chain: &str) -> Vec<Vec<String>>`.
  - `FirewallGuard`: RAII guard calling cleanup on `Drop` (logs errors without panicking) and `apply(&self) -> Result<(), NetfixError>`, `cleanup(&self) -> Result<(), NetfixError>`, `detect_backend() -> Result<FirewallKind, NetfixError>`.

- [ ] **Step 1: Write failing unit tests and `nft -c -f -` dry-run validation test**

```rust
#[test]
fn test_nftables_nfqws_script_includes_fwmark_bypass_and_game_filter() {
    let spec = FirewallSpec::for_nfqws("netfix", 200, 0x4000_0000, true, IpsetMode::Any, vec![], vec![]);
    let script = NftablesBackend::render_script(&spec);
    assert!(script.contains("table inet netfix"));
    assert!(script.contains("meta mark & 0x40000000 == 0"));
    assert!(script.contains("queue num 200 bypass"));
    assert!(script.contains("udp dport 1024-65535"));
}

#[test]
fn test_nftables_ciadpi_transparent_redirects_tcp_and_rejects_quic() {
    let spec = FirewallSpec::for_ciadpi_transparent("netfix", 11080, Some(999));
    let script = NftablesBackend::render_script(&spec);
    assert!(script.contains("skuid != 999"));
    assert!(script.contains("redirect to :11080"));
    assert!(script.contains("udp dport 443 reject"));
}

#[test]
fn test_nftables_syntax_valid_via_nft_check() {
    if which_binary("nft").is_none() { return; }
    for spec in [
        FirewallSpec::for_nfqws("netfix", 200, 0x4000_0000, true, IpsetMode::Any, vec![], vec![]),
        FirewallSpec::for_nfqws("netfix_scan", 201, 0x4000_0000, false, IpsetMode::Loaded, vec!["1.1.1.0/24".into()], vec![]),
        FirewallSpec::for_ciadpi_transparent("netfix", 11080, Some(999)),
    ] {
        let script = NftablesBackend::render_script(&spec);
        let status = std::process::Command::new("nft")
            .args(["-c", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            // feed script and assert status.success()
            ...
        assert!(status.success(), "nft syntax failed for:\n{script}");
    }
}

#[test]
fn test_cleanup_script_handles_missing_table_idempotently() {
    let cleanup = NftablesBackend::render_cleanup("netfix_scan");
    assert!(cleanup.contains("table inet netfix_scan"));
    assert!(cleanup.contains("delete table inet netfix_scan"));
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core firewall`
Expected: FAIL (module `firewall` missing)

- [ ] **Step 3: Implement `NftablesBackend`, `IptablesBackend`, and `FirewallGuard` in `firewall.rs`**

- `NftablesBackend::render_script`:
  - Starts with `add table inet <table>\ndelete table inet <table>\nadd table inet <table> { ... }` (ensures idempotent clean slate without error on missing table).
  - For `nfqws`: `output` and `prerouting` chains (`type filter hook ... priority mangle`), `meta mark & 0x40000000 == 0`, `ct original packets 1-15`, TCP `80, 443`, UDP `443` (and `1024-65535` if `game_filter`), optional `ip daddr @netfix_ipset_v4` / `ip6 daddr @netfix_ipset_v6` when `IpsetMode::Loaded`, sending to `queue num <qnum> bypass`.
  - For `ciadpi --transparent`: `nat output` chain skipping `ip daddr 127.0.0.0/8` and `skuid == <uid>`, redirecting TCP `80, 443` to `:<port>`; `filter output` chain rejecting IPv4 UDP `443` and IPv6 TCP/UDP `80, 443`.
- `IptablesBackend`: builds `-w 5` argument vectors for `iptables`/`ip6tables` with `NETFIX_DPI` chain and `NFQUEUE --queue-num <qnum> --queue-bypass` + `--mark 0/0x40000000`.
- `FirewallGuard`: deletes the table/chains on `Drop` if still active.

- [ ] **Step 4: Run tests including `nft -c -f -` validation**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core firewall`
Expected: PASS (all firewall rendering + `nft -c -f -` kernel parser checks pass)

---

### Task 4: DPI Engine Orchestration (`DpiRunner`, `dpi-run`, `dpi-cleanup`)

**Files:**
- Create: `linux/crates/netfix-core/src/dpi.rs`
- Modify: `linux/crates/netfix-core/src/lib.rs` (export `pub mod dpi;`)

**Interfaces:**
- Consumes: `NetfixConfig`, `strategy::*`, `firewall::*`.
- Produces:
  - `find_engine_binary(name: &str) -> Result<PathBuf, NetfixError>` (checks `/usr/local/libexec/netfix/<name>`, then `PATH`; returns `ExitCode::MissingEngine` if absent).
  - `resolve_free_port(bind_ip: &str, preferred: u16) -> u16`.
  - `build_nfqws_command(cfg: &NetfixConfig, bin: &Path, strategy: &str, qnum: u16) -> Result<Command, NetfixError>`.
  - `build_ciadpi_command(cfg: &NetfixConfig, bin: &Path, strategy: &str, port: u16, transparent: bool) -> Result<Command, NetfixError>`.
  - `run_dpi_service(cfg: &NetfixConfig, shutdown: tokio::sync::watch::Receiver<bool>) -> Result<(), NetfixError>` and `cleanup_dpi_firewall(cfg: &NetfixConfig) -> Result<(), NetfixError>`.

- [ ] **Step 1: Write failing tests for command construction, missing binary error, and port fallback**

```rust
#[test]
fn test_build_nfqws_command_pins_qnum_and_fwmark() {
    let cfg = NetfixConfig::default();
    let cmd = build_nfqws_command(&cfg, Path::new("/usr/bin/nfqws"), "--qnum=1 --dpi-desync=fake", 200).unwrap();
    let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().into_owned()).collect();
    assert!(args.contains(&"--qnum=200".into()));
    assert!(args.contains(&"--dpi-desync-fwmark=0x40000000".into()));
    assert!(args.contains(&"--dpi-desync=fake".into()));
    assert!(!args.contains(&"--qnum=1".into()));
}

#[test]
fn test_missing_engine_returns_exit_code_4() {
    let err = find_engine_binary("definitely-missing-engine-xyz").unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::MissingEngine);
}

#[test]
fn test_resolve_free_port_moves_when_bound() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = listener.local_addr().unwrap().port();
    let free = resolve_free_port("127.0.0.1", busy);
    assert_ne!(free, busy);
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core dpi`
Expected: FAIL

- [ ] **Step 3: Implement `dpi.rs`**

- Implement `find_engine_binary`, `resolve_free_port`, `build_nfqws_command`, `build_ciadpi_command`.
- Implement `run_dpi_service`: checks `geteuid() == 0` when mode requires firewall (`nfqws` or `ciadpi --transparent`), applies `FirewallGuard`, spawns engine child process, listens for `shutdown` channel or child exit, sends `SIGTERM` -> waits 2s -> `SIGKILL`, and drops `FirewallGuard`.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core dpi`
Expected: PASS

---

### Task 5: `netfix-tgproxy` Daemon Binary & Telegram Diagnostics (`tg link`, `dc-check`)

**Files:**
- Create: `linux/crates/netfix-tgproxy/Cargo.toml`
- Create: `linux/crates/netfix-tgproxy/src/main.rs`
- Create: `linux/crates/netfix-core/src/tg.rs`
- Modify: `linux/crates/netfix-core/src/lib.rs` (export `pub mod tg;`)

**Interfaces:**
- Consumes: `tgwsproxy` (`proxy::run_proxy`, `proxy::WsPool`, `proxy::parse_cidr_pool`, `config::*`, `cfproxy::*`, `cffront::*`), `NetfixConfig`.
- Produces:
  - `netfix_core::tg::build_tg_proxy_url(ip: &str, port: u16, secret: &str) -> String`.
  - `netfix_core::tg::probe_dc_and_cf(cfg: &NetfixConfig) -> DcCheckReport` (serializable JSON: `dc_results: Vec<DcProbe>`, `cf_results: Vec<CfProbe>`).
  - `netfix-tgproxy` CLI flags `--config <path>` and graceful shutdown on `SIGINT`/`SIGTERM`.

- [ ] **Step 1: Write failing tests in `tg.rs` and `netfix-tgproxy`**

```rust
// in netfix-core/src/tg.rs
#[test]
fn test_build_tg_proxy_url_formats_dd_secret() {
    let url = build_tg_proxy_url("127.0.0.1", 1443, "0123456789abcdef0123456789abcdef");
    assert_eq!(url, "tg://proxy?server=127.0.0.1&port=1443&secret=dd0123456789abcdef0123456789abcdef");
}

// in netfix-tgproxy/src/main.rs
#[tokio::test]
async fn test_proxy_smoke_rejects_http_with_404_on_ephemeral_port() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let pool = std::sync::Arc::new(tgwsproxy::proxy::WsPool::new(cancel.clone()));
    let handle = tokio::spawn(tgwsproxy::proxy::run_proxy(
        pool, "127.0.0.1".into(), addr.port(), Default::default(), cancel.clone(), listener
    ));
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
    assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("HTTP/1.1 404 Not Found"));
    cancel.cancel();
    let _ = handle.await;
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core tg && cargo test --manifest-path linux/Cargo.toml -p netfix-tgproxy`
Expected: FAIL

- [ ] **Step 3: Implement `tg.rs` and `netfix-tgproxy/src/main.rs`**

- `netfix-tgproxy`: loads `NetfixConfig`, applies `POOL_SIZE`, `CFPROXY_ENABLED`, `CFPROXY.cache_dir`, `CFPROXY.user_domain`, `PROXY_SECRET`, `TLS_VERIFY`, `cffront::set_front_ips`, `cffront::set_plain_first`, binds `TcpListener`, runs `tgwsproxy::proxy::run_proxy`, cancels token on `SIGINT`/`SIGTERM`.
- `tg.rs`: implements `build_tg_proxy_url` and async `probe_dc_and_cf` (parallel TCP+WSS handshake checks for `DC1–DC5` using `DC_DEFAULT_IPS` / `cfg.tgproxy.dc_ips`, plus `cfproxy::default_cfproxy_domains()` + `pinned_cf_domain`).

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core tg && cargo test --manifest-path linux/Cargo.toml -p netfix-tgproxy`
Expected: PASS

---

### Task 6: Two-Phase Strategy Auto-Scanner (`netfixctl scan`)

**Files:**
- Create: `linux/crates/netfix-core/src/scanner.rs`
- Modify: `linux/crates/netfix-core/src/lib.rs` (export `pub mod scanner;`)

**Interfaces:**
- Consumes: `NetfixConfig`, `dpi::*`, `firewall::*`, `strategy::*`.
- Produces:
  - `StreamChunkProbe::pick_chunk_url(player_json: &str) -> Option<String>`, `StreamChunkProbe::score(reachable: usize, stream: Option<&StreamProbeResult>) -> f64`.
  - `scan_strategies(cfg: &NetfixConfig, engine: DpiEngineKind, include_discord: bool, include_ech: bool, on_progress: impl Fn(ScanProgress)) -> Result<ScanReport, NetfixError>`.

- [ ] **Step 1: Write failing tests for YouTube player chunk selection and scoring**

```rust
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
}

#[test]
fn test_stream_score_matches_android_formula() {
    let ok = StreamProbeResult { loaded: true, first_byte_ms: 100, speed_kbps: 400, bytes: 131072, failure: None, via_fallback: false };
    assert!((score(10, Some(&ok)) - 1210.0).abs() < 0.01);
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core scanner`
Expected: FAIL

- [ ] **Step 3: Implement `scanner.rs`**

- Port `QUICK_SITES`, `TEST_SITES`, `ECH_PROBE_HOST`, `StreamChunkProbe` (`youtubei/v1/player` iOS context + 128 KiB `Range: bytes=0-131071` download + `fallbackNodeUrl` retry).
- Implement `scan_strategies`:
  - For `DpiEngineKind::Ciadpi`: starts temporary `ciadpi` on free localhost port, creates `reqwest::Client` with `Proxy::all("socks5h://127.0.0.1:<port>")`.
  - For `DpiEngineKind::Nfqws`: requires root (`ExitCode::PermissionDenied`), creates `FirewallGuard` for `netfix_scan` (`NFQUEUE 201`), spawns temporary `nfqws --qnum=201`, runs `reqwest::Client` directly.
  - Phase 1 filters top 5 finalists on `QUICK_SITES` (`3s` timeout); Phase 2 evaluates finalists on `TEST_SITES` (`5s` timeout) + `StreamChunkProbe` and returns `ScanReport` with winning strategy.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core scanner`
Expected: PASS

---

### Task 7: DNS & `/etc/hosts` Management with Atomic Backup/Reset

**Files:**
- Create: `linux/crates/netfix-core/src/hosts.rs`
- Create: `linux/crates/netfix-core/src/dns.rs`
- Modify: `linux/crates/netfix-core/src/lib.rs` (export `pub mod hosts; pub mod dns;`)

**Interfaces:**
- Produces:
  - `hosts::apply_managed_block(existing: &str, entries: &[String]) -> Result<String, NetfixError>` and `hosts::strip_managed_block(existing: &str) -> Result<String, NetfixError>`.
  - `hosts::update_hosts_file(hosts_path: &Path, backup_path: &Path, entries: &[String]) -> Result<(), NetfixError>`, `hosts::reset_hosts_file(...)`.
  - `dns::render_resolved_dropin(servers: &[String]) -> String`, `dns::servers_for_mode(mode: DnsMode, custom: &[String]) -> Result<Vec<String>, NetfixError>`, `dns::apply_dns(...)`, `dns::reset_dns(...)`.

- [ ] **Step 1: Write failing tests for `/etc/hosts` block integrity & `systemd-resolved` drop-in**

```rust
#[test]
fn test_hosts_apply_and_strip_preserves_user_lines() {
    let orig = "127.0.0.1 localhost\n10.0.0.5 my-nas\n";
    let updated = apply_managed_block(orig, &["1.2.3.4 example.com".into()]).unwrap();
    assert!(updated.contains("10.0.0.5 my-nas"));
    assert!(updated.contains("# BEGIN NETFIX MANAGED\n1.2.3.4 example.com\n# END NETFIX MANAGED"));
    let stripped = strip_managed_block(&updated).unwrap();
    assert_eq!(stripped.trim_end(), orig.trim_end());
}

#[test]
fn test_hosts_partial_marker_aborts_without_truncating() {
    let broken = "127.0.0.1 localhost\n# BEGIN NETFIX MANAGED\n1.2.3.4 foo\n";
    let err = apply_managed_block(broken, &["5.6.7.8 bar".into()]).unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::InvalidInput);
    assert!(strip_managed_block(broken).is_err());
}

#[test]
fn test_render_resolved_dropin_formats_servers() {
    let conf = render_resolved_dropin(&["1.1.1.1".into(), "9.9.9.9".into()]);
    assert!(conf.contains("[Resolve]\nDNS=1.1.1.1 9.9.9.9\n"));
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core hosts && cargo test --manifest-path linux/Cargo.toml -p netfix-core dns`
Expected: FAIL

- [ ] **Step 3: Implement `hosts.rs` and `dns.rs`**

- `hosts.rs`: validates marker pairing (`# BEGIN NETFIX MANAGED` / `# END NETFIX MANAGED`), backs up original file on first edit if backup does not exist, writes atomically via temp file + rename (with write-in-place fallback if `EXDEV` on container bind mounts).
- `dns.rs`: validates server IP literals, renders `/etc/systemd/resolved.conf.d/90-netfix.conf`, detects backend (`systemd-resolved` vs `nmcli` vs `/etc/resolv.conf` backup), and implements `apply_dns` / `reset_dns`.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfix-core hosts && cargo test --manifest-path linux/Cargo.toml -p netfix-core dns`
Expected: PASS

---

### Task 8: `netfixctl` CLI, `setup` Engine Installer, and `systemd` Units

**Files:**
- Create: `linux/crates/netfix-core/src/setup.rs`
- Create: `linux/crates/netfixctl/Cargo.toml`
- Create: `linux/crates/netfixctl/src/main.rs`
- Create: `linux/systemd/netfix-dpi.service`
- Create: `linux/systemd/netfix-tgproxy.service`
- Create: `linux/systemd/netfix.target`
- Modify: `linux/crates/netfix-core/src/lib.rs` (export `pub mod setup;`)

**Interfaces:**
- Consumes: all `netfix_core` modules (`config`, `dpi`, `firewall`, `scanner`, `tg`, `dns`, `hosts`).
- Produces:
  - `netfixctl` subcommands:
    - `setup [--from-local <dir>] [--skip-download]`
    - `start|stop|restart|status [all|dpi|tg] [--json]`
    - `scan [--engine nfqws|ciadpi] [--no-discord] [--ech] [--apply] [--json]`
    - `dc-check [--json]`
    - `dns [set <mode> [servers...] | reset | status] [--json]`
    - `hosts [apply <file> | reset | status] [--json]`
    - `tg [link | qr | pin-cf <domain|auto>]`
    - `dpi-run` / `dpi-cleanup` (internal `systemd` entrypoints)

- [ ] **Step 1: Write failing tests for CLI parsing, JSON status serialization, and SHA-256 verification helper**

```rust
#[test]
fn test_cli_parses_status_json_and_scan_flags() {
    let cli = Cli::try_parse_from(["netfixctl", "--json", "status", "dpi"]).unwrap();
    assert!(cli.json);
    assert!(matches!(cli.command, Commands::Status { target: ServiceTarget::Dpi }));
}

#[test]
fn test_verify_sha256_matches_and_rejects_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("bin");
    std::fs::write(&file, b"hello").unwrap();
    let good = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    assert!(verify_sha256(&file, good).is_ok());
    assert!(verify_sha256(&file, "0000").is_err());
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path linux/Cargo.toml -p netfixctl`
Expected: FAIL

- [ ] **Step 3: Implement `setup.rs`, `netfixctl/src/main.rs`, and `linux/systemd/*` unit files**

- `setup.rs`: creates `/etc/netfix` (`0750 root:netfix`), `/var/lib/netfix/tgproxy` (`netfix:netfix`), `/usr/local/libexec/netfix`, writes default `config.toml` (`0640 root:netfix`) if missing, installs unit files, finds/downloads `nfqws` and `ciadpi` with `verify_sha256`, runs `systemctl daemon-reload`.
- `linux/systemd/netfix-dpi.service`: `ExecStart=/usr/local/bin/netfixctl dpi-run`, `ExecStopPost=/usr/local/bin/netfixctl dpi-cleanup`, `Restart=on-failure`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`.
- `linux/systemd/netfix-tgproxy.service`: `User=netfix`, `Group=netfix`, `ExecStart=/usr/local/bin/netfix-tgproxy --config /etc/netfix/config.toml`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/netfix/tgproxy`.
- `linux/systemd/netfix.target`: `Wants=netfix-dpi.service netfix-tgproxy.service`.
- `netfixctl/src/main.rs`: dispatches subcommands, emits clean human-readable output or `--json`, maps `NetfixError::exit_code()` to exact process exit codes (`0`..`4`).

- [ ] **Step 4: Run full workspace test suite and release/debug build check**

Run:
```bash
cargo test --manifest-path native/tgproxy-rust/Cargo.toml
cargo test --manifest-path linux/Cargo.toml
cargo build --manifest-path linux/Cargo.toml
```
Expected: All unit tests, `nft -c -f -` dry-run checks, and `netfix-tgproxy` smoke test PASS; binaries `netfixctl` and `netfix-tgproxy` compile cleanly.
