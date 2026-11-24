# NetFix Linux Headless — Design Specification

**Date:** 2026-11-19  
**Branch:** `linux-headless` (branched from `main`)  
**Scope:** Sub-project 1 of 2 — Linux headless core (`systemd` services, DPI bypass orchestration, local Telegram MTProto/WebSocket proxy, DNS/hosts management, and CLI/JSON control plane). Sub-project 2 (`linux-desktop` GUI + tray) will build on top of this core in a separate branch.

---

## 1. Purpose, Constraints, and Success Criteria

### Intended Outcome
Provide a Linux headless equivalent of the Windows **NetFix** architecture: two independent local bypass services managed through a single Rust CLI (`netfixctl`), without relying on any remote VPN server.

### Core Principles & Constraints
1. **Two independent local services (parity with Windows `NetFix`):**
   - **DPI Bypass (`netfix-dpi.service`):** Supports `nfqws` (from `bol-van/zapret`, primary Windows-like kernel-queue engine using `nftables`/`iptables` `NFQUEUE` without TUN) and `ciadpi` (from `hufrea/byedpi`, userspace SOCKS5 or `transparent` redirect mode).
   - **Telegram Proxy (`netfix-tgproxy.service`):** Runs an integrated Rust MTProto-over-WebSocket proxy built on `native/tgproxy-rust`.
2. **Non-destructive repository layout:** Keep Android `app/` untouched in `linux/`; integrate `native/tgproxy-rust` cleanly as a shared crate in the Linux workspace without breaking Android library builds.
3. **Engine acquisition:** Do not vendor C sources for `zapret`/`byedpi` in git; `netfixctl setup` locates installed binaries in `PATH` or `/usr/local/libexec/netfix/` and can download/verify or build official upstream releases.
4. **Privilege separation:** `netfix-tgproxy.service` runs unprivileged (`DynamicUser=yes` or dedicated `netfix` user). Elevated privileges (`CAP_NET_ADMIN`, `CAP_NET_RAW`, or `root`) are isolated to `netfix-dpi.service` (when using `nfqws` or `ciadpi --transparent`) and explicit administrative `netfixctl` subcommands (`dns`, `hosts`, `setup`).
5. **GUI-ready contract:** Machine-readable `--json` output on control/diagnostic commands (`status`, `scan`, `dc-check`, `dns`, `hosts`) so `linux-desktop` can wrap `netfixctl` directly without duplicating core logic.

### Success Criteria
- Both `netfix-dpi.service` and `netfix-tgproxy.service` can be enabled, started, stopped, and inspected independently via `netfixctl` and `systemctl`.
- `netfixctl dpi-cleanup` and `ExecStopPost` always remove `netfix` firewall tables cleanly on stop or crash.
- `netfixctl scan` finds working strategies for both `nfqws` and `ciadpi` using multi-host + YouTube stream-chunk verification and persists them per network profile.
- `netfixctl dc-check`, `netfixctl dns`, and `netfixctl hosts` operate idempotently with rollback/backup support.
- All unit tests, `nft -c -f -` dry-run syntax validation, and local proxy smoke tests pass.

---

## 2. Repository & Workspace Architecture

```text
NetFixMobile/
├── native/tgproxy-rust/              # Shared Rust crate (cdylib for Android + rlib for Linux)
│   ├── Cargo.toml                    # crate-type = ["cdylib", "rlib"]
│   └── src/
│       ├── lib.rs                    # Exposes run_proxy/Config/Stats + JNI/C-ABI exports
│       ├── cffront.rs                # Restored/implemented CF front & fast-fail module
│       ├── cfproxy.rs
│       ├── config.rs
│       ├── crypto.rs
│       ├── balancer.rs
│       ├── proxy.rs
│       └── ws.rs
└── linux/
    ├── Cargo.toml                    # Workspace: netfix-core, netfixctl, netfix-tgproxy
    ├── crates/
    │   ├── netfix-core/              # Config, firewall, engines, scanner, DNS/hosts, DC probe
    │   ├── netfixctl/                # User CLI + `dpi-run` / `dpi-cleanup` service entrypoints
    │   └── netfix-tgproxy/           # Daemon binary wrapping native/tgproxy-rust
    ├── presets/
    │   ├── strategies-nfqws.toml     # Curated zapret nfqws strategy presets
    │   ├── strategies-ciadpi.toml    # Ported byedpi strategies from NetFixMobile
    │   └── hostlists/                # Default domain lists (YouTube, Discord, AI, etc.)
    └── systemd/
        ├── netfix-dpi.service
        ├── netfix-tgproxy.service
        └── netfix.target
```

### Shared `native/tgproxy-rust` Adaptation
1. Update `native/tgproxy-rust/Cargo.toml` `crate-type` from `["cdylib"]` to `["cdylib", "rlib"]` so `netfix-tgproxy` can link against it natively in Rust while Android `cargo-ndk` continues producing `libtgwsproxy.so`.
2. Implement `native/tgproxy-rust/src/cffront.rs` matching all symbols referenced by `lib.rs`, `proxy.rs`, and `cfproxy.rs`:
   - Constants: `DIRECT_FAST_TIMEOUT`, `DIRECT_FAST_COOLDOWN`, `DIRECT_RACE_HEAD_START`.
   - State setters/queries: `enabled()`, `direct_fast_fail()`, `set_direct_fast_fail(bool)`, `set_front_ips(Vec<String>)`, `set_plain_first(bool)`, `forget_network_state()`, `direct_ok((i32, i32))`, `mark_direct_ok((i32, i32))`, `forget_direct_ok((i32, i32))`, `check_direct_in_background(...)`.
   - Connection helpers: `connect_known(domain, path)`, `connect_any(domain, path)`, `cf_ws_connect(ip, domain, path, timeout)`.
   - Security improvement: allow toggling TLS certificate verification (`tls_verify: bool` in config, defaulting to `true` on Linux for Cloudflare/DoH paths while keeping `NoVerify` opt-in for direct DC IP-SNI mismatch compatibility if needed).

---

## 3. Configuration & State Layout

- **Config file:** `/etc/netfix/config.toml` (permissions `0640`, owner `root:netfix` so unprivileged `netfix-tgproxy` can read `[tgproxy].secret` without making it world-readable; overridable via `--config <path>` or `NETFIX_CONFIG`).
- **State/backup directory:** `/var/lib/netfix/` (`/var/lib/netfix/tgproxy/` owned by `netfix:netfix` for CF domain cache and auto-generated secret if stored separately).
- **Engine binary directory:** `/usr/local/libexec/netfix/` (fallback search in `PATH`).

### Key Sections of `config.toml`
- `[general]`: `active_network_override`, `log_level`.
- `[dpi]`:
  - `enabled = true`
  - `engine = "nfqws"` (`"nfqws"` | `"ciadpi"`)
  - `ciadpi_mode = "socks5"` (`"socks5"` | `"transparent"`)
  - `socks_bind = "127.0.0.1"` / `socks_port = 1080`
  - `transparent_port = 11080`
  - `nfqueue_num = 200`
  - `fwmark = 0x40000000`
  - `game_filter = false` (`false` = TCP 80,443 + UDP 443; `true` = also UDP 1024-65535)
  - `ipset_mode = "any"` (`"any"` | `"loaded"` | `"none"`)
  - `active_strategy_nfqws`, `active_strategy_ciadpi`
  - `[dpi.network_strategies.<network_key>]`: per-interface/SSID saved winning strategies.
- `[tgproxy]`:
  - `enabled = true`
  - `bind_ip = "127.0.0.1"`
  - `port = 1443`
  - `secret = "<32-hex>"` (generated on `setup` or first start if empty)
  - `pool_size = 4`
  - `dc_ips = "2:149.154.167.220,4:149.154.167.220"`
  - `cf_enabled = true`
  - `cf_priority = true`
  - `pinned_cf_domain = ""`
  - `cf_front_ips = []`
  - `cf_plain_first = false` (safer default on Linux; configurable)
  - `tls_verify = true`
- `[dns]`:
  - `mode = "system"` (`"system"` | `"cloudflare"` | `"google"` | `"quad9"` | `"adguard"` | `"custom"`)
  - `custom_servers = []`

---

## 4. DPI Bypass Subsystem (`netfix-core::dpi` & `netfix-core::firewall`)

### 4.1 Firewall Backend Abstraction
A `FirewallBackend` trait renders and applies rules atomically:
1. **`NftablesBackend` (primary):**
   - Uses a single `inet` table (`table inet netfix` for runtime, `table inet netfix_scan` for scanner) covering both IPv4 and IPv6.
   - Generates a complete script passed to `nft -f -` (and validated in tests via `nft -c -f -`).
   - Cleanup executes `nft delete table inet netfix` (ignoring non-existent table errors).
2. **`IptablesBackend` (fallback when `nft` is unavailable or legacy iptables-only kernel):**
   - Creates dedicated chains `NETFIX_DPI` in `mangle`/`nat`/`filter` for `iptables` and `ip6tables` (both `-w 5`).
   - Cleanup detaches and flushes/deletes only `NETFIX_DPI` chains without disturbing user firewall rules.

### 4.2 Data Flow by Engine Mode

#### Mode A: `nfqws` (Primary, Windows `winws.exe` equivalent)
- **No TUN interface, no SOCKS5 proxy.**
- Outbound (and optionally inbound SYN-ACK/RST) packets matching target ports are queued to `NFQUEUE` (`queue num 200`, `bypass` flag set so traffic is not blackholed if the service stops unexpectedly):
  - `meta mark & 0x40000000 == 0` prevents infinite re-queueing of packets injected by `nfqws --dpi-desync-fwmark=0x40000000`.
  - TCP `dport { 80, 443 }` (limited via `ct original packets 1-15` where supported, or connection-tracking marks, to minimize CPU overhead).
  - UDP `dport 443` (plus `1024-65535` when `game_filter = true`, limited to initial packets per flow).
  - When `ipset_mode == "loaded"`, packets are matched against a populated `nft set` (`netfix_ipset_v4` / `netfix_ipset_v6`).
- `nfqws` is spawned with `--qnum=200 --dpi-desync-fwmark=0x40000000` plus strategy flags and hostlists.

#### Mode B: `ciadpi` (`byedpi`)
- **`socks5` sub-mode (unprivileged):** Spawns `ciadpi --ip <bind> --port <port> <strategy_args>`; no firewall rules applied.
- **`transparent` sub-mode (privileged):** Spawns `ciadpi --ip 127.0.0.1 --port 11080 --transparent <strategy_args>`.
  - Firewall redirects outbound IPv4 TCP `dport { 80, 443 }` (excluding traffic from `netfix-dpi` user/group or loopback `127.0.0.0/8`) to `:11080`.
  - Rejects IPv4 UDP `443` and IPv6 TCP/UDP `80, 443` (matching `RootDpiRules.kt` behavior so apps fall back to IPv4 TCP through `ciadpi`).

### 4.3 Service Lifecycle (`netfixctl dpi-run` & `dpi-cleanup`)
1. `dpi-run` validates binary presence and config, registers `SIGINT`/`SIGTERM` handlers, installs firewall rules, spawns `nfqws` or `ciadpi`, and monitors child exit.
2. On signal or child exit, `dpi-run` terminates the child process gracefully (`SIGTERM` -> timeout -> `SIGKILL`) and cleans up firewall rules.
3. `netfix-dpi.service` also specifies `ExecStopPost=/usr/local/bin/netfixctl dpi-cleanup` so rules are removed even after `SIGKILL`.

---

## 5. Strategy Auto-Selection (`netfixctl scan`)

### Architecture
Ported from `StrategyTester.kt` and `StreamChunkProbe.kt` into `netfix-core::scanner`:

1. **Two-phase evaluation:**
   - **Phase 1 (Quick filter):** Tests all candidate strategies against `QUICK_SITES` (YouTube, `i.ytimg.com`, `yt3.ggpht.com`, `youtubei.googleapis.com`, `manifest.googlevideo.com`, `googlevideo.com` CDN nodes, Discord hosts, optional `cloudflare-ech.com`) with a short timeout (`3s`).
   - **Phase 2 (Finalists):** Top 5 candidates from Phase 1 are tested against full `TEST_SITES` (`5s` timeout) plus **YouTube video stream chunk probe** (fetches player JSON via `youtubei/v1/player` with iOS client context, selects lowest-bitrate video format `>= 128 KiB`, downloads `Range: bytes=0-131071`, measures TTFC and throughput KB/s).
   - **Scoring:** `reachable_hosts * 100.0 + 1000.0 / max(first_byte_ms, 20) + speed_kbps * 0.5` (with fallback-node penalty identical to `StreamChunkProbe.score`).
2. **Engine-specific execution:**
   - **`ciadpi` scan:** Spawns temporary `ciadpi` on a free localhost port; HTTP/HTTPS probe requests go through `socks5h://127.0.0.1:<port>`.
   - **`nfqws` scan:** Requires `CAP_NET_ADMIN`/root; creates an isolated `table inet netfix_scan` (`NFQUEUE 201`) and runs `nfqws --qnum=201` per strategy while `reqwest` probes hosts directly; guarantees cleanup of `netfix_scan` via RAII `Drop` guard + `ctrlc`/signal handler.
   - If `netfix-dpi.service` is currently active, `scan` pauses it before scanning and restores/restarts it with the chosen strategy afterward.
3. **Persistence:** Saves winning strategy under `[dpi.network_strategies.<iface_or_ssid>]` and sets active strategy in `config.toml`.

---

## 6. Telegram Proxy & Diagnostics (`netfix-tgproxy` & `netfixctl dc-check`)

1. **Daemon (`netfix-tgproxy`):**
   - Loads `[tgproxy]` settings from `config.toml` (auto-generates and persists a 32-hex secret if missing).
   - Calls `tgwsproxy::proxy::run_proxy(...)` directly inside a Tokio multi-thread runtime, passing `CancellationToken` wired to `SIGTERM`/`SIGINT`.
   - Applies CF config (`CFPROXY_ENABLED`, `CFPROXY.user_domain`, `cffront` flags, cache dir `/var/lib/netfix/tgproxy`).
   - Periodically logs stats to `stdout`/`journald` and supports `SIGHUP` or `systemctl restart netfix-tgproxy` on config change.
2. **CLI helpers:**
   - `netfixctl tg link`: prints `tg://proxy?server=127.0.0.1&port=<port>&secret=dd<secret>` (and optional ASCII QR).
   - `netfixctl dc-check [--json]`: probes Telegram `DC1–DC5` direct IP latency/WSS handshake and tests known Cloudflare fallback domains (`kws2.<domain>:443/apiws`), reporting latency and HTTP status (`101` Works / `429` Busy / Fail), mirroring `CfProxyChecker.kt` and Windows NetFix DC diagnostics.

---

## 7. DNS, `/etc/hosts`, and Engine Setup

### 7.1 DNS Management (`netfixctl dns`)
- **Primary (`systemd-resolved` detected via `systemctl is-active systemd-resolved`):**
  - Writes `/etc/systemd/resolved.conf.d/90-netfix.conf` with selected DNS servers (and optional DoT) and reloads `systemd-resolved`, or applies per-link via `resolvectl dns <iface> <servers>`.
  - `netfixctl dns reset` removes the drop-in and calls `resolvectl revert <iface>`.
- **Fallbacks:**
  - NetworkManager (`nmcli`): updates `ipv4.dns` / `ipv4.ignore-auto-dns` on active connection with saved previous state in `/var/lib/netfix/dns-backup.json`.
  - Direct `/etc/resolv.conf` (only when neither `systemd-resolved` nor `NetworkManager` manages it): backs up original `/etc/resolv.conf` to `/var/lib/netfix/resolv.conf.bak` before writing managed servers, and restores on `reset`.

### 7.2 `/etc/hosts` Management (`netfixctl hosts`)
- Manages a clearly delimited block:
  ```text
  # BEGIN NETFIX MANAGED
  ...
  # END NETFIX MANAGED
  ```
- Backs up original `/etc/hosts` to `/var/lib/netfix/hosts.bak` on first modification, updates via temp-file + atomic rename on same filesystem (or direct write with lock if `/etc/hosts` is a bind mount in containers).
- `netfixctl hosts reset` strips only the `# BEGIN NETFIX MANAGED ... # END NETFIX MANAGED` block, preserving all user entries.

### 7.3 Engine Setup (`netfixctl setup`)
- Inspects `PATH` and `/usr/local/libexec/netfix/` for `nfqws`, `ciadpi`, `nft`, `iptables`.
- Can fetch/install official upstream releases (`bol-van/zapret` and `hufrea/byedpi`) into `/usr/local/libexec/netfix/` with SHA-256 verification (or build from source tarball if prebuilt arch binary is unavailable), installs `systemd` unit files into `/etc/systemd/system/`, creates `netfix` system user, generates initial `/etc/netfix/config.toml`, and runs `systemctl daemon-reload`.

---

## 8. Error Handling & Reliability

- **Fail-safe firewall cleanup:** RAII guards in `scan` and `dpi-run`, plus `ExecStopPost` in `netfix-dpi.service`, guarantee no orphaned `netfix` / `netfix_scan` tables remain.
- **Root check with clear diagnostics:** Commands requiring root (`dpi-run` for `nfqws`/`transparent`, `scan --engine nfqws`, `dns`, `hosts`, `setup`) check `geteuid() == 0` upfront and emit actionable error messages (and structured JSON errors under `--json`).
- **Port conflict handling:** `ProxyPortResolver` checks port availability before starting `ciadpi` or `netfix-tgproxy` and falls back to nearby free ports when enabled.
- **Exit codes:** `0` success, `1` runtime/network failure, `2` invalid CLI/config, `3` missing privileges, `4` missing engine binary (`nfqws`/`ciadpi`).

---

## 9. Testing Strategy

1. **Unit tests (`cargo test` across workspace):**
   - `netfix-core::firewall`: deterministic rendering of `nftables` and `iptables` rulesets for `nfqws` (with/without `game_filter`, `ipset_mode = any|loaded|none`), `ciadpi --transparent`, and `netfix_scan`.
   - `netfix-core::strategy`: `{sni}` substitution, forbidden CLI flag sanitization, `StreamChunkProbe::score` calculations, JSON response parsing.
   - `netfix-core::hosts` & `dns`: idempotent `# BEGIN NETFIX MANAGED` insertion, update, and removal without altering surrounding lines; `resolved` drop-in rendering.
   - `tgwsproxy`: `cffront` state machine, `cfproxy` domain decoding/cooldowns, `crypto` stream & `MsgSplitter`, `parse_cidr_pool`.
2. **Firewall syntax validation test:**
   - When `nft` is installed on the test host, run `nft -c -f -` against all generated `nftables` scripts in tests (validates kernel-parser grammar without root or modifying host tables).
3. **Local integration / smoke tests (unprivileged):**
   - Start `netfix-tgproxy` against an ephemeral localhost port, verify TCP listen readiness, HTTP request rejection (`404 Not Found`), and invalid MTProto handshake handling without external network calls.
   - Test `netfixctl --json status` and config round-trip against a temporary config directory.
