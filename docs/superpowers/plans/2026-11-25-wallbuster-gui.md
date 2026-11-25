# WallBuster Linux Desktop GUI Implementation Plan

> **Goal:** Build the complete Linux Desktop GUI client for **WallBuster** (`dev.flyingbober.wallbuster`), adhering to Clash Verge + Nekoray design philosophy, featuring three traffic modes (Direct DPI, System Proxy via gsettings/kwriteconfig, TUN), Telegram Proxy with QR, live log terminal, and system tray.
> **Spec Reference:** `docs/superpowers/specs/2026-11-25-wallbuster-gui-design.md`

---

## Task Breakdown

- [ ] **Task 1: Project Scaffolding & Workspace Integration**
  - Scaffold `linux/crates/wallbuster-gui` with Tauri v2 + Vue 3 / Vite + Tailwind CSS.
  - Configure `Cargo.toml` workspace member and Tauri configuration (`tauri.conf.json`) with `dev.flyingbober.wallbuster`.
  - Add assets: icons (tray, app icon), .desktop file template, and Polkit policy template.

- [ ] **Task 2: Rust Backend IPC & System Integrations**
  - Implement `system_proxy.rs`: rootless detection and manipulation of GNOME (`gsettings`) and KDE (`kwriteconfig5`/`kwriteconfig6` + `qdbus`).
  - Implement `daemon_client.rs`: integration with `netfixctl --json` and `netfix-core` for DPI control and Telegram proxy management.
  - Implement `latency.rs`: asynchronous HTTP/TCP latency checks for YouTube, Discord, and Telegram DCs.
  - Implement `logs.rs`: streaming log collector emitting Tauri events for the UI console.
  - Implement `polkit.rs` & `autostart.rs`: check/install polkit policy and manage `~/.config/autostart/`.

- [ ] **Task 3: Frontend UI Components (Clash Verge + Nekoray Aesthetic)**
  - Sidebar component: fixed 200px width with icons and sub-header attribution: `(fork of NetFix Mobile by rupleide)`.
  - First-run Disclaimer Modal with localStorage/config persistence.
  - Dashboard view: Hero connect button with pulsating animation, status cards, latency badges, and traffic mode switcher.
  - Profiles / Strategies view: strategy cards with capability tags and auto-scan modal.
  - Telegram Proxy view: copy link, open in TG, and SVG QR-code renderer.
  - Logs view: Nekoray-style terminal with log level filters, pause/play, and clear.
  - Settings view: DNS switcher, Autostart toggle, Polkit helper status.

- [ ] **Task 4: System Tray & Window Lifecycle**
  - Configure Tauri v2 tray icon with dynamic states (active/inactive).
  - Implement minimize-to-tray on close and tray context menu actions.

- [ ] **Task 5: Packaging & Verification**
  - Verify build and tests across workspace.
  - Update `linux/package.sh` to optionally build `wallbuster` GUI package.
