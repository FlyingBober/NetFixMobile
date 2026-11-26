#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autostart;
mod daemon;
mod latency;
mod logs;
#[allow(dead_code)]
#[path = "../../netfixctl/src/qr.rs"]
mod qr;
mod state;
mod system_proxy;
mod tun;

use serde::{Deserialize, Serialize};
use state::{load_state, save_state, GuiState};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, WindowEvent,
};
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Debug, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub identifier: String,
    pub attribution: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ScanStatus {
    pub running: bool,
    pub phase: String,
    pub index: usize,
    pub total: usize,
    pub strategy_name: String,
    pub passed: String,
    pub detail: String,
    pub percent: u8,
    pub finished_ok: Option<bool>,
    pub message: Option<String>,
}

struct SharedScanState {
    status: Arc<Mutex<ScanStatus>>,
    child_pid: Arc<Mutex<Option<u32>>>,
}

const APP_VERSION: &str = match option_env!("NETFIX_APP_VERSION") {
    Some(v) if !v.is_empty() => v,
    _ => env!("CARGO_PKG_VERSION"),
};

#[tauri::command]
fn get_app_info() -> AppInfo {
    AppInfo {
        name: "NetFixLinux".to_string(),
        version: APP_VERSION.to_string(),
        identifier: "dev.flyingbober.netfixlinux".to_string(),
        attribution: format!("NetFixLinux v{APP_VERSION} — (fork of NetFix Mobile by rupleide)"),
    }
}

#[tauri::command]
fn get_gui_state() -> GuiState {
    load_state()
}

#[tauri::command]
fn accept_disclaimer() -> Result<(), String> {
    let mut state = load_state();
    state.disclaimer_accepted = true;
    save_state(&state)
}

#[tauri::command]
async fn get_status() -> Result<daemon::AppStatus, String> {
    tokio::task::spawn_blocking(daemon::get_app_status)
        .await
        .map_err(|e| format!("Task join error: {e}"))
}

fn apply_dpi_with_mode(enable: bool, traffic_mode: &str) -> Result<(), String> {
    if enable && !tun::is_polkit_installed() {
        tun::install_polkit_policy()?;
    }
    match traffic_mode {
        "system_proxy" => {
            if enable {
                daemon::toggle_dpi(true)?;
                system_proxy::enable_socks5_proxy("127.0.0.1", 1080)?;
            } else {
                let _ = system_proxy::disable_socks5_proxy();
                daemon::toggle_dpi(false)?;
            }
        }
        _ => {
            daemon::toggle_dpi(enable)?;
        }
    }
    Ok(())
}

#[tauri::command]
async fn toggle_connect(connect: bool) -> Result<daemon::AppStatus, String> {
    let mode = load_state().traffic_mode;
    tokio::task::spawn_blocking(move || -> Result<daemon::AppStatus, String> {
        apply_dpi_with_mode(connect, &mode)?;
        daemon::toggle_tg(connect)?;
        Ok(daemon::get_app_status())
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

#[tauri::command]
async fn toggle_dpi_service(enable: bool) -> Result<daemon::AppStatus, String> {
    let mode = load_state().traffic_mode;
    tokio::task::spawn_blocking(move || -> Result<daemon::AppStatus, String> {
        apply_dpi_with_mode(enable, &mode)?;
        Ok(daemon::get_app_status())
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

#[tauri::command]
async fn set_traffic_mode(mode: String) -> Result<GuiState, String> {
    tokio::task::spawn_blocking(move || -> Result<GuiState, String> {
        let mut state = load_state();
        if state.traffic_mode == "system_proxy" && mode != "system_proxy" {
            let _ = system_proxy::disable_socks5_proxy();
        }
        state.traffic_mode = mode;
        save_state(&state)?;
        Ok(state)
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

#[tauri::command]
fn get_strategies() -> Vec<daemon::StrategyItem> {
    daemon::get_preset_strategies()
}

#[tauri::command]
async fn apply_strategy(command: String) -> Result<(), String> {
    let mut state = load_state();
    state.selected_strategy = command.clone();
    let _ = save_state(&state);

    tokio::task::spawn_blocking(move || daemon::apply_strategy_args(&command))
        .await
        .map_err(|e| format!("Task join error: {e}"))?
}

fn parse_scan_line(line: &str) -> Option<ScanStatus> {
    // Format from netfixctl scan: "[quick 1/10] strategy-name -> 3/4 sites (score 85.0)"
    let trimmed = line.trim();
    if !trimmed.starts_with('[') {
        return None;
    }
    let close_idx = trimmed.find(']')?;
    let header = &trimmed[1..close_idx];
    let rest = trimmed[close_idx + 1..].trim();

    let mut header_parts = header.split_whitespace();
    let phase = header_parts.next()?.to_string();
    let frac = header_parts.next()?;
    let (idx_str, tot_str) = frac.split_once('/')?;
    let index: usize = idx_str.parse().ok()?;
    let total: usize = tot_str.parse().ok()?;

    let (strategy_name, passed) = if let Some((name, result)) = rest.split_once("->") {
        (name.trim().to_string(), result.trim().to_string())
    } else {
        (rest.to_string(), String::new())
    };

    let ratio = if total > 0 {
        (index as f64 / total as f64).min(1.0)
    } else {
        0.0
    };
    let percent = if phase == "final" {
        (75.0 + ratio * 23.0).round() as u8
    } else {
        (ratio * 75.0).round() as u8
    };

    Some(ScanStatus {
        running: true,
        phase,
        index,
        total,
        strategy_name,
        passed,
        detail: trimmed.to_string(),
        percent,
        finished_ok: None,
        message: None,
    })
}

#[tauri::command]
fn get_scan_status(scan_state: tauri::State<'_, SharedScanState>) -> ScanStatus {
    scan_state.status.lock().map(|s| s.clone()).unwrap_or_default()
}

#[tauri::command]
fn cancel_auto_scan(scan_state: tauri::State<'_, SharedScanState>) -> Result<(), String> {
    if let Ok(guard) = scan_state.child_pid.lock() {
        if let Some(pid) = *guard {
            let _ = Command::new("pkexec")
                .args(["kill", "-TERM", &pid.to_string()])
                .status()
                .or_else(|_| Command::new("kill").args(["-TERM", &pid.to_string()]).status());
        }
    }
    Ok(())
}

#[tauri::command]
async fn run_auto_scan(scan_state: tauri::State<'_, SharedScanState>) -> Result<String, String> {
    {
        let mut st = scan_state
            .status
            .lock()
            .map_err(|_| "State lock poisoned".to_string())?;
        if st.running {
            return Err("Автоподбор уже запущен".to_string());
        }
        *st = ScanStatus {
            running: true,
            phase: "prepare".to_string(),
            index: 0,
            total: 1,
            strategy_name: "Запрос прав и остановка DPI-сервиса...".to_string(),
            passed: String::new(),
            detail: "На время перебора стратегий DPI временно останавливается, Telegram Proxy продолжает работу.".to_string(),
            percent: 4,
            finished_ok: None,
            message: None,
        };
    }

    let ctl = daemon::resolve_netfixctl_path();
    let mut child = match tokio::process::Command::new("pkexec")
        .args([&ctl, "scan", "--apply"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            if let Ok(mut st) = scan_state.status.lock() {
                st.running = false;
                st.finished_ok = Some(false);
                st.message = Some(format!("Не удалось запустить netfixctl scan: {e}"));
            }
            return Err(format!("Не удалось запустить netfixctl scan: {e}"));
        }
    };

    if let Ok(mut pid_guard) = scan_state.child_pid.lock() {
        *pid_guard = child.id();
    }

    let stderr = child.stderr.take();
    let stdout = child.stdout.take();
    let shared_status = Arc::clone(&scan_state.status);

    let stderr_handle = tokio::spawn(async move {
        let mut lines_buf = Vec::new();
        if let Some(err_stream) = stderr {
            let mut reader = BufReader::new(err_stream).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if let Some(parsed) = parse_scan_line(&line) {
                    if let Ok(mut st) = shared_status.lock() {
                        *st = parsed;
                    }
                } else if !line.trim().is_empty() {
                    if let Ok(mut st) = shared_status.lock() {
                        st.detail = line.trim().to_string();
                    }
                }
                lines_buf.push(line);
            }
        }
        lines_buf.join("\n")
    });

    let stdout_handle = tokio::spawn(async move {
        let mut out_buf = Vec::new();
        if let Some(out_stream) = stdout {
            let mut reader = BufReader::new(out_stream).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                out_buf.push(line);
            }
        }
        out_buf.join("\n")
    });

    let status = child
        .wait()
        .await
        .map_err(|e| format!("Ошибка ожидания завершения сканирования: {e}"))?;

    if let Ok(mut pid_guard) = scan_state.child_pid.lock() {
        *pid_guard = None;
    }

    let err_out = stderr_handle.await.unwrap_or_default();
    let std_out = stdout_handle.await.unwrap_or_default();

    daemon::invalidate_status_cache();

    if status.success() {
        if let Ok(mut st) = scan_state.status.lock() {
            st.running = false;
            st.phase = "done".to_string();
            st.percent = 100;
            st.strategy_name = "Лучшая стратегия применена!".to_string();
            st.detail = "Служба DPI автоматически перезапущена.".to_string();
            st.finished_ok = Some(true);
            st.message = Some("Автоподбор успешно завершён".to_string());
        }
        Ok(std_out)
    } else {
        let msg = if !err_out.trim().is_empty() {
            err_out
        } else {
            "Автоподбор отменён или завершился с ошибкой".to_string()
        };
        if let Ok(mut st) = scan_state.status.lock() {
            st.running = false;
            st.phase = "error".to_string();
            st.finished_ok = Some(false);
            st.message = Some(msg.clone());
        }
        Err(msg)
    }
}

fn render_qr_svg(data: &str) -> String {
    let Ok(matrix) = qr::encode_qr_matrix(data.as_bytes()) else {
        return String::new();
    };
    let size = matrix.len();
    let quiet = 2usize;
    let total = size + quiet * 2;
    let mut rects = String::new();
    for (r, row) in matrix.iter().enumerate() {
        for (c, &dark) in row.iter().enumerate() {
            if dark {
                rects.push_str(&format!(
                    "<rect x=\"{}\" y=\"{}\" width=\"1\" height=\"1\"/>",
                    c + quiet,
                    r + quiet
                ));
            }
        }
    }
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total} {total}\" width=\"100%\" height=\"100%\" shape-rendering=\"crispEdges\"><rect width=\"{total}\" height=\"{total}\" fill=\"#ffffff\"/><g fill=\"#000000\">{rects}</g></svg>"
    )
}

#[tauri::command]
async fn get_tg_info() -> Result<serde_json::Value, String> {
    tokio::task::spawn_blocking(|| -> Result<serde_json::Value, String> {
        let link = daemon::get_tg_link()?;
        let status = daemon::get_app_status();
        let qr_svg = render_qr_svg(&link);
        Ok(serde_json::json!({
            "link": link,
            "qr_svg": qr_svg,
            "active": status.tg_active,
            "port": status.tg_port,
            "cf_enabled": status.tg_cf_enabled,
            "cf_priority": status.tg_cf_priority,
            "pinned_cf_domain": status.tg_pinned_cf_domain,
            "cf_front_ips": status.tg_cf_front_ips,
        }))
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

#[tauri::command]
async fn set_tg_cf_config(
    enabled: bool,
    priority: bool,
    pin_domain: String,
    front_ips: String,
) -> Result<daemon::AppStatus, String> {
    tokio::task::spawn_blocking(move || -> Result<daemon::AppStatus, String> {
        if !tun::is_polkit_installed() {
            tun::install_polkit_policy()?;
        }
        daemon::set_tg_cf_config(enabled, priority, &pin_domain, &front_ips)?;
        Ok(daemon::get_app_status())
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

#[tauri::command]
async fn toggle_tg_service(enable: bool) -> Result<daemon::AppStatus, String> {
    tokio::task::spawn_blocking(move || -> Result<daemon::AppStatus, String> {
        if enable && !tun::is_polkit_installed() {
            tun::install_polkit_policy()?;
        }
        daemon::toggle_tg(enable)?;
        Ok(daemon::get_app_status())
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

#[tauri::command]
async fn set_dns(mode: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || -> Result<String, String> {
        daemon::set_dns_mode(&mode)?;
        let mut state = load_state();
        state.dns_mode = mode.clone();
        let _ = save_state(&state);
        Ok(mode)
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

#[tauri::command]
async fn get_latencies() -> latency::LatencyReport {
    latency::measure_latencies().await
}

#[tauri::command]
async fn install_polkit() -> Result<(), String> {
    tokio::task::spawn_blocking(|| -> Result<(), String> {
        tun::install_polkit_policy()?;
        daemon::invalidate_status_cache();
        Ok(())
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

#[tauri::command]
fn is_polkit_ready() -> bool {
    tun::is_polkit_installed()
}

#[tauri::command]
async fn toggle_autostart(enable: bool) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || -> Result<bool, String> {
        autostart::set_autostart(enable)?;
        let mut state = load_state();
        state.autostart = enable;
        let _ = save_state(&state);
        Ok(autostart::is_autostart_enabled())
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

#[tauri::command]
async fn get_recent_logs(lines: Option<usize>) -> Result<Vec<logs::LogEntry>, String> {
    let count = lines.unwrap_or(120);
    tokio::task::spawn_blocking(move || logs::get_recent_journal_logs(count))
        .await
        .map_err(|e| format!("Task join error: {e}"))
}

#[tauri::command]
async fn copy_to_clipboard(text: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok()
            || std::env::var("XDG_SESSION_TYPE").as_deref() == Ok("wayland");

        let mut candidates: Vec<(&str, Vec<&str>)> = Vec::new();
        if is_wayland && which::which("wl-copy").is_ok() {
            candidates.push(("wl-copy", vec![]));
        }
        if which::which("xclip").is_ok() {
            candidates.push(("xclip", vec!["-selection", "clipboard"]));
        }
        if which::which("xsel").is_ok() {
            candidates.push(("xsel", vec!["--clipboard", "--input"]));
        }
        if !is_wayland && which::which("wl-copy").is_ok() {
            candidates.push(("wl-copy", vec![]));
        }

        for (bin, args) in candidates {
            if let Ok(mut child) = Command::new(bin)
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                if let Ok(status) = child.wait() {
                    daemon::invalidate_status_cache();

    if status.success() {
                        return Ok(());
                    }
                }
            }
        }

        Err("Не найдена утилита буфера обмена (wl-copy / xclip / xsel)".to_string())
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    Command::new("xdg-open")
        .arg(&url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Не удалось открыть ссылку ({url}): {e}"))?;
    Ok(())
}

fn main() {
    // Prevent WebKitGTK DMA-BUF compositing stalls/freezes during window resize on Linux Wayland/X11.
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }

    let shared_scan = SharedScanState {
        status: Arc::new(Mutex::new(ScanStatus::default())),
        child_pid: Arc::new(Mutex::new(None)),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(shared_scan)
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title(&format!(
                    "NetFixLinux v{APP_VERSION} — (fork of NetFix Mobile by rupleide)"
                ));
            }
            let quit_i = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Открыть NetFixLinux", true, None::<&str>)?;
            let toggle_i =
                MenuItem::with_id(app, "toggle", "Подключить / Отключить", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &toggle_i, &quit_i])?;

            let tray_icon = tauri::include_image!("icons/32x32.png");

            let tray = TrayIconBuilder::with_id("netfixlinux-tray")
                .icon(tray_icon)
                .tooltip("NetFixLinux — обход DPI и Telegram Proxy")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        app.exit(0);
                    }
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.unminimize();
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "toggle" => {
                        std::thread::spawn(|| {
                            let status = daemon::get_app_status();
                            let target = !(status.dpi_active && status.tg_active);
                            let mode = load_state().traffic_mode;
                            let _ = apply_dpi_with_mode(target, &mode);
                            let _ = daemon::toggle_tg(target);
                        });
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            if window.is_visible().unwrap_or(false) {
                                let _ = window.hide();
                            } else {
                                let _ = window.unminimize();
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;

            // Keep TrayIcon alive for the entire lifetime of the application
            app.manage(tray);

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let state = load_state();
                if state.minimize_to_tray {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_app_info,
            get_gui_state,
            accept_disclaimer,
            get_status,
            toggle_connect,
            toggle_dpi_service,
            set_traffic_mode,
            get_strategies,
            apply_strategy,
            run_auto_scan,
            get_scan_status,
            cancel_auto_scan,
            get_tg_info,
            set_tg_cf_config,
            toggle_tg_service,
            set_dns,
            get_latencies,
            install_polkit,
            is_polkit_ready,
            toggle_autostart,
            get_recent_logs,
            copy_to_clipboard,
            open_external_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running NetFixLinux application");
}
