use std::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String, // "INFO" | "WARN" | "ERROR"
    pub message: String,
    pub service: String,
}

pub fn get_recent_journal_logs(lines: usize) -> Vec<LogEntry> {
    let mut entries = Vec::new();

    let out = Command::new("journalctl")
        .args([
            "-u",
            "netfix-dpi.service",
            "-u",
            "netfix-tgproxy.service",
            "-n",
            &lines.to_string(),
            "--no-pager",
            "-o",
            "short-iso",
        ])
        .output();

    if let Ok(output) = out {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            // Parse journal line: 2026-11-25T00:54:08+03:00 hostname service[pid]: msg
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() >= 4 {
                let timestamp = parts[0].to_string();
                let svc_raw = parts[2];
                let service = if svc_raw.contains("dpi") {
                    "netfix-dpi"
                } else if svc_raw.contains("tgproxy") {
                    "netfix-tgproxy"
                } else {
                    "systemd"
                }
                .to_string();

                let msg = parts[3].to_string();
                let lower = msg.to_lowercase();
                let level = if lower.contains("error") || lower.contains("failed") || lower.contains("ошибка") {
                    "ERROR"
                } else if lower.contains("warn") || lower.contains("предупреждение") {
                    "WARN"
                } else {
                    "INFO"
                }
                .to_string();

                entries.push(LogEntry {
                    timestamp,
                    level,
                    message: msg,
                    service,
                });
            }
        }
    }

    entries
}
