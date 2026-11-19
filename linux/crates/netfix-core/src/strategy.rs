use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::NetfixError;

const DEFAULT_CIADPI_PRESETS_TOML: &str = include_str!("../../../presets/strategies-ciadpi.toml");
const DEFAULT_NFQWS_PRESETS_TOML: &str = include_str!("../../../presets/strategies-nfqws.toml");
const DEFAULT_HOSTLIST_TXT: &str = include_str!("../../../presets/hostlists/default.txt");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyPreset {
    pub name: String,
    #[serde(default)]
    pub category: String,
    pub args: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct StrategyPresetFile {
    #[serde(default)]
    strategy: Vec<StrategyPreset>,
}

pub fn load_presets_from_str(toml_str: &str) -> Result<Vec<StrategyPreset>, NetfixError> {
    let parsed: StrategyPresetFile = toml::from_str(toml_str)?;
    Ok(parsed.strategy)
}

pub fn load_presets(path: &Path) -> Result<Vec<StrategyPreset>, NetfixError> {
    let raw = std::fs::read_to_string(path)?;
    load_presets_from_str(&raw)
}

pub fn default_ciadpi_presets() -> Vec<StrategyPreset> {
    load_presets_from_str(DEFAULT_CIADPI_PRESETS_TOML)
        .expect("embedded strategies-ciadpi.toml must be valid TOML")
}

pub fn default_nfqws_presets() -> Vec<StrategyPreset> {
    load_presets_from_str(DEFAULT_NFQWS_PRESETS_TOML)
        .expect("embedded strategies-nfqws.toml must be valid TOML")
}

pub fn default_hostlist() -> &'static str {
    DEFAULT_HOSTLIST_TXT
}

pub fn sanitize_ciadpi_args(raw: &str) -> Result<Vec<String>, NetfixError> {
    let tokens = split_checked_args(raw)?;
    Ok(strip_flags(
        &tokens,
        &["--ip", "-i", "--port", "-p"],
        &["-i", "-p"],
        &["--help", "-h", "--version", "-v"],
    ))
}

pub fn sanitize_nfqws_args(raw: &str) -> Result<Vec<String>, NetfixError> {
    let tokens = split_checked_args(raw)?;
    Ok(strip_flags(
        &tokens,
        &["--qnum", "--dpi-desync-fwmark", "--pidfile"],
        &[],
        &["--daemon", "--help", "-h", "--version", "-v"],
    ))
}

pub fn expand_sni(args: &[String], sni: &str) -> Vec<String> {
    args.iter().map(|a| a.replace("{sni}", sni)).collect()
}

fn split_checked_args(raw: &str) -> Result<Vec<String>, NetfixError> {
    for ch in raw.chars() {
        if ch.is_control() {
            return Err(NetfixError::InvalidInput(
                "strategy contains disallowed control characters".into(),
            ));
        }
        if matches!(ch, ';' | '&' | '|' | '`' | '$' | '(' | ')' | '<' | '>') {
            return Err(NetfixError::InvalidInput(format!(
                "strategy contains disallowed shell metacharacter '{ch}'"
            )));
        }
    }
    shell_words::split(raw)
        .map_err(|err| NetfixError::InvalidInput(format!("invalid strategy quoting: {err}")))
}

fn strip_flags(
    tokens: &[String],
    value_flags: &[&str],
    attached_short_prefixes: &[&str],
    standalone_flags: &[&str],
) -> Vec<String> {
    let mut out = Vec::with_capacity(tokens.len());
    let mut skip_next = false;

    for tok in tokens {
        if skip_next {
            skip_next = false;
            continue;
        }

        if standalone_flags.contains(&tok.as_str()) {
            continue;
        }

        if value_flags.contains(&tok.as_str()) {
            skip_next = true;
            continue;
        }

        if value_flags
            .iter()
            .any(|flag| tok.starts_with(flag) && tok.as_bytes().get(flag.len()) == Some(&b'='))
        {
            continue;
        }

        if attached_short_prefixes
            .iter()
            .any(|prefix| tok.starts_with(prefix) && tok.len() > prefix.len())
        {
            continue;
        }

        out.push(tok.clone());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExitCode;

    #[test]
    fn test_sanitize_strips_conflicting_flags_and_rejects_newlines() {
        let args = sanitize_ciadpi_args("--ip 0.0.0.0 --port=9999 -o1 -n {sni} --help").unwrap();
        assert_eq!(expand_sni(&args, "google.com"), vec!["-o1", "-n", "google.com"]);
        assert!(sanitize_nfqws_args("--dpi-desync=fake\nrm -rf /").is_err());
        let nfq = sanitize_nfqws_args("--qnum=10 --dpi-desync-fwmark=0x1 --dpi-desync=fake").unwrap();
        assert_eq!(nfq, vec!["--dpi-desync=fake"]);
    }

    #[test]
    fn test_sanitize_rejects_shell_metacharacters_and_control_chars() {
        for bad in [
            "-o1; id",
            "-o1 && whoami",
            "-o1 | cat",
            "-o1 `id`",
            "-o1 $(id)",
            "-o1\r-d1",
            "-o1\0-d1",
        ] {
            let err = sanitize_ciadpi_args(bad).unwrap_err();
            assert_eq!(err.exit_code(), ExitCode::InvalidInput);
        }
    }

    #[test]
    fn test_sanitize_strips_short_and_nfqws_daemon_flags() {
        let ciadpi = sanitize_ciadpi_args("-i127.0.0.1 -p 8888 -v -h -s1").unwrap();
        assert_eq!(ciadpi, vec!["-s1"]);

        let nfq = sanitize_nfqws_args(
            "--daemon --pidfile /tmp/nfq.pid --qnum 200 --dpi-desync-fwmark 0x1 --dpi-desync=disorder2 --version",
        )
        .unwrap();
        assert_eq!(nfq, vec!["--dpi-desync=disorder2"]);
    }

    #[test]
    fn test_embedded_presets_and_hostlist_parse_and_sanitize() {
        let ciadpi_presets = default_ciadpi_presets();
        assert_eq!(ciadpi_presets.len(), 82);
        assert_eq!(
            ciadpi_presets.iter().filter(|p| p.category == "youtube").count(),
            8
        );
        assert_eq!(
            ciadpi_presets.iter().filter(|p| p.category == "discord").count(),
            1
        );
        for preset in &ciadpi_presets {
            let sanitized = sanitize_ciadpi_args(&preset.args)
                .unwrap_or_else(|e| panic!("preset {} failed: {e}", preset.name));
            assert!(!sanitized.is_empty(), "preset {} became empty", preset.name);
        }

        let nfqws_presets = default_nfqws_presets();
        assert!(!nfqws_presets.is_empty());
        for preset in &nfqws_presets {
            let sanitized = sanitize_nfqws_args(&preset.args)
                .unwrap_or_else(|e| panic!("preset {} failed: {e}", preset.name));
            assert!(!sanitized.is_empty(), "preset {} became empty", preset.name);
        }

        let hostlist = default_hostlist();
        assert!(hostlist.contains("youtube.com"));
        assert!(hostlist.contains("googlevideo.com"));
        assert!(hostlist.contains("discord.com"));
        assert!(hostlist.contains("openai.com"));
    }
}
