use std::path::Path;

use crate::config::{ensure_parent_dir, write_atomic_with_mode};
use crate::NetfixError;

pub const MANAGED_BEGIN: &str = "# BEGIN NETFIX MANAGED";
pub const MANAGED_END: &str = "# END NETFIX MANAGED";
pub const SYSTEM_HOSTS_PATH: &str = "/etc/hosts";
pub const SYSTEM_HOSTS_BACKUP_PATH: &str = "/var/lib/netfix/hosts.bak";

/// Validates user-supplied `/etc/hosts` entries before writing them into the managed block.
fn validate_entries(entries: &[String]) -> Result<Vec<&str>, NetfixError> {
    let mut validated = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.contains('\n') || entry.contains('\r') || entry.contains('\0') {
            return Err(NetfixError::InvalidInput(
                "hosts entry must not contain newline or NUL characters".into(),
            ));
        }
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return Err(NetfixError::InvalidInput(
                "hosts entry must not be empty or whitespace-only".into(),
            ));
        }
        if trimmed.contains(MANAGED_BEGIN) || trimmed.contains(MANAGED_END) {
            return Err(NetfixError::InvalidInput(
                "hosts entry must not contain managed block marker strings".into(),
            ));
        }
        validated.push(trimmed);
    }
    Ok(validated)
}

fn split_lines(raw: &str) -> Vec<&str> {
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split_terminator('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect()
}

fn join_lines(lines: &[&str]) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

/// Finds and validates the `(begin_idx, end_idx)` range of the NetFix managed block.
fn find_managed_block(lines: &[&str]) -> Result<Option<(usize, usize)>, NetfixError> {
    let mut begin_idx: Option<usize> = None;
    let mut end_idx: Option<usize> = None;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed == MANAGED_BEGIN {
            if begin_idx.is_some() {
                return Err(NetfixError::InvalidInput(
                    "duplicate BEGIN NETFIX MANAGED marker in hosts content".into(),
                ));
            }
            if end_idx.is_some() {
                return Err(NetfixError::InvalidInput(
                    "END NETFIX MANAGED marker appears before BEGIN in hosts content".into(),
                ));
            }
            begin_idx = Some(idx);
        } else if trimmed == MANAGED_END {
            if end_idx.is_some() {
                return Err(NetfixError::InvalidInput(
                    "duplicate END NETFIX MANAGED marker in hosts content".into(),
                ));
            }
            if begin_idx.is_none() {
                return Err(NetfixError::InvalidInput(
                    "END NETFIX MANAGED marker without matching BEGIN in hosts content".into(),
                ));
            }
            end_idx = Some(idx);
        }
    }

    match (begin_idx, end_idx) {
        (None, None) => Ok(None),
        (Some(begin), Some(end)) => Ok(Some((begin, end))),
        (Some(_), None) => Err(NetfixError::InvalidInput(
            "BEGIN NETFIX MANAGED marker without matching END in hosts content".into(),
        )),
        (None, Some(_)) => unreachable!("END without BEGIN is rejected inside the loop"),
    }
}

/// Inserts or replaces the `# BEGIN NETFIX MANAGED` / `# END NETFIX MANAGED` block
/// while preserving all surrounding user lines and rejecting malformed markers.
pub fn apply_managed_block(existing: &str, entries: &[String]) -> Result<String, NetfixError> {
    let valid_entries = validate_entries(entries)?;
    let lines = split_lines(existing);
    let block = find_managed_block(&lines)?;

    if valid_entries.is_empty() {
        return Ok(strip_lines_with_block(&lines, block));
    }

    let mut out: Vec<&str> = Vec::with_capacity(lines.len() + valid_entries.len() + 2);
    match block {
        Some((begin, end)) => {
            out.extend_from_slice(&lines[..begin]);
            out.push(MANAGED_BEGIN);
            out.extend_from_slice(&valid_entries);
            out.push(MANAGED_END);
            out.extend_from_slice(&lines[end + 1..]);
        }
        None => {
            out.extend_from_slice(&lines);
            out.push(MANAGED_BEGIN);
            out.extend_from_slice(&valid_entries);
            out.push(MANAGED_END);
        }
    }

    Ok(join_lines(&out))
}

/// Removes the `# BEGIN NETFIX MANAGED` / `# END NETFIX MANAGED` block from `existing`
/// while preserving all user lines and rejecting malformed markers.
pub fn strip_managed_block(existing: &str) -> Result<String, NetfixError> {
    let lines = split_lines(existing);
    let block = find_managed_block(&lines)?;
    Ok(strip_lines_with_block(&lines, block))
}

fn strip_lines_with_block(lines: &[&str], block: Option<(usize, usize)>) -> String {
    let Some((begin, end)) = block else {
        return join_lines(lines);
    };
    let mut out = Vec::with_capacity(lines.len().saturating_sub(end - begin + 1));
    out.extend_from_slice(&lines[..begin]);
    out.extend_from_slice(&lines[end + 1..]);
    join_lines(&out)
}

/// Updates `hosts_path` with `entries`, creating `backup_path` once on first edit
/// before writing atomically (with `EXDEV` fallback for bind-mounted files).
pub fn update_hosts_file(
    hosts_path: &Path,
    backup_path: &Path,
    entries: &[String],
) -> Result<(), NetfixError> {
    let _ = validate_entries(entries)?;

    let (existing, existed) = match std::fs::read_to_string(hosts_path) {
        Ok(content) => (content, true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (String::new(), false),
        Err(err) => return Err(err.into()),
    };

    let updated = apply_managed_block(&existing, entries)?;

    if existed && !backup_path.exists() {
        ensure_parent_dir(backup_path)?;
        write_atomic_with_mode(backup_path, existing.as_bytes(), 0o644)?;
    }

    ensure_parent_dir(hosts_path)?;
    write_atomic_with_mode(hosts_path, updated.as_bytes(), 0o644)?;
    Ok(())
}

/// Restores `hosts_path` from `backup_path` if a backup exists (removing the backup),
/// or strips the managed block safely if no backup exists.
pub fn reset_hosts_file(hosts_path: &Path, backup_path: &Path) -> Result<(), NetfixError> {
    if backup_path.exists() {
        let original = std::fs::read(backup_path)?;
        ensure_parent_dir(hosts_path)?;
        write_atomic_with_mode(hosts_path, &original, 0o644)?;
        std::fs::remove_file(backup_path)?;
        return Ok(());
    }

    let existing = match std::fs::read_to_string(hosts_path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    let stripped = strip_managed_block(&existing)?;
    if stripped != existing {
        write_atomic_with_mode(hosts_path, stripped.as_bytes(), 0o644)?;
    }
    Ok(())
}

/// Updates `/etc/hosts` with NetFix managed entries using `/var/lib/netfix/hosts.bak`.
pub fn apply_system_hosts(entries: &[String]) -> Result<(), NetfixError> {
    crate::require_root("update /etc/hosts")?;
    update_hosts_file(
        Path::new(SYSTEM_HOSTS_PATH),
        Path::new(SYSTEM_HOSTS_BACKUP_PATH),
        entries,
    )
}

/// Restores `/etc/hosts` from `/var/lib/netfix/hosts.bak` or strips the NetFix managed block.
pub fn reset_system_hosts() -> Result<(), NetfixError> {
    crate::require_root("reset /etc/hosts")?;
    reset_hosts_file(
        Path::new(SYSTEM_HOSTS_PATH),
        Path::new(SYSTEM_HOSTS_BACKUP_PATH),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExitCode;

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
        let cases = [
            "127.0.0.1 localhost\n# BEGIN NETFIX MANAGED\n1.2.3.4 foo\n",
            "127.0.0.1 localhost\n# END NETFIX MANAGED\n",
            "127.0.0.1 localhost\n# END NETFIX MANAGED\n# BEGIN NETFIX MANAGED\n",
            "# BEGIN NETFIX MANAGED\n1.2.3.4 a\n# BEGIN NETFIX MANAGED\n# END NETFIX MANAGED\n",
            "# BEGIN NETFIX MANAGED\n1.2.3.4 a\n# END NETFIX MANAGED\n# END NETFIX MANAGED\n",
        ];

        for broken in cases {
            let err = apply_managed_block(broken, &["5.6.7.8 bar".into()]).unwrap_err();
            assert_eq!(err.exit_code(), ExitCode::InvalidInput, "case: {broken}");
            let strip_err = strip_managed_block(broken).unwrap_err();
            assert_eq!(
                strip_err.exit_code(),
                ExitCode::InvalidInput,
                "strip case: {broken}"
            );
        }
    }

    #[test]
    fn test_hosts_rejects_invalid_entries() {
        let orig = "127.0.0.1 localhost\n";
        for bad in [
            "",
            "   \t  ",
            "1.2.3.4 a\n5.6.7.8 b",
            "1.2.3.4 a\r",
            "1.2.3.4 a\0",
            MANAGED_BEGIN,
            MANAGED_END,
        ] {
            let err = apply_managed_block(orig, &[bad.into()]).unwrap_err();
            assert_eq!(err.exit_code(), ExitCode::InvalidInput, "bad entry: {bad:?}");
        }
    }

    #[test]
    fn test_hosts_replaces_existing_block_and_preserves_surrounding_lines() {
        let orig = "127.0.0.1 localhost\n# BEGIN NETFIX MANAGED\n1.1.1.1 old.test\n# END NETFIX MANAGED\n10.0.0.9 nas\n";
        let updated = apply_managed_block(
            orig,
            &["2.2.2.2 new.test".into(), "3.3.3.3 api.test".into()],
        )
        .unwrap();
        assert_eq!(
            updated,
            "127.0.0.1 localhost\n# BEGIN NETFIX MANAGED\n2.2.2.2 new.test\n3.3.3.3 api.test\n# END NETFIX MANAGED\n10.0.0.9 nas\n"
        );
        let stripped = strip_managed_block(&updated).unwrap();
        assert_eq!(stripped, "127.0.0.1 localhost\n10.0.0.9 nas\n");
    }

    #[test]
    fn test_hosts_empty_entries_strips_managed_block() {
        let with_block = "127.0.0.1 localhost\n# BEGIN NETFIX MANAGED\n1.2.3.4 a\n# END NETFIX MANAGED\n";
        let result = apply_managed_block(with_block, &[]).unwrap();
        assert_eq!(result, "127.0.0.1 localhost\n");
    }

    #[test]
    fn test_hosts_update_creates_backup_once_and_resets() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let backup_path = dir.path().join("state").join("hosts.bak");
        let orig = "127.0.0.1 localhost\n10.0.0.5 my-nas\n";
        std::fs::write(&hosts_path, orig).unwrap();

        update_hosts_file(&hosts_path, &backup_path, &["1.2.3.4 example.com".into()]).unwrap();
        assert_eq!(std::fs::read_to_string(&backup_path).unwrap(), orig);

        update_hosts_file(&hosts_path, &backup_path, &["5.6.7.8 other.com".into()]).unwrap();
        assert_eq!(std::fs::read_to_string(&backup_path).unwrap(), orig);
        let current = std::fs::read_to_string(&hosts_path).unwrap();
        assert!(current.contains("5.6.7.8 other.com"));
        assert!(!current.contains("1.2.3.4 example.com"));

        reset_hosts_file(&hosts_path, &backup_path).unwrap();
        assert_eq!(std::fs::read_to_string(&hosts_path).unwrap(), orig);
        assert!(!backup_path.exists());
    }

    #[test]
    fn test_hosts_update_aborts_before_creating_backup_on_broken_markers() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let backup_path = dir.path().join("hosts.bak");
        let broken = "127.0.0.1 localhost\n# BEGIN NETFIX MANAGED\n1.2.3.4 foo\n";
        std::fs::write(&hosts_path, broken).unwrap();

        let err = update_hosts_file(&hosts_path, &backup_path, &["5.6.7.8 bar".into()]).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::InvalidInput);
        assert!(!backup_path.exists());
        assert_eq!(std::fs::read_to_string(&hosts_path).unwrap(), broken);
    }

    #[test]
    fn test_hosts_reset_without_backup_strips_block() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let backup_path = dir.path().join("hosts.bak");
        let content =
            "127.0.0.1 localhost\n# BEGIN NETFIX MANAGED\n1.2.3.4 example.com\n# END NETFIX MANAGED\n";
        std::fs::write(&hosts_path, content).unwrap();

        reset_hosts_file(&hosts_path, &backup_path).unwrap();
        assert_eq!(
            std::fs::read_to_string(&hosts_path).unwrap(),
            "127.0.0.1 localhost\n"
        );
    }

    #[test]
    fn test_system_hosts_requires_root_when_unprivileged() {
        if unsafe { libc::geteuid() == 0 } {
            return;
        }
        let err = apply_system_hosts(&["1.2.3.4 example.com".into()]).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::PermissionDenied);
        let reset_err = reset_system_hosts().unwrap_err();
        assert_eq!(reset_err.exit_code(), ExitCode::PermissionDenied);
    }
}
