use std::process::Command;

pub const POLKIT_ACTION_PATH: &str = "/usr/share/polkit-1/actions/dev.flyingbober.netfixlinux.policy";

pub fn is_polkit_installed() -> bool {
    if let Ok(content) = std::fs::read_to_string(POLKIT_ACTION_PATH) {
        content.contains("dev.flyingbober.netfixlinux.ctl")
    } else {
        false
    }
}

pub fn render_polkit_policy() -> &'static str {
    include_str!("../assets/dev.flyingbober.netfixlinux.policy")
}

pub fn install_polkit_policy() -> Result<(), String> {
    if is_polkit_installed() {
        return Ok(());
    }

    let policy_content = render_polkit_policy();
    let temp_path = "/tmp/dev.flyingbober.netfixlinux.policy";
    std::fs::write(temp_path, policy_content)
        .map_err(|e| format!("Failed to write temp policy file: {e}"))?;

    let status = Command::new("pkexec")
        .args(["cp", temp_path, POLKIT_ACTION_PATH])
        .status()
        .map_err(|e| format!("pkexec copy failed: {e}"))?;

    let _ = std::fs::remove_file(temp_path);

    if status.success() {
        Ok(())
    } else {
        Err("Failed to install Polkit policy (authorization rejected)".to_string())
    }
}
