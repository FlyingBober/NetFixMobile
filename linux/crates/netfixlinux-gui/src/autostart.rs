use std::path::PathBuf;

pub fn autostart_desktop_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("autostart/dev.flyingbober.netfixlinux.desktop"))
}

pub fn is_autostart_enabled() -> bool {
    autostart_desktop_path()
        .map(|p| p.exists())
        .unwrap_or(false)
}

pub fn set_autostart(enable: bool) -> Result<(), String> {
    let Some(path) = autostart_desktop_path() else {
        return Err("Cannot resolve ~/.config directory".to_string());
    };

    if enable {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let current_exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "netfixlinux-gui".to_string());

        let desktop_entry = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=NetFixLinux\n\
             Comment=NetFixLinux Desktop Client (fork of NetFix Mobile)\n\
             Exec={} --minimized\n\
             Icon=dev.flyingbober.netfixlinux\n\
             Terminal=false\n\
             Categories=Network;Proxy;\n",
            current_exe
        );
        std::fs::write(&path, desktop_entry).map_err(|e| format!("Failed to write autostart: {e}"))?;
    } else if path.exists() {
        let _ = std::fs::remove_file(&path);
    }

    Ok(())
}
