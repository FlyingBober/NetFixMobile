use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiState {
    pub disclaimer_accepted: bool,
    pub traffic_mode: String, // "direct" | "system_proxy" | "tun"
    pub selected_strategy: String,
    pub dns_mode: String,
    pub minimize_to_tray: bool,
    pub autostart: bool,
}

impl Default for GuiState {
    fn default() -> Self {
        Self {
            disclaimer_accepted: false,
            traffic_mode: "direct".to_string(),
            selected_strategy: "default".to_string(),
            dns_mode: "system".to_string(),
            minimize_to_tray: true,
            autostart: false,
        }
    }
}

pub fn state_file_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("netfixlinux/gui_state.json"))
}

pub fn load_state() -> GuiState {
    let Some(path) = state_file_path() else {
        return GuiState::default();
    };
    if let Ok(data) = std::fs::read_to_string(path) {
        if let Ok(mut state) = serde_json::from_str::<GuiState>(&data) {
            state.autostart = crate::autostart::is_autostart_enabled();
            return state;
        }
    }
    let mut state = GuiState::default();
    state.autostart = crate::autostart::is_autostart_enabled();
    state
}

pub fn save_state(state: &GuiState) -> Result<(), String> {
    let Some(path) = state_file_path() else {
        return Err("Cannot resolve config directory".to_string());
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let data = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    std::fs::write(path, data).map_err(|e| e.to_string())?;
    Ok(())
}
