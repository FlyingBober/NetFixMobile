fn main() {
    println!("cargo:rerun-if-env-changed=NETFIX_APP_VERSION");
    tauri_build::build()
}
