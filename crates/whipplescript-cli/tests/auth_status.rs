//! The status command must enumerate every provider accepted by `whip auth set`.

use std::process::Command;

#[test]
fn auth_status_reports_all_known_providers_without_panicking() {
    let binary = env!("CARGO_BIN_EXE_whip");
    let config = std::env::temp_dir().join(format!(
        "whip-auth-status-{}-{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir_all(&config).expect("create isolated config");

    let output = Command::new(binary)
        .args(["--json", "auth", "status"])
        .env("HOME", &config)
        .env("XDG_CONFIG_HOME", &config)
        .env("WHIPPLESCRIPT_CONFIG_DIR", &config)
        .output()
        .expect("run auth status");
    let _ = std::fs::remove_dir_all(&config);
    assert!(
        output.status.success(),
        "auth status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("status JSON");
    assert_eq!(report["schema"], "whipplescript.auth_status.v0");
    let providers: Vec<_> = report["providers"]
        .as_array()
        .expect("provider rows")
        .iter()
        .map(|row| row["provider"].as_str().expect("provider name"))
        .collect();
    assert_eq!(providers, ["openai", "anthropic", "xai"]);
}
