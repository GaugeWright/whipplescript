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

/// WS-297: `openai-generic` keys are stored per base URL, reported redacted
/// per endpoint, overridden by `OPENAI_API_KEY`, and cleared per endpoint.
#[test]
fn openai_generic_keys_are_set_reported_and_cleared_per_endpoint() {
    let binary = env!("CARGO_BIN_EXE_whip");
    let config = std::env::temp_dir().join(format!(
        "whip-auth-generic-{}-{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir_all(&config).expect("create isolated config");
    let whip = |args: &[&str], openai_key: Option<&str>| {
        let mut command = Command::new(binary);
        command
            .args(args)
            .env("HOME", &config)
            .env("XDG_CONFIG_HOME", &config)
            .env("WHIPPLESCRIPT_CONFIG_DIR", &config)
            .env_remove("OPENAI_API_KEY")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("XAI_API_KEY")
            .env_remove("WHIPPLESCRIPT_PROVIDER_PROFILES")
            .env("WHIPPLESCRIPT_MISUSE_LOG", "off")
            .stdin(std::process::Stdio::null());
        if let Some(key) = openai_key {
            command.env("OPENAI_API_KEY", key);
        }
        command.output().expect("run whip auth")
    };
    let endpoint_rows = |output: &std::process::Output| -> Vec<serde_json::Value> {
        assert!(
            output.status.success(),
            "auth status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("status JSON");
        report["providers"]
            .as_array()
            .expect("provider rows")
            .iter()
            .filter(|row| row["provider"] == "openai-generic")
            .cloned()
            .collect()
    };

    // A generic key needs its endpoint.
    let refused = whip(
        &["auth", "set", "openai-generic", "secret-local-1234"],
        None,
    );
    assert_eq!(refused.status.code(), Some(2));
    let refused = whip(
        &["auth", "set", "openai-generic", "localhost:11434", "k"],
        None,
    );
    assert!(!refused.status.success(), "a base URL without a scheme");

    for (url, key) in [
        ("http://localhost:11434/v1/", "secret-local-1234"),
        ("https://openrouter.ai/api/v1", "secret-router-5678"),
    ] {
        let set = whip(&["auth", "set", "openai-generic", url, key], None);
        assert!(
            set.status.success(),
            "{}",
            String::from_utf8_lossy(&set.stderr)
        );
        let stdout = String::from_utf8_lossy(&set.stdout);
        assert!(!stdout.contains(key), "set must not echo the key: {stdout}");
    }

    let output = whip(&["--json", "auth", "status"], None);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        !stdout.contains("secret-local-1234") && !stdout.contains("secret-router-5678"),
        "status must redact: {stdout}"
    );
    let rows = endpoint_rows(&output);
    assert_eq!(rows.len(), 2, "{stdout}");
    assert_eq!(rows[0]["base_url"], "http://localhost:11434/v1");
    assert_eq!(rows[0]["credential"], "****1234");
    assert_eq!(rows[0]["source"], "stored (whip auth, this endpoint)");
    assert_eq!(rows[1]["base_url"], "https://openrouter.ai/api/v1");
    assert_eq!(rows[1]["credential"], "****5678");

    // The environment variable wins over the stored key, and status says so.
    let output = whip(&["--json", "auth", "status"], Some("env-key-9999"));
    let rows = endpoint_rows(&output);
    assert_eq!(rows[0]["source"], "env:OPENAI_API_KEY");
    assert_eq!(rows[0]["credential"], "****9999");

    let cleared = whip(
        &[
            "auth",
            "clear",
            "openai-generic",
            "http://localhost:11434/v1",
        ],
        None,
    );
    assert!(cleared.status.success());
    let rows = endpoint_rows(&whip(&["--json", "auth", "status"], None));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["base_url"], "https://openrouter.ai/api/v1");

    let _ = std::fs::remove_dir_all(&config);
}
