//! `whip auth`: inspect and store the LLM credentials native `coerce` uses.
//!
//! whip does not run its own login flow — the environment is already
//! authenticated (Codex via `codex login` → `~/.codex/auth.json`, Claude via the
//! Claude CLI / `ant auth login`). coerce *reads* those existing credentials
//! (see `coerce_runtime`): `whip auth status` shows what resolves and from where,
//! and `whip auth set <provider> <key>` stores an explicit API key when you'd
//! rather not rely on an env var or a reused subscription token.
//!
//! The stored config is plaintext protected by `0600` file permissions — the
//! same model as `~/.codex/auth.json`, `~/.aws/credentials`, or an npm token.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

/// Providers that can hold a stored coerce credential.
pub const KNOWN_PROVIDERS: &[&str] = &["openai", "anthropic", "xai"];

/// Location of the stored credential config:
/// `$WHIPPLESCRIPT_CONFIG_DIR/auth.json`, else
/// `$XDG_CONFIG_HOME/whipplescript/auth.json`, else
/// `~/.config/whipplescript/auth.json`.
pub fn auth_config_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("WHIPPLESCRIPT_CONFIG_DIR") {
        if !dir.trim().is_empty() {
            return Some(PathBuf::from(dir).join("auth.json"));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return Some(PathBuf::from(xdg).join("whipplescript").join("auth.json"));
        }
    }
    let home = std::env::var("HOME").ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("whipplescript")
            .join("auth.json"),
    )
}

/// Read the stored credential map (empty if the file is absent or unparseable).
pub fn read_auth_config(path: &Path) -> Map<String, Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

/// Store (or replace) one provider's credential, preserving the others.
pub fn store_credential(path: &Path, provider: &str, key: &str) -> Result<(), String> {
    let mut config = read_auth_config(path);
    config.insert(provider.to_owned(), Value::String(key.to_owned()));
    write_auth_config(path, &config)
}

fn write_auth_config(path: &Path, config: &Map<String, Value>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create config directory: {error}"))?;
    }
    let text = serde_json::to_string_pretty(&Value::Object(config.clone()))
        .map_err(|error| format!("could not serialize auth config: {error}"))?;
    std::fs::write(path, text).map_err(|error| format!("could not write auth config: {error}"))?;
    set_owner_only_permissions(path)
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("could not restrict auth config permissions: {error}"))
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// The stored credential for a provider, if any (consulted by coerce after env
/// vars).
pub fn stored_credential(provider: &str) -> Option<String> {
    let path = auth_config_path()?;
    read_auth_config(&path)
        .get(provider)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Redact a secret for display: only the last four characters survive.
pub fn redact(secret: &str) -> String {
    let visible = 4;
    if secret.len() <= visible {
        "****".to_owned()
    } else {
        format!("****{}", &secret[secret.len() - visible..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("whip-auth-test-{name}.json"))
    }

    #[test]
    fn store_then_read_roundtrips_and_merges() {
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);
        store_credential(&path, "openai", "sk-openai").expect("store openai");
        store_credential(&path, "anthropic", "sk-ant-api03").expect("store anthropic");
        let config = read_auth_config(&path);
        assert_eq!(
            config.get("openai").and_then(Value::as_str),
            Some("sk-openai")
        );
        assert_eq!(
            config.get("anthropic").and_then(Value::as_str),
            Some("sk-ant-api03")
        );
        // Replacing one preserves the other.
        store_credential(&path, "openai", "sk-openai-2").expect("replace openai");
        let config = read_auth_config(&path);
        assert_eq!(
            config.get("openai").and_then(Value::as_str),
            Some("sk-openai-2")
        );
        assert_eq!(
            config.get("anthropic").and_then(Value::as_str),
            Some("sk-ant-api03")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn stored_config_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("perms");
        let _ = std::fs::remove_file(&path);
        store_credential(&path, "openai", "sk").expect("store");
        let mode = std::fs::metadata(&path)
            .expect("present")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "auth config must be owner-only");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_missing_file_is_empty() {
        let path = temp_path("missing-does-not-exist");
        let _ = std::fs::remove_file(&path);
        assert!(read_auth_config(&path).is_empty());
    }

    #[test]
    fn redact_keeps_only_last_four() {
        assert_eq!(redact("sk-abcdef1234"), "****1234");
        assert_eq!(redact("xy"), "****");
    }
}
