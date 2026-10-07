//! `whip auth`: inspect and store the LLM credentials native `coerce` uses.
//!
//! whip does not run its own login flow — the environment is already
//! authenticated (Codex via `codex login` → `~/.codex/auth.json`, Claude via the
//! Claude CLI / `ant auth login`). coerce *reads* those existing credentials
//! (see `coerce_runtime`): `whip auth status` shows what resolves and from where,
//! and `whip auth set <provider> <key>` stores an explicit API key when you'd
//! rather not rely on an env var or a reused subscription token.
//! `openai-generic` endpoints each get their own key, stored under the
//! endpoint's base URL: `whip auth set openai-generic <base-url> <key>`.
//!
//! The stored config is plaintext protected by `0600` file permissions — the
//! same model as `~/.codex/auth.json`, `~/.aws/credentials`, or an npm token.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

/// Providers that can hold a stored coerce credential.
pub const KNOWN_PROVIDERS: &[&str] = &["openai", "anthropic", "xai"];

/// The provider whose stored credentials are keyed by endpoint rather than held
/// once. Every `openai-generic` endpoint is a different service — a local
/// Ollama, an OpenRouter account, a vLLM box — so one stored key for all of
/// them would hand each endpoint the others' secret. In `auth.json` the entry
/// is an object mapping a normalized base URL to its key.
pub const GENERIC_PROVIDER: &str = "openai-generic";

/// The spelling a base URL is stored and looked up under: trimmed, with any
/// trailing `/` removed and the scheme and host lowercased, so
/// `http://localhost:11434/v1/` and `http://LOCALHOST:11434/v1` are the same
/// endpoint. Only `http` and `https`
/// are accepted; anything else is a typo that would otherwise store a key
/// nothing ever finds.
pub fn normalize_base_url(base_url: &str) -> Result<String, String> {
    let trimmed = base_url.trim().trim_end_matches('/');
    let invalid = || {
        format!("`{base_url}` is not an http(s) base URL (expected e.g. http://localhost:11434/v1)")
    };
    let (scheme, rest) = trimmed.split_once("://").ok_or_else(invalid)?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(invalid());
    }
    // Scheme and host are case-insensitive; the path is not.
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(invalid());
    }
    Ok(format!(
        "{scheme}://{}{path}",
        authority.to_ascii_lowercase()
    ))
}

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

/// Store (or replace) the `openai-generic` credential for one endpoint,
/// preserving every other endpoint's and every other provider's.
pub fn store_endpoint_credential(path: &Path, base_url: &str, key: &str) -> Result<(), String> {
    let base_url = normalize_base_url(base_url)?;
    let mut config = read_auth_config(path);
    let mut endpoints = config
        .get(GENERIC_PROVIDER)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    endpoints.insert(base_url, Value::String(key.to_owned()));
    config.insert(GENERIC_PROVIDER.to_owned(), Value::Object(endpoints));
    write_auth_config(path, &config)
}

/// Remove one provider's stored credential. `Ok(false)` when none was stored.
pub fn clear_credential(path: &Path, provider: &str) -> Result<bool, String> {
    let mut config = read_auth_config(path);
    if config.remove(provider).is_none() {
        return Ok(false);
    }
    write_auth_config(path, &config).map(|()| true)
}

/// Remove the `openai-generic` credential for one endpoint. `Ok(false)` when
/// that endpoint had none. The provider entry goes when its last endpoint does.
pub fn clear_endpoint_credential(path: &Path, base_url: &str) -> Result<bool, String> {
    let base_url = normalize_base_url(base_url)?;
    let mut config = read_auth_config(path);
    let Some(mut endpoints) = config
        .get(GENERIC_PROVIDER)
        .and_then(Value::as_object)
        .cloned()
    else {
        return Ok(false);
    };
    if endpoints.remove(&base_url).is_none() {
        return Ok(false);
    }
    if endpoints.is_empty() {
        config.remove(GENERIC_PROVIDER);
    } else {
        config.insert(GENERIC_PROVIDER.to_owned(), Value::Object(endpoints));
    }
    write_auth_config(path, &config).map(|()| true)
}

/// The `openai-generic` credential stored for one endpoint in a config map.
pub fn endpoint_credential_in(config: &Map<String, Value>, base_url: &str) -> Option<String> {
    let base_url = normalize_base_url(base_url).ok()?;
    config
        .get(GENERIC_PROVIDER)
        .and_then(Value::as_object)
        .and_then(|endpoints| endpoints.get(&base_url))
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
}

/// The endpoints that hold a stored `openai-generic` credential, in order.
pub fn stored_endpoints(config: &Map<String, Value>) -> Vec<String> {
    config
        .get(GENERIC_PROVIDER)
        .and_then(Value::as_object)
        .map(|endpoints| endpoints.keys().cloned().collect())
        .unwrap_or_default()
}

/// The stored `openai-generic` credential for an endpoint, if any (consulted
/// after the environment variable).
pub fn stored_endpoint_credential(base_url: &str) -> Option<String> {
    let path = auth_config_path()?;
    endpoint_credential_in(&read_auth_config(&path), base_url)
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
    fn endpoint_credentials_are_keyed_by_normalized_base_url() {
        let path = temp_path("endpoints");
        let _ = std::fs::remove_file(&path);
        store_credential(&path, "openai", "sk-openai").expect("store openai");
        store_endpoint_credential(&path, "http://localhost:11434/v1/", "ollama")
            .expect("store ollama");
        store_endpoint_credential(&path, "https://openrouter.ai/api/v1", "sk-or")
            .expect("store openrouter");
        let config = read_auth_config(&path);
        // A trailing slash names the same endpoint.
        assert_eq!(
            endpoint_credential_in(&config, "http://localhost:11434/v1").as_deref(),
            Some("ollama")
        );
        assert_eq!(
            endpoint_credential_in(&config, " https://openrouter.ai/api/v1/ ").as_deref(),
            Some("sk-or")
        );
        // Another endpoint, even on the same host, holds nothing.
        assert_eq!(
            endpoint_credential_in(&config, "http://localhost:11434"),
            None
        );
        // The provider-wide entries are untouched and the generic map never
        // reads as an `openai` key.
        assert_eq!(
            config.get("openai").and_then(Value::as_str),
            Some("sk-openai")
        );
        assert_eq!(
            stored_endpoints(&config),
            ["http://localhost:11434/v1", "https://openrouter.ai/api/v1"]
        );

        assert!(clear_endpoint_credential(&path, "http://localhost:11434/v1").expect("clear"));
        assert!(!clear_endpoint_credential(&path, "http://localhost:11434/v1").expect("again"));
        let config = read_auth_config(&path);
        assert_eq!(
            endpoint_credential_in(&config, "http://localhost:11434/v1"),
            None
        );
        assert_eq!(
            endpoint_credential_in(&config, "https://openrouter.ai/api/v1").as_deref(),
            Some("sk-or")
        );
        assert!(clear_endpoint_credential(&path, "https://openrouter.ai/api/v1").expect("last"));
        assert!(!read_auth_config(&path).contains_key(GENERIC_PROVIDER));

        assert!(clear_credential(&path, "openai").expect("clear openai"));
        assert!(!clear_credential(&path, "openai").expect("clear openai again"));
        assert!(read_auth_config(&path).is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn base_url_must_be_http() {
        assert!(normalize_base_url("localhost:11434/v1").is_err());
        assert!(normalize_base_url("https://").is_err());
        assert_eq!(
            normalize_base_url("HTTPS://API.example.com/V1/").as_deref(),
            Ok("https://api.example.com/V1")
        );
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
