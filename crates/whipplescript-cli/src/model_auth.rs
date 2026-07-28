//! The shared model-credential layer (spec/std-coercion.md "Credential layer"):
//! how a model-backed effect resolves an API credential and where it came from.
//!
//! Owned by std.coercion (the operator-config package for model-backed
//! effects) and CONSUMED by both native `coerce` (`coerce_runtime`) and the
//! owned agent harness's model backends (`harness_tools`). The std.agent
//! provider packages (codex/claude session adapters) keep their own auth and
//! are deliberately NOT rehomed here.
//!
//! Precedence is env var → `whip auth` stored config → (OpenAI only) the Codex
//! OAuth token in `~/.codex/auth.json`. Credentials are operator-plane
//! secrets: they never enter facts, evidence, labels, or fingerprints —
//! surfaces report only the [`CredentialSource`] label.

use serde_json::Value;
use whipplescript_kernel::coerce_native::CoerceProvider;

/// Non-empty trimmed environment variable, or `None`.
pub(crate) fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Where a resolved model credential came from (for `whip auth status` /
/// `whip coercion status` — the label is reportable, the credential never is).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialSource {
    /// An environment variable (named).
    Env(&'static str),
    /// The `whip auth set` config file.
    Stored,
    /// The Codex OAuth token in `~/.codex/auth.json`.
    CodexOAuth,
}

impl CredentialSource {
    pub fn label(self) -> String {
        match self {
            CredentialSource::Env(name) => format!("env:{name}"),
            CredentialSource::Stored => "stored (whip auth)".to_owned(),
            CredentialSource::CodexOAuth => "~/.codex/auth.json".to_owned(),
        }
    }
}

/// The credential candidates a resolution consults, snapshot as plain values so
/// the precedence itself is a pure, golden-testable function
/// (`resolve_credential_from`). `resolve_credential_with_source` fills this
/// from the real environment/config/codex files.
pub struct CredentialCandidates {
    /// The provider's environment variable value, if set and non-empty.
    pub env: Option<String>,
    /// The `whip auth set` stored credential, if any.
    pub stored: Option<String>,
    /// The Codex OAuth access token, if present (consulted for OpenAI only).
    pub codex_oauth: Option<String>,
}

/// The env var each provider's credential resolution consults first.
pub fn credential_env_var(provider: CoerceProvider) -> &'static str {
    match provider {
        CoerceProvider::Anthropic => "ANTHROPIC_API_KEY",
        CoerceProvider::OpenAi | CoerceProvider::OpenAiCompat => "OPENAI_API_KEY",
    }
}

/// Pure precedence core: environment variable, then `whip auth` stored config,
/// then (OpenAI only) the Codex OAuth token. `None` means no credential.
pub fn resolve_credential_from(
    provider: CoerceProvider,
    candidates: CredentialCandidates,
) -> Option<(String, CredentialSource)> {
    let env_var = credential_env_var(provider);
    if let Some(key) = candidates.env {
        return Some((key, CredentialSource::Env(env_var)));
    }
    if let Some(key) = candidates.stored {
        return Some((key, CredentialSource::Stored));
    }
    match provider {
        // The Codex OAuth token is an OpenAI credential; it never satisfies
        // Anthropic (which additionally rejects OAuth tokens outright — see
        // `anthropic_oauth_rejection`).
        CoerceProvider::OpenAi | CoerceProvider::OpenAiCompat => candidates
            .codex_oauth
            .map(|key| (key, CredentialSource::CodexOAuth)),
        CoerceProvider::Anthropic => None,
    }
}

/// Resolve the model credential and report where it came from, in precedence
/// order: environment variable, then `whip auth` stored config, then (OpenAI
/// only) the Codex OAuth token. `None` means no credential is available.
pub fn resolve_credential_with_source(
    provider: CoerceProvider,
) -> Option<(String, CredentialSource)> {
    let stored_provider = match provider {
        CoerceProvider::Anthropic => "anthropic",
        CoerceProvider::OpenAi | CoerceProvider::OpenAiCompat => "openai",
    };
    resolve_credential_from(
        provider,
        CredentialCandidates {
            env: env_nonempty(credential_env_var(provider)),
            stored: crate::auth::stored_credential(stored_provider),
            codex_oauth: codex_oauth_token(),
        },
    )
}

/// The Anthropic OAuth-rejection rule (decided 2026-06-23, Jack): Anthropic
/// model calls use a console API key only — reusing a Claude Code OAuth token
/// for the API is a terms gray area. Returns the rejection message when the
/// resolved key is an OAuth token, `None` when the key is acceptable.
pub fn anthropic_oauth_rejection(api_key: &str) -> Option<String> {
    whipplescript_kernel::coerce_native::is_anthropic_oauth_token(api_key).then(|| {
        "Anthropic coerce requires a console API key (`sk-ant-api...`), not a Claude Code \
         OAuth token (`sk-ant-oat...`); set ANTHROPIC_API_KEY or run `whip auth set anthropic <key>`"
            .to_owned()
    })
}

/// The `model = "..."` from `~/.codex/config.toml` (the model the codex CLI is
/// configured to use), so the codex coerce path tracks the user's config rather
/// than a hard-coded default. Shared with the agent-turn app-server path.
pub(crate) fn codex_config_model() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::Path::new(&home)
        .join(".codex")
        .join("config.toml");
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        // Match the top-level `model = "..."` (not `model_reasoning_effort`, etc.).
        let Some(rest) = line.strip_prefix("model") else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        if !value.is_empty() {
            return Some(value.to_owned());
        }
    }
    None
}

/// The Codex account id (`chatgpt-account-id` header) from `~/.codex/auth.json`.
pub(crate) fn codex_account_id() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::Path::new(&home).join(".codex").join("auth.json");
    let json: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    json.get("tokens")
        .and_then(|tokens| tokens.get("account_id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Best-effort read of the Codex OAuth access token from `~/.codex/auth.json`.
/// Tries the common shapes; returns `None` if the file or token is absent.
pub(crate) fn codex_oauth_token() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::Path::new(&home).join(".codex").join("auth.json");
    let text = std::fs::read_to_string(path).ok()?;
    let json: Value = serde_json::from_str(&text).ok()?;
    json.get("tokens")
        .and_then(|tokens| tokens.get("access_token"))
        .and_then(Value::as_str)
        .or_else(|| json.get("access_token").and_then(Value::as_str))
        .or_else(|| json.get("OPENAI_API_KEY").and_then(Value::as_str))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(
        env: Option<&str>,
        stored: Option<&str>,
        codex: Option<&str>,
    ) -> CredentialCandidates {
        CredentialCandidates {
            env: env.map(str::to_owned),
            stored: stored.map(str::to_owned),
            codex_oauth: codex.map(str::to_owned),
        }
    }

    /// Golden precedence table (spec/std-coercion.md "Credential layer",
    /// slice 3 gate): env / stored / codex × openai / anthropic. Pure — the
    /// candidates are injected, so the table is exact and hermetic.
    #[test]
    fn credential_precedence_golden_table() {
        use CoerceProvider::{Anthropic, OpenAi};
        // (provider, (env, stored, codex) candidates, expected (key, source))
        type GoldenRow<'a> = (
            CoerceProvider,
            (Option<&'a str>, Option<&'a str>, Option<&'a str>),
            Option<(&'a str, CredentialSource)>,
        );
        let table: &[GoldenRow] = &[
            // openai: env beats stored beats codex; codex is a real rung.
            (
                OpenAi,
                (Some("e"), Some("s"), Some("c")),
                Some(("e", CredentialSource::Env("OPENAI_API_KEY"))),
            ),
            (
                OpenAi,
                (None, Some("s"), Some("c")),
                Some(("s", CredentialSource::Stored)),
            ),
            (
                OpenAi,
                (None, None, Some("c")),
                Some(("c", CredentialSource::CodexOAuth)),
            ),
            (OpenAi, (None, None, None), None),
            // anthropic: env beats stored; the codex token NEVER satisfies it.
            (
                Anthropic,
                (Some("e"), Some("s"), Some("c")),
                Some(("e", CredentialSource::Env("ANTHROPIC_API_KEY"))),
            ),
            (
                Anthropic,
                (None, Some("s"), Some("c")),
                Some(("s", CredentialSource::Stored)),
            ),
            (Anthropic, (None, None, Some("c")), None),
            (Anthropic, (None, None, None), None),
        ];
        for (provider, (env, stored, codex), expected) in table {
            let resolved = resolve_credential_from(*provider, candidates(*env, *stored, *codex));
            let expected = expected
                .as_ref()
                .map(|(key, source)| ((*key).to_owned(), *source));
            assert_eq!(
                resolved, expected,
                "provider {provider:?} env={env:?} stored={stored:?} codex={codex:?}"
            );
        }
    }

    #[test]
    fn anthropic_oauth_tokens_are_rejected_with_the_console_key_message() {
        // The rule lives HERE (the credential layer owns provider-specific
        // credential policy); coerce and the harness consume it.
        let rejection = anthropic_oauth_rejection("sk-ant-oat01-abc").expect("oauth rejected");
        assert!(rejection.contains("console API key"), "{rejection}");
        assert!(anthropic_oauth_rejection("sk-ant-api03-real").is_none());
    }

    #[test]
    fn openai_compat_uses_the_openai_credential_surface() {
        let resolved = resolve_credential_from(
            CoerceProvider::OpenAiCompat,
            candidates(None, None, Some("codex-token")),
        );
        assert_eq!(
            resolved,
            Some(("codex-token".to_owned(), CredentialSource::CodexOAuth))
        );
        assert_eq!(
            credential_env_var(CoerceProvider::OpenAiCompat),
            "OPENAI_API_KEY"
        );
    }
}
