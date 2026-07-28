//! The identity boundary (DR-0031). WhippleScript CONSUMES an identity assertion;
//! it never authenticates one. `current_principal` reads the principal the
//! environment asserts, via pluggable backends; the governance `party <id> : <Role>`
//! map then turns it into an acts-for role — the agent's authority ceiling (D3).
//!
//! Backends, by trust boundary:
//!   - `env` / launcher-passed (`WHIPPLESCRIPT_PRINCIPAL`): a trusted parent (a web
//!     gateway, scheduler, or K8s) that already authenticated the end-user passes the
//!     identity in. WhippleScript trusts its launcher, as apps trust the reverse
//!     proxy that did the SSO. Also the dev/v0 backend. Explicit override wins.
//!   - `os` (default): the OS-set login identity (`USER` on Unix, `USERNAME` on
//!     Windows). On a managed/AD-joined host this IS the enterprise identity, with
//!     file access control already gated by the same OS principal.
//!   - `token` / OIDC: validate a signed claim against the IdP — designed-for, not
//!     built here.
//!
//! WhippleScript builds no IdP, session store, credential vault, or auth protocol;
//! it accepts an assertion and maps it to a role. Everything upstream is the
//! enterprise's.

/// The principal the environment asserts is running this agent, or `None` if the
/// environment names no one (resolved to the public bottom, fail-closed).
pub fn current_principal() -> Option<String> {
    // `env` / launcher backend first: an explicit, trusted-launcher-passed identity
    // wins over the ambient OS login.
    if let Some(principal) = non_empty_var("WHIPPLESCRIPT_PRINCIPAL") {
        return Some(principal);
    }
    // `os` backend (default): the OS-set login identity.
    non_empty_var("USER").or_else(|| non_empty_var("USERNAME"))
}

fn non_empty_var(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}
