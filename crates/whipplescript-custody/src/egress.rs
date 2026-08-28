//! The governance-carried egress allow-list (DR-0053 §14, as amended
//! 2026-08-27): where a credential may reach.
//!
//! §14 grounded credential scope narrowing in the *turn grant*, which attaches
//! only to `tell` and `invoke`. That left the rule-body `request` — the one
//! construct that actually reaches `CustodyOp::Request` — with no list to
//! consult, and left the turn-grant clause narrowing nothing, since an agent
//! has no custody surface. The ruling moved the CEILING into the signed
//! envelope, where it binds a credential's reach regardless of which construct
//! uses it, and left the turn grant as a narrowing *beneath* that ceiling.
//!
//! Everything here is component-wise. A URL flattened to one string and matched
//! with a wildcard is not an allow-list, it is a suggestion: `*` crosses
//! component boundaries, so `https://*.stripe.com/*` would admit
//! `https://evil.example/a.stripe.com/b`. Method, scheme, host and path are
//! matched against their own components, and `*` cannot cross between them.

use whipplescript_core::selection::glob_matches;

/// One outbound request, decomposed as an allow-list matches it.
///
/// Built from a PARSED url rather than the raw text, which is the load-bearing
/// part: `https://api.stripe.com@evil.example/v1` has host `evil.example`, and
/// a pattern matched against the raw string would read `api.stripe.com` and
/// admit it. Userinfo is dropped. The query is deliberately not part of the
/// target — a scope constrains where a request goes, not what it asks for once
/// it is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressTarget {
    method: String,
    scheme: String,
    /// `host` or `host:port`; a default port for the scheme is omitted so one
    /// spelling of the same endpoint does not become two.
    host: String,
    path: String,
}

impl EgressTarget {
    pub fn parse(method: &str, url: &str) -> Result<Self, String> {
        let parsed = url::Url::parse(url).map_err(|error| format!("unparsable url: {error}"))?;
        let scheme = parsed.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "egress scheme must be http or https, not `{scheme}`"
            ));
        }
        let Some(host) = parsed.host_str() else {
            return Err("url names no host".to_owned());
        };
        let host = host.to_ascii_lowercase();
        let host = match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        let path = parsed.path().to_owned();
        Ok(Self {
            method: method.trim().to_ascii_uppercase(),
            scheme,
            host,
            path: if path.is_empty() {
                "/".to_owned()
            } else {
                path
            },
        })
    }

    /// The operator-facing rendering, for a refusal that names what was refused.
    pub fn render(&self) -> String {
        format!(
            "{} {}://{}{}",
            self.method, self.scheme, self.host, self.path
        )
    }
}

/// One entry in a credential's allow-list: `[METHOD ]scheme://host-glob/path-glob`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeEntry {
    /// `None` = any method. Spelled by writing no method.
    method: Option<String>,
    scheme: String,
    host: String,
    path: String,
}

impl ScopeEntry {
    /// Parse one entry, refusing the shapes that read as a narrowing while
    /// admitting more than the author means.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("empty scope entry".to_owned());
        }
        // An optional leading METHOD, distinguished by being all-uppercase —
        // no scheme is, so the two cannot be confused.
        let (method, rest) = match raw.split_once(char::is_whitespace) {
            Some((head, tail))
                if !head.is_empty()
                    && head.chars().all(|c| c.is_ascii_uppercase())
                    && !tail.trim().is_empty() =>
            {
                (Some(head.to_owned()), tail.trim())
            }
            _ => (None, raw),
        };
        let Some((scheme, authority_and_path)) = rest.split_once("://") else {
            return Err(format!(
                "scope entry `{rest}` names no scheme: write `https://<host>/<path>`, so that a \
                 plaintext endpoint cannot be admitted by a pattern written for a TLS one"
            ));
        };
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "scope scheme must be http or https, not `{scheme}`"
            ));
        }
        // A leading `*` may stand for whole labels but not for part of one.
        // `*.stripe.com` is the subdomain wildcard, anchored at a label
        // boundary by the dot that follows. `*stripe.com` is the over-promise
        // §14 exists to prevent: it reads as narrowed to Stripe and admits
        // `evil-stripe.com`. A bare `*` host is not a narrowing at all.
        if authority_and_path.starts_with('*') && !authority_and_path.starts_with("*.") {
            return Err(
                "a scope host may begin with `*` only as a whole label (`*.stripe.com`): \
                 `*stripe.com` reads as narrowed to that host while admitting \
                 `evil-stripe.com`, and a bare `*` host is not a narrowing at all"
                    .to_owned(),
            );
        }
        let Some((host, path)) = authority_and_path.split_once('/') else {
            return Err(format!(
                "scope entry `{raw}` names a host but no path: write `/…` for one path, or `/*` \
                 for the whole host, so that the whole-host case is something the author says \
                 rather than something a default decides"
            ));
        };
        if host.is_empty() {
            return Err("scope entry names an empty host".to_owned());
        }
        Ok(Self {
            method,
            scheme,
            host: host.to_ascii_lowercase(),
            path: format!("/{path}"),
        })
    }

    fn admits(&self, target: &EgressTarget) -> bool {
        self.method
            .as_ref()
            .is_none_or(|method| method == &target.method)
            && self.scheme == target.scheme
            // Component-wise, so `*` cannot cross from host into path.
            && glob_matches(&self.host, &target.host)
            && glob_matches(&self.path, &target.path)
    }
}

/// Whether any entry admits the target. An EMPTY list admits nothing — the
/// caller decides what an absent list means, which is not the same question.
pub fn admits(entries: &[ScopeEntry], target: &EgressTarget) -> bool {
    entries.iter().any(|entry| entry.admits(target))
}

/// Parse a comma-separated allow-list, reporting the first bad entry.
pub fn parse_scope(raw: &str) -> Result<Vec<ScopeEntry>, String> {
    let entries: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    if entries.is_empty() {
        return Err("an egress scope lists no entries".to_owned());
    }
    entries
        .iter()
        .map(|entry| ScopeEntry::parse(entry))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(method: &str, url: &str) -> EgressTarget {
        EgressTarget::parse(method, url).expect("target parses")
    }

    #[test]
    fn a_scope_admits_what_it_names_and_nothing_else() {
        let scope = parse_scope("POST https://api.stripe.com/v1/refunds/*").expect("scope");
        assert!(admits(
            &scope,
            &target("POST", "https://api.stripe.com/v1/refunds/re_1")
        ));
        // Wrong method, wrong path, wrong host: each on its own is a refusal.
        assert!(!admits(
            &scope,
            &target("DELETE", "https://api.stripe.com/v1/refunds/re_1")
        ));
        assert!(!admits(
            &scope,
            &target("POST", "https://api.stripe.com/v1/charges")
        ));
        assert!(!admits(
            &scope,
            &target("POST", "https://evil.example/v1/refunds/re_1")
        ));
        // And http is not https.
        assert!(!admits(
            &scope,
            &target("POST", "http://api.stripe.com/v1/refunds/re_1")
        ));
    }

    #[test]
    fn a_wildcard_cannot_cross_from_host_into_path() {
        // The reason this module matches components rather than one flattened
        // string. Under a flattened match, `https://*.stripe.com/*` admits
        // `https://evil.example/a.stripe.com/b` — the `*` swallows the host,
        // the literal lands inside the path, and the pattern reads as a
        // subdomain restriction while being none.
        let scope = parse_scope("https://*.stripe.com/*").expect("scope");
        assert!(admits(
            &scope,
            &target("GET", "https://api.stripe.com/v1/charges")
        ));
        assert!(!admits(
            &scope,
            &target("GET", "https://evil.example/a.stripe.com/b")
        ));
    }

    #[test]
    fn userinfo_cannot_impersonate_a_host() {
        // `EgressTarget` parses rather than pattern-matching text, so the host
        // is the host. Matched against the raw url, this admits.
        let scope = parse_scope("https://api.stripe.com/*").expect("scope");
        let spoofed = target("GET", "https://api.stripe.com@evil.example/v1");
        assert_eq!(spoofed.render(), "GET https://evil.example/v1");
        assert!(!admits(&scope, &spoofed));
    }

    #[test]
    fn a_leading_star_may_stand_for_a_label_but_not_part_of_one() {
        let error = ScopeEntry::parse("https://*stripe.com/*").expect_err("refused");
        assert!(error.contains("whole label"), "{error}");
        // A bare `*` host is not a narrowing at all.
        assert!(ScopeEntry::parse("https://*/*").is_err());
        // The anchored subdomain wildcard is exactly how this is written.
        let scope = parse_scope("https://*.stripe.com/*").expect("anchored wildcard is fine");
        assert!(admits(&scope, &target("GET", "https://api.stripe.com/v1")));
        // And it does NOT reach the apex, because `*` matched empty still
        // leaves the anchoring dot to match.
        assert!(!admits(&scope, &target("GET", "https://stripe.com/v1")));
    }

    #[test]
    fn a_scope_entry_must_name_a_scheme_and_a_path() {
        let no_scheme = ScopeEntry::parse("api.stripe.com/*").expect_err("refused");
        assert!(no_scheme.contains("names no scheme"), "{no_scheme}");
        let no_path = ScopeEntry::parse("https://api.stripe.com").expect_err("refused");
        assert!(no_path.contains("no path"), "{no_path}");
    }

    #[test]
    fn a_default_port_does_not_become_a_second_spelling() {
        let scope = parse_scope("https://api.stripe.com/*").expect("scope");
        assert!(admits(
            &scope,
            &target("GET", "https://api.stripe.com:443/v1")
        ));
        // A non-default port is part of the host, so it must be named.
        assert!(!admits(
            &scope,
            &target("GET", "https://api.stripe.com:8443/v1")
        ));
    }

    #[test]
    fn methodless_entries_admit_any_method() {
        let scope = parse_scope("https://api.stripe.com/v1/*").expect("scope");
        for method in ["GET", "POST", "DELETE"] {
            assert!(admits(
                &scope,
                &target(method, "https://api.stripe.com/v1/x")
            ));
        }
    }

    #[test]
    fn an_empty_scope_admits_nothing() {
        assert!(!admits(&[], &target("GET", "https://api.stripe.com/v1")));
        assert!(parse_scope("   ").is_err());
    }
}
