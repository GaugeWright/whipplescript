//! The owned-harness web tools: `web_search` and `web_fetch`.
//!
//! Built per the accepted design notes (`spec/web-search-tool-design-note.md`,
//! `spec/web-fetch-tool-design-note.md`, Jack 2026-07-07): search is a
//! `SearchProvider` trait with Brave as the first first-party provider and
//! model-provider-native search as the zero-config floor; fetch is in-house,
//! structurally GET-only (the only egress is the URL string), with a central
//! `FetchGuard` — SSRF resolve-then-check with the connection pinned to the
//! checked IP, per-hop redirect re-entry, unconditional private/loopback/
//! link-local/metadata denial — and htmd HTML→markdown conversion for context
//! economy. Errors are typed so the model can tell blocked-by-policy from
//! dns/timeout/too-large/http-status. Native transport is sync ureq on the
//! capacity-bounded worker pool (the execution-model posture; no tokio).

use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use serde_json::{json, Value};

/// Typed web-tool failures, distinguishable by the model per the fetch note §2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebToolError {
    /// The guard refused the target before any connection was made.
    BlockedByPolicy(String),
    /// No search provider is configured (the honest absent tier).
    NotConfigured(String),
    Dns(String),
    Timeout,
    TooManyRedirects,
    RateLimited,
    HttpStatus(u16),
    Transport(String),
    Malformed(String),
}

impl WebToolError {
    /// The model-facing error line, prefixed with a stable kind tag.
    pub fn to_tool_message(&self) -> String {
        match self {
            Self::BlockedByPolicy(reason) => format!("blocked-by-policy: {reason}"),
            Self::NotConfigured(message) => format!("not-configured: {message}"),
            Self::Dns(host) => format!("dns: could not resolve `{host}`"),
            Self::Timeout => "timeout: the request exceeded its budget".to_owned(),
            Self::TooManyRedirects => "too-many-redirects: hop limit exceeded".to_owned(),
            Self::RateLimited => {
                "rate-limited: the search provider returned 429; retry later".to_owned()
            }
            Self::HttpStatus(status) => format!("http-status: {status}"),
            Self::Transport(message) => format!("transport: {message}"),
            Self::Malformed(message) => format!("malformed: {message}"),
        }
    }
}

/// Fetch policy knobs with the progressive-rigor defaults of the fetch note
/// §6: guard always on, open web (no domain lists) at zero config, 2 MB body
/// cap, 30 s total budget, 5 redirect hops.
#[derive(Clone, Debug)]
pub struct FetchPolicy {
    pub max_bytes: usize,
    pub timeout: Duration,
    pub max_redirects: usize,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            max_bytes: 2_000_000,
            timeout: Duration::from_secs(30),
            max_redirects: 5,
            allowed_domains: domain_list_from_env("WHIPPLESCRIPT_WEB_ALLOW"),
            blocked_domains: domain_list_from_env("WHIPPLESCRIPT_WEB_BLOCK"),
        }
    }
}

fn domain_list_from_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|domain| domain.trim().to_ascii_lowercase())
                .filter(|domain| !domain.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// A guard-approved target: the URL plus the exact address the check ran
/// against. The connection is pinned to this address so the checked IP is
/// the connected IP (no DNS-rebind window).
#[derive(Debug)]
pub struct GuardedTarget {
    pub url: url::Url,
    pub host: String,
    pub address: SocketAddr,
}

/// The central fetch policy (fetch note §3.1): scheme allowlist, port policy,
/// domain lists, and the UNCONDITIONAL private/loopback/link-local/metadata
/// denial — resolve-then-check. Every redirect hop re-enters this guard.
pub fn guard_url(raw: &str, policy: &FetchPolicy) -> Result<GuardedTarget, WebToolError> {
    let url = url::Url::parse(raw)
        .map_err(|error| WebToolError::BlockedByPolicy(format!("unparseable URL: {error}")))?;
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(WebToolError::BlockedByPolicy(format!(
                "scheme `{other}` is not fetchable (http/https only)"
            )));
        }
    }
    let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
        return Err(WebToolError::BlockedByPolicy("URL has no host".to_owned()));
    };
    let port = url.port_or_known_default().unwrap_or(443);
    if !matches!(port, 80 | 443) {
        return Err(WebToolError::BlockedByPolicy(format!(
            "port {port} is outside the fetch port policy (80/443)"
        )));
    }
    if policy
        .blocked_domains
        .iter()
        .any(|domain| domain_matches(&host, domain))
    {
        return Err(WebToolError::BlockedByPolicy(format!(
            "domain `{host}` is blocked by workspace policy"
        )));
    }
    if !policy.allowed_domains.is_empty()
        && !policy
            .allowed_domains
            .iter()
            .any(|domain| domain_matches(&host, domain))
    {
        return Err(WebToolError::BlockedByPolicy(format!(
            "domain `{host}` is outside the workspace allow-list"
        )));
    }
    // Resolve-then-check: every resolved address must be public. The
    // connection is later pinned to the first checked address, so the check
    // and the connection see the same IP.
    let addresses: Vec<SocketAddr> = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
        Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
        _ => (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| WebToolError::Dns(host.clone()))?
            .collect(),
    };
    if addresses.is_empty() {
        return Err(WebToolError::Dns(host.clone()));
    }
    for address in &addresses {
        if let Some(reason) = non_public_reason(address.ip()) {
            return Err(WebToolError::BlockedByPolicy(format!(
                "`{host}` resolves to {} ({reason}) — private-range and metadata addresses are never fetchable",
                address.ip()
            )));
        }
    }
    Ok(GuardedTarget {
        url,
        host,
        address: addresses[0],
    })
}

/// Why an IP is not publicly routable, if it is not. The metadata service
/// (169.254.169.254) falls under link-local; it is named here for clarity.
fn non_public_reason(ip: IpAddr) -> Option<&'static str> {
    // Kept in parity with the `http source` classifier (`private_or_local_ipv4`
    // / `private_or_local_ipv6` in main.rs): both must reject the same set.
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            if v4.is_loopback() {
                Some("loopback")
            } else if a == 0 {
                Some("non-routable (0.0.0.0/8)")
            } else if v4.is_private() {
                Some("private range")
            } else if a == 100 && (64..=127).contains(&b) {
                Some("CGNAT (100.64/10)")
            } else if v4.is_link_local() {
                Some("link-local/metadata")
            } else if a == 198 && (b == 18 || b == 19) {
                Some("benchmarking (198.18/15)")
            } else if v4.is_unspecified() || v4.is_broadcast() || v4.is_documentation() {
                Some("non-routable")
            } else if a >= 224 {
                Some("multicast/reserved")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            if v6.is_loopback() {
                Some("loopback")
            } else if v6.is_unspecified() {
                Some("non-routable")
            } else if let Some(mapped) = v6.to_ipv4_mapped() {
                non_public_reason(IpAddr::V4(mapped))
            } else if octets[..12] == [0u8; 12] {
                // IPv4-compatible ::a.b.c.d (deprecated but dialed over IPv4).
                non_public_reason(IpAddr::V4(std::net::Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                )))
            } else if octets[..12] == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
                // NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 destination.
                non_public_reason(IpAddr::V4(std::net::Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                )))
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                Some("unique-local")
            } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else {
                None
            }
        }
    }
}

/// The `web_fetch` result, response-shaped per the fetch note §2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchOutcome {
    pub url: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub content: String,
    pub truncated: bool,
}

impl FetchOutcome {
    pub fn to_tool_json(&self) -> String {
        json!({
            "url": self.url,
            "status": self.status,
            "content_type": self.content_type,
            "content": self.content,
            "truncated": self.truncated,
        })
        .to_string()
    }
}

/// GET one URL through the guard: manual redirect loop (each hop re-guarded,
/// connection pinned to the checked address), body streamed up to the byte
/// cap, HTML converted to markdown, binary reduced to a metadata line.
pub fn web_fetch(raw_url: &str, policy: &FetchPolicy) -> Result<FetchOutcome, WebToolError> {
    let mut current = raw_url.to_owned();
    for _hop in 0..=policy.max_redirects {
        let target = guard_url(&current, policy)?;
        let pinned_host = target.host.clone();
        let pinned = target.address;
        let agent = ureq::AgentBuilder::new()
            .timeout(policy.timeout)
            .redirects(0)
            .user_agent("whipplescript-web-fetch")
            .resolver(move |host: &str| {
                if host.eq_ignore_ascii_case(&pinned_host) {
                    Ok(vec![pinned])
                } else {
                    Err(std::io::Error::other(
                        "connection is pinned to the guarded host",
                    ))
                }
            })
            .build();
        let response = match agent.get(target.url.as_str()).call() {
            Ok(response) => response,
            Err(ureq::Error::Status(status, response)) => {
                if (300..400).contains(&status) {
                    if let Some(location) = response.header("location") {
                        current = target
                            .url
                            .join(location)
                            .map_err(|error| {
                                WebToolError::Malformed(format!("bad redirect target: {error}"))
                            })?
                            .to_string();
                        continue;
                    }
                }
                return Err(WebToolError::HttpStatus(status));
            }
            Err(ureq::Error::Transport(transport)) => {
                let message = transport.to_string();
                return Err(
                    if message.to_ascii_lowercase().contains("timed out")
                        || message.to_ascii_lowercase().contains("timeout")
                    {
                        WebToolError::Timeout
                    } else {
                        WebToolError::Transport(message)
                    },
                );
            }
        };
        let status = response.status();
        if (300..400).contains(&status) {
            if let Some(location) = response.header("location") {
                current = target
                    .url
                    .join(location)
                    .map_err(|error| {
                        WebToolError::Malformed(format!("bad redirect target: {error}"))
                    })?
                    .to_string();
                continue;
            }
        }
        let content_type = response
            .header("content-type")
            .map(|value| value.to_owned());
        let mut body = Vec::with_capacity(8192);
        let truncated = {
            let mut reader = response.into_reader().take(policy.max_bytes as u64 + 1);
            reader
                .read_to_end(&mut body)
                .map_err(|error| WebToolError::Transport(error.to_string()))?;
            if body.len() > policy.max_bytes {
                body.truncate(policy.max_bytes);
                true
            } else {
                false
            }
        };
        let media = content_type
            .as_deref()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let content = if media == "text/html" || media == "application/xhtml+xml" {
            let text = String::from_utf8_lossy(&body);
            htmd::convert(&text).unwrap_or_else(|_| text.into_owned())
        } else if media.starts_with("text/")
            || media == "application/json"
            || media == "application/xml"
            || media.ends_with("+json")
            || media.ends_with("+xml")
            || media.is_empty()
        {
            String::from_utf8_lossy(&body).into_owned()
        } else {
            // Binary: a metadata line, never bytes (fetch note §2).
            format!(
                "[binary content: {} bytes of {}]",
                body.len(),
                if media.is_empty() { "unknown" } else { &media }
            )
        };
        return Ok(FetchOutcome {
            url: target.url.to_string(),
            status,
            content_type,
            content,
            truncated,
        });
    }
    Err(WebToolError::TooManyRedirects)
}

/// One search request in the provider-neutral shape (search note §3).
#[derive(Clone, Debug, Default)]
pub struct SearchQuery {
    pub query: String,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub freshness: Option<String>,
    pub count: usize,
}

/// One ranked result in the familiar schema (search note §2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
    pub published: Option<String>,
}

pub fn results_to_tool_json(results: &[SearchResult], provider_tag: &str) -> String {
    json!({
        "provider": provider_tag,
        "results": results
            .iter()
            .map(|result| json!({
                "title": result.title,
                "url": result.url,
                "snippet": result.snippet,
                "published": result.published,
            }))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

/// The durable artifact of the search note §2: one operation, query in,
/// ranked results out. Providers are ~a hundred lines behind it; blessing a
/// provider is configuration, not architecture.
pub trait SearchProvider {
    /// A short tag naming the provider in evidence (`brave`,
    /// `provider-mediated:anthropic`).
    fn tag(&self) -> &'static str;
    fn search(&self, query: &SearchQuery) -> Result<Vec<SearchResult>, WebToolError>;
}

/// Cap a snippet at a byte budget on a char boundary.
fn cap_snippet(mut text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut boundary = max;
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text.truncate(boundary);
    text.push('…');
    text
}

const MAX_SNIPPET_BYTES: usize = 1024;

/// Brave Search (search note §4): the first first-party provider —
/// independent index, simplest API behind the trait.
pub struct BraveSearchProvider {
    api_key: String,
    timeout: Duration,
}

impl BraveSearchProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            timeout: Duration::from_secs(20),
        }
    }
}

/// Map a Brave `web/search` response body onto the neutral schema:
/// `description` (+ `extra_snippets` under the size cap) → snippet,
/// `page_age` → published. Pure, so the mapping is testable offline.
pub fn parse_brave_response(body: &Value) -> Vec<SearchResult> {
    body.pointer("/web/results")
        .and_then(Value::as_array)
        .map(|results| {
            results
                .iter()
                .filter_map(|result| {
                    let url = result.get("url").and_then(Value::as_str)?;
                    let title = result
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let mut snippet = result
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    if let Some(extra) = result.get("extra_snippets").and_then(Value::as_array) {
                        for piece in extra.iter().filter_map(Value::as_str) {
                            if snippet.len() >= MAX_SNIPPET_BYTES {
                                break;
                            }
                            if !snippet.is_empty() {
                                snippet.push('\n');
                            }
                            snippet.push_str(piece);
                        }
                    }
                    Some(SearchResult {
                        title: title.to_owned(),
                        url: url.to_owned(),
                        snippet: cap_snippet(snippet, MAX_SNIPPET_BYTES),
                        published: result
                            .get("page_age")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

impl SearchProvider for BraveSearchProvider {
    fn tag(&self) -> &'static str {
        "brave"
    }

    fn search(&self, query: &SearchQuery) -> Result<Vec<SearchResult>, WebToolError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .user_agent("whipplescript-web-search")
            .build();
        let mut request = agent
            .get("https://api.search.brave.com/res/v1/web/search")
            .set("Accept", "application/json")
            .set("X-Subscription-Token", &self.api_key)
            .query("q", &query.query)
            .query("count", &query.count.clamp(1, 20).to_string());
        if let Some(freshness) = &query.freshness {
            request = request.query("freshness", freshness);
        }
        let response = match request.call() {
            Ok(response) => response,
            Err(ureq::Error::Status(429, _)) => return Err(WebToolError::RateLimited),
            Err(ureq::Error::Status(status, _)) => return Err(WebToolError::HttpStatus(status)),
            Err(ureq::Error::Transport(transport)) => {
                return Err(WebToolError::Transport(transport.to_string()));
            }
        };
        let body: Value = response
            .into_json()
            .map_err(|error| WebToolError::Malformed(error.to_string()))?;
        let mut results = parse_brave_response(&body);
        apply_domain_filters(&mut results, query);
        Ok(results)
    }
}

/// The zero-config floor (search note §5): Anthropic's server-side
/// `web_search` tool driven by a minimal request through a credential the
/// workspace already holds. Degraded (pricier, provider-mediated) and
/// honestly tagged; the decisive IFC property is no-new-readers.
pub struct AnthropicNativeSearchProvider {
    api_key: String,
    model: String,
    timeout: Duration,
}

impl AnthropicNativeSearchProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            model: std::env::var("WHIPPLESCRIPT_WEB_SEARCH_FLOOR_MODEL")
                .ok()
                .filter(|model| !model.is_empty())
                .unwrap_or_else(|| "claude-haiku-4-5-20251001".to_owned()),
            timeout: Duration::from_secs(60),
        }
    }
}

/// Extract results from the Messages API content blocks: each
/// `web_search_tool_result` block carries `content[]` items with
/// url/title/(page_age). Pure for offline testing.
pub fn parse_anthropic_search_response(body: &Value) -> Vec<SearchResult> {
    let mut results = Vec::new();
    let Some(blocks) = body.get("content").and_then(Value::as_array) else {
        return results;
    };
    for block in blocks {
        if block.get("type").and_then(Value::as_str) != Some("web_search_tool_result") {
            continue;
        }
        let Some(items) = block.get("content").and_then(Value::as_array) else {
            continue;
        };
        for item in items {
            let Some(url) = item.get("url").and_then(Value::as_str) else {
                continue;
            };
            results.push(SearchResult {
                title: item
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                url: url.to_owned(),
                snippet: cap_snippet(
                    item.get("encrypted_content")
                        .and_then(Value::as_str)
                        .map(|_| String::new())
                        .or_else(|| {
                            item.get("snippet")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .unwrap_or_default(),
                    MAX_SNIPPET_BYTES,
                ),
                published: item
                    .get("page_age")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            });
        }
    }
    results
}

impl SearchProvider for AnthropicNativeSearchProvider {
    fn tag(&self) -> &'static str {
        "provider-mediated:anthropic"
    }

    fn search(&self, query: &SearchQuery) -> Result<Vec<SearchResult>, WebToolError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .user_agent("whipplescript-web-search")
            .build();
        let mut tool = json!({
            "type": "web_search_20250305",
            "name": "web_search",
            "max_uses": 1,
        });
        if !query.allowed_domains.is_empty() {
            tool["allowed_domains"] = json!(query.allowed_domains);
        }
        if !query.blocked_domains.is_empty() {
            tool["blocked_domains"] = json!(query.blocked_domains);
        }
        let response = match agent
            .post("https://api.anthropic.com/v1/messages")
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", "2023-06-01")
            .send_json(json!({
                "model": self.model,
                "max_tokens": 1024,
                "tools": [tool],
                "messages": [{
                    "role": "user",
                    "content": format!("Search the web for: {}", query.query),
                }],
            })) {
            Ok(response) => response,
            Err(ureq::Error::Status(429, _)) => return Err(WebToolError::RateLimited),
            Err(ureq::Error::Status(status, _)) => return Err(WebToolError::HttpStatus(status)),
            Err(ureq::Error::Transport(transport)) => {
                return Err(WebToolError::Transport(transport.to_string()));
            }
        };
        let body: Value = response
            .into_json()
            .map_err(|error| WebToolError::Malformed(error.to_string()))?;
        let mut results = parse_anthropic_search_response(&body);
        apply_domain_filters(&mut results, query);
        Ok(results)
    }
}

/// Post-filter results by the query's domain lists (providers that support
/// native filters also get them passed through; this is the uniform floor).
fn apply_domain_filters(results: &mut Vec<SearchResult>, query: &SearchQuery) {
    if query.allowed_domains.is_empty() && query.blocked_domains.is_empty() {
        return;
    }
    results.retain(|result| {
        let host = url::Url::parse(&result.url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
            .unwrap_or_default();
        if query
            .blocked_domains
            .iter()
            .any(|domain| domain_matches(&host, &domain.to_ascii_lowercase()))
        {
            return false;
        }
        if !query.allowed_domains.is_empty() {
            return query
                .allowed_domains
                .iter()
                .any(|domain| domain_matches(&host, &domain.to_ascii_lowercase()));
        }
        true
    });
}

/// The resolution chain (search note §2, progressive-rigor ordered):
/// a configured dedicated provider (Brave) if a key exists; else
/// model-provider-native search through a credential the workspace already
/// holds; else honestly absent with a configuration message.
pub fn resolve_search_provider() -> Result<Box<dyn SearchProvider>, WebToolError> {
    for env_name in ["WHIPPLESCRIPT_BRAVE_API_KEY", "BRAVE_API_KEY"] {
        if let Ok(key) = std::env::var(env_name) {
            if !key.is_empty() {
                return Ok(Box::new(BraveSearchProvider::new(key)));
            }
        }
    }
    if let Some((key, _source)) = crate::model_auth::resolve_credential_with_source(
        whipplescript_kernel::coerce_native::CoerceProvider::Anthropic,
    ) {
        return Ok(Box::new(AnthropicNativeSearchProvider::new(key)));
    }
    Err(WebToolError::NotConfigured(
        "no search provider is configured: set WHIPPLESCRIPT_BRAVE_API_KEY (Brave, first-party) \
         or provide an Anthropic credential (provider-mediated floor)"
            .to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_policy() -> FetchPolicy {
        FetchPolicy {
            max_bytes: 2_000_000,
            timeout: Duration::from_secs(5),
            max_redirects: 5,
            allowed_domains: Vec::new(),
            blocked_domains: Vec::new(),
        }
    }

    /// The guard's unconditional denials: loopback, private ranges, the
    /// metadata address, non-http schemes, and off-policy ports — all refused
    /// before any connection exists.
    #[test]
    fn fetch_guard_refuses_non_public_targets_unconditionally() {
        let policy = open_policy();
        for blocked in [
            "http://127.0.0.1/x",
            "http://localhost/x",
            "http://10.0.0.8/x",
            "http://192.168.1.1/router",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/x",
            // IPv4-mapped/compatible IPv6 must be screened as their IPv4:
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[::ffff:127.0.0.1]/x",
            "http://[::ffff:10.0.0.5]/x",
            // Ranges the stdlib v4 helpers miss:
            "http://100.64.0.1/x",
            "http://0.0.0.0/x",
            "file:///etc/passwd",
            "ftp://example.com/x",
            "http://example.com:8080/x",
        ] {
            let refused = guard_url(blocked, &policy);
            assert!(
                matches!(
                    refused,
                    Err(WebToolError::BlockedByPolicy(_)) | Err(WebToolError::Dns(_))
                ),
                "`{blocked}` must be refused, got {refused:?}",
            );
        }
    }

    /// Domain allow/block lists engage as workspace declarations accrue
    /// (progressive rigor); subdomains inherit.
    #[test]
    fn fetch_guard_applies_domain_lists() {
        let mut policy = open_policy();
        policy.blocked_domains = vec!["evil.example".to_owned()];
        assert!(matches!(
            guard_url("https://sub.evil.example/page", &policy),
            Err(WebToolError::BlockedByPolicy(_))
        ));
        policy.blocked_domains.clear();
        policy.allowed_domains = vec!["docs.rs".to_owned()];
        assert!(matches!(
            guard_url("https://example.com/", &policy),
            Err(WebToolError::BlockedByPolicy(_))
        ));
    }

    /// A fetch to a guarded-away target fails typed, without any network.
    #[test]
    fn web_fetch_returns_typed_policy_failures_offline() {
        let outcome = web_fetch("http://169.254.169.254/latest/", &open_policy());
        let Err(error) = outcome else {
            panic!("metadata fetch must be refused");
        };
        assert!(error.to_tool_message().starts_with("blocked-by-policy:"));
    }

    /// The Brave response mapping: description + extra_snippets under the
    /// cap, page_age -> published. Pure and offline.
    #[test]
    fn brave_response_maps_to_the_neutral_schema() {
        let body = serde_json::json!({
            "web": { "results": [
                {
                    "title": "WhippleScript",
                    "url": "https://example.com/whip",
                    "description": "A workflow language.",
                    "extra_snippets": ["Effects are idempotent.", "Facts are typed."],
                    "page_age": "2026-07-01T00:00:00"
                },
                { "url": "https://example.com/bare" }
            ]}
        });
        let results = parse_brave_response(&body);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].title, "WhippleScript");
        assert!(results[0].snippet.contains("workflow language"));
        assert!(results[0].snippet.contains("idempotent"));
        assert_eq!(results[0].published.as_deref(), Some("2026-07-01T00:00:00"));
        assert_eq!(results[1].title, "");
    }

    /// HTML converts to markdown through htmd; plain text passes through.
    #[test]
    fn html_converts_to_markdown() {
        let markdown =
            htmd::convert("<html><body><h1>Title</h1><p>Body <b>bold</b>.</p></body></html>")
                .expect("convert");
        assert!(markdown.contains("# Title"));
        assert!(markdown.contains("**bold**"));
    }

    /// Search results post-filter by domain lists uniformly across providers.
    #[test]
    fn search_results_respect_domain_filters() {
        let mut results = vec![
            SearchResult {
                title: "keep".into(),
                url: "https://docs.rs/ureq".into(),
                snippet: String::new(),
                published: None,
            },
            SearchResult {
                title: "drop".into(),
                url: "https://example.com/x".into(),
                snippet: String::new(),
                published: None,
            },
        ];
        let query = SearchQuery {
            query: "q".into(),
            allowed_domains: vec!["docs.rs".into()],
            ..SearchQuery::default()
        };
        apply_domain_filters(&mut results, &query);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "keep");
    }
}
