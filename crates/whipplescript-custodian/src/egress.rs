//! Real network egress for `request`/`mint` (DR-0053 §2, §9).
//!
//! The custodian holds both secret custody and network egress — a
//! concentration the DR flags (*Open*, mTLS) and requires to be bounded by a
//! deliberate allow-list rather than discovered later. So this egress is
//! **deny-by-default**: it refuses every host not matched by an explicitly
//! configured allow pattern. The custodian stays semantically dumb — it does
//! not interpret the request, it only decides whether the destination host is
//! one the operator opened.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use whipplescript_custody::{EgressRequest, EgressResponse};

use crate::Egress;

/// Cap on response bodies read back into the custodian (and then relayed to
/// whip). 16 MiB matches the model-broker's cap.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub struct UreqEgress {
    /// Host patterns the operator opened: exact (`api.stripe.com`) or
    /// leading-wildcard (`*.amazonaws.com`). Empty list = egress refuses
    /// everything, loudly.
    allow_hosts: Vec<String>,
    agent: ureq::Agent,
}

impl UreqEgress {
    pub fn new(allow_hosts: Vec<String>) -> Self {
        Self {
            allow_hosts,
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(60))
                .build(),
        }
    }

    fn host_allowed(&self, host: &str) -> bool {
        self.allow_hosts.iter().any(|pattern| {
            match pattern.strip_prefix("*.") {
                // `*.amazonaws.com` matches subdomains AND the apex.
                Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
                None => host == pattern,
            }
        })
    }
}

impl Egress for UreqEgress {
    fn perform(&self, request: &EgressRequest) -> Result<EgressResponse, String> {
        let url = url::Url::parse(&request.url).map_err(|e| format!("invalid url: {e}"))?;
        // A userinfo component is how `https://api.stripe.com@evil.com/`
        // spoofs an allow-list that string-matches; the parsed host is
        // authoritative and userinfo is refused outright.
        if !url.username().is_empty() || url.password().is_some() {
            return Err("egress urls must not carry userinfo".to_string());
        }
        let scheme_ok = url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1") | Some("localhost")));
        if !scheme_ok {
            return Err("egress requires https (http only to loopback)".to_string());
        }
        let host = url.host_str().unwrap_or_default();
        if !self.host_allowed(host) {
            return Err(format!(
                "egress to {host:?} is not in the custodian's allow-list"
            ));
        }

        let mut req = self.agent.request(&request.method, &request.url);
        for (name, value) in &request.headers {
            req = req.set(name, value);
        }
        let result = match &request.body_b64 {
            Some(b64) => {
                let body = B64
                    .decode(b64)
                    .map_err(|e| format!("bad body base64: {e}"))?;
                req.send_bytes(&body)
            }
            None => req.call(),
        };
        let response = match result {
            Ok(response) => response,
            // A non-2xx status is a RESPONSE, not an egress failure: whip
            // owns protocol semantics, so it decides what a 402 means.
            Err(ureq::Error::Status(_, response)) => response,
            Err(err) => return Err(format!("egress failed: {err}")),
        };

        let status = response.status();
        let headers: Vec<(String, String)> = response
            .headers_names()
            .into_iter()
            .filter_map(|name| {
                response
                    .header(&name)
                    .map(|value| (name.clone(), value.to_string()))
            })
            .collect();
        let mut body = Vec::new();
        use std::io::Read as _;
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES as u64)
            .read_to_end(&mut body)
            .map_err(|e| format!("egress body read failed: {e}"))?;
        Ok(EgressResponse {
            status,
            headers,
            body_b64: if body.is_empty() {
                None
            } else {
                Some(B64.encode(&body))
            },
        })
    }
}
