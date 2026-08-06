//! Built-in canonicalizers (DR-0053 §7).
//!
//! The split falls on secret-freedom: everything here is pure, deterministic,
//! and never touches material. whip computes the canonical form and the
//! string-to-sign; the custodian holds the key and folds the derivation
//! chain. Canonicalization bugs are a classic signature-bypass class, so the
//! scheme set is **closed** — `aws-sigv4`, `hmac-sha256` (webhook profiles),
//! `jwt-rs256` — and adding one is a whip release, not a config edit.
//! Correctness is a gate: the test suite runs these against the vendors'
//! published vectors.

use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// AWS Signature Version 4, header-auth flavor. whip's half is steps 1–2 of
/// §7: canonical request and string-to-sign. The output's `derivation` is
/// the chain the custodian folds (date, region, service, `aws4_request`);
/// `kSigning` never exists on this side.
pub mod aws_sigv4 {
    use super::{hex, sha256_hex};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Canonicalized {
        pub canonical_request: String,
        pub signed_headers: String,
        pub string_to_sign: String,
        /// The derivation chain for `CustodyOp::Sign` — `[date, region,
        /// service, "aws4_request"]`.
        pub derivation: Vec<String>,
        /// The credential scope, for assembling the Authorization header:
        /// `date/region/service/aws4_request`.
        pub scope: String,
    }

    pub struct Input<'a> {
        pub method: &'a str,
        /// The request path, before canonicalization (no query).
        pub path: &'a str,
        /// The raw query string (no leading `?`), possibly empty.
        pub query: &'a str,
        /// All headers to sign, as sent. Must include `host` and
        /// `x-amz-date`.
        pub headers: &'a [(String, String)],
        /// Hex SHA-256 of the request payload (`sha256("")` for none).
        pub payload_hash_hex: &'a str,
        /// `YYYYMMDD'T'HHMMSS'Z'`.
        pub amz_date: &'a str,
        pub region: &'a str,
        pub service: &'a str,
        /// Path normalization (dot-segment removal, slash collapse). True
        /// for every service except S3.
        pub normalize_path: bool,
        /// Double URI-encoding of path segments. True for every service
        /// except S3.
        pub double_encode: bool,
    }

    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    fn uri_encode(s: &str, keep_slash: bool) -> String {
        let mut out = String::with_capacity(s.len());
        for &b in s.as_bytes() {
            if UNRESERVED.contains(&b) || (keep_slash && b == b'/') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    fn normalize_path(path: &str) -> String {
        // RFC 3986 dot-segment removal over slash-collapsed segments.
        let mut stack: Vec<&str> = Vec::new();
        for seg in path.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    stack.pop();
                }
                s => stack.push(s),
            }
        }
        let mut out = String::from("/");
        out.push_str(&stack.join("/"));
        // A path ending in a slash (or dot-segment) keeps its trailing slash.
        if out.len() > 1 && (path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..")) {
            out.push('/');
        }
        out
    }

    fn canonical_uri(path: &str, normalize: bool, double_encode: bool) -> String {
        let path = if path.is_empty() { "/" } else { path };
        let path = if normalize {
            normalize_path(path)
        } else {
            path.to_string()
        };
        // "Encoded twice for every service except S3" counts the encoding
        // the request target already carries: an incoming `%20` becomes
        // `%2520`, an incoming literal space becomes `%20`. So the
        // canonicalizer applies exactly one encoding pass — or none for S3,
        // which signs the target as-is.
        if double_encode {
            uri_encode(&path, true)
        } else {
            path
        }
    }

    fn canonical_query(query: &str) -> String {
        if query.is_empty() {
            return String::new();
        }
        let mut pairs: Vec<(String, String)> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|pair| {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                (uri_encode(k, false), uri_encode(v, false))
            })
            .collect();
        pairs.sort();
        pairs
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    }

    fn collapse_spaces(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        let mut last_space = false;
        for c in value.trim().chars() {
            if c == ' ' {
                if !last_space {
                    out.push(' ');
                }
                last_space = true;
            } else {
                out.push(c);
                last_space = false;
            }
        }
        out
    }

    fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
        let mut named: Vec<(String, Vec<String>)> = Vec::new();
        for (name, value) in headers {
            let name = name.to_ascii_lowercase();
            let value = collapse_spaces(value);
            match named.iter_mut().find(|(n, _)| *n == name) {
                Some((_, values)) => values.push(value),
                None => named.push((name, vec![value])),
            }
        }
        named.sort_by(|a, b| a.0.cmp(&b.0));
        let block = named
            .iter()
            .map(|(n, vs)| format!("{n}:{}\n", vs.join(",")))
            .collect::<String>();
        let signed = named
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(";");
        (block, signed)
    }

    pub fn canonicalize(input: &Input<'_>) -> Canonicalized {
        let uri = canonical_uri(input.path, input.normalize_path, input.double_encode);
        let query = canonical_query(input.query);
        let (header_block, signed_headers) = canonical_headers(input.headers);
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            input.method, uri, query, header_block, signed_headers, input.payload_hash_hex
        );
        let date = &input.amz_date[..8];
        let scope = format!("{date}/{}/{}/aws4_request", input.region, input.service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
            input.amz_date,
            sha256_hex(canonical_request.as_bytes())
        );
        Canonicalized {
            canonical_request,
            signed_headers,
            string_to_sign,
            derivation: vec![
                date.to_string(),
                input.region.to_string(),
                input.service.to_string(),
                "aws4_request".to_string(),
            ],
            scope,
        }
    }

    /// The Authorization header value, given the signature the custodian
    /// returned.
    pub fn authorization_header(
        access_key_id: &str,
        canonicalized: &Canonicalized,
        signature: &[u8],
    ) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential={access_key_id}/{}, SignedHeaders={}, Signature={}",
            canonicalized.scope,
            canonicalized.signed_headers,
            hex(signature)
        )
    }
}

/// `hmac-sha256` webhook profiles: how a vendor frames the bytes under the
/// MAC and spells the signature header. The framing is public protocol
/// shape; the MAC itself is the custodian's.
pub mod webhook {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Profile {
        /// `X-Hub-Signature-256: sha256=<hex>` over the raw body.
        Github,
        /// `Stripe-Signature: t=<ts>,v1=<hex>` over `"{ts}.{body}"`.
        Stripe,
        /// `X-Slack-Signature: v0=<hex>` over `"v0:{ts}:{body}"`.
        Slack,
        /// The raw body, header spelling left to the caller.
        Raw,
    }

    impl Profile {
        pub fn parse(s: &str) -> Result<Self, String> {
            match s {
                "github" => Ok(Profile::Github),
                "stripe" => Ok(Profile::Stripe),
                "slack" => Ok(Profile::Slack),
                "raw" => Ok(Profile::Raw),
                other => Err(format!("unknown webhook profile {other:?}")),
            }
        }

        /// The bytes the MAC covers. Profiles that bind a timestamp require
        /// one; passing it for the others is an error rather than a silent
        /// ignore.
        pub fn signing_payload(
            &self,
            timestamp: Option<&str>,
            body: &str,
        ) -> Result<String, String> {
            match (self, timestamp) {
                (Profile::Github | Profile::Raw, None) => Ok(body.to_string()),
                (Profile::Github | Profile::Raw, Some(_)) => {
                    Err("this profile does not bind a timestamp".to_string())
                }
                (Profile::Stripe, Some(ts)) => Ok(format!("{ts}.{body}")),
                (Profile::Slack, Some(ts)) => Ok(format!("v0:{ts}:{body}")),
                (Profile::Stripe | Profile::Slack, None) => {
                    Err("this profile requires a timestamp".to_string())
                }
            }
        }
    }
}

/// `jwt-rs256`: the JOSE signing input (RFC 7515). whip builds the input;
/// the custodian signs it RSASSA-PKCS1-v1_5/SHA-256, which is deterministic,
/// so vendor vectors pin the whole path.
pub mod jwt {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    /// `base64url(header) . base64url(claims)`, unpadded, over the exact
    /// serialized bytes given — JSON canonicalization is deliberately NOT
    /// applied, because the signature covers the bytes, not the semantics.
    pub fn signing_input(header_json: &[u8], claims_json: &[u8]) -> String {
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header_json),
            URL_SAFE_NO_PAD.encode(claims_json)
        )
    }

    pub fn assemble(signing_input: &str, signature: &[u8]) -> String {
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}
