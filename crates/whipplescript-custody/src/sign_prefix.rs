//! Declared literal prefixes a `sign` payload must begin with (DR-0053 §14
//! Amendment 2026-08-29).
//!
//! `CustodyOk::Signed` returns the signature TO whip, so a standalone `sign` is
//! an oracle whose payload whip chooses and whose output it may send anywhere.
//! §14 called `sign` non-narrowable because it has no natural GLOB — true of
//! the destination, and false of the payload.
//!
//! **Why a prefix and not a context.** The obvious repair is the pattern this
//! codebase already uses twice — `wrapping_key` HKDF-expands under a domain
//! label, `wrap_aad` binds credential, context and label — so the custodian
//! would sign `context ‖ 0x00 ‖ payload`. That works only when both ends are
//! ours. `wrap`/`unwrap` are custodian-to-custodian; `sign` is verified by
//! GitHub, by AWS, by a TLS peer, each checking the raw signing input its own
//! protocol defines, so a prepended context produces signatures every external
//! verifier rejects.
//!
//! A prefix OF the payload changes nothing about the bytes signed, so interop
//! is untouched — and it is enforced by byte comparison in the custodian, so it
//! binds a fully compromised whip rather than merely an escaped agent.

/// Well-known prefixes, by name. A lookup table of byte constants is not
/// parsing — the custodian still compares bytes — and it is the spelling an
/// operator can actually write.
pub fn named(name: &str) -> Option<Vec<u8>> {
    match name {
        // TLS 1.3's mandated `CertificateVerify` context: sixty-four `0x20`
        // bytes, the context string, and a `0x00` separator. A key granted only
        // the JWT header prefix cannot produce one of these, which is the
        // cross-protocol reuse this exists to stop.
        "tls13-client-auth" => {
            let mut bytes = vec![0x20u8; 64];
            bytes.extend_from_slice(b"TLS 1.3, client CertificateVerify");
            bytes.push(0x00);
            Some(bytes)
        }
        // The fixed header of an RS256 JWT, base64url-encoded, through its `.`
        // separator: `{"alg":"RS256","typ":"JWT"}`.
        "jwt-rs256-header" => Some(b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.".to_vec()),
        _ => None,
    }
}

/// Every name this table carries, for a diagnostic that can list them.
pub const NAMED: [&str; 2] = ["tls13-client-auth", "jwt-rs256-header"];

/// Parse one grant entry: a name from the table, or `hex:<digits>` for a prefix
/// the table does not carry.
pub fn parse(entry: &str) -> Result<Vec<u8>, String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Err("empty sign prefix".to_string());
    }
    if let Some(digits) = entry.strip_prefix("hex:") {
        if digits.is_empty() || digits.len() % 2 != 0 {
            return Err(format!(
                "hex sign prefix must be an even number of digits: {entry:?}"
            ));
        }
        return (0..digits.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&digits[i..i + 2], 16)
                    .map_err(|_| format!("bad hex in sign prefix: {entry:?}"))
            })
            .collect();
    }
    named(entry).ok_or_else(|| {
        format!(
            "unknown sign prefix {entry:?}: name one of {}, or write `hex:<digits>`",
            NAMED.join(", ")
        )
    })
}

/// Parse a comma-separated grant list.
pub fn parse_list(raw: &str) -> Result<Vec<Vec<u8>>, String> {
    let entries: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.is_empty() {
        return Err("sign grant needs at least one prefix".to_string());
    }
    entries.into_iter().map(parse).collect()
}

/// Whether `payload` begins with any granted prefix.
///
/// An EMPTY list admits NOTHING rather than everything. §14 requires the list
/// on a narrowable operation, so a grant reaching here with none is a policy
/// that named the operation and forgot to bound it — and reading that as
/// "anything" is exactly how a narrowing clause becomes an over-promise.
pub fn admits(prefixes: &[Vec<u8>], payload: &[u8]) -> bool {
    prefixes
        .iter()
        .any(|prefix| payload.starts_with(prefix.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole mechanism rests on: a key bounded to one
    /// protocol's prefix cannot produce another protocol's signature.
    #[test]
    fn a_jwt_bounded_key_cannot_produce_a_tls_certificate_verify() {
        let jwt = vec![named("jwt-rs256-header").expect("named")];
        let tls_input = named("tls13-client-auth").expect("named");
        assert!(
            !admits(&jwt, &tls_input),
            "a JWT-bounded key must not sign a TLS CertificateVerify"
        );
        assert!(admits(
            &jwt,
            b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ4In0"
        ));
    }

    /// An empty list admits nothing. Reading it as "anything" would turn a
    /// narrowing clause into an over-promise, which is what §14's two grant
    /// classes exist to avoid.
    #[test]
    fn an_empty_prefix_list_admits_nothing() {
        assert!(!admits(&[], b"anything at all"));
        assert!(parse_list("  ").is_err());
    }

    #[test]
    fn hex_entries_parse_and_malformed_ones_are_refused() {
        assert_eq!(parse("hex:65794a").expect("parses"), b"eyJ".to_vec());
        // `parse_list` filters empty entries before they reach `parse`, so the
        // empty-entry refusal is only reachable directly — and a refusal
        // nothing reaches is one that can stop refusing unnoticed.
        let empty = parse("   ").expect_err("an empty entry must refuse");
        assert!(empty.contains("empty sign prefix"), "{empty}");
        for bad in ["hex:", "hex:abc", "hex:zz", "not-a-name"] {
            assert!(parse(bad).is_err(), "`{bad}` must not parse");
        }
    }

    /// The TLS context is the protocol's, byte for byte — a value that drifted
    /// would bound the key to a prefix no real handshake produces, which reads
    /// as a working grant and refuses every genuine signature.
    #[test]
    fn the_tls_context_matches_the_protocol() {
        let bytes = named("tls13-client-auth").expect("named");
        assert_eq!(bytes.len(), 64 + 33 + 1);
        assert!(bytes[..64].iter().all(|byte| *byte == 0x20));
        assert_eq!(&bytes[64..97], b"TLS 1.3, client CertificateVerify");
        assert_eq!(bytes[97], 0x00);
    }
}
