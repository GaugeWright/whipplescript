//! The keyed half of the canonicalizer differential (DR-0053 §7): whip's
//! canonicalizers produce the string-to-sign, the custodian folds the
//! derivation chain, and the resulting signature must equal the vendor's
//! published value — end to end, across the vendored aws-sig-v4-test-suite
//! and the GitHub/Slack webhook validation examples.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use zeroize::Zeroizing;

use whipplescript_custodian::store::SealedStore;
use whipplescript_custodian::{Custodian, DeniedEgress};
use whipplescript_custody::canon::{aws_sigv4, sha256_hex, webhook};
use whipplescript_custody::{
    CredentialKind, CredentialName, CustodyCall, CustodyOk, CustodyOp, SignatureAlg, UseAttribution,
};

fn suite_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../whipplescript-custody/tests/fixtures/aws-sig-v4-test-suite")
}

fn custodian_with(name: &str, kind: CredentialKind, material: &[u8]) -> Custodian {
    let mut store = SealedStore::create(None, "pw").expect("create");
    store
        .register(
            CredentialName::new(name).expect("name"),
            kind,
            Zeroizing::new(material.to_vec()),
            None,
            None,
        )
        .expect("register");
    Custodian::new(store, Box::new(DeniedEgress))
}

fn sign_hex(custodian: &Custodian, name: &str, derivation: Vec<String>, payload: &[u8]) -> String {
    let reply = custodian.handle(&CustodyCall::new(
        UseAttribution {
            run_id: "differential".into(),
            actor: None,
            effect_key: None,
        },
        CustodyOp::Sign {
            credential: CredentialName::new(name).expect("name"),
            alg: SignatureAlg::HmacSha256,
            derivation,
            payload_b64: B64.encode(payload),
        },
    ));
    match reply.outcome {
        Ok(CustodyOk::Signed { signature_b64, .. }) => B64
            .decode(signature_b64)
            .expect("b64")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        other => panic!("sign failed: {other:?}"),
    }
}

#[test]
fn aws_sigv4_signatures_match_the_vendor_suite() {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(suite_dir())
        .expect("suite dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    assert!(dirs.len() >= 15);

    let mut failures = Vec::new();
    for dir in &dirs {
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).expect(f);
        let context: serde_json::Value =
            serde_json::from_str(&read("context.json")).expect("context");
        let secret = context["credentials"]["secret_access_key"]
            .as_str()
            .expect("secret");
        let expected = read("header-signature.txt");
        let expected = expected.trim();

        // whip's half: parse + canonicalize (same logic as the custody
        // crate's differential test, kept minimal here).
        let raw = read("request.txt");
        let mut lines = raw.lines();
        let request_line = lines.next().expect("request line");
        let (method, rest) = request_line.split_once(' ').expect("method");
        let target = rest.strip_suffix(" HTTP/1.1").unwrap_or(rest);
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, q),
            None => (target, ""),
        };
        let mut headers = Vec::new();
        let mut body = String::new();
        let mut in_body = false;
        for line in lines {
            if in_body {
                if !body.is_empty() {
                    body.push('\n');
                }
                body.push_str(line);
            } else if line.is_empty() {
                in_body = true;
            } else {
                let (n, v) = line.split_once(':').expect("header");
                headers.push((n.to_string(), v.to_string()));
            }
        }
        let timestamp = context["timestamp"].as_str().expect("timestamp");
        let amz_date: String = timestamp
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        if !headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("x-amz-date"))
        {
            headers.push(("X-Amz-Date".to_string(), amz_date.clone()));
        }
        if context["sign_body"].as_bool() == Some(true) {
            headers.push((
                "x-amz-content-sha256".to_string(),
                sha256_hex(body.as_bytes()),
            ));
        }
        let canonicalized = aws_sigv4::canonicalize(&aws_sigv4::Input {
            method,
            path,
            query,
            headers: &headers,
            payload_hash_hex: &sha256_hex(body.as_bytes()),
            amz_date: &amz_date,
            region: context["region"].as_str().expect("region"),
            service: context["service"].as_str().expect("service"),
            normalize_path: context["normalize"].as_bool().unwrap_or(true),
            double_encode: true,
        });

        // The custodian's half: the derivation chain over the sealed secret.
        let custodian = custodian_with("aws", CredentialKind::AwsSigv4, secret.as_bytes());
        let got = sign_hex(
            &custodian,
            "aws",
            canonicalized.derivation.clone(),
            canonicalized.string_to_sign.as_bytes(),
        );
        if got != expected {
            failures.push(format!(
                "{}: expected {expected}, got {got}",
                dir.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} signature mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// GitHub's published webhook validation example: secret
/// `It's a Secret to Everybody`, payload `Hello, World!`.
#[test]
fn github_webhook_mac_matches_the_vendor_example() {
    let custodian = custodian_with(
        "gh_hook",
        CredentialKind::HmacSha256,
        b"It's a Secret to Everybody",
    );
    let payload = webhook::Profile::Github
        .signing_payload(None, "Hello, World!")
        .expect("payload");
    let got = sign_hex(&custodian, "gh_hook", vec![], payload.as_bytes());
    assert_eq!(
        got,
        "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    );
}

/// Slack's published verification example: signing secret
/// `8f742231b10e8888abcd99yyyzzz85a5`, timestamp `1531420618`, the
/// documented slash-command body.
#[test]
fn slack_webhook_mac_matches_the_vendor_example() {
    let custodian = custodian_with(
        "slack_hook",
        CredentialKind::HmacSha256,
        b"8f742231b10e8888abcd99yyyzzz85a5",
    );
    let body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow\
        &channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner\
        &command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands\
        %2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN\
        &trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    let payload = webhook::Profile::Slack
        .signing_payload(Some("1531420618"), body)
        .expect("payload");
    let got = sign_hex(&custodian, "slack_hook", vec![], payload.as_bytes());
    assert_eq!(
        got,
        "a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
    );
}

/// RFC 7515 Appendix A.2: the RFC's RSA key (converted to PKCS#8, verified
/// against the RFC's published signature at fixture-generation time) signing
/// the RFC's exact JWS signing input must reproduce the RFC's signature —
/// RSASSA-PKCS1-v1_5 is deterministic, so this pins the whole jwt-rs256 path.
#[test]
fn jwt_rs256_matches_rfc7515_a2() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use whipplescript_custody::canon::jwt;

    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let key = std::fs::read(fixtures.join("rfc7515_a2_key.pk8")).expect("key fixture");
    let expected_sig_b64u = std::fs::read_to_string(fixtures.join("rfc7515_a2_signature.b64u"))
        .expect("signature fixture");

    let header = br#"{"alg":"RS256"}"#;
    let claims: &[u8] =
        b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    let signing_input = jwt::signing_input(header, claims);

    let custodian = custodian_with("gh_app", CredentialKind::JwtRs256, &key);
    let reply = custodian.handle(&CustodyCall::new(
        UseAttribution {
            run_id: "differential".into(),
            actor: None,
            effect_key: None,
        },
        CustodyOp::Sign {
            credential: CredentialName::new("gh_app").expect("name"),
            alg: SignatureAlg::RsaSha256,
            derivation: vec![],
            payload_b64: B64.encode(signing_input.as_bytes()),
        },
    ));
    let signature = match reply.outcome {
        Ok(CustodyOk::Signed { signature_b64, .. }) => B64.decode(signature_b64).expect("b64"),
        other => panic!("sign failed: {other:?}"),
    };
    assert_eq!(URL_SAFE_NO_PAD.encode(&signature), expected_sig_b64u.trim());

    let token = jwt::assemble(&signing_input, &signature);
    assert_eq!(token.split('.').count(), 3);
}
