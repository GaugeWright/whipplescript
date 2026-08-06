//! Differential tests for the built-in canonicalizers (DR-0053 §7):
//! the secret-free half, compared byte-for-byte against the vendors'
//! published expected values. A canonicalizer that disagrees with the
//! vendor's is a signature bypass, so these are a gate, not a nice-to-have.

use std::path::{Path, PathBuf};

use whipplescript_custody::canon::{aws_sigv4, jwt, sha256_hex, webhook};

fn suite_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/aws-sig-v4-test-suite")
}

struct SuiteCase {
    name: String,
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: String,
    region: String,
    service: String,
    amz_date: String,
    normalize: bool,
    expected_creq: String,
    expected_sts: String,
}

fn parse_request(raw: &str) -> (String, String, String, Vec<(String, String)>, String) {
    let mut lines = raw.lines();
    let request_line = lines.next().expect("request line");
    // The target may contain literal spaces (get-space-normalized), so split
    // off the method and the trailing HTTP version rather than tokenizing.
    let (method, rest) = request_line.split_once(' ').expect("method");
    let method = method.to_string();
    let target = rest.strip_suffix(" HTTP/1.1").unwrap_or(rest).to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
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
            let (name, value) = line.split_once(':').expect("header line");
            headers.push((name.to_string(), value.to_string()));
        }
    }
    (method, path, query, headers, body)
}

fn load_case(dir: &Path) -> SuiteCase {
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).expect(f);
    let context: serde_json::Value = serde_json::from_str(&read("context.json")).expect("context");
    let (method, path, query, mut headers, body) = parse_request(&read("request.txt"));

    // The signer adds x-amz-date from the context timestamp, exactly as a
    // `call … signed with` will: `2015-08-30T12:36:00Z` → `20150830T123600Z`.
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
    // `sign_body: true` cases expect the signer to add the payload-hash
    // header before canonicalizing.
    if context["sign_body"].as_bool() == Some(true) {
        headers.push((
            "x-amz-content-sha256".to_string(),
            sha256_hex(body.as_bytes()),
        ));
    }

    SuiteCase {
        name: dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        method,
        path,
        query,
        headers,
        body,
        region: context["region"].as_str().expect("region").to_string(),
        service: context["service"].as_str().expect("service").to_string(),
        amz_date,
        normalize: context["normalize"].as_bool().unwrap_or(true),
        expected_creq: read("header-canonical-request.txt").replace("\r\n", "\n"),
        expected_sts: read("header-string-to-sign.txt").replace("\r\n", "\n"),
    }
}

fn canonicalize(case: &SuiteCase) -> aws_sigv4::Canonicalized {
    aws_sigv4::canonicalize(&aws_sigv4::Input {
        method: &case.method,
        path: &case.path,
        query: &case.query,
        headers: &case.headers,
        payload_hash_hex: &sha256_hex(case.body.as_bytes()),
        amz_date: &case.amz_date,
        region: &case.region,
        service: &case.service,
        normalize_path: case.normalize,
        double_encode: true,
    })
}

#[test]
fn aws_sigv4_matches_the_vendor_suite() {
    let mut ran = 0usize;
    let mut failures = Vec::new();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(suite_dir())
        .expect("suite dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        let case = load_case(&dir);
        let got = canonicalize(&case);
        if got.canonical_request != case.expected_creq.trim_end_matches('\n') {
            failures.push(format!(
                "{}: canonical request mismatch\n--- expected ---\n{}\n--- got ---\n{}",
                case.name, case.expected_creq, got.canonical_request
            ));
        } else if got.string_to_sign != case.expected_sts.trim_end_matches('\n') {
            failures.push(format!(
                "{}: string-to-sign mismatch\n--- expected ---\n{}\n--- got ---\n{}",
                case.name, case.expected_sts, got.string_to_sign
            ));
        }
        ran += 1;
    }
    assert!(ran >= 15, "expected the vendored suite, ran {ran} cases");
    assert!(
        failures.is_empty(),
        "{} of {ran} cases disagree with the vendor:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// GitHub's published validation example
/// (docs.github.com/webhooks/using-webhooks/validating-webhook-deliveries):
/// the framing is the raw body; the expected MAC is checked in the
/// custodian's differential test with the same constants.
#[test]
fn webhook_profiles_frame_the_vendor_payloads() {
    assert_eq!(
        webhook::Profile::Github
            .signing_payload(None, "Hello, World!")
            .expect("github"),
        "Hello, World!"
    );
    assert_eq!(
        webhook::Profile::Stripe
            .signing_payload(Some("1531420618"), "{}")
            .expect("stripe"),
        "1531420618.{}"
    );
    assert_eq!(
        webhook::Profile::Slack
            .signing_payload(Some("1531420618"), "token=abc")
            .expect("slack"),
        "v0:1531420618:token=abc"
    );
    // Timestamp discipline is explicit, not silently ignored.
    assert!(webhook::Profile::Github
        .signing_payload(Some("1"), "x")
        .is_err());
    assert!(webhook::Profile::Stripe.signing_payload(None, "x").is_err());
}

/// RFC 7515 A.2's signing input: the exact payload bytes from the RFC
/// (with its embedded CRLF line breaks) must produce the RFC's base64url
/// signing input, unpadded.
#[test]
fn jwt_signing_input_matches_rfc7515() {
    let header = br#"{"alg":"RS256"}"#;
    let claims =
        b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    let input = jwt::signing_input(header, claims);
    assert_eq!(
        input,
        "eyJhbGciOiJSUzI1NiJ9.\
         eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
         cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
            .replace(char::is_whitespace, "")
    );
    let token = jwt::assemble(&input, &[0xde, 0xad]);
    assert!(token.starts_with(&input));
    assert_eq!(token.split('.').count(), 3);
}
