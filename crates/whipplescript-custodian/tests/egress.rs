//! The custodian's real egress (DR-0053 §2, §9): deny-by-default host
//! allow-list, userinfo spoof refusal, and a live loopback roundtrip proving
//! substitution happens on the way out and material never comes back.

use std::io::{Read, Write};
use std::net::TcpListener;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use zeroize::Zeroizing;

use whipplescript_custodian::egress::UreqEgress;
use whipplescript_custodian::store::SealedStore;
use whipplescript_custodian::{Custodian, Egress};
use whipplescript_custody::{
    CredentialKind, CredentialName, CustodyCall, CustodyError, CustodyOk, CustodyOp, EgressRequest,
    PresentationForm, Sentinel, UseAttribution,
};

fn name(s: &str) -> CredentialName {
    CredentialName::new(s).expect("valid name")
}

#[test]
fn egress_is_deny_by_default_and_refuses_spoofed_hosts() {
    let egress = UreqEgress::new(vec!["api.stripe.com".into(), "*.amazonaws.com".into()]);
    let req = |url: &str| EgressRequest {
        method: "GET".into(),
        url: url.into(),
        headers: vec![],
        body_b64: None,
    };

    // Not in the allow-list.
    let err = egress
        .perform(&req("https://evil.test/steal"))
        .expect_err("refused");
    assert!(err.contains("allow-list"), "{err}");

    // Userinfo spoofing: the allow-listed name appears in the URL but the
    // real host is evil.test.
    let err = egress
        .perform(&req("https://api.stripe.com@evil.test/steal"))
        .expect_err("refused");
    assert!(err.contains("userinfo"), "{err}");

    // Plain http to a public host is refused even when allow-listed.
    let err = egress
        .perform(&req("http://api.stripe.com/v1/charges"))
        .expect_err("refused");
    assert!(err.contains("https"), "{err}");

    // The wildcard matches subdomains, not lookalike suffixes.
    let err = egress
        .perform(&req("https://not-amazonaws.com/x"))
        .expect_err("refused");
    assert!(err.contains("allow-list"), "{err}");

    // Empty allow-list refuses everything (DeniedEgress semantics at the
    // network layer).
    let none = UreqEgress::new(vec![]);
    assert!(none.perform(&req("https://api.stripe.com/")).is_err());
}

/// Minimal one-shot loopback HTTP server: accepts one connection, captures
/// the request bytes, answers 200 with a JSON body.
///
/// Reads until the headers *and* the whole declared body have arrived. A single
/// `read` is not enough: TCP may deliver the head and the body in separate
/// segments, and on a loaded CI runner it does — the head alone would then be
/// captured and a body assertion would fail for a reason that has nothing to do
/// with what is under test.
fn one_shot_server(response_body: &'static str) -> (u16, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut raw: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).expect("read");
            if n == 0 {
                break; // peer closed
            }
            raw.extend_from_slice(&chunk[..n]);

            // Once the head is complete, keep reading until Content-Length
            // bytes of body are in hand. Absent the header, the head is all
            // there is to wait for.
            let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let body_start = head_end + 4;
            let head = String::from_utf8_lossy(&raw[..head_end]);
            let declared = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.trim()
                        .eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if raw.len() - body_start >= declared {
                break;
            }
        }
        let seen = String::from_utf8_lossy(&raw).into_owned();
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream.write_all(reply.as_bytes()).expect("write");
        seen
    });
    (port, handle)
}

#[test]
fn request_substitutes_and_egresses_but_material_never_returns() {
    let (port, server) = one_shot_server(r#"{"ok":true}"#);

    let mut store = SealedStore::create(None, "pw").expect("store");
    store
        .register(
            name("loop_api"),
            CredentialKind::Bearer,
            Zeroizing::new(b"tok-loopback-123".to_vec()),
            None,
        )
        .expect("register");
    let custodian = Custodian::new(store, Box::new(UreqEgress::new(vec!["127.0.0.1".into()])));

    let sentinel = Sentinel::new(name("loop_api"), PresentationForm::Bearer).render();
    let reply = custodian.handle(&CustodyCall::new(
        UseAttribution {
            run_id: "egress-test".into(),
            actor: None,
            effect_key: None,
        },
        CustodyOp::Request {
            credential: name("loop_api"),
            request: EgressRequest {
                method: "POST".into(),
                url: format!("http://127.0.0.1:{port}/v1/refunds"),
                headers: vec![("Authorization".into(), sentinel)],
                body_b64: Some(B64.encode(br#"{"charge":"ch_1"}"#)),
            },
        },
    ));

    let outcome = reply.outcome.expect("request succeeds");
    let CustodyOk::Requested { response } = outcome else {
        panic!("wrong variant");
    };
    assert_eq!(response.status, 200);
    let body = B64
        .decode(response.body_b64.expect("body"))
        .expect("base64");
    assert_eq!(body, br#"{"ok":true}"#);

    // The server saw the substituted material at the marked slot…
    let seen = server.join().expect("server");
    assert!(
        seen.contains("Authorization: Bearer tok-loopback-123"),
        "{seen}"
    );
    assert!(seen.contains(r#"{"charge":"ch_1"}"#), "{seen}");
    // …and the sentinel never left as-is.
    assert!(!seen.contains("whipplescript-credential"), "{seen}");
}

#[test]
fn a_denied_host_never_reaches_the_network_and_is_recorded() {
    let mut store = SealedStore::create(None, "pw").expect("store");
    store
        .register(
            name("boxed"),
            CredentialKind::Bearer,
            Zeroizing::new(b"tok".to_vec()),
            None,
        )
        .expect("register");
    let custodian = Custodian::new(
        store,
        Box::new(UreqEgress::new(vec!["allowed.example".into()])),
    );
    let sentinel = Sentinel::new(name("boxed"), PresentationForm::Bearer).render();
    let reply = custodian.handle(&CustodyCall::new(
        UseAttribution {
            run_id: "egress-test".into(),
            actor: None,
            effect_key: None,
        },
        CustodyOp::Request {
            credential: name("boxed"),
            request: EgressRequest {
                method: "GET".into(),
                url: "https://blocked.example/x".into(),
                headers: vec![("Authorization".into(), sentinel)],
                body_b64: None,
            },
        },
    ));
    assert!(matches!(
        reply.outcome.expect_err("refused"),
        CustodyError::EgressFailed { .. }
    ));
    assert_eq!(
        custodian.uses().last().expect("record").outcome,
        "egress-failed"
    );
}
