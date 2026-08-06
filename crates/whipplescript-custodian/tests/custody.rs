//! End-to-end custodian tests (DR-0053 tracker slice 1): the daemon is
//! testable with no compiler work, every crypto operation is pinned to a
//! published vector where one exists, and the refusal paths are exercised as
//! deliberately as the happy paths.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use zeroize::Zeroizing;

use whipplescript_custodian::store::SealedStore;
use whipplescript_custodian::{Custodian, DeniedEgress, Egress};
use whipplescript_custody::{
    CredentialKind, CredentialName, CustodyCall, CustodyError, CustodyOk, CustodyOp, CustodyReply,
    CustodyTransport, EgressRequest, EgressResponse, MintExtraction, Operation, PresentationForm,
    Rung, Sentinel, SignatureAlg, UseAttribution, CUSTODY_PROTOCOL,
};

fn name(s: &str) -> CredentialName {
    CredentialName::new(s).expect("valid name")
}

fn attribution() -> UseAttribution {
    UseAttribution {
        run_id: "run-test".into(),
        actor: Some("tester".into()),
        effect_key: None,
    }
}

fn call(op: CustodyOp) -> CustodyCall {
    CustodyCall::new(attribution(), op)
}

fn custodian_with(entries: &[(&str, CredentialKind, &[u8])]) -> Custodian {
    custodian_with_egress(entries, Box::new(DeniedEgress))
}

fn custodian_with_egress(
    entries: &[(&str, CredentialKind, &[u8])],
    egress: Box<dyn Egress>,
) -> Custodian {
    let mut store = SealedStore::create(None, "test-passphrase").expect("create");
    for (n, kind, material) in entries {
        store
            .register(name(n), *kind, Zeroizing::new(material.to_vec()), None)
            .expect("register");
    }
    Custodian::new(store, egress)
}

fn expect_ok(reply: &CustodyReply) -> &CustodyOk {
    match &reply.outcome {
        Ok(ok) => ok,
        Err(e) => panic!("expected success, got {e}"),
    }
}

fn expect_err(reply: &CustodyReply) -> &CustodyError {
    match &reply.outcome {
        Ok(ok) => panic!("expected refusal, got {ok:?}"),
        Err(e) => e,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Signing: pinned to published vectors
// ---------------------------------------------------------------------------

/// RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
#[test]
fn hmac_sha256_matches_rfc4231() {
    let c = custodian_with(&[("jefe", CredentialKind::HmacSha256, b"Jefe")]);
    let reply = c.handle(&call(CustodyOp::Sign {
        credential: name("jefe"),
        alg: SignatureAlg::HmacSha256,
        derivation: vec![],
        payload_b64: B64.encode(b"what do ya want for nothing?"),
    }));
    let CustodyOk::Signed { signature_b64 } = expect_ok(&reply) else {
        panic!("wrong variant")
    };
    assert_eq!(
        hex(&B64.decode(signature_b64).expect("b64")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// RFC 8032 §7.1 test 1: empty message, known seed, known signature.
#[test]
fn ed25519_matches_rfc8032() {
    let seed = hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let c = custodian_with(&[("release", CredentialKind::Ed25519, &seed)]);
    let reply = c.handle(&call(CustodyOp::Sign {
        credential: name("release"),
        alg: SignatureAlg::Ed25519,
        derivation: vec![],
        payload_b64: B64.encode(b""),
    }));
    let CustodyOk::Signed { signature_b64 } = expect_ok(&reply) else {
        panic!("wrong variant")
    };
    assert_eq!(
        hex(&B64.decode(signature_b64).expect("b64")),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
}

/// The AWS SigV4 derivation chain (§7): initial key `"AWS4" || secret`, then
/// HMAC-folded through date / region / service / `aws4_request`, then the
/// string-to-sign. The expected value is cross-checked against an
/// independent Python `hmac` implementation of the same published algorithm
/// (two implementations, one answer); the vendor `aws-sig-v4-test-suite`
/// differential lands with the canonicalizers, which own steps 1–2. What
/// this test pins is the custodian's half: chain order, the AWS4 key
/// prefix, and that kSigning never exists on the whip side.
#[test]
fn aws_sigv4_derivation_chain_matches_aws_example() {
    let c = custodian_with(&[(
        "aws",
        CredentialKind::AwsSigv4,
        b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".as_slice(),
    )]);
    let string_to_sign = "AWS4-HMAC-SHA256\n\
        20150830T123600Z\n\
        20150830/us-east-1/iam/aws4_request\n\
        f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
    let reply = c.handle(&call(CustodyOp::Sign {
        credential: name("aws"),
        alg: SignatureAlg::HmacSha256,
        derivation: vec![
            "20150830".into(),
            "us-east-1".into(),
            "iam".into(),
            "aws4_request".into(),
        ],
        payload_b64: B64.encode(string_to_sign.as_bytes()),
    }));
    let CustodyOk::Signed { signature_b64 } = expect_ok(&reply) else {
        panic!("wrong variant")
    };
    assert_eq!(
        hex(&B64.decode(signature_b64).expect("b64")),
        "33f5dad2191de0cb4b7ab912f876876c2c4f72e2991a458f9499233c7b992438"
    );
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// Verify: constant-time, custodian-side
// ---------------------------------------------------------------------------

#[test]
fn verify_accepts_valid_and_rejects_forged() {
    let c = custodian_with(&[("hook", CredentialKind::HmacSha256, b"webhook-secret")]);
    let payload = b"payload bytes";
    let signed = c.handle(&call(CustodyOp::Sign {
        credential: name("hook"),
        alg: SignatureAlg::HmacSha256,
        derivation: vec![],
        payload_b64: B64.encode(payload),
    }));
    let CustodyOk::Signed { signature_b64 } = expect_ok(&signed) else {
        panic!("wrong variant")
    };

    let valid = c.handle(&call(CustodyOp::Verify {
        credential: name("hook"),
        alg: SignatureAlg::HmacSha256,
        payload_b64: B64.encode(payload),
        signature_b64: signature_b64.clone(),
    }));
    assert!(matches!(
        expect_ok(&valid),
        CustodyOk::Verified { valid: true }
    ));

    let forged = c.handle(&call(CustodyOp::Verify {
        credential: name("hook"),
        alg: SignatureAlg::HmacSha256,
        payload_b64: B64.encode(b"different payload"),
        signature_b64: signature_b64.clone(),
    }));
    assert!(matches!(
        expect_ok(&forged),
        CustodyOk::Verified { valid: false }
    ));
}

// ---------------------------------------------------------------------------
// Wrap/unwrap: label carriage and context binding (§13)
// ---------------------------------------------------------------------------

#[test]
fn wrap_carries_the_label_and_binds_the_context() {
    let c = custodian_with(&[
        ("box", CredentialKind::Raw, b"wrapping-material".as_slice()),
        ("other", CredentialKind::Raw, b"other-material".as_slice()),
    ]);
    let label = serde_json::json!({"confidentiality": "governed", "source": "ledger"});
    let wrapped = c.handle(&call(CustodyOp::Wrap {
        credential: name("box"),
        plaintext_b64: B64.encode(b"application data"),
        label: label.clone(),
        context: "run-7/step-3".into(),
    }));
    let CustodyOk::Wrapped { envelope } = expect_ok(&wrapped) else {
        panic!("wrong variant")
    };
    assert_eq!(envelope.label, label);
    assert_eq!(envelope.credential, name("box"));

    // Roundtrip restores the plaintext AND the label — the boundary does not
    // launder (`credential-wrap-carriage.maude`, `-UNLABELLED`).
    let unwrapped = c.handle(&call(CustodyOp::Unwrap {
        credential: name("box"),
        envelope: envelope.clone(),
        context: "run-7/step-3".into(),
    }));
    let CustodyOk::Unwrapped {
        plaintext_b64,
        label: restored,
    } = expect_ok(&unwrapped)
    else {
        panic!("wrong variant")
    };
    assert_eq!(B64.decode(plaintext_b64).expect("b64"), b"application data");
    assert_eq!(*restored, label);

    // A different context does not open it, even with every label intact
    // (`-UNBOUND`: this is AEAD binding, not label comparison).
    let cross_context = c.handle(&call(CustodyOp::Unwrap {
        credential: name("box"),
        envelope: envelope.clone(),
        context: "run-9/step-1".into(),
    }));
    assert!(matches!(
        expect_err(&cross_context),
        CustodyError::EnvelopeRefused
    ));

    // A different credential does not open it.
    let cross_credential = c.handle(&call(CustodyOp::Unwrap {
        credential: name("other"),
        envelope: envelope.clone(),
        context: "run-7/step-3".into(),
    }));
    assert!(matches!(
        expect_err(&cross_credential),
        CustodyError::EnvelopeRefused
    ));

    // A tampered label breaks the AEAD binding: the recorded label is part
    // of the associated data, so editing it after the fact refuses.
    let mut tampered = envelope.clone();
    tampered.label = serde_json::json!({"confidentiality": "public"});
    let relabelled = c.handle(&call(CustodyOp::Unwrap {
        credential: name("box"),
        envelope: tampered,
        context: "run-7/step-3".into(),
    }));
    assert!(matches!(
        expect_err(&relabelled),
        CustodyError::EnvelopeRefused
    ));
}

// ---------------------------------------------------------------------------
// Request substitution
// ---------------------------------------------------------------------------

/// Egress double: records what actually left, returns a canned response.
struct CapturingEgress {
    seen: std::sync::Mutex<Vec<EgressRequest>>,
    response: EgressResponse,
}

impl CapturingEgress {
    fn new(response: EgressResponse) -> Arc<Self> {
        Arc::new(Self {
            seen: std::sync::Mutex::new(Vec::new()),
            response,
        })
    }
}

impl Egress for CapturingEgress {
    fn perform(&self, request: &EgressRequest) -> Result<EgressResponse, String> {
        self.seen.lock().expect("lock").push(request.clone());
        Ok(self.response.clone())
    }
}

#[test]
fn request_substitutes_at_the_marked_slot_only() {
    let egress = CapturingEgress::new(EgressResponse {
        status: 200,
        headers: vec![],
        body_b64: Some(B64.encode(b"{\"ok\":true}")),
    });
    let c = custodian_with_egress(
        &[("stripe_api", CredentialKind::Bearer, b"sk_live_abc")],
        Box::new(Arc::clone(&egress)),
    );

    let sentinel = Sentinel::new(name("stripe_api"), PresentationForm::Bearer).render();
    let reply = c.handle(&call(CustodyOp::Request {
        credential: name("stripe_api"),
        request: EgressRequest {
            method: "POST".into(),
            url: "https://api.stripe.com/v1/refunds".into(),
            headers: vec![
                ("Authorization".into(), sentinel),
                ("Content-Type".into(), "application/json".into()),
            ],
            body_b64: Some(B64.encode(b"{\"charge\":\"ch_1\"}")),
        },
    }));
    let CustodyOk::Requested { response } = expect_ok(&reply) else {
        panic!("wrong variant")
    };
    assert_eq!(response.status, 200);

    let seen = egress.seen.lock().expect("lock");
    assert_eq!(seen.len(), 1);
    let sent = &seen[0];
    // Material went out at the marked slot — and only there.
    assert_eq!(sent.headers[0].1, "Bearer sk_live_abc");
    assert_eq!(sent.headers[1].1, "application/json");
    assert_eq!(sent.url, "https://api.stripe.com/v1/refunds");
    // The reply whip sees carries no material anywhere.
    let reply_wire = serde_json::to_string(&reply).expect("serialize");
    assert!(!reply_wire.contains("sk_live_abc"));
}

#[test]
fn request_without_a_marked_slot_is_refused() {
    let c = custodian_with(&[("stripe_api", CredentialKind::Bearer, b"sk_live_abc")]);
    let reply = c.handle(&call(CustodyOp::Request {
        credential: name("stripe_api"),
        request: EgressRequest {
            method: "GET".into(),
            url: "https://api.stripe.com/v1/charges".into(),
            headers: vec![],
            body_b64: None,
        },
    }));
    assert!(matches!(
        expect_err(&reply),
        CustodyError::ScopeRefused { .. }
    ));
}

#[test]
fn request_carrying_a_foreign_slot_is_refused() {
    let c = custodian_with(&[
        ("stripe_api", CredentialKind::Bearer, b"sk_live_abc"),
        ("github", CredentialKind::Bearer, b"ghp_xyz"),
    ]);
    let foreign = Sentinel::new(name("github"), PresentationForm::Bearer).render();
    let reply = c.handle(&call(CustodyOp::Request {
        credential: name("stripe_api"),
        request: EgressRequest {
            method: "GET".into(),
            url: "https://api.stripe.com/v1/charges".into(),
            headers: vec![("Authorization".into(), foreign)],
            body_b64: None,
        },
    }));
    assert!(matches!(
        expect_err(&reply),
        CustodyError::ScopeRefused { .. }
    ));
}

// ---------------------------------------------------------------------------
// Mint: the exchange runs custodian-side
// ---------------------------------------------------------------------------

#[test]
fn mint_returns_a_handle_and_the_non_secret_half_only() {
    let egress = CapturingEgress::new(EgressResponse {
        status: 200,
        headers: vec![],
        body_b64: Some(B64.encode(
            br#"{"access_token":"minted-token-123","expires_in":900,"token_type":"bearer"}"#,
        )),
    });
    let c = custodian_with_egress(
        &[("stripe_api", CredentialKind::Bearer, b"sk_live_abc")],
        Box::new(Arc::clone(&egress)),
    );
    let sentinel = Sentinel::new(name("stripe_api"), PresentationForm::Bearer).render();
    let reply = c.handle(&call(CustodyOp::Mint {
        credential: name("stripe_api"),
        scope: vec!["charges:write".into()],
        ttl_secs: 900,
        exchange: EgressRequest {
            method: "POST".into(),
            url: "https://api.stripe.com/v1/tokens".into(),
            headers: vec![("Authorization".into(), sentinel)],
            body_b64: None,
        },
        extraction: MintExtraction {
            token_path: "access_token".into(),
            public_paths: vec!["expires_in".into(), "token_type".into()],
        },
    }));
    let CustodyOk::Minted {
        credential,
        fingerprint,
        public,
    } = expect_ok(&reply)
    else {
        panic!("wrong variant")
    };
    // A handle came back, not the token; the minted entry is usable.
    assert!(credential.as_str().starts_with("stripe_api/mint-"));
    assert_eq!(fingerprint.len(), 16);
    assert_eq!(public["expires_in"], 900);
    let reply_wire = serde_json::to_string(&reply).expect("serialize");
    assert!(!reply_wire.contains("minted-token-123"));

    // The minted handle substitutes like any other credential.
    let sentinel = Sentinel::new(credential.clone(), PresentationForm::Bearer).render();
    let use_minted = c.handle(&call(CustodyOp::Request {
        credential: credential.clone(),
        request: EgressRequest {
            method: "POST".into(),
            url: "https://api.stripe.com/v1/refunds".into(),
            headers: vec![("Authorization".into(), sentinel)],
            body_b64: None,
        },
    }));
    let CustodyOk::Requested { .. } = expect_ok(&use_minted) else {
        panic!("wrong variant")
    };
    let seen = egress.seen.lock().expect("lock");
    assert_eq!(
        seen.last().expect("sent").headers[0].1,
        "Bearer minted-token-123"
    );
}

// ---------------------------------------------------------------------------
// Refusals and admission
// ---------------------------------------------------------------------------

#[test]
fn refusal_paths_are_typed_and_recorded() {
    let c = custodian_with(&[("bearer_only", CredentialKind::Bearer, b"tok")]);

    let unknown = c.handle(&call(CustodyOp::Sign {
        credential: name("missing"),
        alg: SignatureAlg::HmacSha256,
        derivation: vec![],
        payload_b64: B64.encode(b"x"),
    }));
    assert!(matches!(
        expect_err(&unknown),
        CustodyError::UnknownCredential { .. }
    ));

    // The DR's own example: sign with a bearer credential is a kind
    // mismatch.
    let mismatch = c.handle(&call(CustodyOp::Sign {
        credential: name("bearer_only"),
        alg: SignatureAlg::HmacSha256,
        derivation: vec![],
        payload_b64: B64.encode(b"x"),
    }));
    assert!(matches!(
        expect_err(&mismatch),
        CustodyError::KindMismatch { .. }
    ));

    c.revoke(&name("bearer_only")).expect("revoke");
    let revoked = c.handle(&call(CustodyOp::Request {
        credential: name("bearer_only"),
        request: EgressRequest {
            method: "GET".into(),
            url: "https://x.test/".into(),
            headers: vec![(
                "Authorization".into(),
                Sentinel::new(name("bearer_only"), PresentationForm::Bearer).render(),
            )],
            body_b64: None,
        },
    }));
    assert!(matches!(expect_err(&revoked), CustodyError::Revoked { .. }));

    // Every one of those calls — all refusals — left a use record
    // (`UsesAreRecorded`), at the derived rung, tagged degraded at r0.
    let uses = c.uses();
    assert_eq!(uses.len(), 3);
    assert_eq!(
        uses.iter().map(|u| u.outcome.as_str()).collect::<Vec<_>>(),
        vec!["unknown-credential", "kind-mismatch", "revoked"]
    );
    assert!(uses.iter().all(|u| u.rung == Rung::Process && u.degraded));
    assert!(uses.iter().all(|u| u.attribution.run_id == "run-test"));
}

#[test]
fn budgets_bound_use() {
    let mut store = SealedStore::create(None, "pw").expect("create");
    store
        .register(
            name("bounded"),
            CredentialKind::HmacSha256,
            Zeroizing::new(b"key".to_vec()),
            Some(2),
        )
        .expect("register");
    let c = Custodian::new(store, Box::new(DeniedEgress));
    let sign = || {
        call(CustodyOp::Sign {
            credential: name("bounded"),
            alg: SignatureAlg::HmacSha256,
            derivation: vec![],
            payload_b64: B64.encode(b"x"),
        })
    };
    assert!(c.handle(&sign()).outcome.is_ok());
    assert!(c.handle(&sign()).outcome.is_ok());
    let third = c.handle(&sign());
    assert!(matches!(
        expect_err(&third),
        CustodyError::BudgetExhausted { .. }
    ));
}

#[test]
fn derive_returns_a_handle_that_signs() {
    let c = custodian_with(&[("parent", CredentialKind::HmacSha256, b"parent-key")]);
    let derived = c.handle(&call(CustodyOp::Derive {
        credential: name("parent"),
        context: "per-tenant/acme".into(),
    }));
    let CustodyOk::Derived { credential } = expect_ok(&derived) else {
        panic!("wrong variant")
    };
    assert!(credential.as_str().starts_with("parent/hkdf-"));
    let signed = c.handle(&call(CustodyOp::Sign {
        credential: credential.clone(),
        alg: SignatureAlg::HmacSha256,
        derivation: vec![],
        payload_b64: B64.encode(b"payload"),
    }));
    assert!(matches!(expect_ok(&signed), CustodyOk::Signed { .. }));
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

#[test]
fn in_process_transport_speaks_the_wire_protocol() {
    let c = Arc::new(custodian_with(&[(
        "hook",
        CredentialKind::HmacSha256,
        b"secret",
    )]));
    let transport = whipplescript_custodian::InProcessTransport::new(Arc::clone(&c));
    let reply = transport
        .call(call(CustodyOp::Sign {
            credential: name("hook"),
            alg: SignatureAlg::HmacSha256,
            derivation: vec![],
            payload_b64: B64.encode(b"data"),
        }))
        .expect("transport");
    assert!(reply.outcome.is_ok());
    assert_eq!(reply.rung, Rung::Process);
    assert!(reply.degraded);
}

#[test]
fn unix_socket_daemon_serves_and_refuses_get() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let dir = std::env::temp_dir().join(format!("whip-custodian-sock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let socket_path = dir.join("custodian.sock");

    let c = Arc::new(custodian_with(&[(
        "hook",
        CredentialKind::HmacSha256,
        b"secret",
    )]));
    {
        let c = Arc::clone(&c);
        let socket_path = socket_path.clone();
        std::thread::spawn(move || {
            let _ = whipplescript_custodian::serve::serve(c, &socket_path);
        });
    }
    for _ in 0..100 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // A well-formed call over the client transport.
    let transport = whipplescript_custodian::serve::UnixSocketTransport::new(socket_path.clone());
    let reply = transport
        .call(call(CustodyOp::Sign {
            credential: name("hook"),
            alg: SignatureAlg::HmacSha256,
            derivation: vec![],
            payload_b64: B64.encode(b"data"),
        }))
        .expect("transport");
    assert!(reply.outcome.is_ok());
    assert_eq!(reply.use_id.len(), "use-0011223344556677".len());

    // `get` does not exist on the wire: the daemon answers with a protocol
    // error and hangs up (DR-0053 §2 / rejected alternatives).
    let stream = UnixStream::connect(&socket_path).expect("connect");
    let mut writer = stream.try_clone().expect("clone");
    writer
        .write_all(
            format!(
                "{}\n",
                serde_json::json!({
                    "protocol": CUSTODY_PROTOCOL,
                    "attribution": {"run_id": "r"},
                    "op": "get",
                    "credential": "hook",
                })
            )
            .as_bytes(),
        )
        .expect("write");
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).expect("read");
    let value: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
    assert!(value["protocol_error"]
        .as_str()
        .expect("protocol_error")
        .contains("malformed custody call"));

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Every operation names an Operation; the vocabulary is closed
// ---------------------------------------------------------------------------

#[test]
fn use_records_cover_all_operations() {
    let ops = [
        Operation::Request,
        Operation::Sign,
        Operation::Verify,
        Operation::Derive,
        Operation::Wrap,
        Operation::Unwrap,
        Operation::Mint,
    ];
    assert_eq!(ops.len(), Operation::ALL.len());
}
