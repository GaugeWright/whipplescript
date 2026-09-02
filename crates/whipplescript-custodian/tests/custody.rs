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
            .register(
                name(n),
                *kind,
                Zeroizing::new(material.to_vec()),
                None,
                None,
            )
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
    let CustodyOk::Signed { signature_b64, .. } = expect_ok(&reply) else {
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
    let CustodyOk::Signed { signature_b64, .. } = expect_ok(&reply) else {
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
    let CustodyOk::Signed { signature_b64, .. } = expect_ok(&reply) else {
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
    let CustodyOk::Signed { signature_b64, .. } = expect_ok(&signed) else {
        panic!("wrong variant")
    };

    let valid = c.handle(&call(CustodyOp::Verify {
        credential: name("hook"),
        alg: SignatureAlg::HmacSha256,
        payload_b64: B64.encode(payload),
        signature_b64: signature_b64.clone(),
        key_version: None,
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
        key_version: None,
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
        slots: 1,
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
        slots: 0,
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

/// A slot the program did not place — one that arrived inside interpolated
/// data — must refuse the call rather than be filled.
///
/// Slots are found by scanning finished request text, which cannot tell an
/// author-written slot from one carried in by a value. Naming a DIFFERENT
/// credential is already refused, so the dangerous shape is an injected slot
/// naming the SAME credential the call legitimately uses: it passes that check,
/// and `Raw` would place the bare secret wherever the attacker put the marker —
/// here, in a response-visible body field instead of the Authorization header.
/// The declared slot count is what makes the two disagree.
#[test]
fn a_slot_the_program_did_not_declare_is_refused() {
    let egress = CapturingEgress::new(EgressResponse {
        status: 200,
        headers: vec![],
        body_b64: Some(B64.encode(b"{\"ok\":true}")),
    });
    let c = custodian_with_egress(
        &[("stripe_api", CredentialKind::Bearer, b"sk_live_abc")],
        Box::new(Arc::clone(&egress)),
    );
    let authored = Sentinel::new(name("stripe_api"), PresentationForm::Bearer).render();
    // Same credential, so the foreign-slot check does not fire; `Raw` so the
    // bare secret would land in the body.
    let injected = Sentinel::new(name("stripe_api"), PresentationForm::Raw).render();
    let reply = c.handle(&call(CustodyOp::Request {
        credential: name("stripe_api"),
        // The program placed exactly one slot: the Authorization header.
        slots: 1,
        request: EgressRequest {
            method: "POST".into(),
            url: "https://api.stripe.com/v1/refunds".into(),
            headers: vec![("Authorization".into(), authored)],
            body_b64: Some(B64.encode(format!("{{\"note\":\"{injected}\"}}").as_bytes())),
        },
    }));
    assert!(
        matches!(expect_err(&reply), CustodyError::ScopeRefused { .. }),
        "an undeclared slot must refuse the call"
    );
    assert!(
        egress.seen.lock().expect("lock").is_empty(),
        "nothing egressed: the refusal precedes the request"
    );
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
        slots: 1,
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
        exchange_slots: 1,
        // The vendor scope and TTL live in the exchange BODY, which is what
        // goes on the wire — not as op fields beside it that could disagree
        // with it (DR-0053 §5 Amendment 2026-08-27).
        exchange: EgressRequest {
            method: "POST".into(),
            url: "https://api.stripe.com/v1/tokens".into(),
            headers: vec![("Authorization".into(), sentinel)],
            body_b64: Some(whipplescript_custody::encode_body_b64(
                b"grant_type=client_credentials&scope=charges:write&expires_in=900",
            )),
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
        slots: 1,
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
        slots: 1,
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
            None,
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

// The daemon transport itself; the vocabulary tests above cover every
// platform.
#[cfg(target_family = "unix")]
#[test]
fn unix_socket_daemon_serves_and_refuses_get() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "whip-custodian-sock-{}-{nonce}",
        std::process::id()
    ));
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
    let mut listener_ready = false;
    for _ in 0..100 {
        match UnixStream::connect(&socket_path) {
            Ok(stream) => {
                drop(stream);
                listener_ready = true;
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("wait for custodian listener: {error}"),
        }
    }
    assert!(listener_ready, "custodian listener did not become ready");

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
        Operation::Deliver,
    ];
    assert_eq!(ops.len(), Operation::ALL.len());
    // Named individually rather than counted, so adding a member operation
    // fails here with the NAME of the one that has no attribution rather than
    // with two numbers.
    for op in Operation::ALL {
        assert!(
            ops.contains(&op),
            "`{}` is a member operation with no use record: §1 claims attribution for EVERY use",
            op.as_str()
        );
    }
}

// ---------------------------------------------------------------------------
// Container operations (DR-0053 §2 Amendment 2026-08-29)
// ---------------------------------------------------------------------------

/// `Generate` creates sealed material in one act with its registration, and
/// returns a HANDLE. The material never crosses the protocol — that is what
/// keeps §2's claim true of the one operation that could plausibly break it.
#[test]
fn generate_creates_a_usable_credential_and_returns_only_a_handle() {
    let custodian = custodian_with(&[]);
    let target = name("deploy_keys/ci-2026-08");

    let reply = custodian.handle(&call(CustodyOp::Generate {
        credential: target.clone(),
        kind: CredentialKind::Ed25519,
    }));
    let CustodyReply {
        outcome: Ok(CustodyOk::Generated { credential, kind }),
        ..
    } = reply
    else {
        panic!("generate must succeed: {reply:?}");
    };
    assert_eq!(credential, target);
    assert_eq!(kind, CredentialKind::Ed25519);

    // The reply carries a handle and nothing else, so the only way to show the
    // material exists is to USE it — which is also the property worth proving.
    let signed = custodian.handle(&call(CustodyOp::Sign {
        credential: target.clone(),
        alg: SignatureAlg::Ed25519,
        derivation: Vec::new(),
        payload_b64: B64.encode(b"release-manifest"),
    }));
    assert!(
        matches!(signed.outcome, Ok(CustodyOk::Signed { .. })),
        "generated material must be usable: {signed:?}"
    );
}

/// A kind whose material a third party issues cannot be conjured. `bearer` is a
/// token issued TO us and `aws-sigv4`'s secret comes from IAM, so §11's
/// `obtain credential` is their path, not this one.
#[test]
fn generate_refuses_a_kind_nobody_here_can_issue() {
    let custodian = custodian_with(&[]);
    for kind in [CredentialKind::Bearer, CredentialKind::AwsSigv4] {
        let reply = custodian.handle(&call(CustodyOp::Generate {
            credential: name("v/member"),
            kind,
        }));
        let Err(CustodyError::Backend { detail }) = &reply.outcome else {
            panic!("{kind:?} must not be generatable: {reply:?}");
        };
        assert!(
            detail.contains("cannot be generated") && detail.contains(kind.as_str()),
            "the refusal must name the kind it refuses: {detail}"
        );
    }
}

/// `Store::register` is an upsert, which is right for an operator driving the
/// admin surface deliberately and wrong for a name arriving from a running
/// program. A silent overwrite would destroy a live credential and hand back a
/// handle that looks identical.
#[test]
fn generate_refuses_to_overwrite_an_existing_credential() {
    let custodian = custodian_with(&[("vault/live", CredentialKind::HmacSha256, b"existing-key")]);
    let reply = custodian.handle(&call(CustodyOp::Generate {
        credential: name("vault/live"),
        kind: CredentialKind::HmacSha256,
    }));
    let Err(CustodyError::Backend { detail }) = &reply.outcome else {
        panic!("an existing name must not be overwritten: {reply:?}");
    };
    // Asserting the MESSAGE, not just the variant. `Backend` carries every
    // other internal failure too, so a variant-only assertion passes for
    // reasons that have nothing to do with the collision — which is exactly
    // what the mutation sweep reported about the first version of this test.
    assert!(
        detail.contains("already exists"),
        "the refusal must name the collision: {detail}"
    );

    // And the original material survives: the refusal is not a partial write.
    let signed = custodian.handle(&call(CustodyOp::Sign {
        credential: name("vault/live"),
        alg: SignatureAlg::HmacSha256,
        derivation: Vec::new(),
        payload_b64: B64.encode(b"probe"),
    }));
    assert!(matches!(signed.outcome, Ok(CustodyOk::Signed { .. })));
}

/// `Revoke` ends a credential whatever its kind, and reports whether it
/// changed anything. `existed: false` is a SUCCESSFUL call — the same shape
/// `Verified` uses for an invalid signature, so a caller does not have to read
/// an error to learn there was nothing there.
#[test]
fn revoke_ends_a_credential_and_reports_whether_one_existed() {
    let custodian = custodian_with(&[("vault/doomed", CredentialKind::HmacSha256, b"key")]);

    let reply = custodian.handle(&call(CustodyOp::Revoke {
        credential: name("vault/doomed"),
    }));
    assert!(
        matches!(reply.outcome, Ok(CustodyOk::Revoked { existed: true })),
        "{reply:?}"
    );

    // Revocation bites: the credential no longer signs.
    let after = custodian.handle(&call(CustodyOp::Sign {
        credential: name("vault/doomed"),
        alg: SignatureAlg::HmacSha256,
        derivation: Vec::new(),
        payload_b64: B64.encode(b"probe"),
    }));
    assert!(
        matches!(after.outcome, Err(CustodyError::Revoked { .. })),
        "a revoked credential must refuse use: {after:?}"
    );

    let absent = custodian.handle(&call(CustodyOp::Revoke {
        credential: name("vault/never-existed"),
    }));
    assert!(
        matches!(absent.outcome, Ok(CustodyOk::Revoked { existed: false })),
        "revoking nothing is a successful call, not an error: {absent:?}"
    );
}

/// Container operations are attributable like any other use. §1 claims every
/// use is, and a creation nobody recorded would be the worst one to miss.
#[test]
fn a_generate_is_recorded_as_a_use() {
    let custodian = custodian_with(&[]);
    custodian.handle(&call(CustodyOp::Generate {
        credential: name("v/m"),
        kind: CredentialKind::Raw,
    }));
    let uses = custodian.uses();
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].operation, Operation::Generate);
    assert_eq!(uses[0].credential, "v/m");
}

/// Rotation is remote-only, and the refusal names why rather than failing
/// obscurely. A local entry holds exactly one material, so a successor would
/// REPLACE its predecessor and break every outstanding signature — the one
/// thing a one-material store could do, and the opposite of the dual validity
/// §12 asks for.
#[test]
fn rotate_refuses_a_locally_sealed_credential_by_name() {
    let custodian = custodian_with(&[("vault/local", CredentialKind::HmacSha256, b"key")]);
    let reply = custodian.handle(&call(CustodyOp::Rotate {
        credential: name("vault/local"),
    }));
    let Err(CustodyError::Backend { detail }) = reply.outcome else {
        panic!("a local rotation must refuse: {reply:?}");
    };
    assert!(
        detail.contains("cannot rotate") && detail.contains("r3 remote rung"),
        "the refusal must say why and where rotation lives: {detail}"
    );

    // The predecessor is untouched: the refusal is not a partial rotation.
    let signed = custodian.handle(&call(CustodyOp::Sign {
        credential: name("vault/local"),
        alg: SignatureAlg::HmacSha256,
        derivation: Vec::new(),
        payload_b64: B64.encode(b"probe"),
    }));
    assert!(matches!(signed.outcome, Ok(CustodyOk::Signed { .. })));
}

/// Rotation is a container operation, so it reaches the credential's identity
/// rather than its key — but an unknown or revoked entry still has no identity
/// to rotate.
#[test]
fn rotate_refuses_an_unknown_or_revoked_credential() {
    let custodian = custodian_with(&[("vault/dead", CredentialKind::HmacSha256, b"key")]);

    let unknown = custodian.handle(&call(CustodyOp::Rotate {
        credential: name("vault/absent"),
    }));
    assert!(
        matches!(unknown.outcome, Err(CustodyError::UnknownCredential { .. })),
        "{unknown:?}"
    );

    custodian.handle(&call(CustodyOp::Revoke {
        credential: name("vault/dead"),
    }));
    let revoked = custodian.handle(&call(CustodyOp::Rotate {
        credential: name("vault/dead"),
    }));
    assert!(
        matches!(revoked.outcome, Err(CustodyError::Revoked { .. })),
        "a revoked credential has nothing to rotate: {revoked:?}"
    );
}

/// A remote entry with no client configured is a refusal worth naming: the
/// credential exists and its material lives elsewhere, so failing silently
/// would look like a rotation that did nothing.
#[test]
fn rotate_refuses_a_remote_credential_with_no_openbao_connection() {
    let mut store = SealedStore::create(None, "test-passphrase").expect("create");
    store
        .register_remote(
            name("vault/remote"),
            CredentialKind::Ed25519,
            "k".into(),
            None,
            None,
        )
        .expect("register remote");
    let custodian = Custodian::new(store, Box::new(DeniedEgress));

    let reply = custodian.handle(&call(CustodyOp::Rotate {
        credential: name("vault/remote"),
    }));
    let Err(CustodyError::Backend { detail }) = &reply.outcome else {
        panic!("a remote rotation with no client must refuse: {reply:?}");
    };
    assert!(
        detail.contains("no OpenBao connection configured"),
        "the refusal must name what is missing: {detail}"
    );
}

/// The signing bound of DR-0053 §14's amendment, enforced where it has to be.
///
/// `CustodyOk::Signed` returns the signature to whip, so a standalone `sign` is
/// an oracle whose payload whip chooses. The custodian holding the bound is
/// what makes it hold against a fully compromised whip rather than merely an
/// escaped agent — a bound whip supplied is one whip could choose.
#[test]
fn a_configured_prefix_bounds_what_a_credential_may_sign() {
    let mut store = SealedStore::create(None, "test-passphrase").expect("create");
    store
        .register(
            name("acme/github"),
            CredentialKind::HmacSha256,
            Zeroizing::new(b"app-key".to_vec()),
            None,
            None,
        )
        .expect("register");
    let mut prefixes = std::collections::BTreeMap::new();
    prefixes.insert(
        name("acme/github"),
        vec![whipplescript_custody::sign_prefix::named("jwt-rs256-header").expect("named")],
    );
    let custodian = Custodian::new(store, Box::new(DeniedEgress)).with_sign_prefixes(prefixes);

    let sign = |payload: &[u8]| {
        custodian.handle(&call(CustodyOp::Sign {
            credential: name("acme/github"),
            alg: SignatureAlg::HmacSha256,
            derivation: Vec::new(),
            payload_b64: B64.encode(payload),
        }))
    };

    let jwt = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJnaXRodWIifQ";
    assert!(
        matches!(sign(jwt).outcome, Ok(CustodyOk::Signed { .. })),
        "a payload inside the bound must sign"
    );

    // The property the mechanism rests on: a key bounded to one protocol's
    // prefix cannot produce another protocol's signature.
    let tls = whipplescript_custody::sign_prefix::named("tls13-client-auth").expect("named");
    let reply = sign(&tls);
    let Err(CustodyError::Backend { detail }) = &reply.outcome else {
        panic!("a TLS CertificateVerify must be refused: {reply:?}");
    };
    assert!(
        detail.contains("begins with none of the configured prefixes"),
        "the refusal must say why: {detail}"
    );
}

/// A credential the configuration does not name is unbounded. Naming one is
/// what opts it in — a custodian that refused unnamed credentials on upgrade
/// would take every existing deployment down rather than tighten it.
#[test]
fn an_unnamed_credential_signs_without_a_prefix_bound() {
    let custodian = custodian_with(&[("acme/other", CredentialKind::HmacSha256, b"key")]);
    let reply = custodian.handle(&call(CustodyOp::Sign {
        credential: name("acme/other"),
        alg: SignatureAlg::HmacSha256,
        derivation: Vec::new(),
        payload_b64: B64.encode(b"anything at all"),
    }));
    assert!(
        matches!(reply.outcome, Ok(CustodyOk::Signed { .. })),
        "{reply:?}"
    );
}

/// r3 transit signs with the key inside the engine, so a derivation chain — the
/// §7 fold that produces a subkey from the raw material — has nothing to fold.
/// Refused by name rather than silently signing without the chain, which would
/// produce a valid signature under the wrong key.
///
/// Reachable without a server: the refusal happens after the client is resolved
/// and before any request, so a client pointed at a closed port is enough.
#[test]
fn r3_refuses_a_derivation_chain_rather_than_ignoring_it() {
    let mut store = SealedStore::create(None, "test-passphrase").expect("create");
    store
        .register_remote(
            name("acme/remote"),
            CredentialKind::HmacSha256,
            "transit-key".into(),
            None,
            None,
        )
        .expect("register remote");
    let custodian = Custodian::new(store, Box::new(DeniedEgress)).with_openbao(Arc::new(
        whipplescript_custodian::openbao::Client::new("http://127.0.0.1:1", "token"),
    ));

    let reply = custodian.handle(&call(CustodyOp::Sign {
        credential: name("acme/remote"),
        alg: SignatureAlg::HmacSha256,
        derivation: vec!["20260831".into(), "us-east-1".into()],
        payload_b64: B64.encode(b"payload"),
    }));
    let Err(CustodyError::Backend { detail }) = &reply.outcome else {
        panic!("a derivation chain on r3 must refuse: {reply:?}");
    };
    assert!(
        detail.contains("does not support derivation chains"),
        "the refusal must name what it cannot do: {detail}"
    );
}

/// `Register` takes material whip already holds into custody (DR-0053 §15
/// Amendment). The producer that makes `secret<kind>` stop being inert.
///
/// It does not breach §2, and the reason is the point: whip holds plaintext for
/// one admission because the PASTE already put it there. Registration restores
/// the invariant rather than preserving it — exposure narrows from
/// indefinitely-as-a-string to one-admission-then-a-handle.
#[test]
fn register_takes_ingressed_material_into_custody_and_returns_a_handle() {
    let custodian = custodian_with(&[]);
    let target = name("ingress/vendor-key");

    let reply = custodian.handle(&call(CustodyOp::Register {
        credential: target.clone(),
        kind: CredentialKind::HmacSha256,
        material_b64: B64.encode(b"pasted-webhook-secret"),
    }));
    let CustodyReply {
        outcome: Ok(CustodyOk::Registered { credential }),
        ..
    } = reply
    else {
        panic!("register must succeed: {reply:?}");
    };
    assert_eq!(credential, target);

    // The reply is a handle and nothing else. Showing the material arrived
    // means USING it, which is also the property worth proving.
    let signed = custodian.handle(&call(CustodyOp::Sign {
        credential: target,
        alg: SignatureAlg::HmacSha256,
        derivation: Vec::new(),
        payload_b64: B64.encode(b"webhook-body"),
    }));
    assert!(
        matches!(signed.outcome, Ok(CustodyOk::Signed { .. })),
        "registered material must be usable: {signed:?}"
    );
}

/// Registering onto a live name would replace a credential with material a
/// third party supplied — worse than the generate collision, and refused for
/// the same reason: `Store::register` is an upsert, right for an operator and
/// wrong for a name arriving from a running program.
#[test]
fn register_refuses_to_overwrite_an_existing_credential() {
    let custodian = custodian_with(&[("live/key", CredentialKind::HmacSha256, b"original")]);
    let reply = custodian.handle(&call(CustodyOp::Register {
        credential: name("live/key"),
        kind: CredentialKind::HmacSha256,
        material_b64: B64.encode(b"attacker-supplied"),
    }));
    let Err(CustodyError::Backend { detail }) = &reply.outcome else {
        panic!("an existing name must not be overwritten: {reply:?}");
    };
    assert!(detail.contains("already exists"), "{detail}");
}

/// Empty material is refused: a handle to nothing would sign and verify as
/// though it meant something.
#[test]
fn register_refuses_material_that_is_not_there() {
    let custodian = custodian_with(&[]);
    let reply = custodian.handle(&call(CustodyOp::Register {
        credential: name("ingress/empty"),
        kind: CredentialKind::HmacSha256,
        material_b64: String::new(),
    }));
    let Err(CustodyError::Backend { detail }) = &reply.outcome else {
        panic!("empty material must refuse: {reply:?}");
    };
    assert!(detail.contains("no material"), "{detail}");
}

// ---------------------------------------------------------------------------
// Credential leases (DR-0053 §9's fifth lease mechanism)
// ---------------------------------------------------------------------------

/// A lease is revocation nobody had to perform. Past its expiry the credential
/// refuses, and it refuses by a DISTINCT error: an operator reading a refusal
/// needs to know whether someone pulled this credential or whether it simply
/// ran out. The first is an incident, the second is Tuesday.
#[test]
fn an_expired_lease_refuses_and_says_so_distinctly() {
    let mut store = SealedStore::create(None, "test-passphrase").expect("create");
    let past = whipplescript_custodian::now_epoch_s() - 1;
    store
        .register(
            name("acme/expired"),
            CredentialKind::HmacSha256,
            Zeroizing::new(b"key".to_vec()),
            None,
            Some(past),
        )
        .expect("register");
    // A live lease on the same store, so the refusal below is about THIS
    // credential's expiry rather than about leases existing at all.
    store
        .register(
            name("acme/live"),
            CredentialKind::HmacSha256,
            Zeroizing::new(b"key".to_vec()),
            None,
            Some(whipplescript_custodian::now_epoch_s() + 3600),
        )
        .expect("register");
    let custodian = Custodian::new(store, Box::new(DeniedEgress));

    let sign = |credential: &str| {
        custodian.handle(&call(CustodyOp::Sign {
            credential: name(credential),
            alg: SignatureAlg::HmacSha256,
            derivation: Vec::new(),
            payload_b64: B64.encode(b"payload"),
        }))
    };

    let reply = sign("acme/expired");
    let Err(CustodyError::LeaseExpired {
        credential,
        expired_at,
    }) = reply.outcome
    else {
        panic!("an expired lease must refuse by name: {reply:?}");
    };
    assert_eq!(credential.as_str(), "acme/expired");
    assert_eq!(expired_at, past);

    assert!(
        matches!(sign("acme/live").outcome, Ok(CustodyOk::Signed { .. })),
        "a live lease must not refuse"
    );
}

/// A credential with no lease is unbounded in time, as every credential was
/// before this. Naming one opts it in — the same shape the signing bound and
/// the egress allow-list take.
#[test]
fn a_credential_with_no_lease_is_unbounded() {
    let custodian = custodian_with(&[("acme/forever", CredentialKind::HmacSha256, b"key")]);
    let reply = custodian.handle(&call(CustodyOp::Sign {
        credential: name("acme/forever"),
        alg: SignatureAlg::HmacSha256,
        derivation: Vec::new(),
        payload_b64: B64.encode(b"payload"),
    }));
    assert!(
        matches!(reply.outcome, Ok(CustodyOk::Signed { .. })),
        "{reply:?}"
    );
}

/// The expiry is DURABLE, which is the whole reason it sits beside the budget
/// rather than replacing it. The budget's counts live in process memory, so a
/// custodian restart resets them; a lease reopened from the sealed store still
/// refuses.
#[test]
fn a_lease_survives_a_custodian_restart() {
    let dir = std::env::temp_dir().join(format!("whip-lease-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("store.json");
    let past = whipplescript_custodian::now_epoch_s() - 1;
    {
        let mut store = SealedStore::create(Some(path.clone()), "test-passphrase").expect("create");
        store
            .register(
                name("acme/expired"),
                CredentialKind::HmacSha256,
                Zeroizing::new(b"key".to_vec()),
                None,
                Some(past),
            )
            .expect("register");
    }
    let reopened = SealedStore::open(&path, "test-passphrase").expect("reopen");
    let custodian = Custodian::new(reopened, Box::new(DeniedEgress));
    let reply = custodian.handle(&call(CustodyOp::Sign {
        credential: name("acme/expired"),
        alg: SignatureAlg::HmacSha256,
        derivation: Vec::new(),
        payload_b64: B64.encode(b"payload"),
    }));
    assert!(
        matches!(reply.outcome, Err(CustodyError::LeaseExpired { .. })),
        "an expiry must survive the restart that resets a budget: {reply:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `deliver` is a SEPARATE authority from `request`, and only for the kinds
/// that have no public half to publish instead (DR-0053 §5 Amendment).
#[test]
fn delivering_a_credential_is_not_the_same_authority_as_spending_it() {
    use whipplescript_custody::Operation;

    // Spending and giving away are different grants. One covering both would
    // have made every existing `request` grant a handoff grant retroactively.
    assert_ne!(Operation::Request, Operation::Deliver);
    assert_eq!(
        Operation::parse("deliver").expect("known"),
        Operation::Deliver
    );
    assert!(
        Operation::ALL.contains(&Operation::Deliver),
        "a member operation, so a declaration's `allow` list may name it"
    );
    assert!(
        !Operation::Deliver.is_container(),
        "it acts on an existing credential rather than on a vault"
    );
    // Narrowable, and more urgently than `request`: a handoff grant with no
    // destination list would be "give this to anyone".
    assert!(Operation::Deliver.narrowable());
}

#[test]
fn only_kinds_with_no_public_half_can_be_delivered() {
    use whipplescript_custody::{CredentialKind, Operation};

    // The symmetric and opaque kinds have nothing to publish instead.
    for kind in [
        CredentialKind::Bearer,
        CredentialKind::Basic,
        CredentialKind::Raw,
        CredentialKind::HmacSha256,
    ] {
        assert!(
            kind.supports(Operation::Deliver),
            "{kind} has no public half, so handing it over is the only handoff"
        );
    }
    // §5 is explicit that asymmetric kinds hand off by publishing their public
    // half — not material, no operation needed — so admitting them here would
    // offer a way to ship a private key the design says nobody needs.
    for kind in [
        CredentialKind::Ed25519,
        CredentialKind::JwtRs256,
        CredentialKind::MtlsClient,
    ] {
        assert!(
            !kind.supports(Operation::Deliver),
            "{kind} hands off by publishing its public half"
        );
    }
}

#[test]
fn a_kind_that_cannot_be_delivered_is_refused_by_name() {
    let mut store = SealedStore::create(None, "pw").expect("store");
    store
        .register(
            name("release_signing"),
            CredentialKind::Ed25519,
            zeroize::Zeroizing::new([7u8; 32].to_vec()),
            None,
            None,
        )
        .expect("register");
    let custodian = Custodian::new(store, Box::new(whipplescript_custodian::DeniedEgress));

    let reply = custodian.handle(&call(CustodyOp::Deliver {
        credential: name("release_signing"),
        slots: 0,
        request: whipplescript_custody::EgressRequest {
            method: "PUT".into(),
            url: "https://ci.example/secrets".into(),
            headers: vec![],
            body_b64: None,
        },
    }));
    let error = reply.outcome.expect_err("an ed25519 key is not delivered");
    let said = error.to_string();
    assert!(said.contains("release_signing"), "{said}");
    assert!(
        said.contains("deliver"),
        "the refusal names the operation: {said}"
    );
}

#[test]
fn a_handoff_is_recorded_once_and_survives_a_restart() {
    // The reaping rule asks "did this EVER leave", not "when did it last
    // leave", so a second delivery does not move the timestamp. And it is asked
    // at instance terminal, possibly after a restart — a handoff that only
    // lived in memory would reap a key that already reached its recipient.
    let directory = std::env::temp_dir().join(format!("whip-handoff-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("temp dir");
    let path = directory.join("store.json");

    let mut store = SealedStore::create(Some(path.clone()), "pw").expect("store");
    store
        .register(
            name("ci_token"),
            CredentialKind::Bearer,
            zeroize::Zeroizing::new(b"tok".to_vec()),
            None,
            None,
        )
        .expect("register");
    assert_eq!(
        store.delivered_at(&name("ci_token")),
        None,
        "never handed off yet"
    );

    store
        .mark_delivered(&name("ci_token"), 1_000)
        .expect("recorded");
    store
        .mark_delivered(&name("ci_token"), 2_000)
        .expect("again");
    assert_eq!(
        store.delivered_at(&name("ci_token")),
        Some(1_000),
        "the FIRST handoff stands: it left, and when it last left is a different question"
    );

    let reopened = SealedStore::open(&path, "pw").expect("reopen");
    assert_eq!(
        reopened.delivered_at(&name("ci_token")),
        Some(1_000),
        "the record survives the restart the reaping question is asked after"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_handoff_for_a_credential_that_is_not_there_is_refused() {
    let mut store = SealedStore::create(None, "pw").expect("store");
    let refused = store
        .mark_delivered(&name("absent"), 1_000)
        .expect_err("nothing to record against");
    assert!(
        refused.to_string().contains("not in this store"),
        "{refused}"
    );
}

/// A delivery whose record failed says so, and does NOT report success.
///
/// The asymmetry is the point: the credential has already reached the
/// recipient and cannot be recalled, so the only thing that failed is the
/// record — and a reaper reading a missing record would revoke a live key.
#[test]
fn a_handoff_that_cannot_be_recorded_fails_loudly() {
    let mut store = SealedStore::create(None, "pw").expect("store");
    store
        .register(
            name("ci_token"),
            CredentialKind::Bearer,
            zeroize::Zeroizing::new(b"tok".to_vec()),
            None,
            None,
        )
        .expect("register");
    // The store refuses a handoff for a credential it does not hold, which is
    // the failure this message renders.
    let error = store
        .mark_delivered(&name("absent"), 1_000)
        .expect_err("nothing to record against")
        .to_string();
    let said = whipplescript_custodian::unrecordable_handoff_detail(&name("ci_token"), &error);
    assert!(
        said.contains("reached its recipient"),
        "the credential is GONE, and the message must say so: {said}"
    );
    assert!(
        said.contains("could not be recorded"),
        "and that the record is what failed: {said}"
    );
    assert!(
        said.contains("treat it as never delivered"),
        "and what that costs: {said}"
    );
}
