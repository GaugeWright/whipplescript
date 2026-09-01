//! r2 `hardware` over PKCS#11, end to end through the custodian.
//!
//! Split the way the TPM suite is: the rung, the refusals and the store round
//! trip need no token and run on the ordinary green bar; only the signature
//! needs a module, and that test skips with a recorded reason.
//!
//! What the live half evidences depends entirely on which module answered, and
//! `scripts/check-pkcs11-live-smoke.sh` says so in its own output. Against
//! SoftHSM these assertions prove the plumbing; the attributes a software
//! module reports are identical to a hardware one's.

use whipplescript_custodian::pkcs11::KeyAttributes;
use whipplescript_custodian::store::{Pkcs11Ref, SealedStore};
use whipplescript_custodian::Custodian;
use whipplescript_custody::{
    CredentialKind, CredentialName, CustodyCall, CustodyOp, Rung, SignatureAlg, UseAttribution,
};

fn name(text: &str) -> CredentialName {
    CredentialName::new(text).expect("name")
}

fn resident() -> KeyAttributes {
    KeyAttributes {
        sensitive: true,
        extractable: false,
        always_sensitive: true,
        never_extractable: true,
    }
}

fn a_reference() -> Pkcs11Ref {
    Pkcs11Ref {
        module: "/usr/lib/softhsm/libsofthsm2.so".to_owned(),
        token: "whip-smoke".to_owned(),
        key: "release-signing".to_owned(),
    }
}

fn sign_call(credential: &str) -> CustodyCall {
    CustodyCall::new(
        UseAttribution {
            run_id: "run-1".to_owned(),
            actor: None,
            effect_key: None,
        },
        CustodyOp::Sign {
            credential: name(credential),
            alg: SignatureAlg::HmacSha256,
            derivation: vec![],
            payload_b64: "cGF5bG9hZA==".to_owned(),
        },
    )
}

fn registered(reference: Pkcs11Ref) -> Custodian {
    let mut store = SealedStore::create(None, "pass").expect("store");
    store
        .register_pkcs11(
            name("release_signing"),
            CredentialKind::HmacSha256,
            reference,
            resident(),
            None,
            None,
        )
        .expect("registered");
    Custodian::new(store, Box::new(whipplescript_custodian::DeniedEgress))
}

#[test]
fn a_token_credential_reports_hardware_and_is_not_degraded() {
    let custodian = registered(a_reference());
    let reply = custodian.handle(&sign_call("release_signing"));
    assert_eq!(reply.rung, Rung::Hardware);
    assert!(
        !reply.degraded,
        "a key the token says never left is not a degraded rung"
    );
}

#[test]
fn a_token_credential_survives_a_store_round_trip() {
    // Where the key is AND what admitted it both have to survive: the rung is
    // judged against the attributes, so losing them would turn a hardware
    // credential into a malformed entry.
    let directory = std::env::temp_dir().join(format!("whip-p11-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("temp dir");
    let path = directory.join("store.json");

    let mut store = SealedStore::create(Some(path.clone()), "pass").expect("store");
    store
        .register_pkcs11(
            name("release_signing"),
            CredentialKind::HmacSha256,
            a_reference(),
            resident(),
            None,
            None,
        )
        .expect("registered");
    store.persist().expect("persisted");

    let reopened = SealedStore::open(&path, "pass").expect("reopened");
    let custodian = Custodian::new(reopened, Box::new(whipplescript_custodian::DeniedEgress));
    assert_eq!(
        custodian.handle(&sign_call("release_signing")).rung,
        Rung::Hardware
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_token_credential_refuses_operations_that_need_material_on_this_box() {
    let custodian = registered(a_reference());
    let reply = custodian.handle(&CustodyCall::new(
        UseAttribution {
            run_id: "run-1".to_owned(),
            actor: None,
            effect_key: None,
        },
        CustodyOp::Wrap {
            credential: name("release_signing"),
            plaintext_b64: "cGF5bG9hZA==".to_owned(),
            label: serde_json::Value::Null,
            context: "ctx".to_owned(),
        },
    ));
    let said = reply
        .outcome
        .expect_err("wrap needs material this box lacks")
        .to_string();
    assert!(said.contains("PKCS#11 token"), "{said}");
    assert!(
        said.contains("wrap"),
        "the refusal names the operation: {said}"
    );
}

/// A custodian built WITHOUT the `pkcs11` feature refuses by name.
///
/// The configuration the default build and the green bar are in, so it is the
/// path most likely to be taken by someone who did not expect it: a store
/// written on a host with a token, opened on one without the module.
#[cfg(not(feature = "pkcs11"))]
#[test]
fn a_custodian_without_the_feature_refuses_by_name() {
    let custodian = registered(a_reference());
    let reply = custodian.handle(&sign_call("release_signing"));
    // The rung is still r2 — the entry is what it is, and this binary simply
    // cannot reach the token that holds the key.
    assert_eq!(reply.rung, Rung::Hardware);
    let said = reply
        .outcome
        .expect_err("no feature, no signature")
        .to_string();
    assert!(
        said.contains("built without the `pkcs11` feature"),
        "{said}"
    );
    assert!(
        said.contains("--features pkcs11"),
        "and the way forward: {said}"
    );
}

/// The whole of PKCS#11 r2 through the custodian, against whatever module the
/// smoke script pointed it at.
#[cfg(feature = "pkcs11")]
#[test]
fn a_signature_from_the_token_comes_back_through_the_custodian() {
    let Ok(module) = std::env::var("WHIPPLESCRIPT_PKCS11_SMOKE_MODULE") else {
        eprintln!("SKIP: no reachable token (WHIPPLESCRIPT_PKCS11_SMOKE_MODULE is not set)");
        return;
    };
    let reference = Pkcs11Ref {
        module,
        token: std::env::var("WHIPPLESCRIPT_PKCS11_SMOKE_TOKEN").expect("token label"),
        key: std::env::var("WHIPPLESCRIPT_PKCS11_SMOKE_KEY").expect("key label"),
    };

    // Read the attributes the way registration does, so the entry is admitted
    // on what the token actually says rather than on a fixture.
    let admitted = {
        let context =
            whipplescript_custodian::pkcs11_device::module(&reference.module).expect("module");
        let slot =
            whipplescript_custodian::pkcs11_device::slot_with_token(&context, &reference.token)
                .expect("token");
        let pin = std::env::var(whipplescript_custodian::pkcs11::PIN_ENV).expect("pin");
        let session =
            whipplescript_custodian::pkcs11_device::session(&context, slot, &pin).expect("session");
        let (_key, attributes) =
            whipplescript_custodian::pkcs11_device::admitted_key(&session, &reference.key)
                .expect("the key evidences r2");
        attributes
    };

    let mut store = SealedStore::create(None, "pass").expect("store");
    store
        .register_pkcs11(
            name("release_signing"),
            CredentialKind::HmacSha256,
            reference,
            admitted,
            None,
            None,
        )
        .expect("registered");
    let custodian = Custodian::new(store, Box::new(whipplescript_custodian::DeniedEgress));

    let signature = match custodian
        .handle(&sign_call("release_signing"))
        .outcome
        .expect("the token signed")
    {
        whipplescript_custody::CustodyOk::Signed { signature_b64, .. } => signature_b64,
        other => panic!("expected a signature, got {other:?}"),
    };

    let verify = |payload: &str, sig: &str| -> bool {
        let reply = custodian.handle(&CustodyCall::new(
            UseAttribution {
                run_id: "run-1".to_owned(),
                actor: None,
                effect_key: None,
            },
            CustodyOp::Verify {
                credential: name("release_signing"),
                alg: SignatureAlg::HmacSha256,
                payload_b64: payload.to_owned(),
                signature_b64: sig.to_owned(),
                key_version: None,
            },
        ));
        match reply.outcome.expect("the token answered") {
            whipplescript_custody::CustodyOk::Verified { valid } => valid,
            other => panic!("expected a verdict, got {other:?}"),
        }
    };

    assert!(
        verify("cGF5bG9hZA==", &signature),
        "its own signature verifies"
    );
    assert!(
        !verify("b3RoZXI=", &signature),
        "a different payload must not"
    );
}
