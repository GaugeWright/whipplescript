//! r2 `hardware` end to end through the custodian (DR-0053 §4).
//!
//! Split by what each half needs. The rung, the refusals and the store round
//! trip need no chip and run on the ordinary green bar; only the signature
//! itself needs a TPM, and that test skips with a recorded reason — the
//! env-gated live-smoke shape §8 sets for r3.

use whipplescript_custodian::store::SealedStore;
use whipplescript_custodian::tpm::{bind, PcrBinding};
use whipplescript_custodian::Custodian;
use whipplescript_custody::{
    CredentialKind, CredentialName, CustodyCall, CustodyOp, Rung, SignatureAlg, UseAttribution,
};

fn name(text: &str) -> CredentialName {
    CredentialName::new(text).expect("name")
}

fn a_binding() -> PcrBinding {
    bind(&[0, 7], &[b"firmware".to_vec(), b"secureboot".to_vec()]).expect("binding")
}

fn call(credential: &str, payload_b64: &str) -> CustodyCall {
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
            payload_b64: payload_b64.to_owned(),
        },
    )
}

#[test]
fn a_tpm_credential_reports_hardware_and_is_not_degraded() {
    // The rung is DERIVED from what the entry is. r0 entries in the same store
    // still report r0, so this is per-entry evidence rather than a custodian
    // that got promoted.
    let mut store = SealedStore::create(None, "pass").expect("store");
    store
        .register_tpm(
            name("release_signing"),
            CredentialKind::HmacSha256,
            a_binding(),
            None,
            None,
        )
        .expect("registered");
    store
        .register(
            name("local_key"),
            CredentialKind::HmacSha256,
            zeroize::Zeroizing::new(b"0123456789abcdef0123456789abcdef".to_vec()),
            None,
            None,
        )
        .expect("registered");
    let custodian = Custodian::new(store, Box::new(whipplescript_custodian::DeniedEgress));

    let hardware = custodian.handle(&call("release_signing", "cGF5bG9hZA=="));
    assert_eq!(hardware.rung, Rung::Hardware);
    assert!(
        !hardware.degraded,
        "a key that cannot leave the chip is not a degraded rung"
    );

    let local = custodian.handle(&call("local_key", "cGF5bG9hZA=="));
    assert_eq!(
        local.rung,
        Rung::Process,
        "the r0 entry beside it is still r0"
    );
    assert!(local.degraded);
}

#[test]
fn a_tpm_credential_survives_a_store_round_trip() {
    // The binding is what the rung is judged against, so losing it across a
    // reopen would silently turn a hardware credential into a malformed entry.
    let directory = std::env::temp_dir().join(format!("whip-tpm-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("temp dir");
    let path = directory.join("store.json");

    let mut store = SealedStore::create(Some(path.clone()), "pass").expect("store");
    store
        .register_tpm(
            name("release_signing"),
            CredentialKind::HmacSha256,
            a_binding(),
            None,
            None,
        )
        .expect("registered");
    store.persist().expect("persisted");

    let reopened = SealedStore::open(&path, "pass").expect("reopened");
    let custodian = Custodian::new(reopened, Box::new(whipplescript_custodian::DeniedEgress));
    assert_eq!(
        custodian
            .handle(&call("release_signing", "cGF5bG9hZA=="))
            .rung,
        Rung::Hardware
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_tpm_credential_refuses_operations_that_need_material_on_this_box() {
    // `wrap` needs the key in this process. The refusal says why rather than
    // reporting a missing credential, which is what an operator would otherwise
    // go looking for.
    let mut store = SealedStore::create(None, "pass").expect("store");
    store
        .register_tpm(
            name("release_signing"),
            CredentialKind::HmacSha256,
            a_binding(),
            None,
            None,
        )
        .expect("registered");
    let custodian = Custodian::new(store, Box::new(whipplescript_custodian::DeniedEgress));

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
    let error = reply
        .outcome
        .expect_err("wrap needs material this box lacks");
    let said = error.to_string();
    assert!(said.contains("held in a TPM"), "{said}");
    assert!(
        said.contains("wrap"),
        "the refusal names the operation: {said}"
    );
}

/// A custodian built WITHOUT the `tpm` feature refuses a TPM entry by name.
///
/// This is the configuration the default build and the green bar are in, so it
/// is the path most likely to be taken by someone who did not expect it: a
/// store written on a TPM host, opened on one without the feature. Refusing by
/// name beats "no such credential", which sends an operator looking for a
/// registration that is perfectly fine.
#[cfg(not(feature = "tpm"))]
#[test]
fn a_custodian_without_the_feature_refuses_a_tpm_signature_by_name() {
    let mut store = SealedStore::create(None, "pass").expect("store");
    store
        .register_tpm(
            name("release_signing"),
            CredentialKind::HmacSha256,
            a_binding(),
            None,
            None,
        )
        .expect("registered");
    let custodian = Custodian::new(store, Box::new(whipplescript_custodian::DeniedEgress));

    let reply = custodian.handle(&call("release_signing", "cGF5bG9hZA=="));
    // The rung is still r2 — the entry is what it is, and this binary simply
    // cannot reach the chip that holds it.
    assert_eq!(reply.rung, Rung::Hardware);
    let error = reply
        .outcome
        .expect_err("no feature, no signature")
        .to_string();
    assert!(error.contains("built without the `tpm` feature"), "{error}");
    assert!(
        error.contains("--features tpm"),
        "and the way forward: {error}"
    );

    // VERIFY takes the same path and must say the same thing. Answering
    // `valid: false` here would report a bad signature when the truth is that
    // this binary cannot check it — the worst available answer, because it
    // reads as evidence about the signature.
    let verified = custodian.handle(&CustodyCall::new(
        UseAttribution {
            run_id: "run-1".to_owned(),
            actor: None,
            effect_key: None,
        },
        CustodyOp::Verify {
            credential: name("release_signing"),
            alg: SignatureAlg::HmacSha256,
            payload_b64: "cGF5bG9hZA==".to_owned(),
            signature_b64: "c2ln".to_owned(),
            key_version: None,
        },
    ));
    let refused = verified
        .outcome
        .expect_err("no feature, no verdict")
        .to_string();
    assert!(
        refused.contains("built without the `tpm` feature"),
        "{refused}"
    );
    assert!(
        refused.contains("--features tpm"),
        "and the way forward: {refused}"
    );
}

/// The whole of r2 through the custodian, against the real chip.
///
/// Skips with a recorded reason when no TPM is reachable, so the suite stays
/// green on a machine without one — the pattern DR-0053 §8 sets for r3's live
/// smoke, and the reason `whip doctor` would want.
#[cfg(feature = "tpm")]
#[test]
fn a_signature_from_the_chip_comes_back_through_the_custodian() {
    let mut context = match whipplescript_custodian::tpm_device::context() {
        Ok(context) => context,
        Err(reason) => {
            eprintln!("SKIP: no reachable TPM ({reason})");
            return;
        }
    };
    // The binding is read from the chip, so this is the platform state as it
    // actually is rather than a fixture that would pass anywhere.
    let binding = whipplescript_custodian::tpm_device::read_binding(&mut context, &[0, 7])
        .expect("PCRs read");
    drop(context);

    let mut store = SealedStore::create(None, "pass").expect("store");
    store
        .register_tpm(
            name("release_signing"),
            CredentialKind::HmacSha256,
            binding,
            None,
            None,
        )
        .expect("registered");
    let custodian = Custodian::new(store, Box::new(whipplescript_custodian::DeniedEgress));

    let reply = custodian.handle(&call("release_signing", "cGF5bG9hZA=="));
    assert_eq!(reply.rung, Rung::Hardware);
    let signed = reply.outcome.expect("the chip signed");
    match signed {
        whipplescript_custody::CustodyOk::Signed { signature_b64, .. } => {
            assert!(!signature_b64.is_empty());
        }
        other => panic!("expected a signature, got {other:?}"),
    }
}

/// Sign then verify, both inside the chip, with the key that never left it.
///
/// The round trip is the point: a `verify` that always answered true would pass
/// half of this, so a tampered signature and a tampered payload are checked
/// too.
#[cfg(feature = "tpm")]
#[test]
fn the_chip_verifies_what_the_chip_signed() {
    let mut context = match whipplescript_custodian::tpm_device::context() {
        Ok(context) => context,
        Err(reason) => {
            eprintln!("SKIP: no reachable TPM ({reason})");
            return;
        }
    };
    let binding = whipplescript_custodian::tpm_device::read_binding(&mut context, &[0, 7])
        .expect("PCRs read");
    drop(context);

    let mut store = SealedStore::create(None, "pass").expect("store");
    store
        .register_tpm(
            name("release_signing"),
            CredentialKind::HmacSha256,
            binding,
            None,
            None,
        )
        .expect("registered");
    let custodian = Custodian::new(store, Box::new(whipplescript_custodian::DeniedEgress));

    let signature = match custodian
        .handle(&call("release_signing", "cGF5bG9hZA=="))
        .outcome
        .expect("the chip signed")
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
        match reply.outcome.expect("the chip answered") {
            whipplescript_custody::CustodyOk::Verified { valid } => valid,
            other => panic!("expected a verdict, got {other:?}"),
        }
    };

    assert!(
        verify("cGF5bG9hZA==", &signature),
        "its own signature verifies"
    );
    // A different payload under the same signature.
    assert!(
        !verify("b3RoZXI=", &signature),
        "a different payload must not"
    );
    // The signature with one byte changed, base64-safe: flip the first char.
    let mut tampered = signature.clone();
    let first = tampered.remove(0);
    tampered.insert(0, if first == 'A' { 'B' } else { 'A' });
    assert!(
        !verify("cGF5bG9hZA==", &tampered),
        "a tampered signature must not"
    );
}

/// An asymmetric algorithm is refused by name rather than answered `false`.
///
/// Needs no chip: the rule is about the algorithm. A `valid: false` here would
/// say the signature was wrong when the truth is that this credential cannot
/// check that kind of signature at all.
#[test]
fn a_tpm_credential_refuses_an_asymmetric_verify_by_name() {
    let mut store = SealedStore::create(None, "pass").expect("store");
    store
        .register_tpm(
            name("release_signing"),
            CredentialKind::HmacSha256,
            a_binding(),
            None,
            None,
        )
        .expect("registered");
    let custodian = Custodian::new(store, Box::new(whipplescript_custodian::DeniedEgress));

    let reply = custodian.handle(&CustodyCall::new(
        UseAttribution {
            run_id: "run-1".to_owned(),
            actor: None,
            effect_key: None,
        },
        CustodyOp::Verify {
            credential: name("release_signing"),
            alg: SignatureAlg::Ed25519,
            payload_b64: "cGF5bG9hZA==".to_owned(),
            signature_b64: "c2ln".to_owned(),
            key_version: None,
        },
    ));
    let error = reply.outcome.expect_err("not a keyed hash").to_string();
    assert!(error.contains("ed25519"), "names the algorithm: {error}");
    assert!(error.contains("hmac-sha256"), "and what it can do: {error}");
}

/// A binding the platform has moved past refuses, and says what to do.
///
/// Uses a binding that is real in SHAPE but taken against a state this machine
/// is not in, which is what a firmware or kernel update leaves behind. Needs the
/// chip only to read the current state to compare against.
#[cfg(feature = "tpm")]
#[test]
fn a_platform_that_moved_refuses_rather_than_signing() {
    if whipplescript_custodian::tpm_device::context().is_err() {
        eprintln!("SKIP: no reachable TPM");
        return;
    }
    let mut store = SealedStore::create(None, "pass").expect("store");
    store
        .register_tpm(
            name("release_signing"),
            CredentialKind::HmacSha256,
            // Bound to a platform state this machine is not in.
            a_binding(),
            None,
            None,
        )
        .expect("registered");
    let custodian = Custodian::new(store, Box::new(whipplescript_custodian::DeniedEgress));

    let reply = custodian.handle(&call("release_signing", "cGF5bG9hZA=="));
    let error = reply
        .outcome
        .expect_err("a stale binding must not sign")
        .to_string();
    assert!(
        error.contains("no longer at its bound platform state"),
        "{error}"
    );
    assert!(
        error.contains("firmware or kernel update") && error.contains("re-bind"),
        "the refusal must tell an operator what happened and what to do: {error}"
    );
}

/// An entry carrying none of the three shapes is a malformed store, and says so.
///
/// Pinned because adding "or a TPM binding" to the message dragged this
/// pre-existing refusal into the sweep's scope. It is worth having: the three
/// shapes are how the custodian tells r0 from r2 from r3, and an entry with
/// none of them would otherwise be read as one of them by whichever branch
/// happened to come first.
#[test]
fn a_store_entry_with_no_material_and_no_reference_is_refused() {
    let directory = std::env::temp_dir().join(format!("whip-malformed-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("temp dir");
    let path = directory.join("store.json");

    let mut store = SealedStore::create(Some(path.clone()), "pass").expect("store");
    store
        .register_tpm(
            name("release_signing"),
            CredentialKind::HmacSha256,
            a_binding(),
            None,
            None,
        )
        .expect("registered");
    store.persist().expect("persisted");

    // Strip the binding, leaving an entry that claims to be a credential and
    // carries nothing that could make it one.
    let mut file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
    for (_, entry) in file["entries"].as_object_mut().expect("entries").iter_mut() {
        entry.as_object_mut().expect("entry").remove("tpm");
    }
    std::fs::write(&path, file.to_string()).expect("write");

    let error = SealedStore::open(&path, "pass")
        .err()
        .expect("a malformed entry is not openable")
        .to_string();
    assert!(
        error.contains("must carry sealed material, a remote reference, or a TPM binding"),
        "the refusal must name the three shapes: {error}"
    );
    assert!(
        error.contains("release/signing") || error.contains("release_signing"),
        "and which entry: {error}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}
