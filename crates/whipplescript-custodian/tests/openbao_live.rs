//! The r3 `remote` backend against a **real** OpenBao (DR-0053 §4, §8).
//!
//! This is the assertion half of `scripts/check-openbao-live-smoke.sh`; the
//! script owns the vault's lifecycle (start it, mount transit, create the
//! keys, mint a short-lease renewable token) and this file owns what must be
//! true once it is up. Nothing here is mocked — the whole point of r3 is the
//! part that only shows up against a server: OpenBao's `vault:v1:` framing,
//! its `errors` array on a refusal, and a token lease that really does run
//! out.
//!
//! It **skips** when the environment is not configured, so `cargo test
//! --workspace` stays hermetic, and **fails** once it is: a configured smoke
//! that quietly does nothing is worse than no smoke.
//!
//! Required environment (all set by the script):
//!
//! - `WHIPPLESCRIPT_OPENBAO_LIVE=1` — the gate
//! - `BAO_ADDR` / `BAO_TOKEN` — a **renewable, leased** token, not a dev root
//!   token; the renewal stage asserts on the lease
//! - `WHIPPLESCRIPT_OPENBAO_HMAC_KEY` / `WHIPPLESCRIPT_OPENBAO_ED25519_KEY` —
//!   transit key names
//! - `WHIPPLESCRIPT_OPENBAO_LIVE_REPORT` — optional report path

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use whipplescript_custodian::openbao::{spawn_token_renewal, Client, TokenPosture};
use whipplescript_custodian::store::SealedStore;
use whipplescript_custodian::{Custodian, DeniedEgress};
use whipplescript_custody::{
    CredentialKind, CredentialName, CustodyCall, CustodyError, CustodyOk, CustodyOp, CustodyReply,
    Rung, SignatureAlg, UseAttribution,
};

/// How long to let the lease burn before renewing it. Long enough that the
/// TTL visibly drops, short enough that the smoke stays under a minute.
const BURN_SECS: u64 = 3;

/// The smoke waits at most this long for the background renewal thread to
/// take its first pass. The thread renews at half the remaining lease, so the
/// script's token TTL must leave room inside this budget.
const RENEWAL_THREAD_BUDGET_SECS: u64 = 25;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn require(name: &str) -> String {
    env(name).unwrap_or_else(|| {
        panic!("{name} is required when WHIPPLESCRIPT_OPENBAO_LIVE=1 (scripts/check-openbao-live-smoke.sh sets it)")
    })
}

fn write_report(report: &serde_json::Value) {
    let Some(path) = env("WHIPPLESCRIPT_OPENBAO_LIVE_REPORT") else {
        return;
    };
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent).expect("create report directory");
    }
    std::fs::write(&path, format!("{report:#}\n")).expect("write report");
}

fn call(op: CustodyOp) -> CustodyCall {
    CustodyCall::new(
        UseAttribution {
            run_id: "openbao-live-smoke".into(),
            actor: Some("smoke".into()),
            effect_key: None,
        },
        op,
    )
}

fn expect_ok(reply: &CustodyReply) -> &CustodyOk {
    match &reply.outcome {
        Ok(ok) => ok,
        Err(e) => panic!("expected success, got {e}"),
    }
}

fn expect_err(reply: &CustodyReply) -> &CustodyError {
    match &reply.outcome {
        Ok(ok) => panic!("expected a refusal, got {ok:?}"),
        Err(e) => e,
    }
}

/// Flip a bit in the last byte, so "invalid" means invalid rather than
/// "wrong length".
fn corrupt(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    bytes
}

#[test]
fn openbao_live_smoke() {
    if env("WHIPPLESCRIPT_OPENBAO_LIVE").as_deref() != Some("1") {
        write_report(&serde_json::json!({
            "ok": true,
            "skipped": true,
            "reason": "set WHIPPLESCRIPT_OPENBAO_LIVE=1 to run the live OpenBao smoke",
        }));
        eprintln!("skipped: set WHIPPLESCRIPT_OPENBAO_LIVE=1 to run the live OpenBao smoke");
        return;
    }

    let hmac_key = require("WHIPPLESCRIPT_OPENBAO_HMAC_KEY");
    let ed25519_key = require("WHIPPLESCRIPT_OPENBAO_ED25519_KEY");
    // `from_env` is itself under test: the daemon builds its client this way,
    // and a half-configured environment must not look like an absent one.
    let client = Client::from_env()
        .expect("BAO_ADDR/BAO_TOKEN must be a usable pair")
        .expect("BAO_ADDR must be set when WHIPPLESCRIPT_OPENBAO_LIVE=1");
    let addr = client.addr().to_string();

    // -- stage: token lifecycle ---------------------------------------------
    //
    // The lease is the thing r3 gets wrong silently: a daemon that never
    // renews looks perfect until the token expires. So the smoke insists on a
    // *leased, renewable* token — a dev root token (ttl 0) would let every
    // renewal assertion below pass vacuously.

    let lookup = client.token_lookup_self().expect("token lookup-self");
    let posture = TokenPosture::from_lookup(&lookup);
    assert!(
        posture.renewable && posture.ttl_secs > 0,
        "the smoke needs a renewable leased token, got {posture:?} — a dev root token would \
         make the renewal stages vacuous"
    );
    let policies: Vec<String> = lookup["data"]["policies"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !policies.iter().any(|p| p == "root"),
        "the smoke token carries the root policy ({policies:?}); r3 is supposed to run under a \
         scoped policy, and a root token hides every ACL mistake"
    );

    std::thread::sleep(Duration::from_secs(BURN_SECS));
    let burned = TokenPosture::from_lookup(&client.token_lookup_self().expect("lookup"));
    assert!(
        burned.ttl_secs < posture.ttl_secs,
        "lease did not decrease over {BURN_SECS}s ({} -> {}); this token is not really leased",
        posture.ttl_secs,
        burned.ttl_secs
    );

    let renewed = client.token_renew_self().expect("token renew-self");
    assert!(
        renewed.renewable && renewed.ttl_secs > burned.ttl_secs,
        "renew-self did not extend the lease ({} -> {})",
        burned.ttl_secs,
        renewed.ttl_secs
    );

    // -- stage: transit sign/verify -----------------------------------------

    let payload = b"whipplescript r3 live smoke";
    let mut transit = serde_json::Map::new();
    for (label, key, kind) in [
        ("hmac-sha256", hmac_key.as_str(), CredentialKind::HmacSha256),
        ("ed25519", ed25519_key.as_str(), CredentialKind::Ed25519),
    ] {
        let signature = client
            .transit_sign(key, payload, kind)
            .unwrap_or_else(|e| panic!("{label} transit sign: {e}"));
        assert!(
            !signature.is_empty(),
            "{label} produced an empty signature — the vault:v1: framing did not parse"
        );
        assert!(
            client
                .transit_verify(key, payload, &signature, kind)
                .unwrap_or_else(|e| panic!("{label} transit verify: {e}")),
            "{label} did not verify its own signature"
        );
        // A false verdict is a *successful* call, not an error — the
        // distinction the custodian's `Verified { valid }` reply rests on.
        assert!(
            !client
                .transit_verify(key, payload, &corrupt(&signature), kind)
                .unwrap_or_else(|e| panic!("{label} transit verify (corrupt): {e}")),
            "{label} accepted a corrupted signature"
        );
        assert!(
            !client
                .transit_verify(key, b"a different payload", &signature, kind)
                .unwrap_or_else(|e| panic!("{label} transit verify (wrong payload): {e}")),
            "{label} accepted a signature over a different payload"
        );
        transit.insert(
            label.to_string(),
            serde_json::json!({ "key": key, "signatureBytes": signature.len() }),
        );
    }

    // A kind transit cannot serve refuses by name rather than falling back to
    // anything local.
    let refused = client
        .transit_sign(&hmac_key, payload, CredentialKind::Bearer)
        .expect_err("bearer must not sign remotely");
    assert!(refused.contains("does not sign for kind"), "{refused}");

    // -- stage: error mapping against the real server ------------------------
    //
    // `read_response`'s unit tests pin the mapping against synthesized
    // bodies. This pins that OpenBao really does answer in that shape.

    let missing = client
        .transit_sign(
            "whip-smoke-no-such-key",
            payload,
            CredentialKind::HmacSha256,
        )
        .expect_err("a missing transit key must fail");
    assert!(
        missing.starts_with("openbao returned "),
        "a non-2xx from OpenBao lost its status: {missing}"
    );
    let bad_token = Client::new(&addr, "definitely-not-a-valid-token")
        .token_lookup_self()
        .expect_err("a bad token must fail");
    assert!(
        bad_token.contains("403") && bad_token.contains("permission denied"),
        "a 403 lost OpenBao's errors array: {bad_token}"
    );

    // -- stage: the renewal thread ------------------------------------------
    //
    // Not just `token_renew_self` — the loop `whip-custodian serve` starts,
    // renewing off the lease OpenBao reports. Proof is a TTL that goes back
    // *up* while nothing else touches the token.

    let client = Arc::new(client);
    let before = TokenPosture::from_lookup(&client.token_lookup_self().expect("lookup"));
    let handle = spawn_token_renewal(Arc::clone(&client), before)
        .expect("a renewable leased token must start a renewal thread");
    let started = Instant::now();
    let mut lowest = before.ttl_secs;
    let renewal_observed = loop {
        if started.elapsed() > Duration::from_secs(RENEWAL_THREAD_BUDGET_SECS) {
            break false;
        }
        std::thread::sleep(Duration::from_secs(1));
        let now = TokenPosture::from_lookup(&client.token_lookup_self().expect("lookup"));
        // The lease decays every second, so a rise can only be a renewal.
        if now.ttl_secs > lowest {
            break true;
        }
        lowest = lowest.min(now.ttl_secs);
    };
    assert!(
        renewal_observed,
        "the renewal thread did not extend the lease within {RENEWAL_THREAD_BUDGET_SECS}s \
         (lease fell to {lowest}s from {}s); a daemon holding this token would expire",
        before.ttl_secs
    );
    assert!(!handle.is_finished(), "the renewal thread exited early");

    // -- stage: the custodian's r3 dispatch ----------------------------------
    //
    // Everything above drives the client directly. This drives the path whip
    // actually uses: a store entry whose material is a transit *key name*,
    // through `Custodian::handle`.

    let credential = CredentialName::new("smoke/remote-hmac").expect("valid name");
    let mut store = SealedStore::create(None, "openbao-live-smoke").expect("create store");
    store
        .register_remote(
            credential.clone(),
            CredentialKind::HmacSha256,
            hmac_key.clone(),
            None,
        )
        .expect("register remote");
    let custodian = Custodian::new(store, Box::new(DeniedEgress)).with_openbao(Arc::clone(&client));

    let signed = custodian.handle(&call(CustodyOp::Sign {
        credential: credential.clone(),
        alg: SignatureAlg::HmacSha256,
        derivation: Vec::new(),
        payload_b64: B64.encode(payload),
    }));
    // The rung is per-entry evidence: this material never existed on this
    // box, so it is r3 and not degraded — unlike the r0 floor the same
    // custodian reports for local entries.
    assert_eq!(signed.rung, Rung::Remote);
    assert!(!signed.degraded, "an r3 entry must not report degraded");
    let CustodyOk::Signed { signature_b64 } = expect_ok(&signed) else {
        panic!("expected a signature, got {:?}", signed.outcome);
    };

    let verified = custodian.handle(&call(CustodyOp::Verify {
        credential: credential.clone(),
        alg: SignatureAlg::HmacSha256,
        payload_b64: B64.encode(payload),
        signature_b64: signature_b64.clone(),
    }));
    assert_eq!(verified.rung, Rung::Remote);
    assert_eq!(
        expect_ok(&verified),
        &CustodyOk::Verified { valid: true },
        "the custodian did not verify its own remote signature"
    );

    // The operations that would need the material *here* are exactly what r3
    // exists to prevent, and they refuse rather than silently degrading to a
    // local key.
    let derived = custodian.handle(&call(CustodyOp::Derive {
        credential: credential.clone(),
        context: "smoke".into(),
    }));
    assert!(
        matches!(expect_err(&derived), CustodyError::Backend { .. }),
        "derive on a remote entry must refuse, got {:?}",
        derived.outcome
    );

    // A derivation chain folds HMAC over the raw key, which never leaves the
    // transit engine — refused rather than approximated.
    let chained = custodian.handle(&call(CustodyOp::Sign {
        credential,
        alg: SignatureAlg::HmacSha256,
        derivation: vec!["20260806".into(), "us-east-1".into()],
        payload_b64: B64.encode(payload),
    }));
    assert!(
        matches!(expect_err(&chained), CustodyError::Backend { .. }),
        "a derivation chain on a remote entry must refuse, got {:?}",
        chained.outcome
    );

    write_report(&serde_json::json!({
        "ok": true,
        "skipped": false,
        "addr": addr,
        "token": {
            "policies": policies,
            "leaseSecsAtStart": posture.ttl_secs,
            "leaseSecsAfterBurn": burned.ttl_secs,
            "leaseSecsAfterRenew": renewed.ttl_secs,
            "backgroundRenewalObserved": renewal_observed,
        },
        "transit": transit,
        "custodian": {
            "rung": "remote",
            "degraded": false,
            "remoteSignVerifyRoundtrip": true,
            "deriveRefused": true,
            "derivationChainRefused": true,
        },
    }));
}
