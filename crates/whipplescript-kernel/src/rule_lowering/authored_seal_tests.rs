use crate::{
    effect_config::EffectConfig,
    effect_handlers::{
        run_capability_effect_generic, run_custody_capability, CapabilityContract,
        CapabilityOutcome, CapabilityProvider,
    },
    rule_pass::step_instance_generic,
    ProgramVersionInput, RuntimeKernel,
};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    sync::Arc,
};
use whipplescript_custodian::{store::SealedStore, Custodian, DeniedEgress, InProcessTransport};
use whipplescript_custody::{
    CredentialKind, CredentialName, CustodyCall, CustodyOk, CustodyOp, CustodyTransport, Envelope,
    UseAttribution,
};
use whipplescript_parser::{compile_program, IrProgram};
use whipplescript_store::{
    native_stores::NativeStores, CapabilityBinding, CapabilitySchemaRegistration, ClaimableEffect,
    RuntimeStore,
};

fn source(continuation: &str) -> String {
    format!(
        r#"
use std.custody
@service
workflow AuthoredSeal
class Payload {{ notes string }}
class Claim {{ id string rec Payload }}
class Stored {{ id string body sealed<Payload> }}
class Receipt {{ notes string }}
credential phi_key {{ kind raw }}
@external
rule keep
  when Claim as claim
=> {{
  seal claim.rec with phi_key as sealing
  after sealing succeeds as envelope {{
    {continuation}
  }}
}}
"#
    )
}

struct Provider {
    transport: InProcessTransport,
    calls: AtomicUsize,
}
impl CapabilityProvider for Provider {
    fn produce(&self, effect: &ClaimableEffect, _: &EffectConfig) -> CapabilityOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        run_custody_capability(&self.transport, effect, &effect.effect_id)
    }
    fn label(&self) -> &'static str {
        "custody-provider"
    }
}
struct EnvelopeContract;
impl CapabilityContract for EnvelopeContract {
    fn validate_output(&self, effect: &ClaimableEffect, value: &Value) -> Option<String> {
        if effect.target.as_deref() == Some("custody.wrap") && Envelope::recognize(value).is_none()
        {
            Some("actual custodian envelope required".to_owned())
        } else {
            None
        }
    }
}
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    kernel: RuntimeKernel<NativeStores>,
    ir: IrProgram,
    instance: String,
    dir: PathBuf,
    provider: Provider,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
impl Fixture {
    fn new(continuation: &str, binding: bool, credential: bool) -> Self {
        Self::from_source(source(continuation), binding, credential)
    }

    fn from_source(source: String, binding: bool, credential: bool) -> Self {
        let compiled = compile_program(&source);
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let ir = compiled.ir.expect("compiled authored program");
        let dir = std::env::temp_dir().join(format!(
            "whip-authored-seal-{}-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::SeqCst),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("own fixture dir");
        let stores = NativeStores::open(
            dir.join("runtime.sqlite"),
            dir.join("coord.sqlite"),
            dir.join("items.sqlite"),
        )
        .expect("actual native stores");
        let mut kernel = RuntimeKernel::new(stores);
        for capability in ["custody.wrap", "custody.unwrap"] {
            kernel
                .store_mut()
                .register_capability_schema(CapabilitySchemaRegistration {
                    capability,
                    description: "owned synthetic custodian",
                    schema_json: "{}",
                    registered_by_package_id: None,
                })
                .expect("host capability schema");
            if binding {
                kernel
                    .store_mut()
                    .bind_capability(CapabilityBinding {
                        binding_id: capability,
                        program_id: None,
                        capability,
                        provider: "custody-provider",
                        config_json: "{}",
                    })
                    .expect("host's ordinary capability binding");
            }
        }
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: &ir.workflow,
                source_hash: &crate::idempotency_key(&[&source]),
                ir_hash: &crate::idempotency_key(&[&serde_json::to_string(&ir).expect("ir json")]),
                compiler_version: "owned-conformance",
                ir_snapshot: None,
            })
            .expect("retained version");
        let instance = kernel
            .create_instance(&version, "{}")
            .expect("ordinary instance");
        kernel
            .ingest_external_event(&instance, "external.started", "{}", Some("start"))
            .expect("ordinary start");
        kernel
            .derive_fact(
                &instance,
                "Claim",
                "claim-1",
                &json!({"id":"claim-1", "rec":{"notes":"synthetic application value"}}).to_string(),
                None,
                Some("claim-1"),
            )
            .expect("application input fact");
        let mut sealed = SealedStore::create(None, "owned-fixture-password")
            .expect("actual sealed custody store");
        if credential {
            sealed
                .register(
                    CredentialName::new("phi_key").expect("credential name"),
                    CredentialKind::Raw,
                    zeroize::Zeroizing::new(vec![7u8; 32]),
                    None,
                    None,
                )
                .expect("owned synthetic key");
        }
        let transport =
            InProcessTransport::new(Arc::new(Custodian::new(sealed, Box::new(DeniedEgress))));
        Self {
            kernel,
            ir,
            instance,
            dir,
            provider: Provider {
                transport,
                calls: AtomicUsize::new(0),
            },
        }
    }
    fn step(&mut self) {
        step_instance_generic(&mut self.kernel, &self.instance, &self.ir, None, None)
            .expect("ordinary rule pass");
    }
    fn run(&mut self, target: &str) -> String {
        let effects = self
            .kernel
            .claimable_effects(&self.instance)
            .expect("actual claimable effects");
        let effect = effects
            .into_iter()
            .find(|effect| effect.target.as_deref() == Some(target))
            .expect("authored construct must enqueue the actual capability");
        let config = EffectConfig {
            provider: "custody-provider".to_owned(),
            ..EffectConfig::default()
        };
        run_capability_effect_generic(
            &mut self.kernel,
            &self.instance,
            &effect,
            &config,
            &EnvelopeContract,
            &self.provider,
        )
        .expect("ordinary admitted capability run/settlement");
        effect.effect_id
    }
    fn stored(&self) -> Vec<Value> {
        self.kernel
            .store()
            .list_facts(&self.instance)
            .expect("facts")
            .into_iter()
            .filter(|f| f.name == "Stored")
            .map(|f| serde_json::from_str(&f.value_json).expect("stored json"))
            .collect()
    }
}

#[test]
fn authored_seal_queues_wrap_and_real_custodian_settles_its_continuation() {
    let mut f = Fixture::new("record Stored { id claim.id body envelope }", true, true);
    f.step();
    let effects = f.kernel.claimable_effects(&f.instance).expect("claimable");
    assert_eq!(effects.len(), 1);
    let input: Value = serde_json::from_str(&effects[0].input_json).expect("input");
    assert_eq!(input["credential"], "phi_key");
    assert_eq!(
        input["value"],
        json!({"notes":"synthetic application value"})
    );
    assert!(input.get("bindings").is_none());
    let effect_id = f.run("custody.wrap");
    f.step();
    let stored = f.stored();
    assert_eq!(stored.len(), 1);
    let envelope: Envelope =
        serde_json::from_value(stored[0]["body"].clone()).expect("actual custodian envelope");
    assert_eq!(envelope.context, effect_id);
    let reply = f
        .provider
        .transport
        .call(CustodyCall::new(
            UseAttribution {
                run_id: "verify-own-fixture".to_owned(),
                actor: None,
                effect_key: Some(effect_id.clone()),
            },
            CustodyOp::Unwrap {
                credential: CredentialName::new("phi_key").expect("key"),
                context: effect_id,
                envelope,
            },
        ))
        .expect("actual crypto unwrap");
    let CustodyOk::Unwrapped { plaintext_b64, .. } = reply.outcome.expect("unwrap result") else {
        panic!("actual plaintext response required")
    };
    let bytes = crate::exec_http::base64_decode(&plaintext_b64).expect("base64");
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).expect("plaintext json"),
        input["value"]
    );
    let events = f.kernel.store().list_events(&f.instance).expect("events");
    f.step();
    assert_eq!(f.stored(), stored);
    assert_eq!(
        f.kernel.store().list_events(&f.instance).expect("events"),
        events
    );
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn authored_seal_missing_custodian_credential_settles_failure_without_success() {
    let mut f = Fixture::new("record Stored { id claim.id body envelope }", true, false);
    f.step();
    f.run("custody.wrap");
    f.step();
    assert!(f.stored().is_empty());
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 1);
    let effects = f.kernel.store().list_effects(&f.instance).expect("effects");
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].status, "failed");
}

#[test]
fn authored_seal_without_current_host_capability_binding_never_dispatches() {
    let mut f = Fixture::new("record Stored { id claim.id body envelope }", true, true);
    f.step();
    let sql = rusqlite::Connection::open(f.dir.join("runtime.sqlite")).expect("own actual runtime");
    let removed = sql
        .execute(
            "DELETE FROM capability_bindings WHERE capability = 'custody.wrap'",
            [],
        )
        .expect("revoke actual fixture host binding");
    assert!(
        removed > 0,
        "absence comes from an actual current binding removal"
    );
    assert!(f
        .kernel
        .claimable_effects(&f.instance)
        .expect("claimable")
        .is_empty());
    assert!(f.stored().is_empty());
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 0);
    let effects = f.kernel.store().list_effects(&f.instance).expect("effects");
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].status, "blocked_by_capability");
    f.kernel
        .store_mut()
        .bind_capability(CapabilityBinding {
            binding_id: "restored-custody-wrap",
            program_id: None,
            capability: "custody.wrap",
            provider: "custody-provider",
            config_json: "{}",
        })
        .expect("restore fixture's same ordinary host binding");
    f.run("custody.wrap");
    f.step();
    assert_eq!(f.stored().len(), 1);
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn authored_seal_multiline_connectives_are_not_silently_dropped() {
    let source = source("record Stored { id claim.id body envelope }").replace(
        "seal claim.rec with phi_key as sealing",
        "seal claim.rec\n  with phi_key\n  as sealing",
    );
    let mut f = Fixture::from_source(source, true, true);
    f.step();
    let effects = f.kernel.claimable_effects(&f.instance).expect("claimable");
    assert_eq!(
        effects.len(),
        1,
        "valid authored seal must lower despite newline layout"
    );
    let input: Value = serde_json::from_str(&effects[0].input_json).expect("input");
    assert_eq!(
        input["value"],
        json!({"notes":"synthetic application value"})
    );
    f.run("custody.wrap");
    f.step();
    assert_eq!(f.stored().len(), 1);
}

#[test]
fn authored_ordinary_seal_refuses_opened_alias_contexts_including_public_values() {
    let confined = source("open envelope into Payload with phi_key as opening\n after opening succeeds as patient {\n seal patient with phi_key as resealing\n }");
    let checked = compile_program(&confined);
    assert!(
        checked
            .diagnostics
            .iter()
            .any(|d| d.code.as_str() == "security.confinement_crossing"),
        "direct plaintext is already rejected by the compiler: {:?}",
        checked.diagnostics
    );
    for value in ["\"public constant\"", "receipt"] {
        let prefix = if value == "receipt" {
            "declassify patient into Receipt as receipt"
        } else {
            ""
        };
        let continuation=format!("open envelope into Payload with phi_key as opening\n after opening succeeds as patient {{\n {prefix}\n seal {value} with phi_key as resealing\n }}");
        let mut f = Fixture::new(&continuation, true, true);
        f.step();
        f.run("custody.wrap");
        f.step();
        f.run("custody.unwrap");
        let before = f.kernel.store().list_effects(&f.instance).expect("effects");
        let error = step_instance_generic(&mut f.kernel, &f.instance, &f.ir, None, None)
            .expect_err("unsupported in-region producer must refuse before publication");
        assert!(
            matches!(&error, whipplescript_store::StoreError::Conflict(message) if message.contains("in-region seal requires envelope-identity derivation")),
            "{error:?}"
        );
        assert_eq!(
            f.kernel.store().list_effects(&f.instance).expect("effects"),
            before,
            "in-region seal must not publish resolved plaintext or public values pending WS345"
        );
        assert!(f
            .kernel
            .claimable_effects(&f.instance)
            .expect("claimable")
            .is_empty());
        assert_eq!(f.provider.calls.load(Ordering::SeqCst), 2);
    }
}

#[test]
fn authored_seal_quoted_connectives_and_following_effect_keep_exact_slots() {
    for text in [
        "literal with connective",
        "literal as binding",
        "literal with and as text",
    ] {
        let authored = source("record Receipt { notes \"done\" }").replace(
            "seal claim.rec with phi_key as sealing",
            &format!(
                "seal {}\n with phi_key\n as sealing\n seal claim.rec with phi_key as second",
                serde_json::to_string(text).expect("quoted payload")
            ),
        );
        let mut f = Fixture::from_source(authored, true, true);
        f.step();
        let effects = f.kernel.claimable_effects(&f.instance).expect("claimable");
        assert_eq!(
            effects.len(),
            2,
            "both actual authored effects must survive"
        );
        let values: Vec<Value> = effects
            .iter()
            .map(|effect| {
                serde_json::from_str::<Value>(&effect.input_json).expect("input")["value"].clone()
            })
            .collect();
        assert!(
            values.contains(&json!(text)),
            "quoted value must remain exact: {values:?}"
        );
        assert!(
            values.contains(&json!({"notes":"synthetic application value"})),
            "following effect must remain separate"
        );
        f.run("custody.wrap");
        f.run("custody.wrap");
        f.step();
        assert_eq!(
            f.kernel
                .store()
                .list_facts(&f.instance)
                .expect("facts")
                .iter()
                .filter(|fact| fact.name == "Receipt")
                .count(),
            1,
            "real seal binding must resume its own continuation"
        );
    }
}

#[test]
fn authored_seal_quoted_comparison_seals_the_evaluated_boolean() {
    let authored = source("record Stored { id claim.id body envelope }").replace(
        "seal claim.rec with phi_key as sealing",
        "seal \"left\" == \"right\" with phi_key as sealing",
    );
    let mut f = Fixture::from_source(authored, true, true);
    f.step();
    let effect_id = f.run("custody.wrap");
    f.step();
    let envelope: Envelope =
        serde_json::from_value(f.stored()[0]["body"].clone()).expect("actual envelope");
    let reply = f
        .provider
        .transport
        .call(CustodyCall::new(
            UseAttribution {
                run_id: "comparison-oracle".to_owned(),
                actor: None,
                effect_key: Some(effect_id.clone()),
            },
            CustodyOp::Unwrap {
                credential: CredentialName::new("phi_key").expect("key"),
                context: effect_id,
                envelope,
            },
        ))
        .expect("actual unwrap");
    let CustodyOk::Unwrapped { plaintext_b64, .. } = reply.outcome.expect("unwrap result") else {
        panic!("unwrap required")
    };
    let bytes = crate::exec_http::base64_decode(&plaintext_b64).expect("base64");
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).expect("plaintext JSON"),
        json!(false),
        "compiler-supported equality must seal its evaluated boolean"
    );
}
