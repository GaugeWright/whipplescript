//! The plaintext slot an `open` returns into (DR-0074 §3, amended 2026-08-30).
//!
//! `open` is an effect, and an effect's output ordinarily reaches its `after`
//! block through its terminal fact — `rule_lowering::effect_binding_value`
//! resolves every `after` binding out of `facts.value_json`. For `open` that
//! channel is exactly the §4 violation: plaintext in a durable record. So the
//! custody provider settles an open with the envelope's IDENTITY (the manifest's
//! `custody.unwrap` output schema: credential, context, payload type) and puts
//! the plaintext here, keyed by the open's effect id. The rule lowering binds the
//! `after … as <alias>` of a settled open from this slot and nowhere else.
//!
//! **How long an entry lives.** The amendment says "one pass", because under
//! DR-0083 a settled rule firing is not re-lowered. The bound that matters is the
//! firing's, not the pass's: a firing whose continuation enqueues a further
//! effect stays open, and is re-lowered — its whole body, the open's `after`
//! block included — when that effect settles. Re-lowering it without the
//! plaintext would re-derive the region differently (a `case` on the plaintext
//! selecting another arm, a `declassify` producing another value) and commit
//! the difference. So an entry is held until the firing that owns the open
//! CLOSES by completion, which `rule_pass` reports through [`release`]. For the
//! common region — open, declassify, record — that is the round after the one
//! that lowers the continuation. A firing that never closes by completion — one
//! inside a DR-0043 `region`, or one an operator cancelled — keeps its entry for
//! the life of the process; that is memory, bounded by the opens performed, and
//! never a record.
//!
//! **What it is not.** It is process memory, never a record: no store sees it,
//! and nothing here survives the process. A pass that needs an entry this
//! process does not hold — the open settled in another process, or before a
//! restart — refuses to lower the region rather than binding the identity the
//! checker types as the payload. Whether that case re-executes the open or
//! commits settlement and continuation together is DR-0074's open restart
//! question, and this module does not answer it.
//!
//! The one way out of the slot is [`opened`], which is crate-private and whose
//! callers bind the value into a lowering context and nothing else.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use serde_json::Value;

/// The capability an `open` lowers to. Named once so the provider that fills
/// the slot and the lowering that reads it cannot disagree about which settled
/// facts are opens.
pub const OPEN_CAPABILITY: &str = "custody.unwrap";

/// The provenance class a lowering context gives a binding that holds opened
/// plaintext — the alias, and anything `redact` derives from it — so the
/// lowering's durable dumps (an effect's `bindings`) can leave it out.
pub const OPENED_PROVENANCE: &str = "opened";

/// One open's plaintext. Deliberately not `Clone`, `Serialize` or `Display`,
/// and its `Debug` prints nothing of the value: something eventually formats a
/// struct that holds one, and a `{:?}` that printed plaintext into a log would
/// be a §4 violation nobody had to write deliberately.
struct HeldPlaintext(Value);

impl std::fmt::Debug for HeldPlaintext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HeldPlaintext(<opened>)")
    }
}

fn slots() -> &'static Mutex<BTreeMap<String, HeldPlaintext>> {
    static SLOTS: OnceLock<Mutex<BTreeMap<String, HeldPlaintext>>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn with_slots<T>(f: impl FnOnce(&mut BTreeMap<String, HeldPlaintext>) -> T) -> T {
    // A poisoned lock means a panic elsewhere while holding it; the map itself
    // is still consistent (every operation is a single insert/get/remove), so
    // recover it rather than turning one panic into a refusal of every open.
    let mut guard = slots()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

/// Hold an open's plaintext for the firing that owns it. Called by the custody
/// provider when the custodian answers, before the terminal is recorded.
pub fn hold(effect_id: &str, plaintext: Value) {
    with_slots(|slots| {
        slots.insert(effect_id.to_owned(), HeldPlaintext(plaintext));
    });
}

/// The plaintext of a settled open, if this process holds it.
pub(crate) fn opened(effect_id: &str) -> Option<Value> {
    with_slots(|slots| slots.get(effect_id).map(|held| held.0.clone()))
}

/// Whether this process holds the plaintext of `effect_id`.
pub fn is_held(effect_id: &str) -> bool {
    with_slots(|slots| slots.contains_key(effect_id))
}

/// Drop the plaintext of every listed effect that is an open this process
/// holds. `rule_pass` calls this with a firing's effect ids when the firing
/// closes by completion, which is the last moment anything could re-lower the
/// open's region.
pub fn release<'a>(effect_ids: impl IntoIterator<Item = &'a String>) {
    with_slots(|slots| {
        for effect_id in effect_ids {
            slots.remove(effect_id);
        }
    });
}

/// Whether `facts` holds the SUCCESSFUL settlement of the open `effect_id` —
/// the case whose `after … as <alias>` binds plaintext. A failed, timed-out or
/// cancelled open binds what any failed effect binds, and nothing here.
pub(crate) fn is_settled_open(facts: &[whipplescript_store::FactView], effect_id: &str) -> bool {
    facts.iter().any(|fact| {
        if fact.name != "capability.call.succeeded" {
            return false;
        }
        let Ok(payload) = serde_json::from_str::<Value>(&fact.value_json) else {
            return false;
        };
        payload.get("effect_id").and_then(Value::as_str) == Some(effect_id)
            && payload.get("target").and_then(Value::as_str) == Some(OPEN_CAPABILITY)
            && payload.get("status").and_then(Value::as_str) == Some("completed")
    })
}

/// The value an `after <open> succeeds|completes as <alias>` binds to its alias:
/// the plaintext, from the slot. `binding_value` is what the durable fact gave —
/// the envelope's identity — and is what every other binding of the open keeps.
///
/// `Err` when the open settled but this process does not hold its plaintext.
/// Binding the identity there instead would be the lie DR-0074 §3 refused: the
/// checker types the alias at the `into <Type>` class, so its fields would read
/// null with nothing reporting it.
pub(crate) fn alias_value(
    facts: &[whipplescript_store::FactView],
    effect_id: &str,
    predicate: &str,
    binding_value: &Value,
) -> Result<Option<Value>, String> {
    if !matches!(predicate, "succeeds" | "completes") || !is_settled_open(facts, effect_id) {
        return Ok(None);
    }
    let Some(plaintext) = opened(effect_id) else {
        return Err(format!(
            "`open` effect {effect_id} settled, but this process does not hold its plaintext: \
             an open's result is never written to a record (DR-0074 §3), so it reaches its \
             region only in the process that opened it, and it settled in another process or \
             before a restart. Refusing to lower the region rather than binding the envelope's \
             identity as its payload; re-executing the open after a restart is not yet ruled"
        ));
    };
    if predicate == "succeeds" {
        return Ok(Some(plaintext));
    }
    let mut union = binding_value.clone();
    if let Some(object) = union.as_object_mut() {
        object.insert("value".to_owned(), plaintext);
    }
    Ok(Some(union))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_value_is_never_formatted() {
        let held = HeldPlaintext(serde_json::json!({ "notes": "chest pain" }));
        assert_eq!(format!("{held:?}"), "HeldPlaintext(<opened>)");
    }

    #[test]
    fn release_drops_only_the_named_effects() {
        hold("opened-plaintext-test-a", Value::from(1));
        hold("opened-plaintext-test-b", Value::from(2));
        release([&"opened-plaintext-test-a".to_owned()]);
        assert!(!is_held("opened-plaintext-test-a"));
        assert_eq!(opened("opened-plaintext-test-b"), Some(Value::from(2)));
        release([&"opened-plaintext-test-b".to_owned()]);
    }
}

/// The region end to end: seal through a real custodian, open in a rule, and
/// let the region's `declassify` carry a bounded value out into a record.
#[cfg(test)]
mod region_tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use serde_json::{json, Value};
    use whipplescript_custodian::store::SealedStore;
    use whipplescript_custodian::{Custodian, DeniedEgress, InProcessTransport};
    use whipplescript_custody::{CredentialKind, CredentialName};
    use whipplescript_parser::compile_program;
    use whipplescript_store::native_stores::NativeStores;
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, ClaimableEffect, RuntimeStore,
    };

    use crate::effect_config::EffectConfig;
    use crate::effect_handlers::{
        run_capability_effect_generic, run_custody_capability, CapabilityContract,
        CapabilityOutcome, CapabilityProvider,
    };
    use crate::rule_pass::step_instance_generic;
    use crate::{ProgramVersionInput, RuntimeKernel};

    /// What the plaintext says. Nothing durable may contain it.
    const SECRET_NOTES: &str = "confined-notes-7f3a";

    fn source(workflow: &str, region: &str) -> String {
        format!(
            r#"
use std.custody
use std.agent
@service
workflow {workflow}

agent triager {{
  provider owned
  profile "repo-writer"
  capacity 1
}}

class PatientRecord {{
  notes string
  severity int
  urgency "routine" | "urgent"
}}

class Receipt {{
  severity int
}}

class Claim {{
  id string
  body sealed<PatientRecord>
}}

class Triaged {{
  id string
  severity int
}}

credential phi_key {{ kind raw }}

@external
rule triage
  when Claim as claim
=> {{
  open claim.body into PatientRecord with phi_key as opening
  after opening succeeds as patient {{
{region}
  }}
}}
"#
        )
    }

    fn custodian() -> InProcessTransport {
        let mut store = SealedStore::create(None, "pw").expect("store");
        store
            .register(
                CredentialName::new("phi_key").expect("name"),
                CredentialKind::Raw,
                zeroize::Zeroizing::new(vec![7u8; 32]),
                None,
                None,
            )
            .expect("register");
        InProcessTransport::new(Arc::new(Custodian::new(store, Box::new(DeniedEgress))))
    }

    fn sealed(transport: &InProcessTransport) -> Value {
        let effect = ClaimableEffect {
            attempt_admission_event_id: None,
            effect_id: "seal-for-region-test".to_owned(),
            kind: "capability.call".to_owned(),
            target: Some("custody.wrap".to_owned()),
            profile: None,
            input_json: json!({
                "credential": "phi_key",
                "value": { "notes": SECRET_NOTES, "severity": 3, "urgency": "urgent" },
            })
            .to_string(),
            required_capabilities_json: "[]".to_owned(),
            declared_profiles_json: "[]".to_owned(),
        };
        let CapabilityOutcome::Produced(envelope) =
            run_custody_capability(transport, &effect, "run-seal")
        else {
            panic!("sealing failed");
        };
        envelope
    }

    struct Custody<'a>(&'a InProcessTransport);

    impl CapabilityProvider for Custody<'_> {
        fn produce(&self, effect: &ClaimableEffect, _config: &EffectConfig) -> CapabilityOutcome {
            run_custody_capability(self.0, effect, &effect.effect_id)
        }

        fn label(&self) -> &'static str {
            "custody-provider"
        }
    }

    struct NoContract;

    impl CapabilityContract for NoContract {
        fn validate_output(&self, _effect: &ClaimableEffect, _value: &Value) -> Option<String> {
            None
        }
    }

    struct Region {
        kernel: RuntimeKernel<NativeStores>,
        ir: whipplescript_parser::IrProgram,
        instance_id: String,
        dir: PathBuf,
        transport: InProcessTransport,
    }

    impl Drop for Region {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Region {
        fn new(workflow: &str, region: &str) -> Self {
            let compiled = compile_program(&source(workflow, region));
            assert_eq!(compiled.diagnostics, Vec::new());
            let ir = compiled.ir.expect("ir");
            let dir = std::env::temp_dir().join(format!(
                "whip-open-region-{workflow}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_nanos())
                    .unwrap_or_default()
            ));
            std::fs::create_dir_all(&dir).expect("dir");
            let stores = NativeStores::open(
                dir.join("runtime.sqlite"),
                dir.join("coord.sqlite"),
                dir.join("items.sqlite"),
            )
            .expect("stores");
            let mut kernel = RuntimeKernel::new(stores);
            // What the std.custody manifest registers on a real host.
            kernel
                .store_mut()
                .register_capability_schema(CapabilitySchemaRegistration {
                    capability: super::OPEN_CAPABILITY,
                    description: "open a custodian-held envelope",
                    schema_json: "{}",
                    registered_by_package_id: None,
                })
                .expect("capability");
            kernel
                .store_mut()
                .bind_capability(CapabilityBinding {
                    binding_id: "binding-custody-unwrap-global",
                    program_id: None,
                    capability: super::OPEN_CAPABILITY,
                    provider: "custody-provider",
                    config_json: "{}",
                })
                .expect("binding");
            let version = kernel
                .create_program_version(ProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: "source",
                    ir_hash: "ir",
                    compiler_version: "test",
                    ir_snapshot: None,
                })
                .expect("version");
            let instance_id = kernel.create_instance(&version, "{}").expect("instance");
            kernel
                .ingest_external_event(&instance_id, "external.started", "{}", Some("start"))
                .expect("start");
            let transport = custodian();
            let envelope = sealed(&transport);
            kernel
                .derive_fact(
                    &instance_id,
                    "Claim",
                    "claim-1",
                    &json!({ "id": "claim-1", "body": envelope }).to_string(),
                    None,
                    Some("claim-1"),
                )
                .expect("claim");
            Self {
                kernel,
                ir,
                instance_id,
                dir,
                transport,
            }
        }

        fn step(
            &mut self,
        ) -> Result<crate::rule_pass::StepReport, whipplescript_store::StoreError> {
            step_instance_generic(&mut self.kernel, &self.instance_id, &self.ir, None, None)
        }

        /// Run the one queued open and return its effect id.
        fn open(&mut self) -> String {
            let effect = self
                .kernel
                .claimable_effects(&self.instance_id)
                .expect("claimable")
                .into_iter()
                .find(|effect| effect.target.as_deref() == Some(super::OPEN_CAPABILITY))
                .expect("the rule queued an open");
            let transport = std::mem::replace(&mut self.transport, custodian());
            run_capability_effect_generic(
                &mut self.kernel,
                &self.instance_id,
                &effect,
                &EffectConfig::default(),
                &NoContract,
                &Custody(&transport),
            )
            .expect("open settles");
            effect.effect_id
        }

        fn facts_named(&self, name: &str) -> Vec<Value> {
            self.kernel
                .store()
                .list_facts(&self.instance_id)
                .expect("facts")
                .into_iter()
                .filter(|fact| fact.name == name)
                .map(|fact| serde_json::from_str(&fact.value_json).expect("json"))
                .collect()
        }

        /// Every byte the stores wrote, WAL included: §4 is about records,
        /// and this is all of them rather than the tables a test thought of.
        fn durable_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::new();
            for entry in std::fs::read_dir(&self.dir).expect("dir") {
                bytes.extend(std::fs::read(entry.expect("entry").path()).expect("read"));
            }
            bytes
        }
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    #[test]
    fn a_region_reads_its_plaintext_and_no_record_holds_it() {
        let mut region = Region::new(
            "OpenRegionDeclassify",
            "    declassify patient into Receipt as receipt\n    \
             record Triaged { id claim.id  severity receipt.severity }",
        );
        region.step().expect("the claim fires the rule");
        let open = region.open();

        // The settled open records the envelope's identity, never its payload.
        let settled = region.facts_named("capability.call.succeeded");
        let value = &settled
            .iter()
            .find(|fact| fact["effect_id"] == open.as_str())
            .expect("the open settled")["value"];
        assert_eq!(value["credential"], "phi_key");
        assert_eq!(value["payload_type"], "PatientRecord");
        assert!(value.get("notes").is_none(), "{value}");

        region.step().expect("the region lowers");
        let triaged = region.facts_named("Triaged");
        assert_eq!(triaged, vec![json!({ "id": "claim-1", "severity": 3 })]);

        // The firing closed in the round after its continuation committed, and
        // that ends the plaintext's life.
        assert!(
            !super::is_held(&open),
            "a closed firing's plaintext is released"
        );
        region.step().expect("a later pass is quiet");
        assert_eq!(region.facts_named("Triaged").len(), 1);

        let bytes = region.durable_bytes();
        assert!(!bytes.is_empty());
        assert!(
            !contains(&bytes, SECRET_NOTES),
            "opened plaintext reached a durable record"
        );
    }

    #[test]
    fn an_effect_in_a_region_carries_the_released_value_and_not_the_plaintext() {
        // Every effect's input is durable, and the lowering writes the bindings
        // in scope into it. The parser refuses an effect that NAMES the
        // plaintext; this is the effect that does not, in a region that also
        // branches on the plaintext.
        let mut region = Region::new(
            "OpenRegionEffect",
            "    declassify patient into Receipt as receipt\n    \
             tell triager \"Severity {{ receipt.severity }}\" as note\n    \
             case patient.urgency {\n      \
               \"routine\" => {\n        \
                 record Triaged { id \"none\"  severity 0 }\n      \
               }\n      \
               _ => {\n        \
                 record Triaged { id claim.id  severity receipt.severity }\n      \
               }\n    \
             }",
        );
        region.step().expect("the claim fires the rule");
        region.open();
        let report = region.step().expect("the region lowers");

        // The arm the plaintext selected ran.
        assert_eq!(
            region.facts_named("Triaged"),
            vec![json!({ "id": "claim-1", "severity": 3 })]
        );
        // The step report says which arm, and not what it compared.
        assert!(!report.branch_reports.is_empty());
        for branch in &report.branch_reports {
            assert_eq!(branch.actual, Value::String("<opened>".to_owned()));
        }

        let emitted = region
            .kernel
            .store()
            .list_effects(&region.instance_id)
            .expect("effects")
            .into_iter()
            .find(|effect| effect.kind == "agent.tell")
            .expect("the region told the agent");
        let input: Value = serde_json::from_str(&emitted.input_json).expect("json");
        assert_eq!(input["bindings"]["receipt"], json!({ "severity": 3 }));
        assert!(input["bindings"].get("patient").is_none(), "{input}");

        assert!(
            !contains(&region.durable_bytes(), SECRET_NOTES),
            "opened plaintext reached a durable record"
        );
    }

    #[test]
    fn a_region_whose_plaintext_this_process_lacks_refuses_to_lower() {
        // The restart case: the open settled, but the slot did not survive.
        // Binding the identity the fact holds would type-check as a
        // PatientRecord and read null; refusing is the only honest answer.
        let mut region = Region::new(
            "OpenRegionLost",
            "    declassify patient into Receipt as receipt\n    \
             record Triaged { id claim.id  severity receipt.severity }",
        );
        region.step().expect("the claim fires the rule");
        let open = region.open();
        super::release([&open]);

        let error = region.step().expect_err("the region must not lower blind");
        assert!(
            format!("{error:?}").contains("does not hold its plaintext"),
            "{error:?}"
        );
        assert!(region.facts_named("Triaged").is_empty());
    }
}
