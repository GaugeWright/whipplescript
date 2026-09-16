//! Shared native/DO witness. Only compiled in tests or downstream test support.
use crate::{ProgramVersionInput, RuntimeKernel};
use whipplescript_store::coordination::Coordination;
use whipplescript_store::items::WorkItems;
use whipplescript_store::vcs::FrontierRead;
use whipplescript_store::{RevisionActivation, RuntimeStore};

pub const SOURCE: &str = r#"workflow Captured
output result Result
class Result { note string }
class Gate { value string }
rule work when started => {
  during empty(Gate) {
    timer 1s as delay
    after delay succeeds { complete result { note "old" } }
  } on lapse { complete result { note "old lapsed" } }
}
"#;
fn register<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    source: &str,
) -> (
    whipplescript_parser::IrProgram,
    whipplescript_store::ProgramVersionRecord,
) {
    let output = whipplescript_parser::execution_semantics::compile_recorded_program_with_root(
        source,
        None,
        whipplescript_parser::ExecutionSemantics::LegacyActionChainsV1,
    );
    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    let ir = output.ir.expect("conformance source compiles");
    let identity = whipplescript_parser::snapshot::identity_projection(&ir.to_snapshot());
    let source_hash = crate::stable_hash_hex(source);
    let version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &ir.workflow,
                source_hash: &source_hash,
                ir_hash: &crate::stable_hash_hex(&identity),
                compiler_version: "fixture",
                ir_snapshot: Some(&identity),
            },
            &ir,
        )
        .expect("complete version captured");
    assert!(
        kernel
            .store()
            .get_content(&source_hash)
            .expect("source lookup")
            .is_none(),
        "the witness must not have source recompilation available"
    );
    (ir, version)
}
pub fn revised_progression_uses_capture<
    S: RuntimeStore + Coordination + WorkItems + FrontierRead,
>(
    store: S,
) {
    revised_progression_with_reopen(store, |store| store);
}
pub fn revised_progression_with_reopen<
    S: RuntimeStore + Coordination + WorkItems + FrontierRead,
>(
    store: S,
    reopen: impl FnOnce(S) -> S,
) {
    let mut kernel = RuntimeKernel::new(store);
    let (old, version) = register(&mut kernel, SOURCE);
    let instance = kernel
        .create_instance(&version, "{}")
        .expect("instance creates");
    kernel
        .ingest_external_event(&instance, "external.started", "{}", Some("started"))
        .expect("start");
    let started = crate::rule_pass::step_instance_generic(&mut kernel, &instance, &old, None, None)
        .expect("start progression");
    assert_eq!(started.committed_rules, 1);
    assert_eq!(
        kernel
            .store()
            .list_effects(&instance)
            .expect("effects")
            .len(),
        1
    );
    let (new, next) = register(&mut kernel, &SOURCE.replace("\"old\"", "\"new\""));
    kernel
        .store_mut()
        .activate_revision(RevisionActivation {
            instance_id: &instance,
            from_version_id: &version.version_id,
            to_version_id: &next.version_id,
            activation_policy_json: "{}",
            cancellation_policy: "keep",
            rule_carries_json: "[]",
            rule_correspondence_json: "null",
            idempotency_key: Some("revise"),
        })
        .expect("revision activates");
    drop(old);
    let mut kernel = RuntimeKernel::new(reopen(kernel.into_store()));
    crate::time_pass::resolve_due_time_effects(&mut kernel, &instance, "2099-01-01T00:00:00Z")
        .expect("timer settles");
    let progressed =
        crate::rule_pass::step_instance_generic(&mut kernel, &instance, &new, None, None)
            .expect("old progression completes");
    assert_eq!(progressed.committed_rules, 1);
    assert_eq!(
        kernel
            .store()
            .get_instance(&instance)
            .expect("instance")
            .expect("present")
            .status,
        "completed"
    );
    let events = kernel.store().list_events(&instance).expect("events");
    let terminal = events
        .iter()
        .find(|e| e.event_type == "workflow.completed")
        .expect("terminal event");
    let payload: serde_json::Value =
        serde_json::from_str(&terminal.payload_json).expect("terminal JSON");
    assert_eq!(payload["payload"]["note"], "old");
    assert!(kernel
        .store()
        .list_diagnostics(Some(&instance))
        .expect("diagnostics")
        .iter()
        .all(|d| d.code.as_deref() != Some("progression.version_unavailable")));
    let before = events.len();
    crate::rule_pass::step_instance_generic(&mut kernel, &instance, &new, None, None)
        .expect("replay step");
    assert_eq!(
        kernel.store().list_events(&instance).expect("events").len(),
        before
    );
}
