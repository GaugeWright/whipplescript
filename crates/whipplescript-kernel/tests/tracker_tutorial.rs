//! The actual GaugeDesk Basics source, exercised against the runtime rather
//! than a Rust reconstruction of its ordering (DR-0110 TAC-4/5).
#![allow(clippy::unwrap_used)]
use serde_json::{json, Value};
use whipplescript_kernel::{
    effect_config::EffectConfig, effect_handlers::run_queue_effect_generic,
    rule_pass::step_instance_generic, time_pass::resolve_due_time_effects, tracker_wait,
    ProgramVersionInput, RuntimeKernel,
};
use whipplescript_parser::{compile_program, IrProgram};
use whipplescript_store::{native_stores::NativeStores, RuntimeStore};

const SOURCE: &str = include_str!("../../../examples/gaugedesk-basics.whip");

fn start(stores: NativeStores, source: &str) -> (RuntimeKernel<NativeStores>, IrProgram, String) {
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.unwrap();
    stores
        .register_package_manifest(include_str!("../../../std/manifests/tracker.json"))
        .unwrap();
    let mut kernel = RuntimeKernel::new(stores);
    let version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &ir.workflow,
                source_hash: "tutorial",
                ir_hash: "tutorial",
                compiler_version: "test",
                ir_snapshot: None,
            },
            &ir,
        )
        .unwrap();
    let id = kernel
        .create_instance(&version, r#"{"learner":{"authority":"person:learner"}}"#)
        .unwrap();
    kernel
        .ingest_external_event(&id, "external.started", "{}", Some("start"))
        .unwrap();
    for fact in whipplescript_kernel::workflow_input::validate_workflow_start_input(
        &ir,
        &json!({"learner": {"authority": "person:learner"}}),
    )
    .unwrap()
    {
        kernel
            .derive_fact(&id, &fact.name, &fact.key, &fact.value_json, None, None)
            .unwrap();
    }
    (kernel, ir, id)
}

fn drive(kernel: &mut RuntimeKernel<NativeStores>, ir: &IrProgram, id: &str) {
    let config = EffectConfig {
        provider: "builtin-tracker".to_owned(),
        outcome_failed: false,
    };
    for _ in 0..24 {
        step_instance_generic(kernel, id, ir, None, None).unwrap();
        let Some(effect) = kernel.claimable_effects(id).unwrap().into_iter().next() else {
            return;
        };
        if tracker_wait::is_tracker_wait(&effect) {
            tracker_wait::run(kernel, id, &effect, &config).unwrap();
        } else {
            assert_eq!(effect.kind, "tracker.file");
            run_queue_effect_generic(kernel, id, &effect, "2026-09-10T12:00:00Z", &config).unwrap();
        }
    }
    panic!("tutorial did not reach a fixpoint");
}

#[test]
fn basics_files_one_assigned_issue_at_a_time_and_survives_restart() {
    let root = std::env::temp_dir().join(format!(
        "whip-basics-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let open = || {
        NativeStores::open(
            root.join("runtime.db"),
            root.join("coord.db"),
            root.join("items.db"),
        )
        .unwrap()
    };
    let (mut kernel, ir, id) = start(open(), SOURCE);
    for step in 0..4 {
        drive(&mut kernel, &ir, &id);
        let items = kernel
            .store()
            .items
            .list_items(Some("tutorials"), None)
            .unwrap();
        assert_eq!(items.len(), step + 1);
        let open_items: Vec<_> = items.iter().filter(|item| item.status == "open").collect();
        assert_eq!(open_items.len(), 1);
        let issue = open_items[0];
        assert_eq!(issue.assigned_to.as_deref(), Some("person:learner"));
        assert!(kernel.claimable_effects(&id).unwrap().is_empty());
        assert_eq!(
            kernel.store().list_runs(&id).unwrap().len(),
            step * 2 + 1,
            "a pending wait must hold neither a run nor a worker"
        );
        let issue_id = issue.id.clone();
        kernel
            .store_mut()
            .items
            .finish_item(&issue_id, Some("human completed task"), None)
            .unwrap();
        // Reopen before the continuation sees the closing: the historical
        // closing still counts, and the same effect must settle only once.
        if step == 0 {
            kernel
                .store_mut()
                .items
                .set_field(&issue_id, "status", "open")
                .unwrap();
            kernel
                .store_mut()
                .items
                .finish_item(&issue_id, Some("closed again"), None)
                .unwrap();
        }
        drop(kernel);
        kernel = RuntimeKernel::new(open());
    }
    drive(&mut kernel, &ir, &id);
    assert_eq!(
        kernel.store().get_instance(&id).unwrap().unwrap().status,
        "completed"
    );
    assert_eq!(
        kernel
            .store()
            .items
            .list_items(Some("tutorials"), None)
            .unwrap()
            .len(),
        4
    );
    let completed: Vec<Value> = kernel
        .store()
        .list_facts(&id)
        .unwrap()
        .iter()
        .filter(|fact| fact.name == "capability.call.succeeded")
        .map(|fact| serde_json::from_str(&fact.value_json).unwrap())
        .collect();
    assert_eq!(completed.len(), 4);
    assert!(completed.iter().all(|fact| fact["value"]["event"]
        .as_str()
        .is_some_and(|v| !v.is_empty())));
    assert!(completed
        .iter()
        .all(|fact| fact["value"].get("body").is_none()));
    drop(kernel);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cancellation_does_not_complete_a_lesson_and_timeout_fails_the_chain() {
    let (mut kernel, ir, id) = start(NativeStores::open_in_memory().unwrap(), SOURCE);
    drive(&mut kernel, &ir, &id);
    let item = kernel
        .store()
        .items
        .list_items(Some("tutorials"), None)
        .unwrap()
        .remove(0);
    kernel
        .store_mut()
        .items
        .set_field(&item.id, "status", "canceled")
        .unwrap();
    drive(&mut kernel, &ir, &id);
    assert_eq!(
        kernel
            .store()
            .items
            .list_items(Some("tutorials"), None)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(kernel.store().list_runs(&id).unwrap().len(), 1);
    resolve_due_time_effects(&mut kernel, &id, "2099-01-01T00:00:00Z").unwrap();
    drive(&mut kernel, &ir, &id);
    assert_eq!(
        kernel.store().get_instance(&id).unwrap().unwrap().status,
        "failed"
    );
    assert!(!kernel
        .store()
        .list_facts(&id)
        .unwrap()
        .iter()
        .any(|f| f.name == "capability.call.succeeded"));
}

#[test]
fn a_wait_without_a_deadline_is_a_failure_not_a_parked_run() {
    let unbounded = SOURCE.replace(" timeout 30d", "");
    let (mut kernel, ir, id) = start(NativeStores::open_in_memory().unwrap(), &unbounded);
    drive(&mut kernel, &ir, &id);
    assert_eq!(
        kernel.store().get_instance(&id).unwrap().unwrap().status,
        "failed"
    );
    let failures: Vec<_> = kernel
        .store()
        .list_facts(&id)
        .unwrap()
        .into_iter()
        .filter(|f| f.name == "capability.call.failed")
        .collect();
    assert_eq!(failures.len(), 1);
    assert!(failures[0].value_json.contains("positive timeout"));
}

#[test]
fn a_closing_in_another_queue_cannot_release_the_wait() {
    let (mut kernel, ir, id) = start(NativeStores::open_in_memory().unwrap(), SOURCE);
    drive(&mut kernel, &ir, &id);
    let item = kernel
        .store()
        .items
        .list_items(Some("tutorials"), None)
        .unwrap()
        .remove(0);
    kernel.derive_fact(&id, "tracker.issue.closed", "other", &json!({
        "id": item.id, "queue": "elsewhere", "event": "other-event", "closed_at": "2026-09-10",
    }).to_string(), None, None).unwrap();
    assert!(kernel.claimable_effects(&id).unwrap().is_empty());
}

#[test]
fn observing_a_public_closure_cannot_vouch_a_privileged_fact() {
    use whipplescript_kernel::ifc::{check_with_envelope, VerifiedEnvelope};
    let source = r#"use std.tracker
workflow Probe
class Approved { event string }
tracker inbox
rule begin
  when started
=> {
  then issue <- file issue into inbox { title "Approve" }
  then closing <- call tracker.wait_closed for issue timeout 1d
  record Approved { event closing.event }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let envelope =
        VerifiedEnvelope::verify_text("grant fact approved -> fact:Approved from Operator\n")
            .unwrap();
    let diagnostics = check_with_envelope(&compiled.ir.unwrap(), &envelope);
    assert!(
        !diagnostics.is_empty(),
        "an unvouched closure must not manufacture privileged evidence"
    );
}

fn closure_ir(value: &str, dynamic: bool) -> IrProgram {
    let (declaration, trigger, filing, argument) = if dynamic {
        (
            "input request Ref\nclass Ref { id string queue string }",
            "Ref as request",
            "",
            "request",
        )
    } else {
        (
            "",
            "started",
            "then issue <- file issue into inbox { title \"Approve\" }",
            "issue",
        )
    };
    let source = format!(
        r#"use std.tracker
workflow Probe
{declaration}
class Approved {{ event string }}
tracker inbox
tracker elsewhere
rule begin
  when {trigger}
=> {{
  {filing}
  then closing <- call tracker.wait_closed for {argument} timeout 1d
  record Approved {{ event {value} }}
}}
"#
    );
    let compiled = compile_program(&source);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    compiled.ir.unwrap()
}

#[test]
fn closure_integrity_follows_both_data_and_control_and_can_be_vouched() {
    use whipplescript_kernel::ifc::{check_with_envelope, VerifiedEnvelope};
    for value in ["closing.event", "\"approved\""] {
        let ir = closure_ir(value, false);
        let policy = "grant fact approved -> fact:Approved from Operator\n";
        let unvouched = VerifiedEnvelope::verify_text(policy).unwrap();
        assert!(check_with_envelope(&ir, &unvouched)
            .iter()
            .any(|d| d.code
                == whipplescript_parser::diagnostic_code!("security.integrity_injection")));
        let vouched = VerifiedEnvelope::verify_text(&format!(
            "{policy}grant tracker inbox -> tracker:inbox from Operator\n"
        ))
        .unwrap();
        assert!(check_with_envelope(&ir, &vouched).is_empty());
    }
}

#[test]
fn closure_visibility_governs_egress_and_the_executing_principal() {
    use whipplescript_kernel::ifc::{
        check_principal_ceiling, check_with_envelope, VerifiedEnvelope,
    };
    let ir = closure_ir("closing.event", false);
    let policy = VerifiedEnvelope::verify_text(
        "grant tracker inbox -> tracker:inbox readable by Operator\n",
    )
    .unwrap();
    assert!(
        check_with_envelope(&ir, &policy)
            .iter()
            .any(|d| d.code
                == whipplescript_parser::diagnostic_code!("security.confidentiality_leak"))
    );
    assert!(check_principal_ceiling(&ir, &policy, "public")
        .iter()
        .any(|d| d.code
            == whipplescript_parser::diagnostic_code!("security.principal_ceiling_exceeded")));
    assert!(check_principal_ceiling(&ir, &policy, "Operator").is_empty());
    let confined = VerifiedEnvelope::verify_text("grant tracker inbox -> tracker:inbox readable by Operator\ngrant fact approved -> fact:Approved readable by Operator\n").unwrap();
    assert!(check_with_envelope(&ir, &confined).is_empty());
}

#[test]
fn dynamic_closure_references_cannot_hide_a_declared_trackers_label() {
    use whipplescript_kernel::ifc::{
        check_principal_ceiling, check_with_envelope, VerifiedEnvelope,
    };
    let policy = VerifiedEnvelope::verify_text(
        "grant tracker elsewhere -> tracker:elsewhere readable by Operator\n",
    )
    .unwrap();
    let dynamic = closure_ir("closing.event", true);
    assert!(
        check_with_envelope(&dynamic, &policy)
            .iter()
            .any(|d| d.code
                == whipplescript_parser::diagnostic_code!("security.confidentiality_leak"))
    );
    assert!(!check_principal_ceiling(&dynamic, &policy, "public").is_empty());
    // A statically known public queue need not inherit an unrelated queue's label.
    let known = closure_ir("closing.event", false);
    assert!(check_with_envelope(&known, &policy).is_empty());
    assert!(check_principal_ceiling(&known, &policy, "public").is_empty());
}

#[test]
fn a_pending_closure_does_not_starve_an_independent_effect() {
    let source = SOURCE.replace(
        "  then chat_done",
        "  file issue into tutorials { title \"Independent\" } as independent\n  then chat_done",
    );
    let (mut kernel, ir, id) = start(NativeStores::open_in_memory().unwrap(), &source);
    drive(&mut kernel, &ir, &id);
    let items = kernel
        .store()
        .items
        .list_items(Some("tutorials"), None)
        .unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().any(|item| item.title == "Independent"));
    assert!(kernel.claimable_effects(&id).unwrap().is_empty());
}

#[test]
fn missing_and_malformed_issue_references_fail_instead_of_waiting() {
    for (argument, message) in [
        ("", "requires an issue reference"),
        (" for learner", "requires nonempty id and queue"),
    ] {
        let source = SOURCE.replace(" for chat timeout", &format!("{argument} timeout"));
        let (mut kernel, ir, id) = start(NativeStores::open_in_memory().unwrap(), &source);
        drive(&mut kernel, &ir, &id);
        assert_eq!(
            kernel.store().get_instance(&id).unwrap().unwrap().status,
            "failed"
        );
        assert!(
            kernel
                .store()
                .list_facts(&id)
                .unwrap()
                .iter()
                .any(|fact| fact.name == "capability.call.failed"
                    && fact.value_json.contains(message))
        );
    }
}

#[test]
fn independent_roots_share_a_tracker_without_sharing_completion() {
    let (mut kernel, ir, first) = start(NativeStores::open_in_memory().unwrap(), SOURCE);
    drive(&mut kernel, &ir, &first);
    let first_issue = kernel
        .store()
        .items
        .list_items(Some("tutorials"), None)
        .unwrap()
        .remove(0);
    let (mut kernel, _, second) = start(kernel.into_store(), SOURCE);
    drive(&mut kernel, &ir, &second);
    assert_ne!(first, second);
    kernel
        .store_mut()
        .items
        .finish_item(&first_issue.id, Some("only first root"), None)
        .unwrap();
    drive(&mut kernel, &ir, &second);
    assert_eq!(kernel.store().list_runs(&second).unwrap().len(), 1);
    drive(&mut kernel, &ir, &first);
    assert_eq!(kernel.store().list_runs(&first).unwrap().len(), 3);
    assert_eq!(
        kernel
            .store()
            .items
            .list_items(Some("tutorials"), None)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn a_pending_wait_cannot_be_started_and_an_incomplete_closing_cannot_release_it() {
    let (mut kernel, ir, id) = start(NativeStores::open_in_memory().unwrap(), SOURCE);
    drive(&mut kernel, &ir, &id);
    let effect = kernel.store().claimable_effects(&id).unwrap().remove(0);
    let config = EffectConfig {
        provider: "builtin-tracker".to_owned(),
        outcome_failed: false,
    };
    assert!(tracker_wait::run(&mut kernel, &id, &effect, &config).is_err());
    assert_eq!(kernel.store().list_runs(&id).unwrap().len(), 1);
    let item = kernel
        .store()
        .items
        .list_items(Some("tutorials"), None)
        .unwrap()
        .remove(0);
    for (key, event, closed_at) in [("missing-event", "", "now"), ("missing-time", "event", "")] {
        kernel
            .derive_fact(
                &id,
                "tracker.issue.closed",
                key,
                &json!({
                    "id": item.id, "queue": "tutorials", "event": event, "closed_at": closed_at,
                })
                .to_string(),
                None,
                None,
            )
            .unwrap();
    }
    assert!(kernel.claimable_effects(&id).unwrap().is_empty());
    kernel
        .store_mut()
        .items
        .finish_item(&item.id, Some("real closing"), None)
        .unwrap();
    drive(&mut kernel, &ir, &id);
    assert_eq!(kernel.store().list_runs(&id).unwrap().len(), 3);
}

#[test]
fn a_closure_recorded_before_the_wait_exists_is_observed() {
    let (mut kernel, ir, id) = start(NativeStores::open_in_memory().unwrap(), SOURCE);
    step_instance_generic(&mut kernel, &id, &ir, None, None).unwrap();
    let file = kernel.claimable_effects(&id).unwrap().remove(0);
    assert_eq!(file.kind, "tracker.file");
    run_queue_effect_generic(
        &mut kernel,
        &id,
        &file,
        "2026-09-10T12:00:00Z",
        &EffectConfig::default(),
    )
    .unwrap();
    let issue = kernel
        .store()
        .items
        .list_items(Some("tutorials"), None)
        .unwrap()
        .remove(0);
    kernel
        .store_mut()
        .items
        .finish_item(&issue.id, Some("already done"), None)
        .unwrap();
    drive(&mut kernel, &ir, &id);
    let items = kernel
        .store()
        .items
        .list_items(Some("tutorials"), None)
        .unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(kernel.store().list_runs(&id).unwrap().len(), 3);
}
