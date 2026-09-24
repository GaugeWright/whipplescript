//! DR-0126: a workflow's `when <tracker> has ready issue` sees the provider's
//! one readiness, decided at the instant the host is stepping at. Before it the
//! projection admitted every open unclaimed issue, so a rule dispatched work
//! that was blocked by a dependency (found 2026-09-24).
#![allow(clippy::unwrap_used)]
use serde_json::{json, Value};
use whipplescript_kernel::{
    rule_pass::step_instance_generic, time_pass::resolve_due_time_effects, ProgramVersionInput,
    RuntimeKernel,
};
use whipplescript_parser::{compile_program, IrProgram};
use whipplescript_store::items::readiness::WaitCondition;
use whipplescript_store::{native_stores::NativeStores, RuntimeStore};

const SOURCE: &str = r#"use std.tracker

workflow ReadyDispatch

tracker backlog

rule take
  when backlog has ready issue as issue
=> {
  claim issue as active_claim
}
"#;

fn start(stores: NativeStores) -> (RuntimeKernel<NativeStores>, IrProgram, String) {
    let compiled = compile_program(SOURCE);
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
                source_hash: "readiness",
                ir_hash: "readiness",
                compiler_version: "test",
                ir_snapshot: None,
            },
            &ir,
        )
        .unwrap();
    let id = kernel.create_instance(&version, "{}").unwrap();
    kernel
        .ingest_external_event(&id, "external.started", "{}", Some("start"))
        .unwrap();
    (kernel, ir, id)
}

fn projected(kernel: &RuntimeKernel<NativeStores>, id: &str) -> Vec<String> {
    let mut ids: Vec<String> = kernel
        .store()
        .list_facts(id)
        .unwrap()
        .into_iter()
        .filter(|fact| fact.name == "tracker.issue.ready")
        .map(|fact| {
            serde_json::from_str::<Value>(&fact.value_json).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    ids.sort();
    ids
}

fn file(kernel: &mut RuntimeKernel<NativeStores>, title: &str) -> String {
    kernel
        .store_mut()
        .items
        .file_item("backlog", title, "", &[], &json!({}), None, None)
        .unwrap()
        .id
}

#[test]
fn a_blocked_issue_is_not_projected_ready() {
    let (mut kernel, ir, id) = start(NativeStores::open_in_memory().unwrap());
    let blocker = file(&mut kernel, "blocker");
    let blocked = file(&mut kernel, "blocked");
    kernel
        .store_mut()
        .items
        .add_relation(&blocker, &blocked, "blocks", None)
        .unwrap();
    step_instance_generic(&mut kernel, &id, &ir, None, None).unwrap();
    assert_eq!(projected(&kernel, &id), vec![blocker]);
    let claims: Vec<String> = kernel
        .claimable_effects(&id)
        .unwrap()
        .into_iter()
        .filter(|effect| effect.kind == "tracker.claim")
        .map(|effect| {
            serde_json::from_str::<Value>(&effect.input_json).unwrap()["id"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    assert!(!claims.contains(&blocked), "claims drafted: {claims:?}");
}

#[test]
fn a_deferral_lifts_at_the_instant_the_host_steps_at() {
    let (mut kernel, ir, id) = start(NativeStores::open_in_memory().unwrap());
    let deferred = file(&mut kernel, "deferred");
    kernel
        .store_mut()
        .items
        .add_wait(
            &deferred,
            &WaitCondition::At {
                instant: "2030-06-01 00:00:00".into(),
            },
            "2030-06-01 00:00:00",
            None,
        )
        .unwrap();
    // The time pass hands the rule pass its instant; nothing reads a clock.
    resolve_due_time_effects(&mut kernel, &id, "2030-01-01T00:00:00Z").unwrap();
    step_instance_generic(&mut kernel, &id, &ir, None, None).unwrap();
    assert!(projected(&kernel, &id).is_empty());
    resolve_due_time_effects(&mut kernel, &id, "2030-06-02T00:00:00Z").unwrap();
    step_instance_generic(&mut kernel, &id, &ir, None, None).unwrap();
    assert_eq!(projected(&kernel, &id), vec![deferred]);
}

/// DR-0126 RV-3: a parked hosted instance sets its one alarm from this, so an
/// issue that becomes ready only because time passed is not left waiting for
/// an unrelated wake-up.
#[test]
fn a_parked_instance_knows_when_time_alone_changes_readiness() {
    let (mut kernel, ir, _id) = start(NativeStores::open_in_memory().unwrap());
    let now = "2030-01-01T00:00:00Z";
    assert_eq!(
        whipplescript_kernel::time_pass::next_tracker_readiness_due_unix_ms(&kernel, now, &ir)
            .unwrap(),
        None
    );
    let claimed = file(&mut kernel, "claimed");
    kernel
        .store_mut()
        .items
        .claim_item_at(&claimed, "someone", Some("2030-01-01 00:10:00"), now, None)
        .unwrap();
    let due =
        whipplescript_kernel::time_pass::next_tracker_readiness_due_unix_ms(&kernel, now, &ir)
            .unwrap()
            .expect("the lapse is a wake-up");
    assert_eq!(
        due,
        whipplescript_kernel::time_pass::parse_clock_instant("2030-01-01T00:10:00Z")
            .unwrap()
            .timestamp_millis()
    );
}
