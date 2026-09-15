//! Ordinary tracker control calls must retain both task disclosure and mutation influence.
use serde_json::{json, Value};
use whipplescript_kernel::ifc::{check_with_envelope, VerifiedEnvelope};

fn source(capability: &str, argument: &str, continuation: &str) -> String {
    format!(
        r#"use std.tracker
workflow Control(learner: Learner) -> string
class Learner {{ queue string id string assigned_to string }}
tracker tutorials
rule begin
  when Learner as learner
=> {{
  then outcome <- call {capability} for {argument} timeout 1m
  complete result {continuation}
}}
"#
    )
}
fn policy() -> Value {
    json!({"resources": {
        "input:learner":{"reader":"Private", "writer":"Member"},
        "fact:Learner":{"reader":"Private", "writer":"Member"},
        "tracker:tasks":{"reader":"Private", "writer":"Member"},
        "result":{"reader":"Private", "writer":[]},
        "error":{"reader":"Private", "writer":[]}
    }, "bindings":{"tutorials":"tracker:tasks"}})
}
fn messages(source: &str, policy: Value) -> Vec<String> {
    let compilation = whipplescript_parser::compile_program(source);
    let ir = compilation.ir.expect("ordinary package syntax compiles");
    let envelope = VerifiedEnvelope::verify_text(&policy.to_string()).expect("valid envelope");
    check_with_envelope(&ir, &envelope)
        .iter()
        .map(|d| d.message.clone())
        .collect()
}

#[test]
fn tracker_controls_check_writes_even_when_their_result_is_ignored() {
    for capability in [
        "tracker.claim",
        "tracker.renew",
        "tracker.release",
        "tracker.assign",
    ] {
        let source = source(capability, "learner", "\"done\"");
        assert!(messages(&source, policy()).is_empty(), "{capability}");
        let mut document = policy();
        document["resources"]["tracker:tasks"]["reader_sink"] = json!([]);
        let denied = messages(&source, document);
        assert!(
            denied.iter().any(|message| message.contains("denied flow")),
            "{capability}: {denied:?}"
        );
        let mut document = policy();
        document["resources"]["input:learner"]["writer"] = json!([]);
        document["resources"]["fact:Learner"]["writer"] = json!([]);
        let denied = messages(&source, document);
        assert!(
            denied
                .iter()
                .any(|message| message.contains("denied influence")),
            "{capability}: {denied:?}"
        );
    }
}

#[test]
fn tracker_control_outcomes_and_continuations_retain_task_read_classification() {
    for capability in [
        "tracker.claim",
        "tracker.renew",
        "tracker.release",
        "tracker.assign",
    ] {
        for result in ["outcome.id", "\"done\""] {
            let source = source(capability, "learner", result);
            let mut document = policy();
            for name in ["input:learner", "fact:Learner", "result", "error"] {
                document["resources"][name]["reader"] = json!([]);
            }
            let denied = messages(&source, document);
            assert!(
                denied.iter().any(|message| message.contains("denied flow")),
                "{capability}/{result}: {denied:?}"
            );
        }
    }
}

#[test]
fn untrusted_control_arguments_cannot_select_the_person_who_endorses_them() {
    let mut source = source("tracker.assign", "learner", "\"done\"");
    source.push_str(
        r#"
rule review
  when tutorials has ready issue as task
=> {
  claim task as held endorsed
  after held succeeds { complete result "reviewed" }
}
"#,
    );
    let mut document = policy();
    document["resources"]["tracker:tasks"]["writer_sink"] = json!([]);
    assert!(messages(&source, document.clone()).is_empty());
    for writer in [json!([]), json!("Guest")] {
        document["resources"]["input:learner"]["writer"] = writer.clone();
        document["resources"]["fact:Learner"]["writer"] = writer.clone();
        let denied = messages(&source, document.clone());
        assert!(
            denied
                .iter()
                .any(|message| message.contains("NMIF-on-the-assignee")),
            "{writer}: {denied:?}"
        );
    }
}
