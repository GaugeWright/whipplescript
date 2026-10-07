use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use whipplescript_core::norm_evidence::{EvidenceDiagnostic, EvidenceSubject, TestJudgment};
use whipplescript_core::norm_selection::SelectionQuery;
use whipplescript_parser::action_plan::ActionPlan;
use whipplescript_parser::{parse_program, Item};

use super::super::query::{self, NextActionCode, Outcome};
use super::super::{project, Explanation, ReasonCode, ResultStatus};
use super::*;
use crate::lowering::OwnedLowering;
use crate::source_action::arguments::Bindings;
use crate::source_action::journal::Frame;
use crate::source_action::progression::{advance, Leaf};
use crate::source_action::{OwnedWork, WorkState};

fn plan(body: &str) -> ActionPlan {
    let parsed = parse_program(&format!("workflow W\n{body}"));
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let rule = parsed
        .program
        .items
        .iter()
        .find_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .expect("rule");
    whipplescript_parser::action_plan::expand_rule_syntax(&[], rule, &[]).unwrap()
}

fn frame() -> Frame {
    Frame {
        version: "version-7".into(),
        revision: "revision-3".into(),
        rule: "run".into(),
        identity: Some("firing-a".into()),
        trigger_event: Some("event-11".into()),
    }
}

/// Five independent timers, each still pending, so every result begins as a
/// plain `waiting_operation`.
fn waiting_explanation() -> Explanation {
    let plan = plan(
        "rule run when started => {\n timer 1s as capped\n timer 1s as backed\n timer 1s as unconfigured\n timer 1s as refused\n timer 1s as plain\n}",
    );
    let progression = advance(
        &plan,
        "instance-1",
        &frame(),
        19,
        &Bindings::new(),
        &Default::default(),
        |_| {
            Ok(Leaf::Ready {
                lowering: Box::new(OwnedLowering::default()),
                value: None,
                work: Some(OwnedWork {
                    state: WorkState::Pending,
                    causes: BTreeMap::new(),
                }),
            })
        },
    )
    .unwrap();
    project(
        &plan,
        &progression,
        "instance-1",
        &frame(),
        3,
        &BTreeSet::new(),
    )
    .unwrap()
}

fn operation(explanation: &Explanation, name: &str) -> String {
    explanation
        .results
        .iter()
        .find(|result| result.name == name)
        .and_then(|result| result.operation_id.clone())
        .unwrap()
}

fn effect(id: &str, status: &str, cancel_requested: bool) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: id.into(),
        kind: "timer.wait".into(),
        target: None,
        input_json: "{}".into(),
        status: status.into(),
        created_by_rule: "run".into(),
        program_version_id: Some("version-7".into()),
        revision_epoch: 3,
        profile: None,
        cancel_requested,
    }
}

fn event(sequence: i64, kind: &str, payload: serde_json::Value) -> EventView {
    EventView {
        event_id: format!("event-{sequence}"),
        sequence,
        event_type: kind.into(),
        payload_json: payload.to_string(),
        source: "kernel".into(),
        occurred_at: "fixture".into(),
    }
}

#[test]
fn recorded_effect_status_classifies_each_pending_obstruction() {
    let effects = [
        effect("capacity", "blocked_by_capacity", false),
        effect("profile", "blocked_by_profile", false),
        effect("unbound", "blocked", false),
        effect("capability", "blocked_by_capability", false),
        effect("admission", "blocked_by_admission", false),
        effect("gated", "queued", false),
        effect("regated", "queued", false),
        effect("ungated", "queued", false),
        effect("dependency", "blocked_by_dependency", false),
        effect("cancelling", "blocked_by_capacity", true),
        effect("running", "running", false),
    ];
    let events = [
        event(
            1,
            "effect.retried",
            json!({"effect_id": "gated", "retry_after": "2030-01-01T00:00:00Z"}),
        ),
        event(
            2,
            "effect.retried",
            json!({"effect_id": "ungated", "retry_after": null}),
        ),
        // The latest retry decides: a gated retry followed by an immediate one
        // is no longer in backoff.
        event(
            3,
            "effect.retried",
            json!({"effect_id": "regated", "retry_after": "2030-01-01T00:00:00Z"}),
        ),
        event(
            4,
            "effect.retried",
            json!({"effect_id": "regated", "retry_after": null}),
        ),
    ];
    let found = operation_obstructions(&effects, &events);
    assert_eq!(
        found,
        BTreeMap::from([
            ("admission".into(), OperationObstruction::Authority),
            ("capability".into(), OperationObstruction::Authority),
            ("capacity".into(), OperationObstruction::Capacity),
            ("gated".into(), OperationObstruction::Backoff),
            ("profile".into(), OperationObstruction::Configuration),
            ("unbound".into(), OperationObstruction::Configuration),
        ])
    );
}

#[test]
fn operation_join_refines_waiting_reasons_and_next_actions_without_authority() {
    let mut explanation = waiting_explanation();
    let obstructions = BTreeMap::from([
        (
            operation(&explanation, "capped"),
            OperationObstruction::Capacity,
        ),
        (
            operation(&explanation, "backed"),
            OperationObstruction::Backoff,
        ),
        (
            operation(&explanation, "unconfigured"),
            OperationObstruction::Configuration,
        ),
        (
            operation(&explanation, "refused"),
            OperationObstruction::Authority,
        ),
    ]);
    join_operations(&mut explanation, &obstructions);

    let expected = [
        (
            "capped",
            ReasonCode::WaitingCapacity,
            NextActionCode::AwaitOperation,
        ),
        (
            "backed",
            ReasonCode::WaitingBackoff,
            NextActionCode::AwaitOperation,
        ),
        (
            "unconfigured",
            ReasonCode::MissingConfiguration,
            NextActionCode::InspectOperationBlock,
        ),
        (
            "refused",
            ReasonCode::MissingAuthority,
            NextActionCode::InspectOperationBlock,
        ),
        (
            "plain",
            ReasonCode::WaitingOperation,
            NextActionCode::AwaitOperation,
        ),
    ];
    for (name, reason, code) in expected {
        let response =
            query::resolve(std::slice::from_ref(&explanation), "instance-1", name, None).unwrap();
        let Outcome::Selected { selection } = response.outcome else {
            panic!("{name} is selected")
        };
        assert_eq!(selection.result.status, ResultStatus::Waiting, "{name}");
        assert_eq!(selection.result.reasons, vec![reason], "{name}");
        let next = selection.next_action.expect("an observational next action");
        assert_eq!(next.code, code, "{name}");
        assert_eq!(next.operation_id, selection.result.operation_id, "{name}");
        assert!(!next.authorizes_work && !next.retry_permitted, "{name}");
    }
}

fn version(name: &str) -> EvidenceVersion {
    EvidenceVersion {
        name: name.into(),
        version: "1".into(),
        digest: format!("sha256:{name}"),
    }
}

fn judgment(
    artifact: &str,
    outcome: TestOutcome,
    diagnostics: &[EvidenceDiagnostic],
) -> TestJudgment {
    let subject = EvidenceSubject {
        requirement: version("reviewed"),
        method: version("method"),
        artifact: artifact.into(),
    };
    TestJudgment {
        subject: subject.clone(),
        reported_subject: subject,
        outcome,
        required: BTreeSet::from(["case".into()]),
        exercised: BTreeSet::new(),
        counterexamples: Vec::new(),
        diagnostics: diagnostics.iter().cloned().collect(),
    }
}

/// An evaluator selection at one frontier, holding stale evidence about a
/// prior artifact, an inadequate harness failure, a retired report, and both a
/// pass and a counterexample on the current artifact.
fn selection() -> EvidenceSelection {
    let query = SelectionQuery {
        requirement: version("reviewed"),
        artifact: "candidate".into(),
        policy: version("policy"),
        time_basis: "captured".into(),
        frontier: BTreeSet::from(["norm-9".into()]),
    };
    EvidenceSelection {
        query,
        history: BTreeMap::new(),
        judgments: BTreeMap::from([
            (
                "old-pass".into(),
                judgment("previous", TestOutcome::Pass, &[]),
            ),
            (
                "harness".into(),
                judgment("candidate", TestOutcome::HarnessFailed, &[]),
            ),
            (
                "truncated".into(),
                judgment(
                    "candidate",
                    TestOutcome::Pass,
                    &[EvidenceDiagnostic::TruncatedReport],
                ),
            ),
            (
                "retired".into(),
                judgment(
                    "candidate",
                    TestOutcome::Pass,
                    &[EvidenceDiagnostic::MissingProvenance],
                ),
            ),
            ("pass".into(), judgment("candidate", TestOutcome::Pass, &[])),
            ("fail".into(), judgment("candidate", TestOutcome::Fail, &[])),
        ]),
        positive: BTreeSet::from(["pass".into()]),
        counterevidence: BTreeSet::from(["fail".into()]),
        stale: BTreeSet::from(["old-pass".into()]),
        unresolved: BTreeSet::from(["truncated".into(), "harness".into()]),
        excluded: BTreeSet::new(),
        retired_by: BTreeMap::from([("retired".into(), BTreeSet::from(["resolution".into()]))]),
        reused_by: BTreeMap::new(),
        reuse_evaluations: BTreeMap::new(),
        resolution_diagnostics: BTreeMap::new(),
        conformance: Conformance::Conflicted,
    }
}

fn result_id(explanation: &Explanation, name: &str) -> String {
    explanation
        .results
        .iter()
        .find(|result| result.name == name)
        .unwrap()
        .result_id
        .clone()
}

#[test]
fn evaluator_selection_yields_each_support_dimension_separately() {
    let assessment = SupportAssessment::from_selection("result", 19, &selection());
    assert_eq!(assessment.stale, BTreeSet::from(["old-pass".into()]));
    assert_eq!(
        assessment.inadequate,
        BTreeSet::from(["harness".into(), "truncated".into()]),
        "a retired report is not inadequate support, and stale evidence is not double-counted"
    );
    assert_eq!(
        assessment.conflicted,
        BTreeSet::from(["fail".into(), "pass".into()])
    );

    let mut satisfied = selection();
    satisfied.conformance = Conformance::Satisfied;
    satisfied.stale.clear();
    satisfied.judgments.retain(|id, _| id == "pass");
    let assessment = SupportAssessment::from_selection("result", 19, &satisfied);
    assert!(assessment.reasons().is_empty());
}

#[test]
fn support_join_adds_reasons_at_the_same_frontier_and_filters_evidence() {
    let mut explanation = waiting_explanation();
    let plain = result_id(&explanation, "plain");
    let assessment = SupportAssessment::from_selection(plain.clone(), 19, &selection());
    join_support(
        &mut explanation,
        std::slice::from_ref(&assessment),
        &BTreeSet::from(["pass".into(), "old-pass".into()]),
    )
    .unwrap();
    let result = explanation
        .results
        .iter()
        .find(|result| result.result_id == plain)
        .unwrap();
    assert_eq!(
        result.status,
        ResultStatus::Waiting,
        "support never changes the execution status"
    );
    assert_eq!(
        result.reasons,
        vec![
            ReasonCode::WaitingOperation,
            ReasonCode::StaleSupport,
            ReasonCode::InadequateSupport,
            ReasonCode::ConflictedSupport,
        ]
    );
    let [support] = result.support.as_slice() else {
        panic!("one joined assessment")
    };
    assert_eq!(support.requirement, version("reviewed"));
    assert_eq!(support.evidence_refs, vec!["old-pass", "pass"]);
    assert!(
        !support.evidence_complete,
        "hidden evidence cannot disappear behind an apparently complete join"
    );
    let encoded = serde_json::to_string(&explanation).unwrap();
    assert!(!encoded.contains("harness"), "{encoded}");
    assert_eq!(
        serde_json::from_str::<Explanation>(&encoded).unwrap(),
        explanation
    );

    // A second assessment of the same requirement is refused, not merged.
    let error = join_support(&mut explanation, &[assessment], &BTreeSet::new()).unwrap_err();
    assert!(
        error.contains("more than one support assessment"),
        "{error}"
    );
}

#[test]
fn support_join_refuses_another_frontier_or_an_unknown_result() {
    let mut explanation = waiting_explanation();
    let plain = result_id(&explanation, "plain");
    let before = explanation.clone();

    let elsewhere = SupportAssessment::from_selection(plain, 18, &selection());
    let error = join_support(&mut explanation, &[elsewhere], &BTreeSet::new()).unwrap_err();
    assert!(error.contains("frontier 18"), "{error}");

    let unknown = SupportAssessment::from_selection("not-a-result", 19, &selection());
    let error = join_support(&mut explanation, &[unknown], &BTreeSet::new()).unwrap_err();
    assert!(error.contains("does not hold"), "{error}");
    assert_eq!(explanation, before, "a refused join attaches nothing");
}
