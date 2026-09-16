use super::*;
use crate::source_action::explanation::{CauseKind, ResultStatus, SourceReference, SourceRole};
use whipplescript_parser::SourceSpan;

fn result(
    id: &str,
    name: &str,
    status: ResultStatus,
    reasons: Vec<ReasonCode>,
) -> ResultExplanation {
    ResultExplanation {
        result_id: id.into(),
        name: name.into(),
        binding: 7,
        operation_id: Some(format!("operation-{id}")),
        status,
        reasons,
        waiting_on: Vec::new(),
        cause_ids: Vec::new(),
        validity_observations: 0,
        source: vec![SourceReference {
            role: SourceRole::CallSite,
            action: Some("inspect".into()),
            node: Some(3),
            span: SourceSpan { start: 10, end: 20 },
        }],
    }
}

fn explanation(identity: &str, result: ResultExplanation) -> Explanation {
    Explanation {
        schema: super::super::SCHEMA.into(),
        instance_id: "instance-1".into(),
        program_version_id: "version-1".into(),
        revision: "revision-1".into(),
        revision_epoch: 1,
        rule: "review".into(),
        firing: Firing {
            identity: Some(identity.into()),
            trigger_event: Some(format!("event-{identity}")),
        },
        evaluated_frontier: 19,
        results: vec![result],
        causes: Vec::new(),
    }
}

#[test]
fn a_name_across_firings_returns_candidates_instead_of_choosing_latest() {
    let explanations = vec![
        explanation(
            "firing-b",
            result(
                "result-b",
                "verdict",
                ResultStatus::Ready,
                vec![ReasonCode::ValueAvailable],
            ),
        ),
        explanation(
            "firing-a",
            result(
                "result-a",
                "verdict",
                ResultStatus::Waiting,
                vec![ReasonCode::WaitingOperation],
            ),
        ),
    ];
    let response = resolve(&explanations, "instance-1", "verdict", None).unwrap();
    let Outcome::Ambiguous { candidates } = response.outcome else {
        panic!("name must remain ambiguous");
    };
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.firing.identity.as_deref().unwrap())
            .collect::<Vec<_>>(),
        vec!["firing-a", "firing-b"]
    );
    assert_eq!(candidates[0].source[0].role, SourceRole::CallSite);
}

#[test]
fn firing_or_exact_result_identity_selects_without_arrival_order() {
    let explanations = vec![
        explanation(
            "firing-a",
            result(
                "result-a",
                "verdict",
                ResultStatus::Ready,
                vec![ReasonCode::ValueAvailable],
            ),
        ),
        explanation(
            "firing-b",
            result(
                "result-b",
                "verdict",
                ResultStatus::Ready,
                vec![ReasonCode::ValueAvailable],
            ),
        ),
    ];
    for response in [
        resolve(&explanations, "instance-1", "verdict", Some("firing-b")).unwrap(),
        resolve(&explanations, "instance-1", "result-b", None).unwrap(),
    ] {
        let Outcome::Selected { selection } = response.outcome else {
            panic!("selector must resolve result-b");
        };
        assert_eq!(selection.result.result_id, "result-b");
        assert_eq!(selection.firing.identity.as_deref(), Some("firing-b"));
    }
}

#[test]
fn repeated_binding_name_inside_one_firing_stays_ambiguous() {
    let mut explanation = explanation(
        "firing-a",
        result(
            "result-a",
            "wait",
            ResultStatus::Waiting,
            vec![ReasonCode::WaitingOperation],
        ),
    );
    explanation.results.push(result(
        "result-b",
        "wait",
        ResultStatus::Waiting,
        vec![ReasonCode::WaitingOperation],
    ));
    let response = resolve(&[explanation], "instance-1", "wait", Some("firing-a")).unwrap();
    assert!(matches!(
        response.outcome,
        Outcome::Ambiguous { ref candidates } if candidates.len() == 2
    ));
}

#[test]
fn absent_selector_returns_not_found_with_the_requested_context() {
    let response = resolve(
        &[explanation(
            "firing-a",
            result(
                "result-a",
                "answer",
                ResultStatus::Ready,
                vec![ReasonCode::ValueAvailable],
            ),
        )],
        "instance-1",
        "missing",
        Some("firing-a"),
    )
    .unwrap();
    assert_eq!(response.instance_id, "instance-1");
    assert_eq!(response.query.result, "missing");
    assert_eq!(response.query.firing.as_deref(), Some("firing-a"));
    assert_eq!(response.outcome, Outcome::NotFound);
}

#[test]
fn uncertain_operation_guidance_reconciles_and_never_authorizes_retry() {
    let explanation = explanation(
        "firing-a",
        result(
            "result-a",
            "delivery",
            ResultStatus::Uncertain,
            vec![ReasonCode::UncertainOutcome],
        ),
    );
    let response = resolve(&[explanation], "instance-1", "delivery", None).unwrap();
    let Outcome::Selected { selection } = response.outcome else {
        panic!("result selected");
    };
    assert_eq!(
        selection.next_action,
        Some(NextAction {
            code: NextActionCode::ReconcileUncertainOperation,
            result_id: None,
            operation_id: Some("operation-result-a".into()),
            binding: None,
            cause_id: None,
            authorizes_work: false,
            retry_permitted: false,
        })
    );
}

#[test]
fn dependency_and_failure_guidance_names_the_exact_obstruction() {
    let mut waiting = result(
        "result-answer",
        "answer",
        ResultStatus::Waiting,
        vec![ReasonCode::WaitingInput],
    );
    waiting.waiting_on.push(super::super::DependencyReference {
        binding: 4,
        result_id: Some("result-input".into()),
        name: Some("input".into()),
    });
    let response = resolve(
        &[explanation("firing-a", waiting)],
        "instance-1",
        "answer",
        None,
    )
    .unwrap();
    let Outcome::Selected { selection } = response.outcome else {
        panic!("result selected");
    };
    assert_eq!(
        selection.next_action.as_ref().unwrap().result_id.as_deref(),
        Some("result-input")
    );

    let mut failed = result(
        "result-failed",
        "answer",
        ResultStatus::Failed,
        vec![ReasonCode::ExecutionFailure],
    );
    failed.cause_ids.push("cause-1".into());
    let mut explanation = explanation("firing-a", failed);
    explanation.causes.push(CauseExplanation {
        cause_id: "cause-1".into(),
        kind: CauseKind::Failed,
        recovered: false,
        dependents: vec!["result-failed".into()],
        witness_refs: vec!["visible-witness".into()],
        witnesses_complete: true,
    });
    let response = resolve(&[explanation], "instance-1", "answer", None).unwrap();
    let Outcome::Selected { selection } = response.outcome else {
        panic!("result selected");
    };
    assert_eq!(selection.causes.len(), 1);
    assert_eq!(
        selection.next_action.as_ref().unwrap().cause_id.as_deref(),
        Some("cause-1")
    );
}

#[test]
fn ready_and_unselected_results_invent_no_next_action() {
    for (status, reason) in [
        (ResultStatus::Ready, ReasonCode::ValueAvailable),
        (ResultStatus::NotSelected, ReasonCode::NotSelected),
        (ResultStatus::NotReached, ReasonCode::NotReached),
    ] {
        let response = resolve(
            &[explanation(
                "firing-a",
                result("result-a", "answer", status, vec![reason]),
            )],
            "instance-1",
            "answer",
            None,
        )
        .unwrap();
        let Outcome::Selected { selection } = response.outcome else {
            panic!("result selected");
        };
        assert_eq!(selection.next_action, None);
    }
}

#[test]
fn malformed_inputs_refuse_instead_of_dropping_identity_or_causes() {
    let mut wrong_schema = explanation(
        "firing-a",
        result(
            "result-a",
            "answer",
            ResultStatus::Ready,
            vec![ReasonCode::ValueAvailable],
        ),
    );
    wrong_schema.schema = "future".into();
    assert!(resolve(&[wrong_schema], "instance-1", "answer", None).is_err());

    let mut missing_cause = explanation(
        "firing-a",
        result(
            "result-a",
            "answer",
            ResultStatus::Failed,
            vec![ReasonCode::ExecutionFailure],
        ),
    );
    missing_cause.results[0].cause_ids.push("missing".into());
    assert_eq!(
        resolve(&[missing_cause], "instance-1", "answer", None).unwrap_err(),
        "action result `result-a` references missing cause `missing`"
    );

    let duplicated_result = explanation(
        "firing-a",
        result(
            "result-a",
            "answer",
            ResultStatus::Ready,
            vec![ReasonCode::ValueAvailable],
        ),
    );
    assert!(resolve(
        &[duplicated_result.clone(), duplicated_result],
        "instance-1",
        "result-a",
        None,
    )
    .is_err());

    let mut duplicate_cause = explanation(
        "firing-a",
        result(
            "result-a",
            "answer",
            ResultStatus::Failed,
            vec![ReasonCode::ExecutionFailure],
        ),
    );
    duplicate_cause.results[0].cause_ids.push("cause-1".into());
    let cause = CauseExplanation {
        cause_id: "cause-1".into(),
        kind: CauseKind::Failed,
        recovered: false,
        dependents: vec!["result-a".into()],
        witness_refs: Vec::new(),
        witnesses_complete: true,
    };
    duplicate_cause.causes = vec![cause.clone(), cause];
    assert!(resolve(&[duplicate_cause], "instance-1", "answer", None).is_err());

    let mut missing_dependent = explanation(
        "firing-a",
        result(
            "result-a",
            "answer",
            ResultStatus::Failed,
            vec![ReasonCode::ExecutionFailure],
        ),
    );
    missing_dependent.results[0]
        .cause_ids
        .push("cause-1".into());
    missing_dependent.causes.push(CauseExplanation {
        cause_id: "cause-1".into(),
        kind: CauseKind::Failed,
        recovered: false,
        dependents: vec!["another-result".into()],
        witness_refs: Vec::new(),
        witnesses_complete: true,
    });
    assert!(resolve(&[missing_dependent], "instance-1", "answer", None).is_err());

    assert!(resolve(&[], "instance-1", " ", None).is_err());
    assert!(resolve(&[], "instance-1", "answer", Some(" ")).is_err());
}

#[test]
fn response_round_trips_without_payload_fields() {
    let response = resolve(
        &[explanation(
            "firing-a",
            result(
                "result-a",
                "answer",
                ResultStatus::Uncertain,
                vec![ReasonCode::UncertainOutcome],
            ),
        )],
        "instance-1",
        "answer",
        None,
    )
    .unwrap();
    let bytes = serde_json::to_string(&response).unwrap();
    assert!(!bytes.contains("payload"));
    assert_eq!(serde_json::from_str::<Response>(&bytes).unwrap(), response);
}
