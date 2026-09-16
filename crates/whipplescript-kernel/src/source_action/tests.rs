use super::*;
use serde_json::json;

fn cause(kind: FailureKind) -> Cause {
    Cause {
        kind,
        payload: json!({"message": "original provider evidence"}),
        evidence: BTreeSet::from(["event:19".to_owned()]),
    }
}

fn failed(origin: &str, kind: FailureKind, disposition: Disposition) -> OwnedWork {
    OwnedWork {
        causes: BTreeMap::from([(
            CauseId(origin.to_owned()),
            ObservedCause {
                cause: cause(kind),
                recovered: false,
            },
        )]),
        state: WorkState::Failed(disposition),
    }
}

fn work(state: WorkState) -> OwnedWork {
    OwnedWork {
        state,
        causes: BTreeMap::new(),
    }
}

fn pair(left: OwnedWork, right: OwnedWork) -> BTreeMap<String, OwnedWork> {
    BTreeMap::from([
        ("investigation".to_owned(), left),
        ("policy".to_owned(), right),
    ])
}

#[test]
fn a_ready_return_cannot_abandon_running_requested_or_uncertain_work() {
    let result = ChosenResult::Return(json!({"approved": true}));
    for (pending, reason) in [
        (
            work(WorkState::Pending),
            WaitReason::Operation("policy".to_owned()),
        ),
        (
            work(WorkState::CancellationRequested),
            WaitReason::CancellationAcknowledgement("policy".to_owned()),
        ),
        (
            work(WorkState::Uncertain),
            WaitReason::UncertainOutcome("policy".to_owned()),
        ),
    ] {
        let view = project(&result, true, &pair(work(WorkState::Succeeded), pending)).unwrap();
        assert_eq!(view.boundary, Boundary::Waiting(BTreeSet::from([reason])));
    }
}

#[test]
fn acknowledged_cancellation_requires_recovery_and_retains_evidence() {
    let result = ChosenResult::Return(42);
    for (disposition, expected) in [
        (Disposition::Propagate, Boundary::Failed),
        (
            Disposition::Recovering,
            Boundary::Waiting(BTreeSet::from([WaitReason::Recovery("policy".to_owned())])),
        ),
        (Disposition::Recovered, Boundary::Succeeded(42)),
    ] {
        let view = project(
            &result,
            true,
            &pair(
                work(WorkState::Succeeded),
                failed("cancelled-policy", FailureKind::Cancelled, disposition),
            ),
        )
        .unwrap();
        assert_eq!(view.boundary, expected);
        let original = &view.causes[&CauseId("cancelled-policy".to_owned())];
        assert_eq!(original.cause, cause(FailureKind::Cancelled));
        assert_eq!(original.recovered, disposition == Disposition::Recovered);
    }
}

#[test]
fn settled_effects_do_not_prove_continuation_closure() {
    let owned = pair(work(WorkState::Succeeded), work(WorkState::Succeeded));
    assert_eq!(
        project(&ChosenResult::Return(42), false, &owned)
            .unwrap()
            .boundary,
        Boundary::Waiting(BTreeSet::from([WaitReason::Continuations]))
    );
    assert_eq!(
        project(&ChosenResult::Return(42), true, &owned)
            .unwrap()
            .boundary,
        Boundary::Succeeded(42)
    );
}

#[test]
fn no_return_is_pending_but_an_explicit_optional_absence_is_a_value() {
    let owned = BTreeMap::new(); // The selected path starts no work.
    assert_eq!(
        project::<Option<String>>(&ChosenResult::Pending, true, &owned)
            .unwrap()
            .boundary,
        Boundary::Waiting(BTreeSet::from([WaitReason::Return]))
    );
    assert_eq!(
        project(&ChosenResult::Return(None::<String>), true, &owned)
            .unwrap()
            .boundary,
        Boundary::Succeeded(None)
    );
}

#[test]
fn concurrent_failures_survive_drain_and_recovery_without_an_arrival_winner() {
    let first = failed(
        "version/firing/left",
        FailureKind::Failed,
        Disposition::Propagate,
    );
    let second = failed(
        "version/firing/right",
        FailureKind::TimedOut,
        Disposition::Propagate,
    );
    let draining = project::<()>(
        &ChosenResult::Pending,
        true,
        &pair(first.clone(), work(WorkState::Pending)),
    )
    .unwrap();
    assert_eq!(draining.causes.len(), 1);
    assert!(matches!(draining.boundary, Boundary::Waiting(_)));
    let left_first = project::<()>(
        &ChosenResult::Pending,
        true,
        &pair(first.clone(), second.clone()),
    )
    .unwrap();
    let right_first = project::<()>(&ChosenResult::Pending, true, &pair(second, first)).unwrap();
    assert_eq!(left_first, right_first);
    assert_eq!(left_first.boundary, Boundary::Failed);
    assert_eq!(left_first.causes.len(), 2);
}

#[test]
fn a_domain_fail_drains_owned_work_and_does_not_hide_provider_failures() {
    let domain = ChosenResult::<()>::Fail {
        origin: CauseId("review/return".to_owned()),
        cause: Cause {
            kind: FailureKind::Domain,
            payload: json!({"variant": "Rejected", "reason": "policy"}),
            evidence: BTreeSet::new(),
        },
    };
    let mut owned = pair(
        failed(
            "investigate/attempt1",
            FailureKind::Failed,
            Disposition::Propagate,
        ),
        work(WorkState::Pending),
    );
    let draining = project(&domain, true, &owned).unwrap();
    assert!(matches!(draining.boundary, Boundary::Waiting(_)));
    assert_eq!(draining.causes.len(), 2);
    owned.insert("policy".to_owned(), work(WorkState::Succeeded));
    let settled = project(&domain, true, &owned).unwrap();
    assert_eq!(settled.boundary, Boundary::Failed);
    assert_eq!(settled.causes, draining.causes);
}

#[test]
fn nested_diamond_preserves_one_leaf_cause_and_each_paths_recovery() {
    let leaf = "v1/firing1/review/investigate/attempt1";
    let recovered = failed(leaf, FailureKind::Failed, Disposition::Recovered);
    let propagating = failed(leaf, FailureKind::Failed, Disposition::Propagate);
    let view = project(
        &ChosenResult::Return(42),
        true,
        &pair(recovered.clone(), propagating),
    )
    .unwrap();
    assert_eq!(view.boundary, Boundary::Failed);
    assert_eq!(view.causes.len(), 1);
    assert!(!view.causes.values().next().unwrap().recovered);
    let view = project(
        &ChosenResult::Return(42),
        true,
        &pair(recovered.clone(), recovered),
    )
    .unwrap();
    assert_eq!(view.boundary, Boundary::Succeeded(42));
    assert_eq!(view.causes.len(), 1);
    assert!(view.causes.values().next().unwrap().recovered);
}

#[test]
fn same_binding_in_another_call_firing_or_version_is_a_distinct_cause() {
    let identities = [
        "v1/f1/call1/turn",
        "v1/f1/call2/turn",
        "v1/f2/call1/turn",
        "v2/f1/call1/turn",
    ];
    let owned = identities
        .into_iter()
        .map(|id| {
            (
                id.to_owned(),
                failed(id, FailureKind::Failed, Disposition::Propagate),
            )
        })
        .collect();
    let view = project::<()>(&ChosenResult::Pending, true, &owned).unwrap();
    assert_eq!(view.boundary, Boundary::Failed);
    assert_eq!(view.causes.len(), identities.len());
}

#[test]
fn conflicting_duplicate_evidence_is_refused_instead_of_choosing_first() {
    let mut duplicate = cause(FailureKind::Failed);
    duplicate.payload = json!({"different": "terminal"});
    let owned = pair(
        failed("original", FailureKind::Failed, Disposition::Recovered),
        OwnedWork {
            causes: BTreeMap::from([(
                CauseId("original".to_owned()),
                ObservedCause {
                    cause: duplicate,
                    recovered: false,
                },
            )]),
            state: WorkState::Failed(Disposition::Recovered),
        },
    );
    assert_eq!(
        project(&ChosenResult::Return(42), true, &owned),
        Err(ProjectionError::ConflictingCause(CauseId(
            "original".to_owned()
        )))
    );
}

#[test]
fn missing_failure_origin_cannot_turn_into_success() {
    let owned = pair(
        work(WorkState::Succeeded),
        OwnedWork {
            causes: BTreeMap::new(),
            state: WorkState::Failed(Disposition::Recovered),
        },
    );
    assert_eq!(
        project(&ChosenResult::Return(42), true, &owned),
        Err(ProjectionError::MissingCause("policy".to_owned()))
    );
}

#[test]
fn a_domain_return_cannot_relabel_a_provider_terminal() {
    let chosen = ChosenResult::<()>::Fail {
        origin: CauseId("attempt1".to_owned()),
        cause: cause(FailureKind::TimedOut),
    };
    assert_eq!(
        project(&chosen, true, &BTreeMap::new()),
        Err(ProjectionError::NonDomainFailure(CauseId(
            "attempt1".to_owned()
        )))
    );
}

#[test]
fn nested_scope_retains_causes_while_draining_and_after_successful_recovery() {
    let leaf = "v1/f1/review/investigate/attempt1";
    let child_work = pair(
        failed(leaf, FailureKind::Failed, Disposition::Recovered),
        work(WorkState::Pending),
    );
    let child = project(&ChosenResult::Return(42), true, &child_work).unwrap();
    let parent = project(
        &ChosenResult::Return(42),
        true,
        &BTreeMap::from([("child".to_owned(), child.into_owned_work())]),
    )
    .unwrap();
    assert_eq!(
        parent.boundary,
        Boundary::Waiting(BTreeSet::from([WaitReason::Operation("child".to_owned()),]))
    );
    assert_eq!(parent.causes.len(), 1);
    assert!(parent.causes[&CauseId(leaf.to_owned())].recovered);

    let child_work = pair(
        failed(leaf, FailureKind::Failed, Disposition::Recovered),
        work(WorkState::Succeeded),
    );
    let child = project(&ChosenResult::Return(42), true, &child_work).unwrap();
    let parent = project(
        &ChosenResult::Return(42),
        true,
        &BTreeMap::from([("child".to_owned(), child.into_owned_work())]),
    )
    .unwrap();
    assert_eq!(parent.boundary, Boundary::Succeeded(42));
    assert_eq!(parent.causes.len(), 1);
    assert!(parent.causes[&CauseId(leaf.to_owned())].recovered);
}

#[test]
fn child_propagation_does_not_unrecover_its_already_handled_cause() {
    let child_work = pair(
        failed("handled", FailureKind::Failed, Disposition::Recovered),
        failed("unhandled", FailureKind::TimedOut, Disposition::Propagate),
    );
    let child = project::<()>(&ChosenResult::Pending, true, &child_work).unwrap();
    let parent = project::<()>(
        &ChosenResult::Pending,
        true,
        &BTreeMap::from([("child".to_owned(), child.into_owned_work())]),
    )
    .unwrap();
    assert_eq!(parent.boundary, Boundary::Failed);
    assert_eq!(parent.causes.len(), 2);
    assert!(parent.causes[&CauseId("handled".to_owned())].recovered);
    assert!(!parent.causes[&CauseId("unhandled".to_owned())].recovered);
}

#[test]
fn malformed_child_success_cannot_launder_an_unhandled_failure() {
    let mut child = failed("unhandled", FailureKind::Failed, Disposition::Propagate);
    child.state = WorkState::Succeeded;
    assert_eq!(
        project(
            &ChosenResult::Return(42),
            true,
            &BTreeMap::from([("child".to_owned(), child)])
        ),
        Err(ProjectionError::UnrecoveredSuccess("child".to_owned()))
    );
}

#[test]
fn dependency_closed_extraction_preserves_both_orders_but_early_inline_return_does_not() {
    // The inline result reads BOTH values; helper extraction introduces no new
    // wait. Exercise both provider orders, replaying each prefix identically.
    for order in [["investigation", "policy"], ["policy", "investigation"]] {
        let mut owned = pair(work(WorkState::Pending), work(WorkState::Pending));
        for (index, operation) in order.into_iter().enumerate() {
            owned.insert(operation.to_owned(), work(WorkState::Succeeded));
            let chosen = if index == 1 {
                ChosenResult::Return(42)
            } else {
                ChosenResult::Pending
            };
            let first = project(&chosen, true, &owned).unwrap();
            assert_eq!(project(&chosen, true, &owned).unwrap(), first);
            assert_eq!(
                matches!(first.boundary, Boundary::Succeeded(42)),
                index == 1
            );
        }
    }
    // Negative extraction: inline return reads only investigation. Wrapping it
    // with policy adds an owned-work wait, which a refactoring must report.
    let early_inline = ChosenResult::Return(42);
    let extracted = project(
        &early_inline,
        true,
        &pair(work(WorkState::Succeeded), work(WorkState::Pending)),
    )
    .unwrap();
    assert!(matches!(early_inline, ChosenResult::Return(42)));
    assert_eq!(
        extracted.boundary,
        Boundary::Waiting(BTreeSet::from(
            [WaitReason::Operation("policy".to_owned()),]
        ))
    );
}
