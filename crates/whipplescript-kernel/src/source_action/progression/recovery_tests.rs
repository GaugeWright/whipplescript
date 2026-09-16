use super::*;

fn failed(name: &str, kind: FailureKind) -> Leaf {
    Leaf::Ready {
        lowering: Box::default(),
        value: None,
        work: Some(OwnedWork {
            state: WorkState::Failed(Disposition::Propagate),
            causes: BTreeMap::from([(
                CauseId(name.into()),
                ObservedCause {
                    cause: Cause {
                        kind,
                        payload: json!({"reason": name}),
                        evidence: BTreeSet::from([format!("event-{name}")]),
                    },
                    recovered: false,
                },
            )]),
        }),
    }
}
fn cause(p: &Progression, name: &str) -> bool {
    let cause = &p.root.causes[&CauseId(name.into())];
    assert_eq!(cause.cause.payload, json!({"reason": name}));
    assert_eq!(
        cause.cause.evidence,
        BTreeSet::from([format!("event-{name}")])
    );
    cause.recovered
}

#[test]
fn counter_outcome_arms_select_one_success_variant_and_keep_its_value() {
    let plan = plan(
        r#"class Customer { id string }
counter budget { key Customer cap 10 reset daily timezone "UTC" }
action root(customer Customer, units int) -> int {
  consume budget for customer amount units as spent
  after spent ok as outcome { return outcome.remaining }
  after spent over as outcome { return outcome.remaining }
}"#,
    );
    for (variant, remaining) in [("Ok", 7), ("Over", 0)] {
        let receipt = Argument {
            value: json!({
                "variant":variant,"counter":"budget","key":"C-1",
                "remaining":remaining,"period":"2026-09-13"
            }),
            sources: BTreeSet::from([ValueSource::Operation {
                operation_id: "counter-effect".into(),
            }]),
            subjects: Default::default(),
            validity: Default::default(),
        };
        let states = BTreeMap::from([(
            String::from("spent"),
            Leaf::Ready {
                lowering: Box::default(),
                value: Some(receipt),
                work: Some(OwnedWork {
                    state: WorkState::Succeeded,
                    causes: BTreeMap::new(),
                }),
            },
        )]);
        let inputs = Bindings::from([
            (
                plan.scopes[0].parameters[0],
                Slot::Ready(json!({"id":"C-1"}).into()),
            ),
            (plan.scopes[0].parameters[1], Slot::Ready(json!(3).into())),
        ]);
        let projected = advance(
            &plan,
            "instance",
            &frame(),
            1,
            &inputs,
            &Journal::default(),
            |statement| {
                Ok(states
                    .get(&label(&statement))
                    .cloned()
                    .unwrap_or_else(|| leaf(WorkState::Pending, None)))
            },
        )
        .unwrap();
        let Boundary::Succeeded(result) = &projected.scopes[&ScopeId(0)].boundary else {
            panic!("counter arm must return")
        };
        assert_eq!(result.value, json!(remaining));
        assert!(result.sources.contains(&ValueSource::Operation {
            operation_id: "counter-effect".into()
        }));
        assert_eq!(
            projected
                .selected_blocks
                .values()
                .filter(|selected| selected.is_some())
                .count(),
            1
        );
    }
}

#[test]
fn lexical_failure_handler_drains_then_recovers_with_the_aggregate() {
    let p = plan(
        "action root() -> string { timer 1s as primary\ntimer 2s as sibling\nreturn \"normal\"\non failure as problem { timer 3s as cleanup\nreturn problem.summary } }",
    );
    let mut states = BTreeMap::from([
        ("primary".into(), failed("primary", FailureKind::Failed)),
        ("sibling".into(), leaf(WorkState::Pending, None)),
        ("cleanup".into(), leaf(WorkState::Pending, None)),
    ]);
    let draining = run(&p, &states);
    assert!(matches!(draining.root.boundary, Boundary::Waiting(_)));
    assert!(draining
        .bindings
        .iter()
        .all(|(binding, _)| p.bindings[binding.0].name.as_deref() != Some("problem")));

    states.insert(
        "sibling".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    let handling = run(&p, &states);
    assert!(matches!(handling.root.boundary, Boundary::Waiting(_)));
    let problem = p
        .bindings
        .iter()
        .position(|binding| binding.name.as_deref() == Some("problem"))
        .unwrap();
    let Slot::Ready(problem) = &handling.bindings[&BindingId(problem)] else {
        panic!("handler aggregate")
    };
    assert_eq!(
        problem.value["summary"],
        json!("action scope failed with 1 unrecovered cause")
    );
    assert_eq!(problem.value["causes"][0]["origin"], json!("primary"));
    assert_eq!(problem.value["causes"][0]["kind"], json!("Failed"));
    assert_eq!(problem.value["causes"][0]["recovered"], json!(false));

    states.insert(
        "cleanup".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    let done = run(&p, &states);
    let Boundary::Succeeded(result) = &done.scopes[&ScopeId(0)].boundary else {
        panic!("handler result")
    };
    assert_eq!(
        result.value,
        json!("action scope failed with 1 unrecovered cause")
    );
    assert_eq!(
        result.sources,
        BTreeSet::from([ValueSource::Operation {
            operation_id: "primary".into()
        }])
    );
    assert!(cause(&done, "primary"));
}

#[test]
fn lexical_failure_handler_does_not_reenter_and_local_recovery_wins() {
    let p = plan(
        "action root() -> int { timer 1s as primary\nafter primary succeeds { return 1 }\nafter primary fails { return 2 }\non failure as problem { return 3 } }",
    );
    let done = run(
        &p,
        &BTreeMap::from([("primary".into(), failed("primary", FailureKind::Failed))]),
    );
    assert_eq!(
        done.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(json!(2).into())
    );
    assert!(cause(&done, "primary"));
    assert_eq!(
        done.selected_blocks
            .values()
            .filter(|body| body.is_some())
            .count(),
        1
    );

    let p = plan(
        "action root() -> int { timer 1s as primary\nreturn 1\non failure as problem { timer 2s as cleanup\nreturn 2 } }",
    );
    let broken = run(
        &p,
        &BTreeMap::from([
            ("primary".into(), failed("primary", FailureKind::Failed)),
            ("cleanup".into(), failed("cleanup", FailureKind::Failed)),
        ]),
    );
    assert_eq!(broken.root.boundary, Boundary::Failed);
    assert_eq!(broken.root.causes.len(), 2);
    assert!(!cause(&broken, "primary"));
    assert!(!cause(&broken, "cleanup"));

    let p = plan(
        "action root() -> string ! string { fail \"domain failure\"\non failure as problem { return problem.summary } }",
    );
    let recovered = run(&p, &BTreeMap::new());
    let Boundary::Succeeded(result) = &recovered.scopes[&ScopeId(0)].boundary else {
        panic!("domain recovery")
    };
    assert_eq!(
        result.value,
        json!("action scope failed with 1 unrecovered cause")
    );
    let problem = p
        .bindings
        .iter()
        .position(|binding| binding.name.as_deref() == Some("problem"))
        .unwrap();
    let Slot::Ready(problem) = &recovered.bindings[&BindingId(problem)] else {
        panic!("domain aggregate")
    };
    assert_eq!(problem.value["domain"], json!("domain failure"));
    assert_eq!(problem.value["causes"][0]["kind"], json!("Domain"));
}

#[test]
fn lexical_failure_handler_refuses_conflicting_evidence_for_one_origin() {
    let p = plan(
        "action root() -> int { timer 1s as first\ntimer 2s as second\nreturn 1\non failure as problem { return 2 } }",
    );
    let collision = |reason: &str| Leaf::Ready {
        lowering: Box::default(),
        value: None,
        work: Some(OwnedWork {
            state: WorkState::Failed(Disposition::Propagate),
            causes: BTreeMap::from([(
                CauseId("same-origin".into()),
                ObservedCause {
                    cause: Cause {
                        kind: FailureKind::Failed,
                        payload: json!({"reason":reason}),
                        evidence: BTreeSet::new(),
                    },
                    recovered: false,
                },
            )]),
        }),
    };
    let states = BTreeMap::from([
        (String::from("first"), collision("first")),
        (String::from("second"), collision("second")),
    ]);
    let error = advance(
        &p,
        "instance",
        &frame(),
        1,
        &Bindings::new(),
        &Journal::default(),
        |statement| Ok(states[&label(&statement)].clone()),
    )
    .unwrap_err();
    assert_eq!(
        error.message,
        "failure handler observed conflicting evidence for one cause origin"
    );
}

#[test]
fn rule_failure_handler_drains_recovers_and_does_not_reenter() {
    let p = plan(
        "rule root\nwhen started\n=> { timer 1s as primary\ntimer 2s as sibling\non failure as problem { timer 3s as cleanup } }",
    );
    let mut states = BTreeMap::from([
        ("primary".into(), failed("primary", FailureKind::Failed)),
        ("sibling".into(), leaf(WorkState::Pending, None)),
        ("cleanup".into(), leaf(WorkState::Pending, None)),
    ]);
    let draining = run(&p, &states);
    assert!(matches!(draining.root.boundary, Boundary::Waiting(_)));
    assert!(draining
        .bindings
        .iter()
        .all(|(binding, _)| p.bindings[binding.0].name.as_deref() != Some("problem")));

    states.insert(
        "sibling".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    let handling = run(&p, &states);
    let problem = p
        .bindings
        .iter()
        .position(|binding| binding.name.as_deref() == Some("problem"))
        .unwrap();
    let Slot::Ready(problem) = &handling.bindings[&BindingId(problem)] else {
        panic!("rule handler aggregate")
    };
    assert_eq!(
        problem.value["summary"],
        json!("rule progression failed with 1 unrecovered cause")
    );
    assert!(matches!(handling.root.boundary, Boundary::Waiting(_)));

    states.insert(
        "cleanup".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    let recovered = run(&p, &states);
    assert_eq!(recovered.root.boundary, Boundary::Succeeded(()));
    assert!(cause(&recovered, "primary"));

    states.insert("cleanup".into(), failed("cleanup", FailureKind::Failed));
    let broken = run(&p, &states);
    assert_eq!(broken.root.boundary, Boundary::Failed);
    assert_eq!(broken.root.causes.len(), 2);
    assert!(!cause(&broken, "primary"));
    assert!(!cause(&broken, "cleanup"));
    assert_eq!(
        broken
            .selected_blocks
            .values()
            .filter(|body| body.is_some())
            .count(),
        1
    );
}

#[test]
fn rule_failure_handler_runs_after_local_recovery() {
    let p = plan(
        "rule root\nwhen started\n=> { timer 1s as primary\nafter primary fails { timer 2s as local }\non failure as problem { timer 3s as outer } }",
    );
    let recovered = run(
        &p,
        &BTreeMap::from([
            ("primary".into(), failed("primary", FailureKind::Failed)),
            (
                "local".into(),
                leaf(WorkState::Succeeded, Some(Value::Null)),
            ),
        ]),
    );
    assert_eq!(recovered.root.boundary, Boundary::Succeeded(()));
    assert!(cause(&recovered, "primary"));
    assert_eq!(
        recovered
            .selected_blocks
            .values()
            .filter(|body| body.is_some())
            .count(),
        1
    );
    assert!(recovered
        .bindings
        .iter()
        .all(|(binding, _)| p.bindings[binding.0].name.as_deref() != Some("problem")));
}

#[test]
fn action_recovery_returns_only_after_handler_joins_and_preserves_failed_value() {
    let p = plan(
        "action root() -> int { timer 1s as primary
after primary succeeds { return 1 }
after primary fails { timer 2s as fallback
return 2 } }",
    );
    let mut states = BTreeMap::from([("primary".into(), failed("primary", FailureKind::Failed))]);
    for state in [
        WorkState::Pending,
        WorkState::CancellationRequested,
        WorkState::Uncertain,
    ] {
        states.insert("fallback".into(), leaf(state, None));
        let waiting = run(&p, &states);
        assert!(matches!(waiting.root.boundary, Boundary::Waiting(_)));
        assert!(!cause(&waiting, "primary"));
    }
    states.insert(
        "fallback".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    let done = run(&p, &states);
    assert_eq!(
        done.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(json!(2).into())
    );
    assert!(cause(&done, "primary"));
    let primary = p
        .bindings
        .iter()
        .position(|b| b.name.as_deref() == Some("primary"))
        .unwrap();
    assert_eq!(
        done.bindings[&BindingId(primary)],
        Slot::Failed(BTreeSet::from([CauseId("primary".into())]))
    );
    states.insert("fallback".into(), failed("fallback", FailureKind::Failed));
    let broken = run(&p, &states);
    assert_eq!(broken.root.boundary, Boundary::Failed);
    assert_eq!(broken.root.causes.len(), 2);
    assert!(!cause(&broken, "primary"));
    assert!(!cause(&broken, "fallback"));
}

#[test]
fn action_recovery_observes_terminal_kind_and_waits_for_acknowledgement() {
    let p = plan(
        "action root() -> int { timer 1s as primary
after primary succeeds { return 1 }
after primary fails { return 2 }
after primary times out { return 3 }
after primary cancelled { return 4 } }",
    );
    for state in [
        WorkState::Pending,
        WorkState::CancellationRequested,
        WorkState::Uncertain,
    ] {
        let pending = run(&p, &BTreeMap::from([("primary".into(), leaf(state, None))]));
        assert!(matches!(pending.root.boundary, Boundary::Waiting(_)));
        assert!(pending.selected_blocks.is_empty());
    }
    for (kind, value) in [
        (FailureKind::Failed, 2),
        (FailureKind::TimedOut, 3),
        (FailureKind::Cancelled, 4),
    ] {
        let done = run(
            &p,
            &BTreeMap::from([("primary".into(), failed("primary", kind))]),
        );
        assert_eq!(
            done.scopes[&ScopeId(0)].boundary,
            Boundary::Succeeded(json!(value).into())
        );
        assert!(cause(&done, "primary"));
        assert_eq!(
            done.selected_blocks
                .values()
                .filter(|v| v.is_some())
                .count(),
            1
        );
    }
    let done = run(
        &p,
        &BTreeMap::from([(
            "primary".into(),
            leaf(WorkState::Succeeded, Some(Value::Null)),
        )]),
    );
    assert_eq!(
        done.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(json!(1).into())
    );
    assert!(done.root.causes.is_empty());
}

#[test]
fn action_recovery_alias_carries_the_exact_terminal_payload_and_operation_source() {
    for (predicate, kind, payload, field, expected) in [
        (
            "fails",
            FailureKind::Failed,
            json!({"reason":"provider refused", "summary":"primary failed"}),
            "reason",
            "provider refused",
        ),
        (
            "times out",
            FailureKind::TimedOut,
            json!({"summary":"primary timed out"}),
            "summary",
            "primary timed out",
        ),
        (
            "cancelled",
            FailureKind::Cancelled,
            json!({"summary":"primary cancelled"}),
            "summary",
            "primary cancelled",
        ),
    ] {
        let p = plan(&format!(
            "action root() -> string {{ timer 1s as primary\nafter primary {predicate} as problem {{ return problem.{field} }} }}"
        ));
        let leaf = Leaf::Ready {
            lowering: Box::default(),
            value: None,
            work: Some(OwnedWork {
                state: WorkState::Failed(Disposition::Propagate),
                causes: BTreeMap::from([(
                    CauseId("effect-primary".into()),
                    ObservedCause {
                        cause: Cause {
                            kind,
                            payload: payload.clone(),
                            evidence: BTreeSet::from(["terminal-event".into()]),
                        },
                        recovered: false,
                    },
                )]),
            }),
        };
        let done = run(&p, &BTreeMap::from([("primary".into(), leaf)]));
        let Boundary::Succeeded(returned) = &done.scopes[&ScopeId(0)].boundary else {
            panic!("selected recovery handler must return")
        };
        assert_eq!(returned.value, json!(expected));
        assert_eq!(
            returned.sources,
            BTreeSet::from([ValueSource::Operation {
                operation_id: "effect-primary".into()
            }])
        );
        let problem = p
            .bindings
            .iter()
            .position(|binding| binding.name.as_deref() == Some("problem"))
            .unwrap();
        let Slot::Ready(argument) = &done.bindings[&BindingId(problem)] else {
            panic!("selected recovery alias must be ready")
        };
        assert_eq!(argument.value, payload);
        assert_eq!(
            argument.sources,
            BTreeSet::from([ValueSource::Operation {
                operation_id: "effect-primary".into()
            }])
        );
        assert!(argument.subjects.is_empty());
        assert!(argument.validity.is_empty());
        assert!(done.root.causes[&CauseId("effect-primary".into())].recovered);
    }
}

#[test]
fn action_recovery_alias_refuses_ambiguous_terminal_causes() {
    let causes: BTreeMap<_, _> = ["first", "second"]
        .into_iter()
        .map(|name| {
            (
                CauseId(name.into()),
                ObservedCause {
                    cause: Cause {
                        kind: FailureKind::Failed,
                        payload: json!({"reason":name}),
                        evidence: BTreeSet::from([format!("event-{name}")]),
                    },
                    recovered: false,
                },
            )
        })
        .collect();
    for (predicate, field, message) in [
        ("fails", "problem.reason", "matching terminal cause"),
        ("completes", "problem.summary", "terminal cause"),
    ] {
        let p = plan(&format!(
            "action root() -> string {{ timer 1s as primary\n\
             after primary {predicate} as problem {{ return {field} }} }}"
        ));
        let issue = advance(
            &p,
            "instance",
            &frame(),
            1,
            &Bindings::new(),
            &Journal::default(),
            |statement| {
                assert_eq!(label(&statement), "primary");
                Ok(Leaf::Ready {
                    lowering: Box::default(),
                    value: None,
                    work: Some(OwnedWork {
                        state: WorkState::Failed(Disposition::Propagate),
                        causes: causes.clone(),
                    }),
                })
            },
        )
        .unwrap_err();
        assert!(issue.message.contains("more than one"));
        assert!(issue.message.contains(message));
    }
}

#[test]
fn action_completion_alias_is_available_for_every_direct_effect_terminal() {
    let p = plan(
        r#"action root() -> string {
  timer 1s as primary
  after primary completes as outcome {
    case outcome {
      Completed as value => { return "completed" }
      Failed as problem => { return problem.summary }
      TimedOut as problem => { return problem.summary }
      Cancelled as problem => { return problem.summary }
    }
  }
}"#,
    );
    let outcome = p
        .bindings
        .iter()
        .position(|binding| binding.name.as_deref() == Some("outcome"))
        .map(BindingId)
        .unwrap();

    let completed = run(
        &p,
        &BTreeMap::from([(
            "primary".into(),
            leaf(WorkState::Succeeded, Some(json!(null))),
        )]),
    );
    assert!(matches!(
        completed.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(ref value) if value.value == "completed"
    ));
    let Slot::Ready(completed_outcome) = &completed.bindings[&outcome] else {
        panic!("completion alias")
    };
    assert_eq!(completed_outcome.value["tag"], "Completed");
    assert_eq!(completed_outcome.value["status"], "completed");
    assert_eq!(completed_outcome.value["value"], Value::Null);
    assert_eq!(completed_outcome.sources.len(), 1);

    for (kind, tag, status, summary) in [
        (FailureKind::Failed, "Failed", "failed", "failed"),
        (FailureKind::TimedOut, "TimedOut", "timed_out", "timed out"),
        (
            FailureKind::Cancelled,
            "Cancelled",
            "cancelled",
            "cancelled",
        ),
    ] {
        let terminal = Leaf::Ready {
            lowering: Box::default(),
            value: None,
            work: Some(OwnedWork {
                state: WorkState::Failed(Disposition::Propagate),
                causes: BTreeMap::from([(
                    CauseId("effect-primary".into()),
                    ObservedCause {
                        cause: Cause {
                            kind,
                            payload: json!({"summary":summary}),
                            evidence: BTreeSet::from(["terminal-event".into()]),
                        },
                        recovered: false,
                    },
                )]),
            }),
        };
        let done = run(&p, &BTreeMap::from([("primary".into(), terminal)]));
        assert!(matches!(
            done.scopes[&ScopeId(0)].boundary,
            Boundary::Succeeded(ref value) if value.value == summary
        ));
        let Slot::Ready(value) = &done.bindings[&outcome] else {
            panic!("completion alias")
        };
        assert_eq!(value.value["tag"], tag);
        assert_eq!(value.value["status"], status);
        assert_eq!(value.value["summary"], summary);
        assert_eq!(value.value["error"], json!({"summary":summary}));
        assert_eq!(
            value.sources,
            BTreeSet::from([ValueSource::Operation {
                operation_id: "effect-primary".into()
            }])
        );
        assert!(done.root.causes[&CauseId("effect-primary".into())].recovered);
    }
}

#[test]
fn action_outcome_expression_waits_for_each_direct_effect_terminal() {
    let p = plan(
        r#"action root() -> string {
  timer 1s as primary
  case outcome(primary) {
    Completed as value => { return "completed" }
    Failed as problem => { return problem.summary }
    TimedOut as problem => { return problem.summary }
    Cancelled as problem => { return problem.summary }
  }
}"#,
    );

    let pending = run(
        &p,
        &BTreeMap::from([(
            "primary".into(),
            leaf(WorkState::Pending, Some(json!(null))),
        )]),
    );
    assert!(matches!(
        pending.scopes[&ScopeId(0)].boundary,
        Boundary::Waiting(_)
    ));

    let completed = run(
        &p,
        &BTreeMap::from([(
            "primary".into(),
            leaf(WorkState::Succeeded, Some(json!(null))),
        )]),
    );
    assert!(matches!(
        completed.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(ref value) if value.value == "completed"
    ));

    for (kind, summary) in [
        (FailureKind::Failed, "failed"),
        (FailureKind::TimedOut, "timed out"),
        (FailureKind::Cancelled, "cancelled"),
    ] {
        let terminal = Leaf::Ready {
            lowering: Box::default(),
            value: None,
            work: Some(OwnedWork {
                state: WorkState::Failed(Disposition::Propagate),
                causes: BTreeMap::from([(
                    CauseId("effect-primary".into()),
                    ObservedCause {
                        cause: Cause {
                            kind,
                            payload: json!({"summary":summary}),
                            evidence: BTreeSet::from(["terminal-event".into()]),
                        },
                        recovered: false,
                    },
                )]),
            }),
        };
        let done = run(&p, &BTreeMap::from([("primary".into(), terminal)]));
        assert!(matches!(
            done.scopes[&ScopeId(0)].boundary,
            Boundary::Succeeded(ref value) if value.value == summary
        ));
        assert!(done.root.causes[&CauseId("effect-primary".into())].recovered);
    }
}

#[test]
fn action_outcome_expression_recovers_only_after_its_selected_handler_joins() {
    let p = plan(
        r#"action root() -> int {
  timer 1s as primary
  case outcome(primary) {
    Completed as value => { return 1 }
    Failed as problem => {
      timer 2s as fallback
      return 2
    }
    TimedOut as problem => { return 3 }
    Cancelled as problem => { return 4 }
  }
}"#,
    );
    let mut states = BTreeMap::from([("primary".into(), failed("primary", FailureKind::Failed))]);
    states.insert("fallback".into(), leaf(WorkState::Pending, None));
    let waiting = run(&p, &states);
    assert!(matches!(waiting.root.boundary, Boundary::Waiting(_)));
    assert!(!cause(&waiting, "primary"));

    states.insert(
        "fallback".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    let done = run(&p, &states);
    assert_eq!(
        done.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(json!(2).into())
    );
    assert!(cause(&done, "primary"));

    states.insert("fallback".into(), failed("fallback", FailureKind::Failed));
    let broken = run(&p, &states);
    assert_eq!(broken.root.boundary, Boundary::Failed);
    assert!(!cause(&broken, "primary"));
    assert!(!cause(&broken, "fallback"));
}

#[test]
fn child_outcome_aggregates_domain_and_leaf_causes_in_stable_order() {
    let completed = plan(
        r#"action root() -> string {
  child() as child_result
  case outcome(child_result) {
    Completed as value => { return value }
    Failed as failure => { return failure.summary }
  }
}
action child() -> string { return "done" }"#,
    );
    assert!(matches!(
        run(&completed, &BTreeMap::new()).scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(ref value) if value.value == "done"
    ));

    let p = plan(
        r#"action root() -> string {
  child() as child_result
  case outcome(child_result) {
    Completed as value => { return value }
    Failed as failure => { return failure.summary }
  }
}
action child() -> string ! string {
  timer 1s as first
  timer 2s as second
  fail "domain"
}"#,
    );
    let waiting = run(
        &p,
        &BTreeMap::from([
            ("first".into(), failed("leaf-first", FailureKind::Failed)),
            ("second".into(), leaf(WorkState::Pending, None)),
        ]),
    );
    assert!(matches!(waiting.root.boundary, Boundary::Waiting(_)));

    let done = run(
        &p,
        &BTreeMap::from([
            ("first".into(), failed("leaf-first", FailureKind::Failed)),
            (
                "second".into(),
                failed("leaf-second", FailureKind::TimedOut),
            ),
        ]),
    );
    assert!(matches!(
        done.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(ref value)
            if value.value == "child action failed with 3 unrecovered causes"
    ));
    let failure = p
        .bindings
        .iter()
        .position(|binding| binding.name.as_deref() == Some("failure"))
        .map(BindingId)
        .unwrap();
    let Slot::Ready(failure) = &done.bindings[&failure] else {
        panic!("child failure alias")
    };
    assert_eq!(failure.value["domain"], "domain");
    assert_eq!(failure.value["causes"].as_array().unwrap().len(), 3);
    let kinds: BTreeSet<_> = failure.value["causes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|cause| cause["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, BTreeSet::from(["Domain", "Failed", "TimedOut"]));
    assert_eq!(failure.sources.len(), 3);
    assert!(done.root.causes.values().all(|cause| cause.recovered));
}

#[test]
fn child_failure_alias_exposes_the_same_aggregate() {
    let p = plan(
        r#"action root() -> string {
  child() as child_result
  after child_result succeeds { return child_result }
  after child_result fails as failure { return failure.summary }
}
action child() -> string ! string { fail "broken" }"#,
    );
    let done = run(&p, &BTreeMap::new());
    assert!(matches!(
        done.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(ref value)
            if value.value == "child action failed with 1 unrecovered cause"
    ));
    let failure = p
        .bindings
        .iter()
        .position(|binding| binding.name.as_deref() == Some("failure"))
        .map(BindingId)
        .unwrap();
    let Slot::Ready(failure) = &done.bindings[&failure] else {
        panic!("child failure alias")
    };
    assert_eq!(failure.value["domain"], "broken");
    assert_eq!(failure.value["causes"][0]["kind"], "Domain");
    assert!(done.root.causes.values().all(|cause| cause.recovered));
}

#[test]
fn action_completion_alias_refuses_success_without_a_value() {
    let observed = BindingId(0);
    let bindings = Bindings::from([(observed, Slot::Pending)]);
    let work = OwnedWork {
        state: WorkState::Succeeded,
        causes: BTreeMap::new(),
    };
    assert_eq!(
        recovery::terminal_outcome(observed, &work, &bindings, "primary"),
        Err("managed outcome alias has no successful value")
    );
}

#[test]
fn counter_variant_alias_refuses_success_without_a_value() {
    let plan = plan(
        r#"class Customer { id string }
counter budget { key Customer cap 10 reset daily timezone "UTC" }
action root(customer Customer) -> int {
  consume budget for customer amount 1 as spent
  after spent ok as outcome { return outcome.remaining }
  after spent over as outcome { return outcome.remaining }
}"#,
    );
    let observed = BindingId(
        plan.bindings
            .iter()
            .position(|binding| binding.name.as_deref() == Some("spent"))
            .unwrap(),
    );
    let operation = recovery::operation_node(&plan, observed).unwrap();
    let owned = BTreeMap::from([(
        operation,
        OwnedWork {
            state: WorkState::Succeeded,
            causes: BTreeMap::new(),
        },
    )]);
    assert_eq!(
        recovery::alias(
            &plan,
            observed,
            AfterPredicate::Ok,
            &owned,
            &Bindings::from([(observed, Slot::Pending)]),
            "instance",
            &frame(),
        ),
        Err("managed counter alias has no successful value")
    );
}

#[test]
fn action_recovery_observation_outer_return_and_sibling_failures_do_not_excuse_work() {
    for handler in [
        "timer 2s as fallback",
        "timer 2s as fallback
return 2",
    ] {
        let outer_return = if handler.contains("return") {
            ""
        } else {
            "return 1"
        };
        let p = plan(&format!(
            "action root() -> int {{ timer 1s as primary
timer 3s as sibling
after primary fails {{ {handler} }}
{outer_return} }}"
        ));
        let mut states = BTreeMap::from([
            ("primary".into(), failed("primary", FailureKind::Failed)),
            (
                "fallback".into(),
                leaf(WorkState::Succeeded, Some(Value::Null)),
            ),
            ("sibling".into(), failed("sibling", FailureKind::Failed)),
        ]);
        let broken = run(&p, &states);
        assert_eq!(broken.root.boundary, Boundary::Failed);
        assert_eq!(cause(&broken, "primary"), handler.contains("return"));
        assert!(!cause(&broken, "sibling"));
        // Two owned paths to the same origin must not hide the unhandled path.
        states.insert("sibling".into(), failed("primary", FailureKind::Failed));
        let shared = run(&p, &states);
        assert_eq!(shared.root.boundary, Boundary::Failed);
        assert_eq!(shared.root.causes.len(), 1);
        assert!(!cause(&shared, "primary"));
    }
}

#[test]
fn action_recovery_nested_handler_and_aggregate_child_failure_compose() {
    let p = plan(
        "action child() -> int { timer 1s as a
timer 2s as b
return 1 }
action root() -> int { child() as primary
after primary succeeds { return primary }
after primary fails { timer 3s as fallback
after fallback succeeds { return 2 }
after fallback fails { case true { true => { return 3 }
false => { timer 4s as never
return 4 } } } } }",
    );
    let states = BTreeMap::from([
        ("a".into(), failed("a", FailureKind::TimedOut)),
        ("b".into(), failed("b", FailureKind::Cancelled)),
        ("fallback".into(), failed("fallback", FailureKind::Failed)),
    ]);
    let done = run(&p, &states);
    assert_eq!(
        done.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(json!(3).into())
    );
    assert_eq!(done.root.causes.len(), 3);
    for name in ["a", "b", "fallback"] {
        assert!(cause(&done, name));
    }
    assert_eq!(done.scopes[&ScopeId(1)].boundary, Boundary::Failed);
    assert!(done.scopes[&ScopeId(1)]
        .causes
        .values()
        .all(|cause| !cause.recovered));
}

#[test]
fn action_recovery_failed_handler_propagates_to_outer_scope_with_both_causes() {
    let p = plan(
        "action child() -> int { timer 1s as a
after a succeeds { return 1 }
after a fails { timer 2s as b
return b } }
action root() -> int { child() as primary
after primary succeeds { return primary }
after primary fails { return 9 } }",
    );
    let done = run(
        &p,
        &BTreeMap::from([
            ("a".into(), failed("a", FailureKind::Failed)),
            ("b".into(), failed("b", FailureKind::Failed)),
        ]),
    );
    assert_eq!(
        done.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(json!(9).into())
    );
    assert_eq!(done.scopes[&ScopeId(1)].boundary, Boundary::Failed);
    assert_eq!(done.root.causes.len(), 2);
    assert!(cause(&done, "a") && cause(&done, "b"));
}

#[test]
fn action_recovery_suppressed_calls_carry_causes_without_observable_terminals() {
    let p = plan(
        "action echo(x int) -> int { return x }
action root() -> int { timer 1s as a
echo(a) as b
echo(b) as c
after b fails { return 99 }
after c fails { return 98 }
return c }",
    );
    let broken = run(
        &p,
        &BTreeMap::from([("a".into(), failed("a", FailureKind::Failed))]),
    );
    assert_eq!(broken.root.boundary, Boundary::Failed);
    assert_eq!(broken.root.causes.len(), 1);
    assert!(!cause(&broken, "a"));
    assert!(broken.lowering.action_captures.is_empty());
    assert_eq!(broken.selected_blocks.len(), 2);
    assert!(broken.selected_blocks.values().all(Option::is_none));
    for name in ["b", "c"] {
        let b = p
            .bindings
            .iter()
            .position(|b| b.name.as_deref() == Some(name))
            .unwrap();
        assert_eq!(
            broken.bindings[&BindingId(b)],
            Slot::Failed(BTreeSet::from([CauseId("a".into())]))
        );
    }
}

#[test]
fn action_recovery_suppressed_statement_and_barrier_results_close_downstream_reads() {
    for body in [
        "timer 1s as a
coerce fake(a) as b
echo(b) as c
return c",
        "then a <- timer 1s
echo(1) as b
echo(b) as c
return c",
    ] {
        let p = plan(&format!(
            "action echo(x int) -> int {{ return x }}
action root() -> int {{ {body} }}"
        ));
        let broken = advance(
            &p,
            "instance",
            &frame(),
            1,
            &Bindings::new(),
            &Journal::default(),
            |statement| {
                if matches!(statement.body, BodyStmt::Effect(effect) if matches!(effect.kind, whipplescript_parser::body::BodyEffectKind::Timer { .. })) {
                    return Ok(failed("a", FailureKind::Failed));
                }
                let binding = statement.environment["a"];
                Ok(Leaf::Waiting(read_binding(binding, statement.bindings)))
            },
        )
        .unwrap();
        assert_eq!(broken.root.boundary, Boundary::Failed);
        assert!(!cause(&broken, "a"));
        assert!(broken.lowering.action_captures.is_empty());
    }
}

#[test]
fn action_recovery_refuses_root_observation_nonoperation_and_leaf_specific_child_terminals() {
    for source in [
        "action root(x int) -> int { after x fails { return 1 } }",
        "action child() -> int { return 1 }
action root() -> int { child() as c
after c times out { return 2 } }",
        "action child() -> int { return 1 }
action root() -> int { child() as c
after c cancelled { return 2 } }",
    ] {
        let p = plan(source);
        let inputs = p
            .scopes
            .first()
            .into_iter()
            .flat_map(|s| &s.parameters)
            .map(|b| (*b, Slot::Ready(json!(1).into())))
            .collect();
        let issue = advance(
            &p,
            "instance",
            &frame(),
            1,
            &inputs,
            &Journal::default(),
            |_| panic!("preflight before work"),
        )
        .unwrap_err();
        assert!(issue.message.contains("not implemented"), "{issue:?}");
    }
}

#[test]
fn action_progression_refuses_two_selected_results_in_an_invalid_plan() {
    let p = plan("action root() -> int { return 1\nreturn 2 }");
    let issue = advance(
        &p,
        "instance",
        &frame(),
        1,
        &Bindings::new(),
        &Journal::default(),
        |_| panic!("results require no work"),
    )
    .unwrap_err();
    assert_eq!(issue.message, "two selected results in one action");
}

#[test]
fn action_recovery_waits_for_handler_continuation_selection_and_propagates_explicit_fail() {
    let p = plan(
        "action root() -> int { timer 1s as primary
prompt \"gate\" as gate
after primary fails { case gate { true => { timer 2s as later } false => { } }
return 2 } }",
    );
    let mut states = BTreeMap::from([("primary".into(), failed("primary", FailureKind::Failed))]);
    let waiting = run(&p, &states);
    assert!(matches!(waiting.root.boundary, Boundary::Waiting(_)));
    assert!(!cause(&waiting, "primary"));
    states.insert("gate".into(), leaf(WorkState::Succeeded, Some(json!(true))));
    let waiting = run(&p, &states);
    assert!(matches!(waiting.root.boundary, Boundary::Waiting(_)));
    assert!(!cause(&waiting, "primary"));
    states.insert(
        "later".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    let done = run(&p, &states);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert!(cause(&done, "primary"));
    let p = plan(
        "action root() -> int { timer 1s as primary
after primary fails { fail \"domain failure\" } }",
    );
    let broken = run(&p, &states);
    assert_eq!(broken.root.boundary, Boundary::Failed);
    assert_eq!(broken.root.causes.len(), 2);
    assert!(!cause(&broken, "primary"));
    assert!(broken
        .root
        .causes
        .values()
        .any(|cause| cause.cause.kind == FailureKind::Domain && !cause.recovered));
}
