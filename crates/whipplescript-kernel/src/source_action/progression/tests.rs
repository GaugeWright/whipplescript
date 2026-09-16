use super::super::{ObservedCause, WaitReason};
use super::*;
use serde_json::json;
use whipplescript_parser::{parse_program, Item};

#[test]
fn action_region_journal_rejects_history_for_nonregion_and_absent_nodes() {
    use super::super::journal::{
        regions::{context_with_regions, Cut, Phase},
        root::{context_with_root, RootCapture},
    };
    let p = plan("rule root when started => { timer 1s as wait }");
    for region in [0, u64::MAX] {
        let f = frame();
        let context = context_with_root(
            r#"{"identity":null,"trigger_event_id":null,"bindings":[]}"#,
            &f,
            Some(&RootCapture {
                inputs: vec![],
                frontier: 1,
            }),
            1,
        )
        .unwrap();
        let context = context_with_regions(
            &context,
            &f,
            &[Cut {
                region,
                frontier: 1,
                phase: Phase::Holding,
            }],
            1,
        )
        .unwrap();
        let mut journal = Journal::default();
        journal.apply(&whipplescript_store::EventView {
            event_id: "commit".into(), sequence: 2, event_type: "rule.committed".into(),
            payload_json: json!({"rule":"root","context":serde_json::from_str::<Value>(&context).unwrap()}).to_string(),
            source: "test".into(), occurred_at: "test".into(),
        }).unwrap();
        let projected = std::cell::Cell::new(0);
        let result = advance(&p, "instance", &f, 2, &Bindings::new(), &journal, |_| {
            projected.set(projected.get() + 1);
            Ok(leaf(WorkState::Pending, None))
        });
        assert!(result
            .unwrap_err()
            .message
            .contains("recorded region is absent"));
        assert_eq!(
            projected.get(),
            0,
            "invalid region history refuses before projecting work"
        );
    }
}

#[test]
fn action_region_journal_cannot_be_forged_by_a_statement_lowerer() {
    use super::super::journal::regions::{Cut, Phase};
    let p = plan("rule root when started => { timer 1s as wait }");
    let error = advance(
        &p,
        "instance",
        &frame(),
        1,
        &Bindings::new(),
        &Journal::default(),
        |_| {
            Ok(Leaf::Ready {
                lowering: Box::new(OwnedLowering {
                    action_regions: vec![Cut {
                        region: 0,
                        frontier: 1,
                        phase: Phase::Exited,
                    }],
                    ..Default::default()
                }),
                value: None,
                work: Some(OwnedWork {
                    state: WorkState::Pending,
                    causes: BTreeMap::new(),
                }),
            })
        },
    )
    .unwrap_err();
    assert!(
        error.message.contains("cannot own action captures"),
        "{error:?}"
    );
}

fn plan(body: &str) -> ActionPlan {
    let parsed = parse_program(&format!("workflow W\n{body}"));
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let actions: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect();
    if let Some(rule) = parsed.program.items.iter().find_map(|item| match item {
        Item::Rule(rule) => Some(rule),
        _ => None,
    }) {
        whipplescript_parser::action_plan::expand_rule_syntax(&actions, rule, &[]).unwrap()
    } else {
        whipplescript_parser::action_plan::expand_syntax(&actions, "root").unwrap()
    }
}
fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "root".into(),
        identity: None,
        trigger_event: None,
    }
}
fn leaf(state: WorkState, value: Option<Value>) -> Leaf {
    Leaf::Ready {
        lowering: Box::default(),
        value: value.map(Argument::from),
        work: Some(OwnedWork {
            state,
            causes: BTreeMap::new(),
        }),
    }
}
fn label(statement: &Statement<'_>) -> String {
    match statement.body {
        BodyStmt::Effect(effect) => effect.binding.clone().unwrap_or_else(|| "unbound".into()),
        _ => "pure".into(),
    }
}
fn run(p: &ActionPlan, states: &BTreeMap<String, Leaf>) -> Progression {
    advance(
        p,
        "instance",
        &frame(),
        1,
        &Bindings::new(),
        &Journal::default(),
        |statement| {
            Ok(states
                .get(&label(&statement))
                .cloned()
                .unwrap_or_else(|| leaf(WorkState::Pending, None)))
        },
    )
    .unwrap()
}
fn saved(
    captures: &[super::super::journal::CallCapture],
    root: &super::super::journal::root::RootCapture,
) -> Journal {
    let mut journal = Journal::default();
    let context = super::super::journal::context_with_captures(
        r#"{"identity":null,"trigger_event_id":null,"bindings":[]}"#,
        &frame(),
        captures,
        1,
    )
    .unwrap();
    let context =
        super::super::journal::root::context_with_root(&context, &frame(), Some(root), 1).unwrap();
    journal
        .apply(&whipplescript_store::EventView {
            event_id: "commit".into(),
            sequence: 2,
            event_type: "rule.committed".into(),
            payload_json:
                json!({"rule":"root","context":serde_json::from_str::<Value>(&context).unwrap()})
                    .to_string(),
            source: "test".into(),
            occurred_at: "test".into(),
        })
        .unwrap();
    journal
}

#[test]
fn action_progression_nested_calls_activate_capture_and_publish_only_boundaries() {
    let p = plan("action leaf(x string) -> string { return x }\naction middle(x string) -> string { leaf(x) as y\nreturn y }\naction root(x string) -> string { middle(x) as y\nreturn y }");
    let input = p.scopes[0].parameters[0];
    let inputs = Bindings::from([(input, Slot::Ready(json!("original").into()))]);
    let first = advance(
        &p,
        "instance",
        &frame(),
        1,
        &inputs,
        &Journal::default(),
        |_| panic!("no effects"),
    )
    .unwrap();
    assert_eq!(first.lowering.action_captures.len(), 2);
    assert_eq!(first.scopes.len(), 3);
    let Boundary::Succeeded(result) = &first.scopes[&ScopeId(0)].boundary else {
        panic!("root result");
    };
    assert_eq!(result.value, json!("original"));
    assert_eq!(
        result.sources.len(),
        2,
        "nested operation identities survive"
    );
    assert!(matches!(first.root.boundary, Boundary::Succeeded(())));
    let changed = Bindings::from([(input, Slot::Ready(json!("changed").into()))]);
    let replay = advance(
        &p,
        "instance",
        &frame(),
        2,
        &changed,
        &saved(
            &first.lowering.action_captures,
            first.lowering.action_root.as_ref().unwrap(),
        ),
        |_| panic!("no effects"),
    )
    .unwrap();
    assert!(replay.lowering.action_captures.is_empty());
    assert_eq!(replay.scopes, first.scopes);
}

#[test]
fn action_progression_ready_return_joins_discarded_and_named_siblings() {
    let p = plan("action child() -> int { timer 2s as discarded\nreturn 2 }\naction root() -> int { timer 1s as first\nchild()\nreturn 42 }");
    let mut states = BTreeMap::new();
    let independent = run(&p, &states);
    assert!(matches!(independent.root.boundary, Boundary::Waiting(_)));
    assert_eq!(independent.lowering.action_captures.len(), 1);
    assert_eq!(independent.scopes.len(), 2);
    states.insert(
        "first".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    assert!(matches!(
        run(&p, &states).root.boundary,
        Boundary::Waiting(_)
    ));
    states.insert(
        "discarded".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    let done = run(&p, &states);
    assert!(matches!(done.root.boundary, Boundary::Succeeded(())));
    assert_eq!(
        done.scopes[&ScopeId(0)].boundary,
        Boundary::Succeeded(json!(42).into())
    );
}

#[test]
fn action_progression_settled_effect_still_owes_after_and_nested_work() {
    let p = plan("action child() -> int { timer 2s as inner\nreturn 2 }\naction root() -> int { timer 1s as start\nafter start succeeds { child() as followup }\nreturn 1 }");
    let mut states = BTreeMap::new();
    let waiting = run(&p, &states);
    assert!(waiting.lowering.action_captures.is_empty());
    assert!(
        matches!(&waiting.scopes[&ScopeId(0)].boundary, Boundary::Waiting(waits) if waits.contains(&WaitReason::Continuations))
    );
    assert_eq!(waiting.waiting.len(), 1, "after has a located wait");
    states.insert(
        "start".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    let introduced = run(&p, &states);
    assert_eq!(introduced.lowering.action_captures.len(), 1);
    assert_eq!(introduced.scopes.len(), 2);
    assert!(matches!(introduced.root.boundary, Boundary::Waiting(_)));
    assert!(matches!(
        introduced.scopes[&ScopeId(1)].boundary,
        Boundary::Waiting(_)
    ));
    states.insert(
        "inner".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    assert!(matches!(
        run(&p, &states).root.boundary,
        Boundary::Succeeded(())
    ));
}

#[test]
fn action_progression_case_waits_for_guard_and_unselected_calls_create_no_debt() {
    let p = plan("action child() -> int { timer 2s as discarded\nreturn 1 }\naction root() -> int { prompt \"choice\" as choice\nprompt \"guard\" as gate\ncase choice { \"yes\" where gate == \"go\" => { child() as work\nreturn work } _ => { return 0 } } }");
    let mut states = BTreeMap::from([(
        "choice".into(),
        leaf(WorkState::Succeeded, Some(json!("yes"))),
    )]);
    let pending = run(&p, &states);
    assert_eq!(pending.scopes.len(), 1);
    assert!(pending.lowering.action_captures.is_empty());
    assert!(matches!(pending.root.boundary, Boundary::Waiting(_)));
    assert!(
        pending.selected_blocks.is_empty(),
        "a pending guard has not selected or rejected its case"
    );
    assert_eq!(
        pending.waiting.len(),
        1,
        "the case retains its located waiting diagnostic"
    );
    states.insert(
        "gate".into(),
        leaf(WorkState::Succeeded, Some(json!("stop"))),
    );
    let skipped = run(&p, &states);
    assert_eq!(skipped.scopes.len(), 1);
    assert!(skipped.lowering.action_captures.is_empty());
    assert!(matches!(skipped.root.boundary, Boundary::Succeeded(())));
    states.insert("gate".into(), leaf(WorkState::Succeeded, Some(json!("go"))));
    let selected = run(&p, &states);
    assert_eq!(selected.scopes.len(), 2);
    assert_eq!(selected.lowering.action_captures.len(), 1);
    assert!(matches!(selected.root.boundary, Boundary::Waiting(_)));
    let call_result = p
        .nodes
        .iter()
        .find(|node| matches!(node.kind, NodeKind::Call { .. }))
        .unwrap()
        .result
        .unwrap();
    assert_eq!(
        selected.bindings[&call_result],
        Slot::Pending,
        "child return remains private while its work drains"
    );
    states.insert(
        "discarded".into(),
        leaf(WorkState::Succeeded, Some(Value::Null)),
    );
    assert!(matches!(
        run(&p, &states).root.boundary,
        Boundary::Succeeded(())
    ));
}

#[test]
fn action_progression_failure_drains_siblings_and_keeps_the_original_child_cause() {
    let p = plan("action child() -> int ! string { fail \"denied\" }\naction root() -> int { timer 1s as sibling\nchild() as result\nreturn result }");
    let pending = run(&p, &BTreeMap::new());
    assert!(matches!(pending.root.boundary, Boundary::Waiting(_)));
    assert_eq!(pending.root.causes.len(), 1);
    let origin = pending.root.causes.keys().next().unwrap().clone();
    let done = run(
        &p,
        &BTreeMap::from([(
            "sibling".into(),
            leaf(WorkState::Succeeded, Some(Value::Null)),
        )]),
    );
    assert_eq!(done.root.boundary, Boundary::Failed);
    assert_eq!(
        done.root.causes.keys().cloned().collect::<Vec<_>>(),
        vec![origin]
    );
    assert_eq!(
        done.root.causes.values().next().unwrap().cause.payload,
        json!("denied")
    );
    assert!(done.waiting.values().any(resolved_obstruction));
}

#[test]
fn action_progression_root_terminal_waits_for_owned_action_work() {
    let p = plan("action child() -> int { timer 1s as work\nreturn 1 }\nrule root when started => { child() as result\ncomplete out { ok true } }");
    let observe = |settled| {
        advance(
            &p,
            "instance",
            &frame(),
            1,
            &Bindings::new(),
            &Journal::default(),
            |statement| {
                if matches!(statement.body, BodyStmt::Terminal(_)) {
                    Ok(Leaf::Ready {
                        lowering: Box::new(OwnedLowering {
                            terminal: Some(crate::lowering::OwnedWorkflowTerminal {
                                kind: whipplescript_store::WorkflowTerminalKind::Completed,
                                name: "out".into(),
                                payload_json: "{}".into(),
                                validity_json: None,
                                idempotency_key: statement.identity,
                            }),
                            ..Default::default()
                        }),
                        value: None,
                        work: None,
                    })
                } else {
                    Ok(leaf(
                        if settled {
                            WorkState::Succeeded
                        } else {
                            WorkState::Pending
                        },
                        settled.then_some(Value::Null),
                    ))
                }
            },
        )
        .unwrap()
    };
    assert!(observe(false).lowering.terminal.is_none());
    assert!(observe(true).lowering.terminal.is_some());
}

#[test]
fn action_progression_refuses_unimplemented_control_before_projecting_any_statement() {
    let p = plan("action root() -> int { during ready { timer 1s as t } on lapse { }\nreturn 0 }");
    let error = advance(
        &p,
        "instance",
        &frame(),
        1,
        &Bindings::new(),
        &Journal::default(),
        |_| panic!("must preflight"),
    )
    .unwrap_err();
    assert!(error.message.contains("not implemented"));
}

#[test]
fn action_progression_refuses_bad_results_and_ownership() {
    let p = plan("action root() -> int { timer 1s as t\nreturn 1 }");
    for value in [
        leaf(WorkState::Succeeded, None),
        Leaf::Ready {
            lowering: Box::default(),
            value: Some(Value::Null.into()),
            work: None,
        },
        Leaf::Ready {
            lowering: Box::new(OwnedLowering {
                internal_fail: Some("bad net".into()),
                ..Default::default()
            }),
            value: None,
            work: Some(OwnedWork {
                state: WorkState::Pending,
                causes: BTreeMap::new(),
            }),
        },
        Leaf::Ready {
            lowering: Box::default(),
            value: None,
            work: Some(OwnedWork {
                state: WorkState::Failed(Disposition::Propagate),
                causes: BTreeMap::new(),
            }),
        },
    ] {
        assert!(advance(
            &p,
            "instance",
            &frame(),
            1,
            &Bindings::new(),
            &Journal::default(),
            |_| Ok(value.clone())
        )
        .is_err());
    }
    for body in ["", "return 1\nreturn 2"] {
        let p = plan(&format!("action root() -> int {{ {body} }}"));
        assert!(advance(
            &p,
            "instance",
            &frame(),
            1,
            &Bindings::new(),
            &Journal::default(),
            |_| panic!("no effects")
        )
        .is_err());
    }
}

#[test]
fn action_progression_failure_selection_and_cancellation_are_honest() {
    let p = plan(
        "action root() -> int { timer 1s as t\nafter t succeeds { timer 2s as later }\nreturn 1 }",
    );
    for state in [WorkState::CancellationRequested, WorkState::Uncertain] {
        assert!(matches!(
            run(&p, &BTreeMap::from([("t".into(), leaf(state, None))]))
                .root
                .boundary,
            Boundary::Waiting(_)
        ));
    }
    let work = OwnedWork {
        state: WorkState::Failed(Disposition::Propagate),
        causes: BTreeMap::from([(
            CauseId("cancelled-original".into()),
            ObservedCause {
                cause: Cause {
                    kind: FailureKind::Cancelled,
                    payload: Value::Null,
                    evidence: BTreeSet::new(),
                },
                recovered: false,
            },
        )]),
    };
    let done = run(
        &p,
        &BTreeMap::from([(
            "t".into(),
            Leaf::Ready {
                lowering: Box::default(),
                value: None,
                work: Some(work),
            },
        )]),
    );
    assert_eq!(done.root.boundary, Boundary::Failed);
    assert!(done.selected_blocks.values().any(Option::is_none));
    assert!(!done.waiting.values().any(
        |value| matches!(&value.state, State::Blocked { waiting, .. } if !waiting.is_empty())
    ));
}

#[test]
fn action_progression_rejects_foreign_inputs_and_unreachable_recorded_calls() {
    let p = plan("action child() -> int { return 1 }\naction root(flag bool) -> int { case flag { true => { child() as result\nreturn result } false => { return 0 } } }");
    assert!(advance(
        &p,
        "instance",
        &frame(),
        1,
        &Bindings::new(),
        &Journal::default(),
        |_| panic!("no effects")
    )
    .is_err());
    let input = p.scopes[0].parameters[0];
    let run_with = |value, journal: &Journal| {
        advance(
            &p,
            "instance",
            &frame(),
            1,
            &Bindings::from([(input, Slot::Ready(value))]),
            journal,
            |_| panic!("no effects"),
        )
    };
    let first = run_with(json!(true).into(), &Journal::default()).unwrap();
    let journal = saved(
        &first.lowering.action_captures,
        first.lowering.action_root.as_ref().unwrap(),
    );
    let replay = run_with(json!(false).into(), &journal).unwrap();
    assert_eq!(
        replay.scopes, first.scopes,
        "saved root wins before current input selection"
    );
    let mut wrong_root = first.lowering.action_root.clone().unwrap();
    wrong_root.inputs[0].argument.value = json!(false);
    let orphaned = saved(&first.lowering.action_captures, &wrong_root);
    assert!(run_with(json!(true).into(), &orphaned)
        .unwrap_err()
        .message
        .contains("unreachable"));
    let mut corrupt = first.lowering.action_captures[0].clone();
    corrupt.call = 9999;
    assert!(run_with(
        json!(true).into(),
        &saved(&[corrupt], first.lowering.action_root.as_ref().unwrap())
    )
    .unwrap_err()
    .message
    .contains("absent from its source plan"));
}

#[test]
fn action_progression_case_binders_and_evaluation_errors_keep_source_context() {
    let p = plan("action root(x string?) -> string { case x { Some as item => { return item } None => { return \"none\" } } }");
    let input = p.scopes[0].parameters[0];
    for input_value in [json!("present"), Value::Null] {
        let result = advance(
            &p,
            "instance",
            &frame(),
            1,
            &Bindings::from([(input, Slot::Ready(input_value.clone().into()))]),
            &Journal::default(),
            |_| panic!("no effects"),
        )
        .unwrap();
        let Boundary::Succeeded(value) = &result.scopes[&ScopeId(0)].boundary else {
            panic!("success");
        };
        assert_eq!(
            value.value,
            if input_value.is_null() {
                json!("none")
            } else {
                input_value
            }
        );
    }
    let p = plan("action child(x int) -> int { return x }\naction root() -> int { child(1 / 0) as value\nreturn value }");
    let error = advance(
        &p,
        "instance",
        &frame(),
        1,
        &Bindings::new(),
        &Journal::default(),
        |_| panic!("no effects"),
    )
    .unwrap_err();
    assert_eq!(error.message, "division by zero");
    assert!(error.evaluation.is_some());
}

fn terminal() -> crate::lowering::OwnedWorkflowTerminal {
    crate::lowering::OwnedWorkflowTerminal {
        kind: whipplescript_store::WorkflowTerminalKind::Completed,
        name: "out".into(),
        payload_json: "{}".into(),
        validity_json: None,
        idempotency_key: "terminal".into(),
    }
}

#[test]
fn action_progression_refuses_statement_errors_and_escaping_terminals() {
    let action = plan("action root() -> int { timer 1s as t\nreturn 1 }");
    let duplicate =
        plan("rule root when started => { complete out { ok true }\ncomplete out { ok false } }");
    for (p, draft, work) in [
        (
            &action,
            OwnedLowering {
                errors: vec!["payload cannot be admitted".into()],
                ..Default::default()
            },
            Some(OwnedWork {
                state: WorkState::Succeeded,
                causes: BTreeMap::new(),
            }),
        ),
        (
            &action,
            OwnedLowering {
                terminal: Some(terminal()),
                ..Default::default()
            },
            Some(OwnedWork {
                state: WorkState::Succeeded,
                causes: BTreeMap::new(),
            }),
        ),
        (
            &duplicate,
            OwnedLowering {
                terminal: Some(terminal()),
                ..Default::default()
            },
            None,
        ),
    ] {
        assert!(advance(
            p,
            "instance",
            &frame(),
            1,
            &Bindings::new(),
            &Journal::default(),
            |_| Ok(Leaf::Ready {
                lowering: Box::new(draft.clone()),
                value: Some(Value::Null.into()),
                work: work.clone()
            })
        )
        .is_err());
    }
}

#[test]
fn action_progression_refuses_unresolved_pattern_metadata_and_nonboolean_guards() {
    for (source, input) in [
        (
            "action root(x Ticket) -> int { case x { Ticket => { return 1 } _ => { return 0 } } }",
            json!({"ticket":1}),
        ),
        (
            "action root(x Ticket) -> int { case x { Ticket => { return 1 } _ => { return 0 } } }",
            json!({"variant":"Ticket"}),
        ),
        (
            "action root(x Ticket) -> int { case x { Completed => { return 1 } _ => { return 0 } } }",
            json!({"status":"completed","value":1}),
        ),
        (
            "action root(x bool) -> int { case x { true where 42 => { return 1 } _ => { return 0 } } }",
            json!(true),
        ),
    ] {
        let p = plan(source);
        let inputs = Bindings::from([(p.scopes[0].parameters[0], Slot::Ready(input.into()))]);
        let error = advance(
            &p,
            "instance",
            &frame(),
            1,
            &inputs,
            &Journal::default(),
            |_| panic!("no effects")
        ).unwrap_err();
        assert!(matches!(error.message.as_str(), "managed class patterns require resolved type metadata" | "managed case guard requires a boolean"));
    }
}

#[test]
fn action_progression_refuses_incoherent_statement_projection() {
    let p = plan("action root() -> int { prompt \"number\" as t\nreturn 1 }");
    let counter = std::cell::Cell::new(0);
    let error = advance(
        &p,
        "instance",
        &frame(),
        1,
        &Bindings::new(),
        &Journal::default(),
        |_| {
            counter.set(counter.get() + 1);
            Ok(leaf(WorkState::Succeeded, Some(json!(counter.get()))))
        },
    )
    .unwrap_err();
    assert!(error.message.contains("stable projection"));
}

#[test]
fn action_progression_input_isolation_and_recorded_read_bounds_are_checked() {
    let p = plan("action child(x int) -> int { return x }\naction root(x int) -> int { child(x) as y\nreturn y }");
    let input = p.scopes[0].parameters[0];
    for inputs in [
        Bindings::from([(input, Slot::Pending)]),
        Bindings::from([
            (input, Slot::Ready(json!(1).into())),
            (p.scopes[1].parameters[0], Slot::Ready(json!(99).into())),
        ]),
    ] {
        assert!(advance(
            &p,
            "instance",
            &frame(),
            1,
            &inputs,
            &Journal::default(),
            |_| panic!("no effects")
        )
        .is_err());
    }
    let inputs = Bindings::from([(input, Slot::Ready(json!(1).into()))]);
    let first = advance(
        &p,
        "instance",
        &frame(),
        1,
        &inputs,
        &Journal::default(),
        |_| panic!("no effects"),
    )
    .unwrap();
    let mut captures = first.lowering.action_captures;
    captures[0].reads.insert(u64::MAX);
    assert!(advance(
        &p,
        "instance",
        &frame(),
        1,
        &inputs,
        &saved(&captures, first.lowering.action_root.as_ref().unwrap()),
        |_| panic!("no effects")
    )
    .unwrap_err()
    .message
    .contains("absent from its source plan"));
}

#[test]
fn action_progression_order_barrier_stops_new_work_but_not_saved_call_replay() {
    let p = plan("action child() -> int { return 2 }\naction root() -> int { then first <- prompt \"first\"\nchild() as child\nreturn child }");
    let pending = run(&p, &BTreeMap::new());
    assert!(pending.lowering.action_captures.is_empty());
    let done = run(
        &p,
        &BTreeMap::from([("unbound".into(), leaf(WorkState::Succeeded, Some(json!(1))))]),
    );
    assert_eq!(done.lowering.action_captures.len(), 1);
    let replay = advance(
        &p,
        "instance",
        &frame(),
        2,
        &Bindings::new(),
        &saved(
            &done.lowering.action_captures,
            done.lowering.action_root.as_ref().unwrap(),
        ),
        |_| Ok(leaf(WorkState::Pending, None)),
    )
    .unwrap();
    assert_eq!(replay.scopes.len(), 2, "captured child still activates");
    assert_eq!(
        replay.scopes[&ScopeId(1)].boundary,
        Boundary::Succeeded(json!(2).into())
    );
    assert!(
        matches!(replay.root.boundary, Boundary::Waiting(_)),
        "root still owns the pending source"
    );
}

#[test]
fn action_progression_identity_disambiguates_versions_firings_and_call_sites() {
    let base = frame();
    let identity = operation_identity("instance", &base, NodeId(0));
    assert_eq!(identity, operation_identity("instance", &base, NodeId(0)));
    assert_ne!(identity, operation_identity("other", &base, NodeId(0)));
    assert_ne!(identity, operation_identity("instance", &base, NodeId(1)));
    for changed in [
        Frame {
            version: "v2".into(),
            ..base.clone()
        },
        Frame {
            revision: "1".into(),
            ..base.clone()
        },
        Frame {
            rule: "other".into(),
            ..base.clone()
        },
        Frame {
            identity: Some("ticket".into()),
            ..base.clone()
        },
        Frame {
            trigger_event: Some("event".into()),
            ..base.clone()
        },
    ] {
        assert_ne!(
            identity,
            operation_identity("instance", &changed, NodeId(0))
        );
    }
}

#[test]
fn action_progression_unadmitted_leaf_keeps_a_ready_return_open() {
    let p = plan("action root() -> int { timer 1s as t\nreturn 1 }");
    let operation = p
        .nodes
        .iter()
        .find(|node| matches!(node.kind, NodeKind::Statement(_)))
        .unwrap()
        .result
        .unwrap();
    let result = advance(
        &p,
        "instance",
        &frame(),
        1,
        &Bindings::new(),
        &Journal::default(),
        |_| Ok(Leaf::Waiting(read_binding(operation, &Bindings::new()))),
    )
    .unwrap();
    assert_eq!(
        result.scopes[&ScopeId(0)].boundary,
        Boundary::Waiting(BTreeSet::from([WaitReason::Continuations]))
    );
    assert!(
        result.lowering.action_root.is_some(),
        "root capture is admission work even before a leaf is admitted"
    );
    assert!(result.lowering.effects.is_empty());
    assert_eq!(result.waiting.len(), 1);
}

#[test]
fn action_root_traversal_refuses_recorded_calls_without_root_and_callback_root_ownership() {
    let p = plan("action child() -> int { return 1 }\naction root() -> int { child() as result\nreturn result }");
    let first = run(&p, &BTreeMap::new());
    let context = super::super::journal::context_with_captures(
        r#"{"identity":null,"trigger_event_id":null,"bindings":[]}"#,
        &frame(),
        &first.lowering.action_captures,
        1,
    )
    .unwrap();
    let mut journal = Journal::default();
    journal
        .apply(&whipplescript_store::EventView {
            event_id: "legacy-call-only".into(),
            sequence: 2,
            event_type: "rule.committed".into(),
            payload_json:
                json!({"rule":"root","context":serde_json::from_str::<Value>(&context).unwrap()})
                    .to_string(),
            source: "test".into(),
            occurred_at: "test".into(),
        })
        .unwrap();
    assert!(advance(
        &p,
        "instance",
        &frame(),
        2,
        &Bindings::new(),
        &journal,
        |_| panic!("no effects")
    )
    .unwrap_err()
    .message
    .contains("no admitted root capture"));
    let p = plan("action root() -> int { timer 1s as t\nreturn 1 }");
    assert!(advance(
        &p,
        "instance",
        &frame(),
        1,
        &Bindings::new(),
        &Journal::default(),
        |_| Ok(Leaf::Ready {
            lowering: Box::new(OwnedLowering {
                action_root: first.lowering.action_root.clone(),
                ..Default::default()
            }),
            value: Some(Value::Null.into()),
            work: Some(OwnedWork {
                state: WorkState::Succeeded,
                causes: BTreeMap::new()
            })
        })
    )
    .is_err());
}

#[test]
fn managed_record_merge_keeps_first_location_but_refuses_conflicting_content() {
    use crate::lowering::OwnedFact;
    let p = plan("action root() -> null { return null }");
    let fact = OwnedFact {
        fact_id: "same".into(),
        name: "Result".into(),
        key: "key".into(),
        value_json: "{}".into(),
        schema_id: Some("Result".into()),
        provenance_class: "rule".into(),
        correlation_id: None,
        source_span_json: Some("first".into()),
        validity_json: None,
    };
    let mut target = OwnedLowering {
        facts: vec![fact.clone()],
        ..Default::default()
    };
    let second = OwnedFact {
        source_span_json: Some("second".into()),
        ..fact.clone()
    };
    merge(
        &p,
        NodeId(0),
        &mut target,
        OwnedLowering {
            facts: vec![second],
            ..Default::default()
        },
        false,
    )
    .unwrap();
    assert_eq!(target.facts, vec![fact.clone()]);
    for changed in [
        OwnedFact {
            value_json: "{\"changed\":true}".into(),
            ..fact.clone()
        },
        OwnedFact {
            provenance_class: "effect".into(),
            ..fact
        },
    ] {
        let issue = merge(
            &p,
            NodeId(0),
            &mut target,
            OwnedLowering {
                facts: vec![changed],
                ..Default::default()
            },
            false,
        )
        .unwrap_err();
        assert!(issue.message.contains("conflicting assertions"));
    }
}

#[path = "recovery_tests.rs"]
mod recovery_tests;

#[path = "prefix_tests.rs"]
mod prefix_tests;

#[path = "region_prefix_tests.rs"]
mod region_prefix_tests;
