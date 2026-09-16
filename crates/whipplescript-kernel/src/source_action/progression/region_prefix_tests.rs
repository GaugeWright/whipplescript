use super::*;
use crate::source_action::journal::{
    regions::{context_with_regions, Cut, Phase},
    root::{context_with_root, RootCapture},
};
use serde_json::{json, Value};

fn journal(frame: &Frame, region: NodeId, phase: Phase, frontier: i64) -> Journal {
    journal_with_cuts(frame, &[(region, phase)], frontier)
}

fn journal_with_cuts(frame: &Frame, phases: &[(NodeId, Phase)], frontier: i64) -> Journal {
    let context = context_with_root(
        r#"{"identity":null,"trigger_event_id":null,"bindings":[]}"#,
        frame,
        Some(&RootCapture {
            inputs: vec![],
            frontier,
        }),
        frontier,
    )
    .expect("region prefix fixture");
    let context = context_with_regions(
        &context,
        frame,
        &phases
            .iter()
            .map(|(region, phase)| Cut {
                region: region.0 as u64,
                frontier,
                phase: *phase,
            })
            .collect::<Vec<_>>(),
        frontier,
    )
    .expect("region prefix fixture");
    let mut journal = Journal::default();
    journal
        .apply(&whipplescript_store::EventView {
            event_id: "commit".into(),
            sequence: frontier + 1,
            event_type: "rule.committed".into(),
            payload_json: json!({
                "rule": frame.rule,
                "context": serde_json::from_str::<Value>(&context).expect("region prefix fixture")
            })
            .to_string(),
            source: "test".into(),
            occurred_at: "test".into(),
        })
        .expect("region prefix fixture");
    journal
}

fn append_cut(journal: &mut Journal, frame: &Frame, region: NodeId, phase: Phase, frontier: i64) {
    let context = context_with_regions(
        r#"{"identity":null,"trigger_event_id":null,"bindings":[]}"#,
        frame,
        &[Cut {
            region: region.0 as u64,
            frontier,
            phase,
        }],
        frontier,
    )
    .expect("region prefix fixture");
    journal
        .apply(&whipplescript_store::EventView {
            event_id: format!("commit-{frontier}"),
            sequence: frontier + 1,
            event_type: "rule.committed".into(),
            payload_json: json!({
                "rule": frame.rule,
                "context": serde_json::from_str::<Value>(&context).expect("region prefix fixture")
            })
            .to_string(),
            source: "test".into(),
            occurred_at: "test".into(),
        })
        .expect("region prefix fixture");
}

fn region(plan: &ActionPlan) -> NodeId {
    NodeId(
        plan.nodes
            .iter()
            .position(|node| matches!(node.kind, NodeKind::Region { .. }))
            .expect("region prefix fixture"),
    )
}

#[test]
fn reached_unentered_region_observes_its_condition_without_selecting_an_arm() {
    let plan =
        plan("action root() -> int { during true { return 7 } on lapse { fail 8 }\nreturn 9 }");
    let frame = frame();
    let region = region(&plan);
    let journal = journal_with_cuts(&frame, &[], 1);
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        1,
        &Bindings::new(),
        &journal,
        |_| panic!("unentered region has no selected statements"),
    )
    .expect("region condition fixture");

    assert!(matches!(
        projected.region_conditions[&region].state,
        State::Ready(Value::Bool(true))
    ));
    assert!(!projected.selected_blocks.contains_key(&region));
    assert!(projected.chosen_results.is_empty());
    assert!(matches!(projected.root.boundary, Boundary::Waiting(_)));
    assert_eq!(
        crate::source_action::regions::phase_cuts(&plan, &journal, &frame, &projected),
        vec![Cut {
            region: region.0 as u64,
            frontier: 1,
            phase: Phase::Holding,
        }]
    );
}

#[test]
fn until_region_condition_records_whether_the_region_still_holds() {
    let plan =
        plan("action root() -> int { until true { return 7 } on lapse { fail 8 }\nreturn 9 }");
    let frame = frame();
    let region = region(&plan);
    let journal = journal_with_cuts(&frame, &[], 1);
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        1,
        &Bindings::new(),
        &journal,
        |_| panic!("unentered region has no selected statements"),
    )
    .expect("region condition fixture");

    assert!(matches!(
        projected.region_conditions[&region].state,
        State::Ready(Value::Bool(false))
    ));
    assert_eq!(
        crate::source_action::regions::phase_cuts(&plan, &journal, &frame, &projected),
        vec![Cut {
            region: region.0 as u64,
            frontier: 1,
            phase: Phase::Lapsed,
        }]
    );
}

#[test]
fn unavailable_region_condition_remains_blocked_and_emits_no_cut() {
    let plan = plan(
        "action root() -> int { timer 1s as flag\nduring flag { return 7 } on lapse { fail 8 }\nreturn 9 }",
    );
    let frame = frame();
    let region = region(&plan);
    let input = plan.nodes[..region.0]
        .iter()
        .find_map(|node| node.result)
        .expect("blocked region fixture");
    let journal = Journal::default();
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        1,
        &Bindings::new(),
        &journal,
        |_| Ok(leaf(WorkState::Pending, None)),
    )
    .expect("blocked region fixture");

    assert!(matches!(
        &projected.region_conditions[&region].state,
        State::Blocked { waiting, causes }
            if waiting == &BTreeSet::from([input]) && causes.is_empty()
    ));
    assert!(
        crate::source_action::regions::phase_cuts(&plan, &journal, &frame, &projected).is_empty()
    );
}

#[test]
fn non_boolean_region_condition_is_refused_at_the_region() {
    let plan = plan("action root() -> int { during 1 { return 7 } on lapse { fail 8 }\nreturn 9 }");
    let frame = frame();
    let region = region(&plan);
    let issue = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        1,
        &Bindings::new(),
        &Journal::default(),
        |_| panic!("invalid region has no selected statements"),
    )
    .unwrap_err();

    assert_eq!(issue.node, region);
    assert_eq!(issue.span, plan.nodes[region.0].span);
    assert!(issue
        .message
        .contains("region condition requires a boolean"));
}

#[test]
fn action_region_entry_lapse_selects_only_the_lapse_arm_and_binds_empty_progress() {
    let plan = plan(
        "action root() -> int { during false { return 7 } on lapse as progress { return 8 }\nreturn 9 }",
    );
    let frame = frame();
    let region = region(&plan);
    let journal = journal(&frame, region, Phase::Lapsed, 1);
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        1,
        &Bindings::new(),
        &journal,
        |_| panic!("return-only region has no statements"),
    )
    .expect("entry lapse fixture");
    let NodeKind::Region {
        lapse_binding,
        lapse_body,
        ..
    } = plan.nodes[region.0].kind
    else {
        panic!("region")
    };
    let progress = lapse_binding.expect("entry lapse fixture");
    assert!(matches!(
        &projected.bindings[&progress],
        Slot::Ready(value) if value.value == json!({"steps": {}})
    ));
    assert_eq!(projected.selected_blocks[&region], Some(lapse_body));
    let scope = plan.blocks[plan.root.0].scope.expect("entry lapse fixture");
    assert!(matches!(
        &projected.chosen_results[&scope].1,
        ChosenResult::Return(value) if value.value == json!(8)
    ));
    assert_eq!(
        projected.chosen_results.len(),
        1,
        "the lexical tail stays closed after lapse"
    );
}

#[test]
fn action_region_prefix_preserves_a_held_return_candidate_without_opening_the_tail() {
    let plan =
        plan("action root() -> int { during true { return 7 } on lapse { fail 8 }\nreturn 9 }");
    let frame = frame();
    let region = region(&plan);
    let journal = journal(&frame, region, Phase::Holding, 1);
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        1,
        &Bindings::new(),
        &journal,
        |_| panic!("return-only region has no statements"),
    )
    .expect("region prefix fixture");
    let scope = plan.blocks[plan.root.0]
        .scope
        .expect("region prefix fixture");
    let chosen = &projected.chosen_results[&scope];
    assert!(matches!(&chosen.1, ChosenResult::Return(value) if value.value == json!(7)));
    let NodeKind::Region { body, .. } = plan.nodes[region.0].kind else {
        panic!("region")
    };
    assert_eq!(projected.selected_blocks[&region], Some(body));
    assert!(matches!(
        projected.scopes[&scope].boundary,
        Boundary::Waiting(_)
    ));
    assert_eq!(
        projected.chosen_results.len(),
        1,
        "the lexical tail's second return stays unselected"
    );
    let selected = crate::source_action::regions::Layout::build(&plan)
        .expect("region prefix fixture")
        .region(region)
        .expect("region prefix fixture")
        .held
        .selected_held(region, &projected)
        .expect("region prefix fixture");
    assert_eq!(&selected.results[&scope], chosen);
    assert!(projected.region_complete.contains(&region));
    assert_eq!(
        crate::source_action::regions::phase_cuts(&plan, &journal, &frame, &projected),
        vec![Cut {
            region: region.0 as u64,
            frontier: 1,
            phase: Phase::Exited,
        }]
    );
}

#[test]
fn lapsed_region_refuses_a_retained_result_that_conflicts_with_current_selection() {
    let plan = plan(
        "action root() -> int { return 1\nduring true { return 2 } on lapse { timer 1s as cleanup } }",
    );
    let frame = frame();
    let region = region(&plan);
    let NodeKind::Region { body, .. } = plan.nodes[region.0].kind else {
        panic!("retained result fixture")
    };
    let held_return = plan.blocks[body.0]
        .nodes
        .iter()
        .copied()
        .find(|node| matches!(plan.nodes[node.0].kind, NodeKind::Return(_)))
        .expect("retained result fixture");
    let scope = plan.blocks[plan.root.0]
        .scope
        .expect("retained result fixture");
    let mut journal = journal(&frame, region, Phase::Holding, 1);
    append_cut(&mut journal, &frame, region, Phase::Lapsed, 2);
    let retained = BTreeMap::from([(
        region,
        RetainedRegion {
            owned: BTreeMap::new(),
            results: BTreeMap::from([(
                scope,
                (held_return, ChosenResult::Return(Argument::from(json!(2)))),
            )]),
            progress: Argument::from(json!({"steps": {}})),
        },
    )]);

    let issue = advance_captured_regions_with_retained(
        &plan,
        "instance",
        &frame,
        2,
        &Bindings::new(),
        &journal,
        &retained,
        |_| Ok(leaf(WorkState::Pending, None)),
    )
    .unwrap_err();

    assert_eq!(issue.node, region);
    assert_eq!(issue.message, "two selected results in one action");
}

#[test]
fn held_region_lapses_while_selected_work_is_unsettled() {
    let plan = plan(
        "action root() -> int { during false { timer 1s as held } on lapse { return 8 }\nreturn 9 }",
    );
    let frame = frame();
    let region = region(&plan);
    let journal = journal(&frame, region, Phase::Holding, 1);
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        2,
        &Bindings::new(),
        &journal,
        |_| Ok(leaf(WorkState::Pending, None)),
    )
    .expect("held lapse fixture");

    assert!(!projected.region_complete.contains(&region));
    assert_eq!(
        crate::source_action::regions::phase_cuts(&plan, &journal, &frame, &projected),
        vec![Cut {
            region: region.0 as u64,
            frontier: 2,
            phase: Phase::Lapsed,
        }]
    );
}

#[test]
fn completed_held_region_exits_before_a_same_frontier_false_observation_can_lapse_it() {
    let plan = plan(
        "action root() -> int { during false { timer 1s as held } on lapse { return 8 }\nreturn 9 }",
    );
    let frame = frame();
    let region = region(&plan);
    let journal = journal(&frame, region, Phase::Holding, 1);
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        2,
        &Bindings::new(),
        &journal,
        |_| Ok(leaf(WorkState::Succeeded, Some(Value::Null))),
    )
    .expect("held exit fixture");

    assert!(projected.region_complete.contains(&region));
    assert_eq!(
        crate::source_action::regions::phase_cuts(&plan, &journal, &frame, &projected),
        vec![Cut {
            region: region.0 as u64,
            frontier: 2,
            phase: Phase::Exited,
        }]
    );
}

#[test]
fn outer_lapse_suppresses_a_same_frontier_nested_entry() {
    let plan = plan(
        "action root() -> int { during false { during true { return 7 } on lapse { fail 8 } } on lapse { return 9 } }",
    );
    let frame = frame();
    let regions = plan
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| matches!(node.kind, NodeKind::Region { .. }))
        .map(|(index, _)| NodeId(index))
        .collect::<Vec<_>>();
    let journal = journal(&frame, regions[0], Phase::Holding, 1);
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        2,
        &Bindings::new(),
        &journal,
        |_| panic!("return-only regions have no statements"),
    )
    .expect("nested phase fixture");

    assert_eq!(projected.region_conditions.len(), 2);
    assert_eq!(
        crate::source_action::regions::phase_cuts(&plan, &journal, &frame, &projected),
        vec![Cut {
            region: regions[0].0 as u64,
            frontier: 2,
            phase: Phase::Lapsed,
        }],
        "a nested region cannot enter after its enclosing held arm lapses"
    );
}

#[test]
fn action_region_prefix_clean_exit_opens_the_lexical_tail() {
    let plan = plan(
        "action root() -> int { during true { timer 1s as held } on lapse { fail 8 }\nreturn 9 }",
    );
    let frame = frame();
    let region = region(&plan);
    let journal = journal(&frame, region, Phase::Exited, 1);
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        1,
        &Bindings::new(),
        &journal,
        |_| Ok(leaf(WorkState::Succeeded, Some(Value::Null))),
    )
    .expect("region prefix fixture");
    let scope = plan.blocks[plan.root.0]
        .scope
        .expect("region prefix fixture");
    assert!(matches!(
        &projected.scopes[&scope].boundary,
        Boundary::Succeeded(value) if value.value == json!(9)
    ));
    assert!(projected.chosen_results.values().any(
        |(_, result)| matches!(result, ChosenResult::Return(value) if value.value == json!(9))
    ));
}

#[test]
fn action_region_clean_exit_propagates_held_failure_to_its_lexical_handler() {
    let plan = plan(
        "action root() -> int { during true { timer 1s as held } on lapse { fail 8 }\nreturn 9\non failure as problem { return 7 } }",
    );
    let frame = frame();
    let region = region(&plan);
    let journal = journal(&frame, region, Phase::Exited, 1);
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        1,
        &Bindings::new(),
        &journal,
        |statement| {
            assert_eq!(label(&statement), "held");
            Ok(Leaf::Ready {
                lowering: Box::default(),
                value: None,
                work: Some(OwnedWork {
                    state: WorkState::Failed(Disposition::Propagate),
                    causes: BTreeMap::from([(
                        CauseId("held-failure".into()),
                        ObservedCause {
                            cause: Cause {
                                kind: FailureKind::Failed,
                                payload: json!({"reason": "held failed"}),
                                evidence: BTreeSet::from(["held-terminal".into()]),
                            },
                            recovered: false,
                        },
                    )]),
                }),
            })
        },
    )
    .expect("region handler fixture");
    let scope = plan.blocks[plan.root.0]
        .scope
        .expect("region handler fixture");
    assert!(matches!(
        &projected.scopes[&scope].boundary,
        Boundary::Succeeded(value) if value.value == json!(7)
    ));
    assert!(projected.root.causes[&CauseId("held-failure".into())].recovered);
    let handler = plan
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(node.kind, NodeKind::OnFailure { .. }).then_some(NodeId(index))
        })
        .expect("region handler fixture");
    assert!(projected.selected_blocks[&handler].is_some());
}

#[test]
fn action_region_prefix_holding_cut_never_opens_a_successive_region() {
    let plan = plan(
        "action root() -> int { during true { timer 1s as first } on lapse { fail 1 }\nduring true { return 2 } on lapse { fail 2 }\nreturn 3 }",
    );
    let frame = frame();
    let regions = plan
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| matches!(node.kind, NodeKind::Region { .. }))
        .map(|(index, _)| NodeId(index))
        .collect::<Vec<_>>();
    let journal = journal(&frame, regions[0], Phase::Holding, 1);
    let projected = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        1,
        &Bindings::new(),
        &journal,
        |_| Ok(leaf(WorkState::Pending, None)),
    )
    .expect("region prefix fixture");
    assert_eq!(projected.selected_blocks.len(), 1);
    assert!(projected.selected_blocks.contains_key(&regions[0]));
    assert!(!projected.selected_blocks.contains_key(&regions[1]));
    assert!(projected.chosen_results.is_empty());
    let layout =
        crate::source_action::regions::Layout::build(&plan).expect("region prefix fixture");
    let issue = layout
        .region(regions[1])
        .expect("region prefix fixture")
        .held
        .selected_held(regions[1], &projected)
        .unwrap_err();
    assert!(issue.contains("unreachable from its captured root"));
}

#[test]
fn action_region_prefix_refuses_a_lapse_after_a_held_prefix() {
    let plan = plan(
        "action root() -> int { during true { during true { return 1 } on lapse { fail 2 } } on lapse { fail 3 }\nreturn 4 }",
    );
    let frame = frame();
    let regions = plan
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| matches!(node.kind, NodeKind::Region { .. }))
        .map(|(index, _)| NodeId(index))
        .collect::<Vec<_>>();
    let mut journal = journal_with_cuts(
        &frame,
        &[(regions[0], Phase::Holding), (regions[1], Phase::Holding)],
        1,
    );
    append_cut(&mut journal, &frame, regions[1], Phase::Lapsed, 2);
    let issue = advance_captured_regions(
        &plan,
        "instance",
        &frame,
        2,
        &Bindings::new(),
        &journal,
        |_| panic!("return-only regions have no statements"),
    )
    .unwrap_err();
    assert!(issue.message.contains("through a lapsed region"));
}
