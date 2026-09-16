use super::*;
use crate::source_action::{
    journal::{
        regions::{Cut, Phase},
        root::RootCapture,
    },
    rule, Boundary, WorkState,
};
use whipplescript_parser::action_plan::{resolved::resolve_rule_types, NodeId, NodeKind};

const SOURCE: &str = "@service\nworkflow RegionHeld\nrule finish when started => { during true { timer 1s as held } on lapse { timer 2s as cleanup }\ntimer 3s as tail }";

fn setup_source(
    source: &str,
    phase: Phase,
) -> (
    Fixture,
    whipplescript_parser::action_plan::resolved::TypedActionPlan,
    NodeId,
    i64,
    Vec<whipplescript_store::EventView>,
) {
    let parsed = whipplescript_parser::parse_program(source);
    assert!(parsed.diagnostics.is_empty());
    let typed = resolve_rule_types(&parsed.program, "finish").expect("region prefix fixture");
    let region = NodeId(
        typed
            .plan
            .nodes
            .iter()
            .position(|node| matches!(node.kind, NodeKind::Region { .. }))
            .expect("region prefix fixture"),
    );
    let mut fixture = Fixture::with_source(
        SqliteStore::open_in_memory().expect("region prefix fixture"),
        source,
    );
    let events = fixture.events();
    let frontier = events.last().expect("region prefix fixture").sequence;
    let lowering = OwnedLowering {
        action_root: Some(RootCapture {
            inputs: vec![],
            frontier,
        }),
        action_regions: vec![Cut {
            region: region.0 as u64,
            frontier,
            phase,
        }],
        ..Default::default()
    };
    fixture
        .commit(&lowering, &Journal::default())
        .expect("region prefix fixture");
    (fixture, typed, region, frontier, events)
}

fn setup(
    phase: Phase,
) -> (
    Fixture,
    whipplescript_parser::action_plan::resolved::TypedActionPlan,
    NodeId,
    i64,
    Vec<whipplescript_store::EventView>,
) {
    setup_source(SOURCE, phase)
}

fn context<'a>(
    fixture: &'a Fixture,
    typed: &'a whipplescript_parser::action_plan::resolved::TypedActionPlan,
    journal: &'a Journal,
    frontier: i64,
    events: &'a [whipplescript_store::EventView],
) -> rule::Context<'a> {
    rule::Context {
        ir: &fixture.ir,
        typed,
        instance: &fixture.instance,
        frame: &fixture.frame,
        admission: &fixture.context,
        frontier,
        journal,
        effects: &[],
        events,
        facts: &[],
        coercion_fingerprint: "fixture",
        source_path: None,
    }
}

fn stored_context<'a>(
    fixture: &'a Fixture,
    typed: &'a whipplescript_parser::action_plan::resolved::TypedActionPlan,
    journal: &'a Journal,
) -> rule::StoredContext<'a> {
    rule::StoredContext {
        ir: &fixture.ir,
        typed,
        instance: &fixture.instance,
        frame: &fixture.frame,
        admission: &fixture.context,
        journal,
        coercion_fingerprint: "fixture",
        source_path: None,
    }
}

#[test]
fn action_region_live_projection_stages_holding_and_held_work_in_one_commit() {
    let parsed = whipplescript_parser::parse_program(SOURCE);
    let typed = resolve_rule_types(&parsed.program, "finish").expect("region phase fixture");
    let region = NodeId(
        typed
            .plan
            .nodes
            .iter()
            .position(|node| matches!(node.kind, NodeKind::Region { .. }))
            .expect("region phase fixture"),
    );
    let mut fixture = Fixture::with_source(
        SqliteStore::open_in_memory().expect("region phase fixture"),
        SOURCE,
    );
    let events = fixture.events();
    let frontier = events.last().expect("region phase fixture").sequence;
    let journal = fixture.journal();
    let projected = rule::project_regions(context(&fixture, &typed, &journal, frontier, &events))
        .expect("region phase fixture");

    assert_eq!(
        projected.lowering.action_regions,
        vec![Cut {
            region: region.0 as u64,
            frontier,
            phase: Phase::Holding,
        }]
    );
    assert_eq!(projected.lowering.effects.len(), 1);
    assert!(journal.region(&fixture.frame, region.0 as u64).is_none());
    assert!(fixture
        .kernel
        .store()
        .list_effects(&fixture.instance)
        .expect("region phase fixture")
        .is_empty());

    fixture
        .commit(&projected.lowering, &journal)
        .expect("region phase fixture");
    assert_eq!(
        fixture
            .journal()
            .region(&fixture.frame, region.0 as u64)
            .expect("region phase fixture")
            .latest()
            .expect("region phase fixture")
            .phase,
        Phase::Holding
    );
    assert_eq!(
        fixture
            .kernel
            .store()
            .list_effects(&fixture.instance)
            .expect("region phase fixture")
            .len(),
        1
    );
}

#[test]
fn action_region_live_projection_stages_entry_lapse_without_held_work() {
    let source = "@service\nworkflow RegionLapse\nrule finish when started => { during false { timer 1s as held } on lapse as progress { timer 2s as cleanup }\ntimer 3s as tail }";
    let parsed = whipplescript_parser::parse_program(source);
    let typed = resolve_rule_types(&parsed.program, "finish").expect("region phase fixture");
    let region = NodeId(
        typed
            .plan
            .nodes
            .iter()
            .position(|node| matches!(node.kind, NodeKind::Region { .. }))
            .expect("region phase fixture"),
    );
    let fixture = Fixture::with_source(
        SqliteStore::open_in_memory().expect("region phase fixture"),
        source,
    );
    let events = fixture.events();
    let frontier = events.last().expect("region phase fixture").sequence;
    let journal = fixture.journal();
    let projected = rule::project_regions(context(&fixture, &typed, &journal, frontier, &events))
        .expect("region phase fixture");
    let NodeKind::Region {
        body,
        lapse_binding,
        lapse_body,
        ..
    } = typed.plan.nodes[region.0].kind
    else {
        panic!("region phase fixture")
    };

    assert_eq!(
        projected.lowering.action_regions,
        vec![Cut {
            region: region.0 as u64,
            frontier,
            phase: Phase::Lapsed,
        }]
    );
    assert_eq!(projected.selected_blocks[&region], Some(lapse_body));
    assert!(!projected.active_blocks.contains(&body));
    assert_eq!(projected.lowering.effects.len(), 1);
    let progress = lapse_binding.expect("region phase fixture");
    assert!(matches!(
        &projected.bindings[&progress],
        crate::source_action::arguments::Slot::Ready(value)
            if value.value == serde_json::json!({"steps": {"held": "not_requested"}})
    ));
    assert!(journal.region(&fixture.frame, region.0 as u64).is_none());
}

#[test]
fn action_region_store_backed_lapse_retains_only_admitted_work_and_freezes_progress() {
    let source = "@service\nworkflow RegionLapse\nclass Stop { id string }\nrule finish when started => { during empty(Stop) { timer 1s as held\nafter held succeeds { timer 4s as late } } on lapse as progress { timer 2s as cleanup }\ntimer 3s as tail }";
    let parsed = whipplescript_parser::parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed = resolve_rule_types(&parsed.program, "finish").expect("later lapse fixture");
    let region = NodeId(
        typed
            .plan
            .nodes
            .iter()
            .position(|node| matches!(node.kind, NodeKind::Region { .. }))
            .expect("later lapse fixture"),
    );
    let path = std::env::temp_dir().join(format!(
        "whip-action-region-lapse-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("later lapse fixture")
            .as_nanos()
    ));
    let mut fixture = Fixture::with_source(
        SqliteStore::open(&path).expect("later lapse fixture"),
        source,
    );
    let journal = fixture.journal();
    let frontier = fixture
        .events()
        .last()
        .expect("later lapse fixture")
        .sequence;
    let holding = rule::project_regions_from_store(
        fixture.kernel.store(),
        stored_context(&fixture, &typed, &journal),
        frontier,
    )
    .expect("later lapse fixture");
    let held_effect = holding.lowering.effects[0].effect_id.clone();
    fixture
        .commit(&holding.lowering, &journal)
        .expect("later lapse fixture");
    let instance = fixture.instance.clone();
    fixture
        .kernel
        .derive_fact(&instance, "Stop", "stop", r#"{"id":"stop"}"#, None, None)
        .expect("later lapse fixture");

    let journal = fixture.journal();
    let frontier = fixture
        .events()
        .last()
        .expect("later lapse fixture")
        .sequence;
    let lapsed = rule::project_regions_from_store(
        fixture.kernel.store(),
        stored_context(&fixture, &typed, &journal),
        frontier,
    )
    .expect("later lapse fixture");
    let NodeKind::Region {
        body,
        lapse_binding,
        lapse_body,
        ..
    } = typed.plan.nodes[region.0].kind
    else {
        panic!("later lapse fixture")
    };
    let progress = lapse_binding.expect("later lapse fixture");

    assert_eq!(lapsed.lowering.action_regions[0].phase, Phase::Lapsed);
    assert_eq!(
        lapsed.lowering.cancels.as_slice(),
        std::slice::from_ref(&held_effect)
    );
    assert_eq!(lapsed.selected_blocks[&region], Some(lapse_body));
    assert!(!lapsed.active_blocks.contains(&body));
    assert_eq!(lapsed.lowering.effects.len(), 1, "only cleanup is drafted");
    assert!(matches!(
        &lapsed.bindings[&progress],
        crate::source_action::arguments::Slot::Ready(value)
            if value.value == serde_json::json!({"steps": {"held": "cancelled_by_lapse", "late": "not_requested"}})
    ));

    fixture
        .commit(&lapsed.lowering, &journal)
        .expect("later lapse commits atomically");

    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = fixture;
    drop(kernel);
    let mut fixture = Fixture {
        kernel: RuntimeKernel::new(wrap(
            SqliteStore::open(&path).expect("later lapse fixture reopens"),
        )),
        ir,
        instance,
        frame,
        context,
    };
    let journal = fixture.journal();
    let frontier = fixture
        .events()
        .last()
        .expect("later lapse fixture")
        .sequence;
    let healing = rule::project_regions_from_store(
        fixture.kernel.store(),
        stored_context(&fixture, &typed, &journal),
        frontier,
    )
    .expect("durably lapsed region heals its cancellation gap");
    assert!(healing.lowering.action_regions.is_empty());
    assert_eq!(
        healing.lowering.cancels.as_slice(),
        std::slice::from_ref(&held_effect)
    );
    assert!(healing.lowering.effects.is_empty());
    assert!(matches!(
        &healing.bindings[&progress],
        crate::source_action::arguments::Slot::Ready(value)
            if value.value == serde_json::json!({"steps": {"held": "cancelled_by_lapse", "late": "not_requested"}})
    ));
    let healing_event = fixture
        .commit(&healing.lowering, &journal)
        .expect("cancellation repair commits");
    crate::rule_pass::apply_rule_cancels(
        &mut fixture.kernel,
        &fixture.instance,
        &fixture.frame.rule,
        &healing.lowering.cancels,
        &healing_event.event_id,
    )
    .expect("replay applies the missed cancellation");

    let journal = fixture.journal();
    let frontier = fixture
        .events()
        .last()
        .expect("later lapse fixture")
        .sequence;
    let replayed = rule::project_regions_from_store(
        fixture.kernel.store(),
        stored_context(&fixture, &typed, &journal),
        frontier,
    )
    .expect("settled lapsed region replays");
    assert!(replayed.lowering.action_regions.is_empty());
    assert!(replayed.lowering.cancels.is_empty());
    assert!(replayed.lowering.effects.is_empty());
    assert!(replayed.owned.values().any(|work| {
        work.state == WorkState::Failed(crate::source_action::Disposition::Recovered)
            && work.causes.values().any(|cause| {
                cause.cause.kind == crate::source_action::FailureKind::Cancelled && !cause.recovered
            })
    }));
    assert!(
        matches!(
            &replayed.bindings[&progress],
            crate::source_action::arguments::Slot::Ready(value)
                if value.value == serde_json::json!({"steps": {"held": "cancelled_by_lapse", "late": "not_requested"}})
        ),
        "{:?}",
        replayed.bindings[&progress]
    );
    drop(fixture);
    let _ = std::fs::remove_file(path);
}

#[test]
fn action_region_lapse_suppresses_a_late_success_continuation() {
    let source = "@service\nworkflow RegionLapse\nclass Stop { id string }\nrule finish when started => { during empty(Stop) { timer 1s as held\nafter held succeeds { timer 4s as late } } on lapse as progress { timer 2s as cleanup } }";
    let parsed = whipplescript_parser::parse_program(source);
    let typed = resolve_rule_types(&parsed.program, "finish").expect("late continuation fixture");
    let region = NodeId(
        typed
            .plan
            .nodes
            .iter()
            .position(|node| matches!(node.kind, NodeKind::Region { .. }))
            .expect("late continuation fixture"),
    );
    let mut fixture = Fixture::with_source(
        SqliteStore::open_in_memory().expect("late continuation fixture"),
        source,
    );
    let journal = fixture.journal();
    let frontier = fixture
        .events()
        .last()
        .expect("late continuation fixture")
        .sequence;
    let holding = rule::project_regions_from_store(
        fixture.kernel.store(),
        stored_context(&fixture, &typed, &journal),
        frontier,
    )
    .expect("late continuation fixture");
    let held_effect = holding.lowering.effects[0].effect_id.clone();
    fixture
        .commit(&holding.lowering, &journal)
        .expect("late continuation fixture");
    timer_fixture::settle(&mut fixture, &held_effect);
    let instance = fixture.instance.clone();
    fixture
        .kernel
        .derive_fact(&instance, "Stop", "stop", r#"{"id":"stop"}"#, None, None)
        .expect("late continuation fixture");

    let journal = fixture.journal();
    let frontier = fixture
        .events()
        .last()
        .expect("late continuation fixture")
        .sequence;
    let lapsed = rule::project_regions_from_store(
        fixture.kernel.store(),
        stored_context(&fixture, &typed, &journal),
        frontier,
    )
    .expect("late continuation fixture");
    let NodeKind::Region { lapse_binding, .. } = typed.plan.nodes[region.0].kind else {
        panic!("late continuation fixture")
    };
    let progress = lapse_binding.expect("late continuation fixture");

    assert_eq!(lapsed.lowering.action_regions[0].phase, Phase::Lapsed);
    assert!(lapsed.lowering.cancels.is_empty());
    assert_eq!(lapsed.lowering.effects.len(), 1, "only cleanup is drafted");
    assert!(matches!(
        &lapsed.bindings[&progress],
        crate::source_action::arguments::Slot::Ready(value)
            if value.value == serde_json::json!({
                "held": null,
                "steps": {"held": "completed", "late": "not_requested"}
            })
    ));
}

#[test]
fn outer_lapse_reconstructs_an_already_lapsed_nested_region() {
    let source = "@service\nworkflow NestedRegionLapse\nclass StopInner { id string }\nclass StopOuter { id string }\nrule finish when started => { during empty(StopOuter) { during empty(StopInner) { timer 1s as inner_work } on lapse as inner_progress { timer 2s as inner_cleanup }\ntimer 3s as outer_work } on lapse as outer_progress { timer 4s as outer_cleanup } }";
    let parsed = whipplescript_parser::parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed = resolve_rule_types(&parsed.program, "finish").expect("nested lapse fixture");
    let regions = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| matches!(node.kind, NodeKind::Region { .. }))
        .map(|(index, _)| NodeId(index))
        .collect::<Vec<_>>();
    assert_eq!(regions.len(), 2);
    let outer = regions[0];
    let inner = regions[1];
    let mut fixture = Fixture::with_source(
        SqliteStore::open_in_memory().expect("nested lapse fixture"),
        "@service\nworkflow NestedRegionLapse\nclass StopInner { id string }\nclass StopOuter { id string }\nrule finish when started => { during true { timer 1s as held } on lapse { timer 2s as cleanup }\ntimer 3s as tail }",
    );

    for expected in [outer, inner] {
        let journal = fixture.journal();
        let frontier = fixture
            .events()
            .last()
            .expect("nested lapse fixture")
            .sequence;
        let holding = rule::project_regions_from_store(
            fixture.kernel.store(),
            stored_context(&fixture, &typed, &journal),
            frontier,
        )
        .expect("nested region enters");
        assert_eq!(holding.lowering.action_regions.len(), 1);
        assert_eq!(holding.lowering.action_regions[0].region, expected.0 as u64);
        assert_eq!(holding.lowering.action_regions[0].phase, Phase::Holding);
        fixture
            .commit(&holding.lowering, &journal)
            .expect("nested holding cut commits");
    }

    let instance = fixture.instance.clone();
    fixture
        .kernel
        .derive_fact(
            &instance,
            "StopInner",
            "stop-inner",
            r#"{"id":"stop-inner"}"#,
            None,
            None,
        )
        .expect("nested lapse fixture");
    let journal = fixture.journal();
    let frontier = fixture
        .events()
        .last()
        .expect("nested lapse fixture")
        .sequence;
    let inner_lapse = rule::project_regions_from_store(
        fixture.kernel.store(),
        stored_context(&fixture, &typed, &journal),
        frontier,
    )
    .expect("inner region lapses");
    assert_eq!(inner_lapse.lowering.action_regions.len(), 1);
    assert_eq!(
        inner_lapse.lowering.action_regions[0].region,
        inner.0 as u64
    );
    assert_eq!(inner_lapse.lowering.action_regions[0].phase, Phase::Lapsed);
    fixture
        .commit(&inner_lapse.lowering, &journal)
        .expect("inner lapse commits");

    // A holding cut is also the durable membership checkpoint. Record a later
    // outer checkpoint after the inner lapse so reconstructing the outer held
    // prefix must cross the nested lapsed region.
    let journal = fixture.journal();
    let frontier = fixture
        .events()
        .last()
        .expect("nested lapse fixture")
        .sequence;
    fixture
        .commit(
            &OwnedLowering {
                action_regions: vec![Cut {
                    region: outer.0 as u64,
                    frontier,
                    phase: Phase::Holding,
                }],
                ..Default::default()
            },
            &journal,
        )
        .expect("later outer held checkpoint commits");

    fixture
        .kernel
        .derive_fact(
            &instance,
            "StopOuter",
            "stop-outer",
            r#"{"id":"stop-outer"}"#,
            None,
            None,
        )
        .expect("nested lapse fixture");
    let journal = fixture.journal();
    let frontier = fixture
        .events()
        .last()
        .expect("nested lapse fixture")
        .sequence;
    let outer_lapse = rule::project_regions_from_store(
        fixture.kernel.store(),
        stored_context(&fixture, &typed, &journal),
        frontier,
    )
    .expect("outer lapse retains the lapsed inner selection");
    assert_eq!(outer_lapse.lowering.action_regions.len(), 1);
    assert_eq!(
        outer_lapse.lowering.action_regions[0].region,
        outer.0 as u64
    );
    assert_eq!(outer_lapse.lowering.action_regions[0].phase, Phase::Lapsed);
    assert_eq!(
        outer_lapse.lowering.effects.len(),
        1,
        "only the outer cleanup is newly drafted"
    );
    assert!(
        !outer_lapse.lowering.cancels.is_empty(),
        "outer held work is cancelled"
    );
    let inner_work = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| {
            matches!(&node.kind, NodeKind::Statement(body)
                if matches!(body.as_ref(), whipplescript_parser::body::BodyStmt::Effect(effect)
                    if effect.binding.as_deref() == Some("inner_work")))
        })
        .map(|(index, _)| NodeId(index))
        .expect("nested lapse fixture");
    assert!(
        outer_lapse.owned.contains_key(&inner_work),
        "the outer held checkpoint retains the already-lapsed inner work"
    );
}

#[test]
fn action_region_prefix_native_reconstructs_the_recorded_held_selection_without_writes() {
    let (fixture, typed, region, frontier, events) = setup(Phase::Holding);
    let journal = fixture.journal();
    let before = fixture.events();
    let held = rule::project_region_held_from_store(
        fixture.kernel.store(),
        stored_context(&fixture, &typed, &journal),
        region,
    )
    .expect("region prefix fixture")
    .expect("region prefix fixture");
    let held_node = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| {
            matches!(&node.kind, NodeKind::Statement(body) if matches!(body.as_ref(), whipplescript_parser::body::BodyStmt::Effect(effect) if effect.binding.as_deref() == Some("held")))
        })
        .map(|(index, _)| NodeId(index))
        .expect("region prefix fixture");
    assert_eq!(held.region, region);
    assert_eq!(held.frontier, frontier);
    assert_eq!(
        held.children.keys().copied().collect::<Vec<_>>(),
        [held_node]
    );
    assert_eq!(
        held.effects.keys().copied().collect::<Vec<_>>(),
        [held_node]
    );
    assert_eq!(held.effects[&held_node].state, WorkState::Pending);
    assert_eq!(held.progression.lowering.effects.len(), 1);
    assert!(matches!(
        held.progression.root.boundary,
        Boundary::Waiting(_)
    ));
    assert!(held.results.is_empty());
    assert_eq!(fixture.events(), before, "projection appends no events");
    assert!(fixture
        .kernel
        .store()
        .list_effects(&fixture.instance)
        .expect("region prefix fixture")
        .is_empty());
    assert!(rule::project(context(
        &fixture,
        &typed,
        &journal,
        before.last().expect("region prefix fixture").sequence,
        &before,
    ))
    .unwrap_err()
    .message
    .contains("region entry/lapse history"));
    assert!(
        rule::project_captured(context(&fixture, &typed, &journal, frontier, &events,))
            .unwrap_err()
            .message
            .contains("region entry/lapse history")
    );
}

#[test]
fn action_region_prefix_native_later_lapse_does_not_erase_the_held_selection() {
    let (mut fixture, typed, region, frontier, _events) = setup(Phase::Holding);
    let lapse_frontier = fixture
        .events()
        .last()
        .expect("region prefix fixture")
        .sequence;
    let journal = fixture.journal();
    fixture
        .commit(
            &OwnedLowering {
                action_regions: vec![Cut {
                    region: region.0 as u64,
                    frontier: lapse_frontier,
                    phase: Phase::Lapsed,
                }],
                ..Default::default()
            },
            &journal,
        )
        .expect("region prefix fixture");
    let complete = fixture.journal();
    assert_eq!(
        complete
            .region(&fixture.frame, region.0 as u64)
            .expect("region prefix fixture")
            .held_frontier(),
        Some(frontier)
    );
    let before = fixture.events();
    let held = rule::project_region_held_from_store(
        fixture.kernel.store(),
        stored_context(&fixture, &typed, &complete),
        region,
    )
    .expect("region prefix fixture")
    .expect("region prefix fixture");
    assert_eq!(held.frontier, frontier);
    assert_eq!(held.children.len(), 1);
    assert_eq!(held.effects.len(), 1);
    assert_eq!(fixture.events(), before);
}

#[test]
fn action_region_prefix_native_requires_the_exact_historical_prefix() {
    let (fixture, typed, region, frontier, events) = setup(Phase::Holding);
    let journal = fixture.journal();
    let current = fixture.events();
    let issue = rule::project_region_held(
        context(
            &fixture,
            &typed,
            &journal,
            current.last().expect("region prefix fixture").sequence,
            &current,
        ),
        region,
    )
    .unwrap_err();
    assert!(issue
        .message
        .contains(&format!("historical prefix {frontier}")));
    let nonregion = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| matches!(node.kind, NodeKind::Statement(_)))
        .map(|(index, _)| NodeId(index))
        .expect("region prefix fixture");
    assert!(rule::project_region_held(
        context(&fixture, &typed, &journal, frontier, &events),
        nonregion,
    )
    .unwrap_err()
    .message
    .contains("not a source region"));
}

#[test]
fn action_region_prefix_native_lapse_at_entry_has_no_held_selection() {
    let (fixture, typed, region, frontier, events) = setup(Phase::Lapsed);
    let journal = fixture.journal();
    assert!(rule::project_region_held(
        context(&fixture, &typed, &journal, frontier, &events),
        region,
    )
    .expect("region prefix fixture")
    .is_none());
    assert!(fixture
        .kernel
        .store()
        .list_effects(&fixture.instance)
        .expect("region prefix fixture")
        .is_empty());
}

#[test]
fn action_region_prefix_native_requires_recorded_history_for_its_target() {
    let parsed = whipplescript_parser::parse_program(SOURCE);
    let typed = resolve_rule_types(&parsed.program, "finish").expect("region prefix fixture");
    let region = NodeId(
        typed
            .plan
            .nodes
            .iter()
            .position(|node| matches!(node.kind, NodeKind::Region { .. }))
            .expect("region prefix fixture"),
    );
    let mut fixture = Fixture::with_source(
        SqliteStore::open_in_memory().expect("region prefix fixture"),
        SOURCE,
    );
    let events = fixture.events();
    let frontier = events.last().expect("region prefix fixture").sequence;
    fixture
        .commit(
            &OwnedLowering {
                action_root: Some(RootCapture {
                    inputs: vec![],
                    frontier,
                }),
                ..Default::default()
            },
            &Journal::default(),
        )
        .expect("region prefix fixture");
    let journal = fixture.journal();
    let issue = rule::project_region_held(
        context(&fixture, &typed, &journal, frontier, &events),
        region,
    )
    .unwrap_err();
    assert!(issue.message.contains("no recorded region history"));
}
