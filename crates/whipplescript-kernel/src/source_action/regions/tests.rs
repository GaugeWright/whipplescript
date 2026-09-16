use super::*;
use crate::source_action::{Cause, CauseId, Disposition, FailureKind, ObservedCause, WorkState};
use serde_json::json;
use whipplescript_parser::{parse_program, Item};

fn plan(source: &str) -> ActionPlan {
    let parsed = parse_program(&format!("workflow W\n{source}"));
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let actions = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let rule = parsed
        .program
        .items
        .iter()
        .find_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .unwrap();
    whipplescript_parser::action_plan::expand_rule_syntax(&actions, rule, &[]).unwrap()
}
fn named(p: &ActionPlan, name: &str) -> NodeId {
    NodeId(
        p.nodes
            .iter()
            .position(|node| {
                node.result
                    .is_some_and(|id| p.bindings[id.0].name.as_deref() == Some(name))
            })
            .unwrap(),
    )
}
fn region_for(layout: &Layout, node: NodeId) -> (NodeId, &Region) {
    layout
        .regions
        .iter()
        .find_map(|(id, region)| region.held.contains(node).then_some((*id, region)))
        .unwrap()
}
fn effects_below(p: &ActionPlan, call: NodeId) -> BTreeSet<NodeId> {
    let NodeKind::Call { scope, .. } = p.nodes[call.0].kind else {
        panic!("call")
    };
    arm(p, p.scopes[scope.0].entry).effects
}
fn work(state: WorkState) -> OwnedWork {
    OwnedWork {
        state,
        causes: BTreeMap::new(),
    }
}
const SOURCE: &str = r#"
action leaf() -> int { timer 1s as nested
return 1 }
action helper() -> int { leaf() as inner
return 1 }
rule root when started => {
 timer 1s as before
 during true {
   helper() as held
   case true { true => { leaf() as chosen } false => { leaf() as unused } }
 } on lapse { leaf() as cleanup }
 leaf() as afterwards
}
"#;

#[test]
fn action_region_ownership_separates_direct_call_boundaries_from_transitive_leaves() {
    let p = plan(SOURCE);
    let layout = Layout::build(&p).unwrap();
    let held = named(&p, "held");
    let chosen = named(&p, "chosen");
    let unused = named(&p, "unused");
    let cleanup = named(&p, "cleanup");
    let (_, region) = region_for(&layout, held);
    assert_eq!(region.held.children, [held, chosen, unused].into());
    let expected: BTreeSet<_> = [held, chosen, unused]
        .into_iter()
        .flat_map(|call| effects_below(&p, call))
        .collect();
    assert_eq!(region.held.effects, expected);
    assert_eq!(expected.len(), 3);
    assert!(region.held.contains(named(&p, "inner")));
    assert!(!region.held.children.contains(&named(&p, "inner")));
    assert_eq!(region.lapse.children, [cleanup].into());
    assert_eq!(region.lapse.effects, effects_below(&p, cleanup));
    for outside in [named(&p, "before"), cleanup, named(&p, "afterwards")] {
        assert!(!region.held.contains(outside));
    }
    let spans = expected
        .iter()
        .map(|id| p.nodes[id.0].span)
        .collect::<Vec<_>>();
    assert!(
        spans.iter().all(|span| span == &spans[0]),
        "repeated source spans must not alias expanded operations"
    );
    let (id, _) = region_for(&layout, held);
    assert_eq!(layout.exit_before(named(&p, "afterwards")), Some(id));
    assert_eq!(layout.exit_before(held), None);
}

#[test]
fn action_region_ownership_selects_actual_work_without_inventing_unselected_operations() {
    let p = plan(SOURCE);
    let layout = Layout::build(&p).unwrap();
    let held = named(&p, "held");
    let chosen = named(&p, "chosen");
    let unused = named(&p, "unused");
    let cleanup = named(&p, "cleanup");
    let held_leaf = *effects_below(&p, held).first().unwrap();
    let chosen_leaf = *effects_below(&p, chosen).first().unwrap();
    let cleanup_leaf = *effects_below(&p, cleanup).first().unwrap();
    let (_, region) = region_for(&layout, held);
    for state in [
        WorkState::Pending,
        WorkState::CancellationRequested,
        WorkState::Uncertain,
    ] {
        let owned = [
            (held, work(WorkState::Pending)),
            (named(&p, "inner"), work(WorkState::Pending)),
            (held_leaf, work(state)),
            (chosen, work(WorkState::Succeeded)),
            (chosen_leaf, work(WorkState::Succeeded)),
            (cleanup, work(WorkState::Pending)),
            (cleanup_leaf, work(WorkState::Pending)),
            (named(&p, "before"), work(WorkState::Pending)),
        ]
        .into();
        let selected = region.held.select(&owned);
        assert_eq!(
            selected.children.keys().copied().collect::<BTreeSet<_>>(),
            [held, chosen].into()
        );
        assert_eq!(
            selected.effects.keys().copied().collect::<BTreeSet<_>>(),
            [held_leaf, chosen_leaf].into()
        );
        assert_eq!(selected.effects[&held_leaf].state, state);
        assert!(std::ptr::eq(
            selected.effects[&held_leaf],
            &owned[&held_leaf]
        ));
        assert!(!selected.children.contains_key(&unused));
        assert_eq!(
            region
                .lapse
                .select(&owned)
                .effects
                .keys()
                .copied()
                .collect::<BTreeSet<_>>(),
            [cleanup_leaf].into()
        );
    }
    assert!(region.held.select(&BTreeMap::new()).children.is_empty());
    assert!(region.held.select(&BTreeMap::new()).effects.is_empty());
}

#[test]
fn action_region_ownership_preserves_original_failure_evidence() {
    let p = plan(SOURCE);
    let layout = Layout::build(&p).unwrap();
    let held = named(&p, "held");
    let leaf = *effects_below(&p, held).first().unwrap();
    let failure = OwnedWork {
        state: WorkState::Failed(Disposition::Propagate),
        causes: [(
            CauseId("original".into()),
            ObservedCause {
                cause: Cause {
                    kind: FailureKind::Failed,
                    payload: json!({"reason":"provider"}),
                    evidence: ["terminal".into()].into(),
                },
                recovered: false,
            },
        )]
        .into(),
    };
    let owned = [(held, failure.clone()), (leaf, failure.clone())].into();
    let (_, region) = region_for(&layout, held);
    let selected = region.held.select(&owned);
    assert_eq!(selected.children[&held], &failure);
    assert_eq!(selected.effects[&leaf], &failure);
}

#[test]
fn action_region_ownership_exit_predecessors_are_lexical_and_form_a_chain() {
    let p = plan(
        r#"rule root when started => {
 timer 1s as before
 during true { timer 1s as first } on lapse { timer 1s as first_cleanup }
 timer 1s as between
 during true { timer 1s as second } on lapse { timer 1s as second_cleanup }
 timer 1s as tail
 case true {
   true => { during true { timer 1s as nested } on lapse { timer 1s as nested_cleanup }
             timer 1s as branch_tail }
   false => { timer 1s as sibling }
 }
 timer 1s as outside
}"#,
    );
    let layout = Layout::build(&p).unwrap();
    let (first, _) = region_for(&layout, named(&p, "first"));
    let (second, _) = region_for(&layout, named(&p, "second"));
    let (nested, _) = region_for(&layout, named(&p, "nested"));
    assert_eq!(layout.exit_before(first), None);
    assert_eq!(layout.exit_before(named(&p, "before")), None);
    assert_eq!(layout.exit_before(named(&p, "between")), Some(first));
    assert_eq!(layout.exit_before(second), Some(first));
    assert_eq!(layout.exit_before(named(&p, "tail")), Some(second));
    assert_eq!(layout.exit_before(named(&p, "outside")), Some(second));
    assert_eq!(layout.exit_before(named(&p, "branch_tail")), Some(nested));
    assert_eq!(layout.exit_before(named(&p, "sibling")), None);
    assert_eq!(layout.exit_before(named(&p, "nested_cleanup")), None);
}

#[test]
fn action_region_ownership_includes_nested_regions_and_continuations_within_the_held_arm() {
    let p = plan(
        r#"rule root when started => {
 during true {
   timer 1s as start
   after start succeeds { timer 1s as continuation }
   during true { timer 1s as inner } on lapse { timer 1s as inner_cleanup }
 } on lapse { timer 1s as outer_cleanup }
}"#,
    );
    let layout = Layout::build(&p).unwrap();
    let (_, outer) = region_for(&layout, named(&p, "start"));
    let expected: BTreeSet<_> = ["start", "continuation", "inner", "inner_cleanup"]
        .into_iter()
        .map(|name| named(&p, name))
        .collect();
    assert_eq!(outer.held.effects, expected);
    assert_eq!(outer.held.children, expected);
    assert!(!outer.held.contains(named(&p, "outer_cleanup")));
    assert_eq!(outer.lapse.effects, [named(&p, "outer_cleanup")].into());
}

#[test]
fn action_region_ownership_refuses_invalid_plans_before_walking_them() {
    let mut p = plan("rule root when started => { timer 1s as before }");
    p.blocks[p.root.0].nodes.push(NodeId(usize::MAX));
    assert!(Layout::build(&p).is_err());
    let mut p = plan(SOURCE);
    let held = named(&p, "held");
    let NodeKind::Call { scope, .. } = &mut p.nodes[held.0].kind else {
        panic!("call")
    };
    *scope = whipplescript_parser::action_plan::ScopeId(usize::MAX);
    assert!(Layout::build(&p).is_err());
}
