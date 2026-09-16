use super::*;
use crate::source_action::{rule, WorkState};
use whipplescript_parser::action_plan::{resolved::resolve_rule_types, NodeId};

#[test]
fn action_region_ownership_native_progression_keeps_existing_and_new_owned_operations() {
    let source = "@service\nworkflow Captures\nrule finish when started => { timer 1s as first\nafter first succeeds { timer 2s as next } }";
    let parsed = whipplescript_parser::parse_program(source);
    let typed = resolve_rule_types(&parsed.program, "finish").unwrap();
    let mut f = Fixture::with_source(SqliteStore::open_in_memory().unwrap(), source);
    let project = |f: &Fixture| {
        let frontier = f.events().last().unwrap().sequence;
        let prefix = f
            .kernel
            .store()
            .projection_prefix(&f.instance, frontier)
            .unwrap();
        rule::project(rule::Context {
            ir: &f.ir,
            typed: &typed,
            instance: &f.instance,
            frame: &f.frame,
            admission: &f.context,
            frontier,
            journal: &f.journal(),
            effects: &prefix.effects,
            events: &prefix.events,
            facts: &prefix.facts,
            coercion_fingerprint: "fixture",
            source_path: None,
        })
        .unwrap()
    };
    let first = project(&f);
    assert_eq!(first.owned.len(), 1);
    let (&node, work) = first.owned.first_key_value().unwrap();
    assert_eq!(work.state, WorkState::Pending);
    let effect = first.lowering.effects[0].effect_id.clone();
    assert_eq!(
        crate::source_action::progression::operation_identity(&f.instance, &f.frame, node),
        effect
    );
    f.commit(&first.lowering, &f.journal()).unwrap();
    let waiting = project(&f);
    assert!(!waiting.lowering.has_commit_work());
    assert_eq!(
        waiting.owned, first.owned,
        "existing work remains owned when no new work is drafted"
    );
    timer_fixture::settle(&mut f, &effect);
    let next = project(&f);
    assert_eq!(next.lowering.effects.len(), 1);
    assert_eq!(next.owned.len(), 2);
    assert_eq!(next.owned[&node].state, WorkState::Succeeded);
    let later = next.owned.iter().find(|(id, _)| **id != node).unwrap();
    assert_eq!(later.1.state, WorkState::Pending);
    assert_eq!(
        crate::source_action::progression::operation_identity(
            &f.instance,
            &f.frame,
            NodeId(later.0 .0)
        ),
        next.lowering.effects[0].effect_id
    );
}
