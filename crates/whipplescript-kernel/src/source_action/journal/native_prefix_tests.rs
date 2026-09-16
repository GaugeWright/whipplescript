//! Real store prefixes and the shared captured-rule projector. The program
//! compiles in full; this test does not fabricate executable typed metadata.
use super::*;
use crate::lowering::OwnedFact;
use crate::source_action::arguments::{ObservationKind, ObservationMember, QueryObservation};
use crate::source_action::{progression::Progression, rule};
use whipplescript_parser::action_plan::resolved::{resolve_rule_types, TypedActionPlan};
use whipplescript_store::projection_prefix::{ProjectionEffect, ProjectionFact};

const SOURCE: &str = "@service\nworkflow Captures\nrule finish when started => { timer 1s as first\nafter first succeeds { timer 2s as next } }";
fn typed() -> TypedActionPlan {
    let parsed = whipplescript_parser::parse_program(SOURCE);
    assert!(parsed.diagnostics.is_empty());
    resolve_rule_types(&parsed.program, "finish").expect("compiled timer source resolves")
}
#[derive(Clone)]
struct Prefix {
    frontier: i64,
    events: Vec<EventView>,
    effects: Vec<ProjectionEffect>,
    facts: Vec<ProjectionFact>,
}
impl Prefix {
    fn read(f: &Fixture) -> Self {
        let events = f.events();
        Self {
            frontier: events.last().expect("fixture events").sequence,
            events,
            effects: f
                .kernel
                .store()
                .list_effects(&f.instance)
                .expect("fixture effects")
                .iter()
                .map(ProjectionEffect::from)
                .collect(),
            facts: f
                .kernel
                .store()
                .list_facts(&f.instance)
                .expect("fixture facts")
                .iter()
                .map(ProjectionFact::from)
                .collect(),
        }
    }
}
fn context<'a>(
    f: &'a Fixture,
    typed: &'a TypedActionPlan,
    journal: &'a Journal,
    prefix: &'a Prefix,
) -> rule::Context<'a> {
    rule::Context {
        ir: &f.ir,
        typed,
        instance: &f.instance,
        frame: &f.frame,
        admission: &f.context,
        frontier: prefix.frontier,
        journal,
        effects: &prefix.effects,
        events: &prefix.events,
        facts: &prefix.facts,
        coercion_fingerprint: "fixture",
        source_path: None,
    }
}
fn stored_context<'a>(
    f: &'a Fixture,
    typed: &'a TypedActionPlan,
    journal: &'a Journal,
) -> rule::StoredContext<'a> {
    rule::StoredContext {
        ir: &f.ir,
        typed,
        instance: &f.instance,
        frame: &f.frame,
        admission: &f.context,
        journal,
        coercion_fingerprint: "fixture",
        source_path: None,
    }
}
fn current(f: &Fixture, typed: &TypedActionPlan, prefix: &Prefix) -> Progression {
    rule::project(context(f, typed, &f.journal(), prefix)).expect("current source projection")
}

#[test]
fn action_capture_prefix_native_reconstructs_real_admission_and_pending_prefix_after_reopen() {
    let path = std::env::temp_dir().join(format!(
        "whip-capture-prefix-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::with_source(SqliteStore::open(&path).unwrap(), SOURCE);
    let typed = typed();
    let initial = Prefix::read(&f);
    let first = current(&f, &typed, &initial);
    assert_eq!(first.lowering.effects.len(), 1);
    let first_id = first.lowering.effects[0].effect_id.clone();
    let recorded = f.commit(&first.lowering, &f.journal()).unwrap();
    assert!(recorded.sequence > initial.frontier);
    let pending = Prefix::read(&f);
    let waited = current(&f, &typed, &pending);
    assert!(!waited.lowering.has_commit_work());
    timer_fixture::settle(&mut f, &first_id);
    let settled = Prefix::read(&f);
    let next = current(&f, &typed, &settled);
    assert_eq!(next.lowering.effects.len(), 1);
    assert_ne!(next.lowering.effects[0].effect_id, first_id);
    f.commit(&next.lowering, &f.journal()).unwrap();
    let before = f.events();
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context: admission,
    } = f;
    drop(kernel);
    let f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
        ir,
        instance,
        frame,
        context: admission,
    };
    let journal = f.journal();
    // Reconstruct the evaluation whose root was published in the next commit.
    let admission = rule::project_captured_from_store(
        f.kernel.store(),
        stored_context(&f, &typed, &journal),
        initial.frontier,
    )
    .unwrap();
    assert_eq!(admission.lowering.effects, first.lowering.effects);
    assert_eq!(admission.root, first.root);
    assert!(
        admission.lowering.action_root.is_none(),
        "reconstruction uses the admitted root"
    );
    let earlier = rule::project_captured_from_store(
        f.kernel.store(),
        stored_context(&f, &typed, &journal),
        pending.frontier,
    )
    .unwrap();
    assert_eq!(
        earlier, waited,
        "a later timer success must not unlock the old continuation"
    );
    let later = rule::project_captured_from_store(
        f.kernel.store(),
        stored_context(&f, &typed, &journal),
        settled.frontier,
    )
    .unwrap();
    assert_eq!(later, next);
    assert_eq!(
        f.events(),
        before,
        "historical reads append no work or events"
    );
    assert_eq!(f.journal(), journal);
    assert_eq!(f.kernel.store().list_effects(&f.instance).unwrap().len(), 2);
    // Supplying today's completed effect rows with old terminal evidence is
    // not historical reconstruction; the ordinary projector still refuses it.
    let mut mixed = pending;
    mixed.effects = settled.effects;
    assert!(
        rule::project_captured(context(&f, &typed, &journal, &mixed))
            .unwrap_err()
            .message
            .contains("terminal evidence")
    );
    drop(f);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn action_capture_prefix_native_requires_its_admitted_root_and_exact_ordered_event_prefix() {
    let mut f = Fixture::with_source(SqliteStore::open_in_memory().unwrap(), SOURCE);
    let typed = typed();
    let initial = Prefix::read(&f);
    assert!(initial.events.len() >= 2);
    let unadmitted = Journal::default();
    let issue = rule::project_captured(context(&f, &typed, &unadmitted, &initial)).unwrap_err();
    assert!(issue.message.contains("no admitted root"));
    assert_eq!(issue.span, typed.plan.root_rule.as_ref().unwrap().span);
    let first = current(&f, &typed, &initial);
    f.commit(&first.lowering, &unadmitted).unwrap();
    let journal = f.journal();
    let empty = Prefix {
        frontier: 0,
        events: vec![],
        facts: vec![],
        effects: vec![],
    };
    assert!(
        rule::project_captured(context(&f, &typed, &journal, &empty))
            .unwrap_err()
            .message
            .contains("no admitted root")
    );
    let mut another_frame = f.frame.clone();
    another_frame.trigger_event = Some("another firing".into());
    let mut another_admission = f.context.clone();
    another_admission.trigger_event_id = another_frame.trigger_event.clone();
    let c = rule::Context {
        frame: &another_frame,
        admission: &another_admission,
        ..context(&f, &typed, &journal, &initial)
    };
    assert!(rule::project_captured(c)
        .unwrap_err()
        .message
        .contains("no admitted root"));
    let before = f.events();
    for corruption in 0..6 {
        let mut bad = initial.clone();
        match corruption {
            0 => bad.events.clear(),
            1 => bad.events.insert(0, bad.events[0].clone()),
            2 => {
                let mut event = bad.events[0].clone();
                event.sequence = -1;
                bad.events.insert(0, event);
            }
            3 => bad.events.reverse(),
            4 => {
                let mut event = bad.events[0].clone();
                event.sequence = 0;
                bad.events.insert(0, event);
            }
            _ => bad.events = f.events(),
        }
        let issue = rule::project_captured(context(&f, &typed, &journal, &bad)).unwrap_err();
        assert!(
            issue.message.contains("ordered events at its frontier"),
            "{corruption}: {issue:?}"
        );
        assert_eq!(issue.span, typed.plan.root_rule.as_ref().unwrap().span);
    }
    assert_eq!(f.events(), before);
}

#[test]
fn managed_query_native_capture_reopens_with_exact_absence_and_membership_evidence() {
    const QUERY_SOURCE: &str = r#"workflow QueryCapture
class Ticket { owner string }
action find(wanted string) -> bool {
  return exists(Ticket where owner == wanted)
}
action carry(found bool) -> bool {
  return found
}
rule finish when started => {
  find("alice") as found
  carry(found) as result
}"#;
    let parsed = whipplescript_parser::parse_program(QUERY_SOURCE);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed = resolve_rule_types(&parsed.program, "finish").expect("query capture resolves");
    let carry = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| match &node.kind {
            whipplescript_parser::action_plan::NodeKind::Call { scope, .. }
                if typed.plan.scopes[scope.0].action == "carry" =>
            {
                Some(index as u64)
            }
            _ => None,
        })
        .expect("carry call");
    let path = std::env::temp_dir().join(format!(
        "whip-query-capture-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut f = Fixture::new(SqliteStore::open(&path).unwrap());
    let before_fact = Prefix::read(&f);
    let absent = current(&f, &typed, &before_fact);
    let absent_capture = absent
        .lowering
        .action_captures
        .iter()
        .find(|capture| capture.call == carry)
        .expect("absence reaches the second call");
    let absence = absent_capture.arguments[0]
        .validity
        .iter()
        .next()
        .expect("absence observation");
    assert_eq!(absence.frontier, before_fact.frontier);
    assert_eq!(absence.kind, ObservationKind::Fact);
    assert!(absence.members.is_empty());

    let upstream = QueryObservation {
        frontier: before_fact.frontier,
        kind: ObservationKind::Effect,
        head: "kind evidence.check".into(),
        guard_json: None,
        members: BTreeSet::new(),
    };
    let upstream_json = serde_json::to_string(&BTreeSet::from([upstream.clone()])).unwrap();
    let admitted = f
        .commit(
            &OwnedLowering {
                facts: vec![OwnedFact {
                    fact_id: "ticket-alice".into(),
                    name: "Ticket".into(),
                    key: "alice".into(),
                    value_json: json!({"owner":"alice"}).to_string(),
                    schema_id: None,
                    provenance_class: "rule".into(),
                    correlation_id: None,
                    source_span_json: None,
                    validity_json: Some(upstream_json),
                }],
                ..Default::default()
            },
            &Journal::default(),
        )
        .expect("query fact commits");
    let with_fact = Prefix::read(&f);
    let projected = current(&f, &typed, &with_fact);
    let captured = projected
        .lowering
        .action_captures
        .iter()
        .find(|capture| capture.call == carry)
        .expect("membership reaches the second call");
    let observation = captured.arguments[0]
        .validity
        .iter()
        .find(|observation| observation.kind == ObservationKind::Fact)
        .expect("membership observation");
    assert!(captured.arguments[0].validity.contains(&upstream));
    assert_eq!(observation.frontier, with_fact.frontier);
    assert_eq!(
        observation.members,
        [ObservationMember::Fact {
            fact_id: "ticket-alice".into(),
            admission_event: admitted.event_id,
        }]
        .into()
    );
    f.commit(&projected.lowering, &f.journal())
        .expect("query captures commit");
    let expected = f.journal();
    let saved = expected.calls(&f.frame).unwrap()[&carry].clone();
    let before = f.events();
    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    let f = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    assert_eq!(f.journal().calls(&f.frame).unwrap()[&carry], saved);
    let replayed = rule::project_captured_from_store(
        f.kernel.store(),
        stored_context(&f, &typed, &f.journal()),
        with_fact.frontier,
    )
    .expect("query prefix reconstructs");
    assert_eq!(
        replayed
            .bindings
            .values()
            .filter_map(|slot| match slot {
                crate::source_action::arguments::Slot::Ready(argument)
                    if !argument.validity.is_empty() =>
                    Some(&argument.validity),
                _ => None,
            })
            .next(),
        Some(&saved.arguments[0].validity)
    );
    assert_eq!(f.events(), before);
    drop(f);
    std::fs::remove_file(path).unwrap();
}
