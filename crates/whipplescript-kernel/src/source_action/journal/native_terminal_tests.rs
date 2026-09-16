use super::*;
use crate::source_action::{
    progression::{Progression, ProgressionError},
    rule, Boundary,
};
use whipplescript_parser::{
    action_plan::resolved::{resolve_rule_types, TypedActionPlan},
    parse_program,
};
const DECLARATIONS: &str = r#"workflow Captures
output result Answer
failure rejected string
class Answer { text string }
class Ticket { text string }
rule finish when started => { complete result { text "done" } }
"#;
fn typed(body: &str) -> TypedActionPlan {
    let source = format!(
        "{}{}",
        DECLARATIONS
            .split("rule finish")
            .next()
            .expect("fixture declarations"),
        body
    );
    let parsed = parse_program(&source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    resolve_rule_types(&parsed.program, "finish").expect("typed terminal fixture resolves")
}
fn project(f: &Fixture, typed: &TypedActionPlan) -> Result<Progression, ProgressionError> {
    let events = f.events();
    let frontier = events.last().expect("fixture event frontier").sequence;
    let prefix = f
        .kernel
        .store()
        .projection_prefix(&f.instance, frontier)
        .expect("fixture projection prefix");
    rule::project(rule::Context {
        ir: &f.ir,
        typed,
        instance: &f.instance,
        frame: &f.frame,
        admission: &f.context,
        frontier,
        journal: &f.journal(),
        effects: &prefix.effects,
        events: &events,
        facts: &prefix.facts,
        coercion_fingerprint: "fixture",
        source_path: None,
    })
}
#[test]
fn managed_terminal_native_complete_and_declared_failure_join_independent_owned_work() {
    for (terminal, event, status) in [
        (
            "complete result { text \"ready\" }",
            "workflow.completed",
            "completed",
        ),
        ("fail rejected \"declined\"", "workflow.failed", "failed"),
    ] {
        let plan = typed(&format!(
            "rule finish when started => {{ timer 1s as sibling\n{terminal} }}"
        ));
        let mut f = Fixture::with_source(SqliteStore::open_in_memory().unwrap(), DECLARATIONS);
        let waiting = project(&f, &plan).unwrap();
        assert!(matches!(waiting.root.boundary, Boundary::Waiting(_)));
        assert!(waiting.lowering.terminal.is_none());
        assert_eq!(waiting.lowering.effects.len(), 1);
        timer_fixture::commit(&mut f, &waiting);
        assert_eq!(
            f.kernel
                .store()
                .get_instance(&f.instance)
                .unwrap()
                .unwrap()
                .status,
            "running"
        );
        assert!(!f.events().iter().any(|e| e.event_type == event));
        timer_fixture::settle(&mut f, &waiting.lowering.effects[0].effect_id);
        let completed = project(&f, &plan).unwrap();
        assert_eq!(completed.root.boundary, Boundary::Succeeded(()));
        assert!(completed.lowering.terminal.is_some());
        timer_fixture::commit(&mut f, &completed);
        let replay = project(&f, &plan).unwrap();
        assert_eq!(
            completed
                .lowering
                .terminal
                .as_ref()
                .unwrap()
                .idempotency_key,
            replay.lowering.terminal.as_ref().unwrap().idempotency_key
        );
        let before = f.events();
        // An EXACT replay -- same commit key, byte-identical payload -- is
        // absorbed and hands back the event it already wrote; only a NEW firing
        // reaches the running-instance check, which is what refuses a second
        // commit into a finished instance. This asserted the refusal, which
        // meant it was asserting that the replay was not recognised as one.
        let replayed = f.commit(&replay.lowering, &f.journal()).unwrap();
        assert!(
            before
                .iter()
                .any(|event| event.event_id == replayed.event_id),
            "a replayed terminal must return the commit it already made"
        );
        let report = step_instance_generic(&mut f.kernel, &f.instance, &f.ir, None, None).unwrap();
        assert_eq!(report.committed_rules, 0);
        assert_eq!(f.events().len(), before.len());
        assert_eq!(
            f.kernel
                .store()
                .get_instance(&f.instance)
                .unwrap()
                .unwrap()
                .status,
            status
        );
        assert_eq!(
            f.events().iter().filter(|e| e.event_type == event).count(),
            1
        );
    }
}
#[test]
fn managed_terminal_native_unhandled_action_failure_withholds_ready_output() {
    let plan=typed("action reject() -> null ! string { fail \"bad\" }\nrule finish when started => { reject() as rejected\ncomplete result { text \"ready\" } }");
    let f = Fixture::with_source(SqliteStore::open_in_memory().unwrap(), DECLARATIONS);
    let result = project(&f, &plan).unwrap();
    assert_eq!(result.root.boundary, Boundary::Failed);
    assert!(!result.root.causes.is_empty());
    assert!(result.lowering.terminal.is_none());
    assert!(!f
        .events()
        .iter()
        .any(|e| e.event_type == "workflow.completed"));
}
#[test]
fn managed_terminal_native_rule_restores_captured_input_after_consumption() {
    let plan=typed("action answer(t Ticket) -> Answer { return { text t.text } }\nrule finish when Ticket as ticket => { timer 1s as delay\nafter delay succeeds { answer(ticket) as answer\ncomplete result answer } }");
    let mut f = Fixture::with_source(SqliteStore::open_in_memory().unwrap(), DECLARATIONS);
    f.kernel
        .derive_fact(
            &f.instance,
            "Ticket",
            "ticket",
            r#"{"text":"captured"}"#,
            None,
            Some("original"),
        )
        .unwrap();
    let fact = f
        .kernel
        .store()
        .list_facts(&f.instance)
        .unwrap()
        .into_iter()
        .find(|fact| fact.name == "Ticket")
        .unwrap();
    f.context.bindings.push(("ticket".into(), fact.clone()));
    f.context.trigger_event_id = Some(fact.source_event_id.clone());
    f.frame.trigger_event = f.context.trigger_event_id.clone();
    let first = project(&f, &plan).unwrap();
    assert!(first.lowering.action_root.is_some());
    timer_fixture::commit(&mut f, &first);
    consume_record(&mut f, &fact.fact_id);
    f.context.bindings.clear();
    timer_fixture::settle(&mut f, &first.lowering.effects[0].effect_id);
    let ready = project(&f, &plan).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&ready.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"text":"captured"})
    );
    timer_fixture::commit(&mut f, &ready);
    assert_eq!(
        f.kernel
            .store()
            .get_instance(&f.instance)
            .unwrap()
            .unwrap()
            .status,
        "completed"
    );
}

#[test]
fn managed_terminal_native_nested_transformations_and_milestone_remain_synchronous() {
    let plan = typed(
        "action reveal() -> Ticket { return { text \"bounded\" } }\n\
         rule finish when started => {\n\
           reveal() as original\n\
           declassify original into Answer as released\n\
           redact released keep [text] as selected\n\
           emit milestone \"released\" of Answer { text selected.text }\n\
           complete result { text selected.text }\n\
         }",
    );
    let mut f = Fixture::with_source(SqliteStore::open_in_memory().unwrap(), DECLARATIONS);
    let ready = project(&f, &plan).unwrap();
    assert_eq!(ready.root.boundary, Boundary::Succeeded(()));
    assert_eq!(ready.owned.len(), 1);
    assert!(ready
        .owned
        .values()
        .all(|work| work.state == crate::source_action::WorkState::Succeeded));
    assert!(ready.lowering.effects.is_empty());
    assert_eq!(ready.lowering.facts.len(), 1);
    assert_eq!(ready.lowering.facts[0].name, "workflow.milestone:released");
    assert_eq!(
        serde_json::from_str::<Value>(&ready.lowering.facts[0].value_json).unwrap(),
        json!({"milestone":"released", "status":"completed", "value":{"text":"bounded"}})
    );
    assert_eq!(
        serde_json::from_str::<Value>(&ready.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"text":"bounded"})
    );
    timer_fixture::commit(&mut f, &ready);
    assert_eq!(
        f.kernel
            .store()
            .get_instance(&f.instance)
            .unwrap()
            .unwrap()
            .status,
        "completed"
    );
}

#[test]
fn managed_cancel_native_waits_for_terminal_acknowledgement_before_completion() {
    let plan = typed(
        "action child() -> Answer {
           timer 1s as inside
           after inside succeeds { return { text \"late\" } }
           after inside cancelled { return { text \"cancelled\" } }
         }
         rule finish when started => {
           child() as job
           cancel job
           after job succeeds { complete result job }
         }",
    );
    let mut f = Fixture::with_source(SqliteStore::open_in_memory().unwrap(), DECLARATIONS);
    let first = project(&f, &plan).unwrap();
    assert!(matches!(first.root.boundary, Boundary::Waiting(_)));
    assert_eq!(first.lowering.effects.len(), 1);
    assert_eq!(
        first.lowering.cancels,
        vec![first.lowering.effects[0].effect_id.clone()]
    );
    assert!(first.lowering.terminal.is_none());
    let committed = timer_fixture::commit(&mut f, &first);
    crate::rule_pass::apply_rule_cancels(
        &mut f.kernel,
        &f.instance,
        &f.frame.rule,
        &first.lowering.cancels,
        &committed.event_id,
    )
    .unwrap();
    let effect = f
        .kernel
        .store()
        .list_effects(&f.instance)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(effect.status, "cancelled");

    let completed = project(&f, &plan).unwrap();
    assert_eq!(completed.root.boundary, Boundary::Succeeded(()));
    assert_eq!(
        serde_json::from_str::<Value>(&completed.lowering.terminal.as_ref().unwrap().payload_json)
            .unwrap(),
        json!({"text":"cancelled"})
    );
    timer_fixture::commit(&mut f, &completed);
    assert_eq!(
        f.kernel
            .store()
            .get_instance(&f.instance)
            .unwrap()
            .unwrap()
            .status,
        "completed"
    );
}

#[test]
fn managed_terminal_native_rule_refuses_wrong_admission_and_unsupported_unselected_statement() {
    let plan = typed("rule finish when started => { complete result { text \"ready\" } }");
    let mut f = Fixture::with_source(SqliteStore::open_in_memory().unwrap(), DECLARATIONS);
    f.context.identity = Some("other".into());
    assert!(project(&f, &plan)
        .unwrap_err()
        .message
        .contains("pinned admission"));
    f.context.identity = None;
    f.context.trigger_event_id = None;
    assert!(project(&f, &plan)
        .unwrap_err()
        .message
        .contains("pinned admission"));
    f.context.trigger_event_id = f.frame.trigger_event.clone();
    let mut other = plan.clone();
    other.plan.root_rule.as_mut().unwrap().name = "other".into();
    assert!(project(&f, &other)
        .unwrap_err()
        .message
        .contains("pinned admission"));
    f.ir.rules.clear();
    assert!(project(&f, &plan)
        .unwrap_err()
        .message
        .contains("pinned admission"));
    let f = Fixture::with_source(SqliteStore::open_in_memory().unwrap(), DECLARATIONS);
    let plan=typed("rule finish when started => { case true { true => { complete result { text \"ready\" } } false => { exec \"unused\" as unused } } }");
    assert_eq!(
        project(&f, &plan).unwrap_err().message,
        "managed execution does not yet support `exec` in typed composition"
    );
    assert!(f
        .kernel
        .store()
        .list_effects(&f.instance)
        .unwrap()
        .is_empty());
}
