use super::*;
use crate::coerce::{CoerceRequest, FakeCoerceClient};
use crate::source_action::{Boundary, CauseId};
use crate::CoerceExecution;

const DECLARATIONS: &str = r#"
workflow Captures
output result Result
class Result { ok bool }
class Answer { text string }
coerce classify(text string) -> Answer {
  prompt "{{ text }} {{ ctx.output_format }}"
}
rule finish when started => { complete result { ok true } }
"#;
const SOURCE: &str = r#"
workflow Captures
action recover() -> Answer {
  coerce classify("primary") as primary
  after primary succeeds { return primary }
  after primary fails as problem {
    coerce classify(problem.reason) as fallback
    return fallback
  }
}
rule finish when started => {
  recover() as answer
  record Answer { text answer.text }
}
"#;
const OUTCOME_SOURCE: &str = r#"
workflow Captures
action observe() -> string {
  coerce classify("primary") as primary
  after primary completes as outcome {
    case outcome {
      Completed as value => { return value.text }
      Failed as problem => { return problem.reason }
      TimedOut as problem => { return problem.summary }
      Cancelled as problem => { return problem.summary }
    }
  }
}
rule finish when started => {
  observe() as answer
  record Answer { text answer }
}
"#;
const OUTCOME_EXPRESSION_SOURCE: &str = r#"
workflow Captures
action observe() -> string {
  coerce classify("primary") as primary
  case outcome(primary) {
    Completed as value => { return value.text }
    Failed as problem => { return problem.reason }
    TimedOut as problem => { return problem.summary }
    Cancelled as problem => { return problem.summary }
  }
}
rule finish when started => {
  observe() as answer
  record Answer { text answer }
}
"#;
const CHILD_OUTCOME_SOURCE: &str = r#"
workflow Captures
action leaf() -> Answer {
  coerce classify("primary") as primary
  after primary succeeds { return primary }
}
action observe() -> string {
  leaf() as child
  case outcome(child) {
    Completed as value => { return value.text }
    Failed as problem => { return problem.summary }
  }
}
rule finish when started => {
  observe() as answer
  record Answer { text answer }
}
"#;
const LEXICAL_HANDLER_SOURCE: &str = r#"
workflow Captures
action recover() -> string {
  coerce classify("primary") as primary
  after primary succeeds { return primary.text }
  on failure as problem { return problem.summary }
}
rule finish when started => {
  recover() as answer
  record Answer { text answer }
}
"#;
const RULE_HANDLER_SOURCE: &str = r#"
workflow Captures
rule finish when started => {
  coerce classify("primary") as primary
  on failure as problem {
    record Answer { text problem.summary }
  }
}
"#;

fn settle(f: &mut Fixture, effect: &OwnedEffect, succeeds: bool) {
    let input: Value = serde_json::from_str(&effect.input_json).expect("coerce input JSON");
    let request = CoerceRequest::with_evidence_hashes(
        input["function_name"]
            .as_str()
            .expect("coerce function")
            .into(),
        input["arguments"].to_string(),
        input["output_type"]
            .as_str()
            .expect("coerce output type")
            .into(),
    );
    let provider = if succeeds {
        FakeCoerceClient::succeeds(json!({"text":"recovered"}).to_string())
    } else {
        FakeCoerceClient::fails("provider failed")
    };
    f.kernel
        .run_coerce(
            CoerceExecution {
                instance_id: &f.instance,
                effect_id: &effect.effect_id,
                run_id: &format!("run-{}", effect.effect_id),
                provider: "fake-coerce",
                worker_id: "fixture",
                lease_id: &format!("lease-{}", effect.effect_id),
                lease_expires_at: "2030-01-01T00:00:00Z",
                request: &request,
                model: None,
            },
            &provider,
        )
        .expect("coerce settlement");
}

#[test]
fn managed_action_recovery_native_reopens_with_real_failures_and_no_resubmission() {
    for recovery_succeeds in [true, false] {
        let path = std::env::temp_dir().join(format!(
            "action-recovery-{}-{recovery_succeeds}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let plan = record_plan(SOURCE, &[]);
        let artifact = crate::source_action::plan_artifact::encode(&plan).unwrap();
        let mut f = Fixture::with_source(SqliteStore::open(&path).unwrap(), DECLARATIONS);
        let first = timer_fixture::project(&f, &plan);
        assert_eq!(first.lowering.effects.len(), 1);
        assert_eq!(first.lowering.action_captures.len(), 1);
        assert!(first.lowering.facts.is_empty());
        timer_fixture::commit(&mut f, &first);
        let primary = &first.lowering.effects[0];
        settle(&mut f, primary, false);
        let recovering = timer_fixture::project(&f, &plan);
        assert!(matches!(recovering.root.boundary, Boundary::Waiting(_)));
        assert_eq!(recovering.lowering.effects.len(), 1);
        let original = recovering.root.causes[&CauseId(primary.effect_id.clone())].clone();
        assert!(!original.recovered);
        assert!(!original.cause.evidence.is_empty());
        assert!(recovering.lowering.facts.is_empty());
        timer_fixture::commit(&mut f, &recovering);
        let fallback = &recovering.lowering.effects[0];
        let fallback_input: Value = serde_json::from_str(&fallback.input_json).unwrap();
        assert_eq!(fallback_input["arguments"]["arg0"], "coerce failed");
        assert_eq!(
            fallback_input["action_arguments"][0]["sources"][0]["operation_id"],
            primary.effect_id
        );
        // Prove replay derives the failure from immutable events, even after
        // ordinary result facts disappear and the plan/SQLite are reopened.
        let failed_fact = f
            .kernel
            .store()
            .list_facts(&f.instance)
            .unwrap()
            .into_iter()
            .find(|fact| fact.name == "schema.coerce.failed")
            .unwrap();
        consume_record(&mut f, &failed_fact.fact_id);
        let captures = f.journal();
        let Fixture {
            kernel,
            ir,
            instance,
            frame,
            context,
        } = f;
        drop(kernel);
        drop(plan);
        let plan = crate::source_action::plan_artifact::decode(&artifact).unwrap();
        let mut f = Fixture {
            kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
            ir,
            instance,
            frame,
            context,
        };
        let reopened = timer_fixture::project(&f, &plan);
        assert!(matches!(reopened.root.boundary, Boundary::Waiting(_)));
        assert!(!reopened.lowering.has_commit_work());
        assert_eq!(
            reopened.root.causes[&CauseId(primary.effect_id.clone())],
            original
        );
        assert_eq!(f.journal(), captures);
        settle(&mut f, fallback, recovery_succeeds);
        let done = timer_fixture::project(&f, &plan);
        assert!(done.lowering.effects.is_empty());
        assert!(done.lowering.action_captures.is_empty());
        let retained = &done.root.causes[&CauseId(primary.effect_id.clone())];
        assert_eq!(retained.cause, original.cause);
        assert_eq!(retained.recovered, recovery_succeeds);
        if recovery_succeeds {
            assert_eq!(done.root.boundary, Boundary::Succeeded(()));
            assert_eq!(done.root.causes.len(), 1);
            assert_eq!(done.lowering.facts.len(), 1);
            assert_eq!(
                serde_json::from_str::<Value>(&done.lowering.facts[0].value_json).unwrap(),
                json!({"text":"recovered"})
            );
            timer_fixture::commit(&mut f, &done);
        } else {
            assert_eq!(done.root.boundary, Boundary::Failed);
            assert_eq!(done.root.causes.len(), 2);
            assert!(!done.root.causes[&CauseId(fallback.effect_id.clone())].recovered);
            assert!(done.lowering.facts.is_empty());
        }
        let replay = timer_fixture::project(&f, &plan);
        assert!(!replay.lowering.has_commit_work());
        assert_eq!(replay.root, done.root);
        assert_eq!(f.kernel.store().list_effects(&f.instance).unwrap().len(), 2);
        assert_eq!(
            f.events()
                .iter()
                .filter(|event| event.event_type == "schema.coerce.failed")
                .count(),
            if recovery_succeeds { 1 } else { 2 }
        );
        assert!(f
            .kernel
            .store()
            .list_facts(&f.instance)
            .unwrap()
            .iter()
            .all(|fact| matches!(
                fact.name.as_str(),
                "Answer" | "schema.coerce.succeeded" | "schema.coerce.failed"
            )));
        drop(f);
        std::fs::remove_file(path).unwrap();
    }
}

fn assert_terminal_outcome_native(source: &str, label: &str, expected: &str) {
    let path = std::env::temp_dir().join(format!(
        "action-outcome-{label}-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos()
    ));
    let plan = record_plan(source, &[]);
    let artifact = crate::source_action::plan_artifact::encode(&plan)
        .expect("action plan artifact must encode");
    let mut f = Fixture::with_source(
        SqliteStore::open(&path).expect("fixture store must open"),
        DECLARATIONS,
    );
    let first = timer_fixture::project(&f, &plan);
    assert_eq!(first.lowering.effects.len(), 1);
    timer_fixture::commit(&mut f, &first);
    let primary = first.lowering.effects[0].clone();
    settle(&mut f, &primary, false);

    let Fixture {
        kernel,
        ir,
        instance,
        frame,
        context,
    } = f;
    drop(kernel);
    drop(plan);
    let plan = crate::source_action::plan_artifact::decode(&artifact)
        .expect("action plan artifact must decode after reopen");
    let mut f = Fixture {
        kernel: RuntimeKernel::new(wrap(
            SqliteStore::open(&path).expect("fixture store must reopen"),
        )),
        ir,
        instance,
        frame,
        context,
    };
    let done = timer_fixture::project(&f, &plan);
    assert_eq!(done.root.boundary, Boundary::Succeeded(()));
    assert!(done.root.causes[&CauseId(primary.effect_id.clone())].recovered);
    assert!(done.lowering.effects.is_empty());
    assert_eq!(done.lowering.facts.len(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(&done.lowering.facts[0].value_json)
            .expect("settled fact value must be valid JSON"),
        json!({"text":expected})
    );
    timer_fixture::commit(&mut f, &done);
    let replay = timer_fixture::project(&f, &plan);
    assert!(!replay.lowering.has_commit_work());
    assert_eq!(
        f.kernel
            .store()
            .list_effects(&f.instance)
            .expect("effects must remain readable after replay")
            .len(),
        1
    );
    drop(f);
    std::fs::remove_file(path).expect("fixture database must be removable");
}

#[test]
fn managed_terminal_outcome_native_selects_a_typed_failure_after_reopen() {
    assert_terminal_outcome_native(OUTCOME_SOURCE, "alias", "coerce failed");
    assert_terminal_outcome_native(OUTCOME_EXPRESSION_SOURCE, "expression", "coerce failed");
    assert_terminal_outcome_native(
        CHILD_OUTCOME_SOURCE,
        "child",
        "child action failed with 1 unrecovered cause",
    );
    assert_terminal_outcome_native(
        LEXICAL_HANDLER_SOURCE,
        "handler",
        "action scope failed with 1 unrecovered cause",
    );
    assert_terminal_outcome_native(
        RULE_HANDLER_SOURCE,
        "rule-handler",
        "rule progression failed with 1 unrecovered cause",
    );
}
