use super::*;
use crate::lowering::OwnedLowering;
use crate::source_action::arguments::{Argument, Bindings};
use crate::source_action::progression::{advance, Leaf, Statement};
use crate::source_action::{Cause, ObservedCause, OwnedWork};
use serde_json::{json, Value};
use whipplescript_parser::action_plan::ActionPlan;
use whipplescript_parser::{parse_program, Item};

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
    let rule = parsed
        .program
        .items
        .iter()
        .find_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .expect("rule");
    whipplescript_parser::action_plan::expand_rule_syntax(&actions, rule, &[]).unwrap()
}

fn frame(identity: &str) -> Frame {
    Frame {
        version: "version-7".into(),
        revision: "revision-3".into(),
        rule: "run".into(),
        identity: Some(identity.into()),
        trigger_event: Some("event-11".into()),
    }
}

fn label(statement: &Statement<'_>) -> String {
    match statement.body {
        BodyStmt::Effect(effect) => effect.binding.clone().unwrap_or_else(|| "unbound".into()),
        _ => "pure".into(),
    }
}

fn leaf(work: OwnedWork, value: Option<Value>) -> Leaf {
    Leaf::Ready {
        lowering: Box::new(OwnedLowering::default()),
        value: value.map(Argument::from),
        work: Some(work),
    }
}

fn pending() -> Leaf {
    leaf(
        OwnedWork {
            state: WorkState::Pending,
            causes: BTreeMap::new(),
        },
        None,
    )
}

fn explain(
    plan: &ActionPlan,
    progression: &Progression,
    identity: &str,
    visible: &[&str],
) -> Explanation {
    project(
        plan,
        progression,
        "instance-1",
        &frame(identity),
        3,
        &visible.iter().map(|value| (*value).into()).collect(),
    )
    .unwrap()
}

#[test]
fn repeated_helpers_keep_distinct_result_ids_and_call_first_provenance() {
    let plan = plan(
        r#"action fetch(x string) -> string {
  timer 1s as wait
  return x
}
rule run when started => {
  fetch("a") as first
  fetch("b") as second
}"#,
    );
    let progression = advance(
        &plan,
        "instance-1",
        &frame("firing-a"),
        19,
        &Bindings::new(),
        &Default::default(),
        |_| Ok(pending()),
    )
    .unwrap();
    let explanation = explain(&plan, &progression, "firing-a", &[]);
    assert_eq!(explanation.schema, SCHEMA);
    assert_eq!(explanation.evaluated_frontier, 19);
    assert_eq!(explanation.program_version_id, "version-7");
    assert_eq!(explanation.firing.identity.as_deref(), Some("firing-a"));

    let waits: Vec<_> = explanation
        .results
        .iter()
        .filter(|result| result.name == "wait")
        .collect();
    assert_eq!(waits.len(), 2);
    assert_ne!(waits[0].result_id, waits[1].result_id);
    assert_ne!(waits[0].operation_id, waits[1].operation_id);
    for wait in waits {
        assert_eq!(wait.status, ResultStatus::Waiting);
        assert_eq!(wait.reasons, vec![ReasonCode::WaitingOperation]);
        assert_eq!(wait.source[0].role, SourceRole::CallSite);
        assert_eq!(wait.source[1].role, SourceRole::Definition);
        assert_eq!(wait.source[2].role, SourceRole::Result);
        assert_eq!(wait.source[1].action.as_deref(), Some("fetch"));
    }

    let other_firing = explain(&plan, &progression, "firing-b", &[]);
    assert_ne!(
        explanation.results[0].result_id, other_firing.results[0].result_id,
        "two firings never alias even over the same structural binding"
    );
}

#[test]
fn shared_causes_are_grouped_without_payload_or_secondary_cause_loss() {
    let plan = plan("rule run when started => { timer 1s as first\n timer 1s as second }");
    let shared = CauseId("run-shared".into());
    let secondary = CauseId("run-secondary".into());
    let secret = "provider-secret-payload";
    let cause = |id: &CauseId, witness: &str| {
        (
            id.clone(),
            ObservedCause {
                cause: Cause {
                    kind: FailureKind::Failed,
                    payload: json!({"secret": secret}),
                    evidence: BTreeSet::from([witness.into()]),
                },
                recovered: false,
            },
        )
    };
    let progression = advance(
        &plan,
        "instance-1",
        &frame("firing-a"),
        19,
        &Bindings::new(),
        &Default::default(),
        |statement| {
            let mut causes = BTreeMap::from([cause(&shared, "visible-event")]);
            if label(&statement) == "second" {
                causes.insert(secondary.clone(), cause(&secondary, "hidden-event").1);
            }
            Ok(leaf(
                OwnedWork {
                    state: WorkState::Failed(Disposition::Propagate),
                    causes,
                },
                None,
            ))
        },
    )
    .unwrap();
    let explanation = explain(&plan, &progression, "firing-a", &["visible-event"]);
    assert_eq!(explanation.causes.len(), 2);
    let shared = explanation
        .causes
        .iter()
        .find(|cause| cause.cause_id == "run-shared")
        .unwrap();
    assert_eq!(shared.dependents.len(), 2);
    assert_eq!(shared.witness_refs, vec!["visible-event"]);
    assert!(shared.witnesses_complete);
    let secondary = explanation
        .causes
        .iter()
        .find(|cause| cause.cause_id == "run-secondary")
        .unwrap();
    assert_eq!(secondary.dependents.len(), 1);
    assert!(secondary.witness_refs.is_empty());
    assert!(!secondary.witnesses_complete);
    let encoded = serde_json::to_string(&explanation).unwrap();
    assert!(
        !encoded.contains(secret),
        "failure payload crossed: {encoded}"
    );
    assert!(
        !encoded.contains("hidden-event"),
        "hidden witness crossed: {encoded}"
    );
    assert_eq!(
        serde_json::from_str::<Explanation>(&encoded).unwrap(),
        explanation
    );
}

#[test]
fn recovered_failure_remains_linked_to_the_ready_result() {
    let plan = plan("rule run when started => { timer 1s as answer }");
    let recovered = CauseId("earlier-failure".into());
    let progression = advance(
        &plan,
        "instance-1",
        &frame("firing-a"),
        19,
        &Bindings::new(),
        &Default::default(),
        |_| {
            Ok(leaf(
                OwnedWork {
                    state: WorkState::Succeeded,
                    causes: BTreeMap::from([(
                        recovered.clone(),
                        ObservedCause {
                            cause: Cause {
                                kind: FailureKind::Failed,
                                payload: json!({"message": "old"}),
                                evidence: BTreeSet::from(["terminal-4".into()]),
                            },
                            recovered: true,
                        },
                    )]),
                },
                Some(Value::Null),
            ))
        },
    )
    .unwrap();
    let explanation = explain(&plan, &progression, "firing-a", &["terminal-4"]);
    let result = explanation
        .results
        .iter()
        .find(|result| result.name == "answer")
        .unwrap();
    assert_eq!(result.status, ResultStatus::Ready);
    assert_eq!(result.cause_ids, vec!["earlier-failure"]);
    assert!(explanation.causes[0].recovered);
}

#[test]
fn recorded_selection_distinguishes_unselected_from_not_reached() {
    let plan = plan(
        r#"action choose(x string) -> int {
  case x {
    "a" => {
      timer 1s as chosen
      after chosen succeeds { timer 1s as later }
      return 1
    }
    "b" => {
      timer 1s as skipped
      return 2
    }
  }
}
rule run when started => {
  choose("a") as answer
}"#,
    );
    let progression = advance(
        &plan,
        "instance-1",
        &frame("firing-a"),
        19,
        &Bindings::new(),
        &Default::default(),
        |_| Ok(pending()),
    )
    .unwrap();
    let explanation = explain(&plan, &progression, "firing-a", &[]);
    let status = |name: &str| {
        explanation
            .results
            .iter()
            .find(|result| result.name == name)
            .map(|result| (result.status, result.reasons.clone()))
            .unwrap()
    };
    assert_eq!(
        status("chosen"),
        (ResultStatus::Waiting, vec![ReasonCode::WaitingOperation])
    );
    assert_eq!(
        status("skipped"),
        (ResultStatus::NotSelected, vec![ReasonCode::NotSelected])
    );
    assert_eq!(
        status("later"),
        (ResultStatus::NotReached, vec![ReasonCode::NotReached])
    );
}

#[test]
fn waiting_inputs_retain_exact_binding_and_named_result_reference() {
    let plan = plan(
        r#"action use(x string) -> string { return x }
rule run when started => {
  timer 1s as first
  use(first) as answer
}"#,
    );
    let progression = advance(
        &plan,
        "instance-1",
        &frame("firing-a"),
        19,
        &Bindings::new(),
        &Default::default(),
        |statement| {
            Ok(if label(&statement) == "first" {
                pending()
            } else {
                panic!("unexpected statement")
            })
        },
    )
    .unwrap();
    let explanation = explain(&plan, &progression, "firing-a", &[]);
    let first = explanation
        .results
        .iter()
        .find(|result| result.name == "first")
        .unwrap();
    let answer = explanation
        .results
        .iter()
        .find(|result| result.name == "answer")
        .unwrap();
    assert_eq!(answer.status, ResultStatus::Waiting);
    assert_eq!(answer.reasons, vec![ReasonCode::WaitingInput]);
    assert_eq!(answer.waiting_on.len(), 1);
    assert_eq!(answer.waiting_on[0].name.as_deref(), Some("first"));
    assert_eq!(
        answer.waiting_on[0].result_id.as_deref(),
        Some(first.result_id.as_str())
    );
}

#[test]
fn an_action_result_names_the_owned_operation_that_keeps_it_waiting() {
    let plan = plan(
        r#"action review() -> int {
  timer 1s as investigation
  timer 1s as policy
  return 42
}
rule run when started => {
  review() as reviewed
}"#,
    );
    let progression = advance(
        &plan,
        "instance-1",
        &frame("firing-a"),
        19,
        &Bindings::new(),
        &Default::default(),
        |statement| {
            Ok(if label(&statement) == "investigation" {
                leaf(
                    OwnedWork {
                        state: WorkState::Succeeded,
                        causes: BTreeMap::new(),
                    },
                    Some(Value::Null),
                )
            } else {
                pending()
            })
        },
    )
    .unwrap();
    let explanation = explain(&plan, &progression, "firing-a", &[]);
    let policy = explanation
        .results
        .iter()
        .find(|result| result.name == "policy")
        .unwrap();
    let policy_result_id = policy.result_id.clone();
    let reviewed = explanation
        .results
        .iter()
        .find(|result| result.name == "reviewed")
        .unwrap();
    assert_eq!(reviewed.status, ResultStatus::Waiting);
    assert_eq!(reviewed.reasons, vec![ReasonCode::WaitingOperation]);
    assert_eq!(reviewed.waiting_on.len(), 1);
    assert_eq!(reviewed.waiting_on[0].name.as_deref(), Some("policy"));
    assert_eq!(
        reviewed.waiting_on[0].result_id.as_deref(),
        Some(policy_result_id.as_str())
    );

    let response =
        query::resolve(&[explanation], "instance-1", "reviewed", Some("firing-a")).unwrap();
    let query::Outcome::Selected { selection } = response.outcome else {
        panic!("review result selected")
    };
    assert_eq!(
        selection.next_action.as_ref().map(|next| next.code),
        Some(query::NextActionCode::InspectResult)
    );
    assert_eq!(
        selection
            .next_action
            .as_ref()
            .and_then(|next| next.result_id.as_deref()),
        Some(policy_result_id.as_str())
    );
}

#[test]
fn invalid_plan_is_refused_before_it_can_mislabel_selection() {
    let mut plan = plan("rule run when started => { timer 1s as wait }");
    let progression = advance(
        &plan,
        "instance-1",
        &frame("firing-a"),
        19,
        &Bindings::new(),
        &Default::default(),
        |_| Ok(pending()),
    )
    .unwrap();
    plan.nodes[0].block = BlockId(usize::MAX);
    let error = project(
        &plan,
        &progression,
        "instance-1",
        &frame("firing-a"),
        3,
        &BTreeSet::new(),
    )
    .unwrap_err();
    assert!(
        error.contains("invalid action plan for explanation"),
        "{error}"
    );
}
