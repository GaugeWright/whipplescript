use super::*;
use whipplescript_parser::action_plan::resolved::resolve_rule_types;
use whipplescript_parser::{compile_program, parse_program};
pub(super) const HEADER: &str = r#"workflow Demo
agent safe { provider trusted }
agent unsafe { provider unvouched }
class Output { value string }
class Packet { safe string generated string }
class Input { value string gate bool }
table seed as Input [ { value "seed" gate true } ]
coerce tidy(text string) -> Output { prompt "Clean {{ text }}" }
"#;
pub(super) fn typed(source: &str) -> TypedActionPlan {
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let plan = resolve_rule_types(&parsed.program, "run").unwrap();
    let bytes = crate::source_action::plan_artifact::encode_typed(&plan).unwrap();
    crate::source_action::plan_artifact::decode_typed(&bytes).unwrap()
}
pub(super) fn context(trigger: &str) -> IrProgram {
    compiled(&format!(
        "{HEADER}rule run when {trigger} => {{ timer 1s as wait }}"
    ))
}
pub(super) fn compiled(source: &str) -> IrProgram {
    let compiled = compile_program(source);
    compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics))
}
pub(super) fn policy(extra: &str) -> VerifiedEnvelope {
    VerifiedEnvelope::for_test(Envelope::from_dsl(&format!("grant fact out -> fact:Output from Operator\ngrant provider trusted -> trusted from Operator\n{extra}")).unwrap())
}
pub(super) fn check_local_sinks(
    typed: &TypedActionPlan,
    ir: &IrProgram,
    policy: &VerifiedEnvelope,
) -> Vec<Diagnostic> {
    match sinks::inventory(typed, ir) {
        Ok(inventory) => inventory
            .local
            .iter()
            .flat_map(|sink| check_sink(typed, ir, policy, sink.as_sink()))
            .collect(),
        Err(error) => vec![*error],
    }
}
#[test]
fn managed_executor_nested_calls_preserve_every_provider_and_sink_callsite() {
    let source = format!(
        r#"{HEADER}
action produce(target AgentRef<safe | unsafe>) -> string {{ tell target "Draft" as text
return text }}
action publish(text string) -> null {{ record Output {{ value text }}
return null }}
action work(target AgentRef<safe | unsafe>) -> null {{ produce(target) as value
publish(value) as published
return null }}
rule run when started => {{ work(safe) as first
work(unsafe) as second }}"#
    );
    let plan = typed(&source);
    let errors = check_local_sinks(&plan, &context("started"), &policy(""));
    assert_eq!(errors.len(), 2, "{errors:?}");
    let mut callers = Vec::new();
    for error in errors {
        assert_eq!(error.code.as_str(), "security.integrity_injection");
        assert!(error.message.contains("executor `unvouched`"));
        assert!(source[error.span.start..error.span.end].contains("record Output"));
        for name in ["publish", "work"] {
            assert!(error
                .related
                .iter()
                .any(|r| r.message == format!("action `{name}` defined here")));
        }
        callers.push(
            error
                .related
                .iter()
                .find(|r| r.message == "call to action `work`")
                .unwrap()
                .span,
        );
    }
    assert_ne!(callers[0], callers[1]);
    assert!(check_local_sinks(
        &plan,
        &context("started"),
        &policy("grant provider unvouched -> unvouched from Operator")
    )
    .is_empty());
}
#[test]
fn managed_executor_projection_and_owned_completion_do_not_invent_payload_origins() {
    let source = format!(
        r#"{HEADER}
action packet() -> Packet {{ tell unsafe "Draft" as text
return {{ safe "constant" generated text }} }}
action identity(x Packet) -> Packet {{ return x }}
rule run when started => {{ packet() as value
identity(value) as forwarded
record Output {{ value forwarded.safe }} }}"#
    );
    assert!(check_local_sinks(&typed(&source), &context("started"), &policy("")).is_empty());
    let leaking = source.replace("value forwarded.safe", "value forwarded.generated");
    let errors = check_local_sinks(&typed(&leaking), &context("started"), &policy(""));
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("executor `unvouched`"));
}
#[test]
fn managed_executor_endorsement_needs_both_marker_and_sink_grant() {
    let source = format!(
        r#"{HEADER}
action release(text string) -> Output {{ coerce tidy(text) as cleaned endorsed
return cleaned }}
rule run when started => {{ tell unsafe "Draft" as raw
release(raw) as result
record Output {{ value result.value }} }}"#
    );
    let plan = typed(&source);
    let errors = check_local_sinks(&plan, &context("started"), &policy(""));
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("endorsed"));
    let granted = policy("grant endorse unvouched to Operator");
    assert!(check_local_sinks(&plan, &context("started"), &granted).is_empty());
    let unmarked = typed(&source.replace(" as cleaned endorsed", " as cleaned"));
    let errors = check_local_sinks(&unmarked, &context("started"), &granted);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("executor `model`"));
    let wrong_axis = typed(&source.replace(" as cleaned endorsed", " as cleaned declassified"));
    assert!(!check_local_sinks(&wrong_axis, &context("started"), &granted).is_empty());
}
#[test]
fn managed_executor_payload_marker_does_not_endorse_its_selector() {
    let source = format!(
        r#"{HEADER}
action release(text string) -> Output {{
case text {{ "ok" => {{ coerce tidy(text) as cleaned endorsed
return cleaned }} _ => {{ coerce tidy(text) as other endorsed
return other }} }} }}
rule run when started => {{ tell unsafe "Draft" as raw
release(raw) as result
record Output {{ value result.value }} }}"#
    );
    let errors = check_local_sinks(
        &typed(&source),
        &context("started"),
        &policy("grant endorse unvouched to Operator"),
    );
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("executor `unvouched`"));
    assert!(!errors[0].message.contains("lacks a matching"));
}
#[test]
fn managed_executor_earlier_guards_select_a_later_constant_sink() {
    let source = format!(
        r#"{HEADER}
rule run when started => {{ tell unsafe "Draft" as raw
case true {{ true where raw == "yes" => {{ timer 1s as skipped }}
 _ => {{ record Output {{ value "constant" }} }} }} }}"#
    );
    let errors = check_local_sinks(&typed(&source), &context("started"), &policy(""));
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("executor `unvouched`"));
}
#[test]
fn managed_executor_failure_and_region_observations_retain_executor_influence() {
    let failure = format!(
        r#"{HEADER}
action failer(text string) -> string ! string {{ fail text }}
rule run when started => {{ tell unsafe "Draft" as raw
 failer(raw) as result
 after result fails as error {{ record Output {{ value "failed" }} }} }}"#
    );
    assert_eq!(
        check_local_sinks(&typed(&failure), &context("started"), &policy("")).len(),
        1
    );
    let owned_failure = format!(
        r#"{HEADER}
action work() -> string ! string {{ tell unsafe "Draft" as text
fail "literal" }}
rule run when started => {{ work() as result
 after result fails as error {{ record Output {{ value "failed" }} }} }}"#
    );
    assert_eq!(
        check_local_sinks(&typed(&owned_failure), &context("started"), &policy("")).len(),
        1
    );
    let region = format!(
        r#"{HEADER}
rule run when started => {{ tell unsafe "Draft" as text
 during text == "go" {{ record Output {{ value "held" }} }} on lapse as progress {{ record Output {{ value "lapsed" }} }} }}"#
    );
    assert_eq!(
        check_local_sinks(&typed(&region), &context("started"), &policy("")).len(),
        2
    );
}
#[test]
fn managed_executor_fact_inputs_keep_the_original_producer_executor() {
    let source = format!(
        r#"{HEADER}
action identity(x string) -> string {{ return x }}
rule run when Input as input => {{ identity(input.value) as text
record Output {{ value text }} }}"#
    );
    let mut ir = context("Input as input");
    let producer = compiled(&format!(
        r#"{HEADER}
rule produce when started => {{ tell unsafe "Draft" as turn
 after turn succeeds as value {{ record Input {{ value value.summary gate true }} }} }}
rule run when Input as input => {{ timer 1s as wait }}"#
    ));
    ir.rules = producer.rules;
    let errors = check_local_sinks(&typed(&source), &ir, &policy(""));
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("executor `unvouched`"));
}
#[test]
fn managed_executor_refuses_missing_or_ambiguous_policy_context() {
    let source = format!("{HEADER}rule run when started => {{ tell unsafe \"Draft\" as raw\nrecord Output {{ value raw }} }}");
    let original = typed(&source);
    let sink_node = NodeId(original.plan.nodes.iter().position(|node| {
        matches!(&node.kind, NodeKind::Statement(body) if matches!(body.as_ref(), BodyStmt::Record(_)))
    }).unwrap());
    let payload = [Expr::Path(vec!["raw".into()])];
    for which in 0..5 {
        let mut plan = original.clone();
        let mut ir = context("started");
        match which {
            0 => plan.effects.clear(),
            1 => ir.rules.clear(),
            2 => ir.agents.retain(|a| a.name != "unsafe"),
            3 => ir.agents.push(
                ir.agents
                    .iter()
                    .find(|a| a.name == "unsafe")
                    .unwrap()
                    .clone(),
            ),
            _ => ir.rules.push(
                ir.rules
                    .iter()
                    .find(|rule| rule.name == "run")
                    .unwrap()
                    .clone(),
            ),
        }
        let envelope = policy("grant provider unvouched -> unvouched from Operator");
        // Keep the original per-sink refusals independently exercised: an
        // inventory refusal must not mask a regression in that lower-level API.
        let direct = check_sink(
            &plan,
            &ir,
            &envelope,
            Sink {
                node: sink_node,
                resource: "fact:Output",
                payload: &payload,
                selection: &[],
            },
        );
        assert!(!direct.is_empty(), "direct {which}");
        assert!(
            direct
                .iter()
                .all(|d| d.code.as_str() == "construct.invalid_expansion"),
            "{direct:?}"
        );
        let errors = check_local_sinks(
            &plan,
            &ir,
            &policy("grant provider unvouched -> unvouched from Operator"),
        );
        assert!(!errors.is_empty(), "{which}");
        assert!(
            errors
                .iter()
                .all(|d| d.code.as_str() == "construct.invalid_expansion"),
            "{errors:?}"
        );
    }
    let ir = context("started");
    let at = original.plan.blocks[original.plan.root.0].nodes[0];
    let missing = check_sink(
        &original,
        &ir,
        &policy(""),
        Sink {
            node: at,
            resource: "",
            payload: &[],
            selection: &[],
        },
    );
    assert_eq!(missing.len(), 1);
    assert!(missing[0].message.contains("requires a resource"));
    let source = format!(
        "{HEADER}rule run when Input as input => {{ record Output {{ value input.value }} }}"
    );
    assert!(check_local_sinks(&typed(&source), &ir, &policy(""))
        .iter()
        .any(|d| d.message.contains("matching producer analysis")));
}
#[test]
fn managed_executor_shared_legacy_policy_still_requires_endorsed_grants() {
    let source = format!(
        r#"{HEADER}
rule run when started => {{ tell unsafe "Draft" as turn
 after turn succeeds as value {{ coerce tidy(value.summary) as cleaned endorsed
 after cleaned succeeds as result {{ record Output {{ value result.value }} }} }} }}"#
    );
    let ir = compiled(&source);
    let errors = check_with_envelope(&ir, &policy(""));
    assert!(
        errors
            .iter()
            .any(|d| d.message.contains("output of executor `unvouched`")
                && d.message.contains("endorsed")),
        "{errors:?}"
    );
    let granted = check_with_envelope(&ir, &policy("grant endorse unvouched to Operator"));
    assert!(
        !granted
            .iter()
            .any(|d| d.message.contains("output of executor `unvouched`")),
        "{granted:?}"
    );
}

#[test]
fn managed_executor_requires_a_rule_owner_even_for_a_valid_standalone_action() {
    let program =
        parse_program("workflow Demo\naction empty() -> string { return \"constant\" }").program;
    let actions = program
        .items
        .iter()
        .filter_map(|item| match item {
            whipplescript_parser::Item::Action(a) => Some(a.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let plan = whipplescript_parser::action_plan::expand_syntax(&actions, "empty").unwrap();
    let typed = TypedActionPlan {
        plan,
        case_types: BTreeMap::new(),
        effects: BTreeMap::new(),
        views: BTreeMap::new(),
    };
    typed.validate_structure().unwrap();
    let errors = check_sink(
        &typed,
        &context("started"),
        &policy(""),
        Sink {
            node: NodeId(0),
            resource: "fact:Output",
            payload: &[],
            selection: &[],
        },
    );
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("requires a root rule"));
}

#[test]
fn managed_executor_declassification_preserves_integrity_and_empty_domains_stay_empty() {
    let source = format!(
        r#"{HEADER}
rule run when started => {{ coerce tidy("draft") as result
 declassify result into Output as released
 record Output {{ value released.value }} }}"#
    );
    let errors = check_local_sinks(
        &typed(&source),
        &context("started"),
        &policy("grant declassify model to Operator"),
    );
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("executor `model`"));
    let source = format!(
        r#"{HEADER}
action work(target AgentRef<safe | unsafe>) -> null {{ case target {{
 safe => {{ timer 1s as waited }}
 unsafe => {{ timer 1s as waited }}
 _ => {{ tell target "Unreachable" as raw
 record Output {{ value raw }} }} }}
return null }}
rule run when started => {{ work(unsafe) as result }}"#
    );
    let plan = typed(&source);
    assert!(plan
        .effects
        .values()
        .any(|e| e.agent_targets.as_ref().is_some_and(Vec::is_empty)));
    assert!(check_local_sinks(&plan, &context("started"), &policy("")).is_empty());
}
