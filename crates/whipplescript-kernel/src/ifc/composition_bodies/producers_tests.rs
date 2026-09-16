use super::tests::source;
use super::*;
const HEADER: &str = r#"@service
workflow Producers
agent unsafe { provider unvouched profile "reader" capacity 1 }
class A { value string }
class B { value string }
class Output { value string }
file store secret { root "./secret" allow read ["**"] }
coerce tidy(text string) -> B { prompt "Clean {{ text }}" }
"#;
fn policy(extra: &str) -> VerifiedEnvelope {
    VerifiedEnvelope::for_test(
        Envelope::from_dsl(&format!(
            "grant fact out -> fact:Output from Operator\n{extra}"
        ))
        .unwrap(),
    )
}
#[test]
fn source_producers_reach_every_downstream_sink_independent_of_rule_order() {
    let text = format!(
        r#"{HEADER}
action publish(text string) -> null {{ record Output {{ value text }}
 return null }}
action produce() -> string {{ tell unsafe "Draft" as text
 return text }}
rule last when B as value => {{ publish(value.value)
 publish(value.value) }}
rule middle when A as value => {{ record B {{ value value.value }} }}
rule first when started => {{ produce() as text
 record A {{ value text }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let policy = policy("");
    let reach = fact_producers::reach(&bodies, &policy).unwrap();
    for name in ["A", "B", "Output"] {
        assert!(reach[name].contains("output:unvouched"), "{reach:?}");
    }
    let errors = bodies.check_local_executor_integrity(&policy);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors[0].message.contains("executor `unvouched`"));
    assert_ne!(errors[0].related, errors[1].related);
    assert!(text[errors[0].span.start..errors[0].span.end].contains("record Output"));
    assert!(errors[0]
        .related
        .iter()
        .any(|r| r.message == "call to action `publish`"));
    assert!(bodies
        .check_local_executor_integrity(&self::policy(
            "grant provider trusted -> unvouched from Operator"
        ))
        .is_empty());
}
#[test]
fn producer_resource_reads_and_grants_survive_cycles_and_constant_records() {
    for work in [
        "read text from secret at \"in.txt\" as loaded",
        "tell unsafe as turn\n with access to secret { read [\"**\"] }\n \"Read\"",
    ] {
        let text = format!(
            r#"{HEADER}
rule last when B as value => {{ record Output {{ value value.value }} }}
rule backward when B as value => {{ record A {{ value value.value }} }}
rule middle when A as value => {{ record B {{ value value.value }} }}
rule first when started => {{ {work}
 record A {{ value "constant" }} }}
"#
        );
        let analysis = source(&text);
        let bodies = analyze(&analysis).unwrap();
        let reach = fact_producers::reach(&bodies, &policy("")).unwrap();
        for name in ["A", "B", "Output"] {
            assert!(reach[name].contains("secret"), "{work}: {reach:?}");
        }
    }
}
#[test]
fn producer_endorsement_cannot_be_used_as_permission_at_a_later_sink() {
    let text = format!(
        r#"{HEADER}
rule last when B as value => {{ record Output {{ value value.value }} }}
rule first when started => {{ tell unsafe "Draft" as text
 coerce tidy(text) as cleaned endorsed
 record B {{ value cleaned.value }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let policy =
        policy("grant fact mid -> fact:B from Operator\ngrant endorse unvouched to Operator");
    let reach = fact_producers::reach(&bodies, &policy).unwrap();
    assert!(reach["B"].contains("output:unvouched"));
    let errors = bodies.check_local_executor_integrity(&policy);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("rule `last`"));
    assert!(!errors[0].message.contains("endorsed"));
}
#[test]
fn a_later_unmarked_model_owns_its_output_without_losing_source_provenance() {
    let text = format!(
        r#"{HEADER}
rule last when B as value => {{ record Output {{ value value.value }} }}
rule middle when A as value => {{ coerce tidy(value.value) as cleaned
 record B {{ value cleaned.value }} }}
rule first when started => {{ tell unsafe as text
 with access to secret {{ read ["**"] }}
 "Draft"
 record A {{ value text }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let policy = policy("grant provider judge -> model from Operator");
    let reach = fact_producers::reach(&bodies, &policy).unwrap();
    assert!(reach["A"].contains("output:unvouched"));
    assert!(reach["B"].contains("secret"));
    assert!(reach["B"].contains("output:model"));
    assert!(!reach["B"].contains("output:unvouched"));
    assert!(bodies.check_local_executor_integrity(&policy).is_empty());
}
#[test]
fn producer_labels_distinguish_authored_seeds_inputs_and_external_arrivals() {
    let text = format!(
        r#"{HEADER}
input incoming A
table seed as B [{{ value "seed" }}]
@external
rule external when A as value => {{ record Output {{ value value.value }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let reach = fact_producers::reach(&bodies, &policy("")).unwrap();
    assert_eq!(reach["A"], BTreeSet::from(["fact:A".into()]));
    assert!(reach["Output"].contains("fact:A"));
    assert!(reach["B"].is_empty());
    let reach =
        fact_producers::reach(&bodies, &policy("grant fact seed -> fact:B from Operator")).unwrap();
    assert_eq!(reach["B"], BTreeSet::from(["fact:B".into()]));
    let internal = source(&text.replace("@external\n", ""));
    let bodies = analyze(&internal).unwrap();
    let reach = fact_producers::reach(&bodies, &policy("")).unwrap();
    assert!(reach.get("A").is_none_or(BTreeSet::is_empty));
    let reach = fact_producers::reach(
        &bodies,
        &policy("grant fact incoming -> fact:A from Operator"),
    )
    .unwrap();
    assert_eq!(reach["A"], BTreeSet::from(["fact:A".into()]));
}

#[test]
fn producer_selection_and_failure_observation_keep_fact_origins() {
    let action = r#"action reject(value A) -> null ! string { fail value.value }
"#;
    for body in [
        "case value.value { \"yes\" => { record B { value \"constant\" } } _ => { timer 1s as wait } }",
        "during value.value == \"yes\" { record B { value \"constant\" } } on lapse as progress { timer 1s as wait }",
        "during value.value == \"yes\" { timer 1s as wait } on lapse as progress { record B { value \"constant\" } }",
        "reject(value) as result\nafter result fails as reason { record B { value \"failed\" } }",
    ] {
        let text = format!(r#"{HEADER}{action}
rule last when B as value => {{ record Output {{ value value.value }} }}
rule middle when A as value => {{ {body} }}
rule first when started => {{ tell unsafe as text
 with access to secret {{ read ["**"] }}
 "Draft"
 record A {{ value text }} }}
"#);
        let analysis = source(&text);
        let bodies = analyze(&analysis).unwrap();
        let policy = policy("");
        let reach = fact_producers::reach(&bodies, &policy).unwrap();
        assert!(reach["B"].contains("secret"), "{body}: {reach:?}");
        assert!(reach["B"].contains("output:unvouched"), "{body}: {reach:?}");
        let errors = bodies.check_local_executor_integrity(&policy);
        assert_eq!(errors.len(), 1, "{body}: {errors:?}");
    }
}

#[test]
fn an_unattributable_outcome_keeps_the_governed_fact_fallback() {
    let text = format!(
        r#"{HEADER}
rule run when A as value => {{ timer 1s as wait
 after wait fails as failure {{ record B {{ value "constant" }} }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let reach =
        fact_producers::reach(&bodies, &policy("grant fact mid -> fact:B from Operator")).unwrap();
    assert_eq!(reach["B"], BTreeSet::from(["fact:B".into()]));
}

#[test]
fn producer_failures_cannot_become_an_empty_map_or_omit_a_sibling() {
    let text = format!(
        r#"{HEADER}
action publish(value A) -> null {{ record B {{ value value.value }}
 return null }}
rule first when A as value => {{ publish(value) }}
rule second when A as value => {{ publish(value) }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let mut damaged: Vec<_> = bodies
        .rules()
        .iter()
        .map(|body| body.rule.clone())
        .collect();
    for rule in &mut damaged {
        rule.root.whens.clear();
    }
    // Corrupt only the internal source/root join. Keep each actual typed plan
    // and derived inventory so the missing producer context must refuse.
    let corrupt = CompositionBodies {
        source: &analysis,
        rules: bodies
            .rules
            .into_iter()
            .zip(damaged.iter())
            .map(|(body, rule)| RuleBodyAnalysis {
                rule,
                inventory: body.inventory,
            })
            .collect(),
    };
    let errors = corrupt.check_local_executor_integrity(&policy(""));
    assert_eq!(errors.len(), 2, "{errors:?}");
    for error in &errors {
        assert!(error.message.contains("no matching producer analysis"));
        let origin = error
            .related
            .iter()
            .find(|r| r.message == "producer value originates here")
            .unwrap();
        assert!(text[origin.span.start..origin.span.end].contains("value"));
        assert!(text[error.span.start..error.span.end].contains("record B"));
        assert!(error
            .related
            .iter()
            .any(|r| r.message == "call to action `publish`"));
    }
    assert_ne!(errors[0].related, errors[1].related);
}

#[test]
fn producer_projection_does_not_invent_a_flow_from_an_unused_field_or_helper() {
    let text = format!(
        r#"{HEADER}
class Packet {{ safe string generated string }}
action unused() -> null {{ tell unsafe as text
 with access to secret {{ read ["**"] }}
 "Unused"
 return null }}
action pack() -> Packet {{ tell unsafe "Draft" as generated
 return {{ safe "constant" generated generated }} }}
rule last when A as value => {{ record Output {{ value value.value }} }}
rule first when started => {{ pack() as packet
 record A {{ value packet.safe }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let reach = fact_producers::reach(&bodies, &policy("")).unwrap();
    assert!(reach["A"].is_empty(), "{reach:?}");
    assert!(bodies
        .check_local_executor_integrity(&policy(""))
        .is_empty());
    let selected = source(&text.replace("value packet.safe", "value packet.generated"));
    let bodies = analyze(&selected).unwrap();
    assert_eq!(bodies.check_local_executor_integrity(&policy("")).len(), 1);
}

#[test]
fn pure_declassification_preserves_recorded_source_and_executor_origins() {
    let text = format!(
        r#"{HEADER}
action release(value A) -> B {{ declassify value into B as released
 return released }}
rule last when B as value => {{ record Output {{ value value.value }} }}
rule middle when A as value => {{ release(value) as released
 record B from released {{}} }}
rule first when started => {{ tell unsafe as text
 with access to secret {{ read ["**"] }}
 "Draft"
 record A {{ value text }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let reach = fact_producers::reach(&bodies, &policy("")).unwrap();
    assert!(reach["B"].contains("secret"));
    assert!(reach["B"].contains("output:unvouched"));
    assert_eq!(bodies.check_local_executor_integrity(&policy("")).len(), 1);
}

#[test]
fn failed_owned_operations_contribute_without_a_success_return() {
    let text = format!(
        r#"{HEADER}
action work() -> null ! string {{ tell unsafe as text
 with access to secret {{ read ["**"] }}
 "Draft"
 fail "failed" }}
rule last when B as value => {{ record Output {{ value value.value }} }}
rule first when started => {{ work() as result
 after result fails as error {{ record B {{ value "constant" }} }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let reach = fact_producers::reach(&bodies, &policy("")).unwrap();
    assert!(reach["B"].contains("secret"));
    assert!(reach["B"].contains("output:unvouched"));
    assert_eq!(bodies.check_local_executor_integrity(&policy("")).len(), 1);
}

#[test]
fn opening_a_value_keeps_its_executor_without_inventing_endorsement() {
    let declarations = r#"use std.custody
@service
workflow Opened
agent unsafe { provider unvouched profile "reader" capacity 1 }
class Payload { value string }
class Packed { body sealed<Payload> }
class Output { value string }
credential key { kind raw }
coerce pack(text string) -> Packed { prompt "Pack {{ text }}" }
"#;
    let text = format!(
        r#"{declarations}
rule run when started => {{ tell unsafe "Draft" as raw
 coerce pack(raw) as packed
 open packed.body into Payload with key as opened
 after opened succeeds {{ record Output {{ value "opened" }} }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let denied = policy("grant endorse model to Operator");
    let errors = bodies.check_local_executor_integrity(&denied);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("executor `model`"));
    assert!(!errors[0].message.contains("endorsed"));
    assert!(bodies
        .check_local_executor_integrity(&policy("grant provider judge -> model from Operator"))
        .is_empty());

    let legacy = format!(
        r#"{declarations}
rule run when started => {{ tell unsafe "Draft" as turn
 after turn succeeds {{ coerce pack(turn.summary) as packed
 after packed succeeds {{ open packed.body into Payload with key as opened
 after opened succeeds {{ declassify opened into Output as released
 record Output from released {{}} }} }} }} }}
"#
    );
    let compiled = whipplescript_parser::compile_program(&legacy);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
    let errors = check_with_envelope(&ir, &denied);
    assert!(
        errors
            .iter()
            .any(|e| e.code.as_str() == "security.integrity_injection"
                && e.message.contains("executor `model`")),
        "{errors:?}"
    );
    assert!(
        !check_with_envelope(&ir, &policy("grant provider judge -> model from Operator"))
            .iter()
            .any(|e| e.code.as_str() == "security.integrity_injection")
    );
}

#[test]
fn message_and_signal_inputs_are_own_sources_even_for_constant_records() {
    for (declaration, trigger, origin) in [
        ("channel inbox", "message from inbox as notice", "inbox"),
        (
            "signal message.arrived { value string }",
            "message.arrived as notice",
            "signal:message.arrived",
        ),
    ] {
        let text = format!("{HEADER}{declaration}\nrule first when {trigger} => {{ record A {{ value \"constant\" }} }}\nrule last when A as value => {{ record Output {{ value value.value }} }}");
        let analysis = source(&text);
        let bodies = analyze(&analysis).unwrap();
        let reach = fact_producers::reach(&bodies, &policy("")).unwrap();
        assert!(reach["A"].contains(origin), "{reach:?}");
        assert!(reach["Output"].contains(origin), "{reach:?}");
    }
}

#[test]
fn a_read_value_is_attributable_without_an_invented_fallback_label() {
    let text = format!(
        r#"{HEADER}
action load() -> B {{ read text from secret at "in.txt" as loaded
 coerce tidy(loaded.content) as cleaned
 return cleaned }}
rule run when A as value => {{ load() as result
 record B from result {{}} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let reach =
        fact_producers::reach(&bodies, &policy("grant fact mid -> fact:B from Operator")).unwrap();
    assert_eq!(
        reach["B"],
        BTreeSet::from(["secret".into(), "output:model".into()])
    );
}

#[test]
fn an_owned_failed_transformation_retains_its_upstream_fact_sources() {
    let text = format!(
        r#"{HEADER}
action reject(value A) -> null ! string {{ coerce tidy(value.value) as ignored
 fail "failed" }}
rule last when B as value => {{ record Output {{ value value.value }} }}
rule middle when A as value => {{ reject(value) as result
 after result fails as error {{ record B {{ value "constant" }} }} }}
rule first when started => {{ tell unsafe as text
 with access to secret {{ read ["**"] }}
 "Draft"
 record A {{ value text }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let reach = fact_producers::reach(&bodies, &policy("")).unwrap();
    assert!(reach["B"].contains("secret"));
    assert!(reach["B"].contains("output:model"));
}

#[test]
fn every_record_in_one_rule_contributes_its_own_provenance() {
    let text = format!(
        r#"{HEADER}
rule last when A as value => {{ record Output {{ value value.value }} }}
rule first when started => {{ record A {{ value "constant" }}
 tell unsafe "Draft" as text
 record A {{ value text }} }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let reach = fact_producers::reach(&bodies, &policy("")).unwrap();
    assert!(reach["A"].contains("output:unvouched"));
    assert_eq!(bodies.check_local_executor_integrity(&policy("")).len(), 1);
}
