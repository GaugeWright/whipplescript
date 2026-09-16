use super::tests::source;
use super::*;

fn envelope(text: &str) -> VerifiedEnvelope {
    VerifiedEnvelope::for_test(Envelope::from_dsl(text).unwrap())
}
fn matching<'a>(errors: &'a [Diagnostic], code: &str) -> Vec<&'a Diagnostic> {
    errors.iter().filter(|e| e.code.as_str() == code).collect()
}

#[test]
fn region_exit_retains_private_field_selection_through_nested_helpers() {
    for polarity in ["during", "until"] {
        let text = format!(
            r#"@service
workflow Tail
class Input {{ secret string public string }}
class Output {{ value string }}
action publish() -> null {{ record Output {{ value "constant" }}
 return null }}
action wrap() -> null {{ publish()
 return null }}
rule run when Input as input => {{
 publish()
 {polarity} input.secret == "yes" {{ timer 1s as held }} on lapse {{ }}
 wrap()
 wrap()
}}"#
        );
        let analysis = source(&text);
        let bodies = analyze(&analysis).unwrap();
        let policy = VerifiedEnvelope::for_test(
            Envelope::from_json(r#"{"resources":{"Input.secret":{"reader":"Secret"}}}"#).unwrap(),
        );
        let errors = bodies.check_source_flows(&policy, &[]);
        let errors = matching(&errors, "security.projection_leak");
        assert_eq!(errors.len(), 2, "{polarity}: {errors:?}");
        assert_ne!(errors[0].related, errors[1].related);
        for e in errors {
            assert!(e.message.contains("Input.secret"));
            assert!(e
                .related
                .iter()
                .any(|r| r.message == "call to action `wrap`"));
        }
        let public = source(&text.replace("input.secret", "input.public"));
        assert!(analyze(&public)
            .unwrap()
            .check_source_flows(&policy, &[])
            .is_empty());
        let cleared = VerifiedEnvelope::for_test(Envelope::from_json(
            r#"{"resources":{"Input.secret":{"reader":"Secret"},"fact:Output":{"reader":"Secret"}}}"#).unwrap());
        assert!(bodies.check_source_flows(&cleared, &[]).is_empty());
    }
}

#[test]
fn region_exit_diagnostics_name_clean_exit_and_the_actual_helper_call() {
    let text = r#"@service
workflow Tail
signal inbound.ready { yes bool }
class Output { value string }
coerce make() -> Output { prompt "Build" }
action cross() -> null { coerce make() as made endorsed
 return null }
rule run when inbound.ready as event => {
 cross()
 during event.yes { timer 1s as held } on lapse { }
 cross()
 cross()
}"#;
    let analysis = source(text);
    let bodies = analyze(&analysis).unwrap();
    let errors = bodies.check_source_flows(&envelope(""), &[]);
    let errors = matching(&errors, "security.untrusted_selector");
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_ne!(errors[0].related, errors[1].related);
    for e in errors {
        assert!(e.message.contains("clean exit"), "{e:?}");
        assert!(e
            .related
            .iter()
            .any(|r| r.message == "call to action `cross`"));
        assert!(e
            .related
            .iter()
            .any(|r| text[r.span.start..r.span.end].contains("during event.yes")));
    }
    let vouched = envelope("grant signal event -> signal:inbound.ready from Reviewer");
    assert!(bodies.check_source_flows(&vouched, &[]).is_empty());
}

const EXECUTOR: &str = r#"@service
workflow Tail
agent unsafe { provider unvouched profile "reader" capacity 1 }
class A { value string }
class Output { value string }
action choose() -> string { tell unsafe "Choose" as value
 return value }
action publish() -> null { record Output { value "constant" }
 return null }
"#;

#[test]
fn region_exit_retains_executor_integrity_at_constant_tail_sinks() {
    let text = format!(
        r#"{EXECUTOR}
rule run when started => {{ publish()
 choose() as flag
 during flag == "yes" {{ timer 1s as held }} on lapse {{ }}
 publish()
 publish()
}}"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let grant = "grant fact out -> fact:Output from Operator";
    let errors = bodies.check_local_executor_integrity(&envelope(grant));
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_ne!(errors[0].related, errors[1].related);
    for e in errors {
        assert!(e.message.contains("executor `unvouched`"));
        assert!(e
            .related
            .iter()
            .any(|r| r.message == "call to action `publish`"));
    }
    assert!(bodies
        .check_local_executor_integrity(&envelope(&format!(
            "{grant}\ngrant provider safe -> unvouched from Operator"
        )))
        .is_empty());
}

#[test]
fn region_exit_keeps_fact_producer_influence_across_rules() {
    let text = format!(
        r#"{EXECUTOR}
rule consume when A as input => {{ record Output {{ value input.value }} }}
rule produce when started => {{ choose() as flag
 until flag == "stop" {{ timer 1s as held }} on lapse {{ }}
 record A {{ value "constant" }}
}}"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let policy = envelope("grant fact out -> fact:Output from Operator");
    let reach = fact_producers::reach(&bodies, &policy).unwrap();
    assert!(reach["A"].contains("output:unvouched"), "{reach:?}");
    assert!(reach["Output"].contains("output:unvouched"), "{reach:?}");
    let errors = bodies.check_local_executor_integrity(&policy);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("rule `consume`"));
}

#[test]
fn region_exit_keeps_fact_origins_without_an_executor_collector() {
    let text = r#"@service
workflow Tail
class Flag { value string }
class Before { value string }
class A { value string }
class Output { value string }
input incoming Flag
rule consume when A as input => { record Output { value input.value } }
rule produce when Flag as flag => {
 record Before { value "constant" }
 during flag.value == "go" { timer 1s as held } on lapse { }
 record A { value "constant" }
}"#;
    let analysis = source(text);
    let bodies = analyze(&analysis).unwrap();
    let policy = envelope("grant fact source -> fact:Flag readable by Secret");
    let reach = fact_producers::reach(&bodies, &policy).unwrap();
    assert!(reach["Before"].is_empty(), "{reach:?}");
    for name in ["Flag", "A", "Output"] {
        assert_eq!(
            reach[name],
            BTreeSet::from(["fact:Flag".into()]),
            "{name}: {reach:?}"
        );
    }
}
