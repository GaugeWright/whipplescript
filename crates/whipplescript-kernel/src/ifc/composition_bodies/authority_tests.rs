use super::tests::source;
use super::*;

const HEADER: &str = r#"@service
workflow Authority
class Input { value string }
class Output { value string }
file store secret { root "./secret" allow read ["**"] }
agent worker { provider trusted }
"#;
const PARTIES: &str = "party alice : Operator\nparty bob : Requester\n";
fn policy(text: &str) -> VerifiedEnvelope {
    VerifiedEnvelope::for_test(Envelope::from_dsl(text).unwrap())
}
fn ceiling(text: &str, envelope: &str, identity: &str) -> Vec<Diagnostic> {
    let analysis = source(text);
    analyze(&analysis)
        .unwrap()
        .check_principal_ceiling_for_identity(&policy(envelope), identity, &[])
}
fn compiled(text: &str) -> IrProgram {
    let compiled = whipplescript_parser::compile_program(text);
    compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics))
}
fn unwrap(text: &str, envelope: &str) -> Vec<Diagnostic> {
    let analysis = source(text);
    analyze(&analysis)
        .unwrap()
        .check_turn_unwrap_scoping(&policy(envelope))
}
fn has_call(error: &Diagnostic, name: &str) -> bool {
    error
        .related
        .iter()
        .any(|r| r.message == format!("call to action `{name}`"))
}

#[test]
fn every_expanded_read_keeps_its_nested_call_chain_and_all_rules_are_checked() {
    let text=format!("{HEADER}action load() -> null {{ read text from secret at \"in.txt\" as loaded\n return null }}\naction outer() -> null {{ load()\n return null }}\nrule first when started => {{ outer()\n outer() }}\nrule second when started => {{ load() }}");
    let envelope = format!("{PARTIES}grant file_store secret -> secret readable by Operator");
    let errors = ceiling(&text, &envelope, "bob");
    assert_eq!(errors.len(), 3, "{errors:?}");
    for error in &errors {
        assert_eq!(error.code.as_str(), "security.principal_ceiling_exceeded");
        assert!(text[error.span.start..error.span.end].contains("read text from secret"));
        assert!(has_call(error, "load"));
    }
    let nested: Vec<_> = errors.iter().filter(|e| has_call(e, "outer")).collect();
    assert_eq!(nested.len(), 2);
    assert_ne!(nested[0].related, nested[1].related);
    assert!(ceiling(&text, &envelope, "alice").is_empty());
}

#[test]
fn identity_resolution_is_explicit_and_requires_every_compartment() {
    let text=format!("{HEADER}action load() -> null {{ read text from secret at \"in.txt\" as loaded\n return null }}\nrule run when started => {{ load() }}");
    let base = "grant file_store secret -> secret readable by Operator";
    assert!(
        ceiling(&text, base, "unknown").is_empty(),
        "no party map is gradual"
    );
    let mapped = format!("{PARTIES}{base}");
    let unknown = ceiling(&text, &mapped, "unknown");
    assert_eq!(unknown.len(), 1);
    assert!(unknown[0].message.contains("acts-for `public`"));
    let mixed =
        format!("{PARTIES}grant file_store secret -> secret readable by Operator, Reviewer");
    assert_eq!(
        ceiling(&text, &mixed, "alice").len(),
        1,
        "one compartment is insufficient"
    );
    let both = format!("{mixed}\ndelegate Operator acts-for Reviewer");
    assert!(ceiling(&text, &both, "alice").is_empty());
    assert!(
        ceiling(&text, PARTIES, "unknown").is_empty(),
        "unprotected read is public"
    );
}

#[test]
fn classified_grant_reads_include_foreign_egress_verbs_but_not_local_writes() {
    for (resource, operation, expected) in [
        ("secret", "read", 1),
        ("secret", "write", 0),
        ("remote", "notify", 1),
    ] {
        let text=format!("{HEADER}action ask() -> string {{ tell worker \"Read\" with access to {resource} {{ {operation} [\"**\"] }} as result\n return result }}\nrule run when started => {{ ask() }}");
        let envelope = format!("{PARTIES}grant resource source -> {resource} readable by Operator");
        let errors = ceiling(&text, &envelope, "bob");
        assert_eq!(errors.len(), expected, "{resource}/{operation}: {errors:?}");
        if expected > 0 {
            assert!(has_call(&errors[0], "ask"));
            assert!(errors[0].message.contains(resource));
        }
    }
}

#[test]
fn root_messages_signals_trackers_matched_facts_and_guard_queries_require_clearance() {
    for (declaration, trigger, label) in [
        ("channel inbox", "message from inbox as notice", "inbox"),
        (
            "signal work.done { detail string }",
            "work.done as event",
            "signal:work.done",
        ),
        (
            "tracker jobs { provider builtin }",
            "jobs has ready issue as item",
            "jobs",
        ),
        ("input incoming Input", "Input as value", "fact:Input"),
        (
            "input incoming Input",
            "started where exists(Input where value == \"yes\")",
            "fact:Input",
        ),
    ] {
        let text=format!("{HEADER}{declaration}\naction work() -> null {{ return null }}\nrule run when {trigger} => {{ work() }}");
        let envelope = format!("{PARTIES}grant source source -> {label} readable by Operator");
        let errors = ceiling(&text, &envelope, "bob");
        assert_eq!(errors.len(), 1, "{trigger}: {errors:?}");
        assert!(errors[0].message.contains(label));
        assert!(
            text[errors[0].span.start..errors[0].span.end].contains(trigger),
            "{errors:?}"
        );
        assert!(ceiling(&text, &envelope, "alice").is_empty());
    }
}

#[test]
fn later_release_grants_do_not_raise_the_users_read_ceiling() {
    let text=format!("{HEADER}coerce clean(value string) -> Output {{ prompt \"Clean {{{{ value }}}}\" }}\naction read_and_release() -> null {{ read text from secret at \"in.txt\" as loaded\n coerce clean(loaded.content) as result declassified\n record Output {{ value result.value }}\n return null }}\nrule run when started => {{ read_and_release() }}");
    let envelope=format!("{PARTIES}grant file_store secret -> secret readable by Operator\ngrant fact out -> fact:Output readable by Requester\ngrant declassify secret to Requester");
    let errors = ceiling(&text, &envelope, "bob");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(
        errors[0].code.as_str(),
        "security.principal_ceiling_exceeded"
    );
}

fn importer() -> String {
    format!("{HEADER}agent reader {{ provider trusted tools [Fetcher] }}\nclass Trigger {{ value string }}\ntable trigger as Trigger [{{ value \"go\" }}]\naction fetch() -> string {{ tell reader \"Fetch\" as result\n return result }}\nrule consume when Input as value => {{ record Output {{ value value.value }} }}\nrule produce when Trigger as trigger => {{ fetch() as first\n fetch() as second\n record Input {{ value first }} }}")
}
fn tool() -> IrProgram {
    compiled(
        r#"@tool
workflow Fetcher {
 input request Req
 output result Result
 class Req { id string }
 class Result { data string }
 file store secret { root "./secret" allow read ["**"] }
 rule fetch when Req as request => {
  read text from secret at "in.txt" as loaded
  after loaded succeeds as value { complete result { data value.content } }
 }
}"#,
    )
}

#[test]
fn imported_results_retain_each_call_site_and_downstream_fact_sources() {
    let text = importer();
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let envelope = policy(&format!(
        "{PARTIES}grant file_store secret -> secret readable by Operator"
    ));
    let tool = tool();
    let errors =
        bodies.check_principal_ceiling_for_identity(&envelope, "bob", std::slice::from_ref(&tool));
    assert_eq!(errors.len(), 3, "{errors:?}");
    let calls: Vec<_> = errors.iter().filter(|e| has_call(e, "fetch")).collect();
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].related, calls[1].related);
    assert!(errors
        .iter()
        .any(|e| e.message.contains("rule `consume`") && e.message.contains("secret")));
    assert!(bodies
        .check_principal_ceiling_for_identity(&envelope, "alice", &[tool])
        .is_empty());
}

#[test]
fn missing_or_ambiguous_imports_cannot_prove_an_empty_read_ceiling() {
    let text = importer();
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let tool = tool();
    for imports in [vec![], vec![tool.clone(), tool]] {
        let errors =
            bodies.check_principal_ceiling_for_identity(&policy(PARTIES), "alice", &imports);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors
            .iter()
            .all(|e| e.message.contains("one complete imported program") && has_call(e, "fetch")));
    }
}

#[test]
fn failed_producer_analysis_cannot_prove_an_empty_read_ceiling() {
    let text=format!("{HEADER}input incoming Input\nrule produce when Input as value => {{ record Output {{ value value.value }} }}");
    let analysis = source(&text);
    let mut bodies = analyze(&analysis).unwrap();
    let mut actual = analysis.rules()[0].clone();
    actual.root.whens.clear();
    let invalid = CompositionBodies {
        source: &analysis,
        rules: vec![RuleBodyAnalysis {
            rule: &actual,
            inventory: bodies.rules.remove(0).inventory,
        }],
    };
    let errors = invalid.check_principal_ceiling_for_identity(&policy(PARTIES), "alice", &[]);
    assert!(!errors.is_empty());
    assert!(
        errors
            .iter()
            .any(|e| e.message.contains("producer analysis")),
        "{errors:?}"
    );
}

fn unwrap_source(grants: &str) -> String {
    format!("{HEADER}credential key {{ kind raw }}\ncredential other {{ kind raw }}\nclass A {{ value string }}\nclass B {{ value string }}\naction ask() -> string {{ tell worker \"Read\" {grants} as result\n return result }}\naction outer() -> string {{ ask() as result\n return result }}\nrule run when started => {{ outer()\n outer() }}")
}

#[test]
fn unwrap_scoping_requires_the_exact_payload_and_preserves_each_call_chain() {
    let text = unwrap_source("with access to credential key { unwrap for A }");
    for (envelope, count) in [
        ("", 0),
        ("grant credential key -> credential:key", 2),
        (
            "grant credential key -> credential:key\ngrant unwrap key for A to Operator",
            0,
        ),
        (
            "grant credential key -> credential:key\ngrant unwrap key for B to Operator",
            2,
        ),
    ] {
        let errors = unwrap(&text, envelope);
        assert_eq!(errors.len(), count, "{envelope}: {errors:?}");
        for error in &errors {
            assert_eq!(error.code.as_str(), "security.unwrap_not_granted");
            assert!(has_call(error, "ask") && has_call(error, "outer"));
            assert!(text[error.span.start..error.span.end].contains("tell worker"));
            assert!(error.message.contains("unwrap for A"));
        }
        if count == 2 {
            assert_ne!(errors[0].related, errors[1].related);
        }
    }
    let errors = unwrap(
        &text,
        "grant credential key -> credential:key\ngrant unwrap key for B to Operator",
    );
    assert!(errors[0].suggestion.as_deref().unwrap().contains("for B;"));
}

#[test]
fn unwrap_checks_all_credentials_and_payload_types_independently_of_parties() {
    let text=unwrap_source("with access to credential key { unwrap for A unwrap for B } with access to credential other { unwrap for A }");
    let partial = "grant credential key -> credential:key\ngrant unwrap key for A to Operator\ngrant credential other -> credential:other";
    let errors = unwrap(&text, partial);
    assert_eq!(errors.len(), 4, "{errors:?}");
    assert_eq!(
        errors
            .iter()
            .filter(|e| e.message.contains("unwrap for B"))
            .count(),
        2
    );
    assert_eq!(
        errors
            .iter()
            .filter(|e| e.message.contains("`other`"))
            .count(),
        2
    );
    let granted = format!(
        "{partial}\ngrant unwrap key for B to Operator\ngrant unwrap other for A to Operator"
    );
    assert!(unwrap(&text, &granted).is_empty());
}

#[test]
fn legacy_and_managed_read_and_unwrap_diagnostics_use_the_same_policy() {
    let text=format!("{HEADER}credential key {{ kind raw }}\nclass A {{ value string }}\nrule run when started => {{ read text from secret at \"in.txt\" as loaded\n tell worker \"Read\" with access to credential key {{ unwrap for A }} as result }}");
    let ir = compiled(&text);
    let envelope=policy(&format!("{PARTIES}grant file_store secret -> secret readable by Operator\ngrant credential key -> credential:key"));
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    assert_eq!(
        bodies.check_principal_ceiling_for_identity(&envelope, "bob", &[]),
        check_principal_ceiling_for_identity(&ir, &envelope, "bob")
    );
    let mut legacy = Vec::new();
    check_turn_unwrap_scoping(&ir, envelope.envelope(), &mut legacy);
    assert_eq!(bodies.check_turn_unwrap_scoping(&envelope), legacy);
}

#[test]
fn every_source_at_one_site_is_checked_and_unused_helpers_add_no_reads() {
    let text=format!("{HEADER}file store public_files {{ root \"./public\" allow read [\"**\"] }}\naction unused() -> null {{ read text from secret at \"in.txt\" as loaded\n return null }}\naction ask() -> string {{ tell worker \"Read\" with access to public_files {{ read [\"**\"] }} with access to secret {{ read [\"**\"] }} as result\n return result }}\nrule run when started => {{ ask() }}");
    let envelope = format!("{PARTIES}grant file_store secret -> secret readable by Operator");
    let errors = ceiling(&text, &envelope, "bob");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(has_call(&errors[0], "ask"));
    let no_read = text.replace(
        "rule run when started => { ask() }",
        "rule run when started => { record Output { value \"constant\" } }",
    );
    assert_ne!(text, no_read);
    assert!(ceiling(&no_read, &envelope, "bob").is_empty());
}

#[test]
fn unwrap_scopes_cover_model_effects_later_rules_and_bound_credential_aliases() {
    let text=format!("{HEADER}credential key {{ kind raw }}\nclass A {{ value string }}\ncoerce clean(value string) -> Output {{ prompt \"Clean {{{{ value }}}}\" }}\nrule first when started => {{ record Input {{ value \"constant\" }} }}\naction clean_value() -> Output {{ coerce clean(\"value\") with access to credential key {{ unwrap for A }} as result\n return result }}\nrule second when started => {{ clean_value() }}");
    let base =
        "grant credential key -> credential:shared\ngrant credential alias -> credential:shared";
    let errors = unwrap(&text, base);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(has_call(&errors[0], "clean_value"));
    assert!(errors[0].message.contains("rule `second`"));
    assert!(unwrap(
        &text,
        &format!("{base}\ngrant unwrap alias for A to Operator")
    )
    .is_empty());
    let unrelated="grant credential unrelated -> credential:unrelated\ngrant unwrap unrelated for A to Operator";
    assert!(
        unwrap(&text, unrelated).is_empty(),
        "key remains ungoverned"
    );
}
