use super::tests::source;
use super::*;
const HEADER: &str = r#"@service
workflow SourceFlows
class Input { value string }
class Output { value string }
file store secret { root "./secret" allow read ["**"] }
coerce tidy(value string) -> Output { prompt "Clean {{ value }}" }
"#;
fn policy(text: &str) -> VerifiedEnvelope {
    VerifiedEnvelope::for_test(Envelope::from_dsl(text).unwrap())
}
fn check(text: &str, envelope: &str) -> Vec<Diagnostic> {
    let analysis = source(text);
    analyze(&analysis)
        .unwrap()
        .check_source_flows(&policy(envelope), &[])
}
fn compiled(text: &str) -> IrProgram {
    let compiled = whipplescript_parser::compile_program(text);
    compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics))
}
fn leaks(errors: &[Diagnostic]) -> Vec<&Diagnostic> {
    errors
        .iter()
        .filter(|error| error.code.as_str() == "security.confidentiality_leak")
        .collect()
}
fn injections(errors: &[Diagnostic]) -> Vec<&Diagnostic> {
    errors
        .iter()
        .filter(|error| error.code.as_str() == "security.integrity_injection")
        .collect()
}

#[test]
fn source_reads_reach_every_helper_sink_with_distinct_call_locations() {
    let text = format!(
        r#"{HEADER}
action publish() -> null {{ record Output {{ value "constant" }}
 return null }}
rule run when started => {{ read text from secret at "in.txt" as loaded
 publish()
 publish() }}
"#
    );
    let denied = check(
        &text,
        "grant file_store secret -> secret readable by Operator",
    );
    assert_eq!(leaks(&denied).len(), 2, "{denied:?}");
    assert_ne!(denied[0].related, denied[1].related);
    for error in &denied {
        assert!(text[error.span.start..error.span.end].contains("record Output"));
        assert!(error
            .related
            .iter()
            .any(|related| related.message == "call to action `publish`"));
    }
    assert!(check(&text, "grant file_store secret -> secret readable by Operator\ngrant fact out -> fact:Output readable by Operator").is_empty());
}

#[test]
fn matched_facts_guard_queries_messages_and_tracker_roots_are_source_reads() {
    for (declaration, trigger, label) in [
        ("input incoming Input", "Input as value", "fact:Input"),
        (
            "input incoming Input",
            "started where exists(Input where value == \"yes\")",
            "fact:Input",
        ),
        ("channel inbox", "message from inbox as notice", "inbox"),
        (
            "tracker jobs { provider builtin }",
            "jobs has ready issue as item",
            "jobs",
        ),
    ] {
        let text = format!("{HEADER}{declaration}\naction publish() -> null {{ record Output {{ value \"constant\" }}\n return null }}\nrule run when {trigger} => {{ publish() }}");
        let envelope = format!("grant source input -> {label} readable by Secret\ngrant fact out -> fact:Output from Operator");
        let errors = check(&text, &envelope);
        assert_eq!(leaks(&errors).len(), 1, "{trigger}: {errors:?}");
        assert_eq!(injections(&errors).len(), 1, "{trigger}: {errors:?}");
        assert!(
            errors.iter().all(|error| error.message.contains(label)),
            "{errors:?}"
        );
    }
}

#[test]
fn a_mark_and_its_matching_grant_are_both_required_on_each_axis() {
    for (marker, base, grant, other, expected) in [
        ("declassified", "grant fact input -> fact:Input readable by Secret from Operator\ngrant fact out -> fact:Output readable by Requester from Operator\ngrant provider model -> model readable by Secret", "grant declassify fact:Input to Requester", "grant endorse fact:Input to Operator", "security.confidentiality_leak"),
        ("endorsed", "grant fact input -> fact:Input\ngrant fact out -> fact:Output from Operator", "grant endorse fact:Input to Operator", "grant declassify fact:Input to public", "security.integrity_injection"),
    ] {
        for (mark, authorization, allow) in [(marker, grant, true), ("", grant, false), (marker, "", false), (marker, other, false)] {
            let text = format!(r#"{HEADER}
input incoming Input
action clean(value Input) -> Output {{ coerce tidy(value.value) as result {mark}
 return result }}
rule run when Input as value => {{ clean(value) as result
 record Output from result {{}} }}
"#);
            let errors = check(&text, &format!("{base}\n{authorization}"));
            assert_eq!(!errors.iter().any(|error| error.code.as_str() == expected), allow, "{marker}/{mark}/{authorization}: {errors:?}");
            if allow { assert!(errors.is_empty(), "{errors:?}"); }
        }
    }
}

#[test]
fn mixed_payloads_do_not_borrow_a_siblings_declassification_marker() {
    let text = format!(
        r#"{HEADER}
class Pair {{ clean string raw string }}
input incoming Input
action publish(value Input) -> null {{ coerce tidy(value.value) as cleaned declassified
 record Pair {{ clean cleaned.value raw value.value }}
 return null }}
rule run when Input as value => {{ publish(value) }}
"#
    );
    let errors = check(&text, "grant fact input -> fact:Input readable by Secret\ngrant provider model -> model readable by Secret\ngrant declassify fact:Input to public");
    assert_eq!(leaks(&errors).len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("fact:Pair"));
}

#[test]
fn attributable_marked_payloads_exclude_unrelated_rule_reads() {
    let text = format!(
        r#"{HEADER}
input incoming Input
action clean(value Input) -> Output {{ coerce tidy(value.value) as cleaned declassified
 return cleaned }}
rule run when Input as value => {{ read text from secret at "in.txt" as loaded
 clean(value) as cleaned
 record Output from cleaned {{}} }}
"#
    );
    let envelope = "grant fact input -> fact:Input readable by Source\ngrant file_store secret -> secret readable by Other\ngrant provider model -> model readable by Source,Other\ngrant declassify fact:Input to public";
    assert!(check(&text, envelope).is_empty());
    let raw = text.replace(
        "record Output from cleaned {}",
        "record Output { value value.value }",
    );
    assert_eq!(leaks(&check(&raw, envelope)).len(), 1);
}

#[test]
fn internal_signals_carry_the_emitters_trust_without_an_endorsement_override() {
    let text = format!(
        r#"{HEADER}
channel inbox
signal work.done {{ detail string }}
action announce(target string) -> null {{ emit signal work.done to target {{ detail "done" }} as sent
 return null }}
rule produce when message from inbox as notice => {{ announce("peer") }}
rule consume when work.done as event => {{ record Output {{ value "constant" }} }}
"#
    );
    let base = "grant signal done -> signal:work.done internal\ngrant fact out -> fact:Output from Operator";
    assert!(check(
        &text,
        &format!("{base}\ngrant channel inbox -> inbox from Operator")
    )
    .is_empty());
    let denied = check(
        &text,
        &format!("{base}\ngrant endorse signal:work.done to Operator"),
    );
    assert_eq!(injections(&denied).len(), 1, "{denied:?}");
    assert!(denied[0].message.contains("signal:work.done"));
    let marked = text.replace(
        "record Output { value \"constant\" }",
        "coerce tidy(event.detail) as cleaned endorsed\n record Output from cleaned {}",
    );
    assert_ne!(marked, text);
    let errors = check(
        &marked,
        &format!("{base}\ngrant endorse signal:work.done to Operator"),
    );
    assert_eq!(injections(&errors).len(), 1, "{errors:?}");
    let without_reads = text.replace("when message from inbox as notice", "when started");
    assert!(check(&without_reads, base).is_empty());
    for trigger in [
        "Input as value",
        "started where exists(Input where value == \"ready\")",
    ] {
        let from_fact = text
            .replace("channel inbox", "input incoming Input")
            .replace("message from inbox as notice", trigger);
        let errors = check(
            &from_fact,
            &format!("{base}\ngrant fact incoming -> fact:Input"),
        );
        assert_eq!(injections(&errors).len(), 1, "{trigger}: {errors:?}");
        assert!(check(
            &from_fact,
            &format!("{base}\ngrant fact incoming -> fact:Input from Operator")
        )
        .is_empty());
    }
}

#[test]
fn stream_and_opaque_grant_writes_remain_local_destinations() {
    for (extra, effect, destination) in [
        (
            "signal work.done { detail string }",
            "emit signal work.done to target { detail \"constant\" } as sent",
            "stream",
        ),
        (
            "file store outbox { root \"./outbox\" allow write [\"**\"] }",
            "export json Input to outbox at \"out.json\" { mode create } as exported",
            "outbox",
        ),
        (
            "agent writer { provider trusted }",
            "tell writer as text\n with access to remote { get [\"**\"] }\n \"Write\"",
            "remote",
        ),
    ] {
        let text = format!("{HEADER}{extra}\naction work(target string) -> null {{ {effect}\n return null }}\nrule run when started => {{ read text from secret at \"in.txt\" as loaded\n work(\"peer\") }}");
        let errors = check(&text, "grant file_store secret -> secret readable by Operator\ngrant provider trusted -> trusted readable by Operator");
        assert!(
            leaks(&errors)
                .iter()
                .any(|error| error.message.contains(destination)),
            "{destination}: {errors:?}"
        );
    }
}

#[test]
fn imported_reads_feed_producers_and_missing_or_duplicate_imports_refuse() {
    let text = format!(
        r#"{HEADER}
agent reader {{ provider trusted tools [Fetcher] }}
class Trigger {{ value string }}
table trigger as Trigger [{{ value "go" }}]
action fetch() -> string {{ tell reader "Fetch" as result
 return result }}
rule publish when Input as value => {{ record Output {{ value value.value }} }}
rule produce when Trigger as trigger => {{ fetch() as result
 record Input {{ value result }} }}
"#
    );
    let tool = compiled(
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
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let envelope = policy("grant file_store secret -> secret readable by Operator\ngrant fact middle -> fact:Input readable by Operator");
    let errors = bodies.check_source_flows(&envelope, std::slice::from_ref(&tool));
    assert_eq!(leaks(&errors).len(), 1, "{errors:?}");
    assert!(
        errors[0].message.contains("secret") && errors[0].message.contains("fact:Output"),
        "{errors:?}"
    );
    let uncleared = policy("grant file_store secret -> secret readable by Operator");
    assert_eq!(
        leaks(&bodies.check_source_flows(&uncleared, std::slice::from_ref(&tool))).len(),
        2
    );
    for imports in [vec![], vec![tool.clone(), tool.clone()]] {
        let errors = bodies.check_source_flows(&envelope, &imports);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].message.contains("one complete imported program"));
        assert!(errors[0]
            .related
            .iter()
            .any(|related| related.message == "call to action `fetch`"));
    }
    let signal = text
        .replace(
            "agent reader",
            "signal work.done { detail string }\nagent reader",
        )
        .replace(
            "when Input as value => { record Output { value value.value } }",
            "when work.done as event => { record Output { value event.detail } }",
        )
        .replace(
            "record Input { value result }",
            "emit signal work.done to trigger.value { detail result } as sent",
        );
    assert!(signal.contains("when work.done as event"));
    let signal_analysis = source(&signal);
    let signal_bodies = analyze(&signal_analysis).unwrap();
    let signal_policy = policy("grant file_store secret -> secret readable by Operator\ngrant stream events -> stream readable by Operator\ngrant fact out -> fact:Output readable by Operator from Operator\ngrant signal done -> signal:work.done internal");
    let errors = signal_bodies.check_source_flows(&signal_policy, std::slice::from_ref(&tool));
    assert_eq!(injections(&errors).len(), 1, "{errors:?}");
    assert!(leaks(&errors).is_empty(), "{errors:?}");
    assert!(errors[0].message.contains("signal:work.done"));
}

#[test]
fn named_model_egress_uses_the_actual_declaration_and_each_helper_call() {
    let header = HEADER.replace(
        "prompt \"Clean {{ value }}\"",
        "prompt \"Clean {{ value }}\"\n provider private_model",
    );
    let text = format!(
        r#"{header}
input incoming Input
action clean(value Input) -> Output {{ coerce tidy(value.value) as result
 return result }}
rule run when Input as value => {{ clean(value) as first
 clean(value) as second }}
"#
    );
    let base = "grant fact incoming -> fact:Input readable by Secret";
    let errors = check(&text, base);
    assert_eq!(errors.len(), 2, "{errors:?}");
    for error in &errors {
        assert_eq!(error.code.as_str(), "security.provider_egress_leak");
        assert!(error.message.contains("private_model"));
        assert!(text[error.span.start..error.span.end].contains("coerce tidy"));
        assert!(error.related.iter().any(|related| related
            .message
            .contains("sends to provider `private_model`")));
        assert!(error
            .related
            .iter()
            .any(|related| related.message == "call to action `clean`"));
    }
    assert_ne!(errors[0].related, errors[1].related);
    assert!(check(
        &text,
        &format!("{base}\ngrant provider endpoint -> private_model readable by Secret")
    )
    .is_empty());
}

#[test]
fn an_unattributable_marked_input_keeps_the_full_rule_join() {
    let text = format!(
        r#"{HEADER}
agent reader {{ provider trusted }}
action summarize() -> Output {{ tell reader as text
 with access to secret {{ read ["**"] }}
 "Read"
 coerce tidy(text) as result declassified
 return result }}
rule run when started => {{ summarize() as result
 record Output from result {{}} }}
"#
    );
    let base = "grant file_store secret -> secret readable by Secret\ngrant provider model -> model readable by Secret\ngrant declassify fact:Input to public";
    let errors = check(&text, base);
    assert_eq!(leaks(&errors).len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("secret"));
    assert!(check(&text, &format!("{base}\ngrant declassify secret to public")).is_empty());
}

#[test]
fn pure_declassification_through_a_helper_is_a_marked_source_crossing() {
    let text = format!(
        r#"{HEADER}
input incoming Input
action release(value Input) -> Output {{ declassify value into Output as released
 return released }}
rule run when Input as value => {{ release(value) as result
 record Output from result {{}} }}
"#
    );
    let base = "grant fact incoming -> fact:Input readable by Secret";
    assert_eq!(leaks(&check(&text, base)).len(), 1);
    assert!(check(
        &text,
        &format!("{base}\ngrant declassify fact:Input to public")
    )
    .is_empty());
}

#[test]
fn source_context_must_contain_each_actual_checked_agent() {
    let text = format!(
        r#"{HEADER}
agent reader {{ provider trusted }}
action fetch() -> null {{ tell reader "Read" as text
 return null }}
rule run when started => {{ fetch() }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let wrong = source(&format!(
        "{HEADER}rule run when started => {{ timer 1s as wait }}"
    ));
    let damaged = CompositionBodies {
        source: &wrong,
        rules: bodies.rules,
    };
    let errors = damaged.check_source_flows(&policy(""), &[]);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("one actual agent declaration"));
    assert!(errors[0]
        .related
        .iter()
        .any(|related| related.message == "call to action `fetch`"));
}

#[test]
fn a_missing_query_observation_contract_cannot_pass_as_an_empty_source_set() {
    let text = format!(
        r#"{HEADER}
file store outbox {{ root "./outbox" allow write ["**"] }}
action write() -> null {{ write text to outbox at "out.txt" {{ body "{{{{ count(Input) }}}}" mode replace }} as written
 return null }}
rule run when started => {{ write() }}
"#
    );
    let errors = check(&text, "");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("query provenance"));
    assert!(text[errors[0].span.start..errors[0].span.end].contains("write text"));
    assert!(errors[0]
        .related
        .iter()
        .any(|related| related.message == "call to action `write`"));
}

#[test]
fn parameterized_views_preserve_argument_provenance_at_public_sinks() {
    let text = format!(
        r#"{HEADER}
input incoming Input
view disclosed(value Input) -> string {{ return value.value }}
action publish(value Input) -> null {{ record Output {{ value disclosed(value) }}
 return null }}
rule run when Input as value => {{ publish(value) }}
"#
    );
    let errors = check(
        &text,
        "grant fact incoming -> fact:Input readable by Secret",
    );
    assert_eq!(leaks(&errors).len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("fact:Output"));
}

#[test]
fn parameterized_views_cannot_hide_a_missing_query_observation_contract() {
    let text = format!(
        r#"{HEADER}
file store outbox {{ root "./outbox" allow write ["**"] }}
view total() -> int {{ return count(Input) }}
action write() -> null {{ write text to outbox at "out.txt" {{ body "{{{{ total() }}}}" mode replace }} as written
 return null }}
rule run when started => {{ write() }}
"#
    );
    let errors = check(&text, "");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("query provenance"));
}

#[test]
fn every_imported_signal_emitter_contributes_to_the_carried_integrity() {
    let text = format!(
        r#"{HEADER}
signal work.done {{ detail string }}
rule consume when work.done as event => {{ record Output {{ value "constant" }} }}
"#
    );
    let emitter = |workflow: &str, store: &str| {
        compiled(&format!(
            r#"@tool
workflow {workflow} {{
 input request Req
 class Req {{ target string }}
 signal work.done {{ detail string }}
 file store {store} {{ root "./input" allow read ["**"] }}
 rule emit when Req as request => {{ read text from {store} at "in.txt" as loaded
  after loaded succeeds {{ emit signal work.done to request.target {{ detail "done" }} as sent }} }}
}}
"#
        ))
    };
    let trusted = emitter("Trusted", "secret");
    let untrusted = emitter("Untrusted", "outside");
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let envelope = policy("grant file_store secret -> secret from Operator\ngrant signal done -> signal:work.done internal\ngrant fact out -> fact:Output from Operator");
    assert_eq!(
        injections(&bodies.check_source_flows(&envelope, &[])).len(),
        1
    );
    assert!(bodies
        .check_source_flows(&envelope, std::slice::from_ref(&trusted))
        .is_empty());
    let with_local = format!("{text}\nclass Trigger {{ target string }}\ntable trigger as Trigger [{{ target \"peer\" }}]\nrule native when Trigger as value => {{ emit signal work.done to value.target {{ detail \"done\" }} as sent }}");
    let local_analysis = source(&with_local);
    let local = analyze(&local_analysis).unwrap();
    assert_eq!(
        injections(&local.check_source_flows(&envelope, std::slice::from_ref(&untrusted))).len(),
        1
    );
    assert_eq!(
        injections(&bodies.check_source_flows(&envelope, &[trusted, untrusted])).len(),
        1
    );
}

#[test]
fn foreign_tool_operations_are_reads_even_when_the_name_is_an_egress_verb() {
    let text = format!(
        r#"{HEADER}
agent reader {{ provider trusted }}
action work() -> null {{ tell reader as text
 with access to remote {{ notify ["**"] }}
 "Use the tool"
 return null }}
rule consume when Input as value => {{ record Output {{ value value.value }} }}
rule produce when started => {{ work()
 record Input {{ value "constant" }} }}
"#
    );
    let base = "grant fact out -> fact:Output from Operator";
    let errors = check(&text, base);
    assert_eq!(injections(&errors).len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("remote") && errors[0].message.contains("fact:Output"));
    assert!(check(
        &text,
        &format!("{base}\ngrant tool remote -> remote from Operator")
    )
    .is_empty());
}

#[test]
fn a_failed_producer_analysis_cannot_be_discarded_by_source_flow_aggregation() {
    let text = format!(
        r#"{HEADER}
action publish(value Input) -> null {{ record Output {{ value value.value }}
 return null }}
rule run when Input as value => {{ publish(value) }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let mut roots: Vec<_> = bodies
        .rules()
        .iter()
        .map(|body| body.rule.clone())
        .collect();
    for root in &mut roots {
        root.root.whens.clear();
    }
    let damaged = CompositionBodies {
        source: &analysis,
        rules: bodies
            .rules
            .into_iter()
            .zip(roots.iter())
            .map(|(body, rule)| RuleBodyAnalysis {
                rule,
                inventory: body.inventory,
            })
            .collect(),
    };
    let errors = damaged.check_source_flows(&policy(""), &[]);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("no matching producer analysis"));
    assert!(text[errors[0].span.start..errors[0].span.end].contains("record Output"));
    assert!(errors[0]
        .related
        .iter()
        .any(|related| related.message == "call to action `publish`"));
}

#[test]
fn an_opaque_grant_sink_still_requires_its_actual_selection_context() {
    let text = format!(
        r#"{HEADER}
agent writer {{ provider trusted }}
action work(value Input) -> null {{ case value.value {{
 "yes" => {{ tell writer as text
  with access to remote {{ notify ["**"] }}
  "Write" }}
 _ => {{ timer 1s as wait }}
 }}
 return null }}
rule run when Input as value => {{ work(value) }}
"#
    );
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    assert!(bodies.check_source_flows(&policy(""), &[]).is_empty());
    let mut roots: Vec<_> = bodies
        .rules()
        .iter()
        .map(|body| body.rule.clone())
        .collect();
    for root in &mut roots {
        root.root.whens.clear();
    }
    let damaged = CompositionBodies {
        source: &analysis,
        rules: bodies
            .rules
            .into_iter()
            .zip(roots.iter())
            .map(|(body, rule)| RuleBodyAnalysis {
                rule,
                inventory: body.inventory,
            })
            .collect(),
    };
    let errors = damaged.check_source_flows(&policy(""), &[]);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("no matching producer analysis"));
    assert!(text[errors[0].span.start..errors[0].span.end].contains("tell writer"));
    assert!(errors[0]
        .related
        .iter()
        .any(|related| related.message == "source value originates here"));
    assert!(errors[0]
        .related
        .iter()
        .any(|related| related.message == "call to action `work`"));
}
