use super::tests::check;
use super::*;

const HEADER: &str = "@service\nworkflow Demo\nclass Ticket { title string }\nclass Review { title string }\nclass Box { ticket Ticket }\naction write(x Ticket) -> null { record Ticket { title x.title }\nreturn null }\naction work() -> null { timer 1s as wait\nreturn null }\naction finish(x Ticket) -> null { done x\nreturn null }\n";
fn source(body: &str) -> String {
    format!("{HEADER}rule run when Ticket as ticket => {{ {body} }}")
}
fn text(source: &str, span: SourceSpan) -> &str {
    &source[span.start..span.end]
}
fn accepted(source: &str) {
    let errors = check(source, true);
    assert!(errors.is_empty(), "{source}: {errors:?}");
}
fn refused(source: &str) -> Diagnostic {
    let mut errors = check(source, true);
    assert_eq!(errors.len(), 1, "{source}: {errors:?}");
    let error = errors.pop().unwrap();
    assert_eq!(error.severity, Severity::Error);
    assert_eq!(error.code, diagnostic_code!("effect.unconsumed_trigger"));
    error
}

#[test]
fn action_fact_flow_nested_calls_contribute_writes_and_effects_with_source_trace() {
    let source=format!("{HEADER}action middle(x Ticket) -> null {{ write(x)\nwork()\nreturn null }}\naction outer(x Ticket) -> null {{ middle(x)\nreturn null }}\nrule run when Ticket as ticket => {{ outer(ticket) }}");
    let error = refused(&source);
    assert_eq!(text(&source, error.span), "outer");
    for needle in [
        "record Ticket",
        "timer 1s",
        "middle",
        "write",
        "work",
        "run",
    ] {
        assert!(
            error
                .related
                .iter()
                .any(|r| text(&source, r.span).contains(needle)),
            "missing {needle}: {error:?}"
        );
    }
    let result = compile_program(&source);
    assert!(result.ir.is_none());
    assert_eq!(result.diagnostics, vec![error]);
}

#[test]
fn action_fact_flow_discharged_subjects_reach_the_trigger_consumer() {
    for body in [
        "write(ticket)\nwork()\nfinish(ticket)",
        "done ticket -> record Ticket { title ticket.title }\nwork()",
        "write(ticket)\nwork()\ncase ticket { Ticket as original => { finish(original) } }",
    ] {
        accepted(&source(body));
    }
    let prefix=format!("{HEADER}action boxit(x Ticket) -> Box {{ return {{ ticket x }} }}\naction unbox(b Box) -> null {{ finish(b.ticket)\nreturn null }}\n");
    let source=format!("{prefix}rule run when Ticket as ticket => {{ boxit(ticket) as boxed\nunbox(boxed)\nwrite(ticket)\nwork() }}");
    accepted(&source);
    accepted(&source.replace("when Ticket as ticket", "when fact Ticket as ticket"));
    let bad = source.replace("unbox(boxed)\n", "");
    refused(&bad);
    let result = compile_program(&source);
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    assert!(result.ir.is_some());
    assert!(result.typed_actions.is_some());
}

#[test]
fn action_fact_flow_parameter_types_unused_helpers_and_other_facts_cannot_invent_consumption() {
    // Merely accepting Ticket, or declaring a consuming helper, consumes nothing.
    refused(&source("write(ticket)\nwork()"));
    let source=format!("{HEADER}action finish_review(x Review) -> null {{ done x\nreturn null }}\nrule run when {{ Ticket as ticket\nReview as review }} => {{ write(ticket)\nwork()\nfinish_review(review) }}");
    refused(&source);
    let bad = source.replace("finish_review(review)", "finish({ title ticket.title })");
    let errors = check(&bad, true);
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].code,
        diagnostic_code!("construct.invalid_expansion")
    );
    assert!(errors[0].message.contains("original admitted fact"));
}

#[test]
fn action_fact_flow_only_actual_calls_make_the_rule_effectful() {
    accepted(&source("write(ticket)"));
    accepted(&source("work()"));
    accepted(&source("finish(ticket)"));
    accepted(&source("record Ticket { title ticket.title }"));
    // An unrelated effectful rule and an unused effectful helper cannot taint it.
    accepted(&format!(
        "{}\nrule unrelated when started => {{ work() }}",
        source("write(ticket)")
    ));
    let bad = source("write(ticket)\nwork()");
    refused(&bad);
}

#[test]
fn action_fact_flow_all_call_sites_and_wrappers_contribute_without_pacing_shortcuts() {
    for body in [
        "then ignored <- write(ticket)\nwork()",
        "timer 1s as wait\nafter wait succeeds { write(ticket) }",
        "case true { true => { work() } false => { write(ticket) } }",
        "during Ticket { write(ticket) } on lapse { work() }",
        "during Ticket { work() } on lapse { write(ticket) }",
        "write(ticket) as result\nafter result succeeds { work() }",
        "work()\nwrite(ticket)\nwrite(ticket)",
    ] {
        refused(&source(body));
    }
    let source=format!("{HEADER}action replacement(x Review) -> null {{ done x -> record Ticket {{ title x.title }}\nreturn null }}\nrule run when {{ Ticket as ticket\nReview as review }} => {{ replacement(review)\nwork() }}");
    refused(&source);
}

#[test]
fn action_fact_flow_ingestion_writes_share_the_existing_schema_vocabulary() {
    for operation in [
        "exec \"printf '{}'\" -> each Ticket",
        "import json Ticket from docs at \"rows.json\" as rows",
    ] {
        let source=format!("{HEADER}file store docs {{ root \".\" }}\naction ingest() -> null {{ {operation}\nreturn null }}\nrule run when Ticket as ticket => {{ ingest() }}");
        let error = refused(&source);
        assert_eq!(text(&source, error.span), "ingest");
        assert!(error
            .related
            .iter()
            .any(|r| text(&source, r.span) == operation));
    }
    // A single parsed payload is ordinary data; it does not admit a Ticket.
    accepted(&format!("{HEADER}action parse_one() -> Ticket {{ exec \"printf '{{}}'\" -> Ticket as row\nreturn row }}\nrule run when Ticket as ticket => {{ parse_one() }}"));
}

#[test]
fn action_fact_flow_callers_discharge_independently_and_diagnostics_do_not_duplicate_writes() {
    let source=format!("{HEADER}action fixed() -> null {{ record Ticket {{ title \"same\" }}\nwork()\nreturn null }}\nrule first when Ticket as ticket => {{ fixed()\nfixed() }}\nrule second when Review as review => {{ fixed() }}\nrule third when Ticket as ticket => {{ fixed() }}");
    let errors = check(&source, true);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors[0].message.contains("first"));
    assert!(errors[1].message.contains("third"));
    assert!(errors[0].span.start < errors[1].span.start);
    assert!(errors
        .iter()
        .all(|d| d.code == diagnostic_code!("effect.unconsumed_trigger")));
}

#[test]
fn action_fact_flow_unused_record_schemas_are_checked_at_the_definition_once() {
    for (record, code) in [
        (
            "record Missing { title x.title }",
            diagnostic_code!("type.unknown_schema"),
        ),
        (
            "record TerminalFailed {}",
            diagnostic_code!("construct.reserved_name"),
        ),
        (
            "done x -> record Missing { title x.title }",
            diagnostic_code!("type.unknown_schema"),
        ),
    ] {
        let source=format!("{HEADER}action bad(x Ticket) -> null {{ {record}\nreturn null }}\naction wrapper(x Ticket) -> null {{ bad(x)\nreturn null }}\nrule run when Ticket as ticket => {{ wrapper(ticket)\nbad(ticket) }}");
        let errors = check(&source, true);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].severity, Severity::Error);
        assert_eq!(errors[0].code, code);
        assert!(errors[0].message.contains("action `bad`"));
        assert!(text(&source, errors[0].span).contains("record"));
        assert_eq!(compile_program(&source).diagnostics, errors);
    }
    // An author's own class is not the platform terminal family.
    accepted(&format!("{HEADER}class TerminalFailed {{ title string }}\naction own(x Ticket) -> null {{ record TerminalFailed {{ title x.title }}\nreturn null }}"));
}

#[test]
fn action_fact_flow_record_schema_checks_visit_calling_rule_children_and_both_region_arms() {
    for body in [
        "record Missing {}",
        "done ticket -> record Missing {}",
        "timer 1s as t\nafter t succeeds { record Missing {} }",
        "case true { true => { record Ticket { title ticket.title } } false => { record Missing {} } }",
        "during Ticket { record Missing {} } on lapse {}",
        "during Ticket {} on lapse { record Missing {} }",
    ] {
        let errors=check(&source(body),true);
        assert_eq!(errors.len(),1,"{body}: {errors:?}");
        assert_eq!(errors[0].code,diagnostic_code!("type.unknown_schema"));
        assert!(errors[0].message.contains("rule `run`"));
    }
}

#[test]
fn action_fact_flow_nominal_and_explicit_fact_triggers_share_the_legacy_refusal() {
    for pattern in ["Ticket as ticket", "fact Ticket as ticket"] {
        let source=format!("@service\nworkflow Demo\nclass Ticket {{ title string }}\nrule run when {pattern} => {{ timer 1s as wait\nrecord Ticket {{ title ticket.title }} }}");
        let result = compile_program(&source);
        let errors: Vec<_> = result
            .diagnostics
            .iter()
            .filter(|d| d.code == diagnostic_code!("effect.unconsumed_trigger"))
            .collect();
        assert_eq!(errors.len(), 1, "{:?}", result.diagnostics);
        assert_eq!(
            errors[0].message,
            "effectful rule `run` preserves trigger fact `schema:Ticket`"
        );
        assert_eq!(errors[0].severity, Severity::Error);
        assert!(
            !result
                .diagnostics
                .iter()
                .any(|d| d.code == diagnostic_code!("graph.unbounded_effect_recursion")),
            "the same self-edge must not be reported twice"
        );
        let composed = format!("{HEADER}rule run when {pattern} => {{ write(ticket)\nwork() }}");
        assert_eq!(refused(&composed).message, errors[0].message);
    }
    assert_eq!(
        fact_flow::normalize_read("pattern:fact agent.turn.completed as ev"),
        "pattern:fact agent.turn.completed as ev"
    );
}
