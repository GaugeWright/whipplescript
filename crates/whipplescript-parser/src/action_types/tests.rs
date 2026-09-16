use super::*;

pub(super) fn check(source: &str) -> Vec<Diagnostic> {
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let actions: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(a) => Some(a.clone()),
            _ => None,
        })
        .collect();
    let syntax = crate::action_signature::validate(&actions);
    if !syntax.is_empty() {
        return syntax;
    }
    let semantic = SemanticContext::from_program(&parsed.program, BTreeMap::new());
    validate(&actions, &semantic)
}

#[test]
fn scalar_and_record_parameters_have_real_result_types() {
    for source in [
        "workflow Demo\naction identity(x int) -> int { return x }",
        "workflow Demo\naction increment(x int) -> int { return x + 1 }",
        "workflow Demo\nclass Ticket { title string }\naction title(x Ticket) -> string { return x.title }",
        "workflow Demo\nclass Ticket { title string }\naction identity(x Ticket) -> Ticket { return x }",
        "workflow Demo\nclass Ticket { title string }\naction make(x string) -> Ticket { return { title x } }",
        "workflow Demo\naction empty() -> int[] { return [] }",
        "workflow Demo\naction empty() -> map<string> { return {} }",
        "workflow Demo\naction nothing() -> null { return null }",
    ] { assert!(check(source).is_empty(), "{source}: {:?}", check(source)); }
}

#[test]
fn action_timer_success_has_null_type() {
    assert!(check("workflow Demo\naction wait() -> null { timer 1s as t\nreturn t }").is_empty());
    let errors = check("workflow Demo\naction wait() -> string { timer 1s as t\nreturn t }");
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("expects"));
}

#[test]
fn cancellation_accepts_operation_identity_and_refuses_values() {
    for source in [
        "workflow Demo\naction stop() -> null { timer 1s as wait\ncancel wait\nreturn null }",
        "workflow Demo\naction child() -> null { return null }\naction stop() -> null { child() as work\ncancel work\nreturn null }",
    ] {
        assert!(check(source).is_empty(), "{source}: {:?}", check(source));
    }
    for (source, expected, excerpt) in [
        (
            "workflow Demo\naction stop(value string) -> null { cancel value\nreturn null }",
            "is a value",
            "cancel value",
        ),
        (
            "workflow Demo\naction stop() -> null { cancel missing\nreturn null }",
            "unknown binding",
            "cancel missing",
        ),
    ] {
        let errors = check(source);
        assert_eq!(errors.len(), 1, "{source}: {errors:?}");
        assert!(errors[0].message.contains(expected), "{:?}", errors[0]);
        assert_eq!(&source[errors[0].span.start..errors[0].span.end], excerpt);
    }
}

#[test]
fn assignment_is_directional_and_retains_union_and_optional_obligations() {
    for (parameters, result, expression) in [
        ("x int", "string", "x"),
        ("x string?", "string", "x"),
        ("x string | int", "string", "x"),
        ("x string", "string", "null"),
        ("x float", "int", "x"),
        ("x int[]", "string[]", "x"),
        ("x map<int>", "map<string>", "x"),
    ] {
        let source =
            format!("workflow Demo\naction f({parameters}) -> {result} {{ return {expression} }}");
        let diagnostics = check(&source);
        assert_eq!(diagnostics.len(), 1, "{source}: {diagnostics:?}");
        assert!(diagnostics[0].message.contains("expects"));
        assert_eq!(
            &source[diagnostics[0].span.start..diagnostics[0].span.end],
            expression
        );
        assert!(!diagnostics[0].related.is_empty());
    }
    for (parameters, result) in [
        ("x int", "float"),
        ("x string", "string?"),
        ("x string?", "string | null"),
        ("x string | int", "int | string"),
    ] {
        let source = format!("workflow Demo\naction f({parameters}) -> {result} {{ return x }}");
        assert!(check(&source).is_empty(), "{source}: {:?}", check(&source));
    }
}

#[test]
fn mismatched_record_shapes_cannot_hide_behind_object() {
    for expr in [
        "wrong",
        "{ title 42 }",
        "{}",
        "{ title \"ok\", extra 42 }",
        "{ title \"one\", title \"two\" }",
    ] {
        let source = format!("workflow Demo\nclass Ticket {{ title string }}\nclass Other {{ title string }}\naction f(wrong Other) -> Ticket {{ return {expr} }}");
        assert!(!check(&source).is_empty(), "{source}");
    }
}

#[test]
fn nested_calls_check_arity_argument_types_and_result_contracts() {
    let base = "workflow Demo\naction inner(x int) -> int { return x }\n";
    assert!(check(&format!(
        "{base}action outer(x int) -> int {{ then result <- inner(x)\n return result }}"
    ))
    .is_empty());
    for body in [
        "inner()\nreturn 0",
        "inner(\"bad\")\nreturn 0",
        "missing(1)\nreturn 0",
        "inner(1, 2)\nreturn 0",
    ] {
        assert!(
            !check(&format!("{base}action outer() -> int {{ {body} }}")).is_empty(),
            "{body}"
        );
    }
    let diagnostics = check(&format!(
        "{base}action outer() -> string {{ then result <- inner(1)\nreturn result }}"
    ));
    assert!(
        diagnostics
            .iter()
            .any(|d| d.message.contains("expects string, got int")),
        "{diagnostics:?}"
    );
}

#[test]
fn standard_failures_do_not_require_a_domain_contract_but_domain_payloads_do() {
    assert!(check("workflow Demo\naction f() -> string ! int { fail 42 }").is_empty());
    for source in [
        "workflow Demo\naction f() -> string { fail 42 }",
        "workflow Demo\naction f() -> string ! int { fail \"bad\" }",
    ] {
        assert!(!check(source).is_empty(), "{source}");
    }
}

#[test]
fn lexical_failure_handler_has_one_typed_aggregate_and_must_finish() {
    let valid = "workflow Demo\naction f() -> string { timer 1s as work\nafter work succeeds { return \"ok\" }\non failure as problem { return problem.summary } }";
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let wrong = "workflow Demo\naction f() -> string { timer 1s as work\nafter work succeeds { return \"ok\" }\non failure as problem { return problem.causes } }";
    assert!(check(wrong)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("expects string")));

    let unfinished = "workflow Demo\naction f() -> string { timer 1s as work\nafter work succeeds { return \"ok\" }\non failure as problem { timer 2s as cleanup } }";
    assert!(check(unfinished).iter().any(|diagnostic| diagnostic
        .message
        .contains("can finish without returning or propagating")));

    let duplicate = "workflow Demo\naction f() -> string { timer 1s as work\nafter work succeeds { return \"ok\" }\non failure as first { return first.summary }\non failure as second { return second.summary } }";
    assert!(check(duplicate).iter().any(|diagnostic| diagnostic
        .message
        .contains("more than one lexical failure handler")));
}

#[test]
fn child_bindings_do_not_leak_into_siblings_or_outer_results() {
    for source in [
        "workflow Demo\naction inner() -> int { return 1 }\naction f() -> int { case true { true => { inner() as x } false => { return x } } }",
        "workflow Demo\naction inner() -> int { return 1 }\naction f() -> int { case true { true => { inner() as x } false => { inner() as x } }\nreturn x }",
        "workflow Demo\naction inner() -> int { return 1 }\naction f() -> int { inner() as call\nafter call succeeds { record X { value call } }\nreturn x }",
    ] { assert!(check(source).iter().any(|d| d.message.contains("cannot determine the type")), "{source}: {:?}", check(source)); }
}

#[test]
fn forward_managed_operation_bindings_retain_types() {
    for body in [
        "inner() as result\nreturn result",
        "inner() as work\nafter work succeeds { return work }",
    ] {
        let source = format!(
            "workflow Demo\naction inner() -> int {{ return 1 }}\naction f() -> int {{ {body} }}"
        );
        assert!(check(&source).is_empty(), "{source}: {:?}", check(&source));
    }
    // Return reachability is checked separately; this component checks types.
}

#[test]
fn unknown_and_optional_field_accesses_cannot_infer_any_result_type() {
    for (params, expr) in [
        ("x int", "missing"),
        ("x int", "x.missing"),
        ("x Ticket?", "x.title"),
        ("x Ticket", "x.missing"),
    ] {
        let source = format!("workflow Demo\nclass Ticket {{ title string }}\naction f({params}) -> string {{ return {expr} }}");
        let diagnostics = check(&source);
        if params == "x Ticket" {
            assert!(diagnostics.iter().any(|diagnostic| {
                diagnostic.code == diagnostic_code!("type.unknown_field")
                    && diagnostic.message.contains("`x` has no field `missing`")
            }));
        } else {
            assert!(diagnostics
                .iter()
                .any(|d| d.message.contains("cannot determine the type")));
        }
    }
}

#[test]
fn shared_operator_checker_sees_scalar_action_bindings() {
    let diagnostics = check("workflow Demo\naction f(x bool) -> int { return x + 1 }");
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code.as_str() == "expr.non_numeric_operand"),
        "{diagnostics:?}"
    );
}

#[test]
fn compile_path_checks_an_unused_action_contract() {
    let compiled = compile_program("workflow Demo\naction unused(x int) -> string { return x }");
    assert!(compiled.ir.is_none());
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("return from action `unused` expects string, got int")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn declarations_use_shared_schema_agent_and_secret_kind_refusals() {
    for signature in [
        "(x Missing) -> int",
        "() -> Missing",
        "() -> int ! Missing",
        "(x AgentRef<missing>) -> int",
        "(x secret<missing>) -> int",
    ] {
        let source = format!("workflow Demo\naction f{signature} {{ return 1 }}");
        assert!(!check(&source).is_empty(), "{source}");
    }
}

#[test]
fn ambiguous_union_operands_do_not_become_legacy_unknown() {
    let source = "workflow Demo\naction f(x int | string) -> int { return x + 1 }";
    assert!(!check(source).is_empty());
}

#[test]
fn unknown_operation_payload_never_reuses_a_shadowed_parameter_type() {
    let source = "workflow Demo\naction f(x int) -> int { case true { true => { exec \"hello\" as x\n return x } false => { return x } } }";
    assert!(check(source)
        .iter()
        .any(|d| d.message.contains("cannot determine the type")));
}

#[test]
fn class_case_binding_must_be_an_actual_alternative() {
    let classes = "workflow Demo\nclass A { value int }\nclass B { value string }\n";
    let good = format!("{classes}action f(x A | B) -> string {{ case x {{ A a => {{ return \"A\" }} B b => {{ return b.value }} }} }}");
    assert!(check(&good).is_empty(), "{:?}", check(&good));
    let bad = format!("{classes}action f(x int) -> B {{ case x {{ B b => {{ return b }} }} }}");
    assert!(
        check(&bad)
            .iter()
            .any(|d| d.message.contains("cannot bind")),
        "{:?}",
        check(&bad)
    );
}

#[test]
fn enum_literals_and_time_literals_keep_their_declared_domains() {
    for source in [
        "workflow Demo\nenum Status { good\nbad }\naction f() -> Status { return good }",
        "workflow Demo\naction f() -> time { return \"2026-09-08T12:00:00Z\" }",
    ] {
        assert!(check(source).is_empty(), "{source}: {:?}", check(source));
    }
    for source in [
        "workflow Demo\nenum Status { good\nbad }\naction f() -> Status { return \"other\" }",
        "workflow Demo\naction f() -> time { return \"tomorrow\" }",
    ] {
        assert!(!check(source).is_empty(), "{source}");
    }
}

#[test]
fn unresolved_local_cannot_fall_back_to_a_global_enum_variant() {
    let source = "workflow Demo\nenum Status { x\ny }\naction f() -> Status { exec \"hello\" as x\n return x }";
    assert!(check(source)
        .iter()
        .any(|d| d.message.contains("cannot determine the type")));
}

#[test]
fn pure_collection_helpers_check_every_possible_input_variant() {
    for (params, result, expr) in [
        ("x int | string", "int", "count(x)"),
        ("x int | string", "bool", "empty(x)"),
        ("x int | string", "bool", "exists(x)"),
        ("x int?", "bool", "empty(x)"),
    ] {
        let source = format!("workflow Demo\naction f({params}) -> {result} {{ return {expr} }}");
        assert!(!check(&source).is_empty(), "{source}");
    }
    let source = "workflow Demo\naction f(x string | string[]) -> bool { return empty(x) }";
    assert!(check(source).is_empty(), "{:?}", check(source));
}

#[test]
fn action_query_helpers_have_scalar_types_and_share_query_diagnostics() {
    let valid = r#"workflow Demo
class Ticket { owner string }
action facts(wanted string) -> bool {
  return exists(Ticket where owner == wanted)
}
action fact_count() -> int {
  return count(Ticket)
}
action effects() -> bool {
  return empty(effect kind agent.tell where status == "failed")
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown = valid.replace("Ticket where", "Missing where");
    assert!(check(&unknown)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("unknown fact schema `Missing`")));
    let non_boolean = valid.replace("owner == wanted", "owner");
    assert!(check(&non_boolean).iter().any(|diagnostic| diagnostic
        .message
        .contains("non-boolean `where` expression")));
}

#[test]
fn action_values_keep_expected_schema_requirements_for_object_construction() {
    let source = "workflow Demo\naction f() -> int { return count([{ value 1 }]) }";
    assert!(
        check(source)
            .iter()
            .any(|d| d.message.contains("without an expected")),
        "{:?}",
        check(source)
    );
    let source =
        "workflow Demo\nclass Item { value int }\naction f() -> Item[] { return [{ value 1 }] }";
    assert!(check(source).is_empty(), "{:?}", check(source));
}

#[test]
fn action_tell_results_are_strings_and_prompt_reads_are_checked() {
    let prefix = "workflow Demo\nagent worker { provider mock }\nclass Ticket { title string }\n";
    for body in [
        "action ask(ticket Ticket) -> string { tell worker \"Read {{ ticket.title }}\" as answer\nreturn answer }",
        "action ask(ticket Ticket) -> string { then answer <- tell worker \"Read {{ ticket.title }}\"\nreturn answer }",
        "action ask(ticket Ticket) -> string { tell worker \"Read ticket.typo as prose\" as answer\nafter answer succeeds { return answer } }",
    ] {
        let source = format!("{prefix}{body}");
        assert!(check(&source).is_empty(), "{:?}", check(&source));
    }
    for body in [
        "action ask(ticket Ticket) -> int { tell worker \"Read\" as answer\nreturn answer }",
        "action ask(ticket Ticket) -> string { tell worker \"Read {{ ticket.typo }}\" as answer\nreturn answer }",
        "action ask(ticket Ticket) -> string { tell worker \"Read {{ missing }}\" as answer\nreturn answer }",
        "action ask(ticket Ticket) -> string { tell worker \"Read {{ ticket.title\" as answer\nreturn answer }",
    ] {
        let source = format!("{prefix}{body}");
        let errors=check(&source);assert!(!errors.is_empty(), "{source}");
        assert!(errors.iter().all(|e| e.span.end <= source.len()));
    }
}

#[test]
fn action_tell_sealed_prompt_values_require_all_payload_grants() {
    let prefix = "workflow Demo\nagent worker { provider mock }\nclass A { value string }\nclass B { value string }\nclass Box { values sealed<A>[] other sealed<B>? }\nenum Choice { With { body sealed<A> }\nWithout }\n";
    for (ty, grants, ok) in [
        ("sealed<A>", "", false),
        ("Choice", "", false),
        (
            "Choice",
            "with access to credential key { unwrap for A }",
            true,
        ),
        (
            "sealed<A> | sealed<B>",
            "with access to credential key { unwrap for A }",
            false,
        ),
        (
            "sealed<A>",
            "with access to credential key { unwrap for A }",
            true,
        ),
        (
            "sealed<A>",
            "with access to credential key { unwrap for B }",
            false,
        ),
        (
            "Box",
            "with access to credential key { unwrap for A }",
            false,
        ),
        (
            "Box",
            "with access to credential key { unwrap for A unwrap for B }",
            true,
        ),
    ] {
        let source=format!("{prefix}action ask(x {ty}) -> string {{ tell worker \"{{{{ x }}}}\" {grants} as answer\nreturn answer }}");
        let errors = check(&source);
        assert_eq!(errors.is_empty(), ok, "{source}: {errors:?}");
        if !ok {
            assert!(errors
                .iter()
                .any(|e| e.code.as_str() == "security.sealed_value_crossing"));
        }
    }
}

#[test]
fn inline_prompt_is_a_checked_textual_string_operation() {
    let valid = "workflow Demo\naction ask(name string) -> string { prompt \"Hello {{ name }}\" as answer\nreturn answer }";
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown = "workflow Demo\naction ask(name string) -> string { prompt \"Hello {{ missing }}\" as answer\nreturn answer }";
    let errors = check(unknown);
    assert!(
        errors
            .iter()
            .any(|diagnostic| diagnostic.message.contains("missing")),
        "{errors:?}"
    );

    for ty in ["image", "image?", "image[]"] {
        let source = format!(
            "workflow Demo\naction ask(value {ty}) -> string {{ prompt \"Look at {{{{ value }}}}\" as answer\nreturn answer }}"
        );
        assert!(check(&source).iter().any(|diagnostic| diagnostic
            .message
            .contains("inline prompt interpolation cannot contain media")));
    }

    let sealed = "workflow Demo\nclass Secret { text string }\naction ask(value sealed<Secret>) -> string { prompt \"Read {{ value }}\" as answer\nreturn answer }";
    assert!(check(sealed).iter().any(|diagnostic| {
        diagnostic.code.as_str() == "security.sealed_value_crossing"
            && diagnostic.message.contains("inline prompt carries")
    }));
}

#[test]
fn inline_decide_is_a_checked_structural_operation_inside_an_action() {
    let valid = r#"workflow Demo
action judge(name string) -> bool {
  decide "Review {{ name }}" -> { safe bool, reason string } as verdict
  after verdict succeeds { return verdict.safe }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown = r#"workflow Demo
action judge(name string) -> bool {
  decide "Review {{ missing }}" -> { safe bool } as verdict
  after verdict succeeds { return verdict.safe }
}"#;
    let errors = check(unknown);
    assert!(errors.iter().any(|diagnostic| diagnostic
        .message
        .contains("inline decide expression `missing`")));

    let media = r#"workflow Demo
action judge(value image) -> bool {
  decide "Review {{ value }}" -> { safe bool } as verdict
  after verdict succeeds { return verdict.safe }
}"#;
    assert!(check(media).iter().any(|diagnostic| diagnostic
        .message
        .contains("inline decide interpolation cannot contain media")));

    let sealed = r#"workflow Demo
class Secret { text string }
action judge(value sealed<Secret>) -> bool {
  decide "Review {{ value }}" -> { safe bool } as verdict
  after verdict succeeds { return verdict.safe }
}"#;
    assert!(check(sealed).iter().any(|diagnostic| {
        diagnostic.code.as_str() == "security.sealed_value_crossing"
            && diagnostic.message.contains("inline decide carries")
    }));
}

#[test]
fn script_exec_is_a_checked_single_value_operation_inside_an_action() {
    let valid = r#"workflow Demo
class Input { name string }
class Report { ok bool }
action render(input Input) -> bool {
  exec render with input -> Report as report
  after report succeeds { return report.ok }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let wrong_result = valid.replace("-> bool", "-> string");
    assert!(check(&wrong_result)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("expects string, got bool")));

    let missing = valid.replace("with input", "with missing");
    assert!(check(&missing).iter().any(|diagnostic| diagnostic
        .message
        .contains("script exec stdin `missing` has no resolved value type")));
}

#[test]
fn file_read_is_a_checked_structural_operation_inside_an_action() {
    let valid = r#"workflow Demo
file store workspace { root "." allow read ["docs/**"] }
action load(path string) -> string {
  read text from workspace at path as document
  after document succeeds { return document.content }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown_field = valid.replace("document.content", "document.typo");
    assert!(check(&unknown_field)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("typo")));

    let wrong_path = valid.replace("at path", "at 42");
    assert!(check(&wrong_path).iter().any(|diagnostic| diagnostic
        .message
        .contains("file read path `42` must be a string value")));

    let missing = valid.replace("at path", "at missing");
    assert!(check(&missing).iter().any(|diagnostic| diagnostic
        .message
        .contains("file read path `missing` must be a string value")));
}

#[test]
fn file_write_is_a_checked_structural_operation_inside_an_action() {
    let valid = r#"workflow Demo
file store workspace { root "." allow write ["out/**"] }
action save(path string, body string) -> string {
  write markdown to workspace at path { body body mode replace } as saved
  after saved succeeds { return saved.content_hash }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown_field = valid.replace("saved.content_hash", "saved.full_path");
    assert!(check(&unknown_field)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("full_path")));

    for (from, to, expected) in [
        (
            "at path",
            "at 42",
            "file write path `42` must be a string value",
        ),
        (
            "body body",
            "body 42",
            "file write body `42` must be a string value",
        ),
    ] {
        let source = valid.replace(from, to);
        assert!(check(&source)
            .iter()
            .any(|diagnostic| diagnostic.message.contains(expected)));
    }
}

#[test]
fn file_import_is_a_checked_structural_operation_inside_an_action() {
    let valid = r#"workflow Demo
file store workspace { root "." allow read ["docs/**"] }
class Ticket { owner string priority int }
action load(path string) -> int {
  import json Ticket from workspace at path as loaded
  after loaded succeeds { return loaded.admitted }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown_field = valid.replace("loaded.admitted", "loaded.rows");
    assert!(check(&unknown_field)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("rows")));

    let wrong_path = valid.replace("at path", "at 42");
    assert!(check(&wrong_path).iter().any(|diagnostic| diagnostic
        .message
        .contains("file import path `42` must be a string value")));
}

#[test]
fn signal_emit_is_a_checked_structural_operation_inside_an_action() {
    let valid = r#"workflow Demo
signal task.done { id string note string }
class Ticket { peer string id string note string }
action notify(ticket Ticket) -> string {
  emit signal task.done to ticket.peer from ticket { note "sent" } as sent
  after sent succeeds { return sent.event }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown_receipt_field = valid.replace("sent.event", "sent.payload");
    assert!(check(&unknown_receipt_field)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("payload")));

    let wrong_target = valid.replace("to ticket.peer", "to ticket");
    assert!(check(&wrong_target).iter().any(|diagnostic| diagnostic
        .message
        .contains("signal target `ticket` must be a string value")));

    let wrong_payload = valid.replace("note \"sent\"", "note 42");
    assert!(check(&wrong_payload).iter().any(|diagnostic| diagnostic
        .message
        .contains("payload must match its declared fields")));

    let missing_payload = valid.replace(" from ticket { note \"sent\" }", " { note \"sent\" }");
    assert!(check(&missing_payload).iter().any(|diagnostic| diagnostic
        .message
        .contains("payload must match its declared fields")));
}

#[test]
fn counter_consume_is_one_checked_operation_with_two_success_variants() {
    let valid = r#"workflow Demo
class Customer { id string }
counter model_budget { key Customer cap 1000 reset daily timezone "UTC" }
action spend(customer Customer, units int) -> int {
  consume model_budget for customer amount units as spent
  after spent ok as outcome { return outcome.remaining }
  after spent over as outcome { return outcome.remaining }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown_receipt_field = valid.replace("outcome.remaining", "outcome.available");
    assert!(check(&unknown_receipt_field)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("available")));

    let wrong_amount = valid.replace("amount units", "amount customer");
    assert!(check(&wrong_amount).iter().any(|diagnostic| diagnostic
        .message
        .contains("counter amount `customer` must be an integer value")));

    let unknown_counter = valid.replace("consume model_budget", "consume missing_budget");
    assert!(check(&unknown_counter).iter().any(|diagnostic| diagnostic
        .message
        .contains("counter `missing_budget` is not declared")));

    let unknown_key = valid.replace("for customer", "for missing");
    assert!(check(&unknown_key)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("missing")));
}

#[test]
fn ledger_append_is_a_checked_structural_operation_inside_an_action() {
    let valid = r#"workflow Demo
class Decision { area string choice string }
ledger decisions { entry Decision partition by area retain 90d }
action record(decision Decision) -> int {
  append Decision { area decision.area choice decision.choice } to decisions as saved
  after saved succeeds { return saved.seq }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown_receipt_field = valid.replace("saved.seq", "saved.sequence");
    assert!(check(&unknown_receipt_field)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("sequence")));

    let wrong_payload = valid.replace("choice decision.choice", "choice 42");
    assert!(check(&wrong_payload).iter().any(|diagnostic| diagnostic
        .message
        .contains("ledger `decisions` entry must match `Decision`")));

    let wrong_schema = valid
        .replace(
            "class Decision { area string choice string }",
            "class Decision { area string choice string }\nclass Other { area string choice string }",
        )
        .replace("append Decision", "append Other");
    assert!(check(&wrong_schema).iter().any(|diagnostic| diagnostic
        .message
        .contains("ledger `decisions` accepts `Decision` entries, not `Other`")));

    let unknown_ledger = valid.replace("to decisions", "to missing");
    assert!(check(&unknown_ledger).iter().any(|diagnostic| diagnostic
        .message
        .contains("ledger `missing` is not declared")));
}

#[test]
fn tracker_file_is_a_checked_structural_operation_inside_an_action() {
    let valid = r#"workflow Demo
tracker backlog
action file(title string) -> string {
  file issue into backlog { title title body "details" labels ["bug"] metadata { source "api" } } as filed
  after filed succeeds { return filed.id }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown_receipt_field = valid.replace("filed.id", "filed.number");
    assert!(check(&unknown_receipt_field)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("number")));

    let unknown_tracker = valid.replace("into backlog", "into missing");
    assert!(check(&unknown_tracker).iter().any(|diagnostic| diagnostic
        .message
        .contains("tracker `missing` is not declared")));

    let missing_title = valid.replace("title title ", "");
    assert!(check(&missing_title)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("requires a `title` field")));

    let wrong_title = valid.replace("title title", "title 42");
    assert!(check(&wrong_title).iter().any(|diagnostic| diagnostic
        .message
        .contains("field `title` must be a string")));

    let unknown_field = valid.replace("body \"details\"", "priority 1");
    assert!(check(&unknown_field).iter().any(|diagnostic| diagnostic
        .message
        .contains("tracker item has no field `priority`")));
}

#[test]
fn tracker_lifecycle_values_share_one_composable_address() {
    let valid = r#"workflow Demo
tracker backlog
action close(item WorkItem) -> string {
  claim item as held
  after held succeeds {
    finish held { summary item.body } as finished
    after finished succeeds { return finished.status }
  }
}
action reopen(item WorkItem) -> string {
  release item as released
  after released succeeds { return released.id }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let missing_address = valid.replace("item WorkItem", "item string");
    assert!(check(&missing_address).iter().any(|diagnostic| diagnostic
        .message
        .contains("must provide string fields `queue`, `id`, and `title`")));

    let unknown_receipt = valid.replace("finished.status", "finished.done");
    assert!(check(&unknown_receipt)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("finished.done")));

    let unknown_finish_field = valid.replace("summary item.body", "resolution item.body");
    assert!(check(&unknown_finish_field)
        .iter()
        .any(|diagnostic| diagnostic
            .message
            .contains("tracker finish has no field `resolution`")));

    let wrong_summary = valid.replace("summary item.body", "summary 42");
    assert!(check(&wrong_summary).iter().any(|diagnostic| diagnostic
        .message
        .contains("tracker finish field `summary` must be a string")));
}

#[test]
fn file_export_checks_its_collection_contract_at_the_authored_statement() {
    let valid = r#"workflow Demo
file store workspace { root "." allow write ["out/**"] }
class Ticket { owner string priority int }
action save(path string) -> int {
  export jsonl Ticket to workspace at path { where priority > 2 mode replace } as saved
  after saved succeeds { return saved.row_count }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown_field = valid.replace("saved.row_count", "saved.rows");
    assert!(check(&unknown_field)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("rows")));

    let wrong_path = valid.replace("at path", "at 42");
    assert!(check(&wrong_path).iter().any(|diagnostic| diagnostic
        .message
        .contains("file export path `42` must be a string value")));

    let wrong_predicate = valid.replace("priority > 2", "priority + 2");
    assert!(check(&wrong_predicate)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("must be boolean for `Ticket`")));
}

#[test]
fn non_success_aliases_have_their_structured_terminal_payload_types() {
    let valid = r#"workflow Demo
action wait() -> string {
  timer 1s as pause
  after pause succeeds { return "done" }
  after pause fails as problem { return problem.reason }
  after pause times out as problem { return problem.summary }
  after pause cancelled as problem { return problem.summary }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown = valid.replace("problem.reason", "problem.typo");
    assert!(check(&unknown)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("typo")));

    let child = r#"workflow Demo
action parent() -> string {
  child() as result
  after result succeeds { return result }
  after result fails as problem { return problem.summary }
}
action child() -> string ! string { fail "broken" }
"#;
    assert!(check(child).is_empty(), "{:?}", check(child));

    let unavailable = child.replace(
        "after result fails as problem",
        "after result times out as problem",
    );
    assert!(check(&unavailable).iter().any(|diagnostic| diagnostic
        .message
        .contains("settles as `Completed` or `Failed`")));
}

#[test]
fn direct_effect_completion_alias_has_a_finite_terminal_envelope() {
    let valid = r#"workflow Demo
action wait() -> string {
  timer 1s as pause
  after pause completes as outcome {
    case outcome {
      Completed as value => { return "done" }
      Failed as problem => { return problem.reason }
      TimedOut as problem => { return problem.summary }
      Cancelled as problem => { return problem.summary }
    }
  }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown = valid.replace("problem.reason", "problem.typo");
    assert!(check(&unknown)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("typo")));

    let incomplete = valid.replace(
        "      Cancelled as problem => { return problem.summary }\n",
        "",
    );
    assert!(check(&incomplete).iter().any(|diagnostic| diagnostic
        .message
        .contains("does not handle terminal outcome")));
}

#[test]
fn direct_effect_outcome_expression_has_a_finite_terminal_envelope() {
    let valid = r#"workflow Demo
action wait() -> string {
  timer 1s as pause
  case outcome(pause) {
    Completed as value => { return "done" }
    Failed as problem => { return problem.reason }
    TimedOut as problem => { return problem.summary }
    Cancelled as problem => { return problem.summary }
  }
}"#;
    assert!(check(valid).is_empty(), "{:?}", check(valid));

    let unknown = valid.replace("problem.reason", "problem.typo");
    assert!(check(&unknown)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("typo")));

    let incomplete = valid.replace(
        "    Cancelled as problem => { return problem.summary }\n",
        "",
    );
    assert!(check(&incomplete).iter().any(|diagnostic| diagnostic
        .message
        .contains("does not handle terminal outcome")));

    let value = valid.replace("outcome(pause)", "outcome(value)");
    assert!(check(&value).iter().any(|diagnostic| diagnostic
        .message
        .contains("value, not an action operation")));

    let malformed = valid.replace("outcome(pause)", "outcome()");
    assert!(check(&malformed).iter().any(|diagnostic| diagnostic
        .message
        .contains("requires exactly one named operation")));

    let child = r#"workflow Demo
class Problem { reason string }
action parent() -> string {
  child() as result
  case outcome(result) {
    Completed as value => { return value }
    Failed as problem => {
      case problem.domain {
        Problem as domain => { return domain.reason }
        None => { return problem.summary }
      }
    }
  }
}

action child() -> string ! Problem { fail { reason "broken" } }
"#;
    assert!(check(child).is_empty(), "{:?}", check(child));

    let impossible = child.replace(
        "    Completed as value => { return value }",
        "    Completed as value => { return value }\n    TimedOut as problem => { return problem.summary }",
    );
    assert!(check(&impossible)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("is not a terminal outcome")));

    let legacy = r#"workflow Demo
action legacy() { timer 1s as wait }
action parent() -> string {
  legacy() as result
  case outcome(result) {
    Completed as value => { return "done" }
    Failed as problem => { return problem.summary }
  }
}"#;
    assert!(check(legacy).iter().any(|diagnostic| diagnostic
        .message
        .contains("requires an effect or typed child-action operation")));
}

#[test]
fn managed_success_uses_the_operation_binding_without_a_second_alias() {
    let source = r#"workflow Demo
action child() -> string { return "ready" }
action parent() -> string {
  child() as result
  after result succeeds as output { return output }
}"#;
    let diagnostics = check(source);
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(
        diagnostics[0].code,
        diagnostic_code!("construct.redundant_success_alias")
    );
    assert!(diagnostics[0]
        .message
        .contains("operation `result` already denotes its successful value"));
    assert_eq!(
        diagnostics[0].suggestion.as_deref(),
        Some("write `after result succeeds { ... }` and use `result` directly")
    );

    let migrated = source
        .replace(" succeeds as output", " succeeds")
        .replace("output", "result");
    assert!(check(&migrated).is_empty(), "{:?}", check(&migrated));
}
