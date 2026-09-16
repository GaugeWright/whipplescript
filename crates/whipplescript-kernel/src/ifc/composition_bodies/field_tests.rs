use super::tests::source;
use super::*;
const HEADER: &str = r#"@service
workflow Fields
class Input { public string secret string }
class Safe { public string }
class Secret { secret string }
class Output { value string }
class Both { public string secret string }
class Boolean { value bool }
class OptionalValue { value string? }
class Box { item Input }
class Inner { note string }
class Nested { inner Inner many Inner[] maybe Inner? }
coerce make() -> Input { prompt "Build a record" }
coerce echo(value string) -> Output { prompt "Echo {{ value }}" }
action select(input Input) -> bool { return input.secret == "yes" }
action wrap(input Input) -> Box { return { item input } }
action unwrap(input Box) -> Input { return input.item }
"#;
fn check(declarations: &str, body: &str, policy: &str) -> (String, Vec<Diagnostic>) {
    let text = format!("{HEADER}{declarations}\nrule run when Input as input => {{ {body} }}");
    let analysis = source(&text);
    let envelope = VerifiedEnvelope::for_test(Envelope::from_json(policy).unwrap());
    let errors = analyze(&analysis)
        .unwrap()
        .check_source_flows(&envelope, &[]);
    (text, errors)
}
const LABEL: &str = r#"{"resources":{"Input.secret":{"reader":"Secret"}}}"#;
fn fields(errors: &[Diagnostic]) -> Vec<&Diagnostic> {
    errors
        .iter()
        .filter(|error| error.code.as_str() == "security.projection_leak")
        .collect()
}

#[test]
fn redaction_extracts_into_actions_with_exact_field_clearance() {
    for (keep, ty, count) in [("public", "Safe", 0), ("secret", "Secret", 1)] {
        let declarations = format!("action trim(input Input) -> {ty} {{ redact input keep [{keep}] as kept\nreturn kept }}");
        let (text, errors) = check(
            &declarations,
            &format!("trim(input) as result\nrecord {ty} from result {{ }}"),
            LABEL,
        );
        assert_eq!(fields(&errors).len(), count, "{text}: {errors:?}");
        if count == 0 {
            assert!(errors.is_empty(), "{errors:?}");
        } else {
            let error = fields(&errors)[0];
            assert!(error.message.contains("Input.secret"));
            assert!(error
                .related
                .iter()
                .any(|r| r.message == "call to action `trim`"));
            assert!(error
                .related
                .iter()
                .any(|r| r.message == "original field source enters here"));
        }
    }
}

#[test]
fn every_nested_call_and_actual_destination_keeps_a_distinct_diagnostic() {
    let declarations = "action publish(input Box) -> null { unwrap(input) as plain\nrecord Secret { secret plain.secret }\nreturn null }";
    let (text, errors) = check(
        declarations,
        "wrap(input) as boxed\npublish(boxed)\npublish(boxed)",
        LABEL,
    );
    let errors = fields(&errors);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_ne!(errors[0].related, errors[1].related);
    for error in errors {
        assert!(text[error.span.start..error.span.end].contains("record Secret"));
        assert!(error
            .related
            .iter()
            .any(|r| r.message == "call to action `publish`"));
        assert!(error
            .related
            .iter()
            .any(|r| r.message == "call to action `unwrap`"));
        let sites: BTreeSet<_> = error
            .related
            .iter()
            .map(|r| (r.span.start, r.span.end, &r.message))
            .collect();
        assert_eq!(sites.len(), error.related.len(), "{error:?}");
    }
}

#[test]
fn mixed_fields_and_transforms_do_not_erase_restrictions() {
    for body in [
        "record Both { public input.public secret input.secret }",
        "record Boolean { value input.secret == \"yes\" }",
        "redact input keep [public] as safe\nrecord Both { public safe.public secret input.secret }",
        "wrap(input) as boxed\nunwrap(boxed) as plain\nrecord Secret from plain { }",
    ] {
        let (_, errors) = check("", body, LABEL);
        assert_eq!(fields(&errors).len(), 1, "{body}: {errors:?}");
    }
}

#[test]
fn bounded_copies_and_declassification_preserve_copied_field_labels() {
    for (body, count) in [
        ("record Secret from input { }", 1),
        ("record Secret from input { secret \"replacement\" }", 0),
        (
            "declassify input into Secret as kept\nrecord Secret from kept { }",
            1,
        ),
        (
            "declassify input into Safe as kept\nrecord Safe from kept { }",
            0,
        ),
    ] {
        let (_, errors) = check("", body, LABEL);
        assert_eq!(fields(&errors).len(), count, "{body}: {errors:?}");
    }
}

#[test]
fn literal_field_selection_drops_the_sibling_but_dynamic_selection_joins_it() {
    for (value, count) in [
        ("[input.public, input.secret][0]", 0),
        ("[input.public, input.secret][index]", 1),
    ] {
        let declarations =
            format!("action pick(input Input, index int) -> string? {{ return {value} }}");
        let (_, errors) = check(
            &declarations,
            "pick(input, 0) as chosen\nrecord OptionalValue { value chosen }",
            LABEL,
        );
        assert_eq!(fields(&errors).len(), count, "{value}: {errors:?}");
    }
}

#[test]
fn typed_producer_boundaries_keep_labels_even_for_constructed_results() {
    let declarations = "action make_input() -> Input { return { public \"p\" secret \"s\" } }";
    for body in ["make_input() as made", "coerce make() as made"] {
        let (_, errors) = check(
            declarations,
            &format!("{body}\nrecord Secret {{ secret made.secret }}"),
            LABEL,
        );
        assert_eq!(fields(&errors).len(), 1, "{body}: {errors:?}");
        let (_, errors) = check(
            declarations,
            &format!("{body}\nrecord Safe {{ public made.public }}"),
            LABEL,
        );
        assert!(errors.is_empty(), "{body}: {errors:?}");
    }
}

#[test]
fn effect_inputs_carry_field_labels_into_results() {
    let (_, errors) = check(
        "",
        "coerce echo(input.secret) as echoed\nrecord Output { value echoed.value }",
        LABEL,
    );
    assert_eq!(fields(&errors).len(), 1, "{errors:?}");
}

#[test]
fn field_selection_controls_constant_egress_and_recovery() {
    let declarations = "action rejected(input Input) -> string ! string { fail input.secret }\naction decide(input Input) -> string { select(input) as flag\ncase flag { true => { return \"yes\" } false => { return \"no\" } } }";
    for body in [
        "decide(input) as choice\nrecord Output { value choice }",
        "select(input) as flag\ncase flag { true => { record Output { value \"yes\" } } false => {} }",
        "rejected(input) as outcome\nafter outcome fails { record Output { value \"handled\" } }",
        "select(input) as flag\nduring flag { record Output { value \"active\" } } on lapse as state { timer 1s as wait }",
    ] {
        let (_, errors) = check(declarations, body, LABEL);assert_eq!(fields(&errors).len(), 1, "{body}: {errors:?}");
    }
}

#[test]
fn explicit_order_does_not_turn_a_sibling_value_into_payload() {
    let declarations = "action unused(input Input) -> string { return input.secret }\naction constant() -> string { return \"safe\" }";
    let (_, errors) = check(
        declarations,
        "unused(input) as private\nthen result <- constant()\nrecord Output { value result }",
        LABEL,
    );
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn clearing_a_sink_requires_every_field_compartment() {
    let both =
        r#"{"resources":{"Input.secret":{"reader":["A","B"]},"fact:Secret":{"reader":["A"]}}}"#;
    let (_, errors) = check("", "record Secret from input { }", both);
    assert_eq!(fields(&errors).len(), 1, "{errors:?}");
    let cleared = both.replace("\"reader\":[\"A\"]", "\"reader\":[\"A\",\"B\"]");
    let (_, errors) = check("", "record Secret from input { }", &cleared);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn projection_never_exempts_the_whole_source_read_check() {
    let policy =
        r#"{"resources":{"Input.secret":{"reader":"Secret"},"fact:Input":{"reader":"Whole"}}}"#;
    let (_, errors) = check(
        "input arrival Input",
        "redact input keep [public] as kept\nrecord Safe { public kept.public }",
        policy,
    );
    assert!(fields(&errors).is_empty(), "{errors:?}");
    assert!(
        errors
            .iter()
            .any(|e| e.code.as_str() == "security.confidentiality_leak"),
        "{errors:?}"
    );
}

#[test]
fn nested_record_array_map_and_event_fields_keep_their_declared_labels() {
    let policy = r#"{"resources":{"Inner.note":{"reader":"Secret"}}}"#;
    for declaration in [
        "rule nested when Nested as nested => { record Output { value nested.inner.note } }",
        "action first(values Inner[]) -> Inner? { return values[0] }\nrule nested when Nested as nested => { first(nested.many) as chosen\ncase chosen { null => {} _ => { record Output { value chosen.note } } } }",
        "signal loaded.ready { inner Inner }\nrule nested when loaded.ready as event => { record Output { value event.inner.note } }",
        "action collect(inner Inner) -> map<Inner> { return { one inner } }\naction at(values map<Inner>) -> Inner? { return values[\"one\"] }\nrule nested when Nested as nested => { collect(nested.inner) as collected\nat(collected) as chosen\ncase chosen { null => {} _ => { record Output { value chosen.note } } } }",
    ] {
        let (_, errors) = check(declaration, "", policy);
        assert_eq!(fields(&errors).len(), 1, "{declaration}: {errors:?}");
        assert!(fields(&errors)[0].message.contains("Inner.note"));
    }
}

#[test]
fn class_labels_do_not_invent_fields_that_the_record_cannot_carry() {
    let (_, errors) = check(
        "",
        "record Both from input { }",
        r#"{"resources":{"Input.ghost":{"reader":"Secret"}}}"#,
    );
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn failure_type_labels_survive_a_constructed_failure_and_local_recovery() {
    let declarations = "class Problem { secret string }\naction bad() -> null ! Problem { fail { secret \"classified\" } }";
    let (_, errors) = check(
        declarations,
        "bad() as result\nafter result fails { record Output { value \"fallback\" } }",
        r#"{"resources":{"Problem.secret":{"reader":"Secret"}}}"#,
    );
    assert_eq!(fields(&errors).len(), 1, "{errors:?}");
    assert!(fields(&errors)[0]
        .related
        .iter()
        .any(|r| r.message == "call to action `bad`"));
}

#[test]
fn opaque_turns_preserve_possible_field_influence_and_every_grant_destination() {
    let agent = "agent writer { provider trusted }";
    let (_, errors) = check(
        agent,
        "tell writer \"choose\" as choice\nrecord Output { value choice }",
        LABEL,
    );
    assert_eq!(fields(&errors).len(), 1, "{errors:?}");
    let declarations = format!("{agent}\nfile store first {{ root \"./first\" allow write [\"**\"] }}\nfile store second {{ root \"./second\" allow write [\"**\"] }}");
    let body = "tell writer \"act\" with access to first { write [\"**\"] } with access to second { write [\"**\"] } as result";
    let (_, errors) = check(&declarations, body, LABEL);
    assert_eq!(fields(&errors).len(), 2, "{errors:?}");
    let cleared =
        r#"{"resources":{"Input.secret":{"reader":"Secret"},"first":{"reader":"Secret"}}}"#;
    let (_, errors) = check(&declarations, body, cleared);
    assert_eq!(fields(&errors).len(), 1, "{errors:?}");
    assert!(fields(&errors)[0].message.contains("second"));
}

#[test]
fn a_helpers_internal_typed_operation_retains_field_evidence() {
    let declarations = "action created() -> string { coerce make() as made\nreturn made.secret }";
    let (_, errors) = check(
        declarations,
        "created() as value\nrecord Output { value value }",
        LABEL,
    );
    assert_eq!(fields(&errors).len(), 1, "{errors:?}");
}

#[test]
fn composed_suggestions_name_origins_without_inventing_a_safe_alias_projection() {
    let (_, errors) = check(
        "",
        "coerce echo(input.secret) as renamed\nrecord Output { value renamed.value }",
        LABEL,
    );
    let error = fields(&errors)[0];
    let suggestion = error.suggestion.as_ref().unwrap();
    assert!(
        suggestion.contains("contribution from `Input.secret`"),
        "{suggestion}"
    );
    assert!(!suggestion.contains("keep only"), "{suggestion}");
}

#[test]
fn a_nested_field_requires_both_container_and_member_clearance() {
    let declaration =
        "rule nested when Nested as nested => { record Output { value nested.inner.note } }";
    let policy = r#"{"resources":{"Nested.inner":{"reader":"Parent"},"Inner.note":{"reader":"Child"},"fact:Output":{"reader":"Parent"}}}"#;
    let (_, errors) = check(declaration, "", policy);
    assert_eq!(fields(&errors).len(), 1, "{errors:?}");
    assert!(fields(&errors)[0].message.contains("Inner.note"));
    let policy = policy.replace(
        "\"fact:Output\":{\"reader\":\"Parent\"}",
        "\"fact:Output\":{\"reader\":[\"Parent\",\"Child\"]}",
    );
    let (_, errors) = check(declaration, "", &policy);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn container_type_boundaries_preserve_inner_labels_without_a_record_result_alias() {
    let policy = r#"{"resources":{"Inner.note":{"reader":"Secret"}}}"#;
    for (ty, value, index) in [
        ("Inner[]", "[{ note \"n\" }]", "0"),
        ("map<Inner>", "{ one { note \"n\" } }", "\"one\""),
    ] {
        let declarations = format!("action make_values() -> {ty} {{ return {value} }}\naction observes(values {ty}) -> bool {{ return exists(values[{index}]) }}");
        let (_, errors) = check(
            &declarations,
            "make_values() as values\nobserves(values) as found\nrecord Boolean { value found }",
            policy,
        );
        assert_eq!(fields(&errors).len(), 1, "{ty}: {errors:?}");
    }
}

#[test]
fn parent_field_is_required_when_only_the_nested_member_is_cleared() {
    let declaration =
        "rule nested when Nested as nested => { record Output { value nested.inner.note } }";
    let policy = r#"{"resources":{"Nested.inner":{"reader":"Parent"},"Inner.note":{"reader":"Child"},"fact:Output":{"reader":"Child"}}}"#;
    let (_, errors) = check(declaration, "", policy);
    assert_eq!(fields(&errors).len(), 1, "{errors:?}");
    assert!(fields(&errors)[0].message.contains("Nested.inner"));
}

#[test]
fn root_guard_reads_use_the_root_binding_even_when_a_callee_shadows_its_name() {
    for (field, count) in [("secret", 1), ("public", 0)] {
        let declaration = format!("action publish(input string) -> null {{ record Output {{ value input }}\nreturn null }}\nrule selected when Input as input where input.{field} == \"yes\" => {{ publish(\"constant\") }}");
        let (_, errors) = check(&declaration, "", LABEL);
        assert_eq!(fields(&errors).len(), count, "{field}: {errors:?}");
        if count != 0 {
            assert!(fields(&errors)[0]
                .related
                .iter()
                .any(|r| r.message == "root guard observes these fields"));
        }
    }
}

#[test]
fn root_fact_queries_carry_predicate_fields_but_not_unread_siblings() {
    for (guard, count) in [("secret == \"yes\"", 1), ("public == \"yes\"", 0)] {
        let declaration = format!("rule selected when started where exists(Input where {guard}) => {{ record Output {{ value \"constant\" }} }}");
        let (_, errors) = check(&declaration, "", LABEL);
        assert_eq!(fields(&errors).len(), count, "{guard}: {errors:?}");
    }
}

#[test]
fn field_analysis_refuses_malformed_structure_and_selection_with_call_context() {
    use whipplescript_parser::action_plan::NodeKind;
    let text = format!("{HEADER}action publish(yes bool) -> null {{ case yes {{ true => {{ record Output {{ value \"constant\" }} }} false => {{}} }}\nreturn null }}\nrule run when Input as input => {{ select(input) as yes\npublish(yes) }}");
    let analysis = source(&text);
    for corrupt in ["types", "selection", "scope"] {
        let mut rule = analysis.rules()[0].clone();
        if corrupt == "types" {
            rule.typed.case_types.clear();
        } else if corrupt == "scope" {
            rule.typed.plan.scopes[0].parent_call =
                Some(whipplescript_parser::action_plan::NodeId(usize::MAX));
        } else {
            for node in &mut rule.typed.plan.nodes {
                if let NodeKind::Case { scrutinee, .. } = &mut node.kind {
                    *scrutinee = "unknown".into();
                }
            }
        }
        let inventory = analyze(&analysis).unwrap().rules.remove(0).inventory;
        let body = RuleBodyAnalysis {
            rule: &rule,
            inventory,
        };
        let context = program_context::ProgramContext::Composition(&analysis);
        let sinks = source_inputs::local_destinations(&body, context);
        let ((node, resource), sink) = sinks.first_key_value().unwrap();
        let mut errors = Vec::new();
        composition_fields::check(
            &body,
            context,
            &Envelope::from_json("{}").unwrap(),
            *node,
            resource,
            *sink,
            &mut errors,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(text[errors[0].span.start..errors[0].span.end].contains("record Output"));
        if corrupt != "scope" {
            assert!(errors[0]
                .related
                .iter()
                .any(|r| r.message == "call to action `publish`"));
        }
    }
}

#[test]
fn tagged_record_alternatives_keep_variant_field_labels() {
    let declarations = "enum Decision { Approved { score int }\nBlocked }\nclass Container { decision Decision }\nclass Whole { decision Decision }\nrule selected when Container as input => { record Whole { decision input.decision } }";
    let (_, errors) = check(
        declarations,
        "",
        r#"{"resources":{"Decision.Approved.score":{"reader":"Secret"}}}"#,
    );
    assert_eq!(fields(&errors).len(), 1, "{errors:?}");
    let (_, errors) = check(
        declarations,
        "",
        r#"{"resources":{"Decision.Ghost.score":{"reader":"Secret"}}}"#,
    );
    assert!(errors.is_empty(), "{errors:?}");
}
