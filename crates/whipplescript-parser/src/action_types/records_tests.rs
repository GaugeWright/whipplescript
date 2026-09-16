use super::*;

fn check(declarations: &str, params: &str, body: &str) -> Vec<Diagnostic> {
    tests::check(&format!("workflow Records\n{declarations}\naction build({params}) -> null {{ {body}\nreturn null }}"))
}
fn accepts(declarations: &str, params: &str, body: &str) {
    let errors = check(declarations, params, body);
    assert!(
        errors.is_empty(),
        "{declarations}\n{params}\n{body}: {errors:?}"
    );
}
fn refuses(declarations: &str, params: &str, body: &str, code: DiagnosticCode) {
    let errors = check(declarations, params, body);
    assert!(errors.iter().any(|e| e.code == code), "{body}: {errors:?}");
}

#[test]
fn action_record_payload_checks_required_unknown_duplicate_and_directional_fields() {
    let schema = "class Out { name string count float maybe string? }";
    accepts(schema, "name string", "record Out { name name count 1 }");
    for (body, code) in [
        (
            "record Out { count 1 }",
            diagnostic_code!("type.missing_required_field"),
        ),
        (
            "record Out { name 4 count 1 }",
            diagnostic_code!("type.mismatch"),
        ),
        (
            "record Out { name \"x\" count 1 extra true }",
            diagnostic_code!("type.unknown_field"),
        ),
        (
            "record Out { name \"x\" count 1 name \"y\" }",
            diagnostic_code!("type.duplicate_field"),
        ),
    ] {
        refuses(schema, "", body, code);
    }
}

#[test]
fn action_record_payload_projection_copies_matching_fields_and_overrides_before_reads() {
    let schema = "class Input { name int extra bool }\nclass Out { name string flag bool? }";
    accepts(
        schema,
        "source Input",
        "record Out from source { name \"fixed\" }",
    );
    refuses(
        schema,
        "source Input",
        "record Out from source { }",
        diagnostic_code!("type.mismatch"),
    );
    accepts(
        "class Input { name string extra bool }\nclass Out { name string }",
        "source Input",
        "record Out from source { }",
    );
    for ty in ["string", "Input?", "map<string>", "Input | null"] {
        refuses(
            schema,
            &format!("source {ty}"),
            "record Out from source { name \"fixed\" }",
            diagnostic_code!("type.mismatch"),
        );
    }
    refuses(
        schema,
        "",
        "record Out from missing { name \"fixed\" }",
        diagnostic_code!("type.mismatch"),
    );
}

#[test]
fn action_record_payload_shorthand_renaming_and_lexical_shadowing_are_real_reads() {
    let schema = "class Input { name string alternate string flag bool }\nclass Out { name string flag bool? }";
    for body in [
        "record Out from source { name }",
        "record Out from source { name alternate }",
        "record Out from source { name source.alternate }",
        "record Out from source { flag true }",
    ] {
        accepts(schema, "source Input", body);
    }
    accepts(
        schema,
        "source Input, alternate string",
        "record Out from source { name alternate }",
    );
    refuses(
        schema,
        "source Input, alternate int",
        "record Out from source { name alternate }",
        diagnostic_code!("type.mismatch"),
    );
    refuses(
        schema,
        "source Input",
        "record Out from source { name missing }",
        diagnostic_code!("type.unknown_field"),
    );
    refuses(
        schema,
        "source Input",
        "record Out from source { name alternate }\ntimer 1s as alternate",
        diagnostic_code!("type.mismatch"),
    );
    let optional = "class Input { name string flag bool }\nclass Out { name string flag bool? }";
    accepts(
        optional,
        "source Input",
        "record Out from source { flag null }",
    );
}

#[test]
fn action_record_payload_optional_and_union_sources_preserve_missing_members() {
    let schema = "class Has { name string }\nclass Empty { }\nclass Out { name string? }";
    accepts(schema, "source Has | Empty", "record Out from source { }");
    refuses(
        &schema.replace("name string?", "name string"),
        "source Has | Empty",
        "record Out from source { }",
        diagnostic_code!("type.missing_required_field"),
    );
    refuses(
        schema,
        "source Has | Empty",
        "record Out from source { name }",
        diagnostic_code!("type.mismatch"),
    );
    let schema = "class Input { name string? }\nclass Out { name string | null }";
    refuses(
        schema,
        "source Input",
        "record Out from source { }",
        diagnostic_code!("type.missing_required_field"),
    );
    accepts(
        schema,
        "source Input",
        "record Out from source { name source.name }",
    );
    accepts(
        &schema.replace("name string | null", "name string?"),
        "source Input",
        "record Out from source { }",
    );
}

#[test]
fn action_record_payload_conditions_control_required_fields_and_copy_reads() {
    let schema = "class Input { kind \"ready\" | \"waiting\"\nvalue string when kind is \"ready\" }\nclass Out { kind \"ready\" | \"waiting\"\nvalue string when kind is \"ready\" }";
    accepts(schema, "", "record Out { kind \"waiting\" }");
    accepts(schema, "", "record Out { kind \"ready\" value \"yes\" }");
    refuses(
        schema,
        "",
        "record Out { kind \"ready\" }",
        diagnostic_code!("type.missing_required_field"),
    );
    refuses(
        schema,
        "",
        "record Out { kind \"waiting\" value 4 }",
        diagnostic_code!("type.mismatch"),
    );
    refuses(
        schema,
        "source Input",
        "record Out from source { }",
        diagnostic_code!("expr.conditional_without_presence"),
    );
    accepts(schema, "source Input", "case source.kind { \"ready\" => { record Out from source { } } _ => { record Out from source { value \"unused\" } } }");
    let valid = format!(
        "workflow Records\n{schema}\naction make() -> Out {{ return {{ kind \"waiting\" }} }}"
    );
    assert!(tests::check(&valid).is_empty());
    assert!(!tests::check(
        &valid.replace("return { kind \"waiting\" }", "return { kind \"ready\" }")
    )
    .is_empty());
}

#[test]
fn action_record_payload_nested_objects_arrays_maps_and_nominal_fields() {
    let schema = "class Part { name string }\nclass Other { name string }\nclass Out { part Part parts Part[] names map<string> }";
    accepts(
        schema,
        "name string",
        "record Out { part { name name } parts [{ name name }] names { first name } }",
    );
    accepts(
        schema,
        "part Part",
        "record Out { part part parts [part] names {} }",
    );
    refuses(
        schema,
        "part Other",
        "record Out { part part parts [] names {} }",
        diagnostic_code!("type.mismatch"),
    );
    refuses(
        schema,
        "",
        "record Out { part { name 1 } parts [] names {} }",
        diagnostic_code!("type.mismatch"),
    );
    refuses(
        schema,
        "",
        "record Out { part { name \"ok\" } parts [] names { first 1 } }",
        diagnostic_code!("type.mismatch"),
    );
}

#[test]
fn action_record_payload_enum_constructors_require_members_and_synthesize_only_their_tag() {
    let schema = "enum Decision { Approved { score float note string? }\nBlocked }\nclass Out { result Decision }";
    accepts(schema, "", "record Out { result Approved { score 1 } }");
    accepts(schema, "", "record Out { result Blocked }");
    refuses(
        schema,
        "",
        "record Out { result Approved }",
        diagnostic_code!("type.mismatch"),
    );
    refuses(
        schema,
        "",
        "record Out { result Approved { } }",
        diagnostic_code!("type.missing_required_field"),
    );
    refuses(
        schema,
        "",
        "record Out { result Approved { score \"bad\" } }",
        diagnostic_code!("type.mismatch"),
    );
    refuses(
        schema,
        "",
        "record Out { result Approved { score 1 variant \"Blocked\" } }",
        diagnostic_code!("construct.reserved_name"),
    );
    refuses(
        schema,
        "",
        "record Out { result Approved { score 1 extra true } }",
        diagnostic_code!("type.unknown_field"),
    );
    refuses(
        schema,
        "",
        "record Out { result Approved { score 1 score 2 } }",
        diagnostic_code!("type.duplicate_field"),
    );
    refuses(
        schema,
        "",
        "record Out { result Blocked { } }",
        diagnostic_code!("type.mismatch"),
    );
    refuses(
        schema,
        "",
        "record Out { result Missing { } }",
        diagnostic_code!("type.mismatch"),
    );
    refuses(
        "class Part { name string }\nclass Out { part Part }",
        "",
        "record Out { part Part { name \"x\" } }",
        diagnostic_code!("type.mismatch"),
    );
    let optional = schema.replace("score float", "score float?");
    accepts(&optional, "", "record Out { result Approved { } }");
    refuses(
        &optional,
        "",
        "record Out { result Approved }",
        diagnostic_code!("type.mismatch"),
    );
}

#[test]
fn action_record_payload_enum_union_checks_candidates_and_does_not_inherit_projection_shorthand() {
    let schema = "enum NumberResult { Good { value int } }\nenum TextResult { Good { value string } }\nclass Input { value string }\nclass Out { result NumberResult | TextResult }";
    accepts(schema, "", "record Out { result Good { value \"text\" } }");
    accepts(schema, "", "record Out { result Good { value 7 } }");
    refuses(
        schema,
        "source Input",
        "record Out from source { result Good { value value } }",
        diagnostic_code!("type.mismatch"),
    );
    accepts(
        schema,
        "source Input",
        "record Out from source { result Good { value source.value } }",
    );
    accepts(
        &schema.replace("NumberResult | TextResult", "TextResult?"),
        "",
        "record Out { result Good { value \"text\" } }",
    );
    let text =
        format!("workflow Records\n{schema}\naction make() -> NumberResult {{ return Good }}");
    assert!(!tests::check(&text).is_empty());
}

#[test]
fn action_record_payload_diagnostics_are_at_assignments_and_keep_declarations() {
    let source = "workflow Records\nclass Out { name string }\naction make() -> null { record Out { name 4 }\nreturn null }";
    let errors = tests::check(source);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(&source[errors[0].span.start..errors[0].span.end], "name 4");
    assert_eq!(
        &source[errors[0].related[0].span.start..errors[0].related[0].span.end],
        "string"
    );
    assert_eq!(compile_program(source).diagnostics, errors);
    let source = source.replace("name 4", "name \"a\" name \"b\" name \"c\"");
    let errors = tests::check(&source);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors
        .iter()
        .all(|e| &source[e.related[0].span.start..e.related[0].span.end] == "name \"a\""));
}

#[test]
fn action_record_payload_checks_replacements_nested_blocks_and_unused_helpers() {
    let schema = "class Out { name string }";
    for body in [
        "done source -> record Out { name 1 }",
        "timer 1s as wait\nafter wait succeeds { record Out { name 1 } }",
        "case source.name { _ => { record Out { name 1 } } }",
        "during Out { record Out { name 1 } } on lapse { }",
        "during Out { } on lapse { record Out { name 1 } }",
        "then wait <- timer 1s\nrecord Out { name 1 }",
    ] {
        refuses(
            schema,
            "source Out",
            body,
            diagnostic_code!("type.mismatch"),
        );
    }
    let source = "workflow Records\nclass Out { name string }\naction make() -> null { return null }\nrule run when Out as source => { make()\nrecord Out { name 1 } }";
    assert!(compile_program(source)
        .diagnostics
        .iter()
        .any(|d| d.code == diagnostic_code!("type.mismatch") && d.message.contains("Out.name")));
    let valid = source.replace("name 1", "name source.name");
    let compiled = compile_program(&valid);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    assert!(compiled.typed_actions.is_some());
}

#[test]
fn action_record_payload_keeps_unknown_and_kernel_schema_errors_in_their_own_phase() {
    for (record, code) in [
        ("Missing", diagnostic_code!("type.unknown_schema")),
        (
            "TerminalFailed",
            diagnostic_code!("construct.reserved_name"),
        ),
    ] {
        let source = format!(
            "workflow Records\naction make() -> null {{ record {record} {{ }}\nreturn null }}"
        );
        let errors = compile_program(&source).diagnostics;
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].code, code, "{errors:?}");
    }
    refuses(
        "class TerminalFailed { name string }",
        "",
        "record TerminalFailed { }",
        diagnostic_code!("type.missing_required_field"),
    );
}

#[test]
fn action_record_payload_bad_discriminator_does_not_add_speculative_missing_fields() {
    let errors = check(
        "class Out { kind \"ready\" | \"waiting\"\nvalue string when kind is \"ready\" }",
        "",
        "record Out { kind 1 }",
    );
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].code, diagnostic_code!("type.mismatch"));
}

#[test]
fn action_record_payload_composes_helper_data_without_requiring_a_fact_subject() {
    let source = "workflow Records\nclass Input { name string }\nclass Out { name string }\naction input() -> Input { return { name \"data\" } }\naction save() -> null { input() as source\nrecord Out from source { }\nreturn null }";
    assert!(
        tests::check(source).is_empty(),
        "{:?}",
        tests::check(source)
    );
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    assert!(compiled.typed_actions.is_some());
    accepts(
        "class Out { payload sealed<string> }",
        "value sealed<string>",
        "record Out { payload value }",
    );
    refuses(
        "class Out { payload sealed<string> }",
        "value sealed<int>",
        "record Out { payload value }",
        diagnostic_code!("type.mismatch"),
    );
}

#[test]
fn action_record_payload_implicit_and_nested_errors_keep_honest_source_locations() {
    let source = "workflow Records\nclass Input { name int }\nclass Out { name string }\naction save(source Input) -> null { record Out from source { }\nreturn null }";
    let errors = tests::check(source);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(
        &source[errors[0].span.start..errors[0].span.end],
        "record Out from source { }"
    );
    assert!(errors[0].message.contains("copied from source.name"));
    assert_eq!(
        &source[errors[0].related[0].span.start..errors[0].related[0].span.end],
        "string"
    );
    let source = "workflow Records\nenum Result { Good { score int } }\nclass Out { result Result }\naction save() -> null { record Out { result Good { score \"bad\" } }\nreturn null }";
    let errors = tests::check(source);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(
        &source[errors[0].span.start..errors[0].span.end],
        "score \"bad\""
    );
    assert_eq!(
        &source[errors[0].related[0].span.start..errors[0].related[0].span.end],
        "int"
    );
}

#[test]
fn action_record_payload_checks_every_projection_alternative_and_deduplicates_the_same_fault() {
    let schema = "class Alpha { name string }\nclass Zed { name int }\nclass Out { name string? }";
    refuses(
        schema,
        "source Alpha | Zed",
        "record Out from source { }",
        diagnostic_code!("type.mismatch"),
    );
    let errors = check(
        &schema.replace("class Alpha { name string }", "class Alpha { name int }"),
        "source Alpha | Zed",
        "record Out from source { }",
    );
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].code, diagnostic_code!("type.mismatch"));
}

#[test]
fn action_record_payload_declassify_results_use_checked_bounded_projection_types() {
    let declarations = "class Source { value string private string }\nclass Out { value string }";
    accepts(
        declarations,
        "source Source",
        "declassify source into Out as released\nrecord Out { value released.value }",
    );
    for (declarations, params) in [
        (
            "class Source { private string }\nclass Out { value string }",
            "source Source",
        ),
        (
            "class Source { value int }\nclass Out { value string }",
            "source Source",
        ),
        (
            "class Source { value string? }\nclass Out { value string }",
            "source Source",
        ),
        ("class Out { value string }", "source string"),
    ] {
        assert!(!check(
            declarations,
            params,
            "declassify source into Out as released\nrecord Out { value released.value }"
        )
        .is_empty());
    }
    assert!(!check(
        declarations,
        "",
        "declassify missing into Out as released\nrecord Out { value released.value }"
    )
    .is_empty());
}
