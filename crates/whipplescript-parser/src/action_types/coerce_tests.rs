const HEADER: &str = r###"use std.coercion
@service
workflow CoerceArguments
class Item { title string }
class Other { title string }
class Piece { text string }
coerce text(value string) -> Piece { prompt "{{ value }} {{ ctx.output_format }}" }
coerce number(value int) -> Piece { prompt "{{ value }} {{ ctx.output_format }}" }
coerce item(value Item) -> Piece { prompt "{{ ctx.output_format }}" }
coerce optional(value string?) -> Piece { prompt "{{ ctx.output_format }}" }
"###;

#[test]
fn named_coerce_arguments_are_checked_by_the_actual_compiler() {
    let cases = [
        (
            "string_0",
            true,
            r###"action read(value string, record Item) -> null {
coerce text("literal") as result
return null
}
"###,
            None,
        ),
        (
            "string_1",
            true,
            r###"action read(value string, record Item) -> null {
coerce text(value) as result
return null
}
"###,
            None,
        ),
        (
            "string_2",
            true,
            r###"action read(value string, record Item) -> null {
coerce text(record.title) as result
return null
}
"###,
            None,
        ),
        (
            "int_3",
            true,
            r###"action read(value int) -> null {
coerce number(12) as result
return null
}
"###,
            None,
        ),
        (
            "int_4",
            true,
            r###"action read(value int) -> null {
coerce number(value) as result
return null
}
"###,
            None,
        ),
        (
            "int_5",
            true,
            r###"action read(value int) -> null {
coerce number(value + 1) as result
return null
}
"###,
            None,
        ),
        (
            "class",
            true,
            r###"action read(value Item) -> null {
coerce item(value) as result
return null
}
"###,
            None,
        ),
        (
            "optional_null",
            true,
            r###"action read() -> null {
coerce optional(null) as result
return null
}
"###,
            None,
        ),
        (
            "optional_present",
            true,
            r###"action read(value string?) -> null {
case value { null => { } _ => { coerce text(value) as result } }
return null
}
"###,
            None,
        ),
        (
            "optional_field_present",
            true,
            r###"action read(value Item?) -> null {
case value { null => { } _ => { coerce text(value.title) as result } }
return null
}
"###,
            None,
        ),
        (
            "scalar_string_path",
            true,
            r###"action read(value string) -> null {
coerce text(value.summary) as result
return null
}
"###,
            Some("type.unknown_field"),
        ),
        (
            "scalar_int_path",
            true,
            r###"action read(value int) -> null {
coerce number(value.field) as result
return null
}
"###,
            Some("type.unknown_field"),
        ),
        (
            "unknown_class_field",
            true,
            r###"action read(value Item) -> null {
coerce text(value.typo) as result
return null
}
"###,
            Some("type.unknown_field"),
        ),
        (
            "wrong_primitive",
            true,
            r###"action read() -> null {
coerce text(12) as result
return null
}
"###,
            Some("type.mismatch"),
        ),
        (
            "wrong_class",
            true,
            r###"action read(value Other) -> null {
coerce item(value) as result
return null
}
"###,
            Some("type.mismatch"),
        ),
        (
            "optional_value",
            true,
            r###"action read(value string?) -> null {
coerce text(value) as result
return null
}
"###,
            Some("type.mismatch"),
        ),
        (
            "optional_field",
            true,
            r###"action read(value Item?) -> null {
coerce text(value.title) as result
return null
}
"###,
            Some("type.mismatch"),
        ),
        (
            "missing",
            true,
            r###"action read() -> null {
coerce text() as result
return null
}
"###,
            Some("expr.arity_mismatch"),
        ),
        (
            "extra",
            true,
            r###"action read() -> null {
coerce text("x", "y") as result
return null
}
"###,
            Some("expr.arity_mismatch"),
        ),
        (
            "unknown",
            true,
            r###"action read() -> null {
coerce missing("x") as result
return null
}
"###,
            Some("type.unknown_coerce"),
        ),
        (
            "then_valid",
            true,
            r###"action read() -> null {
then result <- coerce text("ok")
return null
}
"###,
            None,
        ),
        (
            "then_invalid",
            true,
            r###"action read() -> null {
then result <- coerce text(2)
return null
}
"###,
            Some("type.mismatch"),
        ),
        (
            "nested_valid",
            true,
            r###"action read() -> null {
timer 1s as wait
after wait succeeds { coerce text("ok") as result }
return null
}
"###,
            None,
        ),
        (
            "nested_invalid",
            true,
            r###"action read() -> null {
timer 1s as wait
after wait succeeds { coerce text(2) as result }
return null
}
"###,
            Some("type.mismatch"),
        ),
        (
            "failure_alias",
            true,
            r###"action read() -> null {
coerce text("ok") as result
after result fails as problem { coerce text(problem.reason) as recovery }
return null
}
"###,
            None,
        ),
        (
            "rule_False",
            true,
            r###"action marker() -> null { return null }
rule run when started => { coerce text("ok") as result }
"###,
            None,
        ),
        (
            "rule_True",
            true,
            r###"action marker() -> null { return null }
rule run when started => { coerce text(1) as result }
"###,
            Some("type.mismatch"),
        ),
        (
            "pattern_expanded",
            false,
            r###"use std.coercion
pattern Helpers {
 coerce text(value string) -> string { prompt "{{ value }}" }
}
@service
workflow Expanded {
 apply Helpers as helper { }
 action read() -> null { coerce helper_text("ok") as result
return null }
}
"###,
            None,
        ),
        (
            "failure_alias_bad_field",
            true,
            r###"action read() -> null { coerce text("ok") as result
after result fails as problem { coerce text(problem.typo) as recovery }
return null }"###,
            Some("type.unknown_field"),
        ),
        (
            "tell_success_False",
            true,
            r###"agent writer { provider fixture }
action read() -> null { tell writer "write" as turn
after turn succeeds { coerce text(turn) as result }
return null }"###,
            None,
        ),
        (
            "tell_success_True",
            true,
            r###"agent writer { provider fixture }
action read() -> null { tell writer "write" as turn
after turn succeeds { coerce text(turn.summary) as result }
return null }"###,
            Some("type.unknown_field"),
        ),
    ];
    for (label, header, body, code) in cases {
        let source = if header {
            format!("{HEADER}{body}")
        } else {
            body.to_owned()
        };
        let output = crate::compile_program(&source);
        match code {
            None => {
                assert!(
                    output.diagnostics.is_empty(),
                    "{label}: {:?}",
                    output.diagnostics
                );
                assert!(output.ir.is_some(), "{label}: no compiled program");
            }
            Some(code) => {
                assert_eq!(
                    output.diagnostics.len(),
                    1,
                    "{label}: {:?}",
                    output.diagnostics
                );
                let diagnostic = &output.diagnostics[0];
                assert_eq!(diagnostic.code.as_str(), code, "{label}: {diagnostic:?}");
                assert!(diagnostic.span.end <= source.len());
                if code == "type.mismatch" {
                    assert!(
                        diagnostic
                            .related
                            .iter()
                            .any(|note| note.message == "coerce parameter declared here"),
                        "{label}: {diagnostic:?}"
                    );
                }
            }
        }
    }
}
