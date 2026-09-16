use super::super::tests::check;
use super::*;
const HEADER: &str = "workflow Projections\nclass Source { public string private string maybe string? }\nclass Out { public string }\nclass Optional { maybe string? }\naction wrap(input Out) -> Out { return input }\n";

#[test]
fn redact_results_compose_and_resolve_forward_chains() {
    for body in [
        "redact input keep [public] as kept\nreturn kept",
        "redact second keep [public] as first\nredact input keep [public, private] as second\nreturn first",
        "wrap(kept) as result\nredact input keep [public] as kept\nreturn result",
    ] {
        let errors = check(&format!("{HEADER}action take(input Source) -> Out {{ {body} }}"));
        assert!(errors.is_empty(), "{body}: {errors:?}");
    }
    let errors = check(&format!("{HEADER}action take(input Source) -> Optional {{ redact input keep [maybe] as kept\nreturn kept }}"));
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn redact_refuses_missing_repeated_nullable_and_shadowed_sources() {
    for (params, body, expected) in [
        (
            "input Source",
            "redact input keep [absent] as kept",
            "has no field `absent`",
        ),
        (
            "input Source",
            "redact input keep [public, public] as kept",
            "repeats field `public`",
        ),
        (
            "input Source?",
            "redact input keep [public] as kept",
            "present record",
        ),
        (
            "input string",
            "redact input keep [public] as kept",
            "present record",
        ),
        (
            "input Source",
            "redact missing keep [public] as kept",
            "present record",
        ),
        (
            "input Source",
            "case true { true => { redact input keep [public] as kept\ntimer 1s as input } false => {} }",
            "present record",
        ),
        (
            "input Source",
            "redact second keep [public] as first\nredact first keep [public] as second",
            "present record",
        ),
    ] {
        let errors = check(&format!(
            "{HEADER}action take({params}) -> null {{ {body}\nreturn null }}"
        ));
        assert!(
            errors.iter().any(|e| e.message.contains(expected)),
            "{params}/{body}: {errors:?}"
        );
    }
}

#[test]
fn redact_preserves_optional_and_conditional_field_obligations() {
    let errors = check(&format!("{HEADER}class Required {{ maybe string }}\naction take(input Source) -> Required {{ redact input keep [maybe] as kept\nreturn kept }}"));
    assert!(
        errors.iter().any(|e| e.message.contains("expects")),
        "{errors:?}"
    );
    let header = "workflow Conditional\nclass Input { kind \"ready\" | \"waiting\"\nvalue string when kind is \"ready\" }\nclass Out { value string }\n";
    let errors = check(&format!("{header}action take(input Input) -> null {{ redact input keep [value] as kept\nreturn null }}"));
    assert!(
        errors
            .iter()
            .any(|e| e.code.as_str() == "expr.conditional_without_presence"),
        "{errors:?}"
    );
    assert_eq!(errors.len(), 1, "{errors:?}");
    let errors = check(&format!("{header}action take(input Input) -> Out {{ case input.kind {{\n \"ready\" => {{ redact input keep [value] as kept\nreturn kept }}\n \"waiting\" => {{ return {{ value \"none\" }} }}\n }} }}"));
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn redact_union_requires_every_variant_and_preserves_field_types() {
    let header = "workflow Union\nclass Left { value string }\nclass Right { value int }\nclass Out { value string | int }\n";
    let errors = check(&format!("{header}action take(input Left | Right) -> Out {{ redact input keep [value] as kept\nreturn kept }}"));
    assert!(errors.is_empty(), "{errors:?}");
    let errors = check(&format!("{header}class Missing {{ other string }}\naction take(input Left | Missing) -> null {{ redact input keep [value] as kept\nreturn null }}"));
    assert!(
        errors.iter().any(|e| e.message.contains("unavailable")),
        "{errors:?}"
    );
}

#[test]
fn result_types_are_joined_by_source_sites_at_every_hygienic_call() {
    use crate::action_plan::{analysis::analyze_composition, NodeId, NodeKind};
    let source = format!("{HEADER}coerce build() -> Source {{ prompt \"Build\" }}\naction take(input Source) -> Out {{ redact input keep [public] as kept\nreturn kept }}\nrule run when Source as input => {{ take(input) as first\ntake(input) as second\ncoerce build() as built\ntimer 1s as waited }}");
    let parsed = parse_program(&source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let analysis = analyze_composition(&parsed.program).unwrap();
    let rule = &analysis.rules()[0];
    assert_eq!(rule.value_types.len(), 6, "{:?}", rule.value_types);
    let mut redacts = 0;
    for (index, node) in rule.typed.plan.nodes.iter().enumerate() {
        if let NodeKind::Statement(statement) = &node.kind {
            if matches!(statement.as_ref(), BodyStmt::Redact { .. }) {
                let IrType::Object(fields) = &rule.value_types[&NodeId(index)] else {
                    panic!("redact type");
                };
                assert_eq!(
                    fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                    ["public"]
                );
                redacts += 1;
            }
        }
    }
    assert_eq!(redacts, 2);
}
