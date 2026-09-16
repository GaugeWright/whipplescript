use super::*;

const HEADER: &str = "@service\nworkflow Demo\nclass Ticket { title string }\nclass Box { ticket Ticket }\naction finish(x Ticket) -> null { done x\nreturn null }\naction identity(x Ticket) -> Ticket { return x }\naction boxed(x Ticket) -> Box { return { ticket x } }\n";

pub(super) fn check(source: &str, types: bool) -> Vec<Diagnostic> {
    let parsed = parse_program(source);
    assert!(
        parsed.diagnostics.is_empty(),
        "{source}: {:?}",
        parsed.diagnostics
    );
    let actions: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(a) => Some(a.clone()),
            _ => None,
        })
        .collect();
    let rules: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Rule(r) => Some(r),
            _ => None,
        })
        .collect();
    let semantic = SemanticContext::from_program(&parsed.program, BTreeMap::new());
    if types {
        let signatures = action_signature::validate(&actions);
        assert!(signatures.is_empty(), "{source}: {signatures:?}");
        let definitions = action_types::validate(&actions, &semantic);
        assert!(definitions.is_empty(), "{source}: {definitions:?}");
        let callers = action_types::validate_callers(&actions, &rules, &semantic);
        assert!(callers.is_empty(), "{source}: {callers:?}");
    }
    validate(&actions, &rules, &semantic)
}
fn program(body: &str) -> String {
    format!("{HEADER}rule run when Ticket as ticket => {{ {body} }}")
}
fn accepted(source: &str) {
    let errors = check(source, true);
    assert!(errors.is_empty(), "{source}: {errors:?}");
}
fn rejected(source: &str) -> Diagnostic {
    let mut errors = check(source, true);
    assert_eq!(errors.len(), 1, "{source}: {errors:?}");
    let error = errors.pop().unwrap();
    assert_eq!(error.severity, Severity::Error);
    error
}
fn text(source: &str, span: SourceSpan) -> &str {
    &source[span.start..span.end]
}

#[test]
fn action_subject_original_survives_nested_return_selection_and_operation_values() {
    for body in [
        "finish(ticket)",
        "timer 1s as wait\nafter wait succeeds { timer 1s as ticket }\nfinish(ticket)",
        "then selected <- identity(ticket)\nfinish(selected)",
        "finish(selected)\nidentity(ticket) as selected",
        "boxed(ticket) as bundle\nfinish(bundle.ticket)",
        "boxed(ticket) as bundle\nafter bundle succeeds { finish(bundle.ticket) }",
        "identity(ticket) as selected\ncase selected { Ticket as original => { finish(original) } }",
    ] { accepted(&program(body)); }
    accepted(&format!("{HEADER}action wrapped(x Ticket) -> null {{ boxed(x) as bundle\nfinish(bundle.ticket)\nreturn null }}\nrule run when Ticket as ticket => {{ wrapped(ticket) }}"));
}

#[test]
fn action_subject_copy_diagnostic_joins_argument_consumption_and_construction() {
    let source = format!("{HEADER}action copy(x Ticket) -> Ticket {{ return {{ title x.title }} }}\naction wrapped(x Ticket) -> null {{ finish(x)\nreturn null }}\nrule run when Ticket as ticket => {{ copy(ticket) as copied\nwrapped(copied) }}");
    let error = rejected(&source);
    assert_eq!(text(&source, error.span), "copied");
    assert!(error.message.contains("call to action `wrapped`"));
    assert!(error
        .related
        .iter()
        .any(|r| text(&source, r.span).contains("done x")));
    assert!(error
        .related
        .iter()
        .any(|r| text(&source, r.span) == "{ title x.title }"));
    assert!(error
        .related
        .iter()
        .any(|r| text(&source, r.span) == "finish"));
    assert!(error
        .suggestion
        .as_ref()
        .unwrap()
        .contains("original matched fact"));
    let compiled = compile_program(&source);
    assert!(compiled.ir.is_none());
    assert_eq!(compiled.diagnostics, vec![error]);
}

#[test]
fn action_subject_nominal_class_is_not_an_identity_proof() {
    let error = rejected(&program("finish({ title ticket.title })"));
    assert!(error.message.contains("constructing a collection"));
    let source = format!("{HEADER}rule run when Box as bundle => {{ finish(bundle.ticket) }}");
    assert!(rejected(&source)
        .message
        .contains("field of a matched fact"));
    let source = format!("{HEADER}action dispose(x Box) -> null {{ done x\nreturn null }}\nrule run when Ticket as ticket => {{ boxed(ticket) as box\ndispose(box) }}");
    assert!(rejected(&source)
        .message
        .contains("constructing a collection"));
    accepted(&format!(
        "{HEADER}rule run when Box as box => {{ done box }}"
    ));
}

#[test]
fn action_subject_every_return_and_parameter_is_required_independently() {
    let prefix = format!("{HEADER}action choose(a Ticket, b Ticket, flag bool) -> Ticket {{ case flag {{ true => {{ return a }} false => {{ return b }} }} }}\n");
    let good = format!("{prefix}rule run when Ticket as ticket => {{ choose(ticket, ticket, true) as selected\nfinish(selected) }}");
    accepted(&good);
    for bad in [
        "choose({ title ticket.title }, ticket, true)",
        "choose(ticket, { title ticket.title }, true)",
    ] {
        let source = good.replace("choose(ticket, ticket, true)", bad);
        assert_eq!(text(&source, rejected(&source).span), "selected");
    }
    let mixed = format!("{HEADER}action maybe(x Ticket, flag bool) -> Ticket {{ case flag {{ true => {{ return x }} false => {{ return {{ title x.title }} }} }} }}\nrule run when Ticket as ticket => {{ maybe(ticket, true) as selected\nfinish(selected) }}");
    assert_eq!(text(&mixed, rejected(&mixed).span), "selected");
    accepted(&mixed.replace("\nfinish(selected)", ""));
    let source = format!("{HEADER}action second(a Ticket, b Ticket) -> null {{ finish(b)\nreturn null }}\nrule run when Ticket as ticket => {{ second({{ title ticket.title }}, ticket) }}");
    accepted(&source);
    let bad = source.replace(
        "second({ title ticket.title }, ticket)",
        "second(ticket, { title ticket.title })",
    );
    assert_eq!(text(&bad, rejected(&bad).span), "{ title ticket.title }");
}

#[test]
fn action_subject_intrinsic_definition_errors_are_reported_once() {
    for (declaration, needle) in [
        ("action bad(x int) -> null { done x\nreturn null }", "value type cannot carry"),
        ("action bad(x Ticket) -> null { identity({ title x.title }) as copied\ndone copied\nreturn null }", "constructing a collection"),
        ("action bad() -> null { timer 1s as elapsed\ndone elapsed\nreturn null }", "operation payloads"),
    ] {
        let source = format!("{HEADER}{declaration}");
        assert!(rejected(&source).message.contains(needle));
    }
    let source = format!("{HEADER}action bad(x Ticket) -> null {{ identity({{ title x.title }}) as copied\ndone copied\nreturn null }}\naction wrapper(x Ticket) -> null {{ bad(x)\nreturn null }}\nrule run when Ticket as ticket => {{ bad(ticket)\nwrapper(ticket)\nbad(ticket) }}");
    let error = rejected(&source);
    assert!(text(&source, error.span).contains("done copied"));
}

#[test]
fn action_subject_wrappers_and_unselected_branches_do_not_hide_requirements() {
    for body in [
        "then result <- finish({ title ticket.title })",
        "timer 1s as wait\nafter wait succeeds { finish({ title ticket.title }) }",
        "case true { true => { finish(ticket) } false => { finish({ title ticket.title }) } }",
        "during Ticket { finish({ title ticket.title }) } on lapse { finish(ticket) }",
        "during Ticket { finish(ticket) } on lapse { finish({ title ticket.title }) }",
        "finish(ticket)\nfinish({ title ticket.title })",
    ] {
        let source = program(body);
        assert_eq!(
            text(&source, rejected(&source).span),
            "{ title ticket.title }"
        );
    }
}

#[test]
fn action_subject_shadowing_and_unresolved_outcomes_never_reuse_outer_proofs() {
    // These direct identity checks exercise locals whose value type contract is
    // deliberately unresolved; public compilation diagnoses that earlier.
    for body in [
        "timer 1s as wait\nafter wait fails as ticket { done ticket }",
        "timer 1s as wait\nafter wait succeeds { timer 1s as ticket\ndone ticket }",
        "during Ticket { finish(ticket) } on lapse as ticket { done ticket }",
    ] {
        let source = program(body);
        let errors = check(&source, false);
        assert_eq!(errors.len(), 1, "{source}: {errors:?}");
        assert!(errors[0].message.contains("original admitted fact"));
    }
}

#[test]
fn action_subject_producer_refusal_precedes_dependent_consumer() {
    let source = format!("{HEADER}action consumed(x Ticket) -> Ticket {{ finish(x)\nreturn x }}\nrule run when Ticket as ticket => {{ finish(result)\nconsumed({{ title ticket.title }}) as result }}");
    let error = rejected(&source);
    assert_eq!(text(&source, error.span), "{ title ticket.title }");
    assert!(error.message.contains("action `consumed`"));
}

#[test]
fn action_subject_local_cycles_refuse_but_shared_dependencies_compose() {
    let cycle = program("identity(b) as a\nidentity(a) as b\nfinish(a)");
    assert!(rejected(&cycle)
        .message
        .contains("cyclic value dependencies"));
    let diamond = program(
        "identity(last) as a\nidentity(last) as b\nidentity(ticket) as last\nfinish(a)\nfinish(b)",
    );
    accepted(&diamond);
    let mut source = HEADER.to_owned();
    for i in 0..200 {
        let next = if i == 0 {
            "identity".into()
        } else {
            format!("chain{}", i - 1)
        };
        source.push_str(&format!(
            "action chain{i}(x Ticket) -> Ticket {{ {next}(x) as value\nreturn value }}\n"
        ));
    }
    source
        .push_str("rule run when Ticket as ticket => { chain199(ticket) as value\nfinish(value) }");
    accepted(&source);
}

#[test]
fn action_subject_public_phase_order_and_managed_output_remain_explicit() {
    let good = program("finish(ticket)");
    let result = compile_program(&good);
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    assert!(result.ir.is_some());
    assert!(result.typed_actions.is_some());
    let bad = program("finish(4)");
    let result = compile_program(&bad);
    assert!(result.ir.is_none());
    assert!(result
        .diagnostics
        .iter()
        .any(|d| d.message.contains("expects Ticket")));
    assert!(!result
        .diagnostics
        .iter()
        .any(|d| d.message.contains("original admitted fact")));
    let mixed =
        format!("{HEADER}action old() {{ timer 1s as t }}\nrule run when started => {{ old() }}");
    let result = compile_program(&mixed);
    assert!(result.ir.is_none());
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.message.contains("needs a result contract")),
        "{:?}",
        result.diagnostics
    );
}

fn span() -> SourceSpan {
    SourceSpan { start: 1, end: 2 }
}
fn fact() -> Value {
    Rc::new(Shape::Fact {
        schema: "Ticket".into(),
        span: span(),
    })
}
fn parameter(index: usize, ty: IrType) -> Value {
    Rc::new(Shape::Parameter {
        index,
        ty,
        span: span(),
    })
}
fn object(fields: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Rc::new(Shape::Object {
        fields: fields.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        span: span(),
    })
}

#[test]
fn action_subject_symbolic_keys_select_exact_member_after_substitution() {
    let subject = shape::select(
        parameter(0, IrType::Map(Box::new(IrType::Ref("Ticket".into())))),
        parameter(1, IrType::Primitive(IrPrimitiveType::String)),
        span(),
    );
    let values = object([("a/~", fact()), ("copy", shape::data(span(), "copied"))]);
    assert_eq!(
        shape::substitute(&subject, &[values.clone(), shape::string("a/~", span())]),
        fact()
    );
    assert!(matches!(
        shape::substitute(&subject, &[values.clone(), shape::string("copy", span())]).as_ref(),
        Shape::Data { .. }
    ));
    let unresolved = shape::substitute(&subject, &[values, shape::data(span(), "computed key")]);
    assert!(matches!(unresolved.as_ref(),Shape::Alternatives(items) if items.len()==3));
    let narrowed = shape::narrow(unresolved, "Some", span());
    assert!(matches!(narrowed.as_ref(),Shape::Alternatives(items) if items.len()==2));
}

#[test]
fn action_subject_optional_container_narrowing_does_not_narrow_its_field() {
    let container = parameter(0, IrType::Optional(Box::new(IrType::Ref("Box".into()))));
    let selected = shape::select(
        shape::narrow(container, "Some", span()),
        shape::string("ticket", span()),
        span(),
    );
    let actual = object([("ticket", shape::absent(span()))]);
    assert_eq!(
        shape::substitute(&selected, &[actual]),
        shape::absent(span())
    );
    let actual = shape::substitute(&selected, &[shape::absent(span())]);
    assert!(matches!(actual.as_ref(), Shape::Never));
    let ordinary = shape::narrow(
        shape::select(
            shape::data(span(), "payload"),
            shape::string("ticket", span()),
            span(),
        ),
        "Some",
        span(),
    );
    assert!(
        matches!(ordinary.as_ref(), Shape::Data { .. }),
        "data cannot become an impossible branch and discharge a requirement"
    );
}

#[test]
fn action_subject_selected_parameter_contract_is_discharged_at_outer_caller() {
    let prefix = format!("{HEADER}action unbox(b Box) -> null {{ identity(b.ticket) as selected\ndone selected\nreturn null }}\naction relay(b Box) -> null {{ unbox(b)\nreturn null }}\n");
    let good = format!(
        "{prefix}rule run when Ticket as ticket => {{ boxed(ticket) as bundle\nrelay(bundle) }}"
    );
    accepted(&good);
    let copied = good.replace("boxed(ticket)", "boxed({ title ticket.title })");
    let error = rejected(&copied);
    assert_eq!(text(&copied, error.span), "bundle");
    assert!(error
        .related
        .iter()
        .any(|r| text(&copied, r.span).contains("done selected")));
    let actual_box = format!("{prefix}rule run when Box as bundle => {{ relay(bundle) }}");
    assert!(rejected(&actual_box)
        .message
        .contains("field of a matched fact"));
}

#[test]
fn action_subject_pure_results_cannot_recover_fact_identity() {
    let source = format!("{HEADER}action title(x Ticket) -> bool {{ return empty(x.title) }}\naction bad(x Ticket) -> null {{ title(x) as computed\ndone computed\nreturn null }}");
    assert!(rejected(&source).message.contains("computed value"));
    let source = format!("{HEADER}action values(x Ticket) -> Ticket[] {{ return [x] }}\naction bad(x Ticket) -> null {{ values(x) as collection\ndone collection\nreturn null }}");
    assert!(rejected(&source)
        .message
        .contains("constructing a collection"));
}

#[test]
fn action_subject_narrowing_only_removes_provably_incompatible_values() {
    let choices = shape::alternatives([
        fact(),
        Rc::new(Shape::Fact {
            schema: "Other".into(),
            span: span(),
        }),
        shape::absent(span()),
    ]);
    assert_eq!(shape::narrow(choices, "Ticket", span()), fact());
    let subject = shape::narrow(parameter(0, IrType::Ref("Ticket".into())), "Ticket", span());
    let copy = object([("title", shape::string("same", span()))]);
    assert_eq!(
        shape::substitute(&subject, std::slice::from_ref(&copy)),
        copy
    );
    let alternatives = shape::alternatives([fact(), shape::data(span(), "copy")]);
    assert_eq!(
        shape::narrow(alternatives.clone(), "_", span()),
        alternatives
    );
    assert!(matches!(
        shape::select(
            Rc::new(Shape::Array {
                items: vec![fact()],
                span: span()
            }),
            shape::string("0", span()),
            span()
        )
        .as_ref(),
        Shape::Unknown { .. }
    ));
}
