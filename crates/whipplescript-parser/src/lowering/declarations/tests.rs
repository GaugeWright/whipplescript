use super::*;
use crate::action_plan::analysis::analyze_composition;

fn parsed(source: &str) -> Program {
    let result = parse_program(source);
    assert!(
        result.diagnostics.is_empty(),
        "{source}: {:?}",
        result.diagnostics
    );
    result.program
}
fn declarations(source: &str) -> Result<DeclarationAnalysis, Vec<Diagnostic>> {
    let program = parsed(source);
    analyze(
        &program,
        &SemanticContext::from_program(&program, BTreeMap::new()),
    )
}

#[test]
fn shared_declarations_match_legacy_examples_without_lowering_their_bodies() {
    for source in [
        include_str!("../../../../../examples/minimal-noop.whip"),
        include_str!("../../../../../examples/file-store-demo.whip"),
        include_str!("../../../../../examples/memory-pool-demo.whip"),
        include_str!("../../../../../examples/gastown-lite.whip"),
        include_str!("../../../../../examples/ingress-http-source.whip"),
        include_str!("../../../../../examples/owned-harness-demo.whip"),
        include_str!("../../../../../examples/improve-triage.whip"),
        include_str!("../../../../../examples/clock-source.whip"),
    ] {
        let result = declarations(source).unwrap();
        let compiled = compile_program(source);
        let ir = compiled
            .ir
            .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
        result.assert_same_declarations(&ir);
        assert!(result.ir.rules.is_empty());
        assert!(!result.bodies().is_empty());
        for warning in result.warnings() {
            assert!(compiled.warnings.contains(warning), "{warning:?}");
        }
    }
}

#[test]
fn composition_keeps_authored_bodies_and_source_annotations_in_order() {
    let source = r#"@service
description "All declarations"
workflow Declared
class Ticket { title string }
@first
description "Initial rule"
rule first when started => {}
action helper() -> int { return 1 }
@seed
description "Seed rows"
table seed as Ticket [{ title "one" }]
@last
description "Final rule"
rule last when started => { helper() as value }
"#;
    let program = parsed(source);
    let analysis = analyze_composition(&program).unwrap();
    let result = analysis.declarations();
    assert_eq!(analysis.rules().len(), 3);
    let expected: Vec<_> = program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Rule(rule) => Some(PendingBody::Rule(rule.clone())),
            Item::Table(table) => Some(PendingBody::Table(table.clone())),
            Item::Action(action) => Some(PendingBody::Action(action.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(result.bodies(), expected);
    assert_eq!(
        result
            .source_tags()
            .iter()
            .map(|tag| (
                tag.target_kind.as_str(),
                tag.target.as_str(),
                tag.name.as_str()
            ))
            .collect::<Vec<_>>(),
        [
            ("workflow", "Declared", "service"),
            ("rule", "first", "first"),
            ("table", "seed", "seed"),
            ("rule", "last", "last")
        ]
    );
    assert_eq!(
        result
            .source_descriptions()
            .iter()
            .map(|description| description.value.as_str())
            .collect::<Vec<_>>(),
        [
            "All declarations",
            "Initial rule",
            "Seed rows",
            "Final rule"
        ]
    );
    assert!(
        result.ir.rules.is_empty(),
        "pending table is not a fabricated rule"
    );
    let legacy = source
        .replace("action helper() -> int { return 1 }\n", "")
        .replace("helper() as value", "");
    let lowered = compile_program(&legacy);
    let ir = lowered
        .ir
        .unwrap_or_else(|| panic!("{:?}", lowered.diagnostics));
    declarations(&legacy).unwrap().assert_same_declarations(&ir);
    assert_eq!(
        ir.rules.len(),
        3,
        "only complete lowering elaborates the table"
    );
}

#[test]
fn composition_refuses_invalid_declarations_through_the_compiler_owner() {
    for (declaration, code, message) in [
        (
            "file store files { root \".\" provider missing }",
            "construct.unknown_provider",
            "unknown provider",
        ),
        (
            "class Broken { value Missing }",
            "type.unknown_schema",
            "Missing",
        ),
        (
            "agent worker using absent { profile \"reader\" capacity 1 }",
            "type.unknown_harness",
            "absent",
        ),
        ("output result Missing", "type.unknown_schema", "Missing"),
        (
            "lease slot { key Missing slots 1 ttl 1m }",
            "type.unknown_schema",
            "Missing",
        ),
        (
            "ledger log { entry Missing partition by id retain 1d }",
            "type.unknown_schema",
            "Missing",
        ),
        (
            "counter quota { key Missing cap 1 reset daily }",
            "type.unknown_schema",
            "Missing",
        ),
        (
            "stream tasks { members [absent] }",
            "type.unknown_agent",
            "absent",
        ),
        (
            "region selected { select \"since(\" }",
            "parse.invalid_selection",
            "selection does not parse",
        ),
    ] {
        let source = format!("@service\nworkflow Invalid\n{declaration}\naction value() -> int {{ return 1 }}\nrule run when started => {{ value() as result }}");
        let errors = analyze_composition(&parsed(&source)).expect_err(&source);
        assert!(
            errors
                .iter()
                .any(|error| error.code.as_str() == code && error.message.contains(message)),
            "{source}: {errors:?}"
        );
        assert_eq!(compile_program(&source).diagnostics, errors);
    }
}

#[test]
fn declaration_conflicts_keep_both_authored_locations() {
    for declaration in [
        "class Ticket { title string }",
        "harness worker: codex",
        "agent worker { provider fixture profile \"reader\" capacity 1 }",
    ] {
        let source = format!("workflow Duplicate\n{declaration}\n{declaration}");
        let errors = analyze_composition(&parsed(&source)).unwrap_err();
        let duplicate = errors
            .iter()
            .find(|error| error.code.as_str() == "construct.duplicate_declaration")
            .unwrap();
        assert_eq!(duplicate.related.len(), 1, "{errors:?}");
        assert!(duplicate.related[0].span.start < duplicate.span.start);
        assert_eq!(
            &source[duplicate.related[0].span.start..duplicate.related[0].span.end],
            &source[duplicate.span.start..duplicate.span.end]
        );
    }
    let source = "workflow Duplicate\nagent worker { provider fixture profile \"reader\" capacity 1 }\nstream first { members [worker] }\nstream second { members [worker] }";
    let errors = analyze_composition(&parsed(source)).unwrap_err();
    assert_eq!(errors[0].code.as_str(), "construct.cardinality_conflict");
    assert_eq!(errors[0].related.len(), 1);
    assert!(errors[0].related[0].span.start < errors[0].span.start);
}

#[test]
fn declaration_analysis_requires_selected_root_and_keeps_earlier_errors_primary() {
    for (source, code) in [
        (
            "class Ticket { title string }",
            "construct.missing_workflow",
        ),
        ("workflow One {}", "construct.invalid_declaration_scope"),
        (
            "workflow One {}\nworkflow Two {}",
            "construct.ambiguous_root_workflow",
        ),
    ] {
        let errors = declarations(source).expect_err(source);
        assert!(
            errors.iter().any(|error| error.code.as_str() == code),
            "{source}: {errors:?}"
        );
    }
    let source = "workflow Selected\nclass Ticket { title string }\naction bad() -> int { return true }\nfile store broken { root \".\" provider missing }";
    let errors = analyze_composition(&parsed(source)).unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].code.as_str(), "type.mismatch");
    assert_eq!(&source[errors[0].span.start..errors[0].span.end], "true");
}

#[test]
fn declarations_expand_observation_copies_and_retain_warnings() {
    let source = r#"@service
workflow Observe
use std.ingress
class Ticket { title string }
counter quota { key Ticket cap 1 reset daily }
source file as feed {
  path "./inbox.txt"
  observe as obs
  emit ingress.fed from obs {}
}
signal ingress.fed { line string }
action value() -> int { return 1 }
rule run when started => { value() as result }
"#;
    let analysis = analyze_composition(&parsed(source)).unwrap();
    let result = analysis.declarations();
    assert_eq!(result.sources().len(), 1);
    let fields = &result.sources()[0].emit_fields;
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].name, "line");
    let SourceValue::Path {
        binding, segments, ..
    } = &fields[0].value
    else {
        panic!("{:?}", fields[0]);
    };
    assert_eq!(binding.name, "obs");
    assert_eq!(segments[0].name, "line");
    assert_eq!(result.warnings().len(), 1);
    assert!(result.warnings()[0].message.contains("timezone"));
    for (bad, needle) in [
        (
            source.replace("from obs", "from other"),
            "only binding in scope",
        ),
        (
            source.replace("signal ingress.fed { line string }", ""),
            "ingress.fed",
        ),
    ] {
        let errors = analyze_composition(&parsed(&bad)).unwrap_err();
        assert!(
            errors.iter().any(|error| error.message.contains(needle)),
            "{errors:?}"
        );
        assert_eq!(compile_program(&bad).diagnostics, errors);
    }
}

#[test]
fn declaration_analysis_refuses_unprepared_scopes_without_silently_selecting() {
    let mut program = parsed("workflow Header");
    program.workflows = parsed("workflow Nested {}").workflows;
    let errors = analyze_composition(&program).unwrap_err();
    assert_eq!(
        errors[0].code.as_str(),
        "construct.invalid_declaration_scope"
    );

    let mut program = parsed("workflow Header\npattern P<T> {}");
    let pattern = program.patterns.remove(0);
    let span = pattern.span;
    program.items.push(Item::Pattern(pattern));
    let errors = analyze_composition(&program).unwrap_err();
    assert_eq!(
        errors[0].code.as_str(),
        "construct.invalid_declaration_scope"
    );
    assert_eq!(errors[0].span, span);

    let program = parsed("workflow Header\napply P<Ticket> as seed {}");
    let errors = analyze_composition(&program).unwrap_err();
    assert_eq!(
        errors[0].code.as_str(),
        "lowering.unexpanded_pattern_application"
    );
    assert!(errors[0].message.contains("seed"));

    let selected = select_root_workflow(parsed("workflow Selected {}"), None).unwrap();
    assert_eq!(
        analyze_composition(&selected)
            .unwrap()
            .declarations()
            .workflow(),
        "Selected"
    );
}
