use whipplescript_parser::execution_semantics::compile_recorded_program_with_root;
use whipplescript_parser::{compile_program, ExecutionSemantics};

// Captured from 2af7c1d2 before adding recorded-semantics dispatch. Deliberately
// fixed bytes, not a comparison with whatever today's source default emits.
const SOURCE: &str = include_str!("fixtures/recorded-actions-v1.whip");
const SNAPSHOT: &str = include_str!("fixtures/recorded-actions-v1.ir");

#[test]
fn missing_and_explicit_legacy_tags_retain_recorded_action_identity() {
    for tag in [None, Some("dr0023-action-chains-v1")] {
        let semantics = ExecutionSemantics::from_recorded_tag(tag).unwrap();
        let output = compile_recorded_program_with_root(SOURCE, Some("RecordedActions"), semantics);
        assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
        let ir = output.ir.unwrap();
        assert_eq!(
            ir.execution_semantics,
            ExecutionSemantics::LegacyActionChainsV1
        );
        assert_eq!(ir.to_snapshot(), SNAPSHOT);
        let body = &ir.rules[0].body;
        assert!(body.contains("after turn__act0 succeeds"));
        assert!(body.contains("after turn__act1 succeeds"));
        assert!(body.contains("label \"first\""));
        assert!(body.contains("label \"second\""));
    }
}

#[test]
fn legacy_action_source_gets_an_immediate_typed_migration_diagnostic() {
    let output = compile_program(SOURCE);
    assert!(output.ir.is_none());
    assert!(
        output
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("needs a result contract")),
        "{:?}",
        output.diagnostics
    );
    assert!(
        output.diagnostics.iter().any(|diagnostic| diagnostic
            .suggestion
            .as_deref()
            .is_some_and(|suggestion| suggestion.contains("-> null"))),
        "{:?}",
        output.diagnostics
    );
}

#[test]
fn actionless_source_remains_on_the_legacy_machine() {
    let output = compile_program("workflow Plain\n");
    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    assert!(output.typed_actions.is_none());
    assert_eq!(
        output.ir.unwrap().execution_semantics,
        ExecutionSemantics::LegacyActionChainsV1
    );
}

#[test]
fn action_source_selects_typed_output_with_checked_plans_and_dispatch_identity() {
    let source = r#"workflow Typed
action label(value string) -> string { return value }
rule run when started => { label("ok") as answer }
"#;
    let output = compile_program(source);
    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    let plans = output.typed_actions.expect("typed plans");
    assert_eq!(
        plans.keys().map(String::as_str).collect::<Vec<_>>(),
        ["run"]
    );
    assert_eq!(plans["run"].plan.root_rule.as_ref().unwrap().name, "run");
    let ir = output.ir.unwrap();
    assert_eq!(ir.execution_semantics, ExecutionSemantics::TypedActionsV1);
    assert!(ir.to_snapshot().contains("dr0100-typed-actions-v1"));
    assert!(ir.rules[0].body.contains("label(\"ok\") as answer"));
    assert!(!ir.rules[0].body.contains("__act"));
    assert_eq!(
        ExecutionSemantics::from_recorded_tag(Some("dr0100-typed-actions-v1")).unwrap(),
        ExecutionSemantics::TypedActionsV1
    );
}

#[test]
fn unsupported_tags_never_select_the_source_default() {
    for tag in ["", "future-v99", "DR0023-action-chains-v1"] {
        let error = ExecutionSemantics::from_recorded_tag(Some(tag)).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("unsupported recorded execution semantics {tag:?}")
        );
    }
}

#[test]
fn recorded_compilation_retains_root_selection_and_whole_bundle_checks() {
    let semantics = ExecutionSemantics::LegacyActionChainsV1;
    let source = "@service workflow First { }\n@service workflow Second { }\n";
    let second = compile_recorded_program_with_root(source, Some("Second"), semantics);
    assert!(second.diagnostics.is_empty(), "{:?}", second.diagnostics);
    assert_eq!(second.ir.unwrap().workflow, "Second");
    let missing = compile_recorded_program_with_root(source, Some("Missing"), semantics);
    assert!(missing.ir.is_none());
    assert!(!missing.diagnostics.is_empty());
    let broken = "@service workflow First { }\n@service workflow Second {\nrule broken\n when started\n=> {\nrecord Missing { x 1 }\n}\n}\n";
    let output = compile_recorded_program_with_root(broken, Some("First"), semantics);
    assert!(output.ir.is_none());
    assert!(
        output
            .diagnostics
            .iter()
            .any(|d| d.message.contains("Missing")),
        "{:?}",
        output.diagnostics
    );
}

#[test]
fn recorded_legacy_path_does_not_silently_execute_typed_actions() {
    let source = "@service\nworkflow Typed\naction value() -> string {\nreturn \"ok\"\n}\n";
    let output =
        compile_recorded_program_with_root(source, None, ExecutionSemantics::LegacyActionChainsV1);
    assert!(output.ir.is_none());
    assert!(
        output
            .diagnostics
            .iter()
            .any(|d| d.message.contains("scope lowering is not implemented")),
        "{:?}",
        output.diagnostics
    );
}
