//! Generation of Maude model searches from the IR, and running the generated fixtures.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
#[test]
fn generates_model_searches_for_effect_dependencies() {
    let source = include_str!("../../../../../examples/queue-worker-with-review.whip");
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("example compiles");
    let (_maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert_eq!(expected.len(), 15);
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.outcome == ExpectedSearchResult::Solution)
            .count(),
        5
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "succeeds")
            .count(),
        9
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "fails")
            .count(),
        3
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "revision-active-rule")
            .count(),
        1
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "revision-stale-rule")
            .count(),
        1
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "revision-effect-attribution")
            .count(),
        1
    );
}

#[test]
fn generates_revision_model_searches_for_effects_and_completes_dependencies() {
    let source = revision_generated_checks_source();
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert!(maude.contains("scopedRuleV("));
    assert!(maude.contains("activeRevision("));
    assert!(maude.contains("effectVersion("));
    assert!(maude.contains("revisionCancellationPolicy("));
    assert!(expected.iter().any(|result| {
        result.predicate == "revision-active-rule"
            && result.outcome == ExpectedSearchResult::Solution
    }));
    assert!(expected.iter().any(|result| {
        result.predicate == "revision-stale-rule"
            && result.outcome == ExpectedSearchResult::NoSolution
    }));
    assert!(expected.iter().any(|result| {
        result.predicate == "revision-effect-attribution"
            && result.outcome == ExpectedSearchResult::NoSolution
    }));
    assert!(expected.iter().any(|result| {
        result.predicate == "revision-completes-cancelled"
            && result.outcome == ExpectedSearchResult::Solution
    }));
}

#[test]
fn generated_ne_false_case_compares_left_and_right_operands() {
    let left = Expr::Literal(ExprLiteral::String("left".to_owned()));
    let right = Expr::Literal(ExprLiteral::String("right".to_owned()));
    let left_key = left.to_snapshot();
    let right_key = right.to_snapshot();
    let expr = Expr::Binary {
        op: BinaryOp::Ne,
        left: Box::new(left),
        right: Box::new(right),
    };
    let mut context = MaudeExprContext::default();

    let cases = maude_bool_cases(&expr, &mut context);

    let left_symbol = context
        .scalar_symbols
        .get(&left_key)
        .expect("left symbol exists");
    let right_symbol = context
        .scalar_symbols
        .get(&right_key)
        .expect("right symbol exists");
    assert_ne!(left_symbol, right_symbol);
    assert_eq!(
        cases.false_expr,
        format!("neExpr(scalar({left_symbol}), scalar({right_symbol}))")
    );
}

#[test]
fn generates_model_searches_for_guards_and_assertions() {
    let source = r#"
workflow GeneratedChecks

class Task {
  priority int
  status string
  labels string[]
  metadata map<string>
}

class Result {
  status string
  metadata map<string>
}

assert count(Result) == 0
assert count(Result) == 0
assert count(Result where status == "accepted") >= 0
assert count(Result where status not in ["accepted", "queued"]) == 0
assert "urgent" in ["urgent", "later"]

rule accept
  when Task as task where task.status == "queued" && task.priority >= 1 && "urgent" in task.labels && task.metadata["phase"] == "kernel" && count(Result where metadata["phase"] == "done") == 0
=> {
  record Result {
    status "accepted"
    metadata { phase task.metadata["phase"] }
  }
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert_eq!(expected.len(), 19);
    assert!(maude.contains("guardExpr("));
    assert!(maude.contains("assertionExpr("));
    assert!(maude.contains("andExpr("));
    assert!(maude.contains("eqExpr("));
    assert!(maude.contains("geExpr("));
    assert!(maude.contains("inExpr("));
    assert!(maude.contains("indexExpr("));
    assert!(maude.contains("arrayHas("));
    assert!(maude.contains("mapHas("));
    assert!(maude.contains("queryFilter("));
    assert!(maude.contains("countExpr(query("));
    assert!(expected.iter().any(|result| {
        result.description == "accept true guard commits rule"
            && result.outcome == ExpectedSearchResult::Solution
    }));
    assert!(expected.iter().any(|result| {
        result.description == "accept false guard cannot commit rule"
            && result.outcome == ExpectedSearchResult::NoSolution
    }));
    assert!(expected.iter().any(|result| {
        result.description == "accept guard error emits diagnostic"
            && result.outcome == ExpectedSearchResult::Solution
    }));
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "assertion-read-only"
                && result.outcome == ExpectedSearchResult::NoSolution)
            .count(),
        15
    );
}

#[test]
fn generates_model_searches_for_terminal_branches() {
    let source = include_str!("../../../../../examples/terminal-output-union.whip");
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("example compiles");
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert!(maude.contains("terminalBranch("));
    assert!(maude.contains("exhaustiveTerminal("));
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "terminal-branch-match")
            .count(),
        4
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "terminal-branch-miss")
            .count(),
        4
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "terminal-exhaustive-miss")
            .count(),
        4
    );
}

#[test]
fn generates_model_searches_for_guarded_terminal_branch_misses() {
    let source = include_str!("../../../../../examples/terminal-output-union.whip");
    let compiled = whipplescript_parser::compile_program(source);
    let mut ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let branch = ir.rules[0]
        .metadata
        .terminal_branches
        .first_mut()
        .expect("terminal branch");
    branch.guard = Some(whipplescript_parser::IrExpression {
        source: "true".to_owned(),
        expr: parse_expression("true").expect("guard parses"),
        span: branch.pattern_span,
    });
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert!(maude.contains("terminalBranchGuard("));
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "terminal-branch-guard-false")
            .count(),
        1
    );
}

#[test]
fn generated_model_search_detects_unsafe_dependency_release_fixture() {
    if find_executable_in_path(&["maude"], &path_value()).is_none() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_path =
        fs::canonicalize(root.join("models/maude/kernel.maude")).expect("kernel path resolves");
    let source = include_str!("../../../../../examples/queue-worker-with-review.whip");
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("example compiles");
    let (maude, expected) = generate_maude_model_search(source, &ir, &kernel_path);
    assert!(!expected.is_empty());

    let module_end = maude
        .find("endm\n\n")
        .expect("generated module has an end marker");
    let unsafe_rule = concat!(
        "  vars U D : EffectId .\n",
        "  rl [unsafe-generated-fixture-release] :\n",
        "    effect(U, queued) dep(U, succeeds, D) effect(D, blocked)\n",
        "    => effect(U, queued) dep(U, succeeds, D) effect(D, queued) .\n",
    );
    let unsafe_maude = format!(
        "{}{}{}",
        &maude[..module_end],
        unsafe_rule,
        &maude[module_end..]
    );

    let output = run_maude_source("unsafe-generated-check-fixture", &unsafe_maude)
        .expect("unsafe generated Maude fixture runs");
    let actual = extract_maude_search_results(&output.stdout);
    assert_eq!(actual.len(), expected.len(), "{}", output.stdout);
    assert!(
        expected
            .iter()
            .zip(actual.iter())
            .any(|(expected, actual)| {
                expected.description.contains("cannot run before")
                    && expected.outcome == ExpectedSearchResult::NoSolution
                    && *actual == ExpectedSearchResult::Solution
            }),
        "unsafe fixture did not produce a generated-check counterexample\n{}",
        output.stdout
    );
}

#[test]
fn generated_model_search_runs_lowered_expression_fixture() {
    if find_executable_in_path(&["maude"], &path_value()).is_none() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_path =
        fs::canonicalize(root.join("models/maude/kernel.maude")).expect("kernel path resolves");
    let source = r#"
workflow GeneratedExpressionChecks

class Task {
  status string
}

class Result {
  status string
}

assert count(Result) == 0
assert count(Result) == 0

rule accept
  when Task as task where task.status == "queued" && count(Result) == 0
=> {
  record Result {
    status "accepted"
  }
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let (maude, expected) = generate_maude_model_search(source, &ir, &kernel_path);
    assert!(!expected.is_empty());

    let output = run_maude_source("generated-expression-check-fixture", &maude)
        .expect("generated expression Maude fixture runs");
    let actual = extract_maude_search_results(&output.stdout);
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|expected| expected.outcome)
            .collect::<Vec<_>>(),
        "{}",
        output.stdout
    );
}

#[test]
fn generated_model_search_runs_revision_fixture() {
    if find_executable_in_path(&["maude"], &path_value()).is_none() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_path =
        fs::canonicalize(root.join("models/maude/kernel.maude")).expect("kernel path resolves");
    let source = revision_generated_checks_source();
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) = generate_maude_model_search(source, &ir, &kernel_path);
    assert!(expected.iter().any(|result| {
        result.predicate == "revision-completes-cancelled"
            && result.outcome == ExpectedSearchResult::Solution
    }));

    let output = run_maude_source("generated-revision-check-fixture", &maude).expect("runs Maude");
    let actual = extract_maude_search_results(&output.stdout);
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|expected| expected.outcome)
            .collect::<Vec<_>>(),
        "{}",
        output.stdout
    );
}

#[test]
fn generates_composition_model_searches_from_ir() {
    let source = composition_invoke_source();
    let compiled =
        whipplescript_parser::compile_program_with_root(source, Some("CompositionModelCheck"));
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    // Workflow completion + failure kernel rules are driven by the declared
    // output/failure contracts.
    assert!(maude.contains("completeWorkflow("));
    assert!(maude.contains("event(workflowCompletedEvt)"));
    assert!(maude.contains("failWorkflow("));
    assert!(maude.contains("event(workflowFailedEvt)"));
    // Workflow invocation kernel rules are driven by the `workflow.invoke`
    // effect.
    assert!(maude.contains("invokeWorkflow("));
    assert!(maude.contains("invocationOutput("));
    assert!(maude.contains("invocationFailure("));

    for predicate in [
        "workflow-complete",
        "workflow-fail",
        "invoke-starts-child",
        "invoke-completes",
        "invoke-fails",
    ] {
        assert!(
            expected.iter().any(|search| {
                search.predicate == predicate && search.outcome == ExpectedSearchResult::Solution
            }),
            "missing solution search for {predicate}"
        );
    }
    for predicate in [
        "workflow-complete-requires-action",
        "workflow-fail-requires-action",
        "invoke-blocks-until-terminal",
    ] {
        assert!(
            expected.iter().any(|search| {
                search.predicate == predicate && search.outcome == ExpectedSearchResult::NoSolution
            }),
            "missing no-solution search for {predicate}"
        );
    }
}

#[test]
fn generates_pattern_elaboration_model_searches_from_ir() {
    let source = composition_pattern_source();
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert!(maude.contains("patternApp("));
    assert!(maude.contains("ruleProvenance("));
    assert!(expected.iter().any(|search| {
        search.predicate == "pattern-elaborates" && search.outcome == ExpectedSearchResult::Solution
    }));
    assert!(expected.iter().any(|search| {
        search.predicate == "pattern-provenance-requires-elaboration"
            && search.outcome == ExpectedSearchResult::NoSolution
    }));
}

#[test]
fn generated_composition_model_search_runs_clean_in_maude() {
    if find_executable_in_path(&["maude"], &path_value()).is_none() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_path =
        fs::canonicalize(root.join("models/maude/kernel.maude")).expect("kernel path resolves");
    let source = composition_invoke_source();
    let compiled =
        whipplescript_parser::compile_program_with_root(source, Some("CompositionModelCheck"));
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) = generate_maude_model_search(source, &ir, &kernel_path);
    assert!(!expected.is_empty());

    let output = run_maude_source("generated-composition-check-fixture", &maude)
        .expect("generated composition Maude fixture runs");
    assert!(
        output.stderr.is_empty(),
        "generated composition Maude emitted warnings:\n{}",
        output.stderr
    );
    let actual = extract_maude_search_results(&output.stdout);
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|expected| expected.outcome)
            .collect::<Vec<_>>(),
        "{}",
        output.stdout
    );
}

#[test]
fn generated_pattern_model_search_runs_clean_in_maude() {
    if find_executable_in_path(&["maude"], &path_value()).is_none() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_path =
        fs::canonicalize(root.join("models/maude/kernel.maude")).expect("kernel path resolves");
    let source = composition_pattern_source();
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) = generate_maude_model_search(source, &ir, &kernel_path);
    assert!(!expected.is_empty());

    let output = run_maude_source("generated-pattern-check-fixture", &maude)
        .expect("generated pattern Maude fixture runs");
    assert!(
        output.stderr.is_empty(),
        "generated pattern Maude emitted warnings:\n{}",
        output.stderr
    );
    let actual = extract_maude_search_results(&output.stdout);
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|expected| expected.outcome)
            .collect::<Vec<_>>(),
        "{}",
        output.stdout
    );
}

#[test]
fn extracts_maude_search_results_in_order() {
    let output = concat!(
        "search 1\nNo solution.\n",
        "search 2\nSolution 1 (state 1)\n",
        "search 3\nNo solution.\n",
    );

    assert_eq!(
        extract_maude_search_results(output),
        vec![
            ExpectedSearchResult::NoSolution,
            ExpectedSearchResult::Solution,
            ExpectedSearchResult::NoSolution,
        ]
    );
}

#[test]
fn locates_dependency_source_span() {
    let source =
        "rule work {\n  after prepare succeeds {\n    agent.tell \"send\" as notify\n  }\n}\n";
    let span = dependency_source_span(source, "prepare", "succeeds");

    assert_eq!(&source[span.start..span.end], "after prepare succeeds");
}
