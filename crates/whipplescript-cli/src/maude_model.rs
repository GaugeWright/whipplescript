//! Generation of Maude model-search programs from the lowered IR, plus the Maude runner and result extraction.
//!
//! Moved verbatim out of `main.rs`; `use super::*` keeps the imports and
//! sibling helpers it already resolved against in scope.

use super::*;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MaudeRunOutput {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

pub(crate) fn run_maude_source(label: &str, source: &str) -> Result<MaudeRunOutput, String> {
    let model_path = temp_scratch_path("whipplescript-model-search", label, "maude");
    fs::write(&model_path, source)
        .map_err(|error| format!("failed to write generated Maude file: {error}"))?;
    let maude = match find_executable_in_path(&["maude"], &path_value()) {
        Some(maude) => maude,
        None => {
            let _ = fs::remove_file(&model_path);
            return Err("Maude executable `maude` was not found on PATH".to_owned());
        }
    };
    let output = Command::new(&maude)
        .arg(&model_path)
        .output()
        .map_err(|error| format!("failed to run `{maude}`: {error}"))?;
    let _ = fs::remove_file(&model_path);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(format!(
            "Maude exited with status {:?}\n{}{}",
            output.status.code(),
            stdout,
            stderr
        ));
    }
    Ok(MaudeRunOutput { stdout, stderr })
}

#[derive(Clone, Debug)]
pub(crate) struct MaudeBoolCases {
    pub(crate) true_expr: String,
    pub(crate) false_expr: String,
    pub(crate) error_expr: String,
}

#[derive(Default)]
pub(crate) struct MaudeExprContext {
    pub(crate) scalar_symbols: std::collections::BTreeMap<String, String>,
    pub(crate) query_symbols: std::collections::BTreeMap<String, String>,
}

pub(crate) fn generate_maude_model_search(
    source: &str,
    ir: &IrProgram,
    kernel_path: &Path,
) -> (String, Vec<ExpectedSearch>) {
    let mut effect_symbols = std::collections::BTreeMap::<String, String>::new();
    let mut rule_symbols = std::collections::BTreeMap::<String, String>::new();
    let mut fact_symbols = std::collections::BTreeMap::<String, String>::new();
    let mut graph_symbols = std::collections::BTreeMap::<String, String>::new();
    let mut assertion_symbols = std::collections::BTreeMap::<usize, String>::new();
    // Composition symbols (workflow/pattern/invoke kernel rules). These are
    // synthesized concrete ops for otherwise-abstract kernel sorts so the
    // generated module can search the elaborate-pattern, complete/fail-workflow
    // and workflow-invocation rules against real compiled IR.
    let mut pattern_symbols = std::collections::BTreeMap::<String, String>::new();
    let mut application_symbols = std::collections::BTreeMap::<String, String>::new();
    let mut workflow_symbols = std::collections::BTreeMap::<String, String>::new();
    let mut instance_symbols = std::collections::BTreeMap::<String, String>::new();
    let mut output_symbols = std::collections::BTreeMap::<String, String>::new();
    let mut failure_symbols = std::collections::BTreeMap::<String, String>::new();
    let mut expr_context = MaudeExprContext::default();
    for rule in &ir.rules {
        rule_symbols
            .entry(rule.name.clone())
            .or_insert_with(|| maude_symbol("rule", &rule.name));
        for when in &rule.whens {
            if let Some(guard) = &when.guard {
                let _ = maude_bool_cases(&guard.expr, &mut expr_context);
            }
        }
        for (when_index, when) in rule.whens.iter().enumerate() {
            let fact_key = rule_fact_key(&rule.name, when_index, &when.pattern);
            fact_symbols
                .entry(fact_key.clone())
                .or_insert_with(|| maude_symbol("fact", &fact_key));
            let graph_key = rule_graph_key(&rule.name, when_index);
            graph_symbols
                .entry(graph_key.clone())
                .or_insert_with(|| maude_symbol("graph", &graph_key));
        }
        for branch in &rule.metadata.terminal_branches {
            let graph_key = terminal_branch_graph_key(&rule.name, branch);
            graph_symbols
                .entry(graph_key.clone())
                .or_insert_with(|| maude_symbol("graph", &graph_key));
            if let Some(guard) = &branch.guard {
                let _ = maude_bool_cases(&guard.expr, &mut expr_context);
            }
        }
        for effect in &rule.metadata.effects {
            let key = effect_key(&rule.name, &effect.id);
            effect_symbols
                .entry(key.clone())
                .or_insert_with(|| maude_symbol("eff", &key));
        }
    }
    for (index, assertion) in ir.assertions.iter().enumerate() {
        assertion_symbols
            .entry(index)
            .or_insert_with(|| maude_symbol("assertion", &assertion_key(index, assertion)));
        let _ = maude_bool_cases(&assertion.expr.expr, &mut expr_context);
    }
    collect_composition_symbols(
        ir,
        &mut rule_symbols,
        &mut fact_symbols,
        &mut graph_symbols,
        &mut pattern_symbols,
        &mut application_symbols,
        &mut workflow_symbols,
        &mut instance_symbols,
        &mut output_symbols,
        &mut failure_symbols,
    );

    let mut output = String::new();
    let mut expected = Vec::new();
    output.push_str(&format!("load {}\n\n", kernel_path.display()));
    output.push_str("mod WHIPPLESCRIPT-GENERATED-CHECK is\n");
    output.push_str("  including WHIPPLESCRIPT-KERNEL .\n");
    append_maude_ops(&mut output, effect_symbols.values(), "EffectId");
    append_maude_ops(&mut output, rule_symbols.values(), "RuleId");
    append_maude_ops(&mut output, fact_symbols.values(), "FactId");
    append_maude_ops(&mut output, graph_symbols.values(), "GraphId");
    append_maude_ops(&mut output, assertion_symbols.values(), "AssertionId");
    append_maude_ops(&mut output, expr_context.scalar_symbols.values(), "Scalar");
    append_maude_ops(&mut output, expr_context.query_symbols.values(), "QueryId");
    append_maude_ops(&mut output, pattern_symbols.values(), "PatternId");
    append_maude_ops(&mut output, application_symbols.values(), "ApplicationId");
    append_maude_ops(&mut output, workflow_symbols.values(), "WorkflowId");
    append_maude_ops(&mut output, instance_symbols.values(), "InstanceId");
    append_maude_ops(&mut output, output_symbols.values(), "OutputId");
    append_maude_ops(&mut output, failure_symbols.values(), "FailureId");
    output.push_str("endm\n\n");

    for rule in &ir.rules {
        for (when_index, when) in rule.whens.iter().enumerate() {
            let Some(guard) = &when.guard else {
                continue;
            };
            let Some(rule_symbol) = rule_symbols.get(&rule.name) else {
                continue;
            };
            let fact_key = rule_fact_key(&rule.name, when_index, &when.pattern);
            let Some(fact_symbol) = fact_symbols.get(&fact_key) else {
                continue;
            };
            let graph_key = rule_graph_key(&rule.name, when_index);
            let Some(graph_symbol) = graph_symbols.get(&graph_key) else {
                continue;
            };
            let cases = maude_bool_cases(&guard.expr, &mut expr_context);
            output.push_str(&format!(
                "--- {}: lowered true guard permits rule commit for `{}`.\n",
                rule.name, guard.source
            ));
            output.push_str(&format!(
                "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  fact({fact_symbol}) rule({rule_symbol}, {fact_symbol}, {graph_symbol}) guardExpr({rule_symbol}, {fact_symbol}, {})\n  =>*\n  fact({fact_symbol}) rule({rule_symbol}, {fact_symbol}, {graph_symbol}) ruleFired({rule_symbol}, {fact_symbol}, {graph_symbol}) graphReady({graph_symbol}) event(ruleCommitEvt) .\n\n",
                cases.true_expr
            ));
            expected.push(ExpectedSearch {
                outcome: ExpectedSearchResult::Solution,
                span: guard.span,
                description: format!("{} true guard commits rule", rule.name),
                upstream: rule.name.clone(),
                predicate: "guard-true",
                downstream: "ruleCommitEvt".to_owned(),
            });

            output.push_str(&format!(
                "--- {}: lowered false guard cannot commit rule for `{}`.\n",
                rule.name, guard.source
            ));
            output.push_str(&format!(
                "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  fact({fact_symbol}) rule({rule_symbol}, {fact_symbol}, {graph_symbol}) guardExpr({rule_symbol}, {fact_symbol}, {})\n  =>*\n  event(ruleCommitEvt) RESIDUAL:Cfg .\n\n",
                cases.false_expr
            ));
            expected.push(ExpectedSearch {
                outcome: ExpectedSearchResult::NoSolution,
                span: guard.span,
                description: format!("{} false guard cannot commit rule", rule.name),
                upstream: rule.name.clone(),
                predicate: "guard-false",
                downstream: "ruleCommitEvt".to_owned(),
            });

            output.push_str(&format!(
                "--- {}: lowered guard error emits a diagnostic and cannot commit rule for `{}`.\n",
                rule.name, guard.source
            ));
            output.push_str(&format!(
                "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  fact({fact_symbol}) rule({rule_symbol}, {fact_symbol}, {graph_symbol}) guardExpr({rule_symbol}, {fact_symbol}, {})\n  =>*\n  fact({fact_symbol}) rule({rule_symbol}, {fact_symbol}, {graph_symbol}) diagnostic({rule_symbol}) .\n\n",
                cases.error_expr
            ));
            expected.push(ExpectedSearch {
                outcome: ExpectedSearchResult::Solution,
                span: guard.span,
                description: format!("{} guard error emits diagnostic", rule.name),
                upstream: rule.name.clone(),
                predicate: "guard-error",
                downstream: "diagnostic".to_owned(),
            });

            output.push_str(&format!(
                "--- {}: guard error cannot commit rule for `{}`.\n",
                rule.name, guard.source
            ));
            output.push_str(&format!(
                "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  fact({fact_symbol}) rule({rule_symbol}, {fact_symbol}, {graph_symbol}) guardExpr({rule_symbol}, {fact_symbol}, {})\n  =>*\n  event(ruleCommitEvt) RESIDUAL:Cfg .\n\n",
                cases.error_expr
            ));
            expected.push(ExpectedSearch {
                outcome: ExpectedSearchResult::NoSolution,
                span: guard.span,
                description: format!("{} guard error cannot commit rule", rule.name),
                upstream: rule.name.clone(),
                predicate: "guard-error",
                downstream: "ruleCommitEvt".to_owned(),
            });
        }

        for dependency in &rule.metadata.dependencies {
            let upstream_key = effect_key(&rule.name, &dependency.upstream);
            let downstream_key = effect_key(&rule.name, &dependency.downstream);
            let Some(upstream) = effect_symbols.get(&upstream_key) else {
                continue;
            };
            let Some(downstream) = effect_symbols.get(&downstream_key) else {
                continue;
            };
            let predicate = maude_predicate(&dependency.predicate);
            let terminal = satisfying_terminal(&dependency.predicate);
            let span = dependency_source_span(source, &dependency.upstream, predicate);
            output.push_str(&format!(
                "--- {}: {} --{}--> {} cannot run before upstream terminal.\n",
                rule.name, dependency.upstream, predicate, dependency.downstream
            ));
            output.push_str(&format!(
                "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  effect({upstream}, queued) dep({upstream}, {predicate}, {downstream}) effect({downstream}, blocked)\n  =>*\n  effect({upstream}, queued) dep({upstream}, {predicate}, {downstream}) effect({downstream}, running) .\n\n"
            ));
            expected.push(ExpectedSearch {
                outcome: ExpectedSearchResult::NoSolution,
                span,
                description: format!(
                    "{} --{}--> {} cannot run before upstream terminal",
                    dependency.upstream, predicate, dependency.downstream
                ),
                upstream: dependency.upstream.clone(),
                predicate,
                downstream: dependency.downstream.clone(),
            });

            output.push_str(&format!(
                "--- {}: satisfying terminal releases downstream.\n",
                rule.name
            ));
            output.push_str(&format!(
                "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  effect({upstream}, {terminal}) dep({upstream}, {predicate}, {downstream}) effect({downstream}, blocked)\n  =>*\n  effect({upstream}, {terminal}) dep({upstream}, {predicate}, {downstream}) effect({downstream}, running) .\n\n"
            ));
            expected.push(ExpectedSearch {
                outcome: ExpectedSearchResult::Solution,
                span,
                description: format!(
                    "{} --{}--> {} releases after satisfying terminal",
                    dependency.upstream, predicate, dependency.downstream
                ),
                upstream: dependency.upstream.clone(),
                predicate,
                downstream: dependency.downstream.clone(),
            });

            if let Some(non_terminal) = non_satisfying_terminal(&dependency.predicate) {
                output.push_str(&format!(
                    "--- {}: non-satisfying terminal does not release downstream.\n",
                    rule.name
                ));
                output.push_str(&format!(
                    "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  effect({upstream}, {non_terminal}) dep({upstream}, {predicate}, {downstream}) effect({downstream}, blocked)\n  =>*\n  effect({upstream}, {non_terminal}) dep({upstream}, {predicate}, {downstream}) effect({downstream}, running) .\n\n"
                ));
                expected.push(ExpectedSearch {
                    outcome: ExpectedSearchResult::NoSolution,
                    span,
                    description: format!(
                        "{} --{}--> {} does not release after non-satisfying terminal",
                        dependency.upstream, predicate, dependency.downstream
                    ),
                    upstream: dependency.upstream.clone(),
                    predicate,
                    downstream: dependency.downstream.clone(),
                });
            }
        }
        append_revision_model_searches(
            source,
            &mut output,
            &mut expected,
            rule,
            &rule_symbols,
            &fact_symbols,
            &graph_symbols,
            &effect_symbols,
        );
        for branch in &rule.metadata.terminal_branches {
            let Some(tag) = branch.tag.as_deref() else {
                continue;
            };
            let Some(rule_symbol) = rule_symbols.get(&rule.name) else {
                continue;
            };
            let Some(first_when) = rule.whens.first() else {
                continue;
            };
            let first_fact_key = rule_fact_key(&rule.name, 0, &first_when.pattern);
            let Some(fact_symbol) = fact_symbols.get(&first_fact_key) else {
                continue;
            };
            let graph_key = terminal_branch_graph_key(&rule.name, branch);
            let Some(graph_symbol) = graph_symbols.get(&graph_key) else {
                continue;
            };
            let tag_symbol = maude_terminal_tag(tag);
            let miss_tag_symbol = maude_terminal_miss_tag(tag);
            let guard_cases = branch
                .guard
                .as_ref()
                .map(|guard| maude_bool_cases(&guard.expr, &mut expr_context));
            let matching_gate = if let Some(cases) = &guard_cases {
                format!(
                    "terminalBranchGuard({rule_symbol}, {fact_symbol}, {tag_symbol}, {tag_symbol}, {}, {graph_symbol})",
                    cases.true_expr
                )
            } else {
                format!(
                    "terminalBranch({rule_symbol}, {fact_symbol}, {tag_symbol}, {tag_symbol}, {graph_symbol})"
                )
            };
            output.push_str(&format!(
                "--- {}: terminal branch `{tag}` commits only for matching terminal tag.\n",
                rule.name
            ));
            output.push_str(&format!(
                "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  fact({fact_symbol}) rule({rule_symbol}, {fact_symbol}, {graph_symbol}) {matching_gate} graph({graph_symbol}, tellEff)\n  =>*\n  fact({fact_symbol}) rule({rule_symbol}, {fact_symbol}, {graph_symbol}) ruleFired({rule_symbol}, {fact_symbol}, {graph_symbol}) event(ruleCommitEvt) graphCommitted({graph_symbol}) effect(tellEff, queued) .\n\n"
            ));
            expected.push(ExpectedSearch {
                outcome: ExpectedSearchResult::Solution,
                span: branch.pattern_span,
                description: format!(
                    "{} terminal {tag} branch commits on matching tag",
                    rule.name
                ),
                upstream: rule.name.clone(),
                predicate: "terminal-branch-match",
                downstream: "ruleCommitEvt".to_owned(),
            });

            let miss_gate = if let Some(cases) = &guard_cases {
                format!(
                    "terminalBranchGuard({rule_symbol}, {fact_symbol}, {miss_tag_symbol}, {tag_symbol}, {}, {graph_symbol})",
                    cases.true_expr
                )
            } else {
                format!(
                    "terminalBranch({rule_symbol}, {fact_symbol}, {miss_tag_symbol}, {tag_symbol}, {graph_symbol})"
                )
            };
            output.push_str(&format!(
                "--- {}: terminal branch `{tag}` cannot commit for another terminal tag.\n",
                rule.name
            ));
            output.push_str(&format!(
                "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  fact({fact_symbol}) rule({rule_symbol}, {fact_symbol}, {graph_symbol}) {miss_gate} graph({graph_symbol}, tellEff)\n  =>*\n  event(ruleCommitEvt) RESIDUAL:Cfg .\n\n"
            ));
            expected.push(ExpectedSearch {
                outcome: ExpectedSearchResult::NoSolution,
                span: branch.pattern_span,
                description: format!("{} terminal {tag} branch misses on other tag", rule.name),
                upstream: rule.name.clone(),
                predicate: "terminal-branch-miss",
                downstream: "ruleCommitEvt".to_owned(),
            });

            if let Some(cases) = &guard_cases {
                output.push_str(&format!(
                    "--- {}: terminal branch `{tag}` cannot commit when its branch guard is false.\n",
                    rule.name
                ));
                output.push_str(&format!(
                    "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  fact({fact_symbol}) rule({rule_symbol}, {fact_symbol}, {graph_symbol}) terminalBranchGuard({rule_symbol}, {fact_symbol}, {tag_symbol}, {tag_symbol}, {}, {graph_symbol}) graph({graph_symbol}, tellEff)\n  =>*\n  event(ruleCommitEvt) RESIDUAL:Cfg .\n\n",
                    cases.false_expr
                ));
                expected.push(ExpectedSearch {
                    outcome: ExpectedSearchResult::NoSolution,
                    span: branch.pattern_span,
                    description: format!("{} terminal {tag} false guard cannot commit", rule.name),
                    upstream: rule.name.clone(),
                    predicate: "terminal-branch-guard-false",
                    downstream: "ruleCommitEvt".to_owned(),
                });
            }

            output.push_str(&format!(
                "--- {}: exhaustive terminal branch miss emits a diagnostic.\n",
                rule.name
            ));
            output.push_str(&format!(
                "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  fact({fact_symbol}) exhaustiveTerminal({rule_symbol}, {fact_symbol}, {miss_tag_symbol}, {tag_symbol})\n  =>*\n  fact({fact_symbol}) diagnostic({rule_symbol}) .\n\n"
            ));
            expected.push(ExpectedSearch {
                outcome: ExpectedSearchResult::Solution,
                span: branch.pattern_span,
                description: format!("{} terminal {tag} exhaustive miss diagnoses", rule.name),
                upstream: rule.name.clone(),
                predicate: "terminal-exhaustive-miss",
                downstream: "diagnostic".to_owned(),
            });
        }
    }

    for (index, assertion) in ir.assertions.iter().enumerate() {
        let Some(assertion_symbol) = assertion_symbols.get(&index) else {
            continue;
        };
        let cases = maude_bool_cases(&assertion.expr.expr, &mut expr_context);
        for (result, expr) in [
            ("aPass", &cases.true_expr),
            ("aFail", &cases.false_expr),
            ("aError", &cases.error_expr),
        ] {
            output.push_str(&format!(
                "--- assertion {}: lowered {result} cannot mutate runtime state.\n",
                index + 1
            ));
            output.push_str(&format!(
                "search [1] in WHIPPLESCRIPT-GENERATED-CHECK :\n  assertionExpr({assertion_symbol}, {expr})\n  =>*\n  event(ruleCommitEvt) RESIDUAL:Cfg .\n\n"
            ));
            expected.push(ExpectedSearch {
                outcome: ExpectedSearchResult::NoSolution,
                span: assertion.expr.span,
                description: format!(
                    "assertion {} {result} cannot mutate runtime state",
                    index + 1
                ),
                upstream: format!("assertion{}", index + 1),
                predicate: "assertion-read-only",
                downstream: "ruleCommitEvt".to_owned(),
            });
        }
    }

    append_composition_model_searches(
        ir,
        &mut output,
        &mut expected,
        &rule_symbols,
        &fact_symbols,
        &graph_symbols,
        &effect_symbols,
        &pattern_symbols,
        &application_symbols,
        &workflow_symbols,
        &instance_symbols,
        &output_symbols,
        &failure_symbols,
    );

    (output, expected)
}

pub(crate) fn maude_bool_cases(expr: &Expr, context: &mut MaudeExprContext) -> MaudeBoolCases {
    match expr {
        Expr::Literal(ExprLiteral::Bool(true)) => MaudeBoolCases {
            true_expr: "boolTrue".to_owned(),
            false_expr: "boolFalse".to_owned(),
            error_expr: "exprError".to_owned(),
        },
        Expr::Literal(ExprLiteral::Bool(false)) => MaudeBoolCases {
            true_expr: "boolTrue".to_owned(),
            false_expr: "boolFalse".to_owned(),
            error_expr: "exprError".to_owned(),
        },
        Expr::Unary {
            op: UnaryOp::Not,
            expr,
        } => {
            let inner = maude_bool_cases(expr, context);
            MaudeBoolCases {
                true_expr: format!("notExpr({})", inner.false_expr),
                false_expr: format!("notExpr({})", inner.true_expr),
                error_expr: format!("notExpr({})", inner.error_expr),
            }
        }
        Expr::Binary {
            op: BinaryOp::And,
            left,
            right,
        } => {
            let left = maude_bool_cases(left, context);
            let right = maude_bool_cases(right, context);
            MaudeBoolCases {
                true_expr: format!("andExpr({}, {})", left.true_expr, right.true_expr),
                false_expr: format!("andExpr({}, {})", left.false_expr, right.true_expr),
                error_expr: format!("andExpr({}, {})", left.error_expr, right.true_expr),
            }
        }
        Expr::Binary {
            op: BinaryOp::Or,
            left,
            right,
        } => {
            let left = maude_bool_cases(left, context);
            let right = maude_bool_cases(right, context);
            MaudeBoolCases {
                true_expr: format!("orExpr({}, {})", left.true_expr, right.false_expr),
                false_expr: format!("orExpr({}, {})", left.false_expr, right.false_expr),
                error_expr: format!("orExpr({}, {})", left.error_expr, right.false_expr),
            }
        }
        Expr::Binary {
            op: BinaryOp::Eq,
            left,
            right,
        } => MaudeBoolCases {
            true_expr: maude_eq_true_expr(left, right, context),
            false_expr: maude_eq_false_expr(left, right, context),
            error_expr: "exprError".to_owned(),
        },
        Expr::Binary {
            op: BinaryOp::Ne,
            left,
            right,
        } => MaudeBoolCases {
            true_expr: format!("notExpr({})", maude_eq_false_expr(left, right, context)),
            false_expr: format!(
                "neExpr({}, {})",
                maude_scalar_expr(left, context),
                maude_scalar_expr(right, context)
            ),
            error_expr: "exprError".to_owned(),
        },
        Expr::Binary {
            op: BinaryOp::Lt,
            left,
            right,
        } => maude_order_bool_cases("ltExpr", left, right, context),
        Expr::Binary {
            op: BinaryOp::Le,
            left,
            right,
        } => maude_order_bool_cases("leExpr", left, right, context),
        Expr::Binary {
            op: BinaryOp::Gt,
            left,
            right,
        } => maude_order_bool_cases("gtExpr", left, right, context),
        Expr::Binary {
            op: BinaryOp::Ge,
            left,
            right,
        } => maude_order_bool_cases("geExpr", left, right, context),
        Expr::Binary {
            op: BinaryOp::In,
            left,
            right,
        } => maude_membership_bool_cases(left, right, false, context),
        Expr::Binary {
            op: BinaryOp::NotIn,
            left,
            right,
        } => maude_membership_bool_cases(left, right, true, context),
        Expr::Call { name, args } if name == "exists" && args.len() == 1 => {
            let collection = maude_collection_expr(&args[0], "qOne", context);
            MaudeBoolCases {
                true_expr: format!("existsExpr({collection})"),
                false_expr: format!(
                    "existsExpr({})",
                    maude_collection_expr(&args[0], "qZero", context)
                ),
                error_expr: format!(
                    "existsExpr({})",
                    maude_collection_expr(&args[0], "qError", context)
                ),
            }
        }
        _ => MaudeBoolCases {
            true_expr: "boolTrue".to_owned(),
            false_expr: "boolFalse".to_owned(),
            error_expr: "exprError".to_owned(),
        },
    }
}

fn maude_order_bool_cases(
    op: &str,
    left: &Expr,
    right: &Expr,
    context: &mut MaudeExprContext,
) -> MaudeBoolCases {
    if let Some((count_expr, literal_expr)) = maude_count_number_pair(left, right, true, context) {
        return MaudeBoolCases {
            true_expr: format!("{op}({count_expr}, {literal_expr})"),
            false_expr: maude_false_order_expr(op),
            error_expr: format!("{op}(exprError, {literal_expr})"),
        };
    }
    if let Some((literal_expr, count_expr)) = maude_count_number_pair(right, left, true, context) {
        return MaudeBoolCases {
            true_expr: format!("{op}({literal_expr}, {count_expr})"),
            false_expr: maude_false_order_expr(op),
            error_expr: format!("{op}({literal_expr}, exprError)"),
        };
    }
    let _ = maude_scalar_expr(left, context);
    let _ = maude_scalar_expr(right, context);
    MaudeBoolCases {
        true_expr: maude_true_order_expr(op),
        false_expr: maude_false_order_expr(op),
        error_expr: format!("{op}(exprError, orderHigh)"),
    }
}

fn maude_true_order_expr(op: &str) -> String {
    let (left, right) = match op {
        "ltExpr" | "leExpr" => ("orderLow", "orderHigh"),
        "gtExpr" | "geExpr" => ("orderHigh", "orderLow"),
        _ => ("orderLow", "orderHigh"),
    };
    format!("{op}({left}, {right})")
}

fn maude_false_order_expr(op: &str) -> String {
    let (left, right) = match op {
        "ltExpr" | "leExpr" => ("orderHigh", "orderLow"),
        "gtExpr" | "geExpr" => ("orderLow", "orderHigh"),
        _ => ("orderHigh", "orderLow"),
    };
    format!("{op}({left}, {right})")
}

fn maude_membership_bool_cases(
    item: &Expr,
    collection: &Expr,
    negated: bool,
    context: &mut MaudeExprContext,
) -> MaudeBoolCases {
    let item_expr = maude_scalar_expr(item, context);
    let present_collection = maude_collection_with_member(collection, &item_expr, true, context);
    let missing_collection = maude_collection_with_member(collection, &item_expr, false, context);
    let true_expr = format!("inExpr({item_expr}, {present_collection})");
    let false_expr = format!("inExpr({item_expr}, {missing_collection})");
    let error_expr = format!("inExpr(exprError, {present_collection})");
    if negated {
        MaudeBoolCases {
            true_expr: format!("notExpr({false_expr})"),
            false_expr: format!("notExpr({true_expr})"),
            error_expr,
        }
    } else {
        MaudeBoolCases {
            true_expr,
            false_expr,
            error_expr,
        }
    }
}

fn maude_eq_true_expr(left: &Expr, right: &Expr, context: &mut MaudeExprContext) -> String {
    let pair = maude_equal_pair(left, right, true, context);
    format!("eqExpr({}, {})", pair.0, pair.1)
}

fn maude_eq_false_expr(left: &Expr, right: &Expr, context: &mut MaudeExprContext) -> String {
    if let Some((query_expr, number_expr)) = maude_count_number_pair(left, right, false, context) {
        return format!("eqExpr({query_expr}, {number_expr})");
    }
    if let Some((number_expr, query_expr)) = maude_count_number_pair(right, left, false, context) {
        return format!("eqExpr({number_expr}, {query_expr})");
    }
    let lhs = maude_scalar_expr(left, context);
    format!("notExpr(eqExpr({lhs}, {lhs}))")
}

fn maude_equal_pair(
    left: &Expr,
    right: &Expr,
    equal: bool,
    context: &mut MaudeExprContext,
) -> (String, String) {
    if let Some((query_expr, number_expr)) = maude_count_number_pair(left, right, equal, context) {
        return (query_expr, number_expr);
    }
    if let Some((number_expr, query_expr)) = maude_count_number_pair(right, left, equal, context) {
        return (number_expr, query_expr);
    }

    let lhs = maude_scalar_expr(left, context);
    if equal {
        return (lhs.clone(), lhs);
    }
    (lhs.clone(), lhs)
}

fn maude_count_number_pair(
    maybe_count: &Expr,
    maybe_number: &Expr,
    equal: bool,
    context: &mut MaudeExprContext,
) -> Option<(String, String)> {
    let Expr::Call { name, args } = maybe_count else {
        return None;
    };
    if name != "count" || args.len() != 1 {
        return None;
    }
    let Expr::Literal(ExprLiteral::Number(number)) = maybe_number else {
        return None;
    };
    let expected = maude_count_literal(number)?;
    let cardinality = if equal {
        maude_query_cardinality_for_count(number)
    } else if number == "0" {
        "qOne"
    } else {
        "qZero"
    };
    let count = format!(
        "countExpr({})",
        maude_collection_expr(&args[0], cardinality, context)
    );
    Some((count, expected))
}

fn maude_count_literal(number: &str) -> Option<String> {
    match number {
        "0" => Some("countZero".to_owned()),
        "1" => Some("countOne".to_owned()),
        "2" => Some("countTwo".to_owned()),
        "3" => Some("countThree".to_owned()),
        _ => number
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 3)
            .map(|_| "countMany".to_owned()),
    }
}

fn maude_query_cardinality_for_count(number: &str) -> &'static str {
    match number {
        "0" => "qZero",
        "1" => "qOne",
        "2" => "qTwo",
        "3" => "qThree",
        _ => "qMany",
    }
}

fn maude_scalar_expr(expr: &Expr, context: &mut MaudeExprContext) -> String {
    match expr {
        Expr::Literal(ExprLiteral::Bool(true)) => "boolTrue".to_owned(),
        Expr::Literal(ExprLiteral::Bool(false)) => "boolFalse".to_owned(),
        Expr::Literal(ExprLiteral::Number(number)) => {
            maude_count_literal(number).unwrap_or_else(|| maude_scalar_symbol(expr, context))
        }
        Expr::Index { target, key } => {
            let key = maude_scalar_expr(key, context);
            let target = maude_index_target_expr(target, &key, expr, context);
            format!("indexExpr({target}, {key})")
        }
        Expr::Array(_) | Expr::Object(_) => maude_value_expr(expr, context),
        Expr::Call { name, args } if name == "count" && args.len() == 1 => {
            format!(
                "countExpr({})",
                maude_collection_expr(&args[0], "qOne", context)
            )
        }
        _ => format!("scalar({})", maude_scalar_symbol(expr, context)),
    }
}

fn maude_value_expr(expr: &Expr, context: &mut MaudeExprContext) -> String {
    match expr {
        Expr::Array(items) => maude_array_literal_expr(items, context),
        Expr::Object(fields) => maude_object_literal_expr(fields, context),
        Expr::Index { target, key } => {
            let key = maude_scalar_expr(key, context);
            let target = maude_index_target_expr(target, &key, expr, context);
            format!("indexExpr({target}, {key})")
        }
        Expr::Query { .. } => maude_collection_expr(expr, "qOne", context),
        _ => maude_scalar_expr(expr, context),
    }
}

fn maude_array_literal_expr(items: &[Expr], context: &mut MaudeExprContext) -> String {
    if items.is_empty() {
        return "arrayEmpty".to_owned();
    }
    format!("arrayOf({})", maude_expr_list(items, context))
}

fn maude_object_literal_expr(fields: &[ExprObjectField], context: &mut MaudeExprContext) -> String {
    if fields.is_empty() {
        return "objectEmpty".to_owned();
    }
    format!("objectOf({})", maude_entry_list(fields, context))
}

fn maude_expr_list(items: &[Expr], context: &mut MaudeExprContext) -> String {
    let Some((first, rest)) = items.split_first() else {
        return "exprNil".to_owned();
    };
    format!(
        "exprCons({}, {})",
        maude_scalar_expr(first, context),
        maude_expr_list(rest, context)
    )
}

fn maude_entry_list(fields: &[ExprObjectField], context: &mut MaudeExprContext) -> String {
    let Some((first, rest)) = fields.split_first() else {
        return "entryNil".to_owned();
    };
    format!(
        "entryCons(entry({}, {}), {})",
        maude_field_key_expr(&first.key, context),
        maude_scalar_expr(&first.value, context),
        maude_entry_list(rest, context)
    )
}

fn maude_collection_expr(
    expr: &Expr,
    cardinality: &'static str,
    context: &mut MaudeExprContext,
) -> String {
    match expr {
        Expr::Query { guard, .. } => {
            let query = maude_query_symbol(expr, context);
            if let Some(guard) = guard {
                let guard_cases = maude_bool_cases(guard, context);
                format!(
                    "queryFilter({query}, {}, {cardinality})",
                    guard_cases.true_expr
                )
            } else {
                format!("query({query}, {cardinality})")
            }
        }
        Expr::Array(items) => {
            let _ = cardinality;
            maude_array_literal_expr(items, context)
        }
        Expr::Object(fields) => {
            let _ = cardinality;
            maude_object_literal_expr(fields, context)
        }
        Expr::Index { .. } => maude_value_expr(expr, context),
        _ => format!(
            "query({}, {cardinality})",
            maude_query_symbol(expr, context)
        ),
    }
}

fn maude_collection_with_member(
    collection: &Expr,
    item_expr: &str,
    present: bool,
    context: &mut MaudeExprContext,
) -> String {
    match collection {
        Expr::Array(_) => {
            if present {
                format!("arrayHas({item_expr})")
            } else {
                format!("arrayMissing({item_expr})")
            }
        }
        Expr::Object(_) => {
            if present {
                format!(
                    "objectHas({item_expr}, scalar({}))",
                    maude_scalar_symbol(collection, context)
                )
            } else {
                format!("objectMissing({item_expr})")
            }
        }
        Expr::Path(_) | Expr::Index { .. } => {
            if present {
                format!(
                    "mapHas({item_expr}, scalar({}))",
                    maude_scalar_symbol(collection, context)
                )
            } else {
                format!("mapMissing({item_expr})")
            }
        }
        _ => {
            if present {
                format!("arrayHas({item_expr})")
            } else {
                format!("arrayMissing({item_expr})")
            }
        }
    }
}

fn maude_index_target_expr(
    target: &Expr,
    key_expr: &str,
    index_expr: &Expr,
    context: &mut MaudeExprContext,
) -> String {
    match target {
        Expr::Object(fields) => {
            let _ = key_expr;
            maude_object_literal_expr(fields, context)
        }
        Expr::Index { .. } => maude_value_expr(target, context),
        _ => format!(
            "mapHas({key_expr}, scalar({}))",
            maude_scalar_symbol(index_expr, context)
        ),
    }
}

fn maude_field_key_expr(key: &str, context: &mut MaudeExprContext) -> String {
    let expr = Expr::Literal(ExprLiteral::String(key.to_owned()));
    maude_scalar_expr(&expr, context)
}

fn maude_scalar_symbol(expr: &Expr, context: &mut MaudeExprContext) -> String {
    let key = expr.to_snapshot();
    context
        .scalar_symbols
        .entry(key.clone())
        .or_insert_with(|| maude_symbol("scalar", &key))
        .clone()
}

fn maude_query_symbol(expr: &Expr, context: &mut MaudeExprContext) -> String {
    let key = expr.to_snapshot();
    context
        .query_symbols
        .entry(key.clone())
        .or_insert_with(|| maude_symbol("query", &key))
        .clone()
}

fn append_maude_ops<'a>(
    output: &mut String,
    symbols: impl IntoIterator<Item = &'a String>,
    sort: &str,
) {
    let symbols = symbols.into_iter().collect::<Vec<_>>();
    if symbols.is_empty() {
        return;
    }
    output.push_str("  ops\n");
    for symbol in symbols {
        output.push_str("    ");
        output.push_str(symbol);
        output.push('\n');
    }
    output.push_str(&format!("    : -> {sort} .\n"));
}

pub(crate) fn extract_maude_search_results(output: &str) -> Vec<ExpectedSearchResult> {
    let mut matches = Vec::new();
    for (index, _) in output.match_indices("Solution 1") {
        matches.push((index, ExpectedSearchResult::Solution));
    }
    for (index, _) in output.match_indices("No solution.") {
        matches.push((index, ExpectedSearchResult::NoSolution));
    }
    matches.sort_by_key(|(index, _)| *index);
    matches.into_iter().map(|(_, result)| result).collect()
}

pub(crate) fn maude_symbol(prefix: &str, value: &str) -> String {
    format!("{prefix}{:016x}", stable_hash(value))
}

fn maude_predicate(predicate: &whipplescript_parser::DependencyPredicate) -> &'static str {
    match predicate {
        whipplescript_parser::DependencyPredicate::Succeeds => "succeeds",
        whipplescript_parser::DependencyPredicate::Fails => "fails",
        whipplescript_parser::DependencyPredicate::TimedOut => "timed_out",
        whipplescript_parser::DependencyPredicate::Cancelled => "cancelled",
        whipplescript_parser::DependencyPredicate::Completes => "completes",
    }
}

fn maude_terminal_tag(tag: &str) -> &'static str {
    match tag {
        "Completed" => "terminalCompleted",
        "Failed" => "terminalFailed",
        "TimedOut" => "terminalTimedOut",
        "Cancelled" => "terminalCancelled",
        _ => "terminalCompleted",
    }
}

fn maude_terminal_miss_tag(tag: &str) -> &'static str {
    match tag {
        "Completed" => "terminalFailed",
        "Failed" => "terminalCompleted",
        "TimedOut" => "terminalCompleted",
        "Cancelled" => "terminalCompleted",
        _ => "terminalFailed",
    }
}
