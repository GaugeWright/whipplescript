//! Selected-path result obligations. Source order alone cannot prove them:
//! `after` blocks are independent graph continuations, while `then` adds an
//! explicit success condition to the rest of its lexical block.

use super::*;

#[derive(Clone, Debug)]
enum Condition {
    Yes,
    No,
    Is(usize, String),
    Not(Box<Condition>),
    All(Vec<Condition>),
    Any(Vec<Condition>),
}

fn successful(outcome: usize) -> Condition {
    Condition::Any(
        ["succeeded", "ok", "over"]
            .into_iter()
            .map(|variant| Condition::Is(outcome, variant.into()))
            .collect(),
    )
}

impl Condition {
    fn and(self, other: Self) -> Self {
        Self::All(vec![self, other])
    }
    fn not(self) -> Self {
        Self::Not(Box::new(self))
    }
    fn evaluate(&self, values: &[Option<String>]) -> Option<bool> {
        match self {
            Self::Yes => Some(true),
            Self::No => Some(false),
            Self::Is(choice, expected) => values[*choice].as_ref().map(|actual| actual == expected),
            Self::Not(inner) => inner.evaluate(values).map(|value| !value),
            Self::All(conditions) | Self::Any(conditions) => {
                let all = matches!(self, Self::All(_));
                let mut unknown = false;
                for condition in conditions {
                    match condition.evaluate(values) {
                        Some(value) if value != all => return Some(!all),
                        None => unknown = true,
                        _ => {}
                    }
                }
                (!unknown).then_some(all)
            }
        }
    }
    fn first_unknown(&self, values: &[Option<String>]) -> Option<usize> {
        match self {
            Self::Is(choice, _) => values[*choice].is_none().then_some(*choice),
            Self::Not(inner) => inner.first_unknown(values),
            Self::All(children) | Self::Any(children) => children
                .iter()
                .find_map(|child| child.first_unknown(values)),
            _ => None,
        }
    }
}

struct Choice {
    label: String,
    values: BTreeSet<String>,
    open: bool,
}
#[derive(Clone)]
struct Binding {
    identity: String,
    outcome: Option<usize>,
}
type Bindings = BTreeMap<String, Binding>;
struct ResultSite {
    span: SourceSpan,
    condition: Condition,
}
struct Work {
    condition: Condition,
    outcome: usize,
}

struct Graph<'a, 's> {
    checker: &'a mut Checker<'s>,
    choices: Vec<Choice>,
    keys: BTreeMap<String, usize>,
    returns: Vec<ResultSite>,
    handler_requirements: Vec<ResultSite>,
    failures: Vec<Condition>,
    work: Vec<Work>,
    next_block: usize,
}

pub(super) fn validate(
    checker: &mut Checker<'_>,
    action: &ActionDecl,
    statements: &[BodyStmt],
    environment: Environment,
) {
    let before = checker.diagnostics.len();
    let mut graph = Graph {
        checker,
        choices: Vec::new(),
        keys: BTreeMap::new(),
        returns: Vec::new(),
        handler_requirements: Vec::new(),
        failures: Vec::new(),
        work: Vec::new(),
        next_block: 0,
    };
    let bindings = action
        .params
        .iter()
        .enumerate()
        .map(|(index, param)| {
            (
                param.name.name.clone(),
                Binding {
                    identity: format!("parameter@{index}"),
                    outcome: None,
                },
            )
        })
        .collect();
    graph.block(action, statements, environment, bindings, Condition::Yes);
    if graph.checker.diagnostics.len() != before {
        return;
    }
    for (index, second) in graph.returns.iter().enumerate() {
        for first in &graph.returns[..index] {
            if let Some(witness) =
                graph.witness(&first.condition.clone().and(second.condition.clone()))
            {
                graph.checker.diagnostics.push(Diagnostic::error(diagnostic_code!("construct.invalid_expansion"), second.span,
                    format!("action `{}` can select two returns{}", action.name.name, graph.describe(&witness)))
                    .with_related(first.span, "the other return can be selected on this path")
                    .with_suggestion("keep one result for this path; independent continuations cannot both return"));
                return;
            }
        }
    }
    // A non-success without recovery propagates; it is not a successful path
    // that owes a manufactured value. Lexical handler graphs extend this
    // admission formula when their recovery contract is lowered.
    let success = Condition::All(
        graph
            .work
            .iter()
            .map(|work| {
                Condition::Any(vec![work.condition.clone().not(), successful(work.outcome)])
            })
            .collect(),
    );
    let missing = success
        .and(Condition::Any(graph.failures.clone()).not())
        .and(
            Condition::Any(
                graph
                    .returns
                    .iter()
                    .map(|result| result.condition.clone())
                    .collect(),
            )
            .not(),
        );
    if let Some(witness) = graph.witness(&missing) {
        graph.checker.diagnostics.push(
            Diagnostic::error(
                diagnostic_code!("construct.invalid_expansion"),
                action.name.span,
                format!(
                    "action `{}` has a successful path without a return{}",
                    action.name.name,
                    graph.describe(&witness)
                ),
            )
            .with_related(
                action.result.as_ref().expect("typed action").success.span(),
                "this result is required",
            )
            .with_suggestion(
                "return the declared value on this selected path, or explicitly fail it",
            ),
        );
    }
    for requirement in &graph.handler_requirements {
        if let Some(witness) = graph.witness(&requirement.condition) {
            graph.checker.diagnostics.push(
                Diagnostic::error(
                    diagnostic_code!("construct.invalid_expansion"),
                    requirement.span,
                    format!(
                        "failure handler in action `{}` can finish without returning or propagating a failure{}",
                        action.name.name,
                        graph.describe(&witness)
                    ),
                )
                .with_related(
                    action.result.as_ref().expect("typed action").success.span(),
                    "this result is required after recovery",
                )
                .with_suggestion("return the declared result, or `fail` with the declared domain failure"),
            );
            return;
        }
    }
}

impl Graph<'_, '_> {
    fn choice(
        &mut self,
        key: String,
        label: String,
        values: BTreeSet<String>,
        open: bool,
    ) -> usize {
        if let Some(&choice) = self.keys.get(&key) {
            self.choices[choice].values.extend(values);
            self.choices[choice].open |= open;
            return choice;
        }
        let choice = self.choices.len();
        self.keys.insert(key, choice);
        self.choices.push(Choice {
            label,
            values,
            open,
        });
        choice
    }
    fn outcome(&mut self, key: String, label: &str, operation: &BodyStmt) -> usize {
        let values: BTreeSet<_> = if matches!(
            operation,
            BodyStmt::Composition(CompositionStmt::Call { .. })
        ) {
            ["succeeded", "failed"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        } else if matches!(
            operation,
            BodyStmt::Effect(effect)
                if matches!(effect.kind, BodyEffectKind::CounterConsume { .. })
        ) {
            ["ok", "over", "failed", "timed_out", "cancelled"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        } else {
            ["succeeded", "failed", "timed_out", "cancelled"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        self.choice(key, label.into(), values, false)
    }
    fn witness(&self, condition: &Condition) -> Option<Vec<Option<String>>> {
        let mut pending = vec![vec![None; self.choices.len()]];
        while let Some(values) = pending.pop() {
            match condition.evaluate(&values) {
                Some(true) => return Some(values),
                Some(false) => continue,
                None => {
                    let choice = condition
                        .first_unknown(&values)
                        .expect("unresolved condition has a choice");
                    for value in self.choices[choice].values.iter().rev() {
                        let mut next = values.clone();
                        next[choice] = Some(value.clone());
                        pending.push(next);
                    }
                }
            }
        }
        None
    }
    fn describe(&self, values: &[Option<String>]) -> String {
        let terms: Vec<_> = values
            .iter()
            .enumerate()
            .filter_map(|(choice, value)| {
                value.as_ref().map(|value| {
                    format!("{} = {}", self.choices[choice].label, display_value(value))
                })
            })
            .collect();
        if terms.is_empty() {
            String::new()
        } else {
            format!(" when {}", terms.join(", "))
        }
    }
    fn refuse(&mut self, span: SourceSpan, message: impl Into<String>) {
        self.checker.diagnostics.push(Diagnostic::error(
            diagnostic_code!("construct.invalid_expansion"),
            span,
            message,
        ));
    }

    fn block(
        &mut self,
        action: &ActionDecl,
        statements: &[BodyStmt],
        environment: Environment,
        mut bindings: Bindings,
        mut condition: Condition,
    ) {
        let block = self.next_block;
        self.next_block += 1;
        let environment = self.checker.block_environment(statements, environment);
        let handler = statements.iter().find_map(|statement| match statement {
            BodyStmt::Composition(CompositionStmt::OnFailure { alias, body, span }) => {
                Some((alias, body, *span))
            }
            _ => None,
        });
        let work_start = self.work.len();
        let failure_start = self.failures.len();
        let return_start = self.returns.len();
        for (index, statement) in statements.iter().enumerate() {
            if let Some((name, operation)) = operation_binding(statement) {
                // The shared lexical binding validator has already established
                // uniqueness, including parameters and entrance aliases.
                let outcome = self.outcome(format!("operation@{block}:{index}"), &name, operation);
                bindings.insert(
                    name,
                    Binding {
                        identity: format!("value@{block}:{index}"),
                        outcome: Some(outcome),
                    },
                );
            }
        }
        for (index, statement) in statements.iter().enumerate() {
            if matches!(
                statement,
                BodyStmt::Composition(CompositionStmt::OnFailure { .. })
            ) {
                continue;
            }
            match statement {
                BodyStmt::Composition(CompositionStmt::Return(value)) => {
                    self.returns.push(ResultSite {
                        span: value.span,
                        condition: condition.clone().and(ready(&value.expr, &bindings)),
                    })
                }
                BodyStmt::Composition(CompositionStmt::Fail(_)) => {
                    self.failures.push(condition.clone())
                }
                BodyStmt::Composition(CompositionStmt::Then { binding, .. }) => {
                    let outcome = bindings[binding].outcome.expect("operation");
                    self.work.push(Work {
                        condition: condition.clone(),
                        outcome,
                    });
                    // The operation is owned at the old condition; only its
                    // continuation acquires the additional success edge.
                    condition = condition.and(successful(outcome));
                }
                BodyStmt::Effect(_) | BodyStmt::Composition(CompositionStmt::Call { .. }) => {
                    let outcome = operation_binding(statement)
                        .and_then(|(name, _)| bindings[&name].outcome)
                        .unwrap_or_else(|| {
                            self.outcome(
                                format!("operation@{block}:{index}"),
                                "unbound operation",
                                statement,
                            )
                        });
                    self.work.push(Work {
                        condition: condition.clone(),
                        outcome,
                    });
                }
                BodyStmt::After(after) => {
                    let Some(binding) = bindings.get(&after.binding) else {
                        self.refuse(
                            after.span,
                            format!(
                                "after refers to unknown action operation `{}`",
                                after.binding
                            ),
                        );
                        continue;
                    };
                    let Some(outcome) = binding.outcome else {
                        self.refuse(
                            after.span,
                            format!("`{}` is a value, not an action operation", after.binding),
                        );
                        continue;
                    };
                    let selected = match after.predicate {
                        body::AfterPredicate::Succeeds => successful(outcome),
                        body::AfterPredicate::Fails => Condition::Is(outcome, "failed".into()),
                        body::AfterPredicate::TimedOut => {
                            Condition::Is(outcome, "timed_out".into())
                        }
                        body::AfterPredicate::Cancelled => {
                            Condition::Is(outcome, "cancelled".into())
                        }
                        body::AfterPredicate::Completes => Condition::Yes,
                        body::AfterPredicate::Ok if self.choices[outcome].values.contains("ok") => {
                            Condition::Is(outcome, "ok".into())
                        }
                        body::AfterPredicate::Over
                            if self.choices[outcome].values.contains("over") =>
                        {
                            Condition::Is(outcome, "over".into())
                        }
                        _ => {
                            self.refuse(after.span, "action return-path analysis does not yet lower this outcome predicate");
                            continue;
                        }
                    };
                    let mut child_types = environment.clone();
                    let mut child_bindings = bindings.clone();
                    if let Some(alias) = &after.alias {
                        child_types.insert(
                            alias.clone(),
                            if after.predicate == body::AfterPredicate::Succeeds {
                                environment.get(&after.binding).cloned().flatten()
                            } else {
                                environment
                                    .operation_outcome(&after.binding, after.predicate)
                                    .cloned()
                            },
                        );
                        if after.predicate == body::AfterPredicate::Succeeds {
                            child_types.inherit_refinements(
                                alias,
                                std::slice::from_ref(&after.binding),
                                &environment,
                            );
                        } else if after.predicate == body::AfterPredicate::Completes {
                            if let Some(outcomes) = environment.outcomes(&after.binding) {
                                child_types.mark_terminal_outcome(alias, outcomes.clone());
                            }
                        }
                        child_bindings.insert(
                            alias.clone(),
                            Binding {
                                identity: format!(
                                    "{}:{}",
                                    binding.identity,
                                    after.predicate.arm_key_str()
                                ),
                                // A terminal observation is ready on the selected
                                // terminal, including non-success. Treating it as
                                // the operation's successful value makes valid
                                // recovery returns look unreachable.
                                outcome: None,
                            },
                        );
                    }
                    self.block(
                        action,
                        &after.body,
                        child_types,
                        child_bindings,
                        condition.clone().and(selected),
                    );
                }
                BodyStmt::Case(case) => {
                    self.case(action, case, &environment, &bindings, condition.clone())
                }
                BodyStmt::Region(region) => {
                    // A region is a history, not an if/else. Its held arm may
                    // have selected work and a result before the condition
                    // lapses, so the after-entry lapse path selects both arms.
                    // Only a clean exit opens the lexical tail.
                    let phase = self.choice(
                        format!("region@{block}:{index}"),
                        format!(
                            "{} `{}`",
                            if region.until { "until" } else { "during" },
                            region.condition
                        ),
                        [
                            "region:lapse at entry",
                            "region:lapse after entry",
                            "region:clean exit",
                        ]
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                        false,
                    );
                    let entered = Condition::Any(vec![
                        Condition::Is(phase, "region:lapse after entry".into()),
                        Condition::Is(phase, "region:clean exit".into()),
                    ]);
                    self.block(
                        action,
                        &region.body,
                        environment.clone(),
                        bindings.clone(),
                        condition.clone().and(entered),
                    );
                    let mut lapse_types = environment.clone();
                    let mut lapse_bindings = bindings.clone();
                    if let Some(binding) = &region.lapse_binding {
                        lapse_types.insert(binding.clone(), None);
                        lapse_bindings.insert(
                            binding.clone(),
                            Binding {
                                identity: format!("region-lapse@{block}:{index}"),
                                outcome: None,
                            },
                        );
                    }
                    let lapsed = Condition::Any(vec![
                        Condition::Is(phase, "region:lapse at entry".into()),
                        Condition::Is(phase, "region:lapse after entry".into()),
                    ]);
                    self.block(
                        action,
                        &region.lapse_body,
                        lapse_types,
                        lapse_bindings,
                        condition.clone().and(lapsed),
                    );
                    condition = condition.and(Condition::Is(phase, "region:clean exit".into()));
                }
                _ => {}
            }
            if matches!(
                statement,
                BodyStmt::Composition(CompositionStmt::Return(_) | CompositionStmt::Fail(_))
            ) {
                if let Some(next) = statements[index + 1..].iter().find(|next| {
                    !matches!(
                        next,
                        BodyStmt::Composition(CompositionStmt::OnFailure { .. })
                    )
                }) {
                    self.refuse(
                        span(next),
                        "statement is unreachable after this action return or failure",
                    );
                }
                break;
            }
        }
        let failure = Condition::Any(
            self.work[work_start..]
                .iter()
                .map(|work| work.condition.clone().and(successful(work.outcome).not()))
                .chain(self.failures[failure_start..].iter().cloned())
                .collect(),
        );
        let Some((alias, body, span)) = handler else {
            return;
        };
        for result in &mut self.returns[return_start..] {
            result.condition = result.condition.clone().and(failure.clone().not());
        }
        let handler_work = self.work.len();
        let handler_returns = self.returns.len();
        let handler_failures = self.failures.len();
        let mut child_types = environment.clone();
        child_types.insert(
            alias.clone(),
            Some(super::failure_aggregate(
                action
                    .result
                    .as_ref()
                    .and_then(|result| result.failure.as_ref()),
            )),
        );
        let mut child_bindings = bindings;
        child_bindings.insert(
            alias.clone(),
            Binding {
                identity: format!("failure-handler@{block}"),
                outcome: None,
            },
        );
        let selected = condition.and(failure);
        self.block(action, body, child_types, child_bindings, selected.clone());
        let handler_success = Condition::All(
            self.work[handler_work..]
                .iter()
                .map(|work| {
                    Condition::Any(vec![work.condition.clone().not(), successful(work.outcome)])
                })
                .collect(),
        );
        let handler_ended = Condition::Any(
            self.returns[handler_returns..]
                .iter()
                .map(|result| result.condition.clone())
                .chain(self.failures[handler_failures..].iter().cloned())
                .collect(),
        );
        self.handler_requirements.push(ResultSite {
            span,
            condition: selected.and(handler_success).and(handler_ended.not()),
        });
    }

    fn guard_truth(&mut self, expr: &Expr, bindings: &Bindings) -> Condition {
        match expr {
            Expr::Literal(ExprLiteral::Bool(value)) => {
                if *value {
                    Condition::Yes
                } else {
                    Condition::No
                }
            }
            Expr::Unary {
                op: UnaryOp::Not,
                expr,
            } => self.guard_truth(expr, bindings).not(),
            Expr::Binary {
                op: BinaryOp::And,
                left,
                right,
            } => self
                .guard_truth(left, bindings)
                .and(self.guard_truth(right, bindings)),
            Expr::Binary {
                op: BinaryOp::Or,
                left,
                right,
            } => Condition::Any(vec![
                self.guard_truth(left, bindings),
                self.guard_truth(right, bindings),
            ]),
            _ => {
                let choice = self.choice(
                    selector_key(expr, bindings),
                    expr.to_snapshot(),
                    ["bool:true".into(), "bool:false".into()].into(),
                    false,
                );
                Condition::Is(choice, "bool:true".into())
            }
        }
    }

    fn case(
        &mut self,
        action: &ActionDecl,
        case: &body::CaseBlock,
        environment: &Environment,
        bindings: &Bindings,
        condition: Condition,
    ) {
        let Ok(expr) = parse_expression(&case.scrutinee) else {
            return;
        };
        let ty = self.checker.infer_node(&expr, case.span, environment);
        let terminal_outcome = environment::terminal_outcomes(&expr, environment);
        let observed_outcome = environment::observed_operation(&expr)
            .and_then(|name| bindings.get(name))
            .and_then(|binding| binding.outcome);
        let terminal_domain = terminal_outcome.map(|outcomes| {
            let values = if observed_outcome.is_some() {
                [
                    ("succeeded", outcomes.succeeded.as_ref()),
                    ("failed", outcomes.failed.as_ref()),
                    ("timed_out", outcomes.timed_out.as_ref()),
                    ("cancelled", outcomes.cancelled.as_ref()),
                ]
                .into_iter()
                .filter_map(|(value, payload)| payload.map(|_| value.to_owned()))
                .collect()
            } else {
                [
                    ("terminal:Completed", outcomes.succeeded.as_ref()),
                    ("terminal:Failed", outcomes.failed.as_ref()),
                    ("terminal:TimedOut", outcomes.timed_out.as_ref()),
                    ("terminal:Cancelled", outcomes.cancelled.as_ref()),
                ]
                .into_iter()
                .filter_map(|(value, payload)| payload.map(|_| value.to_owned()))
                .collect()
            };
            (values, false)
        });
        let Some((mut values, mut open)) = terminal_domain
            .or_else(|| ty.as_ref().and_then(|ty| domain(ty, self.checker.semantic)))
        else {
            self.refuse(
                case.span,
                format!(
                    "cannot determine the alternatives of action case `{}`",
                    case.scrutinee
                ),
            );
            return;
        };
        let declared_values = values.clone();
        let declared_open = open;
        if let Expr::Literal(
            literal @ (ExprLiteral::Bool(_) | ExprLiteral::Number(_) | ExprLiteral::Null),
        ) = &expr
        {
            values = [literal_value(literal).expect("scalar literal")].into();
            open = false;
        }
        if open {
            values.insert("other".into());
        }
        let condition = condition.and(ready(&expr, bindings));
        let key = selector_key(&expr, bindings);
        let choice = observed_outcome
            .unwrap_or_else(|| self.choice(key, case.scrutinee.clone(), values, open));
        let mut remaining = Condition::Yes;
        let mut excluded = environment::CaseExclusions::default();
        for branch in &case.branches {
            let fallback = is_fallback_pattern(&branch.pattern);
            let matched = if fallback {
                Condition::Yes
            } else {
                let terminal_value = terminal_outcome.and_then(|outcomes| {
                    let value = match (observed_outcome.is_some(), branch.pattern.as_str()) {
                        (true, "Completed") if outcomes.succeeded.is_some() => "succeeded".into(),
                        (true, "Failed") if outcomes.failed.is_some() => "failed".into(),
                        (true, "TimedOut") if outcomes.timed_out.is_some() => "timed_out".into(),
                        (true, "Cancelled") if outcomes.cancelled.is_some() => "cancelled".into(),
                        (false, "Completed") if outcomes.succeeded.is_some() => {
                            "terminal:Completed".into()
                        }
                        (false, "Failed") if outcomes.failed.is_some() => "terminal:Failed".into(),
                        (false, "TimedOut") if outcomes.timed_out.is_some() => {
                            "terminal:TimedOut".into()
                        }
                        (false, "Cancelled") if outcomes.cancelled.is_some() => {
                            "terminal:Cancelled".into()
                        }
                        _ => return None,
                    };
                    Some(value)
                });
                let Some(value) = terminal_value.or_else(|| {
                    ty.as_ref()
                        .and_then(|ty| pattern_value(&branch.pattern, ty, self.checker.semantic))
                }) else {
                    self.refuse(
                        branch.span,
                        format!(
                            "case pattern `{}` does not match the type of `{}`",
                            branch.pattern, case.scrutinee
                        ),
                    );
                    continue;
                };
                // `Some` covers every non-null alternative of an optional,
                // including ordinary scalar patterns in an open domain.
                if value == "Some" {
                    Condition::Is(choice, "null".into()).not()
                } else {
                    if !self.choices[choice].values.contains(&value) {
                        if self.choices[choice].open {
                            self.choices[choice].values.insert(value.clone());
                        } else if !declared_open && !declared_values.contains(&value) {
                            self.refuse(
                                branch.span,
                                format!(
                                    "case pattern `{}` is not an alternative of `{}`",
                                    branch.pattern, case.scrutinee
                                ),
                            );
                            continue;
                        }
                    }
                    Condition::Is(choice, value)
                }
            };
            let mut types = environment.clone();
            let mut names = bindings.clone();
            if let Some(binding) = &branch.binding {
                let terminal_payload =
                    terminal_outcome.and_then(|outcomes| match branch.pattern.as_str() {
                        "Completed" => outcomes.succeeded.as_ref(),
                        "Failed" => outcomes.failed.as_ref(),
                        "TimedOut" => outcomes.timed_out.as_ref(),
                        "Cancelled" => outcomes.cancelled.as_ref(),
                        _ => None,
                    });
                types.insert(
                    binding.clone(),
                    terminal_payload
                        .cloned()
                        .or_else(|| Some(IrType::Ref(branch.pattern.clone()))),
                );
                if terminal_payload.is_none() {
                    if let Some(path) = environment::value_path(&expr) {
                        types.inherit_refinements(binding, &path, environment);
                    }
                }
                names.insert(
                    binding.clone(),
                    Binding {
                        identity: selector_key(&expr, bindings),
                        outcome: None,
                    },
                );
            }
            types.narrow_case(&expr, &branch.pattern, &excluded, self.checker.semantic);
            excluded.record(&branch.pattern, branch.guard.is_some(), ty.as_ref());
            let (guard, guard_ready) = match &branch.guard {
                Some(guard) => match parse_expression(guard) {
                    Ok(expr)
                        if self.checker.infer_node(&expr, branch.span, &types)
                            == Some(primitive(IrPrimitiveType::Bool)) =>
                    {
                        types.narrow_guard(&expr, self.checker.semantic);
                        (self.guard_truth(&expr, &names), ready(&expr, &names))
                    }
                    _ => {
                        self.refuse(
                            branch.span,
                            "an action case guard must be a known boolean expression",
                        );
                        (Condition::No, Condition::Yes)
                    }
                },
                None => (Condition::Yes, Condition::Yes),
            };
            let selected = condition
                .clone()
                .and(remaining.clone())
                .and(matched.clone())
                .and(guard_ready.clone())
                .and(guard.clone());
            // A matching but unavailable guard blocks the ordered search. It
            // is not false, so negating readiness must not enable fallback.
            remaining = remaining.and(Condition::Any(vec![
                matched.not(),
                guard_ready.and(guard.not()),
            ]));
            self.block(action, &branch.body, types, names, selected);
        }
    }
}

fn operation_binding(statement: &BodyStmt) -> Option<(String, &BodyStmt)> {
    match statement {
        BodyStmt::Effect(effect) => effect
            .binding
            .as_ref()
            .map(|name| (name.clone(), statement)),
        BodyStmt::Composition(CompositionStmt::Call { binding, .. }) => {
            binding.as_ref().map(|name| (name.clone(), statement))
        }
        BodyStmt::Composition(CompositionStmt::Then {
            binding, operation, ..
        }) => Some((binding.clone(), operation)),
        _ => None,
    }
}

fn domain(ty: &IrType, semantic: &SemanticContext) -> Option<(BTreeSet<String>, bool)> {
    match ty {
        IrType::Primitive(IrPrimitiveType::Bool) => {
            Some((["bool:true".into(), "bool:false".into()].into(), false))
        }
        IrType::Primitive(IrPrimitiveType::Null) => Some((["null".into()].into(), false)),
        IrType::LiteralString(value) => Some(([format!("string:{value}")].into(), false)),
        IrType::Ref(name) => semantic
            .schemas
            .enums
            .get(name)
            .map(|values| {
                (
                    values.iter().map(|value| format!("enum:{value}")).collect(),
                    false,
                )
            })
            .or_else(|| {
                semantic
                    .schemas
                    .class_exists(name)
                    .then(|| ([format!("class:{name}")].into(), false))
            }),
        IrType::AgentRef(names) => Some((
            names.iter().map(|name| format!("agent:{name}")).collect(),
            false,
        )),
        IrType::Union(variants) => {
            let mut values = BTreeSet::new();
            let mut open = false;
            for variant in variants {
                let (next, next_open) = domain(variant, semantic)?;
                values.extend(next);
                open |= next_open;
            }
            Some((values, open))
        }
        IrType::Primitive(
            IrPrimitiveType::String | IrPrimitiveType::Int | IrPrimitiveType::Float,
        ) => Some((BTreeSet::new(), true)),
        IrType::Optional(inner) => {
            let (mut values, open) =
                domain(inner, semantic).unwrap_or_else(|| (["Some".into()].into(), false));
            values.insert("null".into());
            Some((values, open))
        }
        _ => None,
    }
}
fn display_value(value: &str) -> String {
    if value == "other" {
        return "<another value>".into();
    }
    if let Some(value) = value.strip_prefix("string:") {
        return format!("{value:?}");
    }
    value
        .split_once(':')
        .map_or(value, |(_, value)| value)
        .to_owned()
}
fn literal_value(literal: &ExprLiteral) -> Option<String> {
    match literal {
        ExprLiteral::String(value) => Some(format!("string:{value}")),
        ExprLiteral::Bool(value) => Some(format!("bool:{value}")),
        ExprLiteral::Number(value) => Some(format!("number:{value}")),
        ExprLiteral::Null => Some("null".into()),
        _ => None,
    }
}
fn pattern_value(pattern: &str, ty: &IrType, semantic: &SemanticContext) -> Option<String> {
    if let IrType::Union(variants) = ty {
        let values: BTreeSet<_> = variants
            .iter()
            .filter_map(|ty| pattern_value(pattern, ty, semantic))
            .collect();
        return (values.len() == 1).then(|| values.into_iter().next().expect("one pattern"));
    }
    let parsed = parse_expression(pattern).ok();
    match (ty, parsed.as_ref()) {
        (
            IrType::Primitive(IrPrimitiveType::Bool),
            Some(Expr::Literal(literal @ ExprLiteral::Bool(_))),
        )
        | (
            IrType::Primitive(IrPrimitiveType::String) | IrType::LiteralString(_),
            Some(Expr::Literal(literal @ ExprLiteral::String(_))),
        )
        | (
            IrType::Primitive(IrPrimitiveType::Int | IrPrimitiveType::Float),
            Some(Expr::Literal(literal @ ExprLiteral::Number(_))),
        )
        | (
            IrType::Primitive(IrPrimitiveType::Null),
            Some(Expr::Literal(literal @ ExprLiteral::Null)),
        ) => literal_value(literal),
        (
            IrType::Ref(name),
            Some(Expr::Literal(ExprLiteral::Ident(value) | ExprLiteral::String(value))),
        ) if semantic.schemas.enums.contains_key(name) => Some(format!("enum:{value}")),
        (IrType::Ref(name), _) if name == pattern && semantic.schemas.class_exists(name) => {
            Some(format!("class:{name}"))
        }
        (
            IrType::AgentRef(_),
            Some(Expr::Literal(ExprLiteral::Ident(value) | ExprLiteral::String(value))),
        ) => Some(format!("agent:{value}")),
        (IrType::Optional(inner), _) => {
            use crate::case_pattern::{optional_presence, PresencePattern};
            match optional_presence(ty, pattern) {
                Some(PresencePattern::Absent) => Some("null".into()),
                Some(PresencePattern::Present) => Some("Some".into()),
                None if matches!(parsed, Some(Expr::Literal(ExprLiteral::Null))) => {
                    Some("null".into())
                }
                None => pattern_value(pattern, inner, semantic),
            }
        }
        _ => None,
    }
}
fn selector_key(expr: &Expr, bindings: &Bindings) -> String {
    fn renamed(expr: &Expr, bindings: &Bindings) -> Expr {
        let mut result = expr.clone();
        match &mut result {
            Expr::Literal(ExprLiteral::Ident(name)) => {
                if let Some(binding) = bindings.get(name) {
                    *name = binding.identity.clone();
                }
            }
            Expr::Path(path) => {
                if let Some(binding) = bindings.get(&path[0]) {
                    path[0] = binding.identity.clone();
                }
            }
            Expr::Index { target, key } => {
                **target = renamed(target, bindings);
                **key = renamed(key, bindings);
            }
            Expr::Array(items) => {
                for item in items {
                    *item = renamed(item, bindings);
                }
            }
            Expr::Object(fields) => {
                for field in fields {
                    field.value = renamed(&field.value, bindings);
                }
            }
            Expr::Unary { expr, .. } => **expr = renamed(expr, bindings),
            Expr::Binary { left, right, .. } => {
                **left = renamed(left, bindings);
                **right = renamed(right, bindings);
            }
            Expr::Call { args, .. } => {
                for arg in args {
                    *arg = renamed(arg, bindings);
                }
            }
            Expr::Query {
                guard: Some(guard), ..
            } => **guard = renamed(guard, bindings),
            _ => {}
        }
        result
    }
    renamed(expr, bindings).to_snapshot()
}
fn ready(expr: &Expr, bindings: &Bindings) -> Condition {
    if environment::observed_operation(expr).is_some() {
        // Terminal observation waits for settlement in the runtime. It does
        // not require the operation's successful value.
        return Condition::Yes;
    }
    let root = match expr {
        Expr::Literal(ExprLiteral::Ident(name)) => Some(name),
        Expr::Path(path) => path.first(),
        _ => None,
    };
    let own = root
        .and_then(|root| bindings.get(root))
        .and_then(|binding| binding.outcome)
        .map_or(Condition::Yes, successful);
    own.and(Condition::All(
        expr.children()
            .iter()
            .map(|child| ready(child, bindings))
            .collect(),
    ))
}
fn span(statement: &BodyStmt) -> SourceSpan {
    match statement {
        BodyStmt::Composition(composition) => composition.span(),
        BodyStmt::Effect(effect) => effect.span,
        BodyStmt::Record(record) => record.span,
        BodyStmt::After(after) => after.span,
        BodyStmt::Case(case) => case.span,
        BodyStmt::Region(region) => region.span,
        BodyStmt::Terminal(terminal) => terminal.span,
        BodyStmt::Done { span, .. }
        | BodyStmt::Cancel { span, .. }
        | BodyStmt::Milestone { span, .. }
        | BodyStmt::Redact { span, .. }
        | BodyStmt::Declassify { span, .. } => *span,
    }
}

#[cfg(test)]
mod tests;
