//! Managed argument evaluation over the compiler's hygienic binding sites.
//! This produces a selected call's local capture, never an effect admission or
//! a proof that its containing graph is selected, authorized, or closed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use whipplescript_parser::action_plan::{ActionPlan, BindingId, Environment, NodeId, NodeKind};
use whipplescript_parser::{BinaryOp, Expr, ExprLiteral, QueryKind, SourceSpan, UnaryOp};
use whipplescript_store::projection_prefix::{ProjectionEffect, ProjectionFact};

use super::journal::{CallCapture, Frame, Journal};
use super::CauseId;
mod indexing;
pub mod subjects;
use crate::rule_lowering::{eval_binary_values, eval_expr_literal, eval_value_call, EvalValue};
pub use subjects::{FactSubject, FactSubjects};

/// References, not authority or copied facts. The caller retains the owning
/// ledger's fact/resource/IFC obligations when it supplies or consumes a value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueSource {
    Fact {
        fact_id: String,
        admission_event: String,
    },
    Operation {
        operation_id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    Fact,
    Effect,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationMember {
    Fact {
        fact_id: String,
        admission_event: String,
    },
    Effect {
        effect_id: String,
    },
}

/// One result-bearing read over one captured projection. An empty `members`
/// set is positive absence evidence at `frontier`; a nonempty set preserves the
/// exact membership that made `count`, `exists`, or `empty` evaluate as it did.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryObservation {
    pub frontier: i64,
    pub kind: ObservationKind,
    pub head: String,
    pub guard_json: Option<String>,
    pub members: BTreeSet<ObservationMember>,
}

pub type Validity = BTreeSet<QueryObservation>;

#[derive(Clone, Copy)]
pub struct QueryContext<'a> {
    pub frontier: i64,
    pub facts: &'a [ProjectionFact],
    pub effects: &'a [ProjectionEffect],
    pub views: &'a BTreeMap<String, whipplescript_parser::action_plan::resolved::TypedView>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Argument {
    #[serde(default)]
    pub subjects: FactSubjects,
    pub value: Value,
    pub sources: BTreeSet<ValueSource>,
    #[serde(default)]
    pub validity: Validity,
}

impl From<Value> for Argument {
    fn from(value: Value) -> Self {
        Self {
            value,
            sources: BTreeSet::new(),
            subjects: FactSubjects::new(),
            validity: Validity::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Slot {
    Ready(Argument),
    Pending,
    Failed(BTreeSet<CauseId>),
}

pub type Bindings = BTreeMap<BindingId, Slot>;
pub type OutcomeContext<'a> = &'a dyn Fn(BindingId) -> Evaluation;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationError {
    pub message: String,
    pub waiting: BTreeSet<BindingId>,
    pub causes: BTreeSet<CauseId>,
}

impl From<String> for EvaluationError {
    fn from(message: String) -> Self {
        Self {
            message,
            waiting: BTreeSet::new(),
            causes: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum State {
    Ready(Value),
    /// Successful optional absence. It may become null at a value boundary;
    /// pending never may. Checked field/type contracts precede this evaluator.
    Absent,
    Blocked {
        waiting: BTreeSet<BindingId>,
        causes: BTreeSet<CauseId>,
    },
    Invalid(Box<EvaluationError>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evaluation {
    pub subjects: FactSubjects,
    pub state: State,
    pub reads: BTreeSet<BindingId>,
    pub sources: BTreeSet<ValueSource>,
    pub validity: Validity,
}

impl Evaluation {
    fn scalar(value: EvalValue) -> Self {
        Self {
            state: match value {
                EvalValue::Json(value) => State::Ready(value),
                EvalValue::Missing => State::Absent,
                EvalValue::Error(message) => State::Invalid(Box::new(message.into())),
            },
            reads: BTreeSet::new(),
            sources: BTreeSet::new(),
            subjects: FactSubjects::new(),
            validity: Validity::new(),
        }
    }

    pub(super) fn invalid(message: &str) -> Self {
        Self::scalar(EvalValue::error(message))
    }
}

/// Strict expressions observe every operand, retaining independent waits and
/// original failure identities. No blocked operand reaches a scalar operator.
pub(super) fn strict(
    inputs: Vec<Evaluation>,
    apply: impl FnOnce(Vec<Value>) -> EvalValue,
) -> Evaluation {
    let mut reads = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut validity = Validity::new();
    let mut waiting = BTreeSet::new();
    let mut causes = BTreeSet::new();
    let mut error = None;
    let mut values = Vec::new();
    let mut blocked = false;
    for input in inputs {
        reads.extend(input.reads);
        sources.extend(input.sources);
        validity.extend(input.validity);
        match input.state {
            State::Ready(value) => values.push(value),
            State::Absent => values.push(Value::Null),
            State::Blocked {
                waiting: waits,
                causes: failures,
            } => {
                blocked = true;
                waiting.extend(waits);
                causes.extend(failures);
            }
            State::Invalid(issue) => {
                waiting.extend(issue.waiting);
                causes.extend(issue.causes);
                error.get_or_insert(issue.message);
            }
        }
    }
    let state = if let Some(message) = error {
        State::Invalid(Box::new(EvaluationError {
            message,
            waiting,
            causes,
        }))
    } else if blocked {
        State::Blocked { waiting, causes }
    } else {
        Evaluation::scalar(apply(values)).state
    };
    Evaluation {
        state,
        reads,
        sources,
        validity,
        subjects: FactSubjects::new(),
    }
}

pub(super) fn read_binding(binding: BindingId, bindings: &Bindings) -> Evaluation {
    if let Some(Slot::Ready(argument)) = bindings.get(&binding) {
        if let Err(message) = subjects::validate(argument) {
            return Evaluation {
                state: State::Invalid(Box::new(message.into())),
                reads: BTreeSet::from([binding]),
                sources: argument.sources.clone(),
                validity: argument.validity.clone(),
                subjects: FactSubjects::new(),
            };
        }
    }
    let subjects = match bindings.get(&binding) {
        Some(Slot::Ready(argument)) => argument.subjects.clone(),
        _ => FactSubjects::new(),
    };
    let (state, sources, validity) = match bindings.get(&binding) {
        Some(Slot::Ready(argument)) => (
            State::Ready(argument.value.clone()),
            argument.sources.clone(),
            argument.validity.clone(),
        ),
        Some(Slot::Failed(causes)) if !causes.is_empty() => (
            State::Blocked {
                waiting: BTreeSet::new(),
                causes: causes.clone(),
            },
            BTreeSet::new(),
            Validity::new(),
        ),
        Some(Slot::Failed(_)) => (
            State::Invalid(Box::new(
                "failed action value has no originating cause"
                    .to_owned()
                    .into(),
            )),
            BTreeSet::new(),
            Validity::new(),
        ),
        Some(Slot::Pending) | None => (
            State::Blocked {
                waiting: BTreeSet::from([binding]),
                causes: BTreeSet::new(),
            },
            BTreeSet::new(),
            Validity::new(),
        ),
    };
    Evaluation {
        state,
        reads: BTreeSet::from([binding]),
        sources,
        validity,
        subjects,
    }
}

pub fn evaluate(expr: &Expr, environment: &Environment, bindings: &Bindings) -> Evaluation {
    evaluate_inner(expr, environment, bindings, None, None, None)
}

pub fn evaluate_with_queries(
    expr: &Expr,
    environment: &Environment,
    bindings: &Bindings,
    queries: QueryContext<'_>,
) -> Evaluation {
    evaluate_inner(expr, environment, bindings, Some(queries), None, None)
}

pub(crate) fn evaluate_with_context(
    expr: &Expr,
    environment: &Environment,
    bindings: &Bindings,
    queries: Option<QueryContext<'_>>,
    outcomes: Option<OutcomeContext<'_>>,
) -> Evaluation {
    evaluate_inner(expr, environment, bindings, queries, outcomes, None)
}

fn evaluate_inner(
    expr: &Expr,
    environment: &Environment,
    bindings: &Bindings,
    queries: Option<QueryContext<'_>>,
    outcomes: Option<OutcomeContext<'_>>,
    projection: Option<&Value>,
) -> Evaluation {
    let eval = |expr| evaluate_inner(expr, environment, bindings, queries, outcomes, projection);
    match expr {
        Expr::Literal(ExprLiteral::Ident(name)) => {
            if let Some(value) = projection.and_then(|value| value.get(name)) {
                Evaluation::scalar(EvalValue::Json(value.clone()))
            } else if let Some(binding) = environment.get(name) {
                read_binding(*binding, bindings)
            } else {
                Evaluation::scalar(EvalValue::Json(eval_expr_literal(&ExprLiteral::Ident(
                    name.clone(),
                ))))
            }
        }
        Expr::Literal(literal) => Evaluation::scalar(EvalValue::Json(eval_expr_literal(literal))),
        Expr::Path(path) => {
            let Some((root, fields)) = path.split_first() else {
                return Evaluation::invalid("empty managed value path");
            };
            if let Some(value) = projection.and_then(|value| value.get(root)) {
                let mut current = Some(value);
                for field in fields {
                    current = current.and_then(|value| value.get(field));
                }
                return current.cloned().map_or_else(
                    || Evaluation::scalar(EvalValue::Missing),
                    |value| Evaluation::scalar(EvalValue::Json(value)),
                );
            }
            let Some(binding) = environment.get(root) else {
                return Evaluation::invalid("unknown managed value binding");
            };
            let mut result = read_binding(*binding, bindings);
            if let State::Ready(value) = &result.state {
                let mut current = Some(value);
                for field in fields {
                    current = current.and_then(|value| value.get(field));
                }
                result.state = current.cloned().map_or(State::Absent, State::Ready);
            }
            let pointer: String = fields
                .iter()
                .map(|field| format!("/{}", subjects::token(field)))
                .collect();
            result.subjects = if matches!(result.state, State::Ready(_)) {
                subjects::selected(&result.subjects, &pointer)
            } else {
                FactSubjects::new()
            };
            result
        }
        Expr::Array(items) => {
            let values: Vec<_> = items.iter().map(eval).collect();
            let subjects = values
                .iter()
                .enumerate()
                .flat_map(|(index, value)| subjects::nested(&value.subjects, &index.to_string()))
                .collect();
            let mut result = strict(values, |values| EvalValue::Json(Value::Array(values)));
            if matches!(result.state, State::Ready(_)) {
                result.subjects = subjects;
            }
            result
        }
        Expr::Object(fields) => {
            let inputs: Vec<_> = fields.iter().map(|field| eval(&field.value)).collect();
            let mut subjects = FactSubjects::new();
            for (field, value) in fields.iter().zip(&inputs) {
                let prefix = format!("/{}", subjects::token(&field.key));
                let subtree = format!("{prefix}/");
                subjects.retain(|path, _| path != &prefix && !path.starts_with(&subtree));
                subjects.extend(subjects::nested(&value.subjects, &field.key));
            }
            let mut result = strict(inputs, |values| {
                EvalValue::Json(Value::Object(
                    fields
                        .iter()
                        .map(|field| field.key.clone())
                        .zip(values)
                        .collect(),
                ))
            });
            if matches!(result.state, State::Ready(_)) {
                result.subjects = subjects;
            }
            result
        }
        Expr::Index { target, key } => indexing::evaluate(eval(target), eval(key)),
        Expr::Unary {
            op: UnaryOp::Not,
            expr,
        } => strict(vec![eval(expr)], |values| match values.as_slice() {
            [Value::Bool(value)] => EvalValue::Json(Value::Bool(!value)),
            _ => EvalValue::error("managed negation requires a boolean"),
        }),
        Expr::Binary {
            op: op @ (BinaryOp::And | BinaryOp::Or),
            left,
            right,
        } => {
            let mut left = eval(left);
            left.subjects.clear();
            match &left.state {
                State::Ready(Value::Bool(value)) if *value == (*op == BinaryOp::Or) => left,
                State::Ready(Value::Bool(_)) => {
                    strict(vec![left, eval(right)], |values| match values.as_slice() {
                        [_, Value::Bool(value)] => EvalValue::Json(Value::Bool(*value)),
                        _ => EvalValue::error("managed boolean operator requires booleans"),
                    })
                }
                State::Blocked { .. } | State::Invalid(_) => left,
                _ => Evaluation {
                    state: State::Invalid(Box::new(
                        "managed boolean operator requires booleans"
                            .to_owned()
                            .into(),
                    )),
                    ..left
                },
            }
        }
        Expr::Binary { op, left, right } => strict(vec![eval(left), eval(right)], |values| {
            let mut values = values.into_iter();
            eval_binary_values(
                *op,
                EvalValue::Json(values.next().expect("left operand")),
                EvalValue::Json(values.next().expect("right operand")),
                None,
                None,
            )
        }),
        Expr::Call { name, args }
            if matches!(name.as_str(), "count" | "exists" | "empty")
                && matches!(args.as_slice(), [Expr::Query { .. }]) =>
        {
            let mut result = eval(&args[0]);
            if let State::Ready(Value::Number(number)) = &result.state {
                let Some(count) = number.as_i64() else {
                    result.state = State::Invalid(Box::new(
                        "managed query count exceeds the runtime range"
                            .to_owned()
                            .into(),
                    ));
                    return result;
                };
                result.state = State::Ready(match name.as_str() {
                    "count" => Value::Number(count.into()),
                    "exists" => Value::Bool(count > 0),
                    _ => Value::Bool(count == 0),
                });
            }
            result
        }
        Expr::Call { name, args } if name == "outcome" => {
            let [argument] = args.as_slice() else {
                return Evaluation::invalid("managed outcome requires one named operation");
            };
            let operation = match argument {
                Expr::Literal(ExprLiteral::Ident(name)) => Some(name.as_str()),
                Expr::Path(path) if path.len() == 1 => Some(path[0].as_str()),
                _ => None,
            };
            let Some(binding) = operation.and_then(|name| environment.get(name)).copied() else {
                return Evaluation::invalid("managed outcome requires a known named operation");
            };
            outcomes.map_or_else(
                || Evaluation::invalid("managed outcome requires operation observations"),
                |observe| observe(binding),
            )
        }
        Expr::Call { name, args }
            if queries.is_some_and(|context| context.views.contains_key(name)) =>
        {
            let context = queries.expect("view guard established query context");
            let view = &context.views[name];
            if args.len() != view.parameters.len() {
                return Evaluation::invalid("captured parameterized view arity is invalid");
            }
            let evaluated: Vec<_> = args.iter().map(eval).collect();
            let joined = strict(evaluated.clone(), |_| EvalValue::Json(Value::Null));
            if !matches!(joined.state, State::Ready(_)) {
                return joined;
            }
            let mut nested_environment = environment.clone();
            let mut nested_bindings = bindings.clone();
            let mut remap = BTreeMap::new();
            let mut next = nested_bindings
                .keys()
                .map(|binding| binding.0)
                .max()
                .unwrap_or(0)
                .saturating_add(1);
            for (name, value) in view.parameters.iter().zip(evaluated) {
                let binding = BindingId(next);
                next = next.saturating_add(1);
                nested_environment.insert(name.clone(), binding);
                let original_reads = value.reads.clone();
                nested_bindings.insert(
                    binding,
                    Slot::Ready(Argument {
                        value: match value.state {
                            State::Ready(value) => value,
                            State::Absent => Value::Null,
                            _ => unreachable!("joined view arguments are ready"),
                        },
                        sources: value.sources,
                        subjects: value.subjects,
                        validity: value.validity,
                    }),
                );
                remap.insert(binding, original_reads);
            }
            let mut result = evaluate_inner(
                &view.expression,
                &nested_environment,
                &nested_bindings,
                Some(context),
                outcomes,
                projection,
            );
            let synthetic: Vec<_> = result
                .reads
                .iter()
                .filter(|binding| remap.contains_key(binding))
                .copied()
                .collect();
            for binding in synthetic {
                result.reads.remove(&binding);
                result
                    .reads
                    .extend(remap.remove(&binding).unwrap_or_default());
            }
            result
        }
        Expr::Call { name, args } => strict(args.iter().map(eval).collect(), |values| {
            if values.len() != 1 {
                return EvalValue::error("managed expression function requires one argument");
            }
            eval_value_call(
                name,
                EvalValue::Json(values.into_iter().next().expect("one argument")),
            )
        }),
        Expr::Query { kind, head, guard } => evaluate_query(
            *kind,
            head,
            guard.as_deref(),
            environment,
            bindings,
            queries,
            outcomes,
        ),
    }
}

fn evaluate_query(
    kind: QueryKind,
    head: &str,
    guard: Option<&Expr>,
    environment: &Environment,
    bindings: &Bindings,
    queries: Option<QueryContext<'_>>,
    outcomes: Option<OutcomeContext<'_>>,
) -> Evaluation {
    let Some(queries) = queries else {
        return Evaluation::invalid("managed query requires a captured projection");
    };
    if queries.frontier < 0 || head.trim().is_empty() {
        return Evaluation::invalid("managed query has an invalid projection identity");
    }
    let mut candidates = Vec::<(ObservationMember, Value, Validity)>::new();
    match kind {
        QueryKind::Fact => {
            for fact in queries.facts.iter().filter(|fact| fact.name == head.trim()) {
                if fact.fact_id.is_empty() || fact.source_event_id.is_empty() {
                    return Evaluation::invalid(
                        "managed fact query member has no durable identity",
                    );
                }
                let Ok(value) = serde_json::from_str(&fact.value_json) else {
                    return Evaluation::invalid("managed fact query member has invalid value JSON");
                };
                let validity = match fact.validity_json.as_deref() {
                    Some(raw) => match serde_json::from_str(raw) {
                        Ok(validity) => validity,
                        Err(_) => {
                            return Evaluation::invalid(
                                "managed fact query member has invalid validity JSON",
                            )
                        }
                    },
                    None => Validity::new(),
                };
                candidates.push((
                    ObservationMember::Fact {
                        fact_id: fact.fact_id.clone(),
                        admission_event: fact.source_event_id.clone(),
                    },
                    value,
                    validity,
                ));
            }
        }
        QueryKind::Effect => {
            let selected_kind = head
                .trim()
                .strip_prefix("kind ")
                .map(str::trim)
                .filter(|value| !value.is_empty());
            for effect in queries
                .effects
                .iter()
                .filter(|effect| selected_kind.is_none_or(|kind| effect.kind == kind))
            {
                if effect.effect_id.is_empty() {
                    return Evaluation::invalid(
                        "managed effect query member has no durable identity",
                    );
                }
                candidates.push((
                    ObservationMember::Effect {
                        effect_id: effect.effect_id.clone(),
                    },
                    serde_json::json!({
                        "kind": effect.kind,
                        "target": effect.target,
                        "status": effect.status,
                        "profile": effect.profile,
                    }),
                    Validity::new(),
                ));
            }
        }
    }
    let mut members = BTreeSet::new();
    let mut guards = Vec::new();
    let mut inherited = Validity::new();
    for (member, value, validity) in candidates {
        inherited.extend(validity);
        if let Some(guard) = guard {
            let mut evaluated = evaluate_inner(
                guard,
                environment,
                bindings,
                Some(queries),
                outcomes,
                Some(&value),
            );
            if let State::Ready(value) = &evaluated.state {
                if !value.is_boolean() {
                    evaluated.state = State::Invalid(Box::new(
                        "managed query predicate requires a boolean"
                            .to_owned()
                            .into(),
                    ));
                }
            }
            if matches!(evaluated.state, State::Ready(Value::Bool(true))) {
                members.insert(member);
            }
            guards.push(evaluated);
        } else {
            members.insert(member);
        }
    }
    let mut result = strict(guards, |_| EvalValue::Json(Value::Null));
    if matches!(result.state, State::Ready(_)) {
        result.validity.extend(inherited);
        let Ok(count) = i64::try_from(members.len()) else {
            return Evaluation::invalid("managed query result exceeds integer range");
        };
        result.state = State::Ready(Value::Number(count.into()));
        result.validity.insert(QueryObservation {
            frontier: queries.frontier,
            kind: match kind {
                QueryKind::Fact => ObservationKind::Fact,
                QueryKind::Effect => ObservationKind::Effect,
            },
            head: head.trim().to_owned(),
            guard_json: guard.map(|guard| {
                serde_json::to_string(guard).expect("expression serialization is infallible")
            }),
            members,
        });
    }
    result
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCall {
    pub capture: CallCapture,
    pub parameters: BTreeMap<BindingId, Slot>,
    pub fresh: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallObstruction {
    pub span: SourceSpan,
    pub evaluation: Evaluation,
}

/// Evaluate a call ALREADY selected by the scope driver. An existing capture
/// wins before reading live arguments/barriers. No source execution path is
/// enabled by this function, and the returned delta still needs guarded commit.
pub fn prepare_call(
    plan: &ActionPlan,
    node: NodeId,
    bindings: &Bindings,
    journal: &Journal,
    frame: &Frame,
    frontier: i64,
) -> Result<PreparedCall, Box<CallObstruction>> {
    prepare_call_with_queries(plan, node, bindings, journal, frame, frontier, (None, None))
}

pub(crate) fn prepare_call_with_queries(
    plan: &ActionPlan,
    node: NodeId,
    bindings: &Bindings,
    journal: &Journal,
    frame: &Frame,
    frontier: i64,
    observations: (Option<QueryContext<'_>>, Option<OutcomeContext<'_>>),
) -> Result<PreparedCall, Box<CallObstruction>> {
    let (queries, outcomes) = observations;
    let node_id = node;
    let node = &plan.nodes[node.0];
    let obstruction = |evaluation| {
        Box::new(CallObstruction {
            span: node.span,
            evaluation,
        })
    };
    let NodeKind::Call { scope, arguments } = &node.kind else {
        let invalid = Evaluation::invalid("argument capture requires an action call");
        // MUTATION-SUCCESS-EXPR: Ok(PreparedCall { capture: CallCapture { call: node_id.0 as u64, arguments: Vec::new(), reads: BTreeSet::new(), frontier }, parameters: BTreeMap::new(), fresh: true })
        return Err(obstruction(invalid));
    };
    let scope = &plan.scopes[scope.0];
    let saved = journal
        .calls(frame)
        .and_then(|calls| calls.get(&(node_id.0 as u64)));
    let fresh = saved.is_none();
    let capture = if let Some(saved) = saved {
        saved.clone()
    } else {
        let barrier = node.order_after.map(|before| {
            plan.nodes[before.0].result.map_or_else(
                || Evaluation::invalid("action success barrier has no result slot"),
                |binding| read_binding(binding, bindings),
            )
        });
        if let Some(barrier) = &barrier {
            if !matches!(barrier.state, State::Ready(_)) {
                return Err(obstruction(barrier.clone()));
            }
        }
        let evaluated: Vec<_> = arguments
            .iter()
            .map(|argument| {
                evaluate_with_context(
                    &argument.value.expr,
                    &argument.environment,
                    bindings,
                    queries,
                    outcomes,
                )
            })
            .collect();
        let combined = strict(evaluated.clone(), |values| {
            EvalValue::Json(Value::Array(values))
        });
        if !matches!(combined.state, State::Ready(_)) {
            let span = evaluated
                .iter()
                .position(|value| matches!(value.state, State::Invalid(_)))
                .map_or(node.span, |index| arguments[index].value.span);
            return Err(Box::new(CallObstruction {
                span,
                evaluation: combined,
            }));
        }
        let mut reads = combined.reads;
        if let Some(barrier) = barrier {
            reads.extend(barrier.reads);
        }
        let arguments = evaluated
            .into_iter()
            .map(|value| Argument {
                value: match value.state {
                    State::Ready(value) => value,
                    State::Absent => Value::Null,
                    _ => unreachable!("strict arguments checked"),
                },
                sources: value.sources,
                subjects: value.subjects,
                validity: value.validity,
            })
            .collect();
        CallCapture {
            call: node_id.0 as u64,
            arguments,
            reads: reads.into_iter().map(|binding| binding.0 as u64).collect(),
            frontier,
        }
    };
    if capture.arguments.len() != scope.parameters.len() {
        return Err(obstruction(Evaluation::invalid(
            "captured action arity differs from its scope",
        )));
    }
    let parameters = scope
        .parameters
        .iter()
        .copied()
        .zip(capture.arguments.iter().cloned().map(Slot::Ready))
        .collect();
    Ok(PreparedCall {
        capture,
        parameters,
        fresh,
    })
}

#[cfg(test)]
mod tests;
