//! One lexical body, with forward results represented by binding occurrences.
//! Calls reference summaries rather than duplicating a callee's statement tree.
use super::*;
use crate::body::{AfterPredicate, BodyStmt, CompositionExpr, CompositionStmt};
use std::rc::Rc;

type Environment = BTreeMap<String, usize>;
#[derive(Clone)]
pub(super) struct Expression {
    pub value: Expr,
    pub span: SourceSpan,
    environment: Environment,
}
#[derive(Clone)]
pub(super) struct Call {
    pub id: usize,
    pub name: String,
    pub span: SourceSpan,
    pub arguments: Vec<Expression>,
}
#[derive(Clone)]
enum Cell {
    Ready(Value),
    Call(Call),
    Alias(Expression, Option<String>),
}
pub(super) struct Consumption {
    pub value: Expression,
    pub binding: String,
    pub span: SourceSpan,
}
#[derive(Default)]
pub(super) struct Graph {
    cells: Vec<Cell>,
    pub calls: Vec<Call>,
    pub consumes: Vec<Consumption>,
    returns: Vec<Expression>,
    pub flow: flow::Flow,
}
impl Graph {
    pub fn build(
        statements: &[BodyStmt],
        inputs: impl IntoIterator<Item = (String, Value)>,
    ) -> Self {
        let mut graph = Self::default();
        let environment = inputs
            .into_iter()
            .map(|(name, value)| {
                let id = graph.cells.len();
                graph.cells.push(Cell::Ready(value));
                (name, id)
            })
            .collect();
        graph.block(statements, environment);
        graph
    }
    fn expression(value: &CompositionExpr, environment: &Environment) -> Expression {
        Expression {
            value: value.expr.clone(),
            span: value.span,
            environment: environment.clone(),
        }
    }
    fn source(source: &str, span: SourceSpan, environment: &Environment) -> Expression {
        // The shared body parser and type phase own expression syntax. Keep an
        // unparsed source unresolved for direct analysis callers as well.
        Expression {
            value: parse_expression(source).unwrap_or_else(|_| Expr::Path(Vec::new())),
            span,
            environment: environment.clone(),
        }
    }
    fn block(&mut self, statements: &[BodyStmt], mut environment: Environment) {
        for statement in statements {
            if let Some(name) = action_plan::binding_name(statement) {
                let id = self.cells.len();
                self.cells.push(Cell::Ready(Rc::new(Shape::Unknown {
                    span: action_plan::span(statement),
                    reason: "this local has no fact-identity result contract",
                })));
                environment.insert(name.to_owned(), id);
            }
        }
        for statement in statements {
            let local = action_plan::binding_name(statement)
                .and_then(|name| environment.get(name))
                .copied();
            let statement = match statement {
                BodyStmt::Composition(CompositionStmt::Then { operation, .. }) => {
                    operation.as_ref()
                }
                other => other,
            };
            self.flow.observe(statement);
            match statement {
                BodyStmt::Composition(CompositionStmt::Call {
                    name,
                    name_span,
                    arguments,
                    ..
                }) => {
                    let call = Call {
                        id: self.calls.len(),
                        name: name.clone(),
                        span: *name_span,
                        arguments: arguments
                            .iter()
                            .map(|value| Self::expression(value, &environment))
                            .collect(),
                    };
                    if let Some(id) = local {
                        self.cells[id] = Cell::Call(call.clone());
                    }
                    self.calls.push(call);
                }
                BodyStmt::Composition(CompositionStmt::Return(value)) => {
                    self.returns.push(Self::expression(value, &environment))
                }
                BodyStmt::Done { binding, span, .. } => self.consumes.push(Consumption {
                    value: Expression {
                        value: Expr::Path(vec![binding.clone()]),
                        span: *span,
                        environment: environment.clone(),
                    },
                    binding: binding.clone(),
                    span: *span,
                }),
                BodyStmt::Effect(effect) => {
                    if let Some(id) = local {
                        self.cells[id] = Cell::Ready(shape::data(
                            effect.span,
                            "operation payloads do not carry admitted fact identity",
                        ));
                    }
                }
                BodyStmt::After(after) => {
                    let mut child = environment.clone();
                    if let Some(alias) = &after.alias {
                        let id = self.cells.len();
                        self.cells
                            .push(if after.predicate == AfterPredicate::Succeeds {
                                Cell::Alias(
                                    Self::source(&after.binding, after.span, &environment),
                                    None,
                                )
                            } else {
                                Cell::Ready(Rc::new(Shape::Unknown {
                                    span: after.span,
                                    reason: "a non-success outcome is not an admitted fact",
                                }))
                            });
                        child.insert(alias.clone(), id);
                    }
                    self.block(&after.body, child);
                }
                BodyStmt::Case(case) => {
                    for branch in &case.branches {
                        let mut child = environment.clone();
                        if let Some(alias) = &branch.binding {
                            let id = self.cells.len();
                            self.cells.push(Cell::Alias(
                                Self::source(&case.scrutinee, case.span, &environment),
                                Some(branch.pattern.clone()),
                            ));
                            child.insert(alias.clone(), id);
                        }
                        self.block(&branch.body, child);
                    }
                }
                BodyStmt::Region(region) => {
                    self.block(&region.body, environment.clone());
                    let mut lapse = environment.clone();
                    if let Some(name) = &region.lapse_binding {
                        let id = self.cells.len();
                        self.cells.push(Cell::Ready(Rc::new(Shape::Unknown {
                            span: region.span,
                            reason: "a lapse report is not an admitted fact",
                        })));
                        lapse.insert(name.clone(), id);
                    }
                    self.block(&region.lapse_body, lapse);
                }
                _ => {}
            }
        }
    }
    pub fn resolve(&self, summaries: &BTreeMap<String, Summary>) -> Values {
        fn dependencies(expression: &Expression) -> BTreeSet<usize> {
            let mut pending = vec![&expression.value];
            let mut found = BTreeSet::new();
            while let Some(expr) = pending.pop() {
                let name = match expr {
                    Expr::Literal(ExprLiteral::Ident(name)) => Some(name),
                    Expr::Path(path) => path.first(),
                    _ => None,
                };
                if let Some(id) = name.and_then(|name| expression.environment.get(name)) {
                    found.insert(*id);
                }
                pending.extend(expr.children());
            }
            found
        }
        let mut values = Values {
            cells: vec![None; self.cells.len()],
            call_order: Vec::new(),
        };
        let mut active = vec![false; self.cells.len()];
        for start in 0..self.cells.len() {
            let mut pending = vec![(start, false)];
            while let Some((id, ready)) = pending.pop() {
                if values.cells[id].is_some() {
                    active[id] = false;
                    continue;
                }
                if !ready {
                    if active[id] {
                        values.cells[id] = Some(Rc::new(Shape::Unknown {
                            span: self.cell_span(id),
                            reason: "cyclic value dependencies cannot establish fact identity",
                        }));
                        continue;
                    }
                    active[id] = true;
                    pending.push((id, true));
                    let needs = match &self.cells[id] {
                        Cell::Ready(_) => BTreeSet::new(),
                        Cell::Alias(expr, _) => dependencies(expr),
                        Cell::Call(call) => call.arguments.iter().flat_map(dependencies).collect(),
                    };
                    pending.extend(needs.into_iter().map(|id| (id, false)));
                    continue;
                }
                let value = match &self.cells[id] {
                    Cell::Ready(value) => value.clone(),
                    Cell::Alias(expr, pattern) => {
                        let value = values.expression(expr);
                        pattern.as_ref().map_or(value.clone(), |pattern| {
                            shape::narrow(value, pattern, expr.span)
                        })
                    }
                    Cell::Call(call) => {
                        values.call_order.push(call.id);
                        let summary = &summaries[&call.name];
                        let arguments: Vec<_> = call
                            .arguments
                            .iter()
                            .map(|expr| values.expression(expr))
                            .collect();
                        shape::substitute(&summary.result, &arguments)
                    }
                };
                values.cells[id] = Some(value);
                active[id] = false;
            }
        }
        values
    }
    fn cell_span(&self, id: usize) -> SourceSpan {
        match &self.cells[id] {
            Cell::Call(call) => call.span,
            Cell::Alias(expr, _) => expr.span,
            Cell::Ready(_) => SourceSpan { start: 0, end: 0 },
        }
    }
    pub fn result(&self, values: &Values) -> Value {
        shape::alternatives(self.returns.iter().map(|expr| values.expression(expr)))
    }
}
pub(super) struct Values {
    cells: Vec<Option<Value>>,
    pub call_order: Vec<usize>,
}
impl Values {
    pub fn expression(&self, expression: &Expression) -> Value {
        self.evaluate(&expression.value, expression.span, &expression.environment)
    }
    fn binding(&self, name: &str, span: SourceSpan, environment: &Environment) -> Value {
        environment
            .get(name)
            .and_then(|id| self.cells[*id].clone())
            .unwrap_or_else(|| {
                Rc::new(Shape::Unknown {
                    span,
                    reason: "this binding has no resolved value origin",
                })
            })
    }
    fn evaluate(&self, expr: &Expr, span: SourceSpan, environment: &Environment) -> Value {
        let evaluate = |expr| self.evaluate(expr, span, environment);
        match expr {
            Expr::Literal(ExprLiteral::Ident(name)) if environment.contains_key(name) => {
                self.binding(name, span, environment)
            }
            Expr::Literal(ExprLiteral::Null) => shape::absent(span),
            Expr::Literal(ExprLiteral::String(value) | ExprLiteral::Ident(value)) => {
                shape::string(value, span)
            }
            Expr::Literal(_) => shape::data(span, "a literal is an ordinary value"),
            Expr::Path(path) => {
                let Some((name, fields)) = path.split_first() else {
                    return Rc::new(Shape::Unknown {
                        span,
                        reason: "the value expression is unresolved",
                    });
                };
                fields
                    .iter()
                    .fold(self.binding(name, span, environment), |value, field| {
                        shape::select(value, shape::string(field, span), span)
                    })
            }
            Expr::Object(fields) => Rc::new(Shape::Object {
                fields: fields
                    .iter()
                    .map(|field| (field.key.clone(), evaluate(&field.value)))
                    .collect(),
                span,
            }),
            Expr::Array(items) => Rc::new(Shape::Array {
                items: items.iter().map(evaluate).collect(),
                span,
            }),
            Expr::Index { target, key } => shape::select(evaluate(target), evaluate(key), span),
            Expr::Query { .. } => Rc::new(Shape::Unknown {
                span,
                reason: "query evidence has no resolved fact-admission contract",
            }),
            _ => shape::data(span, "a computed value is not the original fact"),
        }
    }
}
