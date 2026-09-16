//! Derived may-provenance, not readiness, validity or an IFC permission.
//! Cells share hygienic bindings; operation transfers remain the IFC owner's job.
use super::*;
use crate::{Expr, ExprLiteral, RelatedInfo};
use std::collections::BTreeSet;

fn error(span: SourceSpan, message: String) -> Box<Diagnostic> {
    Box::new(super::error(span, message))
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Origin {
    Input(BindingId),
    Operation(NodeId),
    /// A declassification output; its schema and grant transfer belong to IFC.
    Crossing(NodeId),
    Outcome {
        observed: BindingId,
        observer: NodeId,
    },
    Lapse(NodeId),
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ValuePath {
    pub origin: Origin,
    pub fields: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Control {
    Case {
        node: NodeId,
        branch: usize,
    },
    After(NodeId),
    FailureHandler(NodeId),
    Region {
        node: NodeId,
        lapse: bool,
    },
    /// The region exited cleanly before this lexical tail was admitted.
    /// Its condition influenced selection; it is not an ongoing condition here.
    RegionExit(NodeId),
    OrderedAfter(NodeId),
    ScopeSuccess(ScopeId),
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProducedPath {
    pub node: NodeId,
    pub fields: Vec<String>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Trace {
    /// False means no potential success value, not a public constant value.
    /// True is an upper bound; it does not prove readiness or satisfiable controls.
    pub may_have_value: bool,
    pub sources: BTreeSet<ValuePath>,
    /// Typed producer boundaries traversed before alias/return expansion.
    pub produced: BTreeSet<ProducedPath>,
    pub controls: BTreeSet<Control>,
}
#[derive(Clone, Debug)]
enum Value {
    Never,
    Constant,
    /// A fact/effect query is real provenance, but this generic graph does not
    /// own its observation contract. Refuse only when a consumer traces it;
    /// merely capturing a pure view that contains a query remains valid.
    UnobservedQuery,
    Source(Origin),
    Alias(usize),
    Object(BTreeMap<String, usize>),
    Array(Vec<usize>),
    /// Pure transformations mix entire inputs, even when an output is projected.
    Mix(Vec<usize>),
    Choice(Vec<usize>),
    Select {
        target: usize,
        key: String,
    },
    DynamicSelect {
        target: usize,
        key: usize,
    },
    Produced {
        value: usize,
        node: NodeId,
    },
    Controlled {
        value: usize,
        controls: BTreeSet<Control>,
    },
}
#[derive(Clone, Debug)]
struct Cell {
    value: Value,
    span: SourceSpan,
}

pub struct Graph<'a> {
    plan: &'a ActionPlan,
    views: &'a BTreeMap<String, resolved::TypedView>,
    constants: &'a BTreeSet<String>,
    cells: Vec<Cell>,
    controls: Vec<BTreeSet<Control>>,
    returns: Vec<Vec<NodeId>>,
}
impl<'a> Graph<'a> {
    /// Constants are names established by the owning compiler's declarations.
    /// A missing lexical name is never silently promoted to a constant.
    pub fn new(
        typed: &'a resolved::TypedActionPlan,
        constants: &'a BTreeSet<String>,
    ) -> Result<Self, Box<Diagnostic>> {
        typed
            .validate_structure()
            .map_err(|message| error(SourceSpan { start: 0, end: 0 }, message))?;
        let plan = &typed.plan;
        let mut graph = Self {
            plan,
            views: &typed.views,
            constants,
            cells: plan
                .bindings
                .iter()
                .map(|binding| Cell {
                    value: Value::Never,
                    span: binding.span,
                })
                .collect(),
            controls: vec![BTreeSet::new(); plan.nodes.len()],
            returns: vec![Vec::new(); plan.scopes.len()],
        };
        graph.selections();
        for (index, node) in plan.nodes.iter().enumerate() {
            if matches!(node.kind, NodeKind::Return(_)) {
                if let Some(scope) = plan.blocks[node.block.0].scope {
                    graph.returns[scope.0].push(NodeId(index));
                }
            }
        }
        for index in 0..plan.bindings.len() {
            graph.cells[index].value = graph.binding(BindingId(index))?;
        }
        Ok(graph)
    }
    fn add(&mut self, value: Value, span: SourceSpan) -> usize {
        let id = self.cells.len();
        self.cells.push(Cell { value, span });
        id
    }
    fn controlled(&mut self, value: usize, controls: BTreeSet<Control>, span: SourceSpan) -> usize {
        if controls.is_empty() {
            value
        } else {
            self.add(Value::Controlled { value, controls }, span)
        }
    }
    fn selections(&mut self) {
        let mut pending = vec![(self.plan.root, BTreeSet::new())];
        while let Some((block, mut inherited)) = pending.pop() {
            for id in &self.plan.blocks[block.0].nodes {
                let node = &self.plan.nodes[id.0];
                let mut here = inherited.clone();
                if let Some(before) = node.order_after {
                    here.insert(Control::OrderedAfter(before));
                }
                self.controls[id.0] = here.clone();
                match &node.kind {
                    NodeKind::Call { scope, .. } => {
                        pending.push((self.plan.scopes[scope.0].entry, here))
                    }
                    NodeKind::After { body, .. } => {
                        here.insert(Control::After(*id));
                        pending.push((*body, here));
                    }
                    NodeKind::OnFailure { body, .. } => {
                        here.insert(Control::FailureHandler(*id));
                        pending.push((*body, here));
                    }
                    NodeKind::Case { branches, .. } => {
                        for (branch, arm) in branches.iter().enumerate() {
                            let mut controls = here.clone();
                            controls.insert(Control::Case { node: *id, branch });
                            pending.push((arm.body, controls));
                        }
                    }
                    NodeKind::Region {
                        body, lapse_body, ..
                    } => {
                        let mut normal = here.clone();
                        normal.insert(Control::Region {
                            node: *id,
                            lapse: false,
                        });
                        pending.push((*body, normal));
                        here.insert(Control::Region {
                            node: *id,
                            lapse: true,
                        });
                        pending.push((*lapse_body, here));
                        inherited.insert(Control::RegionExit(*id));
                    }
                    _ => {}
                }
            }
        }
    }
    fn binding(&mut self, id: BindingId) -> Result<Value, Box<Diagnostic>> {
        let binding = &self.plan.bindings[id.0];
        let span = binding.span;
        let (value, control_node) = match &binding.source {
            BindingSource::RuleInput { .. } => return Ok(Value::Source(Origin::Input(id))),
            BindingSource::Parameter { scope, index, .. } => {
                let Some(call) = self.plan.scopes[scope.0].parent_call else {
                    return Ok(Value::Source(Origin::Input(id)));
                };
                let NodeKind::Call { arguments, .. } = &self.plan.nodes[call.0].kind else {
                    unreachable!("validated parent call");
                };
                let argument = &arguments[*index];
                (
                    self.expression(
                        &argument.value.expr,
                        &argument.environment,
                        argument.value.span,
                        Some(call),
                    )?,
                    call,
                )
            }
            BindingSource::Node(node) => {
                let value = match &self.plan.nodes[node.0].kind {
                    NodeKind::Call { scope, .. } => {
                        let mut values = Vec::new();
                        for returned in self.returns[scope.0].clone() {
                            let node = &self.plan.nodes[returned.0];
                            let NodeKind::Return(value) = &node.kind else {
                                unreachable!();
                            };
                            let value = self.expression(
                                &value.expr,
                                &self.plan.blocks[node.block.0].environment,
                                value.span,
                                Some(returned),
                            )?;
                            values.push(self.controlled(
                                value,
                                self.controls[returned.0].clone(),
                                node.span,
                            ));
                        }
                        let joined = self.add(Value::Choice(values), span);
                        self.controlled(
                            joined,
                            BTreeSet::from([Control::ScopeSuccess(*scope)]),
                            span,
                        )
                    }
                    NodeKind::Statement(statement) => match statement.as_ref() {
                        BodyStmt::Effect(_) => {
                            self.add(Value::Source(Origin::Operation(*node)), span)
                        }
                        BodyStmt::Redact { source, keep, .. } => {
                            let env =
                                &self.plan.blocks[self.plan.nodes[node.0].block.0].environment;
                            let target = self.expression(
                                &Expr::Literal(ExprLiteral::Ident(source.clone())),
                                env,
                                span,
                                Some(*node),
                            )?;
                            let fields = keep
                                .iter()
                                .map(|key| {
                                    (
                                        key.clone(),
                                        self.add(
                                            Value::Select {
                                                target,
                                                key: key.clone(),
                                            },
                                            span,
                                        ),
                                    )
                                })
                                .collect();
                            self.add(Value::Object(fields), span)
                        }
                        BodyStmt::Declassify { .. } => {
                            self.add(Value::Source(Origin::Crossing(*node)), span)
                        }
                        _ => unreachable!("validated value-producing statement"),
                    },
                    _ => unreachable!("validated result producer"),
                };
                (
                    self.add(Value::Produced { value, node: *node }, span),
                    *node,
                )
            }
            BindingSource::After { node } => {
                let NodeKind::After {
                    observed,
                    predicate,
                    ..
                } = &self.plan.nodes[node.0].kind
                else {
                    unreachable!();
                };
                let value = if *predicate == AfterPredicate::Succeeds {
                    observed.0
                } else {
                    self.add(
                        Value::Source(Origin::Outcome {
                            observed: *observed,
                            observer: *node,
                        }),
                        span,
                    )
                };
                (value, *node)
            }
            BindingSource::Case { node, .. } => {
                let parent = &self.plan.nodes[node.0];
                let NodeKind::Case { scrutinee, .. } = &parent.kind else {
                    unreachable!();
                };
                let expr = crate::parse_expression(scrutinee)
                    .map_err(|message| error(parent.span, message))?;
                (
                    self.expression(
                        &expr,
                        &self.plan.blocks[parent.block.0].environment,
                        parent.span,
                        Some(*node),
                    )?,
                    *node,
                )
            }
            BindingSource::FailureHandler { node } => {
                let values: Vec<_> = self
                    .plan
                    .protected_operation_nodes(*node)
                    .into_iter()
                    .filter_map(|operation| self.plan.nodes[operation.0].result)
                    .map(|observed| {
                        self.add(
                            Value::Source(Origin::Outcome {
                                observed,
                                observer: *node,
                            }),
                            span,
                        )
                    })
                    .collect();
                (self.add(Value::Choice(values), span), *node)
            }
            BindingSource::Lapse { node } => {
                (self.add(Value::Source(Origin::Lapse(*node)), span), *node)
            }
        };
        let controlled = self.controlled(value, self.controls[control_node.0].clone(), span);
        Ok(Value::Alias(controlled))
    }
    fn expression(
        &mut self,
        expr: &Expr,
        env: &Environment,
        span: SourceSpan,
        observer: Option<NodeId>,
    ) -> Result<usize, Box<Diagnostic>> {
        self.expression_with_parameters(expr, env, &BTreeMap::new(), span, observer)
    }
    fn expression_with_parameters(
        &mut self,
        expr: &Expr,
        env: &Environment,
        parameters: &BTreeMap<String, usize>,
        span: SourceSpan,
        observer: Option<NodeId>,
    ) -> Result<usize, Box<Diagnostic>> {
        let value = match expr {
            Expr::Literal(ExprLiteral::Ident(name)) => {
                if let Some(value) = parameters.get(name) {
                    return Ok(*value);
                }
                if let Some(binding) = env.get(name) {
                    return Ok(binding.0);
                }
                if !self.constants.contains(name) {
                    let message = format!("unknown managed provenance value `{name}`");
                    // MUTATION-SUCCESS-EXPR: Ok(0)
                    return Err(error(span, message));
                }
                Value::Constant
            }
            Expr::Literal(_) => Value::Constant,
            Expr::Path(path) => {
                let Some((name, fields)) = path.split_first() else {
                    // MUTATION-SUCCESS-EXPR: Ok(0)
                    return Err(error(span, "empty managed provenance path".into()));
                };
                let target = parameters
                    .get(name)
                    .copied()
                    .or_else(|| env.get(name).map(|binding| binding.0));
                let Some(mut target) = target else {
                    let message = format!("unknown managed provenance binding `{name}`");
                    // MUTATION-SUCCESS-EXPR: Ok(0)
                    return Err(error(span, message));
                };
                for key in fields {
                    target = self.add(
                        Value::Select {
                            target,
                            key: key.clone(),
                        },
                        span,
                    );
                }
                return Ok(target);
            }
            Expr::Object(fields) => {
                let mut object = BTreeMap::new();
                for field in fields {
                    object.insert(
                        field.key.clone(),
                        self.expression_with_parameters(
                            &field.value,
                            env,
                            parameters,
                            span,
                            observer,
                        )?,
                    );
                }
                Value::Object(object)
            }
            Expr::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|expr| {
                        self.expression_with_parameters(expr, env, parameters, span, observer)
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Expr::Index { target, key } => {
                let target =
                    self.expression_with_parameters(target, env, parameters, span, observer)?;
                let static_key = match key.as_ref() {
                    Expr::Literal(ExprLiteral::String(key)) => Some(key.clone()),
                    Expr::Literal(ExprLiteral::Number(key)) => {
                        key.parse::<usize>().ok().map(|key| key.to_string())
                    }
                    _ => None,
                };
                if let Some(key) = static_key {
                    Value::Select { target, key }
                } else {
                    Value::DynamicSelect {
                        target,
                        key: self
                            .expression_with_parameters(key, env, parameters, span, observer)?,
                    }
                }
            }
            Expr::Call { name, args } if self.views.contains_key(name) => {
                let view = self.views[name].clone();
                let arguments = args
                    .iter()
                    .map(|argument| {
                        self.expression_with_parameters(argument, env, parameters, span, observer)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let parameters = view.parameters.iter().cloned().zip(arguments).collect();
                return self.expression_with_parameters(
                    &view.expression,
                    env,
                    &parameters,
                    span,
                    observer,
                );
            }
            Expr::Call { name, args } if name == "outcome" => {
                let [argument] = args.as_slice() else {
                    return Err(error(
                        span,
                        "outcome provenance requires exactly one named operation".into(),
                    ));
                };
                let observed = match argument {
                    Expr::Literal(ExprLiteral::Ident(name)) => env.get(name).copied(),
                    Expr::Path(path) if path.len() == 1 => env.get(&path[0]).copied(),
                    _ => None,
                }
                .ok_or_else(|| {
                    error(
                        span,
                        "outcome provenance requires a known named operation".into(),
                    )
                })?;
                let operation = matches!(
                    self.plan.bindings[observed.0].source,
                    BindingSource::Node(node)
                        if matches!(&self.plan.nodes[node.0].kind, NodeKind::Call { .. })
                            || matches!(
                                &self.plan.nodes[node.0].kind,
                                NodeKind::Statement(statement)
                                    if matches!(statement.as_ref(), BodyStmt::Effect(_))
                            )
                );
                if !operation {
                    return Err(error(
                        span,
                        "outcome provenance requires an effect or child-action operation".into(),
                    ));
                }
                let observer = observer.ok_or_else(|| {
                    error(
                        span,
                        "outcome provenance requires a managed observation site".into(),
                    )
                })?;
                Value::Source(Origin::Outcome { observed, observer })
            }
            Expr::Query { .. } => Value::UnobservedQuery,
            _ => Value::Mix(
                expr.children()
                    .into_iter()
                    .map(|expr| {
                        self.expression_with_parameters(expr, env, parameters, span, observer)
                    })
                    .collect::<Result<_, _>>()?,
            ),
        };
        Ok(self.add(value, span))
    }
    /// A checked rule guard reads the root environment, never a callee's locals.
    pub fn trace_root(&mut self, expr: &Expr, span: SourceSpan) -> Result<Trace, Box<Diagnostic>> {
        let value = self.expression(
            expr,
            &self.plan.blocks[self.plan.root.0].environment,
            span,
            None,
        )?;
        self.trace(value)
    }
    /// The source node supplies the lexical environment and selection context.
    pub fn trace_at(&mut self, id: NodeId, expr: &Expr) -> Result<Trace, Box<Diagnostic>> {
        let node = self.plan.nodes.get(id.0).ok_or_else(|| {
            error(
                SourceSpan { start: 0, end: 0 },
                "value-flow source node is out of range".into(),
            )
        })?;
        let value = self.expression(
            expr,
            &self.plan.blocks[node.block.0].environment,
            node.span,
            Some(id),
        )?;
        let mut trace = self.trace(value)?;
        // Node references, rather than reparsed names, retain the full branch context.
        trace.controls.extend(self.controls[id.0].iter().cloned());
        Ok(trace)
    }
    /// A later arm also depends on earlier guards not selecting an earlier arm.
    /// Each guard keeps its own pattern binder and cannot capture body locals.
    pub fn trace_case_selection(
        &mut self,
        id: NodeId,
        branch: usize,
    ) -> Result<Trace, Box<Diagnostic>> {
        let Some(node) = self.plan.nodes.get(id.0) else {
            let message = "case selection node is out of range";
            let span = SourceSpan { start: 0, end: 0 };
            // MUTATION-SUCCESS-EXPR: Ok(Trace::default())
            return Err(error(span, message.into()));
        };
        let NodeKind::Case {
            scrutinee,
            branches,
        } = &node.kind
        else {
            let message = "case selection requires a case node";
            // MUTATION-SUCCESS-EXPR: Ok(Trace::default())
            return Err(error(node.span, message.into()));
        };
        if branch >= branches.len() {
            let message = "case selection arm is out of range";
            // MUTATION-SUCCESS-EXPR: Ok(Trace::default())
            return Err(error(node.span, message.into()));
        }
        let expression =
            crate::parse_expression(scrutinee).map_err(|message| error(node.span, message))?;
        let mut result = self.trace_at(id, &expression)?;
        for arm in branches.iter().take(branch + 1) {
            if let Some(guard) = &arm.guard {
                let expression =
                    crate::parse_expression(guard).map_err(|message| error(arm.span, message))?;
                let value =
                    self.expression(&expression, &arm.guard_environment, arm.span, Some(id))?;
                let trace = self.trace(value)?;
                result.sources.extend(trace.sources);
                result.controls.extend(trace.controls);
            }
        }
        Ok(result)
    }
    pub fn trace_binding(&self, binding: BindingId) -> Result<Trace, Box<Diagnostic>> {
        self.binding_trace(binding, false)
    }
    /// Original-value forwarding only. The consumer still proves what each
    /// origin denotes: data provenance alone cannot confer resource authority.
    /// Controls and no-success paths retain the ordinary trace's meaning.
    pub fn identity_binding(&self, binding: BindingId) -> Result<Trace, Box<Diagnostic>> {
        self.binding_trace(binding, true)
    }
    fn binding_trace(&self, binding: BindingId, identity: bool) -> Result<Trace, Box<Diagnostic>> {
        if binding.0 >= self.plan.bindings.len() {
            let span = SourceSpan { start: 0, end: 0 };
            let message = "value-flow binding is out of range";
            // MUTATION-SUCCESS-EXPR: Ok(Trace::default())
            return Err(error(span, message.into()));
        }
        self.trace_mode(binding.0, identity)
    }
    fn trace(&self, root: usize) -> Result<Trace, Box<Diagnostic>> {
        self.trace_mode(root, false)
    }
    fn trace_mode(&self, root: usize, identity: bool) -> Result<Trace, Box<Diagnostic>> {
        enum Work {
            Enter(usize, Vec<String>),
            Exit(usize),
        }
        let mut work = vec![Work::Enter(root, Vec::new())];
        let mut active: BTreeSet<usize> = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut trace = Trace::default();
        while let Some(task) = work.pop() {
            let Work::Enter(id, fields) = task else {
                if let Work::Exit(id) = task {
                    active.remove(&id);
                }
                continue;
            };
            if active.contains(&id) {
                let mut issue = error(
                    self.cells[id].span,
                    "managed value provenance contains a cycle".into(),
                );
                for binding in active.iter().filter_map(|id| self.plan.bindings.get(*id)) {
                    issue.related.push(RelatedInfo {
                        span: binding.span,
                        message: format!(
                            "value binding `{}` participates in this dependency",
                            binding.name.as_deref().unwrap_or("<anonymous>")
                        ),
                    });
                }
                // MUTATION-SUCCESS-EXPR: Ok(Trace::default())
                return Err(issue);
            }
            if !seen.insert((id, fields.clone())) {
                continue;
            }
            active.insert(id);
            work.push(Work::Exit(id));
            let child = |id, fields| Work::Enter(id, fields);
            let original = match &self.cells[id].value {
                Value::Constant
                | Value::UnobservedQuery
                | Value::Mix(_)
                | Value::DynamicSelect { .. } => false,
                Value::Object(object) => fields.first().is_some_and(|key| object.contains_key(key)),
                Value::Array(items) => fields
                    .first()
                    .and_then(|key| key.parse::<usize>().ok())
                    .is_some_and(|key| key < items.len()),
                Value::Never
                | Value::Source(_)
                | Value::Alias(_)
                | Value::Choice(_)
                | Value::Select { .. }
                | Value::Produced { .. }
                | Value::Controlled { .. } => true,
            };
            if identity && !original {
                let message = "resource identity requires an original value, not constructed or transformed data";
                // MUTATION-SUCCESS-EXPR: Ok(Trace::default())
                return Err(error(self.cells[id].span, message.into()));
            }
            match &self.cells[id].value {
                Value::Never => {}
                Value::Constant => trace.may_have_value = true,
                Value::UnobservedQuery => {
                    let message = "query provenance requires its own observation contract";
                    // MUTATION-SUCCESS-EXPR: Ok(Trace::default())
                    return Err(error(self.cells[id].span, message.into()));
                }
                Value::Source(origin) => {
                    trace.may_have_value = true;
                    trace.sources.insert(ValuePath {
                        origin: origin.clone(),
                        fields,
                    });
                }
                Value::Alias(id) => work.push(child(*id, fields)),
                Value::Object(object) => {
                    if let Some((key, rest)) = fields.split_first() {
                        if let Some(id) = object.get(key) {
                            work.push(child(*id, rest.to_vec()));
                        } else {
                            trace.may_have_value = true;
                        }
                    } else {
                        trace.may_have_value = true;
                        work.extend(object.values().map(|id| child(*id, Vec::new())));
                    }
                }
                Value::Array(items) => {
                    if let Some((key, rest)) = fields.split_first() {
                        if let Some(id) = key.parse::<usize>().ok().and_then(|key| items.get(key)) {
                            work.push(child(*id, rest.to_vec()));
                        } else {
                            trace.may_have_value = true;
                        }
                    } else {
                        trace.may_have_value = true;
                        work.extend(items.iter().map(|id| child(*id, Vec::new())));
                    }
                }
                Value::Mix(inputs) => {
                    trace.may_have_value = true;
                    work.extend(inputs.iter().map(|id| child(*id, Vec::new())));
                }
                Value::Choice(arms) => {
                    work.extend(arms.iter().map(|id| child(*id, fields.clone())))
                }
                Value::Select { target, key } => {
                    let mut path = vec![key.clone()];
                    path.extend(fields);
                    work.push(child(*target, path));
                }
                Value::DynamicSelect { target, key } => {
                    work.push(child(*target, Vec::new()));
                    work.push(child(*key, Vec::new()));
                }
                Value::Produced { value, node } => {
                    trace.produced.insert(ProducedPath {
                        node: *node,
                        fields: fields.clone(),
                    });
                    work.push(child(*value, fields));
                }
                Value::Controlled { value, controls } => {
                    trace.controls.extend(controls.iter().cloned());
                    work.push(child(*value, fields));
                }
            }
        }
        Ok(trace)
    }
}
#[cfg(test)]
mod tests;
