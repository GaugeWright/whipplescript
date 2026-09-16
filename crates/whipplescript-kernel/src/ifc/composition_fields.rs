//! Additive field clearance over the actual value graph and checked source types.
use super::output_integrity::managed::incomplete;
use super::program_context::ProgramContext;
use super::*;
use whipplescript_parser::action_plan::value_flow::{Control, Graph, Origin, Trace, ValuePath};
use whipplescript_parser::action_plan::{BindingId, BindingSource, NodeId, NodeKind, ScopeId};
use whipplescript_parser::body::BodyStmt;
use whipplescript_parser::{Expr, ExprLiteral, IrSchema, IrType, QueryKind, SourceSpan};

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
enum Work {
    Value(ValuePath),
    Selection(Control),
    Outcome(BindingId),
}

struct Walk<'a> {
    body: &'a RuleBodyAnalysis<'a>,
    context: ProgramContext<'a>,
    envelope: &'a Envelope,
    graph: Graph<'a>,
    pending: Vec<Work>,
    seen: BTreeSet<Work>,
    fields: BTreeSet<String>,
    sites: BTreeSet<NodeId>,
    inputs: BTreeSet<BindingId>,
    guards: BTreeSet<(usize, usize)>,
}

impl Walk<'_> {
    fn guard_expression(
        &mut self,
        expr: &Expr,
        scopes: &[String],
        span: SourceSpan,
    ) -> Result<(), Box<Diagnostic>> {
        fn has_query(expr: &Expr) -> bool {
            matches!(expr, Expr::Query { .. }) || expr.children().iter().any(|expr| has_query(expr))
        }
        if scopes.is_empty() && !has_query(expr) {
            let trace = self.graph.trace_root(expr, span)?;
            self.enqueue(trace);
            return Ok(());
        }
        if let Expr::Query { kind, head, guard } = expr {
            if let Some(guard) = guard {
                let mut scopes = scopes.to_vec();
                if *kind == QueryKind::Fact {
                    scopes.push(head.clone());
                }
                self.guard_expression(guard, &scopes, span)?;
            }
            return Ok(());
        }
        let path = match expr {
            Expr::Literal(ExprLiteral::Ident(name)) => Some(vec![name.clone()]),
            Expr::Path(path) => Some(path.clone()),
            _ => None,
        };
        if let Some(path) = path {
            if let Some(head) = path.first() {
                let local = scopes.iter().rev().find(|schema| self.context.schemas().iter().any(|decl| matches!(decl, IrSchema::Class(class) if &class.name == *schema && class.fields.iter().any(|field| &field.name == head))));
                if let Some(schema) = local {
                    self.typed_fields(&IrType::Ref(schema.clone()), &path);
                    return Ok(());
                }
            }
            let trace = self.graph.trace_root(expr, span)?;
            self.enqueue(trace);
        } else {
            for child in expr.children() {
                self.guard_expression(child, scopes, span)?;
            }
        }
        Ok(())
    }
    fn root_guards(&mut self) -> Result<(), Box<Diagnostic>> {
        for when in &self.body.rule.root.whens {
            if let Some(guard) = &when.guard {
                self.guards.insert((guard.span.start, guard.span.end));
                self.guard_expression(&guard.expr, &[], guard.span)?;
            }
            if let Some(target) = when.pattern.strip_suffix(" is available") {
                let expr = whipplescript_parser::parse_expression(target)
                    .map_err(|message| incomplete(&message))?;
                self.guards.insert((when.span.start, when.span.end));
                self.guard_expression(&expr, &[], when.span)?;
            }
        }
        Ok(())
    }
    fn typed_fields(&mut self, ty: &IrType, path: &[String]) {
        let mut pending = vec![(ty.clone(), path.to_vec())];
        let mut seen = BTreeSet::new();
        while let Some((ty, path)) = pending.pop() {
            match ty {
                IrType::Ref(name) => {
                    if !seen.insert((name.clone(), path.clone())) {
                        continue;
                    }
                    let enumeration =
                        self.context
                            .schemas()
                            .iter()
                            .find_map(|schema| match schema {
                                IrSchema::Enum(enumeration) if enumeration.name == name => {
                                    Some(enumeration)
                                }
                                _ => None,
                            });
                    let declared = self
                        .context
                        .schemas()
                        .iter()
                        .find_map(|schema| match schema {
                            IrSchema::Class(class) if class.name == name => Some(&class.fields),
                            _ => None,
                        })
                        .or_else(|| {
                            self.context
                                .events()
                                .iter()
                                .find(|event| event.name == name)
                                .map(|event| &event.fields)
                        });
                    let fields: Vec<_> = declared
                        .into_iter()
                        .flatten()
                        .map(|field| (field.name.clone(), field.ty.clone()))
                        .collect();
                    if let Some((field, rest)) = path.split_first() {
                        self.fields.insert(format!("{name}.{field}"));
                        if let Some((_, ty)) = fields.iter().find(|(name, _)| name == field) {
                            pending.push((ty.clone(), rest.to_vec()));
                        }
                    } else {
                        // Built-in/schema-less surfaces may still have explicit
                        // field labels in the verified envelope. Keep those too.
                        let prefix = format!("{name}.");
                        self.fields.extend(
                            self.envelope
                                .readers
                                .keys()
                                .chain(self.envelope.address_of.keys())
                                .filter(|field| {
                                    declared.is_none()
                                        && enumeration.is_none()
                                        && field.starts_with(&prefix)
                                })
                                .cloned(),
                        );
                        for (field, ty) in fields {
                            self.fields.insert(format!("{name}.{field}"));
                            pending.push((ty, Vec::new()));
                        }
                    }
                    // A tagged sum's declared alternatives carry their own labels.
                    if let Some(enumeration) = enumeration {
                        for variant in &enumeration.variants {
                            pending.push((IrType::Ref(format!("{name}.{variant}")), path.clone()));
                        }
                    }
                }
                IrType::Object(fields) => {
                    if let Some((field, rest)) = path.split_first() {
                        if let Some(field) = fields.iter().find(|f| &f.name == field) {
                            pending.push((field.ty.clone(), rest.to_vec()));
                        }
                    } else {
                        pending.extend(fields.into_iter().map(|field| (field.ty, Vec::new())));
                    }
                }
                IrType::Union(variants) => {
                    pending.extend(variants.into_iter().map(|ty| (ty, path.clone())))
                }
                IrType::Optional(inner) => pending.push((*inner, path)),
                IrType::Array(inner) | IrType::Map(inner) => {
                    pending.push((*inner, path.get(1..).unwrap_or_default().to_vec()))
                }
                _ => {}
            }
        }
    }
    fn enqueue(&mut self, trace: Trace) {
        for produced in trace.produced {
            self.sites.insert(produced.node);
            if let Some(ty) = self.body.rule.value_types.get(&produced.node) {
                self.typed_fields(ty, &produced.fields);
            }
        }
        self.pending
            .extend(trace.sources.into_iter().map(Work::Value));
        self.pending
            .extend(trace.controls.into_iter().map(Work::Selection));
    }
    fn expression(&mut self, node: NodeId, expr: &Expr) -> Result<(), Box<Diagnostic>> {
        let trace = self.graph.trace_at(node, expr)?;
        self.enqueue(trace);
        Ok(())
    }
    fn text(&mut self, node: NodeId, text: &str) -> Result<(), Box<Diagnostic>> {
        let expr =
            whipplescript_parser::parse_expression(text).map_err(|message| incomplete(&message))?;
        self.expression(node, &expr)
    }
    fn opaque_inputs(&mut self) {
        self.pending
            .extend(self.body.rule.typed.plan.root_inputs.iter().map(|binding| {
                Work::Value(ValuePath {
                    origin: Origin::Input(*binding),
                    fields: Vec::new(),
                })
            }));
        for ty in self.body.rule.value_types.values() {
            self.typed_fields(ty, &[]);
        }
    }
    fn failure_sources(&mut self, scope: ScopeId) -> Result<(), Box<Diagnostic>> {
        let plan = &self.body.rule.typed.plan;
        for (index, node) in plan.nodes.iter().enumerate() {
            if plan.blocks[node.block.0].scope == Some(scope) {
                if let NodeKind::Fail(value) = &node.kind {
                    self.sites.insert(NodeId(index));
                    if let Some(ty) = self.body.rule.value_types.get(&NodeId(index)) {
                        self.typed_fields(ty, &[]);
                    }
                    self.expression(NodeId(index), &value.expr)?;
                }
            }
        }
        for node in &plan.scopes[scope.0].operations {
            if let Some(binding) = plan.nodes[node.0].result {
                self.pending.push(Work::Outcome(binding));
            }
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Box<Diagnostic>> {
        let plan = &self.body.rule.typed.plan;
        while let Some(work) = self.pending.pop() {
            if !self.seen.insert(work.clone()) {
                continue;
            }
            match work {
                Work::Value(ValuePath {
                    origin: Origin::Input(binding),
                    fields,
                }) => {
                    self.inputs.insert(binding);
                    if let Some(schema) = plan.bindings[binding.0]
                        .name
                        .as_ref()
                        .and_then(|name| self.body.rule.root.binding_schemas.get(name))
                    {
                        self.typed_fields(&IrType::Ref(schema.clone()), &fields);
                    }
                }
                Work::Value(ValuePath {
                    origin: Origin::Operation(node),
                    ..
                }) => {
                    let NodeKind::Statement(statement) = &plan.nodes[node.0].kind else {
                        unreachable!("checked operation");
                    };
                    let BodyStmt::Effect(effect) = statement.as_ref() else {
                        unreachable!("checked effect");
                    };
                    if let Some(inputs) = effect.kind.carried_input_expressions() {
                        for input in inputs {
                            self.text(node, input)?;
                        }
                    } else {
                        self.opaque_inputs();
                    }
                }
                Work::Value(ValuePath {
                    origin: Origin::Crossing(node),
                    fields,
                }) => {
                    let NodeKind::Statement(statement) = &plan.nodes[node.0].kind else {
                        unreachable!("checked crossing");
                    };
                    let BodyStmt::Declassify {
                        source,
                        target_type,
                        ..
                    } = statement.as_ref()
                    else {
                        unreachable!("checked crossing");
                    };
                    if fields.is_empty() {
                        for schema in self.context.schemas() {
                            if let IrSchema::Class(class) = schema {
                                if &class.name == target_type {
                                    for field in &class.fields {
                                        self.expression(
                                            node,
                                            &Expr::Path(vec![source.clone(), field.name.clone()]),
                                        )?;
                                    }
                                }
                            }
                        }
                    } else {
                        self.expression(
                            node,
                            &Expr::Path(std::iter::once(source.clone()).chain(fields).collect()),
                        )?;
                    }
                }
                Work::Value(ValuePath {
                    origin: Origin::Outcome { observed, .. },
                    ..
                }) => self.pending.push(Work::Outcome(observed)),
                Work::Value(ValuePath {
                    origin: Origin::Lapse(node),
                    ..
                }) => self
                    .pending
                    .push(Work::Selection(Control::Region { node, lapse: true })),
                Work::Outcome(binding) => {
                    self.enqueue(self.graph.trace_binding(binding)?);
                    if let BindingSource::Node(node) = plan.bindings[binding.0].source {
                        if let NodeKind::Call { scope, .. } = plan.nodes[node.0].kind {
                            self.failure_sources(scope)?;
                        }
                    }
                }
                Work::Selection(Control::Case { node, branch }) => {
                    self.sites.insert(node);
                    let trace = self.graph.trace_case_selection(node, branch)?;
                    self.enqueue(trace);
                }
                Work::Selection(Control::After(node)) => {
                    self.sites.insert(node);
                    let NodeKind::After { observed, .. } = plan.nodes[node.0].kind else {
                        unreachable!("checked continuation");
                    };
                    self.pending.push(Work::Outcome(observed));
                }
                Work::Selection(Control::FailureHandler(node)) => {
                    self.sites.insert(node);
                    self.pending.extend(
                        plan.protected_operation_nodes(node)
                            .into_iter()
                            .filter_map(|operation| plan.nodes[operation.0].result)
                            .map(Work::Outcome),
                    );
                }
                Work::Selection(Control::Region { node, .. } | Control::RegionExit(node)) => {
                    self.sites.insert(node);
                    let NodeKind::Region { condition, .. } = &plan.nodes[node.0].kind else {
                        unreachable!("checked region");
                    };
                    self.text(node, condition)?;
                }
                Work::Selection(Control::OrderedAfter(_) | Control::ScopeSuccess(_)) => {}
            }
        }
        Ok(())
    }
}

pub(super) fn check(
    body: &RuleBodyAnalysis<'_>,
    context: ProgramContext<'_>,
    envelope: &Envelope,
    node: NodeId,
    destination: &str,
    sink: Option<&ManagedOwnedSink>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let constants = fact_producers::constants(context);
    let result = (|| {
        let mut walk = Walk {
            body,
            context,
            envelope,
            graph: Graph::new(&body.rule.typed, &constants)?,
            pending: Vec::new(),
            seen: BTreeSet::new(),
            fields: BTreeSet::new(),
            sites: BTreeSet::new(),
            inputs: BTreeSet::new(),
            guards: BTreeSet::new(),
        };
        walk.root_guards()?;
        if let Some(sink) = sink {
            for expr in &sink.payload {
                walk.expression(node, expr)?;
            }
            walk.pending
                .extend(sink.selection.iter().cloned().map(Work::Selection));
        } else if body.rule.typed.effects.contains_key(&node) {
            let NodeKind::Statement(statement) = &body.rule.typed.plan.nodes[node.0].kind else {
                unreachable!("checked sink");
            };
            let BodyStmt::Effect(authored) = statement.as_ref() else {
                unreachable!("checked sink effect");
            };
            if let Some(inputs) = authored.kind.carried_input_expressions() {
                for input in inputs {
                    walk.text(node, input)?;
                }
            } else {
                walk.opaque_inputs();
            }
        }
        walk.expression(node, &Expr::Literal(ExprLiteral::Null))?;
        if let Some(effect) = body.inventory.effects.get(&node) {
            walk.pending
                .extend(effect.controls.iter().cloned().map(Work::Selection));
        }
        walk.finish()?;
        if let Some(mut diagnostic) = projection_policy::check(
            &body.rule.root.name.name,
            body.rule.typed.plan.nodes[node.0].span,
            destination,
            projection_policy::Kind::Composed,
            &walk.fields,
            envelope,
        ) {
            managed_call_context(&mut diagnostic, &body.rule.typed.plan, node);
            for site in walk.sites {
                diagnostic.related.push(RelatedInfo {
                    span: body.rule.typed.plan.nodes[site.0].span,
                    message: "field value or selection passes through here".into(),
                });
                managed_call_context(&mut diagnostic, &body.rule.typed.plan, site);
            }
            for (start, end) in walk.guards {
                diagnostic.related.push(RelatedInfo {
                    span: SourceSpan { start, end },
                    message: "root guard observes these fields".into(),
                });
            }
            for input in walk.inputs {
                diagnostic.related.push(RelatedInfo {
                    span: body.rule.typed.plan.bindings[input.0].span,
                    message: "original field source enters here".into(),
                });
            }
            let mut seen = BTreeSet::new();
            diagnostic.related.retain(|related| {
                seen.insert((
                    related.span.start,
                    related.span.end,
                    related.message.clone(),
                ))
            });
            diagnostics.push(diagnostic);
        }
        Ok::<_, Box<Diagnostic>>(())
    })();
    if let Err(error) = result {
        diagnostics.push(source_inputs::at_sink(*error, body, node));
    }
}
