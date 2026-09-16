//! Whole-fact reach from actual managed producers; no fabricated legacy metadata.
use super::output_integrity::managed::{self, incomplete, Sink};
use super::program_context::ProgramContext;
use super::*;
use whipplescript_parser::action_plan::value_flow::{Control, Graph, Origin, Trace};
use whipplescript_parser::action_plan::{BindingId, BindingSource, NodeId, NodeKind, ScopeId};
use whipplescript_parser::body::BodyStmt;
use whipplescript_parser::{Expr, ExprLiteral, IrSchema, IrType};
pub(super) type Reach = BTreeMap<String, BTreeSet<String>>;

pub(super) fn governed_token(schema: &str, envelope: &Envelope) -> Option<String> {
    let token = format!("fact:{schema}");
    envelope
        .governed
        .contains(envelope.resolve(&token))
        .then_some(token)
}
/// Origin-aware seeds shared with legacy provenance: an external arrival keeps
/// its label even ungoverned, unlike program-authored seeds and workflow inputs.
pub(super) fn initial(
    context: ProgramContext<'_>,
    envelope: &Envelope,
    schemas: &BTreeSet<&str>,
) -> Reach {
    let mut reach = Reach::new();
    for contract in context.workflow_contracts() {
        if contract.kind == IrWorkflowContractKind::Input {
            if let IrType::Ref(name) = &contract.ty {
                if schemas.contains(name.as_str()) {
                    if let Some(token) = governed_token(name, envelope) {
                        reach.entry(name.clone()).or_default().insert(token);
                    }
                }
            }
        }
    }
    let external: BTreeSet<_> = context
        .source_tags()
        .iter()
        .filter(|tag| tag.name == "external" && tag.target_kind == "rule")
        .map(|tag| tag.target.as_str())
        .collect();
    for (name, whens) in context.roots() {
        if !external.contains(name) {
            continue;
        }
        for when in whens {
            if let Some(head) = when.pattern.split_whitespace().next() {
                if schemas.contains(head) {
                    reach
                        .entry(head.into())
                        .or_default()
                        .insert(format!("fact:{head}"));
                }
            }
        }
    }
    reach
}

pub(super) fn reach(
    bodies: &CompositionBodies<'_>,
    verified: &VerifiedEnvelope,
) -> Result<Reach, Vec<Diagnostic>> {
    reach_with_reads(bodies, verified, &BTreeMap::new())
}

pub(super) fn reach_with_reads(
    bodies: &CompositionBodies<'_>,
    verified: &VerifiedEnvelope,
    additional: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Reach, Vec<Diagnostic>> {
    let context = ProgramContext::Composition(bodies.source());
    let schemas = context
        .schemas()
        .iter()
        .filter_map(|schema| match schema {
            IrSchema::Class(class) => Some(class.name.as_str()),
            _ => None,
        })
        .collect();
    let constants = constants(context);
    let mut reach = initial(context, verified.envelope(), &schemas);
    loop {
        let mut changed = false;
        let mut diagnostics = Vec::new();
        for body in bodies.rules() {
            let typed = &body.rule.typed;
            let mut own = own_reads(context, body);
            if let Some(reads) = additional.get(&body.rule.root.name.name) {
                own.extend(reads.iter().cloned());
            }
            let inputs = input_map(context, &body.rule.root.whens, &reach);
            for sink in &body.inventory.local {
                let Some(schema) = sink.resource.strip_prefix("fact:") else {
                    continue;
                };
                let result = (|| {
                    let graph = Graph::new(typed, &constants)?;
                    let mut walk = Sources {
                        body,
                        graph,
                        inputs: &inputs,
                        pending: Vec::new(),
                        seen: BTreeSet::new(),
                        sources: own.clone(),
                        attributed: true,
                        fallback: body
                            .rule
                            .root
                            .whens
                            .iter()
                            .any(|when| when.pattern.trim() == "started"),
                    };
                    walk.sink(&sink.as_sink())?;
                    let mut sources = walk.sources;
                    // Endorsement was checked at its sink, and cannot travel
                    // as a permission attached to a produced fact.
                    for token in managed::collect(typed, context, &sink.as_sink(), &reach)? {
                        sources.insert(format!("output:{}", token.handle));
                    }
                    if walk.fallback {
                        if let Some(token) = governed_token(schema, verified.envelope()) {
                            sources.insert(token);
                        }
                    }
                    Ok::<_, Box<Diagnostic>>(sources)
                })();
                match result {
                    Ok(sources) => {
                        let entry = reach.entry(schema.into()).or_default();
                        let before = entry.len();
                        entry.extend(sources);
                        changed |= entry.len() != before;
                    }
                    Err(mut diagnostic) => {
                        let span = typed.plan.nodes[sink.node.0].span;
                        if diagnostic.span
                            != (whipplescript_parser::SourceSpan { start: 0, end: 0 })
                            && diagnostic.span != span
                        {
                            diagnostic.related.push(RelatedInfo {
                                span: diagnostic.span,
                                message: "producer value originates here".into(),
                            });
                        }
                        diagnostic.span = span;
                        managed_call_context(&mut diagnostic, &typed.plan, sink.node);
                        diagnostics.push(*diagnostic);
                    }
                }
            }
        }
        if !diagnostics.is_empty() {
            return Err(diagnostics);
        }
        if !changed {
            return Ok(reach);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Work {
    Value(Origin),
    Selection(Control),
    Outcome(BindingId),
}
struct Sources<'a> {
    body: &'a RuleBodyAnalysis<'a>,
    graph: Graph<'a>,
    inputs: &'a Reach,
    pending: Vec<Work>,
    seen: BTreeSet<Work>,
    sources: BTreeSet<String>,
    fallback: bool,
    attributed: bool,
}
impl Sources<'_> {
    fn enqueue(&mut self, trace: Trace) {
        self.pending.extend(
            trace
                .sources
                .into_iter()
                .map(|source| Work::Value(source.origin)),
        );
        self.pending
            .extend(trace.controls.into_iter().map(Work::Selection));
    }
    fn expression(&mut self, node: NodeId, source: &str) -> Result<(), Box<Diagnostic>> {
        let expr = whipplescript_parser::parse_expression(source)
            .map_err(|message| incomplete(&message))?;
        let trace = self.graph.trace_at(node, &expr)?;
        self.enqueue(trace);
        Ok(())
    }
    fn sink(&mut self, sink: &Sink<'_>) -> Result<(), Box<Diagnostic>> {
        let trace = self
            .graph
            .trace_at(sink.node, &Expr::Literal(ExprLiteral::Null))?;
        self.enqueue(trace);
        self.pending
            .extend(sink.selection.iter().cloned().map(Work::Selection));
        for expr in sink.payload {
            let trace = self.graph.trace_at(sink.node, expr)?;
            self.enqueue(trace);
        }
        while let Some(work) = self.pending.pop() {
            if !self.seen.insert(work.clone()) {
                continue;
            }
            let typed = &self.body.rule.typed;
            match work {
                Work::Value(Origin::Input(binding)) => {
                    let name = typed.plan.bindings[binding.0].name.as_deref().unwrap_or("");
                    let Some(sources) = self.inputs.get(name) else {
                        let mut error = incomplete(&format!(
                            "input `{name}` has no matching producer analysis"
                        ));
                        error.span = typed.plan.bindings[binding.0].span;
                        // MUTATION-SUCCESS-EXPR: Ok(())
                        return Err(error);
                    };
                    self.sources.extend(
                        sources
                            .iter()
                            .filter(|source| !source.starts_with("output:"))
                            .cloned(),
                    );
                }
                Work::Value(Origin::Operation(node)) => self.operation(node)?,
                Work::Value(Origin::Crossing(node)) => {
                    let NodeKind::Statement(statement) = &typed.plan.nodes[node.0].kind else {
                        unreachable!("checked crossing")
                    };
                    let BodyStmt::Declassify { source, .. } = statement.as_ref() else {
                        unreachable!("checked declassification")
                    };
                    self.expression(node, source)?;
                }
                Work::Value(Origin::Outcome { observed, .. }) => {
                    self.pending.push(Work::Outcome(observed))
                }
                Work::Value(Origin::Lapse(node)) => self
                    .pending
                    .push(Work::Selection(Control::Region { node, lapse: true })),
                Work::Outcome(binding) => {
                    self.enqueue(self.graph.trace_binding(binding)?);
                    if let BindingSource::Node(node) = typed.plan.bindings[binding.0].source {
                        if let NodeKind::Call { scope, .. } = typed.plan.nodes[node.0].kind {
                            self.failure_sources(scope)?;
                        }
                    }
                }
                Work::Selection(Control::Case { node, branch }) => {
                    let trace = self.graph.trace_case_selection(node, branch)?;
                    self.enqueue(trace);
                }
                Work::Selection(Control::After(node)) => {
                    let NodeKind::After { observed, .. } = typed.plan.nodes[node.0].kind else {
                        unreachable!("checked after")
                    };
                    self.pending.push(Work::Outcome(observed));
                }
                Work::Selection(Control::FailureHandler(node)) => {
                    self.pending.extend(
                        typed
                            .plan
                            .protected_operation_nodes(node)
                            .into_iter()
                            .filter_map(|operation| typed.plan.nodes[operation.0].result)
                            .map(Work::Outcome),
                    );
                }
                Work::Selection(Control::Region { node, .. } | Control::RegionExit(node)) => {
                    let NodeKind::Region { condition, .. } = &typed.plan.nodes[node.0].kind else {
                        unreachable!("checked region")
                    };
                    self.expression(node, condition)?;
                }
                // These are scheduling edges, not value provenance.
                Work::Selection(Control::ScopeSuccess(_) | Control::OrderedAfter(_)) => {}
            }
        }
        Ok(())
    }
    fn failure_sources(&mut self, scope: ScopeId) -> Result<(), Box<Diagnostic>> {
        let typed = &self.body.rule.typed;
        for (index, node) in typed.plan.nodes.iter().enumerate() {
            if typed.plan.blocks[node.block.0].scope != Some(scope) {
                continue;
            }
            if let NodeKind::Fail(value) = &node.kind {
                let trace = self.graph.trace_at(NodeId(index), &value.expr)?;
                self.enqueue(trace);
            }
        }
        for node in &typed.plan.scopes[scope.0].operations {
            if let Some(binding) = typed.plan.nodes[node.0].result {
                self.pending.push(Work::Outcome(binding));
            }
        }
        Ok(())
    }
    fn operation(&mut self, node: NodeId) -> Result<(), Box<Diagnostic>> {
        let typed = &self.body.rule.typed;
        let effect = &typed.effects[&node];
        let NodeKind::Statement(statement) = &typed.plan.nodes[node.0].kind else {
            unreachable!("checked operation")
        };
        let BodyStmt::Effect(statement) = statement.as_ref() else {
            unreachable!("checked effect")
        };
        if let Some(inputs) = statement.kind.carried_input_expressions() {
            for input in inputs {
                self.expression(node, input)?;
            }
        } else if effect_flow(&effect.contract.kind).resource_is_output_provenance {
            self.sources
                .extend(self.body.inventory.effects[&node].resources.iter().cloned());
        } else {
            self.attributed = false;
            if matches!(
                output_integrity::transfer(
                    &effect.contract.kind,
                    effect.contract.endorsed,
                    effect.contract.exec_target.as_ref(),
                    false
                ),
                output_integrity::Transfer::None
            ) {
                self.fallback = true;
            }
        }
        Ok(())
    }
}

pub(super) fn constants(context: ProgramContext<'_>) -> BTreeSet<String> {
    context
        .agents()
        .iter()
        .map(|agent| agent.name.clone())
        .chain(
            context
                .schemas()
                .iter()
                .filter_map(|schema| match schema {
                    IrSchema::Enum(value) => Some(value),
                    _ => None,
                })
                .flat_map(|value| value.variants.clone()),
        )
        .collect()
}

pub(super) fn input_map(
    context: ProgramContext<'_>,
    whens: &[whipplescript_parser::IrWhen],
    facts: &Reach,
) -> Reach {
    let schemas = context
        .schemas()
        .iter()
        .filter_map(|schema| match schema {
            IrSchema::Class(class) => Some(class.name.as_str()),
            _ => None,
        })
        .collect();
    let signals = context
        .events()
        .iter()
        .map(|event| event.name.as_str())
        .collect();
    let trackers = context
        .trackers()
        .iter()
        .map(|tracker| tracker.name.as_str())
        .collect();
    let mut inputs = trigger_source_map_whens(whens, &signals, &schemas, facts);
    for when in whens {
        if let (Some(resource), Some(binding)) = (
            tracker_trigger_handle(&when.pattern, &trackers),
            binding_after_as(&when.pattern),
        ) {
            inputs.insert(binding.into(), BTreeSet::from([resource.into()]));
        }
    }
    inputs
}

/// The actual rule's non-fact sources, including opaque grant traffic.
pub(super) fn own_reads(
    context: ProgramContext<'_>,
    body: &RuleBodyAnalysis<'_>,
) -> BTreeSet<String> {
    source_reads::own(context, body)
        .into_iter()
        .map(|read| read.source)
        .collect()
}

pub(super) struct Carried {
    pub sources: BTreeSet<String>,
    pub attributed: bool,
    pub marked: bool,
    pub declassified: bool,
    pub endorsed: bool,
}

/// Markers are properties of actual payload origins, not names substituted into a helper.
pub(super) fn carried(
    body: &RuleBodyAnalysis<'_>,
    context: ProgramContext<'_>,
    facts: &Reach,
    sink: &Sink<'_>,
    claims: &BTreeSet<Origin>,
) -> Result<Carried, Box<Diagnostic>> {
    let constants = constants(context);
    let mut graph = Graph::new(&body.rule.typed, &constants)?;
    let mut origins = BTreeSet::new();
    for expr in sink.payload {
        origins.extend(
            graph
                .trace_at(sink.node, expr)?
                .sources
                .into_iter()
                .map(|source| source.origin),
        );
    }
    let marked = |declassify: bool| {
        !origins.is_empty()
            && origins.iter().all(|origin| {
                if !declassify && claims.contains(origin) {
                    true
                } else {
                    match origin {
                        Origin::Operation(node) => {
                            let contract = &body.rule.typed.effects[node].contract;
                            if declassify {
                                contract.declassified
                            } else {
                                contract.endorsed
                            }
                        }
                        Origin::Crossing(_) => declassify,
                        _ => false,
                    }
                }
            })
    };
    let all_marked = !origins.is_empty()
        && origins.iter().all(|origin| {
            if claims.contains(origin) {
                true
            } else {
                match origin {
                    Origin::Operation(node) => {
                        let contract = &body.rule.typed.effects[node].contract;
                        contract.declassified || contract.endorsed
                    }
                    Origin::Crossing(_) => true,
                    _ => false,
                }
            }
        });
    let declassified = marked(true);
    let endorsed = marked(false);
    let inputs = input_map(context, &body.rule.root.whens, facts);
    let mut walk = Sources {
        body,
        graph,
        inputs: &inputs,
        pending: Vec::new(),
        seen: BTreeSet::new(),
        sources: BTreeSet::new(),
        fallback: false,
        attributed: true,
    };
    walk.sink(sink)?;
    Ok(Carried {
        sources: walk.sources,
        attributed: walk.attributed,
        marked: all_marked,
        declassified,
        endorsed,
    })
}
