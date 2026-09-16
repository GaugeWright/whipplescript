//! Preserve inherited input-selection constraints through the hygienic graph.
use super::output_integrity::managed::incomplete;
use super::program_context::ProgramContext;
use super::*;
use whipplescript_parser::action_plan::resolved::TypedActionPlan;
use whipplescript_parser::action_plan::value_flow::{Control, Graph, Origin, Trace};
use whipplescript_parser::action_plan::{BindingId, BindingSource, NodeId, NodeKind, ScopeId};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt};
use whipplescript_parser::{Expr, ExprLiteral};

pub(super) fn check(
    body: &RuleBodyAnalysis<'_>,
    context: ProgramContext<'_>,
    envelope: &Envelope,
    destinations: &BTreeMap<(NodeId, String), Option<&ManagedOwnedSink>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let inputs = selector_policy::inputs(context, &body.rule.root.whens);
    if inputs.is_empty() {
        return;
    }
    let typed = &body.rule.typed;
    let constants = fact_producers::constants(context);
    let graph = match Graph::new(typed, &constants) {
        Ok(graph) => graph,
        Err(error) => {
            diagnostics.push(*error);
            return;
        }
    };
    let mut walk = Walk {
        typed,
        graph,
        pending: Vec::new(),
        seen: BTreeSet::new(),
        inputs: BTreeSet::new(),
        sites: BTreeSet::new(),
    };
    for (index, node) in typed.plan.nodes.iter().enumerate() {
        let id = NodeId(index);
        let crossing = match &node.kind {
            NodeKind::Statement(statement) => match statement.as_ref() {
                BodyStmt::Declassify { .. } => Some(true),
                BodyStmt::Effect(effect)
                    if matches!(
                        effect.kind,
                        BodyEffectKind::TrackerClaim { endorsed: true, .. }
                    ) =>
                {
                    Some(false)
                }
                BodyStmt::Effect(_) => typed.effects.get(&id).and_then(|effect| {
                    (effect.contract.endorsed || effect.contract.declassified)
                        .then_some(effect.contract.declassified)
                }),
                _ => None,
            },
            _ => None,
        };
        let sinks: Vec<_> = destinations
            .keys()
            .filter(|(node, _)| *node == id)
            .map(|(_, sink)| sink)
            .collect();
        if crossing.is_none() && sinks.is_empty() {
            continue;
        }
        let result = (|| {
            let mut controls = walk
                .graph
                .trace_at(id, &Expr::Literal(ExprLiteral::Null))?
                .controls;
            if let Some(effect) = body.inventory.effects.get(&id) {
                controls.extend(effect.controls.iter().cloned());
            }
            for control in controls {
                let (site, scrutinee, pattern) = match &control {
                    Control::Case { node, branch } => {
                        let NodeKind::Case {
                            scrutinee,
                            branches,
                        } = &typed.plan.nodes[node.0].kind
                        else {
                            unreachable!("checked case")
                        };
                        (*node, scrutinee.clone(), branches[*branch].pattern.clone())
                    }
                    Control::After(node) => {
                        let NodeKind::After { observed, .. } = typed.plan.nodes[node.0].kind else {
                            unreachable!("checked after")
                        };
                        (
                            *node,
                            typed.plan.bindings[observed.0]
                                .name
                                .clone()
                                .unwrap_or_else(|| "operation outcome".into()),
                            "outcome".into(),
                        )
                    }
                    Control::FailureHandler(node) => {
                        (*node, "scope failures".into(), "unrecovered".into())
                    }
                    Control::Region { node, .. } | Control::RegionExit(node) => {
                        let NodeKind::Region { condition, .. } = &typed.plan.nodes[node.0].kind
                        else {
                            unreachable!("checked region")
                        };
                        (
                            *node,
                            condition.clone(),
                            match control {
                                Control::Region { lapse: true, .. } => "lapse",
                                Control::Region { lapse: false, .. } => "active",
                                _ => "clean exit",
                            }
                            .into(),
                        )
                    }
                    Control::OrderedAfter(_) | Control::ScopeSuccess(_) => continue,
                };
                walk.selection(control)?;
                for (binding, marked) in &walk.inputs {
                    let Some(name) = typed.plan.bindings[binding.0].name.as_ref() else {
                        continue;
                    };
                    let Some(input) = inputs.get(name) else {
                        continue;
                    };
                    let selection = selector_policy::Selection {
                        rule: &body.rule.root.name.name,
                        span: node.span,
                        scrutinee: &scrutinee,
                        pattern: &pattern,
                    };
                    let start = diagnostics.len();
                    if let Some(declassified) = crossing {
                        selection.crossing(input, *marked, declassified, envelope, diagnostics);
                    }
                    for sink in &sinks {
                        selection.invocation(input, *marked, sink, envelope, diagnostics);
                    }
                    for error in &mut diagnostics[start..] {
                        managed_call_context(error, &typed.plan, id);
                        for cause in walk.sites.iter().copied().chain(std::iter::once(site)) {
                            error.related.push(RelatedInfo {
                                span: typed.plan.nodes[cause.0].span,
                                message: "this selection controls the operation".into(),
                            });
                            managed_call_context(error, &typed.plan, cause);
                        }
                        error.related.push(RelatedInfo {
                            span: typed.plan.bindings[binding.0].span,
                            message: format!("original selector input `{name}`"),
                        });
                        let mut seen = BTreeSet::new();
                        error
                            .related
                            .retain(|r| seen.insert((r.span.start, r.span.end, r.message.clone())));
                    }
                }
            }
            Ok::<_, Box<Diagnostic>>(())
        })();
        if let Err(mut error) = result {
            if error.span != node.span {
                error.related.push(RelatedInfo {
                    span: error.span,
                    message: "selector analysis failed here".into(),
                });
            }
            error.span = node.span;
            managed_call_context(&mut error, &typed.plan, id);
            diagnostics.push(*error);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Work {
    Value(Origin, bool),
    Selection(Control),
    Outcome(BindingId),
}
struct Walk<'a> {
    typed: &'a TypedActionPlan,
    graph: Graph<'a>,
    pending: Vec<Work>,
    seen: BTreeSet<Work>,
    inputs: BTreeSet<(BindingId, bool)>,
    sites: BTreeSet<NodeId>,
}
impl Walk<'_> {
    fn enqueue(&mut self, trace: Trace, marked: bool) {
        self.pending.extend(
            trace
                .sources
                .into_iter()
                .map(|s| Work::Value(s.origin, marked)),
        );
        self.pending
            .extend(trace.controls.into_iter().map(Work::Selection));
    }
    fn expression(
        &mut self,
        node: NodeId,
        text: &str,
        marked: bool,
    ) -> Result<(), Box<Diagnostic>> {
        let expr =
            whipplescript_parser::parse_expression(text).map_err(|message| incomplete(&message))?;
        let trace = self.graph.trace_at(node, &expr)?;
        self.enqueue(trace, marked);
        Ok(())
    }
    fn failure_sources(&mut self, scope: ScopeId) -> Result<(), Box<Diagnostic>> {
        for (index, node) in self.typed.plan.nodes.iter().enumerate() {
            if self.typed.plan.blocks[node.block.0].scope == Some(scope) {
                if let NodeKind::Fail(value) = &node.kind {
                    let trace = self.graph.trace_at(NodeId(index), &value.expr)?;
                    self.enqueue(trace, false);
                }
            }
        }
        for node in &self.typed.plan.scopes[scope.0].operations {
            if let Some(binding) = self.typed.plan.nodes[node.0].result {
                self.pending.push(Work::Outcome(binding));
            }
        }
        Ok(())
    }
    fn selection(&mut self, control: Control) -> Result<(), Box<Diagnostic>> {
        self.pending.clear();
        self.seen.clear();
        self.inputs.clear();
        self.sites.clear();
        self.pending.push(Work::Selection(control));
        while let Some(work) = self.pending.pop() {
            if !self.seen.insert(work.clone()) {
                continue;
            }
            match work {
                Work::Value(Origin::Input(binding), marked) => {
                    self.inputs.insert((binding, marked));
                }
                Work::Value(Origin::Operation(node), marked) => {
                    let NodeKind::Statement(statement) = &self.typed.plan.nodes[node.0].kind else {
                        unreachable!("checked operation")
                    };
                    let BodyStmt::Effect(effect) = statement.as_ref() else {
                        unreachable!("checked effect")
                    };
                    if let Some(inputs) = effect.kind.carried_input_expressions() {
                        let marked = marked || self.typed.effects[&node].contract.endorsed;
                        for input in inputs {
                            self.expression(node, input, marked)?;
                        }
                    } else {
                        // Without an input contract, retain every possible original
                        // input. This is conservative influence, not exact byte provenance.
                        self.inputs.extend(
                            self.typed
                                .plan
                                .root_inputs
                                .iter()
                                .map(|binding| (*binding, marked)),
                        );
                    }
                }
                Work::Value(Origin::Crossing(node), marked) => {
                    let NodeKind::Statement(statement) = &self.typed.plan.nodes[node.0].kind else {
                        unreachable!("checked crossing")
                    };
                    let BodyStmt::Declassify { source, .. } = statement.as_ref() else {
                        unreachable!("checked crossing")
                    };
                    self.expression(node, source, marked)?;
                }
                Work::Value(Origin::Outcome { observed, .. }, _) => {
                    self.pending.push(Work::Outcome(observed))
                }
                Work::Value(Origin::Lapse(node), _) => self
                    .pending
                    .push(Work::Selection(Control::Region { node, lapse: true })),
                Work::Outcome(binding) => {
                    self.enqueue(self.graph.trace_binding(binding)?, false);
                    if let BindingSource::Node(node) = self.typed.plan.bindings[binding.0].source {
                        if let NodeKind::Call { scope, .. } = self.typed.plan.nodes[node.0].kind {
                            self.failure_sources(scope)?;
                        }
                    }
                }
                Work::Selection(Control::Case { node, branch }) => {
                    self.sites.insert(node);
                    let trace = self.graph.trace_case_selection(node, branch)?;
                    self.enqueue(trace, false);
                }
                Work::Selection(Control::After(node)) => {
                    self.sites.insert(node);
                    let NodeKind::After { observed, .. } = self.typed.plan.nodes[node.0].kind
                    else {
                        unreachable!("checked after")
                    };
                    self.pending.push(Work::Outcome(observed));
                }
                Work::Selection(Control::FailureHandler(node)) => {
                    self.sites.insert(node);
                    self.pending.extend(
                        self.typed
                            .plan
                            .protected_operation_nodes(node)
                            .into_iter()
                            .filter_map(|operation| self.typed.plan.nodes[operation.0].result)
                            .map(Work::Outcome),
                    );
                }
                Work::Selection(Control::Region { node, .. } | Control::RegionExit(node)) => {
                    self.sites.insert(node);
                    let NodeKind::Region { condition, .. } = &self.typed.plan.nodes[node.0].kind
                    else {
                        unreachable!("checked region")
                    };
                    self.expression(node, condition, false)?;
                }
                Work::Selection(Control::OrderedAfter(_) | Control::ScopeSuccess(_)) => {}
            }
        }
        // A raw route imposes the stronger obligation for this same input and
        // selection. Keep independent inputs; avoid repeating a weaker route.
        let raw: BTreeSet<_> = self
            .inputs
            .iter()
            .filter(|(_, marked)| !marked)
            .map(|(binding, _)| *binding)
            .collect();
        self.inputs
            .retain(|(binding, marked)| !marked || !raw.contains(binding));
        Ok(())
    }
}
