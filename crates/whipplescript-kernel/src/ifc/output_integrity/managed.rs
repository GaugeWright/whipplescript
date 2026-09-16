//! Per-sink executor influence, using the shared IFC transfer and sink policy.
//! The compiler owns sink coverage, expression types and complete producer IR.
use super::*;
use crate::ifc::program_context::ProgramContext;
pub mod sinks;
use whipplescript_parser::action_plan::resolved::TypedActionPlan;
use whipplescript_parser::action_plan::value_flow::{Control, Graph, Origin, Trace};
use whipplescript_parser::action_plan::{BindingId, BindingSource, NodeId, NodeKind, ScopeId};
use whipplescript_parser::body::BodyStmt;
use whipplescript_parser::{Expr, ExprLiteral, IrSchema};

/// An actual compiler-checked egress expression and its policy resource.
/// Every sink must be supplied by the owning full-program checker.
pub struct Sink<'a> {
    pub node: NodeId,
    pub resource: &'a str,
    pub payload: &'a [Expr],
    /// Destination selection is never endorsed by a payload marker.
    pub selection: &'a [Control],
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::ifc) struct Token {
    pub handle: String,
    pub crossed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Work {
    Value(Origin, bool),
    Selection(Control),
    Outcome(BindingId),
}

pub fn check_sink(
    typed: &TypedActionPlan,
    ir: &IrProgram,
    verified: &VerifiedEnvelope,
    sink: Sink<'_>,
) -> Vec<Diagnostic> {
    let schemas = ir
        .schemas
        .iter()
        .filter_map(|schema| match schema {
            IrSchema::Class(class) => Some(class.name.as_str()),
            _ => None,
        })
        .collect();
    let signals = ir.events.iter().map(|event| event.name.as_str()).collect();
    let facts = fact_reach_map(ir, verified.envelope(), &signals, &schemas);
    check_sink_in(typed, ProgramContext::Legacy(ir), verified, sink, &facts)
}

pub(in crate::ifc) fn check_sink_in(
    typed: &TypedActionPlan,
    ir: ProgramContext<'_>,
    verified: &VerifiedEnvelope,
    sink: Sink<'_>,
    facts: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Diagnostic> {
    let result = collect(typed, ir, &sink, facts);
    let mut diagnostics = match result {
        Err(issue) => vec![*issue],
        Ok(tokens) => tokens
            .into_iter()
            .filter(|token| {
                denied(
                    verified.envelope(),
                    &token.handle,
                    sink.resource,
                    token.crossed,
                )
            })
            .map(|token| {
                diagnostic(
                    &typed.plan.root_rule.as_ref().expect("checked root").name,
                    typed.plan.nodes[sink.node.0].span,
                    &token.handle,
                    sink.resource,
                    token.crossed,
                    verified.envelope(),
                )
            })
            .collect(),
    };
    // A corrupt plan has no safe ownership chain to traverse.
    if typed.validate_structure().is_ok() {
        if let Some(node) = typed.plan.nodes.get(sink.node.0) {
            for diagnostic in &mut diagnostics {
                if diagnostic.span == (SourceSpan { start: 0, end: 0 }) {
                    diagnostic.span = node.span;
                }
                managed_call_context(diagnostic, &typed.plan, sink.node);
            }
        }
    }
    diagnostics
}
/// Raw executor identities; a producer must discard the sink-local crossed flag.
pub(in crate::ifc) fn collect(
    typed: &TypedActionPlan,
    ir: ProgramContext<'_>,
    sink: &Sink<'_>,
    facts: &BTreeMap<String, BTreeSet<String>>,
) -> Result<BTreeSet<Token>, Box<Diagnostic>> {
    let constants: BTreeSet<String> = ir
        .agents()
        .iter()
        .map(|agent| agent.name.clone())
        .chain(
            ir.schemas()
                .iter()
                .filter_map(|schema| match schema {
                    IrSchema::Enum(e) => Some(e),
                    _ => None,
                })
                .flat_map(|e| e.variants.clone()),
        )
        .collect();
    let graph = Graph::new(typed, &constants)?;
    let Some(root) = typed.plan.root_rule.as_ref() else {
        let message = "managed executor analysis requires a root rule";
        // MUTATION-SUCCESS-EXPR: Ok(BTreeSet::new())
        return Err(incomplete(message));
    };
    let Some(rule) = ir.root(&root.name) else {
        let message = "managed executor analysis requires one matching rule declaration";
        // MUTATION-SUCCESS-EXPR: Ok(BTreeSet::new())
        return Err(incomplete(message));
    };
    if sink.resource.is_empty() {
        // MUTATION-SUCCESS-EXPR: Ok(BTreeSet::new())
        return Err(incomplete("managed executor sink requires a resource"));
    }
    let schemas = ir
        .schemas()
        .iter()
        .filter_map(|s| match s {
            IrSchema::Class(c) => Some(c.name.as_str()),
            _ => None,
        })
        .collect();
    let signals = ir.events().iter().map(|e| e.name.as_str()).collect();
    let inputs = trigger_source_map_whens(rule.whens, &signals, &schemas, facts);
    let mut walk = Walk {
        typed,
        ir,
        graph,
        inputs,
        pending: Vec::new(),
        seen: BTreeSet::new(),
        tokens: BTreeSet::new(),
    };
    // Even a constant/empty payload observes its lexical selection context.
    let context = walk
        .graph
        .trace_at(sink.node, &Expr::Literal(ExprLiteral::Null))?;
    walk.enqueue(context, false);
    walk.pending
        .extend(sink.selection.iter().cloned().map(Work::Selection));
    for expr in sink.payload {
        let trace = walk.graph.trace_at(sink.node, expr)?;
        walk.enqueue(trace, false);
    }
    walk.run()?;
    Ok(walk.tokens)
}

struct Walk<'a> {
    typed: &'a TypedActionPlan,
    ir: ProgramContext<'a>,
    graph: Graph<'a>,
    inputs: BTreeMap<String, BTreeSet<String>>,
    pending: Vec<Work>,
    seen: BTreeSet<Work>,
    tokens: BTreeSet<Token>,
}
impl Walk<'_> {
    fn enqueue(&mut self, trace: Trace, crossed: bool) {
        self.pending.extend(
            trace
                .sources
                .into_iter()
                .map(|source| Work::Value(source.origin, crossed)),
        );
        // A payload marker cannot endorse a selector as a side effect.
        self.pending
            .extend(trace.controls.into_iter().map(Work::Selection));
    }
    fn expression(
        &mut self,
        node: NodeId,
        source: &str,
        crossed: bool,
    ) -> Result<(), Box<Diagnostic>> {
        let expr = whipplescript_parser::parse_expression(source)
            .map_err(|message| incomplete(&message))?;
        let trace = self.graph.trace_at(node, &expr)?;
        self.enqueue(trace, crossed);
        Ok(())
    }
    fn run(&mut self) -> Result<(), Box<Diagnostic>> {
        while let Some(work) = self.pending.pop() {
            if !self.seen.insert(work.clone()) {
                continue;
            }
            match work {
                Work::Value(Origin::Input(binding), crossed) => {
                    let name = self.typed.plan.bindings[binding.0]
                        .name
                        .as_deref()
                        .unwrap_or("");
                    let Some(sources) = self.inputs.get(name) else {
                        let message = format!("input `{name}` has no matching producer analysis");
                        // MUTATION-SUCCESS-EXPR: Ok(())
                        return Err(incomplete(&message));
                    };
                    for source in sources {
                        if let Some(handle) = source.strip_prefix("output:") {
                            self.tokens.insert(Token {
                                handle: handle.into(),
                                crossed,
                            });
                        }
                    }
                }
                Work::Value(Origin::Operation(node), crossed) => self.operation(node, crossed)?,
                Work::Value(Origin::Crossing(node), crossed) => {
                    let NodeKind::Statement(statement) = &self.typed.plan.nodes[node.0].kind else {
                        unreachable!("checked crossing")
                    };
                    let BodyStmt::Declassify { source, .. } = statement.as_ref() else {
                        unreachable!("checked declassify")
                    };
                    // Declassification changes confidentiality, never executor integrity.
                    self.expression(node, source, crossed)?;
                }
                Work::Value(Origin::Outcome { observed, .. }, _) => {
                    self.pending.push(Work::Outcome(observed))
                }
                Work::Value(Origin::Lapse(node), _) => self
                    .pending
                    .push(Work::Selection(Control::Region { node, lapse: true })),
                Work::Outcome(binding) => {
                    let trace = self.graph.trace_binding(binding)?;
                    self.enqueue(trace, false);
                    if let BindingSource::Node(node) = self.typed.plan.bindings[binding.0].source {
                        if let NodeKind::Call { scope, .. } = self.typed.plan.nodes[node.0].kind {
                            self.failure_sources(scope)?;
                        }
                    }
                }
                Work::Selection(Control::Case { node, branch }) => {
                    let trace = self.graph.trace_case_selection(node, branch)?;
                    self.enqueue(trace, false);
                }
                Work::Selection(Control::After(node)) => {
                    let NodeKind::After { observed, .. } = self.typed.plan.nodes[node.0].kind
                    else {
                        unreachable!("checked after")
                    };
                    self.pending.push(Work::Outcome(observed));
                }
                Work::Selection(Control::FailureHandler(node)) => {
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
                    let NodeKind::Region { condition, .. } = &self.typed.plan.nodes[node.0].kind
                    else {
                        unreachable!("checked region")
                    };
                    self.expression(node, condition, false)?;
                }
                // Scheduling joins are not byte-producing executors. Their admission,
                // termination and confidentiality obligations are separate checks.
                Work::Selection(Control::ScopeSuccess(_) | Control::OrderedAfter(_)) => {}
            }
        }
        Ok(())
    }
    fn failure_sources(&mut self, scope: ScopeId) -> Result<(), Box<Diagnostic>> {
        for (index, node) in self.typed.plan.nodes.iter().enumerate() {
            if self.typed.plan.blocks[node.block.0].scope != Some(scope) {
                continue;
            }
            if let NodeKind::Fail(value) = &node.kind {
                let trace = self.graph.trace_at(NodeId(index), &value.expr)?;
                self.enqueue(trace, false);
            }
        }
        // Uncaught child failures can contribute an outcome without a success return.
        for node in &self.typed.plan.scopes[scope.0].operations {
            if let Some(binding) = self.typed.plan.nodes[node.0].result {
                self.pending.push(Work::Outcome(binding));
            }
        }
        Ok(())
    }
    fn operation(&mut self, node: NodeId, crossed: bool) -> Result<(), Box<Diagnostic>> {
        let effect = &self.typed.effects[&node];
        let NodeKind::Statement(statement) = &self.typed.plan.nodes[node.0].kind else {
            unreachable!("checked effect")
        };
        let BodyStmt::Effect(statement) = statement.as_ref() else {
            unreachable!("checked effect")
        };
        let carried = statement.kind.carried_input_expressions();
        match transfer(
            &effect.contract.kind,
            effect.contract.endorsed,
            effect.contract.exec_target.as_ref(),
            carried.is_some(),
        ) {
            Transfer::Agent => {
                for target in effect.agent_targets.as_ref().expect("checked tell domain") {
                    let Some(agent) = unique(
                        self.ir
                            .agents()
                            .iter()
                            .filter(|agent| agent.name == *target),
                    ) else {
                        let message = format!(
                            "checked executor `{target}` requires one matching agent declaration"
                        );
                        // MUTATION-SUCCESS-EXPR: Ok(())
                        return Err(incomplete(&message));
                    };
                    self.tokens.insert(Token {
                        // `provider_kind`, not the raw field: an agent bound
                        // `using <harness>` leaves `IrAgent::provider` empty and
                        // reaches the harness's kind, so reading the field alone
                        // vouches for it as `provider:unknown` -- no endpoint for
                        // a grant to name. The legacy walk resolves it the same
                        // way, and the two walks answering differently is what
                        // that one resolver exists to prevent.
                        handle: self
                            .ir
                            .provider_kind(agent)
                            .map(str::to_owned)
                            .unwrap_or_else(|| "provider:unknown".into()),
                        crossed,
                    });
                }
            }
            Transfer::CoerceEgress => {
                let declaration = effect.contract.coerce_target.as_deref().and_then(|target| {
                    self.ir
                        .coerces()
                        .iter()
                        .find(|declaration| declaration.name == target)
                });
                self.tokens.insert(Token {
                    handle: super::super::coerce_principal(
                        effect.contract.prompt_provider.as_deref(),
                        declaration,
                    )
                    .to_owned(),
                    crossed,
                });
            }
            Transfer::Executor(handle) => {
                self.tokens.insert(Token { handle, crossed });
            }
            Transfer::Inputs { endorsed } => {
                for argument in carried.expect("validated carried input transfer") {
                    self.expression(node, argument, crossed || endorsed)?;
                }
            }
            Transfer::None => {}
        }
        Ok(())
    }
}
fn unique<T>(mut values: impl Iterator<Item = T>) -> Option<T> {
    let first = values.next()?;
    values.next().is_none().then_some(first)
}
pub(in crate::ifc) fn incomplete(message: &str) -> Box<Diagnostic> {
    Box::new(Diagnostic::error(
        diagnostic_code!("construct.invalid_expansion"),
        SourceSpan { start: 0, end: 0 },
        message,
    ))
}
#[cfg(test)]
mod tests;
