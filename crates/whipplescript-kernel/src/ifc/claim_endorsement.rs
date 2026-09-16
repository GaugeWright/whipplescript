//! Static claim marks and closed record fields over actual hygienic values.
use super::output_integrity::managed::{incomplete, sinks::record_fields};
use super::program_context::ProgramContext;
use super::*;
use whipplescript_parser::action_plan::resolved::TypedActionPlan;
use whipplescript_parser::action_plan::value_flow::{Graph, Origin, Trace};
use whipplescript_parser::action_plan::{BindingId, NodeId, NodeKind};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt};
use whipplescript_parser::{Expr, IrSchema};

pub(super) type Marks = BTreeMap<String, BTreeSet<Origin>>;

pub(super) fn check(
    bodies: &CompositionBodies<'_>,
    verified: &VerifiedEnvelope,
) -> Result<Marks, Vec<Diagnostic>> {
    let context = ProgramContext::Composition(bodies.source());
    let mut marks = Marks::new();
    let mut diagnostics = Vec::new();
    for body in bodies.rules() {
        match rule(body, context, verified.envelope(), &mut diagnostics) {
            Ok(roots) => {
                marks.insert(body.rule.root.name.name.clone(), roots);
            }
            Err(error) => diagnostics.push(*error),
        }
    }
    if !diagnostics.is_empty() {
        // MUTATION-SUCCESS-EXPR: Ok(marks)
        return Err(diagnostics);
    }
    Ok(marks)
}

fn at_node(
    mut error: Box<Diagnostic>,
    body: &RuleBodyAnalysis<'_>,
    node: NodeId,
) -> Box<Diagnostic> {
    let span = body.rule.typed.plan.nodes[node.0].span;
    if error.span != (whipplescript_parser::SourceSpan { start: 0, end: 0 }) && error.span != span {
        error.related.push(RelatedInfo {
            span: error.span,
            message: "claim influence originates here".into(),
        });
    }
    error.span = span;
    managed_call_context(&mut error, &body.rule.typed.plan, node);
    error
}

fn rule(
    body: &RuleBodyAnalysis<'_>,
    context: ProgramContext<'_>,
    envelope: &Envelope,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<BTreeSet<Origin>, Box<Diagnostic>> {
    let typed = &body.rule.typed;
    let claims: Vec<_> = typed
        .effects
        .keys()
        .copied()
        .filter(|node| {
            matches!(&typed.plan.nodes[node.0].kind, NodeKind::Statement(statement)
            if matches!(statement.as_ref(), BodyStmt::Effect(effect)
                if matches!(effect.kind, BodyEffectKind::TrackerClaim { endorsed: true, .. })))
        })
        .collect();
    let Some(first) = claims.first().copied() else {
        return Ok(BTreeSet::new());
    };
    let constants = fact_producers::constants(context);
    let graph = Graph::new(typed, &constants).map_err(|error| at_node(error, body, first))?;
    let mut walk = Influence { typed, graph };
    let mut marked: BTreeMap<Origin, BTreeSet<NodeId>> = BTreeMap::new();
    for node in claims {
        let start = diagnostics.len();
        for tracker in &body.inventory.effects[&node].resources {
            claim_policy::tracker(
                &body.rule.root.name.name,
                typed.plan.nodes[node.0].span,
                tracker,
                envelope,
                diagnostics,
            );
        }
        for error in &mut diagnostics[start..] {
            managed_call_context(error, &typed.plan, node);
        }
        let subject = typed.effects[&node]
            .resource_subject
            .expect("validated claim subject");
        for origin in walk
            .originals(subject)
            .map_err(|error| at_node(error, body, node))?
        {
            marked.entry(origin).or_default().insert(node);
        }
    }
    for (index, node) in typed.plan.nodes.iter().enumerate() {
        let NodeKind::Statement(statement) = &node.kind else {
            continue;
        };
        let record = match statement.as_ref() {
            BodyStmt::Record(record)
            | BodyStmt::Done {
                replacement: Some(record),
                ..
            } => record,
            _ => continue,
        };
        let id = NodeId(index);
        let result = (|| {
            let mut classes = context.schemas().iter().filter_map(|schema| match schema {
                IrSchema::Class(class) if class.name == record.schema => Some(class),
                _ => None,
            });
            let class = classes
                .next()
                .filter(|_| classes.next().is_none())
                .ok_or_else(|| {
                    incomplete("claim field checking requires one actual class declaration")
                })?;
            let fields = record_fields(
                record,
                context,
                &typed.plan.blocks[node.block.0].environment,
            )?;
            for (name, expression) in fields {
                let field = class
                    .fields
                    .iter()
                    .find(|field| field.name == name)
                    .ok_or_else(|| {
                        incomplete(&format!("claim field `{name}` has no declared type"))
                    })?;
                let trace = walk.graph.trace_at(id, &expression)?;
                let causes = walk.influenced(trace, &marked)?;
                if !causes.is_empty() {
                    let start = diagnostics.len();
                    claim_policy::field(
                        &body.rule.root.name.name,
                        node.span,
                        &record.schema,
                        &name,
                        &field.ty,
                        diagnostics,
                    );
                    for error in &mut diagnostics[start..] {
                        managed_call_context(error, &typed.plan, id);
                        for cause in &causes {
                            error.related.push(RelatedInfo {
                                span: typed.plan.nodes[cause.0].span,
                                message: "possible claim origin for this field".into(),
                            });
                            managed_call_context(error, &typed.plan, *cause);
                        }
                        let mut seen = BTreeSet::new();
                        error.related.retain(|related| {
                            seen.insert((
                                related.span.start,
                                related.span.end,
                                related.message.clone(),
                            ))
                        });
                    }
                }
            }
            Ok::<_, Box<Diagnostic>>(())
        })();
        result.map_err(|error| at_node(error, body, id))?;
    }
    Ok(marked.into_keys().collect())
}

struct Influence<'a> {
    typed: &'a TypedActionPlan,
    graph: Graph<'a>,
}
impl Influence<'_> {
    fn originals(&self, binding: BindingId) -> Result<BTreeSet<Origin>, Box<Diagnostic>> {
        let mut pending: Vec<_> = self
            .graph
            .trace_binding(binding)?
            .sources
            .into_iter()
            .map(|source| source.origin)
            .collect();
        let mut seen = BTreeSet::new();
        let mut originals = BTreeSet::new();
        while let Some(origin) = pending.pop() {
            if !seen.insert(origin.clone()) {
                continue;
            }
            if let Origin::Operation(node) = &origin {
                if self.typed.effects[node].contract.kind == IrEffectKind::TrackerClaim {
                    let subject = self.typed.effects[node]
                        .resource_subject
                        .expect("validated claim subject");
                    pending.extend(
                        self.graph
                            .trace_binding(subject)?
                            .sources
                            .into_iter()
                            .map(|source| source.origin),
                    );
                    continue;
                }
            }
            originals.insert(origin);
        }
        Ok(originals)
    }

    fn influenced(
        &mut self,
        trace: Trace,
        marked: &BTreeMap<Origin, BTreeSet<NodeId>>,
    ) -> Result<BTreeSet<NodeId>, Box<Diagnostic>> {
        if marked.is_empty() {
            return Ok(BTreeSet::new());
        }
        let mut pending: Vec<_> = trace
            .sources
            .into_iter()
            .map(|source| source.origin)
            .collect();
        let mut seen = BTreeSet::new();
        let mut causes = BTreeSet::new();
        while let Some(origin) = pending.pop() {
            if let Some(nodes) = marked.get(&origin) {
                causes.extend(nodes.iter().copied());
                continue;
            }
            if !seen.insert(origin.clone()) {
                continue;
            }
            match origin {
                Origin::Input(_) => {}
                Origin::Operation(node) => {
                    let NodeKind::Statement(statement) = &self.typed.plan.nodes[node.0].kind else {
                        unreachable!("checked operation")
                    };
                    let BodyStmt::Effect(effect) = statement.as_ref() else {
                        unreachable!("checked effect")
                    };
                    if let BodyEffectKind::TrackerClaim { .. } = effect.kind {
                        let roots = self.originals(
                            self.typed.effects[&node]
                                .resource_subject
                                .expect("validated claim subject"),
                        )?;
                        pending.extend(roots);
                    } else if let Some(inputs) = effect.kind.carried_input_expressions() {
                        for input in inputs {
                            self.enqueue(node, input, &mut pending)?;
                        }
                    } else {
                        // Opaque outputs may retain any rule input. Absence of an
                        // input contract cannot certify that claim influence vanished.
                        causes.extend(marked.values().flatten().copied());
                    }
                }
                Origin::Crossing(node) => {
                    let NodeKind::Statement(statement) = &self.typed.plan.nodes[node.0].kind else {
                        unreachable!("checked crossing")
                    };
                    let BodyStmt::Declassify { source, .. } = statement.as_ref() else {
                        unreachable!("checked crossing")
                    };
                    self.enqueue(node, source, &mut pending)?;
                }
                Origin::Outcome { .. } | Origin::Lapse(_) => {
                    causes.extend(marked.values().flatten().copied())
                }
            }
        }
        Ok(causes)
    }
    fn enqueue(
        &mut self,
        node: NodeId,
        source: &str,
        pending: &mut Vec<Origin>,
    ) -> Result<(), Box<Diagnostic>> {
        let expression: Expr = whipplescript_parser::parse_expression(source)
            .map_err(|message| incomplete(&message))?;
        pending.extend(
            self.graph
                .trace_at(node, &expression)?
                .sources
                .into_iter()
                .map(|source| source.origin),
        );
        Ok(())
    }
}
