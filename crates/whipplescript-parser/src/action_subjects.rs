//! Inferred fact-identity requirements for typed composition. Value typing and
//! readiness are separate proofs. This phase never creates a fact or effect.
use super::*;
use std::rc::Rc;
mod flow;
mod graph;
mod shape;
use shape::{Shape, Value};

#[derive(Clone)]
struct Requirement {
    subject: Value,
    witness: SourceSpan,
    trace: Vec<RelatedInfo>,
}
struct Summary {
    result: Value,
    requirements: Vec<Requirement>,
    flow: flow::Flow,
}
struct Use {
    span: SourceSpan,
    message: String,
    witness: SourceSpan,
    trace: Vec<RelatedInfo>,
}
fn error(span: SourceSpan, message: impl Into<String>) -> Diagnostic {
    Diagnostic::error(
        diagnostic_code!("construct.invalid_expansion"),
        span,
        message,
    )
}
fn require(
    subject: &Value,
    usage: &Use,
    requirements: &mut Vec<Requirement>,
    diagnostics: &mut Vec<Diagnostic>,
    semantic: &SemanticContext,
) {
    match subject.as_ref() {
        Shape::Never => return,
        Shape::Alternatives(items) => {
            for item in items {
                require(item, usage, requirements, diagnostics, semantic);
            }
            return;
        }
        Shape::Fact { .. }
        | Shape::Parameter { .. }
        | Shape::Select { .. }
        | Shape::Narrow { .. }
            if matches!(subject.as_ref(), Shape::Fact { .. })
                || (!shape::parameters(subject).is_empty()
                    && shape::possible_fact(subject, semantic)) =>
        {
            if !requirements
                .iter()
                .any(|r| r.subject == *subject && r.witness == usage.witness)
            {
                requirements.push(Requirement {
                    subject: subject.clone(),
                    witness: usage.witness,
                    trace: usage.trace.clone(),
                });
            }
            return;
        }
        _ => {}
    }
    let (origin, reason) = match subject.as_ref() {
        Shape::Data { span, reason, .. } | Shape::Unknown { span, reason } => (*span, *reason),
        Shape::Object { span, .. } | Shape::Array { span, .. } => (
            *span,
            "constructing a collection preserves its members, not a whole-fact identity",
        ),
        Shape::Parameter { span, .. } => (
            *span,
            "this parameter's value type cannot carry an admitted fact",
        ),
        Shape::Select { span, .. } | Shape::Narrow { span, .. } => (
            *span,
            "this selection cannot establish an original fact identity",
        ),
        _ => unreachable!("successful proofs and alternatives handled above"),
    };
    let mut diagnostic = error(usage.span, format!("{}: {reason}", usage.message));
    let mut related = Vec::new();
    if usage.witness != usage.span {
        related.push(RelatedInfo {
            span: usage.witness,
            message: "the original fact is consumed here".into(),
        });
    }
    related.extend(usage.trace.iter().cloned());
    if origin != usage.span && origin != usage.witness {
        related.push(RelatedInfo {
            span: origin,
            message: reason.into(),
        });
    }
    for item in related {
        if !diagnostic.related.contains(&item) {
            diagnostic.related.push(item);
        }
    }
    diagnostic.suggestion = Some(
        "pass the original matched fact through the helper instead of rebuilding its fields".into(),
    );
    if !diagnostics.contains(&diagnostic) {
        diagnostics.push(diagnostic);
    }
}
fn summarize(
    graph: &graph::Graph,
    summaries: &BTreeMap<String, Summary>,
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Summary> {
    let values = graph.resolve(summaries);
    let mut requirements = Vec::new();
    let mut flow = graph.flow.clone();
    let mut order = values.call_order.clone();
    for call in &graph.calls {
        if !order.contains(&call.id) {
            order.push(call.id);
        }
    }
    // Check producers before their users, so an invalid call does not acquire
    // a result proof that causes a cascade at every downstream consuming call.
    for id in order {
        let call = &graph.calls[id];
        let callee = &summaries[&call.name];
        flow.inherit(&callee.flow, call);
        let arguments: Vec<_> = call
            .arguments
            .iter()
            .map(|expr| values.expression(expr))
            .collect();
        for requirement in &callee.requirements {
            let parameters = shape::parameters(&requirement.subject);
            let span = if parameters.len() == 1 {
                call.arguments[*parameters.first().expect("one responsible parameter")].span
            } else {
                call.span
            };
            let mut trace = requirement.trace.clone();
            trace.push(RelatedInfo {
                span: call.span,
                message: format!("call to action `{}`", call.name),
            });
            let usage = Use { span,
                message: format!("call to action `{}` must supply an original admitted fact to its consuming helper", call.name),
                witness: requirement.witness, trace };
            let subject = shape::substitute(&requirement.subject, &arguments);
            let before = diagnostics.len();
            require(&subject, &usage, &mut requirements, diagnostics, semantic);
            if diagnostics.len() != before {
                return None;
            }
        }
    }
    for consumed in &graph.consumes {
        let usage = Use {
            span: consumed.span,
            message: format!(
                "`done {}` requires an original admitted fact",
                consumed.binding
            ),
            witness: consumed.span,
            trace: Vec::new(),
        };
        let before = diagnostics.len();
        require(
            &values.expression(&consumed.value),
            &usage,
            &mut requirements,
            diagnostics,
            semantic,
        );
        if diagnostics.len() != before {
            return None;
        }
    }
    Some(Summary {
        result: graph.result(&values),
        requirements,
        flow,
    })
}

/// One possible writer of this schema. The witness is deterministic, not a
/// complete list of producers or their input provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactWrite {
    /// Canonical dependency key, such as `schema:Ticket`.
    pub fact: String,
    pub span: SourceSpan,
    pub calls: Vec<RelatedInfo>,
}

/// May-footprint of the actual rule and its called helpers. It does not prove
/// pacing, guaranteed consumption, termination, readiness or IFC authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleFactFlow {
    pub writes: Vec<FactWrite>,
    pub consumes: BTreeSet<String>,
    pub effectful: bool,
}

#[cfg(test)]
fn validate(
    actions: &[ActionDecl],
    rules: &[&RuleDecl],
    semantic: &SemanticContext,
) -> Vec<Diagnostic> {
    analyze(actions, rules, semantic).0
}

/// Signature/value/authority phases precede this in public compilation. The
/// declaration check is repeated here to give direct callers the same finite
/// DAG guarantee; no recursive call expansion or invented callee is used.
pub(crate) fn analyze(
    actions: &[ActionDecl],
    rules: &[&RuleDecl],
    semantic: &SemanticContext,
) -> (Vec<Diagnostic>, BTreeMap<String, RuleFactFlow>) {
    let mut diagnostics = action_signature::validate(actions);
    if !diagnostics.is_empty() {
        return (diagnostics, BTreeMap::new());
    }
    for action in actions.iter().filter(|action| action.result.is_none()) {
        diagnostics.push(
            error(
                action.name.span,
                format!(
                    "action `{}` needs a result contract for scope expansion",
                    action.name.name
                ),
            )
            .with_suggestion(format!(
                "declare a result such as `action {}(...) -> null` and return it on every path",
                action.name.name
            )),
        );
    }
    if !diagnostics.is_empty() {
        return (diagnostics, BTreeMap::new());
    }
    let mut pending = BTreeMap::new();
    for action in actions.iter().filter(|action| action.result.is_some()) {
        let (body, errors) = body::parse_action_body(&action.body.text, action.body.body_base());
        diagnostics.extend(errors);
        diagnostics.extend(action_plan::validate_bindings(action, &body));
        validate_recorded_schemas_named(
            &format!("action `{}`", action.name.name),
            &body.statements,
            semantic,
            &mut diagnostics,
        );
        let inputs = action.params.iter().enumerate().map(|(index, param)| {
            (
                param.name.name.clone(),
                Rc::new(Shape::Parameter {
                    index,
                    ty: lower_type(param.ty.clone()),
                    span: param.ty.span(),
                }),
            )
        });
        pending.insert(
            action.name.name.clone(),
            graph::Graph::build(&body.statements, inputs),
        );
    }
    if !diagnostics.is_empty() {
        return (diagnostics, BTreeMap::new());
    }
    let mut summaries = BTreeMap::new();
    let mut invalid = BTreeSet::new();
    while !pending.is_empty() {
        let ready = pending
            .iter()
            .find(|(_, graph)| {
                graph
                    .calls
                    .iter()
                    .all(|call| summaries.contains_key(&call.name) || invalid.contains(&call.name))
            })
            .map(|(name, _)| name.clone())
            .expect("validated action call graph has a ready definition");
        let graph = pending.remove(&ready).expect("selected pending definition");
        if graph.calls.iter().any(|call| invalid.contains(&call.name)) {
            invalid.insert(ready);
            continue;
        }
        match summarize(&graph, &summaries, semantic, &mut diagnostics) {
            Some(summary) => {
                summaries.insert(ready, summary);
            }
            None => {
                invalid.insert(ready);
            }
        }
    }
    if !diagnostics.is_empty() {
        diagnostics.sort_by_key(|error| (error.span.start, error.span.end));
        return (diagnostics, BTreeMap::new());
    }
    let mut flows = BTreeMap::new();
    for rule in rules {
        let (body, errors) = body::parse_composed_rule_body(&rule.body.text, rule.body.body_base());
        if !errors.is_empty() {
            diagnostics.extend(errors);
            continue;
        }
        let mut names = Vec::new();
        let mut inputs = Vec::new();
        for when in &rule.whens {
            if let Some((name, schema)) = binding_from_when(&when.text) {
                let (pattern, _) = split_when_guard(&when.text);
                let start = pattern
                    .rfind(&name)
                    .expect("matched alias occurs in trigger");
                let span = when_guard_span(when, &pattern[start..start + name.len()]);
                names.push(Ident {
                    name: name.clone(),
                    span,
                });
                inputs.push((name, Rc::new(Shape::Fact { schema, span })));
            }
        }
        let errors = action_plan::validate_rule_bindings(&body, &names);
        if !errors.is_empty() {
            diagnostics.extend(errors);
            continue;
        }
        let before = diagnostics.len();
        validate_recorded_schemas(rule, &body.statements, semantic, &mut diagnostics);
        if diagnostics.len() != before {
            continue;
        }
        let graph = graph::Graph::build(&body.statements, inputs);
        if let Some(summary) = summarize(&graph, &summaries, semantic, &mut diagnostics) {
            summary
                .flow
                .validate(rule, &summary.requirements, &mut diagnostics);
            flows.insert(
                rule.name.name.clone(),
                summary.flow.metadata(&summary.requirements),
            );
        }
    }
    (diagnostics, flows)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod flow_tests;
