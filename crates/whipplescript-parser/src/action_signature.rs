//! DR-0100 declaration checks, before hygienic expansion. No provider work or
//! runtime scope is created here. The finite call-graph model is
//! `models/maude/action-call-graph.maude`.

use std::collections::BTreeMap;

use crate::body::{self, BodyAst, BodyStmt, CompositionStmt};
use crate::{diagnostic_code, ActionDecl, Diagnostic, SourceSpan};

struct Call {
    target: usize,
    span: SourceSpan,
}

fn error(span: SourceSpan, message: String) -> Diagnostic {
    Diagnostic::error(
        diagnostic_code!("construct.invalid_expansion"),
        span,
        message,
    )
}

/// Check every visible definition, including unused actions. DFS uses an
/// explicit stack so a long finite chain cannot overflow the compiler stack.
/// A repeated definition on ANOTHER completed path is ordinary composition.
pub(crate) fn validate(actions: &[ActionDecl]) -> Vec<Diagnostic> {
    let mut names: BTreeMap<&str, usize> = BTreeMap::new();
    let mut diagnostics = Vec::new();
    for (index, action) in actions.iter().enumerate() {
        if let Some(&first) = names.get(action.name.name.as_str()) {
            diagnostics.push(
                error(
                    action.name.span,
                    format!("duplicate action `{}`", action.name.name),
                )
                .with_related(actions[first].name.span, "first action definition"),
            );
        } else {
            names.insert(action.name.name.as_str(), index);
        }
        let mut params = BTreeMap::new();
        for param in &action.params {
            if let Some(&first) = params.get(param.name.name.as_str()) {
                diagnostics.push(
                    error(
                        param.name.span,
                        format!(
                            "duplicate parameter `{}` in action `{}`",
                            param.name.name, action.name.name
                        ),
                    )
                    .with_related(first, "first parameter declaration"),
                );
            } else {
                params.insert(param.name.name.as_str(), param.name.span);
            }
        }
    }
    if !diagnostics.is_empty() {
        return diagnostics;
    }
    let bodies: Vec<BodyAst> = actions
        .iter()
        .map(|action| {
            let (body, errors) =
                body::parse_action_body(&action.body.text, action.body.body_base());
            diagnostics.extend(errors);
            body
        })
        .collect();
    if !diagnostics.is_empty() {
        return diagnostics;
    }
    let graph: Vec<Vec<Call>> = bodies.iter().map(|body| calls(body, &names)).collect();
    let mut state = vec![0u8; actions.len()];
    for root in 0..actions.len() {
        if state[root] != 0 {
            continue;
        }
        let mut stack = vec![(root, 0usize)];
        state[root] = 1;
        while let Some(&(caller, next)) = stack.last() {
            let Some(call) = graph[caller].get(next) else {
                state[caller] = 2;
                stack.pop();
                continue;
            };
            stack.last_mut().expect("current frame").1 += 1;
            match state[call.target] {
                0 => {
                    state[call.target] = 1;
                    stack.push((call.target, 0));
                }
                1 => {
                    let start = stack
                        .iter()
                        .position(|&(node, _)| node == call.target)
                        .expect("active definition is on the current path");
                    let mut path: Vec<&str> = stack[start..]
                        .iter()
                        .map(|&(node, _)| actions[node].name.name.as_str())
                        .collect();
                    path.push(actions[call.target].name.name.as_str());
                    let mut diagnostic = error(
                        call.span,
                        format!("recursive action expansion: {}", path.join(" -> ")),
                    )
                    .with_suggestion(
                        "break this call cycle; actions must expand to a finite graph",
                    );
                    for &(node, next) in &stack[start..] {
                        diagnostic = diagnostic.with_related(
                            actions[node].name.span,
                            format!("action `{}` is defined here", actions[node].name.name),
                        );
                        let edge = &graph[node][next - 1];
                        if edge.span != call.span {
                            diagnostic = diagnostic.with_related(
                                edge.span,
                                format!(
                                    "`{}` calls `{}` here",
                                    actions[node].name.name, actions[edge.target].name.name
                                ),
                            );
                        }
                    }
                    diagnostics.push(diagnostic);
                    return diagnostics;
                }
                _ => {}
            }
        }
    }
    diagnostics
}

fn calls(body: &BodyAst, names: &BTreeMap<&str, usize>) -> Vec<Call> {
    let mut pending: Vec<&BodyStmt> = body.statements.iter().rev().collect();
    let mut calls = Vec::new();
    while let Some(statement) = pending.pop() {
        match statement {
            BodyStmt::Composition(CompositionStmt::Call {
                name, name_span, ..
            }) => {
                if let Some(&target) = names.get(name.as_str()) {
                    calls.push(Call {
                        target,
                        span: *name_span,
                    });
                }
            }
            BodyStmt::Composition(CompositionStmt::Then { operation, .. }) => {
                pending.push(operation)
            }
            BodyStmt::Composition(CompositionStmt::OnFailure { body, .. }) => {
                pending.extend(body.iter().rev())
            }
            BodyStmt::After(after) => pending.extend(after.body.iter().rev()),
            BodyStmt::Case(case) => {
                for branch in case.branches.iter().rev() {
                    pending.extend(branch.body.iter().rev());
                }
            }
            BodyStmt::Region(region) => {
                pending.extend(region.lapse_body.iter().rev());
                pending.extend(region.body.iter().rev());
            }
            _ => {}
        }
    }
    calls
}

#[cfg(test)]
mod tests;
