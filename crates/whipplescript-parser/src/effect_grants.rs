//! One owner for explicit per-effect grant contracts. A valid clause does not
//! establish effective authorization; registry, profile and IFC checks follow.

use super::*;
use body::{BodyStmt, CompositionStmt};

pub(crate) mod resources;

pub(super) fn validate(
    owner: &str,
    span: SourceSpan,
    grants: &[IrAccessGrant],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut seen = BTreeSet::new();
    for grant in grants {
        if grant.operations.is_empty() {
            diagnostics.push(Diagnostic {
                code: diagnostic_code!("construct.missing_requirement"),
                severity: Severity::Error,
                related: Vec::new(),
                fixits: Vec::new(),
                span,
                message: format!(
                    "{owner} has a `with access to {}` grant that grants no operations",
                    grant.resource
                ),
                suggestion: suggest(
                    "list at least one operation in the grant block, or drop the grant".to_owned(),
                ),
            });
        }
        validate_credential_grant_classes(owner, span, grant, diagnostics);
        if !seen.insert(grant.resource.clone()) {
            diagnostics.push(Diagnostic {
                code: diagnostic_code!("capability.duplicate_grant"),
                severity: Severity::Error,
                related: Vec::new(),
                fixits: Vec::new(),
                span,
                message: format!(
                    "{owner} lists access resource `{}` more than once on one effect",
                    grant.resource
                ),
                suggestion: suggest(
                    "merge the grant clauses for a resource into a single block".to_owned(),
                ),
            });
        }
    }
}

/// DR-0053 §14 as extended by DR-0074 §2: each custody operation declares how
/// it may be narrowed, and a grant that narrows it the wrong way is a check
/// error rather than a clause that reads as narrowed while meaning nothing.
///
/// Only `credential` grants are classed here. Every other resource keeps its
/// own vocabulary, and an operation name that happens to collide with a custody
/// one must not be dragged into custody's rules.
fn validate_credential_grant_classes(
    owner: &str,
    span: SourceSpan,
    grant: &IrAccessGrant,
    diagnostics: &mut Vec<Diagnostic>,
) {
    use whipplescript_custody::{GrantClass, Operation};

    let Some(credential) = grant.resource.strip_prefix("credential ") else {
        return;
    };
    for op in &grant.operations {
        let Ok(operation) = Operation::parse(&op.operation) else {
            continue;
        };
        let class = operation.grant_class();
        let (bad, detail) = match class {
            GrantClass::Narrowable => (op.globs.is_empty(), "names no glob list"),
            GrantClass::TypeNarrowed => match (&op.target, op.globs.is_empty()) {
                (None, _) => (true, "names no type"),
                (Some(_), false) => (true, "carries a glob list as well as a type"),
                (Some(_), true) => (false, ""),
            },
            GrantClass::NonNarrowable => (
                op.target.is_some() || !op.globs.is_empty(),
                "carries a narrowing clause",
            ),
        };
        if !bad {
            continue;
        }
        diagnostics.push(Diagnostic {
            code: diagnostic_code!("capability.invalid_narrowing"),
            severity: Severity::Error,
            related: Vec::new(),
            fixits: Vec::new(),
            span,
            message: format!(
                "{owner} grants `{}` on credential `{credential}` but {detail}: this operation takes {}",
                op.operation,
                class.requirement()
            ),
            suggestion: suggest(match class {
                GrantClass::Narrowable => format!(
                    "narrow it, as in `{} [\"host/path/*\"]`",
                    op.operation
                ),
                // Failing closed is the point: reading a bare `unwrap` as
                // "every type" would preserve exactly the over-grant DR-0074
                // exists to remove.
                GrantClass::TypeNarrowed => format!(
                    "name the type it may open, as in `{} for PatientRecord`",
                    op.operation
                ),
                GrantClass::NonNarrowable => format!(
                    "name it bare, as in `{}`",
                    op.operation
                ),
            }),
        });
    }
}

/// Visit declarations once, including unused helpers. Calls do not recursively
/// re-check definitions or multiply the same source diagnostic.
pub(super) fn validate_composition(actions: &[ActionDecl], rules: &[&RuleDecl]) -> Vec<Diagnostic> {
    visit_composition(actions, rules, &mut |owner, effect, diagnostics| {
        validate(
            owner,
            effect.span,
            &ir_access_grants_for_body(&effect.kind),
            diagnostics,
        );
    })
}

fn visit_composition(
    actions: &[ActionDecl],
    rules: &[&RuleDecl],
    visit: &mut impl FnMut(&str, &body::EffectStmt, &mut Vec<Diagnostic>),
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for action in actions.iter().filter(|action| action.result.is_some()) {
        let (ast, errors) = body::parse_action_body(&action.body.text, action.body.body_base());
        if !errors.is_empty() {
            diagnostics.extend(errors);
            continue;
        }
        block(
            &format!("action `{}`", action.name.name),
            &ast.statements,
            visit,
            &mut diagnostics,
        );
    }
    for rule in rules {
        let (ast, errors) = body::parse_composed_rule_body(&rule.body.text, rule.body.body_base());
        if !errors.is_empty() {
            diagnostics.extend(errors);
            continue;
        }
        block(
            &format!("rule `{}`", rule.name.name),
            &ast.statements,
            visit,
            &mut diagnostics,
        );
    }
    diagnostics
}

fn block(
    owner: &str,
    statements: &[BodyStmt],
    visit: &mut impl FnMut(&str, &body::EffectStmt, &mut Vec<Diagnostic>),
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in statements {
        match statement {
            BodyStmt::Effect(effect) => visit(owner, effect, diagnostics),
            BodyStmt::Composition(CompositionStmt::Then { operation, .. }) => block(
                owner,
                std::slice::from_ref(operation.as_ref()),
                visit,
                diagnostics,
            ),
            BodyStmt::Composition(CompositionStmt::OnFailure { body, .. }) => {
                block(owner, body, visit, diagnostics)
            }
            BodyStmt::After(after) => block(owner, &after.body, visit, diagnostics),
            BodyStmt::Case(case) => {
                for branch in &case.branches {
                    block(owner, &branch.body, visit, diagnostics);
                }
            }
            BodyStmt::Region(region) => {
                block(owner, &region.body, visit, diagnostics);
                block(owner, &region.lapse_body, visit, diagnostics);
            }
            BodyStmt::Composition(
                CompositionStmt::Call { .. }
                | CompositionStmt::Return(_)
                | CompositionStmt::Fail(_),
            )
            | BodyStmt::Record(_)
            | BodyStmt::Done { .. }
            | BodyStmt::Terminal(_)
            | BodyStmt::Cancel { .. }
            | BodyStmt::Milestone { .. }
            | BodyStmt::Redact { .. }
            | BodyStmt::Declassify { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests;
