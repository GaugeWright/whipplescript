//! Provider egress has one policy owner for legacy and managed effects.
use super::program_context::ProgramContext;
use super::*;
use whipplescript_parser::{IrAccessGrant, IrAgent, SourceSpan};

pub(super) fn turn(
    rule: &str,
    span: SourceSpan,
    agent: &IrAgent,
    provider: Option<&str>,
    grants: &[IrAccessGrant],
    envelope: &Envelope,
    diagnostics: &mut Vec<Diagnostic>,
) {
    // Resolved by the caller through `agent_provider_kind`, never read off
    // `IrAgent::provider` here: an agent bound `using <harness>` leaves that
    // field empty and reaches the harness's kind, and taking the field alone
    // gave such an agent no provider door at all -- no egress check on its
    // context. See `a_harness_bound_agent_egresses_to_the_harness_kind`.
    let Some(provider) = provider else {
        return;
    };
    for grant in grants {
        let resource = grant.resource.as_str();
        let reads_resource = grant.operations.iter().any(|op| is_read_op(&op.operation));
        if reads_resource && envelope.leaks(resource, provider) {
            diagnostics.push(Diagnostic {
                code: diagnostic_code!("security.provider_egress_leak"),
                severity: Severity::Error,
                span,
                message: format!(
                    "denied egress in rule `{rule}`: `{resource}` may be read by \
                     {rr} only — sending this turn's context to provider \
                     `{provider}` (clearance {pr}) would disclose it to a model \
                     outside its readers (the checker denies every turn egress to \
                     a provider not cleared for everything the turn read)",
                    rr = envelope.reader_label(resource),
                    pr = envelope.reader_label(provider),
                ),
                suggestion: suggest(format!(
                    "bind the agent to a provider cleared for `{resource}`, or \
                     declassify before the turn"
                )),
                related: vec![RelatedInfo {
                    span: agent.span,
                    message: format!("`{}` is bound to provider `{provider}` here", agent.name),
                }],
                fixits: Vec::new(),
            });
            break;
        }
    }
}

/// Retain these reads in the caller's flow analysis even when its provider is
/// cleared: passing the provider boundary does not clear a later output sink.
pub(super) fn tool_result(
    rule: &str,
    span: SourceSpan,
    agent: &IrAgent,
    provider: Option<&str>,
    tool: &IrProgram,
    envelope: &Envelope,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<String> {
    let reads = result_dependency_reads(tool);
    // Resolved by the caller, for the reason `turn` above gives.
    if let Some(provider) = provider {
        for resource in &reads {
            if envelope.leaks(resource, provider) {
                diagnostics.push(Diagnostic {
                    code: diagnostic_code!("security.provider_egress_leak"),
                    severity: Severity::Error,
                    span,
                    message: format!(
                        "denied egress in rule `{rule}`: agent `{agent}` may call \
                         tool `{tool}` which reads `{resource}` ({rr} only) — its \
                         provider `{provider}` (clearance {pr}) is outside those \
                         readers, so the tool result would reach an uncleared \
                         model (the checker denies every tool-result egress to a \
                         provider not cleared for it)",
                        agent = agent.name,
                        tool = tool.workflow,
                        rr = envelope.reader_label(resource),
                        pr = envelope.reader_label(provider),
                    ),
                    suggestion: suggest(format!(
                        "bind `{}` to a provider cleared for \
                         `{resource}`, or declassify before the tool result \
                         reaches the turn",
                        agent.name
                    )),
                    related: Vec::new(),
                    fixits: Vec::new(),
                });
            }
        }
    }
    reads
}

/// Only the provider-egress portion of managed IFC, not permission to execute.
/// The compiler supplies matching declarations and all tool programs. The full
/// program owner authenticates the checked domain and the imported versions.
pub fn check_managed(
    typed: &whipplescript_parser::action_plan::resolved::TypedActionPlan,
    ir: &IrProgram,
    verified: &VerifiedEnvelope,
    imports: &[IrProgram],
) -> Vec<Diagnostic> {
    check_in(typed, ProgramContext::Legacy(ir), verified, imports)
}

pub(super) fn check_in(
    typed: &whipplescript_parser::action_plan::resolved::TypedActionPlan,
    ir: ProgramContext<'_>,
    verified: &VerifiedEnvelope,
    imports: &[IrProgram],
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Err(problem) = typed.validate_structure() {
        diagnostics.push(incomplete(
            SourceSpan { start: 0, end: 0 },
            format!("managed provider check requires a valid typed plan: {problem}"),
        ));
        return diagnostics;
    }
    let Some(rule) = typed
        .plan
        .root_rule
        .as_ref()
        .filter(|root| ir.root(&root.name).is_some())
    else {
        diagnostics.push(incomplete(
            SourceSpan { start: 0, end: 0 },
            "managed provider check requires its matching root declaration".into(),
        ));
        return diagnostics;
    };
    for (id, effect) in &typed.effects {
        let Some(targets) = &effect.agent_targets else {
            continue;
        };
        let node = &typed.plan.nodes[id.0];
        let before = diagnostics.len();
        for target in targets {
            let Some(agent) = unique(ir.agents().iter().filter(|agent| agent.name == *target))
            else {
                diagnostics.push(incomplete(
                    node.span,
                    format!("checked tell target `{target}` requires exactly one matching agent declaration"),
                ));
                continue;
            };
            turn(
                &rule.name,
                node.span,
                agent,
                ir.provider_kind(agent),
                &effect.contract.access_grants,
                verified.envelope(),
                &mut diagnostics,
            );
            for name in &agent.tools {
                let Some(tool) = unique(imports.iter().filter(|tool| tool.workflow == *name))
                else {
                    diagnostics.push(incomplete(node.span, format!("agent `{target}` tool `{name}` requires exactly one imported program for provider analysis")));
                    continue;
                };
                let start = diagnostics.len();
                tool_result(
                    &rule.name,
                    node.span,
                    agent,
                    ir.provider_kind(agent),
                    tool,
                    verified.envelope(),
                    &mut diagnostics,
                );
                for diagnostic in &mut diagnostics[start..] {
                    diagnostic.related.push(RelatedInfo {
                        span: agent.span,
                        message: format!("agent `{target}` declared here"),
                    });
                }
            }
        }
        for diagnostic in &mut diagnostics[before..] {
            managed_call_context(diagnostic, &typed.plan, *id);
        }
    }
    diagnostics
}
fn unique<T>(mut candidates: impl Iterator<Item = T>) -> Option<T> {
    let first = candidates.next()?;
    candidates.next().is_none().then_some(first)
}
fn incomplete(span: SourceSpan, message: String) -> Diagnostic {
    Diagnostic::error(
        diagnostic_code!("construct.invalid_expansion"),
        span,
        message,
    )
}
#[cfg(test)]
mod tests;

pub(super) fn coerce<'a>(
    rule: &str,
    span: SourceSpan,
    // Resolved by the caller through `coerce_principal`, never off the
    // declaration alone: an inline `prompt "..." using <provider>` names its
    // endpoint at the EFFECT, having no declaration to carry the clause
    // (DR-0062 amendment 2026-09-14). Reading only the declaration judges such
    // a prompt as the un-named backend and clears it by the wrong label.
    principal: &str,
    declaration: Option<&whipplescript_parser::IrCoerce>,
    reads: impl IntoIterator<Item = &'a str>,
    envelope: &Envelope,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for resource in reads {
        if envelope.leaks(resource, principal) {
            diagnostics.push(Diagnostic {
                code: diagnostic_code!("security.provider_egress_leak"),
                severity: Severity::Error,
                span,
                message: format!(
                    "denied egress in rule `{rule}`: a `coerce`/`decide`/`prompt` reads \
                             `{resource}`, which {rr} only may read — sending the prompt to the \
                             schema.coerce model provider `{principal}` (clearance {pr}) would \
                             disclose it to an uncleared model (the checker denies every prompt \
                             egress to a provider not cleared for its inputs)",
                    rule = rule,
                    rr = envelope.reader_label(resource),
                    pr = envelope.reader_label(principal),
                ),
                suggestion: suggest(format!(
                    "clear this endpoint for the resource (`grant provider {principal} -> \
                             … readable by <role>`), or declassify before the coerce"
                )),
                // Point at the declaration whose `provider` clause chose
                // this endpoint — or, when none did, say so, since the
                // remedy there is to name one rather than to re-grant.
                related: declaration
                    .map(|decl| RelatedInfo {
                        span: decl.span,
                        message: match decl.provider.as_deref() {
                            Some(provider) => {
                                format!("`{}` sends to provider `{provider}` here", decl.name)
                            }
                            None => format!(
                                "`{}` names no provider, so it is judged as the \
                                         un-named backend `{UNNAMED_COERCE_BACKEND}` — name one \
                                         to govern this coerce per endpoint",
                                decl.name
                            ),
                        },
                    })
                    .into_iter()
                    .collect(),
                fixits: Vec::new(),
            });
            break;
        }
    }
}
