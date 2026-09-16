//! Shared declaration-level capability requirements; runtime authorization remains separate.
use super::*;

pub(super) fn validate(
    owner: &str,
    span: SourceSpan,
    agent: &str,
    required_capabilities: &[String],
    semantic: &SemanticContext,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if required_capabilities.is_empty() {
        return;
    }
    let declared = semantic
        .agent_capabilities
        .get(agent)
        .cloned()
        .unwrap_or_default();
    for capability in required_capabilities {
        if !declared.contains(capability) {
            diagnostics.push(Diagnostic {
                code: diagnostic_code!("construct.capability_not_declared"),
                severity: Severity::Error,
                related: Vec::new(),
                fixits: Vec::new(),
                span,
                message: format!(
                    "{owner} tells agent `{agent}` requiring undeclared capability `{capability}`"
                ),
                suggestion: suggest(suggest_otherwise(
                    capability,
                    declared.iter(),
                    format!(
                        "add `{capability}` to agent `{agent}` capabilities or choose another AgentRef target"
                    ),
                )),
            });
        }
    }
}
