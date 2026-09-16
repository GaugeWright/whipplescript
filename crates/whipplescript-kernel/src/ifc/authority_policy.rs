//! Shared static authority ceilings; runtime custody still checks the opener.
use super::*;
use whipplescript_parser::SourceSpan;

pub(super) fn principal_read(
    rule: &str,
    span: SourceSpan,
    src: &str,
    principal_role: &str,
    envelope: &Envelope,
) -> Option<Diagnostic> {
    let cleared = envelope
        .reader_set(src)
        .iter()
        .all(|r| envelope.can_act(principal_role, r));
    if cleared {
        return None;
    }
    let required = envelope.reader_label(src);
    Some(Diagnostic {
        code: diagnostic_code!("security.principal_ceiling_exceeded"),
        severity: Severity::Error,
        span,
        message: format!(
            "denied read in rule `{rule}`: the agent acts-for `{principal_role}`, \
                         which is outside `{src}`'s readers ({required}) — an agent can never read \
                         above the user's clearance (DR-0028 D3)",
            rule = rule,
        ),
        suggestion: suggest(format!(
            "the principal role `{principal_role}` is not cleared for `{src}`; serve a user \
                         whose role acts-for {required}, or do not read `{src}`"
        )),
        related: Vec::new(),
        fixits: Vec::new(),
    })
}

pub(super) fn unwrap_grants(
    rule: &str,
    span: SourceSpan,
    grants: &[whipplescript_parser::IrAccessGrant],
    envelope: &Envelope,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for grant in grants {
        let Some(credential) = grant.resource.strip_prefix("credential ") else {
            continue;
        };
        for op in &grant.operations {
            if op.operation != "unwrap" {
                continue;
            }
            // A bare `unwrap` is the parser's diagnostic, already
            // emitted. Reporting it twice would say nothing new.
            let Some(payload_type) = op.target.as_deref() else {
                continue;
            };
            // An ungoverned credential is not an ungranted one: under
            // the gradual model a handle the envelope never mentions is
            // outside the policy's scope, and refusing here would make
            // governance a precondition for naming a credential at all.
            if !envelope.governs(envelope.resolve(credential)) {
                continue;
            }
            if envelope.grants_any_unwrap(credential, payload_type) {
                continue;
            }
            let available = envelope.unwrap_types_for(credential);
            diagnostics.push(Diagnostic {
                code: diagnostic_code!("security.unwrap_not_granted"),
                severity: Severity::Error,
                span,
                related: Vec::new(),
                fixits: Vec::new(),
                message: format!(
                    "rule `{rule}` scopes `unwrap for {payload_type}` on credential \
                             `{credential}`, which governance grants to nobody for that type",
                    rule = rule,
                ),
                suggestion: suggest(if available.is_empty() {
                    format!(
                        "governance grants no unwrap at all on `{credential}`; add \
                                 `grant unwrap {credential} for {payload_type} to <Role>` to the \
                                 envelope, or drop the operation from the turn"
                    )
                } else {
                    format!(
                        "governance grants unwrap on `{credential}` for {}; scope the \
                                 turn to one of those, or add `grant unwrap {credential} for \
                                 {payload_type} to <Role>` to the envelope",
                        available.join(", ")
                    )
                }),
            });
        }
    }
}
