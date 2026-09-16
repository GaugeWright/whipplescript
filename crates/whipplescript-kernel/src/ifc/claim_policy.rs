//! Shared tracker vouch and closed-field policy for endorsed claims.
use super::*;
use whipplescript_parser::SourceSpan;

pub(super) fn tracker(
    rule: &str,
    span: SourceSpan,
    tracker: &str,
    envelope: &Envelope,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !envelope.integrity_set(tracker).is_empty() {
        return;
    }
    diagnostics.push(Diagnostic {
        code: diagnostic_code!("security.unvouched_endorsement"),
        severity: Severity::Error,
        span,
        message: format!(
            "`claim … endorsed` in rule `{rule}` claims out of tracker `{tracker}`, \
                     which nobody vouches (integrity public) — an endorsement may only draw \
                     its authority from a queue the envelope says who may file into, or an \
                     agent could file its own issue and claim it",
            rule = rule,
        ),
        suggestion: suggest(format!(
            "name who may file into it: `grant tracker {tracker} -> \
                     tracker:/{tracker} from <Role>`. if this claim is not an integrity \
                     crossing, drop the `endorsed` marker instead"
        )),
        related: Vec::new(),
        fixits: Vec::new(),
    });
}

pub(super) fn field(
    rule: &str,
    span: SourceSpan,
    schema: &str,
    field_name: &str,
    ty: &whipplescript_parser::IrType,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !carries_prose(ty) {
        return;
    }
    diagnostics.push(Diagnostic {
        code: diagnostic_code!("security.endorsed_prose_field"),
        severity: Severity::Error,
        span,
        message: format!(
            "in rule `{rule}`, `{schema}.{field_name}` is shaped by an endorsed \
                             claim but can carry prose — an endorsement raises a *decision* to \
                             trusted integrity, and a free-text field raised the same way \
                             launders whatever the endorser quoted from the untrusted item",
            rule = rule,
        ),
        suggestion: suggest(format!(
            "declare `{field_name}` as a closed union of literals (e.g. \
                             `\"keep\" | \"flag\"`) or another type that cannot hold a sentence \
                             — a number or a bool. to keep the endorser's prose, record it in a \
                             separate fact the envelope leaves at public integrity"
        )),
        related: Vec::new(),
        fixits: Vec::new(),
    });
}
