//! One executor transfer and sink policy for legacy and managed values.
use super::*;
use whipplescript_parser::{IrExecTarget, SourceSpan};
pub mod managed;

pub(super) enum Transfer {
    Agent,
    Inputs {
        endorsed: bool,
    },
    /// An UNMARKED coercion vouches as the ENDPOINT it reaches, which only the
    /// caller can resolve (`super::coerce_principal`). A variant rather than a
    /// handle computed here, because this function is given a KIND and not a
    /// program: the literal `model` it returned for every coercion is the exact
    /// drift DR-0062's amendment closed, and a variant the caller must answer
    /// cannot quietly come back.
    CoerceEgress,
    Executor(String),
    None,
}
pub(super) fn transfer(
    kind: &IrEffectKind,
    endorsed: bool,
    target: Option<&IrExecTarget>,
    carries_inputs: bool,
) -> Transfer {
    match kind {
        IrEffectKind::AgentTell => Transfer::Agent,
        IrEffectKind::SchemaCoerce if endorsed => Transfer::Inputs { endorsed: true },
        IrEffectKind::CapabilityCall if carries_inputs => Transfer::Inputs { endorsed: false },
        IrEffectKind::SchemaCoerce => Transfer::CoerceEgress,
        IrEffectKind::ExecCommand => Transfer::Executor(match target {
            Some(IrExecTarget::Capability { name }) => format!("script:{name}"),
            _ => "exec:raw".into(),
        }),
        // This exhaustive list is the existing executor-output policy. Resource
        // reads, writes and admission remain in their own shared effect audit.
        IrEffectKind::CapabilityCall
        | IrEffectKind::EventEmit
        | IrEffectKind::WorkflowInvoke
        | IrEffectKind::TimerWait
        | IrEffectKind::HttpRequest
        | IrEffectKind::MintCredential
        | IrEffectKind::RotateCredential
        | IrEffectKind::RevokeCredential
        | IrEffectKind::TrackerFile
        | IrEffectKind::TrackerClaim
        | IrEffectKind::TrackerRenew
        | IrEffectKind::TrackerRelease
        | IrEffectKind::TrackerFinish
        | IrEffectKind::LeaseAcquire
        | IrEffectKind::LeaseRenew
        | IrEffectKind::LedgerAppend
        | IrEffectKind::CounterConsume
        | IrEffectKind::SignalEmit
        | IrEffectKind::FileRead
        | IrEffectKind::FileWrite
        | IrEffectKind::FileImport
        | IrEffectKind::FileExport => Transfer::None,
    }
}
pub(super) fn denied(envelope: &Envelope, handle: &str, sink: &str, crossed: bool) -> bool {
    !(envelope.dominates(
        &envelope.integrity_set(handle),
        &envelope.integrity_sink(sink),
    ) || (crossed && envelope.endorse_raises(handle, sink)))
}
pub(super) fn diagnostic(
    rule: &str,
    span: SourceSpan,
    handle: &str,
    sink: &str,
    crossed: bool,
    envelope: &Envelope,
) -> Diagnostic {
    let via = if crossed {
        " (its `endorsed` judgment lacks a matching `grant endorse` for this sink)"
    } else {
        ""
    };
    Diagnostic {
        code: diagnostic_code!("security.integrity_injection"),
        severity: Severity::Error,
        span,
        message: format!(
            "denied influence in rule `{rule}`: the output of executor `{handle}` \
                     (vouched at {provided}) shapes `{sink}`, which only {required}-vouched data \
                     may shape{via} (the checker denies every effect output flowing into a sink \
                     above its executor's `from` clearance; DR-0046)",
            rule = rule,
            provided = envelope.integrity_label(handle),
            required = envelope.integrity_label(sink),
        ),
        suggestion: suggest(format!(
            "escalate (needs governance): vouch the executor's outputs with `grant … -> … \
                     from <role>` on `{handle}`, or route the value through a `coerce … endorsed` \
                     judgment under `grant endorse {handle} to <role vouched for {sink}>`"
        )),
        related: Vec::new(),
        fixits: Vec::new(),
    }
}
