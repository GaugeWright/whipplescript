//! One source-flow policy for legacy and actual managed reads.
use super::*;
use whipplescript_parser::SourceSpan;

pub(super) fn leaks(envelope: &Envelope, source: &str, sink: &str, marked: bool) -> bool {
    envelope.leaks(source, sink) && !(marked && envelope.declassify_releases(source, sink))
}

pub(super) fn injects(
    envelope: &Envelope,
    source: &str,
    sink: &str,
    carried: Option<&CarriedIntegrity>,
    marked: bool,
) -> bool {
    if let Some(carried) = carried {
        return carried
            .as_ref()
            .is_some_and(|set| !envelope.dominates(set, &envelope.integrity_sink(sink)));
    }
    let source = source.strip_prefix("output:").unwrap_or(source);
    !(envelope.dominates(
        &envelope.integrity_set(source),
        &envelope.integrity_sink(sink),
    ) || (marked && envelope.endorse_raises(source, sink)))
}

pub(super) fn leak_diagnostic(
    rule: &str,
    span: SourceSpan,
    src: &str,
    sink: &str,
    reaches_marked: bool,
    envelope: &Envelope,
) -> Diagnostic {
    let reach_note = if reaches_marked {
        " — it reaches the marked crossing's inputs, so the release requires its grant"
    } else {
        ""
    };
    // The endpoint's clearance can be in order while the party in between is
    // not; say which one refused, or the two reader labels read as a
    // contradiction -- the sink's own readers are printed as its clearance, so
    // a refusal naming the same role on both sides explains nothing without
    // this (DR-0053 §9).
    let custodian_note = envelope
        .uncleared_custodian(src, sink)
        .map(|custodian| {
            format!(
                " — and `{sink}` routes its payload through custodian `{custodian}`,                  which is not cleared for those readers (DR-0053 §9: confine the                  credential with `egress from workflow`, or delegate the custodian)"
            )
        })
        .unwrap_or_default();
    Diagnostic {
        code: diagnostic_code!("security.confidentiality_leak"),
        severity: Severity::Error,
        span,
        message: format!(
            "denied flow in rule `{rule}`: `{src}` may be read by {src_reader} only — \
             writing it to `{sink}` (readable by {sink_reader}) would expose it to parties \
             outside its readers (the checker denies every flow from a value to a sink \
             whose readers are not all within the value's reader set){reach_note}\
             {custodian_note}",
            rule = rule,
            src_reader = envelope.reader_label(src),
            sink_reader = envelope.reader_label(sink),
        ),
        suggestion: suggest(format!(
            "self-serve (no grant needed): separate the contexts — read `{src}` in a \
             distinct turn and pass only a bounded result. escalate (needs governance): \
             route the release through a `coerce … declassified` whose output is the \
             egress's whole payload, under `grant declassify {src} to <role cleared for \
             {sink}>` (a grant alone never blesses a raw flow)"
        )),
        related: Vec::new(),
        fixits: Vec::new(),
    }
}

pub(super) fn injection_diagnostic(
    rule: &str,
    span: SourceSpan,
    src: &str,
    sink: &str,
    src_int: &str,
    envelope: &Envelope,
) -> Diagnostic {
    let src_name = match src.strip_prefix("output:") {
        Some(handle) => format!("the fact-carried output of executor `{handle}`"),
        None => format!("`{src}`"),
    };
    Diagnostic {
        code: diagnostic_code!("security.integrity_injection"),
        severity: Severity::Error,
        span,
        message: format!(
            "denied influence in rule `{rule}`: {src_name} is untrusted (integrity \
             {src_int}) — it can never influence `{sink}`, which only {sink_int}-vouched \
             data may shape (the checker denies every flow from lower-integrity data into \
             a higher-integrity sink; the sanctioned crossing is a source-marked \
             `endorsed` coerce)",
            rule = rule,
            sink_int = envelope.integrity_label(sink),
        ),
        suggestion: suggest(format!(
            "self-serve (no grant needed): do not let `{src}` influence `{sink}` — gate \
             the sink on trusted data. escalate (needs governance): route the influence \
             through a `coerce … endorsed` whose output is the sink's whole payload, \
             under `grant endorse {src} to <role>` (a grant alone never vouches a raw \
             influence)"
        )),
        related: Vec::new(),
        fixits: Vec::new(),
    }
}
