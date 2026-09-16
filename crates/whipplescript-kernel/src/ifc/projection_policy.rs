//! One reader-set judgment for legacy and composed field projections.
use super::*;

pub(super) enum Kind {
    Redacted,
    Bounded,
    Composed,
}

pub(super) fn check(
    rule: &str,
    span: whipplescript_parser::SourceSpan,
    sink: &str,
    kind: Kind,
    fields: &BTreeSet<String>,
    envelope: &Envelope,
) -> Option<Diagnostic> {
    let readers = envelope.reader_sink(sink);
    let offending: Vec<_> = fields
        .iter()
        .filter(|field| !envelope.dominates(&readers, &envelope.reader_set(field)))
        .collect();
    if offending.is_empty() {
        return None;
    }
    let required: BTreeSet<_> = fields
        .iter()
        .flat_map(|field| envelope.reader_set(field))
        .collect();
    let short = |field: &str| field.rsplit('.').next().unwrap_or(field).to_owned();
    let safe: BTreeSet<_> = fields
        .iter()
        .filter(|field| !offending.contains(field))
        .map(|field| short(field))
        .collect();
    let dropped = offending
        .iter()
        .map(|field| short(field))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");
    let full = offending
        .iter()
        .map(|field| field.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let (kind, suggestion) = match kind {
        Kind::Composed => ("composed egress", format!("omit or replace the contribution from `{full}`, or clear `{sink}` with `grant … -> {sink} readable by <role>`; other source obligations still apply")),
        kind => {
            let narrowing = if safe.is_empty() { format!("omit the restricted field(s) `{dropped}`") }
                else { format!("drop the field(s) `{dropped}` the destination cannot read (keep only [{}])", safe.into_iter().collect::<Vec<_>>().join(", ")) };
            (match kind { Kind::Redacted => "redacted egress", _ => "bounded-type egress" }, format!("{narrowing}, or clear the destination with `grant … -> {sink} readable by <role>`; other source obligations still apply"))
        }
    };
    Some(Diagnostic::error(diagnostic_code!("security.projection_leak"), span,
        format!("denied flow in rule `{rule}`: the {kind} `{sink}` carries field(s) `{full}` requiring {} — the destination is readable by {}", label_text(&required), label_text(&readers)))
        .with_suggestion(suggestion))
}
