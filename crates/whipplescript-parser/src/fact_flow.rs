//! Shared fact-write vocabulary and effectful trigger-consumption policy.
//! A footprint is not evidence of execution, pacing or termination.
use super::*;

pub(crate) fn record(statement: &body::BodyStmt) -> Option<&body::RecordStmt> {
    match statement {
        body::BodyStmt::Record(record)
        | body::BodyStmt::Done {
            replacement: Some(record),
            ..
        } => Some(record),
        _ => None,
    }
}

pub(crate) fn ingest_schema(effect: &body::EffectStmt) -> Option<&str> {
    match &effect.kind {
        body::BodyEffectKind::Exec {
            parse_target: Some(parse),
            ..
        } if parse.each => Some(&parse.schema),
        body::BodyEffectKind::FileImport { schema, .. } => Some(schema),
        _ => None,
    }
}

pub(crate) fn normalize_read(read: &str) -> String {
    let Some(pattern) = read.strip_prefix("pattern:fact ") else {
        return read.to_owned();
    };
    match pattern.split_whitespace().next() {
        Some(name) if name.starts_with(char::is_uppercase) => format!("schema:{name}"),
        _ => read.to_owned(),
    }
}

pub(crate) fn validate_self_trigger(
    rule: &str,
    span: SourceSpan,
    effectful: bool,
    reads: &[String],
    writes: &[String],
    consumes: &[String],
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !effectful {
        return;
    }
    for written_fact in writes {
        if reads.contains(written_fact) && !consumes.contains(written_fact) {
            diagnostics.push(Diagnostic {
                code: diagnostic_code!("effect.unconsumed_trigger"),
                severity: Severity::Error,
                related: Vec::new(),
                fixits: Vec::new(),
                span,
                message: format!("effectful rule `{rule}` preserves trigger fact `{written_fact}`"),
                suggestion: suggest(
                    "consume or advance the triggering fact, or move the next effect behind an external completion event".to_owned(),
                ),
            });
        }
    }
}
