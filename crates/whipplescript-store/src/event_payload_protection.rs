//! One encoding for native event payload protection. Each event owner defines
//! its operational projection; the original bytes are never normalized.
use crate::{payload_protection::PayloadProtection, StoreError, StoreResult};
use serde_json::Value;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    pub(crate) version: u8,
    pub(crate) operational: Value,
    pub(crate) sealed: Vec<u8>,
}

pub(crate) fn coordinate(id: &str, kind: &str, summary: &Value) -> StoreResult<String> {
    Ok(serde_json::to_string(&(
        id,
        kind,
        crate::effect_recovery::canonical_value(summary),
    ))?)
}

pub(crate) fn seal(
    protection: &PayloadProtection,
    plane: &str,
    id: &str,
    kind: &str,
    raw: &str,
    project: fn(&str, &Value) -> Value,
) -> StoreResult<String> {
    let operational = project(kind, &serde_json::from_str(raw)?);
    let sealed = protection.seal(plane, &coordinate(id, kind, &operational)?, raw.as_bytes())?;
    Ok(serde_json::to_string(&Envelope {
        version: 1,
        operational,
        sealed,
    })?)
}

pub(crate) fn envelope(raw: &str, subject: &'static str) -> StoreResult<Envelope> {
    let envelope: Envelope = serde_json::from_str(raw)?;
    if envelope.version != 1 {
        return Err(StoreError::fault(
            subject,
            "unsupported event envelope version",
        ));
    }
    Ok(envelope)
}

// The coordinates, owner diagnostic and projection are distinct parts of the
// persisted contract; grouping them would add another descriptor to maintain.
#[allow(clippy::too_many_arguments)]
pub(crate) fn open(
    protection: &PayloadProtection,
    plane: &str,
    subject: &'static str,
    id: &str,
    kind: &str,
    raw: &str,
    project: fn(&str, &Value) -> Value,
) -> StoreResult<String> {
    let envelope = envelope(raw, subject)?;
    let opened = protection.open(
        plane,
        &coordinate(id, kind, &envelope.operational)?,
        &envelope.sealed,
    )?;
    let raw = String::from_utf8(opened)
        .map_err(|_| StoreError::fault(subject, "decoded event payload is not UTF-8"))?;
    if project(kind, &serde_json::from_str(&raw)?) != envelope.operational {
        return Err(StoreError::fault(
            subject,
            "event operational summary differs from sealed payload",
        ));
    }
    Ok(raw)
}
