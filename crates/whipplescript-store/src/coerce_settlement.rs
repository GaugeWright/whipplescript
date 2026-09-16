//! One transaction for the existing coerce terminal, result event and fact.
//! Terminal metadata is redacted; only the result event carries usable data.
use crate::{EffectCompletion, NewFact, StoreError, StoreResult};

#[derive(Clone, Copy, Debug)]
pub struct CoerceSettlementFact<'a> {
    pub fact_id: &'a str,
    pub result_event_key: &'a str,
    pub fact_event_key: &'a str,
    pub name: &'a str,
    pub output_type: &'a str,
    pub value_json: &'a str,
}

impl<'a> CoerceSettlementFact<'a> {
    pub fn validate(&self, completion: EffectCompletion<'_>) -> StoreResult<()> {
        let value: serde_json::Value = serde_json::from_str(self.value_json)?;
        let expected = match completion.status {
            "completed" => "schema.coerce.succeeded",
            "failed" => "schema.coerce.failed",
            "timed_out" => "schema.coerce.timed_out",
            _ => "",
        };
        let keys = [
            self.result_event_key,
            self.fact_event_key,
            completion.idempotency_key.unwrap_or(""),
        ];
        if expected.is_empty()
            || self.name != expected
            || self.fact_id.trim().is_empty()
            || keys.iter().any(|key| key.trim().is_empty())
            || keys[0] == keys[1]
            || keys[0] == keys[2]
            || keys[1] == keys[2]
            || self.output_type.trim().is_empty()
            || value.get("effect_id").and_then(serde_json::Value::as_str)
                != Some(completion.effect_id)
            || value.get("run_id").and_then(serde_json::Value::as_str) != Some(completion.run_id)
            || value.get("status").and_then(serde_json::Value::as_str) != Some(completion.status)
            || value.get("output_type").and_then(serde_json::Value::as_str)
                != Some(self.output_type)
            || value
                .get("function_name")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|name| name.trim().is_empty())
            || value.get("value").is_none()
        {
            return Err(StoreError::Conflict(
                "coerce settlement result does not bind its terminal".into(),
            ));
        }
        Ok(())
    }

    pub fn check_kind(&self, kind: Option<&str>) -> StoreResult<()> {
        if kind != Some("schema.coerce") {
            return Err(StoreError::Conflict(
                "coerce settlement requires a recorded schema.coerce effect".into(),
            ));
        }
        Ok(())
    }

    pub fn require_fresh_fact(&self, active: bool) -> StoreResult<()> {
        if active {
            return Err(StoreError::Conflict(
                "coerce settlement fact is already active".into(),
            ));
        }
        Ok(())
    }

    pub fn fact(&self, completion: EffectCompletion<'a>) -> NewFact<'a> {
        NewFact {
            fact_id: self.fact_id,
            name: self.name,
            key: completion.run_id,
            value_json: self.value_json,
            schema_id: Some(self.output_type),
            provenance_class: "effect",
            correlation_id: Some(completion.effect_id),
            source_span_json: None,
            validity_json: None,
        }
    }

    pub fn payload(&self, completion: EffectCompletion<'_>) -> StoreResult<String> {
        Ok(serde_json::json!({
            "fact_id": self.fact_id, "name": self.name, "key": completion.run_id,
            "value": serde_json::from_str::<serde_json::Value>(self.value_json)?,
            "schema_id": self.output_type, "provenance_class": "effect",
            "correlation_id": completion.effect_id,
        })
        .to_string())
    }
}

#[cfg(feature = "native")]
pub(crate) fn append_result(
    connection: &rusqlite::Connection,
    completion: EffectCompletion<'_>,
    fact: CoerceSettlementFact<'_>,
) -> StoreResult<()> {
    use rusqlite::OptionalExtension;
    let kind: Option<String> = connection
        .query_row(
            "SELECT kind FROM effects WHERE instance_id = ?1 AND effect_id = ?2",
            [completion.instance_id, completion.effect_id],
            |row| row.get(0),
        )
        .optional()?;
    fact.check_kind(kind.as_deref())?;
    let active = connection.query_row(
        "SELECT 1 FROM facts WHERE instance_id = ?1 AND name = ?2 AND key = ?3 AND consumed_at IS NULL",
        [completion.instance_id, fact.name, completion.run_id], |_| Ok(()),
    ).optional()?.is_some();
    fact.require_fresh_fact(active)?;
    crate::append_event_on(
        connection,
        crate::NewEvent {
            instance_id: completion.instance_id,
            event_type: fact.name,
            payload_json: fact.value_json,
            source: "kernel",
            causation_id: Some(completion.run_id),
            correlation_id: Some(completion.effect_id),
            idempotency_key: Some(fact.result_event_key),
        },
    )?;
    let payload = fact.payload(completion)?;
    let event = crate::append_event_on(
        connection,
        crate::NewEvent {
            instance_id: completion.instance_id,
            event_type: "fact.derived",
            payload_json: &payload,
            source: "kernel",
            causation_id: Some(completion.run_id),
            correlation_id: Some(completion.effect_id),
            idempotency_key: Some(fact.fact_event_key),
        },
    )?;
    let (version, epoch) = crate::active_revision_on(connection, completion.instance_id)?;
    crate::insert_fact(
        connection,
        completion.instance_id,
        "kernel",
        &event.event_id,
        version.as_deref(),
        epoch,
        &fact.fact(completion),
    )
}

/// Shared native and hosted settlement/replay fixture.
#[doc(hidden)]
pub mod conformance;

#[cfg(all(test, feature = "native"))]
mod tests;
