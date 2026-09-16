//! Host-owned retention of one returned exec settlement per invocation.
use crate::{StoreError, StoreResult};
use serde_json::{json, Value};

pub const EVENT_TYPE: &str = "exec.settlement.retained";

#[derive(Clone, Copy, Debug)]
pub struct Retention<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
    pub input_json: &'a str,
    pub settlement_json: &'a str,
}

impl Retention<'_> {
    pub fn key(&self) -> String {
        retention_key(self.run_id)
    }

    pub fn payload(&self) -> StoreResult<String> {
        Ok(json!({
            "protocol": "whipplescript.exec.settlement-retention/v1",
            "instance_id": self.instance_id, "effect_id": self.effect_id,
            "run_id": self.run_id,
            "input": serde_json::from_str::<Value>(self.input_json)?,
            "settlement": serde_json::from_str::<Value>(self.settlement_json)?,
        })
        .to_string())
    }

    pub fn verify_input(&self, stored: &str) -> StoreResult<()> {
        if serde_json::from_str::<Value>(stored)? != serde_json::from_str::<Value>(self.input_json)?
        {
            return Err(StoreError::Conflict(
                "exec settlement differs from the run's stored input".into(),
            ));
        }
        Ok(())
    }
}

pub fn verify_replay(
    event_type: &str,
    source: &str,
    retained: &str,
    requested: &str,
) -> StoreResult<()> {
    if event_type != EVENT_TYPE
        || source != "kernel"
        || serde_json::from_str::<Value>(retained)? != serde_json::from_str::<Value>(requested)?
    {
        return Err(StoreError::Conflict(
            "exec settlement receipt cannot be replaced".into(),
        ));
    }
    Ok(())
}

pub fn retention_key(run_id: &str) -> String {
    format!("exec-settlement-retained:{run_id}")
}

/// Recheck the selected receipt and input inside the projection transaction.
pub fn verify_settlement(
    event_type: &str,
    source: &str,
    retained: &str,
    input: &str,
    completion: crate::EffectCompletion<'_>,
    facts: &[crate::SettlementFact<'_>],
    cache: Option<crate::SettlementCache<'_>>,
) -> StoreResult<()> {
    let receipt: Value = serde_json::from_str(retained)?;
    let projections: Vec<_> = facts
        .iter()
        .map(|p| {
            json!({
                "name": p.fact.name, "key": p.fact.key, "value": p.fact.value_json,
                "ingest": p.fact.provenance_class == "ingest", "event_key": p.idempotency_key,
            })
        })
        .collect();
    let material = json!({
        "status": completion.status, "exit_code": completion.exit_code,
        "summary": completion.summary, "metadata": serde_json::from_str::<Value>(completion.metadata_json)?,
        "projections": projections, "cache": cache.map(|c| (c.content_key, c.result_json)),
    });
    if event_type != EVENT_TYPE
        || source != "kernel"
        || receipt["protocol"] != "whipplescript.exec.settlement-retention/v1"
        || receipt["instance_id"] != completion.instance_id
        || receipt["effect_id"] != completion.effect_id
        || receipt["run_id"] != completion.run_id
        || receipt["input"] != serde_json::from_str::<Value>(input)?
        || receipt["settlement"] != material
    {
        return Err(StoreError::Conflict(
            "exec projection batch differs from its retained receipt".into(),
        ));
    }
    Ok(())
}
