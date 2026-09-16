//! Host-owned wake scheduling for an unresolved executor invocation.
use crate::{StoreError, StoreResult};
use serde_json::{json, Value};

pub const EVENT_TYPE: &str = "exec.reconciliation.scheduled";

#[derive(Clone, Copy)]
pub struct Schedule<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
    pub input_json: &'a str,
    pub invocation_json: &'a str,
    pub now_epoch_ms: i64,
    pub due_epoch_ms: i64,
}

impl Schedule<'_> {
    pub fn key(&self) -> String {
        json!([EVENT_TYPE, self.run_id, self.due_epoch_ms]).to_string()
    }

    pub fn payload(&self) -> StoreResult<String> {
        if self.due_epoch_ms <= self.now_epoch_ms {
            return Err(StoreError::Conflict(
                "exec reconciliation wake must be in the future".into(),
            ));
        }
        Ok(json!({
            "protocol": "whipplescript.exec.reconciliation-wake/v1",
            "instance_id": self.instance_id, "effect_id": self.effect_id,
            "run_id": self.run_id, "scheduled_at_epoch_ms": self.now_epoch_ms,
            "due_epoch_ms": self.due_epoch_ms,
            "input": serde_json::from_str::<Value>(self.input_json)?,
            "invocation": serde_json::from_str::<Value>(self.invocation_json)?,
        })
        .to_string())
    }

    /// Called inside the writer transaction against the original run metadata.
    pub fn verify_binding(&self, input: &str, metadata: &str) -> StoreResult<()> {
        verify_retained_dispatch(self.input_json, self.invocation_json, input, metadata)
    }

    pub fn verify_replay(
        &self,
        kind: &str,
        source: &str,
        stored: &str,
        requested: &str,
    ) -> StoreResult<()> {
        if kind != EVENT_TYPE
            || source != "kernel"
            || serde_json::from_str::<Value>(stored)? != serde_json::from_str::<Value>(requested)?
        {
            return Err(StoreError::Conflict(
                "exec reconciliation wake cannot be replaced".into(),
            ));
        }
        Ok(())
    }
}

/// Shared transaction-time binding check for outcome wakes and lifetime custody.
pub fn verify_retained_dispatch(
    input_json: &str,
    invocation_json: &str,
    input: &str,
    metadata: &str,
) -> StoreResult<()> {
    let metadata: Value = serde_json::from_str(metadata)?;
    let invocation: Value = serde_json::from_str(invocation_json)?;
    let input: Value = serde_json::from_str(input)?;
    let plan = &metadata["executor_dispatch"];
    if plan["protocol"] != "whipplescript.exec.dispatch/v1"
        || plan["input_sha256"] != crate::items::sha256_hex(&input.to_string())
        || plan["request_body_sha256"]
            != crate::items::sha256_hex(&invocation["dispatch"].to_string())
        || !invocation.is_object()
        || metadata.get("executor_invocation") != Some(&invocation)
        || input != serde_json::from_str::<Value>(input_json)?
    {
        return Err(StoreError::Conflict(
            "exec reconciliation differs from the original invocation".into(),
        ));
    }
    Ok(())
}
