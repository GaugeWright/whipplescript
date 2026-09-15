//! Publish the original control outcome, including a recorded domain refusal.
use super::*;
use crate::tracker_control::{TrackerControl, TrackerControlReceipt};

pub const CONTROL_DELIVERY_EVENT: &str = "tracker.control.result_delivered";
pub const CONTROL_PROVIDER: &str = "builtin-tracker";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerControlResultDelivery {
    pub control: TrackerControl,
    pub run_id: String,
    pub control_receipt: TrackerControlReceipt,
    pub fact_id: String,
    /// Current investigator provenance. The storage operation grants no authority.
    pub recovery: Value,
}

pub fn control_receipt_evidence_digest(receipt: &TrackerControlReceipt) -> String {
    crate::items::sha256_hex(
        &canonical_value(&json!([
            "whipplescript.tracker-control-receipt.v1",
            receipt
        ]))
        .to_string(),
    )
}

pub fn control_value(control: &TrackerControl, receipt: &TrackerControlReceipt) -> Value {
    json!({"id": control.item_id, "queue": control.queue, "outcome": receipt.outcome})
}

impl TrackerControlResultDelivery {
    pub fn validate(&self) -> StoreResult<()> {
        self.control_receipt.validate_for(&self.control)?;
        if self.run_id.trim().is_empty()
            || self.fact_id.trim().is_empty()
            || !self.recovery.is_object()
        {
            return Err(StoreError::Conflict(
                "tracker control result coordinates are incomplete".into(),
            ));
        }
        Ok(())
    }
    pub fn value(&self) -> Value {
        control_value(&self.control, &self.control_receipt)
    }
    pub fn check_dispatch(&self, payload: &Value) -> StoreResult<()> {
        let dispatch = &payload["metadata"]["tracker_control"];
        let binding = &dispatch["binding"];
        if payload["effect_id"] != self.control.effect_id
            || payload["run_id"] != self.run_id
            || payload["provider"] != CONTROL_PROVIDER
            || dispatch["request"] != serde_json::to_value(&self.control)?
            || dispatch["fingerprint"] != self.control.fingerprint()?
            || binding["tracker"]["queue"] != self.control.queue
            || binding["item_id"] != self.control.item_id
            || binding["subject_id"] != self.control.subject_id
            || payload["metadata"]["action_execution"]["request"]["provenance"]["executor"]
                != self.control.actor
        {
            return Err(StoreError::Conflict(
                "tracker control result differs from its original dispatch".into(),
            ));
        }
        Ok(())
    }
    pub fn application_evidence(&self, payload: &Value) -> StoreResult<DispositionEvidence> {
        self.check_dispatch(payload)?;
        let marker: DispatchMarker = serde_json::from_value(payload["external_dispatch"].clone())?;
        let frame = marker.frame;
        if frame.protocol != crate::effect_recovery::EFFECT_RECOVERY_PROTOCOL
            || frame.instance_id != self.control.instance_id
            || frame.effect_id != self.control.effect_id
            || frame.run_id != self.run_id
            || frame.kind != "capability.call"
            || frame.provider != CONTROL_PROVIDER
            || frame.target.as_deref() != Some(self.control.capability())
        {
            return Err(StoreError::Conflict(
                "tracker control result evidence differs from its dispatch".into(),
            ));
        }
        let authority = self
            .recovery
            .get("issuer")
            .and_then(Value::as_str)
            .filter(|issuer| !issuer.trim().is_empty())
            .ok_or_else(|| {
                StoreError::Conflict("tracker control result recovery issuer is missing".into())
            })?;
        Ok(DispositionEvidence {
            frame,
            // Applied means this exact command was evaluated and its result
            // retained. The outcome does not claim that a refused lease changed.
            disposition: EvidenceDisposition::Applied,
            evidence_ref: format!("tracker-control:{}", self.control.operation_id),
            evidence_digest: control_receipt_evidence_digest(&self.control_receipt),
            authority_ref: authority.into(),
        })
    }
}
