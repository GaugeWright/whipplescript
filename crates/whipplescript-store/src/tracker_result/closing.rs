//! Receipt-bound continuation for an ordinary tracker.finish operation.
use super::*;
use crate::tracker_closure::{TrackerClosure, TrackerClosureReceipt};

pub const CLOSING_DELIVERY_EVENT: &str = "tracker.closing.result_delivered";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerClosureResultDelivery {
    pub closure: TrackerClosure,
    pub run_id: String,
    pub closing_receipt: TrackerClosureReceipt,
    pub fact_id: String,
    /// Current investigator provenance. This is evidence, not an authority grant.
    pub recovery: Value,
}

pub fn closing_receipt_evidence_digest(receipt: &TrackerClosureReceipt) -> String {
    crate::items::sha256_hex(
        &canonical_value(&json!([
            "whipplescript.tracker-closing-receipt.v1",
            receipt
        ]))
        .to_string(),
    )
}

impl TrackerClosureResultDelivery {
    pub fn validate(&self) -> StoreResult<()> {
        self.closure.fingerprint()?;
        self.closing_receipt.validate_for(&self.closure)?;
        if self.run_id.trim().is_empty()
            || self.fact_id.trim().is_empty()
            || !self.recovery.is_object()
        {
            return Err(StoreError::Conflict(
                "tracker closing result coordinates are incomplete".into(),
            ));
        }
        Ok(())
    }

    pub fn value(&self) -> Value {
        json!({"id": self.closure.item_id, "status": "done", "summary": self.closure.summary})
    }

    pub fn check_dispatch(&self, payload: &Value) -> StoreResult<()> {
        let dispatch = &payload["metadata"]["tracker_closure"];
        let binding = &dispatch["binding"];
        if payload["effect_id"] != self.closure.effect_id
            || payload["run_id"] != self.run_id
            || payload["provider"] != "queue"
            || dispatch["operation_id"] != self.closure.operation_id
            || dispatch["fingerprint"] != self.closure.fingerprint()?
            || dispatch["summary"] != json!(self.closure.summary)
            || binding["tracker"]["queue"] != self.closure.queue
            || binding["item_id"] != self.closure.item_id
            || binding["subject_id"] != self.closure.subject_id
            || binding["expected_holder"] != json!(self.closure.expected_holder)
            || payload["metadata"]["action_execution"]["request"]["provenance"]["executor"]
                != self.closure.actor
        {
            return Err(StoreError::Conflict(
                "tracker closing result differs from its original dispatch".into(),
            ));
        }
        Ok(())
    }

    pub fn application_evidence(&self, payload: &Value) -> StoreResult<DispositionEvidence> {
        self.check_dispatch(payload)?;
        let marker: DispatchMarker = serde_json::from_value(payload["external_dispatch"].clone())?;
        let frame = marker.frame;
        if frame.protocol != crate::effect_recovery::EFFECT_RECOVERY_PROTOCOL
            || frame.instance_id != self.closure.instance_id
            || frame.effect_id != self.closure.effect_id
            || frame.run_id != self.run_id
            || frame.kind != "tracker.finish"
            || frame.provider != "queue"
            || frame.target.is_some()
        {
            return Err(StoreError::Conflict(
                "tracker closing result evidence differs from its dispatch".into(),
            ));
        }
        let authority = self
            .recovery
            .get("issuer")
            .and_then(Value::as_str)
            .filter(|issuer| !issuer.trim().is_empty())
            .ok_or_else(|| {
                StoreError::Conflict("tracker closing result recovery issuer is missing".into())
            })?;
        Ok(DispositionEvidence {
            frame,
            disposition: EvidenceDisposition::Applied,
            evidence_ref: self.closing_receipt.event_id.clone(),
            evidence_digest: closing_receipt_evidence_digest(&self.closing_receipt),
            authority_ref: authority.into(),
        })
    }
}
