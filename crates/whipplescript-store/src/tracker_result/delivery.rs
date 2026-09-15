//! Fixed tracker result profiles share one fenced publication transaction.
//! Untagged decoding preserves the already emitted filing payload; all variants
//! reject unknown fields and have distinct required receipt fields.
use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeliveredTrackerResult {
    Filing(Box<TrackerResultDelivery>),
    Closing(Box<TrackerClosureResultDelivery>),
    Control(Box<TrackerControlResultDelivery>),
}

impl DeliveredTrackerResult {
    pub fn instance_id(&self) -> &str {
        match self {
            Self::Filing(d) => &d.instance_id,
            Self::Closing(d) => &d.closure.instance_id,
            Self::Control(d) => &d.control.instance_id,
        }
    }
    pub fn effect_id(&self) -> &str {
        match self {
            Self::Filing(d) => &d.effect_id,
            Self::Closing(d) => &d.closure.effect_id,
            Self::Control(d) => &d.control.effect_id,
        }
    }
    pub fn run_id(&self) -> &str {
        match self {
            Self::Filing(d) => &d.run_id,
            Self::Closing(d) => &d.run_id,
            Self::Control(d) => &d.run_id,
        }
    }
    pub fn fact_id(&self) -> &str {
        match self {
            Self::Filing(d) => &d.fact_id,
            Self::Closing(d) => &d.fact_id,
            Self::Control(d) => &d.fact_id,
        }
    }
    pub fn operation_id(&self) -> &str {
        match self {
            Self::Filing(d) => &d.filing_receipt.operation_id,
            Self::Closing(d) => &d.closure.operation_id,
            Self::Control(d) => &d.control.operation_id,
        }
    }
    pub fn kind(&self) -> &str {
        match self {
            Self::Filing(_) => "tracker.file",
            Self::Closing(_) => "tracker.finish",
            Self::Control(_) => "capability.call",
        }
    }
    pub fn provider(&self) -> &'static str {
        match self {
            Self::Filing(_) | Self::Closing(_) => "queue",
            Self::Control(_) => CONTROL_PROVIDER,
        }
    }
    pub fn target(&self) -> Option<&str> {
        match self {
            Self::Filing(d) => Some(&d.queue),
            Self::Closing(_) => None,
            Self::Control(d) => Some(d.control.capability()),
        }
    }
    pub fn delivery_event(&self) -> &str {
        match self {
            Self::Filing(_) => DELIVERY_EVENT,
            Self::Closing(_) => CLOSING_DELIVERY_EVENT,
            Self::Control(_) => CONTROL_DELIVERY_EVENT,
        }
    }
    pub fn success_name(&self) -> &str {
        match self {
            Self::Filing(_) => "tracker.file.completed",
            Self::Closing(_) => "tracker.finish.completed",
            Self::Control(_) => "capability.call.succeeded",
        }
    }
    pub fn failure_name(&self) -> &str {
        match self {
            Self::Filing(_) => "tracker.file.failed",
            Self::Closing(_) => "tracker.finish.failed",
            Self::Control(_) => "capability.call.failed",
        }
    }
    pub fn event_key(&self) -> String {
        format!(
            "tracker-result:{}",
            crate::items::sha256_hex(&json!([self.instance_id(), self.effect_id()]).to_string())
        )
    }
    pub fn validate(&self) -> StoreResult<()> {
        match self {
            Self::Filing(d) => d.validate(),
            Self::Closing(d) => d.validate(),
            Self::Control(d) => d.validate(),
        }
    }
    pub fn value(&self) -> Value {
        match self {
            Self::Filing(d) => d.value(),
            Self::Closing(d) => d.value(),
            Self::Control(d) => d.value(),
        }
    }
    pub fn fact_value(&self) -> Value {
        json!({"effect_id": self.effect_id(), "run_id": self.run_id(), "status": "completed", "value": self.value()})
    }
    pub fn application_evidence(&self, payload: &Value) -> StoreResult<DispositionEvidence> {
        match self {
            Self::Filing(d) => d.application_evidence(payload),
            Self::Closing(d) => d.application_evidence(payload),
            Self::Control(d) => d.application_evidence(payload),
        }
    }
    pub fn terminal_metadata(&self, event: &str) -> String {
        match self {
            Self::Filing(d) => json!({"value": d.value(), "filing_receipt": d.filing_receipt, "recovery_event_id": event}),
            Self::Closing(d) => json!({"value": d.value(), "closing_receipt": d.closing_receipt, "recovery_event_id": event}),
            Self::Control(d) => json!({"value": d.value(), "control_receipt": d.control_receipt, "recovery_event_id": event}),
        }.to_string()
    }
}

impl From<TrackerResultDelivery> for DeliveredTrackerResult {
    fn from(delivery: TrackerResultDelivery) -> Self {
        Self::Filing(Box::new(delivery))
    }
}
impl From<TrackerClosureResultDelivery> for DeliveredTrackerResult {
    fn from(delivery: TrackerClosureResultDelivery) -> Self {
        Self::Closing(Box::new(delivery))
    }
}
impl<T: Into<DeliveredTrackerResult>> RecordedTrackerResult<T> {
    pub fn into_delivered(self) -> RecordedTrackerResult<DeliveredTrackerResult> {
        RecordedTrackerResult {
            delivery: self.delivery.into(),
            consumed_failure_facts: self.consumed_failure_facts,
            complete_running_attempt: self.complete_running_attempt,
        }
    }
}

impl From<TrackerControlResultDelivery> for DeliveredTrackerResult {
    fn from(delivery: TrackerControlResultDelivery) -> Self {
        Self::Control(Box::new(delivery))
    }
}
