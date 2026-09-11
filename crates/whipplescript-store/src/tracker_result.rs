//! Atomic publication of an already verified tracker filing or closing result.
//! The kernel must authenticate recovery and read the actual target receipt.
//! This storage operation grants no authority and never calls a tracker sink.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    effect_recovery::{canonical_value, DispatchMarker, DispositionEvidence, EvidenceDisposition},
    tracker_filing::TrackerFilingReceipt,
    StoreError, StoreResult, StoredEvent,
};

mod closing;
mod delivery;
pub use closing::{
    closing_receipt_evidence_digest, TrackerClosureResultDelivery, CLOSING_DELIVERY_EVENT,
};
#[doc(hidden)]
pub use delivery::DeliveredTrackerResult;

pub const DELIVERY_EVENT: &str = "tracker.filing.result_delivered";

pub fn receipt_evidence_digest(receipt: &TrackerFilingReceipt) -> String {
    crate::items::sha256_hex(
        &canonical_value(&json!(["whipplescript.tracker-filing-receipt.v1", receipt])).to_string(),
    )
}

#[doc(hidden)]
pub mod closing_conformance;
#[doc(hidden)]
pub mod conformance;
#[cfg(all(test, feature = "native"))]
mod tests;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerResultDelivery {
    pub instance_id: String,
    pub effect_id: String,
    pub run_id: String,
    pub queue: String,
    pub title: String,
    pub filing_receipt: TrackerFilingReceipt,
    pub fact_id: String,
    /// The verified recovery command, with current investigator provenance.
    /// Proof bytes and task bodies do not belong in this record.
    pub recovery: Value,
}

pub trait TrackerResultPublications {
    fn publish_tracker_result(
        &mut self,
        owner_epoch: i64,
        expected_head: &str,
        delivery: &TrackerResultDelivery,
    ) -> StoreResult<StoredEvent>;
    fn publish_tracker_closure_result(
        &mut self,
        owner_epoch: i64,
        expected_head: &str,
        delivery: &TrackerClosureResultDelivery,
    ) -> StoreResult<StoredEvent>;
}

impl TrackerResultDelivery {
    pub fn event_key(&self) -> String {
        format!(
            "tracker-result:{}",
            crate::items::sha256_hex(&json!([self.instance_id, self.effect_id]).to_string())
        )
    }

    pub fn value(&self) -> Value {
        json!({"queue": self.queue, "id": self.filing_receipt.item_id, "title": self.title})
    }

    pub fn fact_value(&self) -> Value {
        json!({"effect_id": self.effect_id, "run_id": self.run_id,
            "status": "completed", "value": self.value()})
    }

    pub fn validate(&self) -> StoreResult<()> {
        if [
            &self.instance_id,
            &self.effect_id,
            &self.run_id,
            &self.queue,
            &self.fact_id,
            &self.filing_receipt.operation_id,
            &self.filing_receipt.fingerprint,
            &self.filing_receipt.item_id,
            &self.filing_receipt.event_id,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
            || !self.recovery.is_object()
        {
            return Err(StoreError::Conflict(
                "tracker result delivery coordinates are incomplete".into(),
            ));
        }
        Ok(())
    }

    /// Validate against the retained run-start, not a current issue projection.
    pub fn check_dispatch(&self, payload: &Value) -> StoreResult<()> {
        let filing = &payload["metadata"]["tracker_filing"];
        if payload["effect_id"] != self.effect_id
            || payload["run_id"] != self.run_id
            || payload["provider"] != "queue"
            || filing["operation_id"] != self.filing_receipt.operation_id
            || filing["fingerprint"] != self.filing_receipt.fingerprint
            || filing["queue"] != self.queue
            || filing["title"] != self.title
        {
            return Err(StoreError::Conflict(
                "tracker result differs from its original dispatch".into(),
            ));
        }
        Ok(())
    }

    /// Derive standard target knowledge from the already verified receipt and
    /// the exact retained dispatch. This does not authenticate either input.
    pub fn application_evidence(&self, payload: &Value) -> StoreResult<DispositionEvidence> {
        self.check_dispatch(payload)?;
        let dispatch: DispatchMarker =
            serde_json::from_value(payload["external_dispatch"].clone())?;
        let frame = dispatch.frame;
        if frame.protocol != crate::effect_recovery::EFFECT_RECOVERY_PROTOCOL
            || frame.instance_id != self.instance_id
            || frame.effect_id != self.effect_id
            || frame.run_id != self.run_id
            || frame.kind != "tracker.file"
            || frame.provider != "queue"
            || frame.target.as_deref() != Some(self.queue.as_str())
        {
            return Err(StoreError::Conflict(
                "tracker result evidence differs from its dispatch".into(),
            ));
        }
        let authority = self
            .recovery
            .get("issuer")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                StoreError::Conflict("tracker result recovery issuer is missing".into())
            })?;
        Ok(DispositionEvidence {
            frame,
            disposition: EvidenceDisposition::Applied,
            evidence_ref: self.filing_receipt.event_id.clone(),
            evidence_digest: receipt_evidence_digest(&self.filing_receipt),
            authority_ref: authority.into(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedTrackerResult<D = TrackerResultDelivery> {
    pub delivery: D,
    pub consumed_failure_facts: Vec<String>,
    pub complete_running_attempt: bool,
}

#[cfg(feature = "native")]
mod native {
    use super::*;
    use crate::{EffectCompletion, NewEvent, NewFact, SqliteStore};
    use rusqlite::{params, Connection, OptionalExtension};

    impl TrackerResultPublications for SqliteStore {
        fn publish_tracker_result(
            &mut self,
            owner_epoch: i64,
            expected_head: &str,
            delivery: &TrackerResultDelivery,
        ) -> StoreResult<StoredEvent> {
            self.publish_tracker_delivery(
                owner_epoch,
                expected_head,
                &DeliveredTrackerResult::from(delivery.clone()),
            )
        }
        fn publish_tracker_closure_result(
            &mut self,
            owner_epoch: i64,
            expected_head: &str,
            delivery: &TrackerClosureResultDelivery,
        ) -> StoreResult<StoredEvent> {
            self.publish_tracker_delivery(
                owner_epoch,
                expected_head,
                &DeliveredTrackerResult::from(delivery.clone()),
            )
        }
    }

    impl SqliteStore {
        fn publish_tracker_delivery(
            &mut self,
            owner_epoch: i64,
            expected_head: &str,
            delivery: &DeliveredTrackerResult,
        ) -> StoreResult<StoredEvent> {
            delivery.validate()?;
            let tx = self
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // Check both fences even for an exact redelivery. The embedding
            // separately repeats current authority before calling this method.
            if crate::instance_owner_epoch_on(&tx, delivery.instance_id())? != owner_epoch {
                return Err(StoreError::Conflict(
                    "tracker result owner changed before publication".into(),
                ));
            }
            if crate::chain_head_on(&tx, delivery.instance_id())?.digest != expected_head {
                return Err(StoreError::Conflict(
                    "tracker result history changed before publication".into(),
                ));
            }
            let key = delivery.event_key();
            let existing: Option<(StoredEvent, String, String, Option<String>)> = tx.query_row(
                "SELECT event_id, sequence, event_type, payload_json, source FROM events WHERE instance_id=?1 AND idempotency_key=?2",
                [delivery.instance_id(), &key], |row| Ok((StoredEvent { event_id: row.get(0)?, sequence: row.get(1)? }, row.get(2)?, row.get(3)?, row.get(4)?)))
                .optional()?;
            if let Some((event, kind, payload, source)) = existing {
                let recorded: RecordedTrackerResult<DeliveredTrackerResult> =
                    serde_json::from_str(&payload)?;
                if kind != delivery.delivery_event()
                    || source.as_deref() != Some("kernel")
                    || recorded.delivery != *delivery
                {
                    return Err(StoreError::Conflict(
                        "tracker result identity already binds a different delivery".into(),
                    ));
                }
                return Ok(event);
            }
            let state: Option<(String, String, Option<String>, String, String, String)> = tx.query_row(
                "SELECT i.status, e.kind, e.target, e.status, r.provider, r.status FROM instances i JOIN effects e ON e.instance_id=i.instance_id JOIN runs r ON r.instance_id=e.instance_id AND r.effect_id=e.effect_id WHERE i.instance_id=?1 AND e.effect_id=?2 AND r.run_id=?3",
                [delivery.instance_id(), delivery.effect_id(), delivery.run_id()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)))
                .optional()?;
            let Some((instance, kind, queue, effect, provider, run)) = state else {
                return Err(StoreError::Conflict(
                    "tracker result original attempt is missing".into(),
                ));
            };
            if instance != "running"
                || kind != delivery.kind()
                || queue.as_deref() != delivery.target()
                || provider != "queue"
                || !matches!(effect.as_str(), "running" | "failed")
                || !matches!(
                    run.as_str(),
                    "running" | "failed" | "lease_expired" | "uncertain"
                )
            {
                return Err(StoreError::Conflict(
                    "tracker result cannot advance this workflow or attempt".into(),
                ));
            }
            let (started_at, start): (i64, String) = tx.query_row(
                "SELECT sequence, payload_json FROM events WHERE instance_id=?1 AND source='kernel' AND event_type='effect.run_started' AND json_extract(payload_json,'$.run_id')=?2",
                [delivery.instance_id(), delivery.run_id()], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let evidence = delivery.application_evidence(&serde_json::from_str(&start)?)?;
            let later_attempt: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE instance_id=?1 AND source='kernel' AND event_type='effect.run_started' AND sequence>?2 AND json_extract(payload_json,'$.effect_id')=?3)",
                params![delivery.instance_id(), started_at, delivery.effect_id()], |row| row.get(0))?;
            if later_attempt {
                return Err(StoreError::Conflict(
                    "tracker result has a later competing attempt".into(),
                ));
            }
            // A rule can observe a failure without consuming its fact. Until
            // its exact observation dependencies can be proved, a post-terminal
            // rule commit is insufficient evidence of an unhandled failure.
            let handled: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE instance_id=?1 AND source='kernel' AND event_type='rule.committed' AND sequence > (SELECT MIN(sequence) FROM events WHERE instance_id=?1 AND source='kernel' AND event_type IN ('effect.terminal','lease.expired') AND json_extract(payload_json,'$.run_id')=?2))",
                [delivery.instance_id(), delivery.run_id()], |row| row.get(0))?;
            let settled_fact: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM facts WHERE instance_id=?1 AND key=?2 AND (name=?3 OR (name=?4 AND consumed_at IS NOT NULL)))",
                [delivery.instance_id(), delivery.effect_id(), delivery.success_name(), delivery.failure_name()], |row| row.get(0))?;
            if handled || settled_fact {
                return Err(StoreError::Conflict(
                    "tracker result failure may already have been handled".into(),
                ));
            }
            let failures = {
                let mut query = tx.prepare("SELECT fact_id FROM facts WHERE instance_id=?1 AND name=?3 AND key=?2 AND consumed_at IS NULL ORDER BY fact_id")?;
                let rows = query
                    .query_map(
                        [
                            delivery.instance_id(),
                            delivery.effect_id(),
                            delivery.failure_name(),
                        ],
                        |row| row.get(0),
                    )?
                    .collect::<Result<Vec<String>, _>>()?;
                rows
            };
            let record = RecordedTrackerResult {
                delivery: delivery.clone(),
                consumed_failure_facts: failures,
                complete_running_attempt: run == "running",
            };
            let event = crate::append_event_fenced_on(
                &tx,
                owner_epoch,
                expected_head,
                NewEvent {
                    instance_id: delivery.instance_id(),
                    event_type: delivery.delivery_event(),
                    payload_json: &serde_json::to_string(&record)?,
                    source: "kernel",
                    causation_id: Some(delivery.run_id()),
                    correlation_id: Some(delivery.operation_id()),
                    idempotency_key: Some(&key),
                },
            )?;
            crate::append_event_on(
                &tx,
                NewEvent {
                    instance_id: delivery.instance_id(),
                    event_type: "effect.disposition.recorded",
                    payload_json: &serde_json::to_string(&evidence)?,
                    source: "kernel",
                    causation_id: Some(&event.event_id),
                    correlation_id: Some(delivery.operation_id()),
                    idempotency_key: Some(&format!("{key}:applied")),
                },
            )?;
            apply_result(&tx, delivery.instance_id(), &event.event_id, &record)?;
            if record.complete_running_attempt {
                let metadata = delivery.terminal_metadata(&event.event_id);
                let terminal_key = format!("{key}:terminal");
                let completion = EffectCompletion {
                    instance_id: delivery.instance_id(),
                    effect_id: delivery.effect_id(),
                    run_id: delivery.run_id(),
                    provider: "queue",
                    worker_id: "tracker-recovery",
                    status: "completed",
                    exit_code: None,
                    summary: None,
                    metadata_json: &metadata,
                    idempotency_key: Some(&terminal_key),
                };
                let payload = crate::effect_completion_payload(completion, None, "completed")?;
                let terminal = crate::append_event_on(
                    &tx,
                    NewEvent {
                        instance_id: delivery.instance_id(),
                        event_type: "effect.terminal",
                        payload_json: &payload,
                        source: "kernel",
                        causation_id: Some(&event.event_id),
                        correlation_id: None,
                        idempotency_key: Some(&terminal_key),
                    },
                )?;
                crate::replay_effect_terminal(
                    &tx,
                    delivery.instance_id(),
                    &terminal.event_id,
                    &payload,
                )?;
            }
            tx.commit()?;
            Ok(event)
        }
    }

    pub(crate) fn apply_result(
        connection: &Connection,
        instance: &str,
        event: &str,
        record: &RecordedTrackerResult<DeliveredTrackerResult>,
    ) -> StoreResult<()> {
        let delivery = &record.delivery;
        if delivery.instance_id() != instance {
            return Err(StoreError::Conflict(
                "tracker result replay instance differs".into(),
            ));
        }
        let failures: Vec<&str> = record
            .consumed_failure_facts
            .iter()
            .map(String::as_str)
            .collect();
        crate::consume_facts(connection, instance, &failures)?;
        connection.execute("UPDATE effects SET status='completed', updated_at=(SELECT occurred_at FROM events WHERE event_id=?3) WHERE instance_id=?1 AND effect_id=?2",
            params![instance, delivery.effect_id(), event])?;
        crate::satisfy_dependencies_on(connection, instance)?;
        let value = delivery.fact_value().to_string();
        let fact = NewFact {
            fact_id: delivery.fact_id(),
            name: delivery.success_name(),
            key: delivery.effect_id(),
            value_json: &value,
            schema_id: None,
            provenance_class: "external",
            correlation_id: None,
            source_span_json: None,
        };
        let (version, epoch) = crate::active_revision_on(connection, instance)?;
        crate::insert_fact(
            connection,
            instance,
            "kernel",
            event,
            version.as_deref(),
            epoch,
            &fact,
        )
    }
}

#[cfg(feature = "native")]
pub(crate) use native::apply_result;

#[cfg(feature = "native")]
impl TrackerResultPublications for crate::native_stores::NativeStores {
    fn publish_tracker_result(
        &mut self,
        owner_epoch: i64,
        expected_head: &str,
        delivery: &TrackerResultDelivery,
    ) -> StoreResult<StoredEvent> {
        self.runtime
            .publish_tracker_result(owner_epoch, expected_head, delivery)
    }
    fn publish_tracker_closure_result(
        &mut self,
        owner_epoch: i64,
        expected_head: &str,
        delivery: &TrackerClosureResultDelivery,
    ) -> StoreResult<StoredEvent> {
        self.runtime
            .publish_tracker_closure_result(owner_epoch, expected_head, delivery)
    }
}
