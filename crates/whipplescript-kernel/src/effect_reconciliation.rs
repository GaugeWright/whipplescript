//! A fenced append over the recorded attempt, with no execution or I/O retry.
#[cfg(any(test, feature = "test-support"))]
pub mod conformance;
use whipplescript_store::effect_recovery::{fold_attempts, ExternalDisposition};
use whipplescript_store::event_chain::{fold_owned, OwnedChainEntry};
use whipplescript_store::log_append::LogAppend;
use whipplescript_store::{EventView, NewEvent, RuntimeStore};

use crate::host_facade::{positive_sequence, HostFacadeError};
use crate::host_protocol::recovery::{
    ReconciliationDiagnostic, ReconciliationReceipt, RecordedReconciliation,
    VerifiedReconciliation, EFFECT_RECONCILIATION_PROTOCOL,
};
use crate::host_protocol::{PinnedPosition, ProtocolError};
use crate::RuntimeKernel;

impl<S: RuntimeStore + LogAppend> RuntimeKernel<S> {
    pub(crate) fn record_reconciliation(
        &mut self,
        verified: &VerifiedReconciliation,
        owner_epoch: i64,
    ) -> Result<ReconciliationReceipt, HostFacadeError> {
        let command = verified.command();
        let frame = &command.evidence.frame;
        let key = command.request_key()?;
        let mut prefix = self
            .store()
            .chain_prefix(&frame.instance_id)
            .map_err(HostFacadeError::Store)?;
        checked_prefix(&frame.instance_id, &prefix)?;
        // Verification occurs even on redelivery: an old receipt does not
        // confer current access, and a changed meaning cannot spend the key.
        if let Some(index) = prefix
            .iter()
            .position(|entry| entry.idempotency_key.as_deref() == Some(&key))
        {
            let existing = &prefix[index];
            if existing.source.as_deref() != Some("kernel")
                || existing.event_type != "effect.disposition.reconciled"
                || serde_json::from_str::<RecordedReconciliation>(&existing.payload_json)
                    .map_err(HostFacadeError::Json)?
                    .command
                    != *command
            {
                return Err(ProtocolError::Mismatch(
                    "reconciliation request already binds different evidence",
                )
                .into());
            }
            prefix.truncate(index + 1);
            return receipt(verified, &prefix);
        }
        let events: Vec<_> = prefix
            .iter()
            .map(|entry| EventView {
                event_id: entry.event_id.clone(),
                sequence: entry.sequence,
                event_type: entry.event_type.clone(),
                payload_json: entry.payload_json.clone(),
                source: entry.source.clone().unwrap_or_default(),
                occurred_at: entry.occurred_at.clone(),
            })
            .collect();
        let attempts = fold_attempts(&frame.instance_id, &frame.effect_id, &events)
            .map_err(HostFacadeError::Store)?;
        let Some(attempt) = attempts.iter().find(|attempt| {
            attempt
                .dispatch
                .as_ref()
                .is_some_and(|dispatch| dispatch.frame == *frame)
        }) else {
            // MUTATION-SUCCESS-EXPR: receipt(verified, &prefix)
            return Err(ProtocolError::Mismatch("reconciliation exact recorded dispatch").into());
        };
        let contradictory = attempt.disposition != ExternalDisposition::Unknown
            && attempt.disposition != ExternalDisposition::from(command.evidence.disposition);
        let diagnostic = (attempt.disputed || contradictory).then(|| ReconciliationDiagnostic {
            code: whipplescript_core::runtime_diagnostic_code!("runtime.recovery_uncertain")
                .as_str()
                .into(),
            effect_id: frame.effect_id.clone(),
            run_id: frame.run_id.clone(),
            message:
                "Authenticated target evidence is disputed; automatic recovery remains refused."
                    .into(),
            evidence_refs: attempt
                .evidence
                .iter()
                .map(|evidence| evidence.evidence_ref.clone())
                .chain(std::iter::once(command.evidence.evidence_ref.clone()))
                .collect(),
        });
        let head = fold_owned(&frame.instance_id, &prefix);
        let payload = serde_json::to_string(&RecordedReconciliation {
            command: command.clone(),
            diagnostic,
        })
        .map_err(HostFacadeError::Json)?;
        let fingerprint = command.fingerprint()?;
        let event = self
            .store_mut()
            .append_event_fenced(
                owner_epoch,
                &head.digest,
                NewEvent {
                    instance_id: &frame.instance_id,
                    event_type: "effect.disposition.reconciled",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: Some(&frame.run_id),
                    correlation_id: Some(&fingerprint),
                    idempotency_key: Some(&key),
                },
            )
            .map_err(HostFacadeError::Store)?;
        // Pin the actual committed event, including its store-minted time/id.
        // Concurrent later appends cannot move the receipt's position.
        prefix = self
            .store()
            .chain_prefix(&frame.instance_id)
            .map_err(HostFacadeError::Store)?;
        prefix.retain(|entry| entry.sequence <= event.sequence);
        require_committed_event(&prefix, &event)?;
        receipt(verified, &prefix)
    }
}

fn receipt(
    verified: &VerifiedReconciliation,
    prefix: &[OwnedChainEntry],
) -> Result<ReconciliationReceipt, HostFacadeError> {
    let command = verified.command();
    let instance = &command.evidence.frame.instance_id;
    let head = checked_prefix(instance, prefix)?;
    Ok(ReconciliationReceipt {
        protocol: EFFECT_RECONCILIATION_PROTOCOL.into(),
        request_key: command.request_key()?,
        fingerprint: command.fingerprint()?,
        recorded_at: PinnedPosition {
            instance_ref: instance.clone(),
            sequence: positive_sequence(head.sequence.unwrap_or(0))?,
            head_digest: head.digest,
        },
    })
}

pub(crate) fn checked_prefix(
    instance: &str,
    prefix: &[OwnedChainEntry],
) -> Result<whipplescript_store::event_chain::ChainHead, HostFacadeError> {
    let contiguous = prefix.iter().enumerate().all(|(index, entry)| {
        i64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            == Some(entry.sequence)
    });
    if !contiguous {
        return Err(ProtocolError::Mismatch("reconciliation durable prefix").into());
    }
    Ok(fold_owned(instance, prefix))
}

fn require_committed_event(
    prefix: &[OwnedChainEntry],
    event: &whipplescript_store::StoredEvent,
) -> Result<(), HostFacadeError> {
    if !prefix
        .last()
        .is_some_and(|last| last.event_id == event.event_id && last.sequence == event.sequence)
    {
        return Err(ProtocolError::Mismatch("reconciliation committed evidence").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_store::native_stores::NativeStores;

    #[test]
    fn authenticated_reconciliation_native_journey() {
        for actor in ["person:1", "agent:1"] {
            conformance::journey(NativeStores::open_in_memory().unwrap(), actor);
        }
    }

    #[test]
    fn reconciliation_receipts_require_a_complete_prefix_ending_at_the_committed_event() {
        let row = OwnedChainEntry {
            event_id: "event".into(),
            sequence: 1,
            event_type: "effect.disposition.reconciled".into(),
            payload_json: "{}".into(),
            occurred_at: "2026-09-05T00:00:00Z".into(),
            source: Some("kernel".into()),
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
            format_version: Some(1),
        };
        let event = whipplescript_store::StoredEvent {
            event_id: row.event_id.clone(),
            sequence: row.sequence,
        };
        checked_prefix("instance", std::slice::from_ref(&row)).unwrap();
        require_committed_event(std::slice::from_ref(&row), &event).unwrap();
        assert!(require_committed_event(&[], &event).is_err());
        for sequence in [0, 2] {
            let mut changed = row.clone();
            changed.sequence = sequence;
            assert!(checked_prefix("instance", std::slice::from_ref(&changed)).is_err());
            assert!(require_committed_event(&[changed], &event).is_err());
        }
        let mut changed = row.clone();
        changed.event_id = "other-event".into();
        assert!(require_committed_event(&[changed], &event).is_err());
        assert!(checked_prefix("instance", &[row.clone(), row]).is_err());
    }
}
