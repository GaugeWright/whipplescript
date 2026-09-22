//! Atomic runtime-journal retention for signed observation publication.
//!
//! These are storage values, not execution-verification or publishing grants.
//! The host must construct candidates from verified execution and use ordinary
//! signed-ledger admission when submitting the retained envelope.
use crate::norm::{NormAct, SignedNormEvent};
use crate::{NewEvent, RuntimeStore, StoreError, StoreResult, StoredEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const PREPARED: &str = "norm.publication.prepared";
const ACKNOWLEDGED: &str = "norm.publication.acknowledged";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationSlot {
    pub ledger: String,
    pub instance: String,
    pub effect: String,
    pub run: String,
}

/// The durable fact a retention rests on. An observation rests on the
/// slot's settled run; a build artifact (DR-0124 §14.6) rests on the durable
/// build record the wrapper appended under the slot's instance, whose payload
/// is the candidate's invocation. Absent in older payloads, which were runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicationBasis {
    Run {},
    Event { event_id: String },
}

impl Default for PublicationBasis {
    fn default() -> Self {
        Self::Run {}
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationCandidate {
    pub slot: PublicationSlot,
    /// Existing invocation and observer codecs, retained without reinterpretation.
    pub invocation: Value,
    pub observation: Value,
    pub event: SignedNormEvent,
    #[serde(default, skip_serializing_if = "PublicationBasis::is_run")]
    pub basis: PublicationBasis,
}

impl PublicationBasis {
    fn is_run(&self) -> bool {
        matches!(self, Self::Run {})
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedPublication {
    pub preparation: StoredEvent,
    pub candidate: PublicationCandidate,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgment {
    slot: PublicationSlot,
    event_id: String,
}

pub trait NormPublicationJournal: RuntimeStore {
    /// Recover signed bytes without consulting a signer or current key configuration.
    fn retained_publication(
        &self,
        slot: &PublicationSlot,
    ) -> StoreResult<Option<RetainedPublication>> {
        retained(self, slot)
    }
    /// Select and return the complete winner inside one backend transaction.
    fn prepare_publication(
        &self,
        candidate: &PublicationCandidate,
    ) -> StoreResult<RetainedPublication>;
    /// Record a ledger receipt only for the exact retained signed event.
    fn acknowledge_publication(
        &self,
        slot: &PublicationSlot,
        event_id: &str,
    ) -> StoreResult<StoredEvent>;
}

fn key(slot: &PublicationSlot, kind: &str) -> StoreResult<String> {
    let bytes = serde_json::to_vec(&(kind, slot))?;
    let digest: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!("norm-publication:{digest}"))
}

fn conflict(message: &str) -> StoreError {
    StoreError::Conflict(format!("norm publication {message}"))
}

fn retained<S: RuntimeStore + ?Sized>(
    store: &S,
    slot: &PublicationSlot,
) -> StoreResult<Option<RetainedPublication>> {
    // Publication is an external fact: a context restore must not free its slot.
    for event in store.list_events(&slot.instance)? {
        if event.event_type == PREPARED {
            let candidate: PublicationCandidate = serde_json::from_str(&event.payload_json)?;
            if candidate.slot == *slot {
                return Ok(Some(RetainedPublication {
                    preparation: StoredEvent {
                        event_id: event.event_id,
                        sequence: event.sequence,
                    },
                    candidate,
                }));
            }
        }
    }
    Ok(None)
}

// Authority parents and bound keys belong to the selected signed envelope.
// They may differ across valid competing preparations after key rotation.
fn same_observation_action(left: &NormAct, right: &NormAct) -> bool {
    match (left, right) {
        (
            NormAct::Create {
                ledger: left_ledger,
                vocabulary: left_vocabulary,
                fields_json: left_fields,
                ..
            },
            NormAct::Create {
                ledger: right_ledger,
                vocabulary: right_vocabulary,
                fields_json: right_fields,
                ..
            },
        ) => {
            left_ledger == right_ledger
                && left_vocabulary == right_vocabulary
                && left_fields == right_fields
        }
        _ => false,
    }
}

/// Backend implementation helper. The caller MUST hold its writer transaction
/// across this entire function; ordinary append_event alone is insufficient.
#[doc(hidden)]
pub fn prepare_in_transaction<S: RuntimeStore>(
    store: &S,
    candidate: &PublicationCandidate,
) -> StoreResult<RetainedPublication> {
    let creates_in_ledger = matches!(&candidate.event.statement.action,
        NormAct::Create { ledger, .. } if ledger == &candidate.slot.ledger);
    if !creates_in_ledger {
        return Err(conflict("envelope does not create in the selected ledger"));
    }
    if let Some(winner) = retained(store, &candidate.slot)? {
        if winner.candidate.invocation != candidate.invocation
            || winner.candidate.observation != candidate.observation
            || winner.candidate.event.statement.actor.principal
                != candidate.event.statement.actor.principal
            || !same_observation_action(
                &winner.candidate.event.statement.action,
                &candidate.event.statement.action,
            )
            || winner.candidate.event.statement.protocol != candidate.event.statement.protocol
            || winner.candidate.basis != candidate.basis
        {
            return Err(conflict("slot has different immutable bindings"));
        }
        return Ok(winner);
    }
    match &candidate.basis {
        PublicationBasis::Run {} => {
            let terminal = store
                .list_runs(&candidate.slot.instance)?
                .into_iter()
                .any(|run| {
                    run.run_id == candidate.slot.run
                        && run.effect_id == candidate.slot.effect
                        && matches!(run.status.as_str(), "completed" | "failed")
                });
            if !terminal {
                return Err(conflict("requires the selected durable terminal run"));
            }
        }
        PublicationBasis::Event { event_id } => {
            let recorded = store
                .list_events(&candidate.slot.instance)?
                .into_iter()
                .any(|event| {
                    event.event_id == *event_id
                        && serde_json::from_str::<Value>(&event.payload_json)
                            .is_ok_and(|payload| payload == candidate.invocation)
                });
            if !recorded {
                return Err(conflict(
                    "requires the durable record it names, with the candidate's invocation as its payload",
                ));
            }
        }
    }
    let payload = serde_json::to_string(candidate)?;
    let key = key(&candidate.slot, PREPARED)?;
    let preparation = store.append_event(NewEvent {
        instance_id: &candidate.slot.instance,
        event_type: PREPARED,
        payload_json: &payload,
        source: "kernel",
        causation_id: None,
        correlation_id: Some(&candidate.slot.effect),
        idempotency_key: Some(&key),
    })?;
    Ok(RetainedPublication {
        preparation,
        candidate: candidate.clone(),
    })
}

/// Backend implementation helper with the same writer-transaction requirement.
#[doc(hidden)]
pub fn acknowledge_in_transaction<S: RuntimeStore>(
    store: &S,
    slot: &PublicationSlot,
    event_id: &str,
) -> StoreResult<StoredEvent> {
    let winner = retained(store, slot)?.ok_or_else(|| conflict("has no retained preparation"))?;
    if winner.candidate.event.tracker_event()?.event_id != event_id {
        return Err(conflict("receipt names another signed event"));
    }
    for event in store.list_events(&slot.instance)? {
        if event.event_type == ACKNOWLEDGED {
            let acknowledged: Acknowledgment = serde_json::from_str(&event.payload_json)?;
            if acknowledged.slot == *slot {
                if acknowledged.event_id != event_id {
                    return Err(conflict("retained acknowledgment differs from receipt"));
                }
                return Ok(StoredEvent {
                    event_id: event.event_id,
                    sequence: event.sequence,
                });
            }
        }
    }
    let payload = serde_json::to_string(&Acknowledgment {
        slot: slot.clone(),
        event_id: event_id.into(),
    })?;
    let key = key(slot, ACKNOWLEDGED)?;
    store.append_event(NewEvent {
        instance_id: &slot.instance,
        event_type: ACKNOWLEDGED,
        payload_json: &payload,
        source: "kernel",
        causation_id: Some(&winner.preparation.event_id),
        correlation_id: Some(&slot.effect),
        idempotency_key: Some(&key),
    })
}

#[cfg(feature = "native")]
impl NormPublicationJournal for crate::SqliteStore {
    fn prepare_publication(
        &self,
        candidate: &PublicationCandidate,
    ) -> StoreResult<RetainedPublication> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let winner = prepare_in_transaction(self, candidate)?;
        tx.commit()?;
        Ok(winner)
    }
    fn acknowledge_publication(
        &self,
        slot: &PublicationSlot,
        event_id: &str,
    ) -> StoreResult<StoredEvent> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let receipt = acknowledge_in_transaction(self, slot, event_id)?;
        tx.commit()?;
        Ok(receipt)
    }
}

#[cfg(feature = "native")]
impl NormPublicationJournal for crate::native_stores::NativeStores {
    fn prepare_publication(
        &self,
        candidate: &PublicationCandidate,
    ) -> StoreResult<RetainedPublication> {
        self.runtime.prepare_publication(candidate)
    }
    fn acknowledge_publication(
        &self,
        slot: &PublicationSlot,
        event_id: &str,
    ) -> StoreResult<StoredEvent> {
        self.runtime.acknowledge_publication(slot, event_id)
    }
}
