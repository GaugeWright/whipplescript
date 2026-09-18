//! Verified execution -> retained signed envelope -> ledger receipt -> journal ack.
//! The journal and ledger commit separately; each returned value retains the
//! original envelope so recovery never signs or submits a competing candidate.
use crate::norm_execution::VerifiedNormExecution;
use serde_json::{json, Value};
use whipplescript_core::vocabulary::VocabularyRef;
use whipplescript_store::norm::{NormAct, NormActor, NormStatement, NormVerifier, SignedNormEvent};
use whipplescript_store::norm_commands::NormCommandStore;
use whipplescript_store::norm_history::CapturedNormHistory;
use whipplescript_store::norm_publication::{
    NormPublicationJournal, PublicationCandidate, PublicationSlot, RetainedPublication,
};
use whipplescript_store::StoredEvent;

pub struct ObservationSigning<'a> {
    pub vocabulary: &'a VocabularyRef,
    pub authority: Option<&'a str>,
    pub actor: &'a NormActor,
    pub created_at: &'a str,
}

/// Read-only signing handoff. A retained event needs no new signature.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservationPublicationDraft {
    Unsigned { statement: NormStatement },
    Retained { event: SignedNormEvent },
}

/// Constructible only by binding a retained envelope to verified execution.
#[derive(Clone, Debug)]
pub struct PreparedObservationPublication {
    retained: RetainedPublication,
}

/// Constructible only after the ledger returns this envelope's identity.
#[derive(Clone, Debug)]
pub struct ObservationPublicationReceipt {
    publication: PreparedObservationPublication,
    event_id: String,
}

pub(crate) fn fields(execution: &VerifiedNormExecution) -> Result<Value, String> {
    Ok(json!({
        "instance": execution.instance_id(),
        "effect": execution.intent().effect_id,
        "run": execution.run_id(),
        "invocation_json": serde_json::to_string(execution.intent()).map_err(|e| e.to_string())?,
        "observation_json": serde_json::to_string(execution.observation()).map_err(|e| e.to_string())?,
    }))
}

impl PreparedObservationPublication {
    fn statement(
        execution: &VerifiedNormExecution,
        signing: &ObservationSigning<'_>,
    ) -> Result<NormStatement, String> {
        // The signer is checked once, in `prepare`, which every path reaches;
        // a second check here was a refusal nothing could exercise.
        Ok(NormStatement {
            premises: None,
            protocol: "whipplescript.norm/v1".into(),
            actor: signing.actor.clone(),
            nonce: crate::execution_run_key(
                execution.instance_id(),
                &execution.intent().effect_id,
                execution.run_id(),
                &[
                    "norm-observation",
                    &execution.intent().anchor.checkpoint.ledger,
                ],
            ),
            created_at: signing.created_at.into(),
            action: NormAct::Create {
                ledger: execution.intent().anchor.checkpoint.ledger.clone(),
                authority: signing.authority.map(str::to_owned),
                vocabulary: signing.vocabulary.clone(),
                fields_json: fields(execution)?.to_string(),
            },
        })
    }

    /// Reconstruct the signing payload, or return a verified retained winner.
    /// An empty-slot read is not a reservation; prepare still arbitrates races.
    pub fn draft<S: NormPublicationJournal>(
        execution: &VerifiedNormExecution,
        history: &CapturedNormHistory,
        journal: &S,
        verifier: &dyn NormVerifier,
        signing: ObservationSigning<'_>,
    ) -> Result<ObservationPublicationDraft, String> {
        let statement = Self::statement(execution, &signing)?;
        let slot = PublicationSlot {
            ledger: execution.intent().anchor.checkpoint.ledger.clone(),
            instance: execution.instance_id().into(),
            effect: execution.intent().effect_id.clone(),
            run: execution.run_id().into(),
        };
        if journal
            .retained_publication(&slot)
            .map_err(|e| format!("{e:?}"))?
            .is_some()
        {
            let retained = Self::prepare(execution, history, journal, verifier, signing, |_| {
                Err("retained publication disappeared during signing handoff".into())
            })?;
            Ok(ObservationPublicationDraft::Retained {
                event: retained.event().clone(),
            })
        } else {
            history
                .preview_creation(&statement)
                .map_err(|e| format!("{e:?}"))?;
            Ok(ObservationPublicationDraft::Unsigned { statement })
        }
    }

    /// A client signature supplies authentication only. Reconstruct the entire
    /// expected statement before retention, including when recovering a winner.
    pub fn prepare_signed<S: NormPublicationJournal>(
        execution: &VerifiedNormExecution,
        history: &CapturedNormHistory,
        journal: &S,
        verifier: &dyn NormVerifier,
        event: &SignedNormEvent,
    ) -> Result<Self, String> {
        let NormAct::Create {
            authority,
            vocabulary,
            ..
        } = &event.statement.action
        else {
            return Err("observation publication requires a create statement".into());
        };
        let signing = ObservationSigning {
            vocabulary,
            authority: authority.as_deref(),
            actor: &event.statement.actor,
            created_at: &event.statement.created_at,
        };
        let expected = Self::statement(execution, &signing)?;
        if event.statement != expected || event.successor_signature.is_some() {
            return Err("signed observation differs from recovered execution".into());
        }
        event.authenticate(verifier).map_err(|e| format!("{e:?}"))?;
        Self::prepare(execution, history, journal, verifier, signing, |_| {
            Ok(event.signature.clone())
        })
    }

    /// A signer is called only for an empty slot. Retained signatures and
    /// authority parents survive configuration changes; ledger admission still
    /// verifies their historical binding and current admission requirements.
    pub fn prepare<S: NormPublicationJournal>(
        execution: &VerifiedNormExecution,
        history: &CapturedNormHistory,
        journal: &S,
        verifier: &dyn NormVerifier,
        signing: ObservationSigning<'_>,
        sign: impl FnOnce(&NormStatement) -> Result<String, String>,
    ) -> Result<Self, String> {
        if signing.actor.principal != execution.intent().publisher {
            return Err("observation signer differs from prepared publisher".into());
        }
        let slot = PublicationSlot {
            ledger: execution.intent().anchor.checkpoint.ledger.clone(),
            instance: execution.instance_id().into(),
            effect: execution.intent().effect_id.clone(),
            run: execution.run_id().into(),
        };
        let invocation = serde_json::to_value(execution.intent()).map_err(|e| e.to_string())?;
        let observation =
            serde_json::to_value(execution.observation()).map_err(|e| e.to_string())?;
        let expected_fields = fields(execution)?;
        let retained = match journal
            .retained_publication(&slot)
            .map_err(|e| format!("{e:?}"))?
        {
            Some(retained) => retained,
            None => {
                let statement = Self::statement(execution, &signing)?;
                let signature = sign(&statement)?;
                let event = SignedNormEvent {
                    statement,
                    signature,
                    successor_signature: None,
                };
                event.authenticate(verifier).map_err(|e| format!("{e:?}"))?;
                // Signing may have yielded while a compatible candidate won.
                // A losing candidate's current preflight must not replace or
                // prevent recovery of that already-retained event.
                if let Some(winner) = journal
                    .retained_publication(&slot)
                    .map_err(|e| format!("{e:?}"))?
                {
                    winner
                } else if let Err(error) = history.preflight(&event, verifier) {
                    journal
                        .retained_publication(&slot)
                        .map_err(|e| format!("{e:?}"))?
                        .ok_or_else(|| format!("publication preflight refused: {error:?}"))?
                } else {
                    journal
                        .prepare_publication(&PublicationCandidate {
                            slot: slot.clone(),
                            invocation: invocation.clone(),
                            observation: observation.clone(),
                            event,
                        })
                        .map_err(|e| format!("{e:?}"))?
                }
            }
        };
        let candidate = &retained.candidate;
        let action_matches = match &candidate.event.statement.action {
            NormAct::Create {
                ledger,
                vocabulary,
                fields_json,
                ..
            } => {
                ledger == &slot.ledger
                    && vocabulary == signing.vocabulary
                    && serde_json::from_str::<Value>(fields_json).map_err(|e| e.to_string())?
                        == expected_fields
            }
            _ => false,
        };
        if candidate.slot != slot
            || candidate.invocation != invocation
            || candidate.observation != observation
            || candidate.event.statement.actor.principal != execution.intent().publisher
            || candidate.event.statement.protocol != "whipplescript.norm/v1"
            || !action_matches
        {
            return Err("retained publication differs from verified execution".into());
        }
        candidate
            .event
            .authenticate(verifier)
            .map_err(|e| format!("{e:?}"))?;
        Ok(Self { retained })
    }

    pub fn event(&self) -> &SignedNormEvent {
        &self.retained.candidate.event
    }

    /// Use the existing signed-ledger admission, including nonce recovery and
    /// charter grants. Only its exact returned event can become a receipt.
    pub fn submit<L: NormCommandStore>(
        &self,
        ledger: &mut L,
        verifier: &dyn NormVerifier,
    ) -> Result<ObservationPublicationReceipt, String> {
        let event_id = ledger
            .append_norm(self.event(), verifier)
            .map_err(|e| format!("{e:?}"))?;
        if event_id
            != self
                .event()
                .tracker_event()
                .map_err(|e| format!("{e:?}"))?
                .event_id
        {
            return Err("ledger receipt differs from retained publication".into());
        }
        Ok(ObservationPublicationReceipt {
            publication: self.clone(),
            event_id,
        })
    }
}

impl ObservationPublicationReceipt {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    pub fn acknowledge<S: NormPublicationJournal>(
        &self,
        journal: &S,
    ) -> Result<StoredEvent, String> {
        journal
            .acknowledge_publication(&self.publication.retained.candidate.slot, &self.event_id)
            .map_err(|e| format!("{e:?}"))
    }
}
