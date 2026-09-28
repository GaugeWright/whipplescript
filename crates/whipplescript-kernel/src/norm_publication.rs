//! Verified execution -> retained signed envelope -> ledger receipt -> journal ack.
//! The journal and ledger commit separately; each returned value retains the
//! original envelope so recovery never signs or submits a competing candidate.
use crate::norm_buck2_execution::VerifiedBuck2Execution;
use crate::norm_execution::VerifiedNormExecution;
use crate::norm_projection::VerifiedExecution;
use serde_json::{json, Value};
use whipplescript_core::vocabulary::VocabularyRef;
use whipplescript_store::norm::{NormAct, NormActor, NormStatement, NormVerifier, SignedNormEvent};
use whipplescript_store::norm_commands::NormCommandStore;
use whipplescript_store::norm_history::CapturedNormHistory;
use whipplescript_store::norm_publication::{
    NormPublicationJournal, PublicationBasis, PublicationCandidate, PublicationSlot,
    RetainedPublication,
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

/// A recovered execution a publication can bind to: its journal slot, its
/// prepared publisher, and the durable fact its retention rests on. Only
/// verified executions implement it; it is not a publication grant.
pub trait PublishableExecution {
    fn ledger(&self) -> &str;
    fn instance_id(&self) -> &str;
    fn effect_id(&self) -> &str;
    fn run_id(&self) -> &str;
    /// The requirement the signed invocation names.
    fn requirement(&self) -> &str;
    fn publisher(&self) -> &str;
    /// The invocation as it is published, in the existing codec.
    fn invocation_json(&self) -> Result<String, String>;
    /// The observation as it is published, in the existing codec.
    fn observation_json(&self) -> Result<String, String>;
    /// The durable journal fact the retention rests on.
    fn basis(&self) -> PublicationBasis;
}

impl PublishableExecution for VerifiedNormExecution {
    fn ledger(&self) -> &str {
        &self.intent().anchor.checkpoint.ledger
    }
    fn instance_id(&self) -> &str {
        VerifiedNormExecution::instance_id(self)
    }
    fn effect_id(&self) -> &str {
        &self.intent().effect_id
    }
    fn run_id(&self) -> &str {
        VerifiedNormExecution::run_id(self)
    }
    fn requirement(&self) -> &str {
        &self.intent().requirement.name
    }
    fn publisher(&self) -> &str {
        &self.intent().publisher
    }
    fn invocation_json(&self) -> Result<String, String> {
        serde_json::to_string(self.intent()).map_err(|e| e.to_string())
    }
    fn observation_json(&self) -> Result<String, String> {
        serde_json::to_string(self.observation()).map_err(|e| e.to_string())
    }
    fn basis(&self) -> PublicationBasis {
        PublicationBasis::Run {}
    }
}

/// A Buck2 run rests on its durable record, whose payload is the published
/// invocation; its observation is the adapter's report of the record.
impl PublishableExecution for VerifiedBuck2Execution {
    fn ledger(&self) -> &str {
        &self.intent().anchor.checkpoint.ledger
    }
    fn instance_id(&self) -> &str {
        VerifiedBuck2Execution::instance_id(self)
    }
    fn effect_id(&self) -> &str {
        &self.intent().effect_id
    }
    fn run_id(&self) -> &str {
        VerifiedBuck2Execution::run_id(self)
    }
    fn requirement(&self) -> &str {
        &self.intent().requirement.name
    }
    fn publisher(&self) -> &str {
        &self.intent().publisher
    }
    fn invocation_json(&self) -> Result<String, String> {
        serde_json::to_string(self.record()).map_err(|e| e.to_string())
    }
    fn observation_json(&self) -> Result<String, String> {
        serde_json::to_string(self.report()).map_err(|e| e.to_string())
    }
    fn basis(&self) -> PublicationBasis {
        PublicationBasis::Event {
            event_id: self.run_id().into(),
        }
    }
}

impl PublishableExecution for VerifiedExecution {
    fn ledger(&self) -> &str {
        self.as_publishable().ledger()
    }
    fn instance_id(&self) -> &str {
        self.as_publishable().instance_id()
    }
    fn effect_id(&self) -> &str {
        self.as_publishable().effect_id()
    }
    fn run_id(&self) -> &str {
        self.as_publishable().run_id()
    }
    fn requirement(&self) -> &str {
        self.as_publishable().requirement()
    }
    fn publisher(&self) -> &str {
        self.as_publishable().publisher()
    }
    fn invocation_json(&self) -> Result<String, String> {
        self.as_publishable().invocation_json()
    }
    fn observation_json(&self) -> Result<String, String> {
        self.as_publishable().observation_json()
    }
    fn basis(&self) -> PublicationBasis {
        self.as_publishable().basis()
    }
}

impl VerifiedExecution {
    fn as_publishable(&self) -> &dyn PublishableExecution {
        match self {
            Self::PythonCalls(execution) => execution.as_ref(),
            Self::Buck2Tests(execution) => execution.as_ref(),
        }
    }
}

pub(crate) fn fields(execution: &dyn PublishableExecution) -> Result<Value, String> {
    Ok(json!({
        "instance": execution.instance_id(),
        "effect": execution.effect_id(),
        "run": execution.run_id(),
        "invocation_json": execution.invocation_json()?,
        "observation_json": execution.observation_json()?,
    }))
}

/// A charter activation that retires a requirement retires its running
/// effects with it (norm-plane §10): a late outcome is not published.
fn refuse_retired(
    execution: &dyn PublishableExecution,
    history: &CapturedNormHistory,
    verifier: &dyn NormVerifier,
) -> Result<(), String> {
    let requirement = execution.requirement();
    if history
        .project(None, verifier)
        .map_err(|e| format!("{e:?}"))?
        .is_retired(requirement)
    {
        return Err(format!(
            "requirement {requirement} was retired by a charter activation; its run's outcome stays in the runtime journal"
        ));
    }
    Ok(())
}

fn slot(execution: &dyn PublishableExecution) -> PublicationSlot {
    PublicationSlot {
        ledger: execution.ledger().into(),
        instance: execution.instance_id().into(),
        effect: execution.effect_id().into(),
        run: execution.run_id().into(),
    }
}

impl PreparedObservationPublication {
    fn statement(
        execution: &dyn PublishableExecution,
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
                execution.effect_id(),
                execution.run_id(),
                &["norm-observation", execution.ledger()],
            ),
            created_at: signing.created_at.into(),
            action: NormAct::Create {
                ledger: execution.ledger().into(),
                authority: signing.authority.map(str::to_owned),
                vocabulary: signing.vocabulary.clone(),
                fields_json: fields(execution)?.to_string(),
            },
        })
    }

    /// Reconstruct the signing payload, or return a verified retained winner.
    /// An empty-slot read is not a reservation; prepare still arbitrates races.
    pub fn draft<S: NormPublicationJournal>(
        execution: &dyn PublishableExecution,
        history: &CapturedNormHistory,
        journal: &S,
        verifier: &dyn NormVerifier,
        signing: ObservationSigning<'_>,
    ) -> Result<ObservationPublicationDraft, String> {
        refuse_retired(execution, history, verifier)?;
        let statement = Self::statement(execution, &signing)?;
        let slot = slot(execution);
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
        execution: &dyn PublishableExecution,
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
        execution: &dyn PublishableExecution,
        history: &CapturedNormHistory,
        journal: &S,
        verifier: &dyn NormVerifier,
        signing: ObservationSigning<'_>,
        sign: impl FnOnce(&NormStatement) -> Result<String, String>,
    ) -> Result<Self, String> {
        if signing.actor.principal != execution.publisher() {
            return Err("observation signer differs from prepared publisher".into());
        }
        let slot = slot(execution);
        let invocation: Value =
            serde_json::from_str(&execution.invocation_json()?).map_err(|e| e.to_string())?;
        let observation: Value =
            serde_json::from_str(&execution.observation_json()?).map_err(|e| e.to_string())?;
        let basis = execution.basis();
        let expected_fields = fields(execution)?;
        let retained = match journal
            .retained_publication(&slot)
            .map_err(|e| format!("{e:?}"))?
        {
            Some(retained) => retained,
            None => {
                refuse_retired(execution, history, verifier)?;
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
                            basis: basis.clone(),
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
            || candidate.event.statement.actor.principal != execution.publisher()
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
