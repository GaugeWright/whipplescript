//! A build artifact's publication by the wrapper (DR-0124 §14.6).
//!
//! The same journal-retained, at-most-once path a Home process uses for an
//! observation, keyed by the artifact's identity — ledger, cut, target label,
//! configuration — instead of an execution's slot. Preparation retains one
//! signed candidate per identity; a retry recovers the retained envelope and
//! never signs a competitor; a candidate that differs from what was retained
//! for the same identity is refused. Submission is the ordinary signed-ledger
//! admission under the charter's `build.publish` scope, so the ledger, not
//! the executor, decides what enters. As an observation's retention rests on
//! its settled run, an artifact's rests on the durable build record the
//! wrapper appended to its runtime journal under the artifact's instance,
//! with the artifact as its payload: a publication with no such record is
//! refused by the journal, so nothing is published that was not first
//! durably built. The record carries the cut, the label
//! and configuration, the output digests, the action-classification basis
//! of §14.2 and the versioned cut-to-input-root encoding of §14.3. Nothing
//! here computes a build, reads a store, or knows what an artifact means.
use serde::{Deserialize, Serialize};
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

/// The versioned encoding between a workspace cut's canonical identity and
/// remote-execution directory and action objects (§14.3). Named in every
/// artifact record so a result's provenance says which encoding produced it.
pub const INPUT_ROOT_ENCODING_V1: &str = "whipplescript.build.input-root/v1";

/// What the wrapper asserts about one built target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildArtifact {
    pub ledger: String,
    pub cut: String,
    pub label: String,
    pub configuration: String,
    /// Output digests, in the order the target declares its outputs.
    pub outputs: Vec<String>,
    /// The action-classification basis the result carries (§14.2).
    pub classification: String,
    pub encoding: String,
    /// The action digest Buck2 computed, when the wrapper has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

impl BuildArtifact {
    /// The record's fields, as the `artifact` vocabulary declares them.
    pub fn fields(&self) -> Value {
        let mut fields = json!({
            "cut": self.cut,
            "label": self.label,
            "configuration": self.configuration,
            "outputs": self.outputs,
            "classification": self.classification,
            "encoding": self.encoding,
        });
        if let Some(action) = &self.action {
            fields["action"] = json!(action);
        }
        fields
    }

    /// One retention slot per artifact identity.
    fn slot(&self) -> PublicationSlot {
        PublicationSlot {
            ledger: self.ledger.clone(),
            instance: format!("build:{}", self.cut),
            effect: format!("{}#{}", self.label, self.configuration),
            run: "artifact".into(),
        }
    }

    fn nonce(&self) -> String {
        crate::idempotency_key(&[
            "norm-artifact",
            &self.ledger,
            &self.cut,
            &self.label,
            &self.configuration,
        ])
    }
}

pub struct ArtifactSigning<'a> {
    pub vocabulary: &'a VocabularyRef,
    pub authority: Option<&'a str>,
    pub actor: &'a NormActor,
    pub created_at: &'a str,
}

/// Constructible only by binding a retained envelope to the artifact.
#[derive(Clone, Debug)]
pub struct PreparedArtifactPublication {
    retained: RetainedPublication,
}

/// Constructible only after the ledger returns this envelope's identity.
#[derive(Clone, Debug)]
pub struct ArtifactPublicationReceipt {
    publication: PreparedArtifactPublication,
    event_id: String,
}

impl PreparedArtifactPublication {
    fn statement(artifact: &BuildArtifact, signing: &ArtifactSigning<'_>) -> NormStatement {
        NormStatement {
            premises: None,
            protocol: "whipplescript.norm/v1".into(),
            actor: signing.actor.clone(),
            nonce: artifact.nonce(),
            created_at: signing.created_at.into(),
            action: NormAct::Create {
                ledger: artifact.ledger.clone(),
                authority: signing.authority.map(str::to_owned),
                vocabulary: signing.vocabulary.clone(),
                fields_json: artifact.fields().to_string(),
            },
        }
    }

    /// The runtime-journal instance and event type under which the wrapper
    /// records a completed build before publishing it.
    pub fn build_instance(artifact: &BuildArtifact) -> String {
        artifact.slot().instance
    }
    pub const BUILD_RECORDED: &'static str = "build.recorded";

    /// A signer is called only for an empty slot. A retained envelope for the
    /// same identity is recovered and must describe the same artifact.
    /// `build_record` is the durable journal event the wrapper appended for
    /// this build; the journal refuses a retention it does not find.
    pub fn prepare<S: NormPublicationJournal>(
        artifact: &BuildArtifact,
        build_record: &str,
        history: &CapturedNormHistory,
        journal: &S,
        verifier: &dyn NormVerifier,
        signing: ArtifactSigning<'_>,
        sign: impl FnOnce(&NormStatement) -> Result<String, String>,
    ) -> Result<Self, String> {
        let slot = artifact.slot();
        let basis = PublicationBasis::Event {
            event_id: build_record.into(),
        };
        let invocation = serde_json::to_value(artifact).map_err(|e| e.to_string())?;
        let expected_fields = artifact.fields();
        let retained = match journal
            .retained_publication(&slot)
            .map_err(|e| format!("{e:?}"))?
        {
            Some(retained) => retained,
            None => {
                let statement = Self::statement(artifact, &signing);
                let signature = sign(&statement)?;
                let event = SignedNormEvent {
                    statement,
                    signature,
                    successor_signature: None,
                };
                event.authenticate(verifier).map_err(|e| format!("{e:?}"))?;
                // Signing may have yielded while a compatible candidate won;
                // a losing candidate's preflight must not replace it.
                if let Some(winner) = journal
                    .retained_publication(&slot)
                    .map_err(|e| format!("{e:?}"))?
                {
                    winner
                } else if let Err(error) = history.preflight(&event, verifier) {
                    journal
                        .retained_publication(&slot)
                        .map_err(|e| format!("{e:?}"))?
                        .ok_or_else(|| {
                            format!("artifact publication preflight refused: {error:?}")
                        })?
                } else {
                    journal
                        .prepare_publication(&PublicationCandidate {
                            slot: slot.clone(),
                            invocation: invocation.clone(),
                            observation: expected_fields.clone(),
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
            || candidate.basis != basis
            || candidate.event.statement.actor != *signing.actor
            || candidate.event.statement.protocol != "whipplescript.norm/v1"
            || !action_matches
        {
            // MUTATION-SUCCESS-EXPR: Ok(Self { retained: retained.clone() })
            return Err("retained artifact publication differs from the artifact".into());
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

    /// Ordinary signed-ledger admission; the ledger's returned identity is
    /// the receipt.
    pub fn submit<L: NormCommandStore>(
        &self,
        ledger: &mut L,
        verifier: &dyn NormVerifier,
    ) -> Result<ArtifactPublicationReceipt, String> {
        let event_id = ledger
            .append_norm(self.event(), verifier)
            .map_err(|e| format!("{e:?}"))?;
        Ok(ArtifactPublicationReceipt {
            publication: self.clone(),
            event_id,
        })
    }
}

impl ArtifactPublicationReceipt {
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
