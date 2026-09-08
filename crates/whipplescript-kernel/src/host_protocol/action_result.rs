//! Current read authority over an immutable action admission and recorded log.
use serde::{Deserialize, Serialize};

use super::action::{
    canonical_json, ActionAdmissionReceipt, ActionProvenance, HostActionCommand,
    HOST_ACTION_PROTOCOL,
};
use super::{nonempty, PinnedPosition, PolicyEpochRef, ProtocolError};
use crate::ifc::VerifiedEnvelope;

pub const ACTION_RESULT_PROTOCOL: &str = "whipplescript.action-result.v1";

/// A projection read, not a resubmission or a permission to execute anything.
/// `evidence_handle` and its label identify the complete instance evidence
/// compartment; the verifier must authorize that exact compartment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadActionResult {
    pub protocol: String,
    pub issuer: String,
    pub scope: String,
    #[serde(deserialize_with = "super::action_wire::Policy::deserialize")]
    pub policy: PolicyEpochRef,
    pub provenance: ActionProvenance,
    pub admission: ActionAdmissionReceipt,
    pub evidence_handle: String,
    pub evidence_label_ref: String,
    /// None reads the recorded head. A supplied pin reads exactly that prefix.
    #[serde(default, deserialize_with = "super::action_wire::optional_position")]
    pub through: Option<PinnedPosition>,
}

impl ReadActionResult {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.protocol != ACTION_RESULT_PROTOCOL
            || self.admission.protocol != HOST_ACTION_PROTOCOL
        {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        for (field, value) in [
            ("result issuer", &self.issuer),
            ("result scope", &self.scope),
            ("result fingerprint", &self.admission.fingerprint),
            ("result instance", &self.admission.instance_ref),
            (
                "result admission digest",
                &self.admission.admitted_at.head_digest,
            ),
            ("result evidence handle", &self.evidence_handle),
            ("result evidence label", &self.evidence_label_ref),
        ] {
            nonempty(field, value)?;
        }
        if self.admission.admitted_at.instance_ref != self.admission.instance_ref
            || self.admission.admitted_at.sequence == 0
            || self.through.as_ref().is_some_and(|pin| {
                pin.instance_ref != self.admission.instance_ref
                    || pin.sequence < self.admission.admitted_at.sequence
                    || pin.head_digest.is_empty()
            })
        {
            return Err(ProtocolError::Mismatch("result evidence coordinates"));
        }
        self.policy.validate()?;
        self.provenance.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|_| ProtocolError::Invalid("result query serialization"))?;
        let mut bytes = b"whipplescript:action-result:read:v1\0".to_vec();
        canonical_json(&value, &mut bytes)?;
        Ok(bytes)
    }
}

/// A pinned host read boundary. Authenticate the whole request and current
/// revocation, issuer/scope and delegation. Resolve the evidence handle to this
/// exact action instance and authorize its complete metadata compartment under
/// the actual label. An admission proof alone is not a read proof. Payload
/// dereference remains a separate governed read; this API returns no bodies.
pub trait ActionResultVerifier {
    fn verify(
        &self,
        request: &ReadActionResult,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError>;
}

pub(crate) struct VerifiedResultRead(ReadActionResult);

impl VerifiedResultRead {
    pub(crate) fn verify(
        request: ReadActionResult,
        envelope: &VerifiedEnvelope,
        verifier: &dyn ActionResultVerifier,
        proof: &[u8],
    ) -> Result<Self, ProtocolError> {
        let policy = PolicyEpochRef::from_verified(request.policy.epoch, envelope)?;
        if request.policy != policy
            || !envelope.attestation().is_some_and(|attestation| {
                attestation.epoch == Some(request.policy.epoch)
                    && attestation.authority.as_deref() == Some(request.issuer.as_str())
            })
        {
            return Err(ProtocolError::Mismatch(
                "result read signed authority and epoch",
            ));
        }
        let bytes = request.signing_bytes()?;
        verifier.verify(&request, &bytes, proof)?;
        Ok(Self(request))
    }

    pub(crate) fn request(&self) -> &ReadActionResult {
        &self.0
    }
}

/// Coordinates into the snapshot's pinned prefix. This is a reference to an
/// existing event, including output/footprint/diagnostic records, never a copy
/// of a possibly secret-bearing payload or a claim it remains available.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionEvidenceRef {
    pub event_id: String,
    pub sequence: u64,
    pub kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionWorkflowStatus {
    Completed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionInstanceStatus {
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionTerminalEvidence {
    pub status: ActionWorkflowStatus,
    #[serde(deserialize_with = "super::action_wire::Position::deserialize")]
    pub recorded_at: PinnedPosition,
    pub evidence: ActionEvidenceRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionEffectEvidence {
    pub effect_id: String,
    /// No attempts means not dispatched in this recorded prefix. A workflow
    /// terminal never converts an unknown attempt into applied or not applied.
    pub attempts: Vec<whipplescript_store::effect_recovery::AttemptDisposition>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResultSnapshot {
    pub protocol: String,
    pub admission: ActionAdmissionReceipt,
    pub command: HostActionCommand,
    #[serde(deserialize_with = "super::action_wire::Policy::deserialize")]
    pub read_policy: PolicyEpochRef,
    pub evidence_handle: String,
    pub evidence_label_ref: String,
    #[serde(deserialize_with = "super::action_wire::Position::deserialize")]
    pub observed_at: PinnedPosition,
    pub instance_status: ActionInstanceStatus,
    pub status_evidence: ActionEvidenceRef,
    pub terminal: Option<ActionTerminalEvidence>,
    pub effects: Vec<ActionEffectEvidence>,
    pub evidence: Vec<ActionEvidenceRef>,
}
