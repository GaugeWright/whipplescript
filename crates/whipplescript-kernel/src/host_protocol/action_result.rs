//! Current read authority over an immutable action admission and recorded log.
use serde::{Deserialize, Serialize};

use super::action::{
    canonical_json, ActionAdmissionReceipt, ActionProvenance, HostActionCommand,
    HOST_ACTION_PROTOCOL,
};
use super::{nonempty, PinnedPosition, PolicyEpochRef, ProtocolError};
use crate::ifc::VerifiedEnvelope;

pub const ACTION_RESULT_PROTOCOL: &str = "whipplescript.action-result.v1";
pub const ACTION_RESULT_PROTOCOL_V2: &str = "whipplescript.action-result.v2";
/// V2's read authority plus the run's anchor and act footprint (DR-0207). A
/// reader asks for V4 to be sent those fields; a V1 or V2 read is answered in
/// the shape that reader was built for, and refuses an anchored action rather
/// than send it a field its strict decoder would reject. There is no V3: the
/// published v5 host-action contract's vectors use that name as their example
/// of a protocol every reader refuses, and those vectors are immutable.
pub const ACTION_RESULT_PROTOCOL_V4: &str = "whipplescript.action-result.v4";

/// A projection read, not a resubmission or a permission to execute anything.
/// `evidence_handle` and its label identify the complete instance evidence
/// compartment; the verifier must authorize that exact compartment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadActionResult {
    pub protocol: String,
    pub issuer: String,
    /// V2 current read-policy authority, distinct from the historical issuer
    /// and from the policy's cryptographic signer. V1 omits this field.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "read_authority"
    )]
    pub read_authority: Option<String>,
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

fn read_authority<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<String>, D::Error> {
    // Absence is the V1 default; an explicit null is not an authority name.
    String::deserialize(decoder).map(Some)
}

impl ReadActionResult {
    fn current_authority(&self) -> Result<&str, ProtocolError> {
        match (self.protocol.as_str(), self.read_authority.as_deref()) {
            (ACTION_RESULT_PROTOCOL, None) => Ok(&self.issuer),
            (ACTION_RESULT_PROTOCOL_V2 | ACTION_RESULT_PROTOCOL_V4, Some(authority))
                if !authority.trim().is_empty() =>
            {
                Ok(authority)
            }
            // MUTATION-SUCCESS-EXPR: Ok(&self.issuer)
            _ => Err(ProtocolError::WrongVersion(self.protocol.clone())),
        }
    }

    /// Whether this reader negotiated the anchor and footprint fields.
    pub fn reads_footprint(&self) -> bool {
        self.protocol == ACTION_RESULT_PROTOCOL_V4
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.current_authority()?;
        if self.admission.anchor.is_some() && !self.reads_footprint() {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        if self.admission.protocol != HOST_ACTION_PROTOCOL {
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
        let mut bytes = match self.protocol.as_str() {
            ACTION_RESULT_PROTOCOL => b"whipplescript:action-result:read:v1\0".to_vec(),
            ACTION_RESULT_PROTOCOL_V2 => b"whipplescript:action-result:read:v2\0".to_vec(),
            _ => b"whipplescript:action-result:read:v4\0".to_vec(),
        };
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
        let authority = request.current_authority()?;
        if request.policy != policy
            || !envelope.attestation().is_some_and(|attestation| {
                attestation.epoch == Some(request.policy.epoch)
                    && attestation.authority.as_deref() == Some(authority)
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
    /// Present exactly on a V4 snapshot (DR-0207); omitted otherwise, so a
    /// V1 or V2 snapshot is byte-identical to one that predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub footprint: Option<ActionFootprint>,
}

/// Whether the runtime saw what an act did, or only that it ran.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FootprintObservation {
    /// A runtime-mediated act: what it read and changed is recorded by the
    /// runtime itself, in the events this snapshot's evidence references.
    Observed,
    /// An opaque act — a shell command, an agent's tool loop, a provider
    /// call — whose invocation and captured output are recorded but whose
    /// filesystem and network actions are not. Never read as "did nothing".
    Unobserved,
}

/// One act of the run, in the order its effect first appears in the prefix.
/// The footprint body stays behind the evidence references; this records only
/// how much of it the runtime could see.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActFootprint {
    pub effect_id: String,
    pub kind: String,
    pub observation: FootprintObservation,
}

/// The run's act footprint and its unobserved share, `unobserved` of `total`
/// acts. Counts, not a ratio, so the record is exact and a reader computes
/// whatever presentation it wants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionFootprint {
    pub acts: Vec<ActFootprint>,
    pub unobserved: u64,
    pub total: u64,
}

impl ActionFootprint {
    pub fn from_acts(acts: Vec<ActFootprint>) -> Self {
        let unobserved = acts
            .iter()
            .filter(|act| act.observation == FootprintObservation::Unobserved)
            .count() as u64;
        let total = acts.len() as u64;
        Self {
            acts,
            unobserved,
            total,
        }
    }

    /// The share of acts whose footprint is unobserved; `None` for a run that
    /// has taken no act, which has no share rather than a zero one.
    pub fn unobserved_share(&self) -> Option<f64> {
        (self.total > 0).then(|| self.unobserved as f64 / self.total as f64)
    }
}

/// The runtime's classification of an effect kind's footprint. Exhaustive over
/// the language's effect kinds, so a new kind cannot ship without someone
/// deciding whether the runtime sees what it does; a kind this build does not
/// know is unobserved, never assumed mediated.
pub fn act_observation(kind: &str) -> FootprintObservation {
    use whipplescript_parser::IrEffectKind as K;
    let Some(known) = K::ALL.iter().find(|known| known.as_str() == kind) else {
        return FootprintObservation::Unobserved;
    };
    match known {
        K::ExecCommand | K::AgentTell | K::CapabilityCall => FootprintObservation::Unobserved,
        K::SchemaCoerce
        | K::EventEmit
        | K::WorkflowInvoke
        | K::TimerWait
        | K::HttpRequest
        | K::MintCredential
        | K::RotateCredential
        | K::RevokeCredential
        | K::TrackerFile
        | K::TrackerClaim
        | K::TrackerRenew
        | K::TrackerRelease
        | K::TrackerFinish
        | K::TrackerMembership
        | K::TrackerInspect
        | K::LeaseAcquire
        | K::LeaseRenew
        | K::LedgerAppend
        | K::CounterConsume
        | K::SignalEmit
        | K::FileRead
        | K::FileWrite
        | K::FileImport
        | K::FileExport => FootprintObservation::Observed,
    }
}
