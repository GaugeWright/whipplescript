//! Shared read-only verification of a retained, complete native candidate.
use super::*;
use crate::branches::flowing_fence::{FlowingFence, FlowingSourceKind};
use crate::vcs::flowing_subject::CapturedGateSubject;

/// Constructed only by the owning VCS reader after repeating its source
/// derivation. This is neither Home authority nor a ref-admission certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedNativeCandidate {
    subject: CapturedGateSubject,
}

impl VerifiedNativeCandidate {
    pub fn subject(&self) -> &CapturedGateSubject {
        &self.subject
    }
}

use super::native_candidate_recording::witness_for;

impl<B: Branches + FlowingSources + FlowingAdmissions + FlowingAbandonments, C: ContentBlobs>
    WorkspaceVcs<B, C>
{
    /// Verify an existing candidate without storing a cut or issuing a
    /// witness. The embedding supplies the original immutable revision from
    /// its independent review authority, not a reconstructed or caller-chosen
    /// revision. This only establishes the owning VCS's source proof.
    pub fn verify_retained_native_candidate(
        &self,
        revision: &NativeRevision,
        witness_digest: &str,
        attempt_id: &str,
    ) -> StoreResult<VerifiedNativeCandidate>
    where
        B: FlowingFence,
    {
        let captured = self.capture_gate_subject(witness_digest, attempt_id)?;
        let witness = captured.witness();
        let derived = match captured.fence().kind {
            FlowingSourceKind::Twig => self.derive_native_review_candidate(
                revision,
                witness.expected_trunk_cut_id.as_deref(),
                &witness.candidate_cut_id,
            )?,
            FlowingSourceKind::Branch => self.derive_named_branch_candidate(
                revision,
                witness.expected_trunk_cut_id.as_deref(),
                &witness.candidate_cut_id,
            )?,
        };
        let NativeCandidateOutcome::Prepared(candidate) = derived else {
            let reason = format!("retained candidate source proof refuses: {derived:?}");
            // MUTATION-SUCCESS-EXPR: Ok(VerifiedNativeCandidate { subject: captured.clone() })
            return Err(StoreError::Conflict(reason));
        };
        if candidate.candidate_witness_digest != witness_digest
            || witness_for(revision, &candidate) != *witness
        {
            return Err(StoreError::Conflict(
                "retained candidate differs from current source derivation".into(),
            ));
        }
        let current = self.capture_gate_subject(witness_digest, attempt_id)?;
        if current != captured {
            return Err(StoreError::Conflict(
                "retained candidate premises changed during source derivation".into(),
            ));
        }
        Ok(VerifiedNativeCandidate { subject: captured })
    }
}
