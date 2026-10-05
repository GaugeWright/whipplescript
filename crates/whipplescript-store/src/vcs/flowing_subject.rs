//! Owning read-only subject capture shared by native and hosted VCS readers.
use super::WorkspaceVcs;
use crate::branches::flowing_admission::{
    FlowingAdmissions, FlowingAttemptPin, FlowingCandidateWitness,
};
use crate::branches::flowing_fence::{FlowingFence, FlowingFenceState};
use crate::branches::flowing_holders::FlowingUnitHolder;
use crate::branches::flowing_sources::FlowingSources;
use crate::branches::{BranchStatus, Branches, MAINLINE_BRANCH_ID};
use crate::content::ContentBlobs;
use crate::{StoreError, StoreResult};

/// Read from the ref authority, never deserialized from an attempted plan.
/// This proves a currently retained native subject, not policy or dependency
/// coverage. The final ref door still has to fence these mutable premises.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedGateSubject {
    pub(super) witness: FlowingCandidateWitness,
    pub(super) pin: FlowingAttemptPin,
    pub(super) fence: FlowingFenceState,
    pub(super) lineage_fences: Vec<FlowingFenceState>,
    pub(super) unit_holders: Vec<FlowingUnitHolder>,
}

impl CapturedGateSubject {
    pub fn witness(&self) -> &FlowingCandidateWitness {
        &self.witness
    }
    pub fn attempt_id(&self) -> &str {
        &self.pin.op_id
    }
    pub fn fence(&self) -> &FlowingFenceState {
        &self.fence
    }
    pub fn lineage_fences(&self) -> &[FlowingFenceState] {
        &self.lineage_fences
    }
    pub fn unit_holders(&self) -> &[FlowingUnitHolder] {
        &self.unit_holders
    }
}

fn invalid(reason: &str) -> StoreError {
    StoreError::Conflict(format!("candidate gate refuses: {reason}"))
}

impl<B: Branches + FlowingAdmissions + FlowingFence + FlowingSources, C: ContentBlobs>
    WorkspaceVcs<B, C>
{
    /// Capture a live retained candidate without executing or creating work.
    /// A source tail may advance; the immutable selected prefix stays exact.
    pub fn capture_gate_subject(
        &self,
        witness_digest: &str,
        attempt_op_id: &str,
    ) -> StoreResult<CapturedGateSubject> {
        if witness_digest.trim().is_empty() || attempt_op_id.trim().is_empty() {
            return Err(invalid("candidate or attempt identity is incomplete"));
        }
        let Some(witness) = self.branches.candidate_witness(witness_digest)? else {
            return Err(invalid("candidate witness is missing"));
        };
        let Some(pin) = self.branches.flowing_attempt_pin(attempt_op_id)? else {
            return Err(invalid("candidate attempt is not retained"));
        };
        if pin.released_at.is_some()
            || pin.witness_digest != witness_digest
            || pin.source_cut_id != witness.source_cut_id
            || pin.candidate_cut_id != witness.candidate_cut_id
        {
            return Err(invalid("candidate attempt pin differs from witness"));
        }
        if self
            .branches
            .flowing_cancellation_for_attempt(attempt_op_id)?
            .is_some()
        {
            return Err(invalid("candidate attempt was cancelled"));
        }
        let Some(fence) = self.branches.flowing_source(&witness.source_branch_id)? else {
            return Err(invalid("source fence is missing"));
        };
        if fence.incarnation_id != witness.source_incarnation_id
            || !fence.admission_enabled
            || fence.held
            || fence.revision.is_some()
        {
            return Err(invalid("source eligibility or coordinator changed"));
        }
        let Some(trunk) = self.branches.get_branch(MAINLINE_BRANCH_ID)? else {
            return Err(invalid("trunk is missing"));
        };
        if trunk.status != BranchStatus::Active
            || trunk.head_cut_id != witness.expected_trunk_cut_id
        {
            return Err(invalid("trunk base changed"));
        }
        let Some(cut) = self.branches.get_cut(&witness.candidate_cut_id)? else {
            return Err(invalid("candidate cut is missing"));
        };
        if cut.branch_id != MAINLINE_BRANCH_ID
            || cut.manifest_hash != witness.candidate_manifest_hash
            || (witness.expected_trunk_cut_id.as_deref() != Some(witness.candidate_cut_id.as_str())
                && cut.parent_cut_id != witness.expected_trunk_cut_id)
        {
            return Err(invalid("candidate cut differs from retained witness"));
        }
        let lineage_fences = crate::branches::flowing_lineage::capture(&self.branches, &witness)?
            .ok_or_else(|| invalid("source lineage is unknown or ineligible"))?;
        let unit_holders = crate::branches::flowing_holders::capture(&self.branches, &witness)?
            .ok_or_else(|| invalid("unit holder is unknown or changed"))?;
        Ok(CapturedGateSubject {
            witness,
            pin,
            fence,
            lineage_fences,
            unit_holders,
        })
    }
}
