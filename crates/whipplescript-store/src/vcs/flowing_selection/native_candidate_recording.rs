//! Recording follows the shared complete-prefix/content derivation.
use super::*;

pub(super) fn witness_for(
    revision: &NativeRevision,
    candidate: &NativeCandidate,
) -> FlowingCandidateWitness {
    FlowingCandidateWitness {
        contribution_id: candidate.contribution_id.clone(),
        revision_sequence: candidate.revision_sequence,
        source_branch_id: revision.source_branch_id.clone(),
        source_incarnation_id: revision.source_incarnation_id.clone(),
        source_cut_id: candidate.source_cut_id.clone(),
        source_manifest_hash: revision.source_manifest_hash.clone(),
        expected_trunk_cut_id: candidate.expected_trunk_cut_id.clone(),
        candidate_cut_id: candidate.candidate_cut_id.clone(),
        candidate_manifest_hash: candidate.candidate_manifest_hash.clone(),
        source_atoms_digest: candidate.source_atoms_digest.clone(),
        units: candidate.units.clone(),
    }
}

impl<B: Branches + FlowingSources + FlowingAdmissions, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// The sole recording half of the candidate constructors. The source
    /// derivation has already computed the exact content and accounting.
    pub(super) fn record_derived_native_candidate(
        &mut self,
        revision: &NativeRevision,
        mut candidate: NativeCandidate,
        actor: &str,
        recorded_at: &str,
    ) -> StoreResult<NativeCandidateOutcome> {
        use NativeCandidateOutcome as R;
        if candidate.expected_trunk_cut_id.as_deref() != Some(candidate.candidate_cut_id.as_str()) {
            let origin = format!("transport:{}", revision.source_branch_id);
            let matches = |cut: &CutRow| {
                cut.branch_id == crate::branches::MAINLINE_BRANCH_ID
                    && cut.parent_cut_id == candidate.expected_trunk_cut_id
                    && cut.manifest_hash == candidate.candidate_manifest_hash
                    && cut.change_id == candidate.candidate_cut_id
                    && cut.origin.as_deref() == Some(origin.as_str())
                    && cut.actor.as_deref() == Some(actor)
                    && cut.intent.as_deref() == Some(revision.contribution_id.as_str())
                    && cut.recorded_at == recorded_at
            };
            if self
                .branches
                .get_cut(&candidate.candidate_cut_id)?
                .is_none()
            {
                self.branches.record_cut(CutRecord {
                    cut_id: &candidate.candidate_cut_id,
                    change_id: &candidate.candidate_cut_id,
                    branch_id: crate::branches::MAINLINE_BRANCH_ID,
                    manifest_hash: &candidate.candidate_manifest_hash,
                    parent_cut_id: candidate.expected_trunk_cut_id.as_deref(),
                    origin: Some(&origin),
                    actor: Some(actor),
                    intent: Some(&revision.contribution_id),
                    recorded_at,
                })?;
            }
            if !self
                .branches
                .get_cut(&candidate.candidate_cut_id)?
                .as_ref()
                .is_some_and(matches)
            {
                return Ok(R::CandidateMismatch);
            }
        }
        candidate.candidate_witness_digest = self
            .branches
            .record_candidate_witness(&witness_for(revision, &candidate))?;
        Ok(R::Prepared(candidate))
    }
}
