//! Publish an observation of recorded native merge inputs under both owners.
//! Candidate merge bytes are ephemeral; no filesystem import or native write.
use super::*;
mod settlement;
pub use settlement::{
    AppliedRecordedSettlement, PreparedRecordedSettlement, RecordedSettlementOutcome,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedMergeOutcome {
    UpToDate,
    Clean { changed_paths: Vec<String> },
    Conflicted { conflicts: Vec<PathConflict> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedMergeReview {
    pub branch_id: String,
    pub head_cut_id: String,
    pub target_branch_id: String,
    pub target_cut_id: Option<String>,
    pub branch_point_cut_id: Option<String>,
    pub outcome: RecordedMergeOutcome,
    pub diff: Vec<crate::diff::DiffEntry>,
}

#[derive(Clone)]
struct RecordedMergeInputs {
    branch: BranchRow,
    target: BranchRow,
    cuts: Vec<CutRow>,
    retained: Vec<String>,
}

/// Recorded review evidence only, never a grant for publication or merging.
/// The embedding keeps its original product writer from preparation through
/// final publication, and checks that original authority at its own commit.
#[derive(Clone)]
pub struct PreparedRecordedMergeReview {
    inputs: RecordedMergeInputs,
    review: RecordedMergeReview,
}

impl PreparedRecordedMergeReview {
    pub fn review(&self) -> &RecordedMergeReview {
        &self.review
    }
}

impl NativeWorkspaceVcs {
    /// Authorize before opening. Only existing current-generation authorities
    /// are accepted; no creation, WAL conversion or migration occurs here.
    pub fn open_for_recorded_review(
        branches_path: impl AsRef<Path>,
        content_path: impl AsRef<Path>,
    ) -> StoreResult<Self> {
        Ok(Self::from_parts(
            BranchStore::open_for_fenced_observation(branches_path)?,
            ContentStore::open_for_retained_publication(content_path)?,
        ))
    }

    /// Review exactly `expected_head`, retaining complete compared inputs and
    /// caller-selected original evidence through one embedding publication.
    /// `check` is the original host authority; it must not reacquire either
    /// native store or perform external work. The publication callback writes
    /// embedding references only, and must enforce its own final authorization
    /// at commit. No native mutation or payload preparation belongs in it.
    pub fn publish_recorded_merge_review<T>(
        &self,
        branch_id: &str,
        expected_head: &str,
        original_evidence: &[String],
        check: &mut dyn FnMut() -> StoreResult<()>,
        publish: impl FnOnce(&RecordedMergeReview, &Self) -> StoreResult<T>,
    ) -> StoreResult<T> {
        check()?;
        let inputs =
            self.capture_recorded_merge_inputs(branch_id, expected_head, original_evidence)?;
        self.publish_recorded_merge_inputs(inputs, Some(check), publish)
    }

    /// Prepare under the borrowed original embedding check while its actual
    /// product writer is held. The returned evidence carries no authority.
    /// Use the same original product writer for the final protected publication.
    pub fn prepare_recorded_merge_review(
        &self,
        branch_id: &str,
        expected_head: &str,
        original_evidence: &[String],
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<PreparedRecordedMergeReview> {
        check()?;
        let inputs =
            self.capture_recorded_merge_inputs(branch_id, expected_head, original_evidence)?;
        let prepared = inputs.clone();
        let review = self
            .publish_recorded_merge_inputs(inputs, Some(check), |review, _| Ok(review.clone()))?;
        Ok(PreparedRecordedMergeReview {
            inputs: prepared,
            review,
        })
    }

    /// Revalidate the exact prepared review through both native owners while
    /// the embedding consumes its SAME original product writer at commit.
    /// That commit must recheck the original authority and bind its receipt.
    /// No standalone authorization check or renewed identity is substituted.
    pub fn publish_prepared_recorded_merge_review<T>(
        &self,
        prepared: &PreparedRecordedMergeReview,
        publish: impl FnOnce(&RecordedMergeReview, &Self) -> StoreResult<T>,
    ) -> StoreResult<T> {
        self.publish_recorded_merge_inputs(prepared.inputs.clone(), None, |review, vcs| {
            if review != &prepared.review {
                return Err(StoreError::Conflict(
                    "prepared recorded merge review changed before publication".into(),
                ));
            }
            publish(review, vcs)
        })
    }

    fn capture_recorded_merge_inputs(
        &self,
        branch_id: &str,
        expected_head: &str,
        original_evidence: &[String],
    ) -> StoreResult<RecordedMergeInputs> {
        let branch = self
            .branches
            .get_branch(branch_id)?
            .ok_or_else(|| StoreError::Conflict("recorded review branch unavailable".into()))?;
        let target = branch
            .parent_branch_id
            .as_deref()
            .map(|id| self.branches.get_branch(id))
            .transpose()?
            .flatten()
            .ok_or_else(|| StoreError::Conflict("recorded review parent unavailable".into()))?;
        if branch.status != BranchStatus::Active
            || target.status != BranchStatus::Active
            || branch.head_cut_id.as_deref() != Some(expected_head)
        {
            return Err(StoreError::Conflict(
                "recorded review requires the active original head and parent".into(),
            ));
        }
        let coordinates = [
            (
                branch.head_cut_id.as_deref(),
                branch.head_manifest_hash.as_deref(),
            ),
            (
                branch.branch_point_cut_id.as_deref(),
                branch.branch_point_manifest_hash.as_deref(),
            ),
            (
                target.head_cut_id.as_deref(),
                target.head_manifest_hash.as_deref(),
            ),
        ];
        let mut cuts = Vec::new();
        let mut retained = original_evidence.to_vec();
        for (cut_id, manifest_hash) in coordinates {
            match (cut_id, manifest_hash) {
                (Some(id), Some(hash)) => {
                    let cut = self.branches.get_cut(id)?.ok_or_else(|| {
                        StoreError::Conflict("recorded review cut unavailable".into())
                    })?;
                    if cut.manifest_hash != hash {
                        return Err(StoreError::Conflict(
                            "recorded review head differs from its cut".into(),
                        ));
                    }
                    retained.push(hash.to_owned());
                    retained.extend(self.load_manifest(Some(hash))?.into_values());
                    cuts.push(cut);
                }
                (None, None) => {}
                _ => {
                    return Err(StoreError::Conflict(
                        "recorded review coordinate is incomplete".into(),
                    ))
                }
            }
        }
        Ok(RecordedMergeInputs {
            branch,
            target,
            cuts,
            retained,
        })
    }

    fn publish_recorded_merge_inputs<T>(
        &self,
        inputs: RecordedMergeInputs,
        mut check: Option<&mut dyn FnMut() -> StoreResult<()>>,
        publish: impl FnOnce(&RecordedMergeReview, &Self) -> StoreResult<T>,
    ) -> StoreResult<T> {
        let RecordedMergeInputs {
            branch,
            target,
            cuts,
            retained,
        } = inputs;
        let branch_id = branch.branch_id.as_str();
        // All native publication paths obtain the content exclusion before
        // the branch writer. Keep that order even for this observation.
        self.content.publish_retained(&retained, || {
            self.branches.with_fenced_observation(|| {
                if self.branches.get_branch(branch_id)?.as_ref() != Some(&branch)
                    || self.branches.get_branch(&target.branch_id)?.as_ref() != Some(&target)
                    || cuts
                        .iter()
                        .map(|cut| {
                            self.branches
                                .get_cut(&cut.cut_id)
                                .map(|current| current.as_ref() == Some(cut))
                        })
                        .collect::<StoreResult<Vec<_>>>()?
                        .iter()
                        .any(|same| !same)
                {
                    return Err(StoreError::Conflict(
                        "recorded review inputs changed before publication".into(),
                    ));
                }
                if let Some(check) = check.as_mut() {
                    check()?;
                }
                let outcome = match self.plan_merge_probe(branch_id, &|body| {
                    Ok(crate::stable_hash_bytes_hex(body.as_bytes()))
                })? {
                    MergeProbePlan::UpToDate => RecordedMergeOutcome::UpToDate,
                    MergeProbePlan::Clean { changed_paths, .. } => {
                        RecordedMergeOutcome::Clean { changed_paths }
                    }
                    MergeProbePlan::Conflicted { conflicts } => {
                        RecordedMergeOutcome::Conflicted { conflicts }
                    }
                    _ => unreachable!(
                        "validated active topology remains under the branch writer fence"
                    ),
                };
                let review = RecordedMergeReview {
                    branch_id: branch_id.to_owned(),
                    head_cut_id: branch
                        .head_cut_id
                        .clone()
                        .expect("capture requires original head"),
                    target_branch_id: target.branch_id.clone(),
                    target_cut_id: target.head_cut_id.clone(),
                    branch_point_cut_id: branch.branch_point_cut_id.clone(),
                    outcome,
                    diff: crate::diff::diff_manifests(
                        &self.load_manifest(target.head_manifest_hash.as_deref())?,
                        &self.load_manifest(branch.head_manifest_hash.as_deref())?,
                        &self.content,
                        3,
                    )?,
                };
                if let Some(check) = check.as_mut() {
                    check()?;
                }
                publish(&review, self)
            })
        })
    }
}

#[cfg(test)]
mod tests;
