//! Exact recorded merge-keeping under original host access and the mainline gate.
use super::*;
use std::cell::RefCell;

/// Immutable candidate evidence; application still requires original access.
pub struct PreparedRecordedSettlement {
    inputs: RecordedMergeInputs,
    manifest: BTreeMap<String, String>,
    manifest_hash: String,
    change_id: String,
    retained: Vec<String>,
    cut_id: String,
    actor: String,
    intent: String,
    at: String,
}

/// Original native receipt, never a host authorization or a product receipt.
#[derive(Clone)]
pub struct AppliedRecordedSettlement {
    source: BranchRow,
    target: BranchRow,
    cut: CutRow,
    op: OpRow,
    inputs: Vec<CutRow>,
    retained: Vec<String>,
}
impl AppliedRecordedSettlement {
    pub fn cut(&self) -> &CutRow {
        &self.cut
    }
    pub fn operation(&self) -> &OpRow {
        &self.op
    }
}

pub enum RecordedSettlementOutcome {
    Applied(Box<AppliedRecordedSettlement>),
    GateRefused(GateRefusal),
    GateStale { changed: String },
}

impl NativeWorkspaceVcs {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_recorded_settlement(
        &self,
        branch_id: &str,
        original_head: &str,
        original_evidence: &[String],
        cut_id: &str,
        actor: &str,
        intent: &str,
        at: &str,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<PreparedRecordedSettlement> {
        check()?;
        if cut_id.is_empty() || actor.is_empty() || intent.is_empty() {
            return Err(StoreError::Conflict(
                "recorded settlement original meaning unavailable".into(),
            ));
        }
        let inputs =
            self.capture_recorded_merge_inputs(branch_id, original_head, original_evidence)?;
        self.require_legacy_source(branch_id, "recorded settlement")?;
        self.require_legacy_source(&inputs.target.branch_id, "recorded settlement")?;
        let bodies = RefCell::new(BTreeMap::new());
        let captured = inputs.clone();
        let manifest = self.publish_recorded_merge_inputs(inputs, Some(check), |_, vcs| {
            vcs.require_legacy_source(branch_id, "recorded settlement")?;
            vcs.require_legacy_source(&captured.target.branch_id, "recorded settlement")?;
            vcs.recorded_settlement_manifest(
                branch_id,
                captured.target.head_manifest_hash.as_deref(),
                &|body| {
                    let id = crate::stable_hash_bytes_hex(body.as_bytes());
                    bodies.borrow_mut().insert(id.clone(), body.to_owned());
                    Ok(id)
                },
            )
        })?;
        check()?;
        let prepared = crate::content::publication::PreparedBlobs::new(&self.content);
        // The content owner computes and verifies IDs. Retention below checks
        // every candidate reference, including each refiner's computed ID.
        for body in bodies.into_inner().into_values() {
            prepared.put_text(&body)?;
        }
        let change_id =
            StoreError::written_row(captured.cuts.first().cloned(), "captured native head")?
                .change_id;
        let manifest_hash = crate::manifest_tree::build(&prepared, &manifest)?;
        let mut retained = captured.retained.clone();
        retained.extend(prepared.ids());
        retained.extend(manifest.values().cloned());
        retained.push(manifest_hash.clone());
        check()?;
        Ok(PreparedRecordedSettlement {
            inputs: captured,
            manifest,
            manifest_hash,
            change_id,
            retained,
            cut_id: cut_id.into(),
            actor: actor.into(),
            intent: intent.into(),
            at: at.into(),
        })
    }

    fn recorded_settlement_manifest(
        &self,
        branch_id: &str,
        target_manifest: Option<&str>,
        prepare: &impl Fn(&str) -> StoreResult<String>,
    ) -> StoreResult<BTreeMap<String, String>> {
        match self.plan_merge_probe(branch_id, prepare)? {
            MergeProbePlan::Clean { manifest, .. } => Ok(manifest),
            MergeProbePlan::UpToDate => self.load_manifest(target_manifest),
            _ => Err(StoreError::Conflict(
                "recorded settlement requires a clean original candidate".into(),
            )),
        }
    }

    /// Recompute while both native writers are held. The original host check
    /// must remain the same check borrowed from its pending product writer.
    pub fn apply_prepared_recorded_settlement(
        &self,
        prepared: &PreparedRecordedSettlement,
        check: &mut dyn FnMut() -> StoreResult<()>,
        gate: &mut dyn MainlineGate,
    ) -> StoreResult<RecordedSettlementOutcome> {
        check()?;
        let source = &prepared.inputs.branch;
        let target = &prepared.inputs.target;
        let origin = format!("merge:{}", source.branch_id);
        let cut = CutRecord {
            cut_id: &prepared.cut_id,
            change_id: &prepared.change_id,
            branch_id: &target.branch_id,
            manifest_hash: &prepared.manifest_hash,
            parent_cut_id: target.head_cut_id.as_deref(),
            origin: Some(&origin),
            actor: Some(&prepared.actor),
            intent: Some(&prepared.intent),
            recorded_at: &prepared.at,
        };
        self.content.publish_retained(&prepared.retained, || {
            self.branches.commit_recorded_merge(
                source,
                target,
                &prepared.inputs.cuts,
                cut,
                check,
                |advance| {
                    self.require_legacy_source(&source.branch_id, "recorded settlement")?;
                    self.require_legacy_source(&target.branch_id, "recorded settlement")?;
                    let candidate = self.recorded_settlement_manifest(
                        &source.branch_id,
                        target.head_manifest_hash.as_deref(),
                        &|body| Ok(crate::stable_hash_bytes_hex(body.as_bytes())),
                    )?;
                    if candidate != prepared.manifest {
                        return Err(StoreError::Conflict(
                            "prepared recorded settlement candidate changed".into(),
                        ));
                    }
                    let capture = |id: &str| {
                        self.capture_norm_artifact(
                            id,
                            crate::norm_artifact::ArtifactLimits::default(),
                        )
                    };
                    if let GateVerdict::Refuse(refusal) =
                        gate.prepare(cut.parent_cut_id, cut.cut_id, &capture)?
                    {
                        return Ok(RecordedSettlementOutcome::GateRefused(refusal));
                    }
                    match gate.commit(advance)? {
                        GateCommit::Stale { changed } => {
                            if self
                                .branches
                                .get_op(&format!("op-{}", cut.cut_id))?
                                .is_some()
                            {
                                return Err(StoreError::Conflict(
                                    "recorded settlement gate reported stale after committing"
                                        .into(),
                                ));
                            }
                            Ok(RecordedSettlementOutcome::GateStale { changed })
                        }
                        GateCommit::Committed => self
                            .applied_recorded_settlement(prepared)
                            .map(|receipt| RecordedSettlementOutcome::Applied(Box::new(receipt))),
                    }
                },
            )
        })
    }

    fn applied_recorded_settlement(
        &self,
        prepared: &PreparedRecordedSettlement,
    ) -> StoreResult<AppliedRecordedSettlement> {
        let cut = self
            .branches
            .get_cut(&prepared.cut_id)?
            .ok_or_else(|| StoreError::Conflict("recorded settlement cut unavailable".into()))?;
        let op = self
            .branches
            .get_op(&format!("op-{}", prepared.cut_id))?
            .ok_or_else(|| {
                StoreError::Conflict("recorded settlement operation unavailable".into())
            })?;
        let source = self
            .branches
            .get_branch(&prepared.inputs.branch.branch_id)?
            .ok_or_else(|| StoreError::Conflict("recorded settlement source unavailable".into()))?;
        let target = self
            .branches
            .get_branch(&prepared.inputs.target.branch_id)?
            .ok_or_else(|| StoreError::Conflict("recorded settlement target unavailable".into()))?;
        let mut expected_source = prepared.inputs.branch.clone();
        let mut expected_target = prepared.inputs.target.clone();
        expected_source.head_cut_id = Some(prepared.cut_id.clone());
        expected_source.head_manifest_hash = Some(prepared.manifest_hash.clone());
        expected_source.branch_point_cut_id = expected_source.head_cut_id.clone();
        expected_source.branch_point_manifest_hash = expected_source.head_manifest_hash.clone();
        expected_source.updated_at = prepared.at.clone();
        expected_target.head_cut_id = Some(prepared.cut_id.clone());
        expected_target.head_manifest_hash = Some(prepared.manifest_hash.clone());
        expected_target.updated_at = prepared.at.clone();
        let origin = format!("merge:{}", prepared.inputs.branch.branch_id);
        let expected_cut = CutRecord {
            cut_id: &prepared.cut_id,
            change_id: &prepared.change_id,
            branch_id: &prepared.inputs.target.branch_id,
            manifest_hash: &prepared.manifest_hash,
            parent_cut_id: prepared.inputs.target.head_cut_id.as_deref(),
            origin: Some(&origin),
            actor: Some(&prepared.actor),
            intent: Some(&prepared.intent),
            recorded_at: &prepared.at,
        };
        let expected_deltas = vec![
            OpBranchDelta {
                branch_id: expected_target.branch_id.clone(),
                before: Some(OpBranchState::of(&prepared.inputs.target)),
                after: OpBranchState::of(&expected_target),
            },
            OpBranchDelta {
                branch_id: expected_source.branch_id.clone(),
                before: Some(OpBranchState::of(&prepared.inputs.branch)),
                after: OpBranchState::of(&expected_source),
            },
        ];
        if source != expected_source
            || target != expected_target
            || !cut.matches_record(expected_cut)
            || op.kind != "merge-keep"
            || op.origin.as_deref() != Some(&origin)
            || op.recorded_at != prepared.at
            || op.deltas != expected_deltas
        {
            return Err(StoreError::Conflict(
                "recorded settlement differs from its original operation".into(),
            ));
        }
        Ok(AppliedRecordedSettlement {
            source,
            target,
            cut,
            op,
            inputs: prepared.inputs.cuts.clone(),
            retained: prepared.retained.clone(),
        })
    }

    /// Recover only the exact original attributed operation after a native
    /// commit outlived its embedding attempt. This performs no head movement.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_recorded_settlement(
        &self,
        branch_id: &str,
        original_head: &str,
        original_evidence: &[String],
        cut_id: &str,
        actor: &str,
        intent: &str,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<AppliedRecordedSettlement> {
        check()?;
        let unavailable = || {
            StoreError::Conflict(
                "original recorded settlement recovery evidence unavailable".into(),
            )
        };
        let source = self
            .branches
            .get_branch(branch_id)?
            .ok_or_else(unavailable)?;
        let target = self
            .branches
            .get_branch(source.parent_branch_id.as_deref().ok_or_else(unavailable)?)?
            .ok_or_else(unavailable)?;
        let cut = self.branches.get_cut(cut_id)?.ok_or_else(unavailable)?;
        let op = self
            .branches
            .get_op(&format!("op-{cut_id}"))?
            .ok_or_else(unavailable)?;
        let origin = format!("merge:{branch_id}");
        if actor.is_empty()
            || intent.is_empty()
            || cut.actor.as_deref() != Some(actor)
            || cut.intent.as_deref() != Some(intent)
            || cut.branch_id != target.branch_id
            || cut.origin.as_deref() != Some(&origin)
            || op.kind != "merge-keep"
            || op.origin.as_deref() != Some(&origin)
            || op.recorded_at != cut.recorded_at
            || op.deltas.len() != 2
            || source.status != BranchStatus::Active
            || target.status != BranchStatus::Active
            || source.head_cut_id.as_deref() != Some(cut_id)
            || source.branch_point_cut_id.as_deref() != Some(cut_id)
            || source.head_manifest_hash.as_deref() != Some(&cut.manifest_hash)
            || source.branch_point_manifest_hash.as_deref() != Some(&cut.manifest_hash)
            || target.head_cut_id.as_deref() != Some(cut_id)
            || target.head_manifest_hash.as_deref() != Some(&cut.manifest_hash)
        {
            return Err(StoreError::Conflict(
                "original recorded settlement recovery meaning differs".into(),
            ));
        }
        let source_delta = &op.deltas[1];
        let target_delta = &op.deltas[0];
        let before_source = source_delta.before.as_ref().ok_or_else(unavailable)?;
        let before_target = target_delta.before.as_ref().ok_or_else(unavailable)?;
        if source_delta.branch_id != branch_id
            || target_delta.branch_id != target.branch_id
            || source_delta.after != OpBranchState::of(&source)
            || target_delta.after != OpBranchState::of(&target)
            || before_source.head_cut_id.as_deref() != Some(original_head)
            || before_target.head_cut_id != cut.parent_cut_id
            || before_source.status != BranchStatus::Active
            || before_target.status != BranchStatus::Active
        {
            return Err(StoreError::Conflict(
                "original recorded settlement recovery operation differs".into(),
            ));
        }
        let mut inputs = vec![];
        let mut retained = original_evidence.to_vec();
        for (id, hash) in [
            (
                &before_source.head_cut_id,
                &before_source.head_manifest_hash,
            ),
            (
                &before_source.branch_point_cut_id,
                &before_source.branch_point_manifest_hash,
            ),
            (
                &before_target.head_cut_id,
                &before_target.head_manifest_hash,
            ),
        ] {
            match (id, hash) {
                (Some(id), Some(hash)) => {
                    let input = self.branches.get_cut(id)?.ok_or_else(unavailable)?;
                    if input.manifest_hash != *hash
                        || (id == original_head && input.change_id != cut.change_id)
                    {
                        return Err(StoreError::Conflict(
                            "original recorded settlement recovery cut differs".into(),
                        ));
                    }
                    retained.push(hash.clone());
                    retained.extend(self.load_manifest(Some(hash))?.into_values());
                    inputs.push(input);
                }
                (None, None) => {}
                _ => {
                    return Err(StoreError::Conflict(
                        "original recorded settlement recovery coordinate is incomplete".into(),
                    ))
                }
            }
        }
        retained.push(cut.manifest_hash.clone());
        retained.extend(self.load_manifest(Some(&cut.manifest_hash))?.into_values());
        let receipt = AppliedRecordedSettlement {
            source,
            target,
            cut,
            op,
            inputs,
            retained,
        };
        self.publish_recorded_settlement(&receipt, |receipt, _| {
            self.require_legacy_source(&receipt.source.branch_id, "recorded settlement recovery")?;
            self.require_legacy_source(&receipt.target.branch_id, "recorded settlement recovery")?;
            check()?;
            Ok(receipt.clone())
        })
    }

    /// Keep the exact applied native evidence while the embedding consumes its
    /// same original writer. The embedding commit performs final authorization.
    pub fn publish_recorded_settlement<T>(
        &self,
        applied: &AppliedRecordedSettlement,
        publish: impl FnOnce(&AppliedRecordedSettlement, &Self) -> StoreResult<T>,
    ) -> StoreResult<T> {
        self.content.publish_retained(&applied.retained, || {
            self.branches.with_fenced_observation(|| {
                if self
                    .branches
                    .get_branch(&applied.source.branch_id)?
                    .as_ref()
                    != Some(&applied.source)
                    || self
                        .branches
                        .get_branch(&applied.target.branch_id)?
                        .as_ref()
                        != Some(&applied.target)
                    || self.branches.get_cut(&applied.cut.cut_id)?.as_ref() != Some(&applied.cut)
                    || self.branches.get_op(&applied.op.op_id)?.as_ref() != Some(&applied.op)
                    || applied.inputs.iter().any(|cut| {
                        self.branches.get_cut(&cut.cut_id).ok().flatten().as_ref() != Some(cut)
                    })
                {
                    return Err(StoreError::Conflict(
                        "recorded settlement evidence changed before publication".into(),
                    ));
                }
                publish(applied, self)
            })
        })
    }
}

#[cfg(test)]
mod tests;
