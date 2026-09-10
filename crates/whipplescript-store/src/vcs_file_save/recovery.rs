//! Read the result committed at the original target cut. This never repeats a
//! save, resolves today's head, or authenticates a recovery caller. The host
//! must authorize the exact evidence compartment before entering this seam.
use super::*;
use crate::branches::write_evidence::WriteEvidenceRef;

/// References sufficient to recover a committed result after the draft or
/// base body is no longer retained. This is an expected binding, not a grant.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SaveResultBinding {
    pub branch_id: String,
    pub path: String,
    pub base_cut_id: String,
    pub draft_hash: String,
    pub executing_principal: String,
    pub evidence_label: String,
}
impl From<&VersionedSaveBinding> for SaveResultBinding {
    fn from(binding: &VersionedSaveBinding) -> Self {
        Self {
            branch_id: binding.branch_id.clone(),
            path: binding.path.clone(),
            base_cut_id: binding.base_cut_id.clone(),
            draft_hash: binding.draft_hash.clone(),
            executing_principal: binding.executing_principal.clone(),
            evidence_label: binding.evidence_label.clone(),
        }
    }
}

#[derive(Debug)]
pub struct RecoveredSave<T = SaveReceipt> {
    pub reference: WriteEvidenceRef,
    pub receipt: T,
    pub receipt_json: String,
    pub accepted_content: String,
}

impl<T> RecoveredSave<T> {
    pub(super) fn into_accepted(self) -> FileWriteAccepted {
        FileWriteAccepted {
            content: self.accepted_content,
            evidence: Some(FileWriteEvidence {
                schema_ref: self.reference.schema_ref,
                label_ref: self.reference.label_ref,
                content: self.receipt_json,
            }),
        }
    }
}

impl<B: Branches, C: ContentBlobs> VersionedSaveFileStore<B, C> {
    /// `None` means no cut is currently observed, not proof of non-application:
    /// an earlier authorized writer may still commit. A cut without its result
    /// reference is unavailable evidence, including the legacy adapter shape.
    pub fn recover_result(&self, attempt: &SaveAttempt) -> io::Result<Option<RecoveredSave>> {
        if self.resolution_scope.is_some() {
            return Err(denied("scoped saves require scoped recovery"));
        }
        read_committed_save(
            &self.workspace.borrow(),
            &SaveResultBinding::from(&self.binding),
            attempt,
        )
    }
}

/// Current authority and label access are the host's precondition. Reads only
/// the exact committed cut and retained result, with no writable adapter and
/// no draft/base body required. A missing cut never proves safe resubmission.
pub fn read_committed_save<B: Branches, C: ContentBlobs>(
    workspace: &WorkspaceVcs<B, C>,
    binding: &SaveResultBinding,
    attempt: &SaveAttempt,
) -> io::Result<Option<RecoveredSave>> {
    read_committed_save_as(workspace, binding, attempt, SAVE_RECEIPT_SCHEMA, |json| {
        let receipt: SaveReceipt = serde_json::from_str(json).map_err(io_error)?;
        Ok((receipt.clone(), receipt))
    })
}

pub(super) fn read_committed_save_as<B: Branches, C: ContentBlobs, T>(
    workspace: &WorkspaceVcs<B, C>,
    binding: &SaveResultBinding,
    attempt: &SaveAttempt,
    schema: &str,
    decode: impl FnOnce(&str) -> io::Result<(SaveReceipt, T)>,
) -> io::Result<Option<RecoveredSave<T>>> {
    let cut_id = save_cut_id(&attempt.instance_id, &attempt.effect_id);
    let cut = workspace.get_cut(&cut_id).map_err(io_error)?;
    let reference = workspace.write_evidence(&cut_id).map_err(io_error)?;
    let Some(cut) = cut else {
        if reference.is_some() {
            return Err(io_error("save result reference has no committed cut"));
        }
        return Ok(None);
    };
    let reference =
        reference.ok_or_else(|| io_error("committed save result reference is unavailable"))?;
    reference.validate().map_err(io_error)?;
    if reference.schema_ref != schema
        || reference.label_ref != binding.evidence_label
        || cut.branch_id != binding.branch_id
        || cut.actor.as_deref() != Some(&binding.executing_principal)
        || cut.origin.as_deref() != Some(format!("write:{}", binding.path).as_str())
        || cut
            .intent
            .as_deref()
            .map(serde_json::from_str::<SaveAttempt>)
            .transpose()
            .map_err(io_error)?
            .as_ref()
            != Some(attempt)
    {
        return Err(denied(
            "committed save evidence does not bind the requested scope and attempt",
        ));
    }
    let receipt_json = workspace
        .content_store()
        .get_text(&reference.content_hash)
        .map_err(io_error)?
        .text()
        .ok_or_else(|| io_error("committed save result content is unavailable or erased"))?;
    if crate::stable_hash_hex(&receipt_json) != reference.content_hash {
        return Err(io_error(
            "committed save result content does not match its hash",
        ));
    }
    let (receipt, typed_receipt) = decode(&receipt_json)?;
    let (result_cut, parent, operation, hash) = match &receipt.result {
        SaveResult::Written {
            cut_id,
            parent_cut_id,
            operation_id,
            accepted_content_hash,
        }
        | SaveResult::Merged {
            cut_id,
            parent_cut_id,
            operation_id,
            accepted_content_hash,
            ..
        } => (cut_id, parent_cut_id, operation_id, accepted_content_hash),
        SaveResult::Conflicted { .. } => {
            return Err(io_error("a conflict cannot be a committed save result"))
        }
    };
    if receipt.protocol != schema
        || receipt.branch_id != binding.branch_id
        || receipt.path != binding.path
        || receipt.base_cut_id != binding.base_cut_id
        || receipt.draft_hash != binding.draft_hash
        || receipt.executing_principal != binding.executing_principal
        || receipt.attempt != *attempt
        || result_cut != &cut_id
        || parent != &cut.parent_cut_id
        || operation != &format!("op-{cut_id}")
    {
        return Err(denied(
            "committed save result differs from the immutable binding",
        ));
    }
    let op = workspace
        .get_op(operation)
        .map_err(io_error)?
        .ok_or_else(|| io_error("committed save operation is unavailable"))?;
    if op.kind != "write"
        || op.origin != cut.origin
        || op.deltas.len() != 1
        || op.deltas[0].branch_id != cut.branch_id
        || op.deltas[0].after.head_cut_id.as_deref() != Some(cut_id.as_str())
        || op.deltas[0].after.head_manifest_hash.as_deref() != Some(cut.manifest_hash.as_str())
        || op.deltas[0]
            .before
            .as_ref()
            .map(|before| &before.head_cut_id)
            != Some(&cut.parent_cut_id)
    {
        return Err(io_error("committed save operation differs from its cut"));
    }
    let accepted_content = workspace
        .read_at_cut(&cut_id, &binding.path)
        .map_err(io_error)?
        .ok_or_else(|| io_error("committed save body is unavailable"))?;
    if crate::stable_hash_hex(&accepted_content) != *hash {
        return Err(io_error(
            "committed save body differs from its recorded result",
        ));
    }
    Ok(Some(RecoveredSave {
        reference,
        receipt: typed_receipt,
        receipt_json,
        accepted_content,
    }))
}

pub(super) struct SaveEvidenceBuilder<'a> {
    pub binding: &'a VersionedSaveBinding,
    pub attempt: &'a SaveAttempt,
    pub resolution_scope: Option<&'a ResolutionMemoryScope>,
}
impl crate::vcs::SaveResultEvidenceBuilder for SaveEvidenceBuilder<'_> {
    fn prepare(
        &self,
        plan: &crate::vcs::SaveCommitPlan<'_>,
    ) -> crate::StoreResult<FileWriteEvidence> {
        let result = match plan.pieces {
            Some(pieces) => SaveResult::Merged {
                cut_id: plan.cut_id.into(),
                parent_cut_id: plan.parent_cut_id.map(str::to_owned),
                operation_id: format!("op-{}", plan.cut_id),
                accepted_content_hash: crate::stable_hash_hex(plan.accepted),
                pieces: pieces.to_vec(),
            },
            None => SaveResult::Written {
                cut_id: plan.cut_id.into(),
                parent_cut_id: plan.parent_cut_id.map(str::to_owned),
                operation_id: format!("op-{}", plan.cut_id),
                accepted_content_hash: crate::stable_hash_hex(plan.accepted),
            },
        };
        if let Some(scope) = self.resolution_scope {
            if plan.resolution_scope != Some(scope) {
                return Err(crate::StoreError::Conflict(
                    "save candidate differs from bound resolution scope".into(),
                ));
            }
            return scoped::evidence(
                self.binding,
                scope,
                self.attempt.clone(),
                result,
                plan.resolution_observations.to_vec(),
            )
            .map_err(|error| crate::StoreError::Conflict(error.to_string()));
        }
        // The VCS supplies the actual candidate, including a raced merge's
        // accepted body. The immutable command binding remains explicit too.
        Ok(FileWriteEvidence {
            schema_ref: SAVE_RECEIPT_SCHEMA.into(),
            label_ref: self.binding.evidence_label.clone(),
            content: serde_json::to_string(&SaveReceipt {
                protocol: SAVE_RECEIPT_SCHEMA.into(),
                branch_id: plan.branch_id.into(),
                path: plan.path.into(),
                base_cut_id: plan.base_cut_id.into(),
                draft_hash: crate::stable_hash_hex(plan.draft),
                executing_principal: self.binding.executing_principal.clone(),
                attempt: self.attempt.clone(),
                result,
            })?,
        })
    }
}
