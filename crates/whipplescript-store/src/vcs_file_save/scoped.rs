//! A distinct receipt and recovery door for admitted remembered inputs. These
//! descriptors do not authenticate a host or implement its IFC admission.
use super::*;
use crate::branches::resolution_origin::ResolutionObservation;
use crate::vcs::resolution_scope::ResolutionPayloadUse;

pub const SCOPED_SAVE_RECEIPT_SCHEMA: &str = "whipplescript.vcs-save-result.v2";

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScopedSaveReceipt {
    pub protocol: String,
    pub binding: SaveResultBinding,
    pub attempt: SaveAttempt,
    pub result: SaveResult,
    pub resolution_scope: ResolutionMemoryScope,
    pub observations: Vec<ResolutionLookup>,
}

impl ScopedSaveReceipt {
    /// Shape and internal consistency only; this cannot prove that a candidate
    /// ran or that the reader has authority over the named scope.
    pub fn validate(&self) -> io::Result<()> {
        let invalid = self.protocol != SCOPED_SAVE_RECEIPT_SCHEMA
            || matches!(self.result, SaveResult::Written { .. }) && !self.observations.is_empty()
            || self.observations.iter().any(|lookup| {
                !matches!(
                    (&lookup.observed, lookup.payload_use),
                    (
                        ResolutionObservation::Missing
                            | ResolutionObservation::OriginUnavailable { .. },
                        ResolutionPayloadUse::NotRead
                    ) | (
                        ResolutionObservation::Recorded { .. },
                        ResolutionPayloadUse::Applied
                            | ResolutionPayloadUse::Unavailable
                            | ResolutionPayloadUse::NonText
                    )
                )
            });
        if invalid {
            return Err(denied(
                "scoped save receipt has inconsistent memory evidence",
            ));
        }
        Ok(())
    }

    fn common(&self) -> SaveReceipt {
        SaveReceipt {
            protocol: self.protocol.clone(),
            branch_id: self.binding.branch_id.clone(),
            path: self.binding.path.clone(),
            base_cut_id: self.binding.base_cut_id.clone(),
            draft_hash: self.binding.draft_hash.clone(),
            executing_principal: self.binding.executing_principal.clone(),
            attempt: self.attempt.clone(),
            result: self.result.clone(),
        }
    }
}

pub(super) fn evidence(
    binding: &VersionedSaveBinding,
    scope: &ResolutionMemoryScope,
    attempt: SaveAttempt,
    result: SaveResult,
    observations: Vec<ResolutionLookup>,
) -> io::Result<FileWriteEvidence> {
    let receipt = ScopedSaveReceipt {
        protocol: SCOPED_SAVE_RECEIPT_SCHEMA.into(),
        binding: SaveResultBinding::from(binding),
        attempt,
        result,
        resolution_scope: scope.clone(),
        observations,
    };
    receipt.validate()?;
    Ok(FileWriteEvidence {
        schema_ref: SCOPED_SAVE_RECEIPT_SCHEMA.into(),
        label_ref: binding.evidence_label.clone(),
        content: serde_json::to_string(&receipt).map_err(io_error)?,
    })
}

impl<B: Branches, C: ContentBlobs> VersionedSaveFileStore<B, C> {
    /// The trusted host must verify this exact resource/compartment and apply
    /// runtime IFC before use. Constructing a namespace is not authorization.
    pub fn new_in_resolution_scope(
        workspace: WorkspaceVcs<B, C>,
        binding: VersionedSaveBinding,
        scope: ResolutionMemoryScope,
    ) -> io::Result<Self> {
        let mut files = Self::new(workspace, binding)?;
        files.resolution_scope = Some(scope);
        Ok(files)
    }

    pub fn recover_scoped_result(
        &self,
        attempt: &SaveAttempt,
    ) -> io::Result<Option<RecoveredSave<ScopedSaveReceipt>>> {
        let scope = self
            .resolution_scope
            .as_ref()
            .ok_or_else(|| denied("legacy saves have no scoped recovery binding"))?;
        read_committed_scoped_save(
            &self.workspace.borrow(),
            &SaveResultBinding::from(&self.binding),
            scope,
            attempt,
        )
    }
}

/// Read the original receipt without reading current resolution memory or
/// reconstructing observations. The host authorizes this exact binding first.
pub fn read_committed_scoped_save<B: Branches, C: ContentBlobs>(
    workspace: &WorkspaceVcs<B, C>,
    binding: &SaveResultBinding,
    scope: &ResolutionMemoryScope,
    attempt: &SaveAttempt,
) -> io::Result<Option<RecoveredSave<ScopedSaveReceipt>>> {
    recovery::read_committed_save_as(
        workspace,
        binding,
        attempt,
        SCOPED_SAVE_RECEIPT_SCHEMA,
        |json| {
            let receipt: ScopedSaveReceipt = serde_json::from_str(json).map_err(io_error)?;
            receipt.validate()?;
            if receipt.resolution_scope != *scope || receipt.binding != *binding {
                return Err(denied(
                    "scoped save result differs from its expected scope and binding",
                ));
            }
            Ok((receipt.common(), receipt))
        },
    )
}

pub mod conformance;
#[cfg(test)]
mod tests;
