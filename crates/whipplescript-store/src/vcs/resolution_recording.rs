//! Prepare resolution bodies and publish their independent branch receipt.
//! This is a target storage seam; admission and execution authority remain the
//! governed host binding's responsibility.
use super::{RegionResolution, WorkspaceVcs};
use crate::branches::resolution_batch::{
    ResolutionMemoryBatch, ResolutionMemoryEntry, ResolutionMemoryReceipt,
};
use crate::branches::Branches;
use crate::content::ContentBlobs;
use crate::StoreResult;

impl<B: Branches, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// Read the knowledge outcome without preparing content or saving a file.
    pub fn resolution_receipt(
        &self,
        operation_id: &str,
    ) -> StoreResult<Option<ResolutionMemoryReceipt>> {
        self.branches.resolution_batch(operation_id)
    }

    /// Record both side orientations as one independently recoverable effect.
    /// The handle must carry an attributed actor and causal intent. A later
    /// save uses its own operation identity and cannot undo this knowledge.
    pub fn record_region_resolutions_recorded(
        &mut self,
        operation_id: &str,
        resolutions: &[RegionResolution],
        at: &str,
    ) -> StoreResult<ResolutionMemoryReceipt> {
        self.record_region_resolutions_in_namespace(operation_id, resolutions, at, None)
    }

    pub(super) fn record_region_resolutions_in_namespace(
        &mut self,
        operation_id: &str,
        resolutions: &[RegionResolution],
        at: &str,
        scope: Option<&super::resolution_scope::ResolutionMemoryScope>,
    ) -> StoreResult<ResolutionMemoryReceipt> {
        let request = prepare_batch(
            scope,
            operation_id,
            resolutions,
            self.actor.as_deref().unwrap_or_default(),
            self.intent.as_deref().unwrap_or_default(),
            at,
        )?;
        // Recover before touching content: erased bodies stay erased and an
        // uncertain recording is never replaced by a fresh recording.
        if let Some(receipt) = self.resolution_receipt(operation_id)? {
            return receipt.check_retry(&request);
        }
        let mut prepared = Vec::with_capacity(resolutions.len());
        for resolution in resolutions {
            let identity = self.content.put_text(&resolution.resolution_text)?;
            crate::content::verify_body(
                &identity,
                resolution.resolution_text.as_bytes(),
                "resolution preparation",
            )?;
            prepared.push(identity);
        }
        // Native content collection/erasure is excluded across the separate
        // branch commit. Hosted storage provides the same publication seam.
        self.content.publish_retained(&prepared, || {
            self.branches.record_resolution_batch(&request)
        })
    }
}

/// One pure construction shared by bound host recording and the storage verb.
pub(crate) fn prepare_batch(
    scope: Option<&super::resolution_scope::ResolutionMemoryScope>,
    operation_id: &str,
    resolutions: &[RegionResolution],
    actor: &str,
    intent: &str,
    at: &str,
) -> StoreResult<ResolutionMemoryBatch> {
    let mut entries = Vec::with_capacity(resolutions.len().saturating_mul(2));
    for resolution in resolutions {
        let identity = crate::chunking::content_hash_hex(resolution.resolution_text.as_bytes());
        for (ours, theirs) in [
            (&resolution.ours_text, &resolution.theirs_text),
            (&resolution.theirs_text, &resolution.ours_text),
        ] {
            entries.push(ResolutionMemoryEntry {
                triple_key: super::resolution_scope::region_key_in_scope(
                    scope,
                    &resolution.base_text,
                    ours,
                    theirs,
                )?,
                resolution: identity.clone(),
            });
        }
    }
    let request = ResolutionMemoryBatch {
        operation_id: operation_id.into(),
        actor: actor.into(),
        intent: intent.into(),
        recorded_at: at.into(),
        entries,
    };
    request.validate()?;
    Ok(request)
}

/// Shared fixtures execute the same VCS operation on real native/DO stores.
pub mod conformance;

#[cfg(all(test, feature = "native"))]
mod tests;
