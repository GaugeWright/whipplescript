//! Explicit namespaces for remembered inputs. Scope identity is a storage
//! descriptor, not a grant: the admitting host must verify its authority,
//! resource and policy compartment before recording or consuming knowledge.
mod observations;
pub(super) use observations::applied_ids;
pub use observations::{ResolutionLookup, ResolutionPayloadUse, ScopedSaveOutcome};

use super::{RegionResolution, SaveResultEvidenceBuilder, SaveWithBaseOutcome, WorkspaceVcs};
use crate::branches::{resolution_batch::ResolutionMemoryReceipt, Branches};
use crate::content::ContentBlobs;
use crate::{StoreError, StoreResult};

/// A stable resource and its admitted knowledge compartment. Actors and request
/// ids are intentionally absent: independently authorized people and agents can
/// reuse the same knowledge. A changed compartment gets a different namespace.
/// No constructor or serialization of this descriptor establishes admission.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "ResolutionScopeWire")]
pub struct ResolutionMemoryScope {
    authority: String,
    resource: String,
    compartment: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolutionScopeWire {
    authority: String,
    resource: String,
    compartment: String,
}
impl TryFrom<ResolutionScopeWire> for ResolutionMemoryScope {
    type Error = String;
    fn try_from(wire: ResolutionScopeWire) -> Result<Self, Self::Error> {
        Self::new(wire.authority, wire.resource, wire.compartment)
            .map_err(|error| format!("{error:?}"))
    }
}

impl ResolutionMemoryScope {
    pub fn new(authority: String, resource: String, compartment: String) -> StoreResult<Self> {
        let incomplete = [&authority, &resource, &compartment]
            .iter()
            .any(|value| value.trim().is_empty());
        if incomplete {
            return Err(StoreError::Conflict(
                "resolution scope requires authority, resource and compartment".into(),
            ));
        }
        Ok(Self {
            authority,
            resource,
            compartment,
        })
    }

    /// Identity of the immutable namespace descriptor, not a knowledge snapshot
    /// or an access grant. Shared by admission and the execution binding.
    pub fn version_ref(&self) -> String {
        let preimage = serde_json::json!([
            "whipplescript:resolution-scope-reference:v1",
            self.authority,
            self.resource,
            self.compartment,
        ]);
        format!(
            "resolution-scope:v1:{}",
            crate::items::sha256_hex(&preimage.to_string())
        )
    }

    fn key(&self, region_key: &str) -> StoreResult<String> {
        // JSON tuple framing keeps separators, Unicode and resource boundaries
        // unambiguous. The prefix cannot alias legacy rk/path memory keys.
        let preimage = serde_json::to_string(&(
            "whipplescript:resolution-scope:v1",
            &self.authority,
            &self.resource,
            &self.compartment,
            region_key,
        ))?;
        Ok(format!("rks1|{}", crate::items::sha256_hex(&preimage)))
    }
}

impl<B: Branches, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// Independently record knowledge in an already admitted compartment. No
    /// legacy fallback or cross-compartment first winner is consulted.
    pub fn record_region_resolutions_in_scope(
        &mut self,
        scope: &ResolutionMemoryScope,
        operation_id: &str,
        resolutions: &[RegionResolution],
        at: &str,
    ) -> StoreResult<ResolutionMemoryReceipt> {
        self.record_region_resolutions_in_namespace(operation_id, resolutions, at, Some(scope))
    }

    /// Save with only this compartment's region knowledge. Recording knowledge
    /// is a separate effect; this method cannot write resolution-memory rows.
    /// The host still owns admission, exact remembered-input evidence and IFC.
    #[allow(clippy::too_many_arguments)]
    pub fn save_with_base_in_resolution_scope(
        &mut self,
        scope: &ResolutionMemoryScope,
        branch_id: &str,
        path: &str,
        draft: &str,
        base_cut_id: &str,
        cut_id: &str,
        at: &str,
        builder: Option<&dyn SaveResultEvidenceBuilder>,
    ) -> StoreResult<ScopedSaveOutcome> {
        let mut observations = Vec::new();
        let outcome = self.save_with_base_using_memory(
            branch_id,
            path,
            draft,
            base_cut_id,
            cut_id,
            at,
            builder,
            Some(scope),
            &mut observations,
        )?;
        Ok(ScopedSaveOutcome {
            outcome,
            scope: scope.clone(),
            observations,
        })
    }

    pub(super) fn region_key_in_scope(
        scope: Option<&ResolutionMemoryScope>,
        base: &str,
        ours: &str,
        theirs: &str,
    ) -> StoreResult<String> {
        let legacy_key = Self::region_key(base, ours, theirs);
        match scope {
            Some(scope) => scope.key(&legacy_key),
            None => Ok(legacy_key),
        }
    }
}

/// The same storage boundary is exercised on native and DO implementations.
pub mod conformance;

#[cfg(all(test, feature = "native"))]
mod tests;
