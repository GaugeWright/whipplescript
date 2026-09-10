//! Current authority over the original knowledge scope precedes target reads.
//! The v2 reader verifies historical evidence without consulting today's memory.
use super::*;
use whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope;
use whipplescript_store::vcs_file_save::read_committed_scoped_save;

/// Trusted host configuration resolved from original admitted references,
/// independently of the receipt being investigated. This is not a grant.
pub struct ScopedVersionedSaveEvidenceSource<'a, B: Branches, C: ContentBlobs> {
    pub save: VersionedSaveEvidenceSource<'a, B, C>,
    pub resolution_scope: &'a ResolutionMemoryScope,
}

/// A mandatory additional authority boundary: implementing the legacy target
/// verifier alone cannot authorize access to scoped resolution evidence.
pub trait ScopedSaveReconciliationAuthority: SaveReconciliationAuthority {
    /// Verify this exact scope's authority, resource/path and compartment from
    /// the original admitted references, registered operation and original
    /// policy, and verify current receipt access and effective path grants.
    /// A receipt or today's broader grant must not define the expected scope.
    /// Runs after ordinary target authorization and before any target content
    /// read. No original execution permission substitutes for current access.
    fn authorize_resolution_scope(
        &self,
        command: &ReconcileEffectCommand,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        binding: &SaveResultBinding,
        scope: &ResolutionMemoryScope,
    ) -> Result<(), ProtocolError>;
}

pub(crate) fn prepare_scoped<B: Branches, C: ContentBlobs>(
    command: &ReconcileEffectCommand,
    source: &ScopedVersionedSaveEvidenceSource<'_, B, C>,
    prefix: &[OwnedChainEntry],
    authority: &dyn ScopedSaveReconciliationAuthority,
    authorization: &[u8],
) -> Result<VerifiedSaveEvidence, HostFacadeError> {
    prepare_target(
        command,
        &source.save,
        prefix,
        authority,
        authorization,
        |original, execution, attempt| {
            authority.authorize_resolution_scope(
                command,
                original,
                execution,
                source.save.binding,
                source.resolution_scope,
            )?;
            read_committed_scoped_save(
                source.save.workspace,
                source.save.binding,
                source.resolution_scope,
                attempt,
            )
            .map(|result| result.map(|saved| saved.receipt_json))
            .map_err(|_| {
                ProtocolError::Mismatch(
                    "scoped versioned save retained target evidence is unavailable",
                )
                .into()
            })
        },
    )
}
