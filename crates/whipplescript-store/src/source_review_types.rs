//! Immutable native review coordinates, shared by source readers on every host.
//! These serializable references carry no authority or candidate proof.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeUnitRef {
    pub unit_id: String,
    pub source_cut_id: String,
    pub pin_id: String,
    pub basis_digest: String,
    pub principal: String,
    pub intent: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRevision {
    pub contribution_id: String,
    pub sequence: i64,
    pub upload_id: String,
    pub actor: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub source_cut_id: String,
    pub source_manifest_hash: String,
    pub units: Vec<NativeUnitRef>,
}

/// An installed owning reader, separate from methodology and Home coverage.
/// Implementations validate the native contribution's exact trunk target and
/// predecessor receipt contract before returning its original immutable upload.
/// Authentication, standing and Home namespace selection belong to the embedder.
pub trait NativeReviewReader {
    fn capture_native_revision(
        &self,
        contribution_id: &str,
        sequence: i64,
    ) -> Result<NativeRevision, NativeReviewReadError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeReviewReadError {
    /// Missing or inaccessible authority is a located planning gap.
    Unavailable(String),
    /// Present but invalid authority refuses the query.
    Invalid(String),
}
