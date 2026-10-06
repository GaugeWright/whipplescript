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
