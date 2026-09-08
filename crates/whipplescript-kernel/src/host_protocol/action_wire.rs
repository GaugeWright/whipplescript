//! Strict decoding for shared types inside the versioned action extension.
//! Remote derives construct the existing types, preserving their serialization
//! and leaving the older turn protocol's decoding contract intact.
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
#[serde(remote = "super::PolicyEpochRef", deny_unknown_fields)]
pub(super) struct Policy {
    epoch: u64,
    envelope_hash: String,
    signer: String,
    #[serde(default)]
    key_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(remote = "super::ResourceRef", deny_unknown_fields)]
pub(super) struct Resource {
    handle: String,
    kind: String,
    #[serde(default)]
    selector: Option<String>,
    #[serde(default)]
    writable: Option<bool>,
}

#[derive(Deserialize)]
#[serde(remote = "super::PinnedPosition", deny_unknown_fields)]
pub(super) struct Position {
    instance_ref: String,
    sequence: u64,
    head_digest: String,
}

pub(super) fn optional_position<'de, D>(
    deserializer: D,
) -> Result<Option<super::PinnedPosition>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct StrictPosition(
        #[serde(deserialize_with = "Position::deserialize")] super::PinnedPosition,
    );
    Option::<StrictPosition>::deserialize(deserializer).map(|position| position.map(|p| p.0))
}

#[cfg(test)]
#[path = "action_wire_tests.rs"]
mod tests;
