//! Content digests as the Remote Execution API names them: the SHA-256 of the
//! bytes, in hex, with their length. A workspace content id is not one of
//! these — the store truncates its hashes — which is what the cut encoding
//! of `cut.rs` is for.

use std::fmt;

use sha2::{Digest as _, Sha256};

#[cfg(feature = "endpoint")]
use crate::proto::re;

#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub struct Digest {
    pub hash: String,
    pub size_bytes: i64,
}

impl Digest {
    pub fn of(bytes: &[u8]) -> Self {
        let hash = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Self {
            hash,
            size_bytes: i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        }
    }

    /// The empty blob, which the protocol lets a client assume is present.
    pub fn empty() -> Self {
        Self::of(b"")
    }

    pub fn is_empty(&self) -> bool {
        self.size_bytes == 0
    }

    /// A digest a client named: well-formed only as 64 hex characters and a
    /// non-negative size.
    #[cfg(feature = "endpoint")]
    pub fn from_proto(digest: &re::Digest) -> Result<Self, String> {
        Self::named(&digest.hash, digest.size_bytes)
    }

    /// A digest named by its hash and size: well-formed only as 64 hex
    /// characters and a non-negative size.
    pub fn named(hash: &str, size_bytes: i64) -> Result<Self, String> {
        let lowered = hash.to_ascii_lowercase();
        if lowered.len() != 64 || !lowered.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("not a SHA-256 digest: {hash}"));
        }
        if size_bytes < 0 {
            return Err(format!("negative digest size: {size_bytes}"));
        }
        Ok(Self {
            hash: lowered,
            size_bytes,
        })
    }

    #[cfg(feature = "endpoint")]
    pub fn to_proto(&self) -> re::Digest {
        re::Digest {
            hash: self.hash.clone(),
            size_bytes: self.size_bytes,
        }
    }

    /// The `{hash}/{size}` form ByteStream resource names carry.
    pub fn from_resource(hash: &str, size: &str) -> Result<Self, String> {
        let size_bytes = size
            .parse::<i64>()
            .map_err(|_| format!("not a blob size: {size}"))?;
        Self::named(hash, size_bytes)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.hash, self.size_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_the_sha256_and_the_length_and_a_named_one_must_be_well_formed() {
        let digest = Digest::of(b"hello");
        assert_eq!(
            digest.hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(digest.size_bytes, 5);
        assert_eq!(digest.to_string(), format!("{}/5", digest.hash));
        assert!(Digest::empty().is_empty());
        #[cfg(feature = "endpoint")]
        assert_eq!(Digest::from_proto(&digest.to_proto()).unwrap(), digest);
        assert_eq!(
            Digest::named("abc", 1).unwrap_err(),
            "not a SHA-256 digest: abc"
        );
        assert_eq!(
            Digest::named(&digest.hash, -1).unwrap_err(),
            "negative digest size: -1"
        );
        assert_eq!(
            Digest::from_resource(&digest.hash, "five").unwrap_err(),
            "not a blob size: five"
        );
        assert_eq!(Digest::from_resource(&digest.hash, "5").unwrap(), digest);
    }
}
