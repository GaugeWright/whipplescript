//! Buck2's test protocol at release 2026-09-15, generated once from the
//! vendored files under `proto/` by protox, prost and tonic, and checked in;
//! `tests/generated.rs` proves the checked-in code is what those files
//! generate. Regenerate after bumping the pinned Buck2 release.

#[allow(clippy::all, clippy::pedantic, dead_code)]
pub mod buck {
    pub mod data {
        include!("proto/buck.data.rs");
    }
    pub mod host_sharing {
        include!("proto/buck.host_sharing.rs");
    }
    pub mod test {
        include!("proto/buck.test.rs");
    }
}
