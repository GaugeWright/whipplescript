//! The Remote Execution API as the pinned Buck2 release (2026-09-15) vendors
//! it, generated once from the files under `proto/` by protox, prost and
//! tonic, and checked in; `tests/generated.rs` proves the checked-in code is
//! what those files generate. Regenerate after bumping the pinned release.

#[allow(clippy::all, clippy::pedantic, dead_code)]
pub mod build {
    pub mod bazel {
        pub mod remote {
            pub mod execution {
                pub mod v2 {
                    include!("proto/build.bazel.remote.execution.v2.rs");
                }
            }
        }
        pub mod semver {
            include!("proto/build.bazel.semver.rs");
        }
    }
}

#[allow(clippy::all, clippy::pedantic, dead_code)]
pub mod google {
    pub mod api {
        include!("proto/google.api.rs");
    }
    pub mod bytestream {
        include!("proto/google.bytestream.rs");
    }
    pub mod longrunning {
        include!("proto/google.longrunning.rs");
    }
    pub mod rpc {
        include!("proto/google.rpc.rs");
    }
}

pub use build::bazel::remote::execution::v2 as re;
