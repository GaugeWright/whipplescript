//! The remote-execution endpoint of DR-0124 §14.3–§14.4: the Remote
//! Execution API's execution, action-cache, content-addressable-storage and
//! capabilities services, served to a Buck2 daemon over the compute plane's
//! seam, under the five rules at the store boundary and the versioned
//! encoding between a workspace cut and an input root.

//!
//! Without the default `endpoint` feature the crate is only the confined run
//! and the sidecar's wire contract — what the `whip executor` sidecar mounts
//! to run build actions for an endpoint elsewhere.

#[cfg(feature = "endpoint")]
pub mod cache;
#[cfg(feature = "endpoint")]
pub mod cut;
#[cfg(feature = "endpoint")]
pub mod db;
pub mod digest;
#[cfg(feature = "endpoint")]
pub mod endpoint;
#[cfg(feature = "endpoint")]
pub mod proto;
pub mod runner;
#[cfg(feature = "endpoint")]
pub mod server;
#[cfg(feature = "endpoint")]
pub mod services;
pub mod sidecar;
#[cfg(feature = "endpoint")]
pub mod store;
