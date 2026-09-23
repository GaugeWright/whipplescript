//! The remote-execution endpoint of DR-0124 §14.3–§14.4: the Remote
//! Execution API's execution, action-cache, content-addressable-storage and
//! capabilities services, served to a Buck2 daemon over the compute plane's
//! seam, under the five rules at the store boundary and the versioned
//! encoding between a workspace cut and an input root.

pub mod cache;
pub mod cut;
pub mod digest;
pub mod endpoint;
pub mod proto;
pub mod runner;
pub mod server;
pub mod services;
pub mod store;
