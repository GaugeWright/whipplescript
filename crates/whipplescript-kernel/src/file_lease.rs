//! Bounded worker leases for synchronous file operations. A deadline describes
//! the worker attempt; it is neither target authority nor proof of cancellation.
use chrono::{DateTime, Datelike, Duration, SecondsFormat, Utc};
use whipplescript_store::{RuntimeStore, StoreError, StoreResult};

use crate::RuntimeKernel;

pub const DEFAULT_FILE_LEASE_SECONDS: u32 = 60;
pub const MAX_FILE_LEASE_SECONDS: u32 = 3600;

/// Trusted runtime configuration, reapplied by the host on restart. Changing it
/// never rewrites a recorded lease or authorizes an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileLeasePolicy {
    seconds: u32,
}
impl Default for FileLeasePolicy {
    fn default() -> Self {
        Self {
            seconds: DEFAULT_FILE_LEASE_SECONDS,
        }
    }
}
impl FileLeasePolicy {
    pub fn new(seconds: u32) -> StoreResult<Self> {
        if !(1..=MAX_FILE_LEASE_SECONDS).contains(&seconds) {
            return Err(StoreError::Conflict(
                "file lease lifetime must be between 1 and 3600 seconds".into(),
            ));
        }
        Ok(Self { seconds })
    }

    pub fn seconds(self) -> u32 {
        self.seconds
    }

    fn deadline(self, observed_at: &str) -> StoreResult<String> {
        let now = DateTime::parse_from_rfc3339(observed_at)
            .map_err(|_| StoreError::Conflict("invalid file lease clock observation".into()))?
            .with_timezone(&Utc);
        let deadline = now
            .checked_add_signed(Duration::seconds(i64::from(self.seconds)))
            .filter(|value| (1..=9999).contains(&value.year()))
            .ok_or_else(|| StoreError::Conflict("file lease deadline is out of range".into()))?;
        Ok(deadline.to_rfc3339_opts(SecondsFormat::Secs, true))
    }
}

impl<S: RuntimeStore> RuntimeKernel<S> {
    /// Configure future synchronous file attempts. Current execution authority
    /// and the recorded leases of existing attempts remain independent.
    pub fn set_file_lease_policy(&mut self, policy: FileLeasePolicy) {
        self.file_lease_policy = policy;
    }

    pub(crate) fn file_lease_deadline(&self) -> StoreResult<String> {
        self.file_lease_policy
            .deadline(&self.store.resolve_clock("now")?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_lease_policy_has_a_positive_bounded_lifetime_and_exact_deadline() {
        for seconds in [0, MAX_FILE_LEASE_SECONDS + 1, u32::MAX] {
            assert!(FileLeasePolicy::new(seconds).is_err());
        }
        for seconds in [1, DEFAULT_FILE_LEASE_SECONDS, MAX_FILE_LEASE_SECONDS] {
            let policy = FileLeasePolicy::new(seconds).expect("valid file lease policy");
            assert_eq!(policy.seconds(), seconds);
            let start = "2026-09-09T12:00:00Z";
            let deadline = DateTime::parse_from_rfc3339(
                &policy.deadline(start).expect("compute file lease deadline"),
            )
            .expect("parse deadline");
            assert_eq!(
                deadline - DateTime::parse_from_rfc3339(start).expect("parse observed clock"),
                Duration::seconds(i64::from(seconds)),
            );
        }
        assert_eq!(
            FileLeasePolicy::default()
                .deadline("2026-09-09T13:00:00+01:00")
                .expect("normalize clock offset"),
            "2026-09-09T12:01:00Z",
        );
    }

    #[test]
    fn file_lease_policy_refuses_invalid_clocks_and_unrepresentable_deadlines() {
        let policy = FileLeasePolicy::default();
        assert!(matches!(
            policy.deadline("not a clock").expect_err("invalid clock must refuse"),
            StoreError::Conflict(reason) if reason == "invalid file lease clock observation"
        ));
        assert!(matches!(
            policy.deadline("9999-12-31T23:59:59Z").expect_err("unrepresentable deadline must refuse"),
            StoreError::Conflict(reason) if reason == "file lease deadline is out of range"
        ));
    }
}
