//! Immutable host-owned request custody, independent of effect terminal state.
use crate::{StoreError, StoreResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const EVENT_TYPE: &str = "exec.lifetime.tracked";
pub const PROTOCOL: &str = "whipplescript.exec.lifetime/v1";

/// Shared live/replay classification. An orphaned tracking row must not silently
/// downgrade execution to generic lease recovery when its journal key changes.
pub const LEASE_EXEC_STATE_SQL: &str = r#"
WITH tracking AS (
 SELECT 1 FROM events WHERE instance_id=?1 AND
 (idempotency_key=?3 OR (event_type='exec.lifetime.tracked' AND json_extract(payload_json,'$.run_id')=?2))
)
SELECT EXISTS(SELECT 1 FROM runs r JOIN effects e
 ON e.instance_id=r.instance_id AND e.effect_id=r.effect_id
 WHERE r.instance_id=?1 AND r.run_id=?2 AND (r.provider='exec' OR e.kind='exec.command'))
 OR EXISTS(SELECT 1 FROM tracking), EXISTS(SELECT 1 FROM tracking)
"#;

#[derive(Clone, Copy)]
pub struct Track<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
    pub input_json: &'a str,
    pub invocation_json: &'a str,
    pub executor_url: &'a str,
}

impl Track<'_> {
    pub fn key(&self) -> String {
        json!([EVENT_TYPE, self.run_id]).to_string()
    }

    pub fn payload(&self) -> StoreResult<String> {
        let invocation: Value = serde_json::from_str(self.invocation_json)?;
        if self.instance_id.is_empty()
            || self.effect_id.is_empty()
            || self.run_id.is_empty()
            || self.executor_url.is_empty()
            || invocation["protocol"] != "whipplescript.exec.invocation/v1"
            || invocation["invocation"]["instance_id"] != self.instance_id
            || invocation["invocation"]["effect_id"] != self.effect_id
            || invocation["run_id"] != self.run_id
        {
            return Err(StoreError::Conflict(
                "exec lifetime request identity differs".into(),
            ));
        }
        Ok(json!({"protocol":PROTOCOL, "instance_id":self.instance_id,
            "effect_id":self.effect_id, "run_id":self.run_id,
            "input":serde_json::from_str::<Value>(self.input_json)?,
            "invocation":invocation, "executor_url":self.executor_url})
        .to_string())
    }

    pub fn verify_binding(&self, input: &str, metadata: &str) -> StoreResult<()> {
        crate::exec_reconciliation::verify_retained_dispatch(
            self.input_json,
            self.invocation_json,
            input,
            metadata,
        )?;
        let metadata: Value = serde_json::from_str(metadata)?;
        let invocation: Value = serde_json::from_str(self.invocation_json)?;
        if metadata["executor_url"] != self.executor_url
            || metadata["executor_dispatch"]["request_sha256"]
                != crate::items::sha256_hex(
                    &json!([self.executor_url, invocation["dispatch"]]).to_string(),
                )
        {
            return Err(StoreError::Conflict(
                "exec lifetime target differs from retained dispatch".into(),
            ));
        }
        Ok(())
    }

    pub fn verify_replay(
        &self,
        kind: &str,
        source: &str,
        stored: &str,
        requested: &str,
    ) -> StoreResult<()> {
        if kind != EVENT_TYPE
            || source != "kernel"
            || serde_json::from_str::<Value>(stored)? != serde_json::from_str::<Value>(requested)?
        {
            return Err(StoreError::Conflict(
                "exec lifetime request cannot be replaced".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exec_lifetime_fence_requires_nonempty_identity() {
        let valid = Fence {
            instance_id: "instance",
            run_id: "run",
            reason: FenceReason::Deadline,
        };
        assert!(valid.validate().is_ok());
        assert!(Fence {
            instance_id: "",
            ..valid
        }
        .validate()
        .is_err());
        assert!(Fence {
            run_id: "",
            ..valid
        }
        .validate()
        .is_err());
    }
    #[test]
    fn exec_lifetime_payload_requires_bound_nonempty_identity() {
        let envelope = json!({"protocol":"whipplescript.exec.invocation/v1", "run_id":"run",
            "invocation":{"instance_id":"instance", "effect_id":"effect", "attempt_admission_event_id":null},
            "dispatch":{"protocol":"whip-executor/1","effect_id":"effect"}}).to_string();
        let original = Track {
            instance_id: "instance",
            effect_id: "effect",
            run_id: "run",
            input_json: "{}",
            invocation_json: &envelope,
            executor_url: "http://executor/exec",
        };
        assert!(original.payload().is_ok());
        for field in ["instance", "effect", "run", "url", "envelope"] {
            let mut request = original;
            match field {
                "instance" => request.instance_id = "",
                "effect" => request.effect_id = "",
                "run" => request.run_id = "",
                "url" => request.executor_url = "",
                _ => request.invocation_json = "{}",
            }
            assert!(request.payload().is_err(), "{field}");
        }
    }
}

pub const FENCE_EVENT: &str = "exec.fence.requested";
pub const FENCE_PROTOCOL: &str = "whipplescript.exec.fence-request/v1";

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    Deadline,
    Cancellation,
    Retry,
    Recovery,
}

#[derive(Clone, Copy)]
pub struct Fence<'a> {
    pub instance_id: &'a str,
    pub run_id: &'a str,
    pub reason: FenceReason,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceRecord {
    pub protocol: String,
    pub instance_id: String,
    pub effect_id: String,
    pub run_id: String,
    pub tracking_event_id: String,
    pub fence_id: String,
    pub reason: FenceReason,
}

impl Fence<'_> {
    pub fn key(&self) -> String {
        json!([FENCE_EVENT, self.run_id]).to_string()
    }
    pub fn tracking_key(&self) -> String {
        json!([EVENT_TYPE, self.run_id]).to_string()
    }
    pub fn validate(&self) -> StoreResult<()> {
        if self.instance_id.is_empty() || self.run_id.is_empty() {
            return Err(StoreError::Conflict(
                "exec fence request identity is invalid".into(),
            ));
        }
        Ok(())
    }
    pub fn payload(
        &self,
        tracking_event_id: &str,
        kind: &str,
        source: &str,
        tracked: &str,
    ) -> StoreResult<String> {
        self.validate()?;
        let tracked: Value = serde_json::from_str(tracked)?;
        if tracking_event_id.is_empty()
            || kind != EVENT_TYPE
            || source != "kernel"
            || tracked["protocol"] != PROTOCOL
            || tracked["instance_id"] != self.instance_id
            || tracked["run_id"] != self.run_id
        {
            return Err(StoreError::Conflict(
                "exec fence requires its original tracking record".into(),
            ));
        }
        let effect = tracked["effect_id"]
            .as_str()
            .ok_or_else(|| StoreError::Conflict("exec fence tracking effect is missing".into()))?;
        let url = tracked["executor_url"]
            .as_str()
            .ok_or_else(|| StoreError::Conflict("exec fence tracking target is missing".into()))?;
        Track {
            instance_id: self.instance_id,
            effect_id: effect,
            run_id: self.run_id,
            input_json: &tracked["input"].to_string(),
            invocation_json: &tracked["invocation"].to_string(),
            executor_url: url,
        }
        .payload()?;
        Ok(serde_json::to_string(&FenceRecord {
            protocol: FENCE_PROTOCOL.into(),
            instance_id: self.instance_id.into(),
            effect_id: effect.into(),
            run_id: self.run_id.into(),
            tracking_event_id: tracking_event_id.into(),
            fence_id: self.key(),
            reason: self.reason,
        })?)
    }
    pub fn verify_existing(
        &self,
        kind: &str,
        source: &str,
        stored: &str,
        requested: &str,
    ) -> StoreResult<()> {
        let stored: FenceRecord = serde_json::from_str(stored)?;
        let requested: FenceRecord = serde_json::from_str(requested)?;
        if kind != FENCE_EVENT
            || source != "kernel"
            || stored.protocol != FENCE_PROTOCOL
            || stored.instance_id != requested.instance_id
            || stored.effect_id != requested.effect_id
            || stored.run_id != requested.run_id
            || stored.tracking_event_id != requested.tracking_event_id
            || stored.fence_id != requested.fence_id
        {
            return Err(StoreError::Conflict(
                "exec fence intent cannot be replaced".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifetimeEvidence {
    Pending,
    NotAdmitted {
        fence_id: String,
    },
    Terminated {
        incarnation: String,
        fence_id: String,
        barrier_id: String,
    },
}

impl LifetimeEvidence {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::NotAdmitted { fence_id } if fence_id.is_empty() => {
                Err("provider non-admission fence identity is empty".into())
            }
            Self::Terminated {
                incarnation,
                fence_id,
                barrier_id,
            } if incarnation.is_empty() || fence_id.is_empty() || barrier_id.is_empty() => {
                Err("provider termination binding is empty".into())
            }
            _ => Ok(()),
        }
    }
}

pub const PROOF_EVENT: &str = "exec.fence.proved";
pub const PROOF_PROTOCOL: &str = "whipplescript.exec.fence-proof/v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Closure {
    pub placement: Value,
    pub lifetime: LifetimeEvidence,
}
impl Closure {
    pub fn verify(&self, tracked: &Value) -> StoreResult<()> {
        self.lifetime.validate().map_err(StoreError::Conflict)?;
        if self.lifetime == LifetimeEvidence::Pending {
            return Err(StoreError::Conflict(
                "pending lifetime is not closure".into(),
            ));
        }
        verify_controller_placement(&self.placement, tracked)
    }
}

pub(crate) fn verify_controller_placement(placement: &Value, tracked: &Value) -> StoreResult<()> {
    if placement.as_object().is_none_or(|value| value.len() != 5)
        || placement["protocol"] != "whipplescript.exec.placement/v2"
        || placement["envelope"] != tracked["invocation"]
        || placement["selected"] != tracked["invocation"]["invocation"]
        || placement["container_id"].as_str().is_none_or(str::is_empty)
        || placement["dispatch_id"].as_str().is_none_or(str::is_empty)
    {
        return Err(StoreError::Conflict(
            "exec closure differs from its original controller request".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]

pub struct Journal<'a> {
    pub event_id: &'a str,
    pub kind: &'a str,
    pub source: &'a str,
    pub payload: &'a str,
}
#[derive(Clone, Copy)]
pub struct Proof<'a> {
    pub instance_id: &'a str,
    pub run_id: &'a str,
    pub closure_json: &'a str,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRecord {
    pub protocol: String,
    pub instance_id: String,
    pub effect_id: String,
    pub run_id: String,
    pub tracking_event_id: String,
    pub fence_event_id: String,
    pub closure: Closure,
}
impl Proof<'_> {
    pub fn key(&self) -> String {
        json!([PROOF_EVENT, self.run_id]).to_string()
    }
    pub fn payload(&self, tracking: Journal<'_>, fence: Journal<'_>) -> StoreResult<String> {
        let fence_record: FenceRecord = serde_json::from_str(fence.payload)?;
        let request = Fence {
            instance_id: self.instance_id,
            run_id: self.run_id,
            reason: fence_record.reason,
        };
        let expected = request.payload(
            tracking.event_id,
            tracking.kind,
            tracking.source,
            tracking.payload,
        )?;
        request.verify_existing(fence.kind, fence.source, fence.payload, &expected)?;
        let closure: Closure = serde_json::from_str(self.closure_json)?;
        closure.verify(&serde_json::from_str(tracking.payload)?)?;
        if fence.event_id.is_empty() {
            return Err(StoreError::Conflict(
                "exec closure fence event identity is empty".into(),
            ));
        }
        Ok(serde_json::to_string(&ProofRecord {
            protocol: PROOF_PROTOCOL.into(),
            instance_id: self.instance_id.into(),
            effect_id: fence_record.effect_id,
            run_id: self.run_id.into(),
            tracking_event_id: tracking.event_id.into(),
            fence_event_id: fence.event_id.into(),
            closure,
        })?)
    }
    pub fn verify_replay(
        &self,
        kind: &str,
        source: &str,
        stored: &str,
        requested: &str,
    ) -> StoreResult<()> {
        if kind != PROOF_EVENT
            || source != "kernel"
            || serde_json::from_str::<Value>(stored)? != serde_json::from_str::<Value>(requested)?
        {
            return Err(StoreError::Conflict(
                "exec closure proof cannot be replaced".into(),
            ));
        }
        Ok(())
    }
}

/// Select only the cancellation request’s retained original run binding.
pub const CANCELLATION_FOR_RUN_SQL: &str = "SELECT 1 FROM effect_cancellation_requests r JOIN evidence e ON e.instance_id = r.instance_id AND e.subject_id = r.request_id JOIN json_each(e.metadata_json, '$.active_run_ids') j WHERE r.instance_id = ?1 AND r.effect_id = ?2 AND e.kind = 'effect.cancellation.requested' AND e.subject_type = 'effect_cancellation_request' AND j.value = ?3 LIMIT 1";

/// A workflow terminal does not close an external process tree. Recheck every
/// tracked run of the effect inside replacement-attempt admission's transaction.
pub fn verify_retry_closure(
    instance: &str,
    effect: &str,
    runs: &[(String, bool)],
    mut read: impl FnMut(&str) -> StoreResult<Option<crate::exec_outcome::OwnedJournal>>,
) -> StoreResult<()> {
    fn journal(row: &crate::exec_outcome::OwnedJournal) -> Journal<'_> {
        Journal {
            event_id: &row.0,
            kind: &row.1,
            source: &row.2,
            payload: &row.3,
        }
    }
    for (run, has_tracking) in runs {
        let Some(tracking) = read(&json!([EVENT_TYPE, run]).to_string())? else {
            if *has_tracking {
                return Err(StoreError::Conflict(
                    "executor retry tracking journal identity changed".into(),
                ));
            }
            continue;
        };
        let fence = read(&json!([FENCE_EVENT, run]).to_string())?.ok_or_else(|| {
            StoreError::Conflict("executor retry requires retained fence intent".into())
        })?;
        let held = read(&json!([PROOF_EVENT, run]).to_string())?
            .ok_or_else(|| StoreError::Conflict("executor retry awaits lifetime closure".into()))?;
        let record: ProofRecord = serde_json::from_str(&held.3)?;
        let closure = serde_json::to_string(&record.closure)?;
        let proof = Proof {
            instance_id: instance,
            run_id: run,
            closure_json: &closure,
        };
        let expected = proof.payload(journal(&tracking), journal(&fence))?;
        proof.verify_replay(&held.1, &held.2, &held.3, &expected)?;
        if held.0.is_empty() || record.effect_id != effect {
            return Err(StoreError::Conflict(
                "executor retry closure differs from its effect".into(),
            ));
        }
    }
    Ok(())
}

/// Inventory prevents a changed tracking idempotency key from making a tracked
/// run appear legacy and bypassing the closure check.
pub const RETRY_RUNS_SQL: &str = "SELECT r.run_id, EXISTS(SELECT 1 FROM events e WHERE e.instance_id=r.instance_id AND e.event_type='exec.lifetime.tracked' AND json_extract(e.payload_json,'$.run_id')=r.run_id) FROM runs r WHERE r.instance_id=?1 AND r.effect_id=?2";
