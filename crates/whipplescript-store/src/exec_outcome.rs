//! Immutable broker outcome custody, independent of workflow settlement.
use crate::{
    exec_lifetime::{self, Fence, FenceRecord, Journal, LifetimeEvidence, Proof, ProofRecord},
    StoreError, StoreResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const EVENT_TYPE: &str = "exec.outcome.observed";
pub const PROTOCOL: &str = "whipplescript.exec.outcome-observation/v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Completed { status: u16, body: Value },
    NotExecuted,
    Uncertain,
}
#[derive(Clone, Copy)]
pub struct Retention<'a> {
    pub instance_id: &'a str,
    pub run_id: &'a str,
    pub placement_json: &'a str,
    pub outcome_json: &'a str,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub protocol: String,
    pub instance_id: String,
    pub effect_id: String,
    pub run_id: String,
    pub tracking_event_id: String,
    pub fence_event_id: String,
    pub proof_event_id: Option<String>,
    pub placement: Value,
    pub outcome: Outcome,
}
impl Retention<'_> {
    pub fn key(&self) -> String {
        json!([EVENT_TYPE, self.run_id]).to_string()
    }
    pub fn proof_key(&self) -> String {
        json!([exec_lifetime::PROOF_EVENT, self.run_id]).to_string()
    }
    pub fn needs_proof(&self) -> StoreResult<bool> {
        Ok(!matches!(
            serde_json::from_str::<Outcome>(self.outcome_json)?,
            Outcome::Completed { .. }
        ))
    }
    pub fn payload(
        &self,
        tracking: Journal<'_>,
        fence: Journal<'_>,
        proof: Option<Journal<'_>>,
    ) -> StoreResult<String> {
        let intent: FenceRecord = serde_json::from_str(fence.payload)?;
        let request = Fence {
            instance_id: self.instance_id,
            run_id: self.run_id,
            reason: intent.reason,
        };
        let expected = request.payload(
            tracking.event_id,
            tracking.kind,
            tracking.source,
            tracking.payload,
        )?;
        request.verify_existing(fence.kind, fence.source, fence.payload, &expected)?;
        if fence.event_id.is_empty() {
            return Err(StoreError::Conflict(
                "exec outcome fence identity is empty".into(),
            ));
        }
        let placement: Value = serde_json::from_str(self.placement_json)?;
        exec_lifetime::verify_controller_placement(
            &placement,
            &serde_json::from_str(tracking.payload)?,
        )?;
        let outcome: Outcome = serde_json::from_str(self.outcome_json)?;
        let proof_event_id = if matches!(outcome, Outcome::Completed { .. }) {
            None
        } else {
            let journal = proof.ok_or_else(|| {
                StoreError::Conflict("exec non-result requires retained closure proof".into())
            })?;
            let record: ProofRecord = serde_json::from_str(journal.payload)?;
            let closure = serde_json::to_string(&record.closure)?;
            let selected = Proof {
                instance_id: self.instance_id,
                run_id: self.run_id,
                closure_json: &closure,
            };
            let expected = selected.payload(tracking, fence)?;
            selected.verify_replay(journal.kind, journal.source, journal.payload, &expected)?;
            if journal.event_id.is_empty()
                || record.closure.placement != placement
                || !matches!(
                    (&outcome, &record.closure.lifetime),
                    (Outcome::NotExecuted, LifetimeEvidence::NotAdmitted { .. })
                        | (Outcome::Uncertain, LifetimeEvidence::Terminated { .. })
                )
            {
                return Err(StoreError::Conflict(
                    "exec outcome contradicts its closure proof".into(),
                ));
            }
            Some(journal.event_id.to_owned())
        };
        Ok(serde_json::to_string(&Record {
            protocol: PROTOCOL.into(),
            instance_id: self.instance_id.into(),
            effect_id: intent.effect_id,
            run_id: self.run_id.into(),
            tracking_event_id: tracking.event_id.into(),
            fence_event_id: fence.event_id.into(),
            proof_event_id,
            placement,
            outcome,
        })?)
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
                "exec observed outcome cannot be replaced".into(),
            ));
        }
        Ok(())
    }
}

/// Journal rows read by their original idempotency keys inside a transaction.
pub type OwnedJournal = (String, String, String, String);
fn journal(row: &OwnedJournal) -> Journal<'_> {
    Journal {
        event_id: &row.0,
        kind: &row.1,
        source: &row.2,
        payload: &row.3,
    }
}

/// Recheck resolution evidence at terminal projection, preserving the distinct
/// uncertain run status. Ordinary legacy settlements retain their existing path.
pub fn projection_run_status(
    completion: crate::EffectCompletion<'_>,
    default_run_status: &str,
    has_cache: bool,
    mut read: impl FnMut(&str) -> StoreResult<Option<OwnedJournal>>,
) -> StoreResult<String> {
    let metadata: Value = serde_json::from_str(completion.metadata_json)?;
    let Some(reference) = metadata.get("executor_outcome_event_id") else {
        return Ok(default_run_status.into());
    };
    let reference = reference
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            StoreError::Conflict("exec settlement outcome reference is invalid".into())
        })?;
    let row = read(&json!([EVENT_TYPE, completion.run_id]).to_string())?.ok_or_else(|| {
        StoreError::Conflict("exec settlement observed outcome is missing".into())
    })?;
    let record: Record = serde_json::from_str(&row.3)?;
    let placement = record.placement.to_string();
    let outcome = serde_json::to_string(&record.outcome)?;
    let request = Retention {
        instance_id: completion.instance_id,
        run_id: completion.run_id,
        placement_json: &placement,
        outcome_json: &outcome,
    };
    let intent = Fence {
        instance_id: completion.instance_id,
        run_id: completion.run_id,
        reason: exec_lifetime::FenceReason::Recovery,
    };
    let tracking = read(&intent.tracking_key())?
        .ok_or_else(|| StoreError::Conflict("exec settlement tracking is missing".into()))?;
    let fence = read(&intent.key())?
        .ok_or_else(|| StoreError::Conflict("exec settlement fence is missing".into()))?;
    let proof = if request.needs_proof()? {
        read(&request.proof_key())?
    } else {
        None
    };
    let expected = request.payload(
        journal(&tracking),
        journal(&fence),
        proof.as_ref().map(journal),
    )?;
    request.verify_replay(&row.1, &row.2, &row.3, &expected)?;
    if row.0 != reference || record.effect_id != completion.effect_id {
        return Err(StoreError::Conflict(
            "exec settlement selects another observed outcome".into(),
        ));
    }
    let (effect_status, run_status) = match record.outcome {
        Outcome::Completed { status, body } => {
            if !matches!(completion.status, "completed" | "failed")
                || metadata["executor_response"] != json!({"status":status,"body":body})
            {
                return Err(StoreError::Conflict(
                    "exec settlement changed its observed response".into(),
                ));
            }
            (completion.status, completion.status)
        }
        other => {
            if has_cache || completion.exit_code.is_some() {
                return Err(StoreError::Conflict(
                    "exec non-result cannot supply cache or exit status".into(),
                ));
            }
            match other {
                Outcome::Uncertain => ("failed", "uncertain"),
                Outcome::NotExecuted => match serde_json::from_str::<FenceRecord>(&fence.3)?.reason
                {
                    exec_lifetime::FenceReason::Cancellation => ("cancelled", "cancelled"),
                    exec_lifetime::FenceReason::Deadline => ("timed_out", "timed_out"),
                    _ => ("failed", "failed"),
                },
                Outcome::Completed { .. } => unreachable!(),
            }
        }
    };
    if completion.status != effect_status {
        return Err(StoreError::Conflict(
            "exec settlement status contradicts its observed outcome".into(),
        ));
    }
    Ok(run_status.into())
}
