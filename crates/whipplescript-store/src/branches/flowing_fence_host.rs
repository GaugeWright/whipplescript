//! Body-free projection of one durable flowing source-fence transition.
//!
//! A receipt is historical evidence from the owning ref store. It does not
//! establish the source's current Hold state or the policy of every source in
//! a unit's transitive lineage.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::flowing_fence::{
    missing_transition_field, FlowingFence, FlowingFenceAction, FlowingFenceReceipt,
    FlowingSourceKind,
};
use crate::{StoreError, StoreResult};

pub const FLOWING_FENCE_EVIDENCE_V1: &str = "whipplescript.flowing_fence_evidence.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FlowingHostFenceActionV1 {
    Hold,
    ReleaseHold,
    BeginRevision {
        before_cut_id: Option<String>,
        after_cut_id: String,
    },
    FinishRevision {
        begin_op_id: String,
    },
    AbortRevision {
        begin_op_id: String,
    },
    Takeover {
        new_owner: String,
    },
    InvalidateEligibility {
        reason_digest: String,
    },
    DisableAdmission,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostRevisionV1 {
    pub begin_op_id: String,
    pub before_cut_id: Option<String>,
    pub after_cut_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostFenceEvidenceV1 {
    pub schema: String,
    pub operation_id: String,
    pub source_branch_id: String,
    pub incarnation_id: String,
    pub source_kind: FlowingSourceKind,
    pub action: FlowingHostFenceActionV1,
    pub expected_eligibility_epoch: i64,
    pub resulting_eligibility_epoch: i64,
    pub expected_owner_epoch: i64,
    pub resulting_owner_epoch: i64,
    pub resulting_owner: String,
    pub resulting_held: bool,
    pub resulting_admission_enabled: bool,
    pub resulting_revision: Option<FlowingHostRevisionV1>,
    pub request_digest: String,
    pub state_digest: String,
}

pub trait FlowingFenceEvidenceReader {
    fn read_fence_receipt(&self, operation_id: &str) -> StoreResult<Option<FlowingFenceReceipt>>;
}

impl<T: FlowingFence> FlowingFenceEvidenceReader for T {
    fn read_fence_receipt(&self, operation_id: &str) -> StoreResult<Option<FlowingFenceReceipt>> {
        self.flowing_fence_receipt(operation_id)
    }
}

fn invalid(reason: &str) -> StoreError {
    StoreError::Conflict(format!("flowing fence host evidence refuses: {reason}"))
}

fn digest(domain: &str, value: &impl Serialize) -> StoreResult<String> {
    let bytes = serde_json::to_vec(&(domain, value))?;
    Ok(format!(
        "sha256:{}",
        crate::chunking::content_hash_hex(&bytes)
    ))
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 32
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn next(epoch: i64) -> StoreResult<i64> {
    epoch
        .checked_add(1)
        .ok_or_else(|| invalid("epoch overflow"))
}

fn same_or_next(expected: i64, actual: i64) -> StoreResult<bool> {
    Ok(actual == expected || actual == next(expected)?)
}

pub fn read_fence_evidence(
    fences: &impl FlowingFenceEvidenceReader,
    operation_id: &str,
) -> StoreResult<Option<FlowingHostFenceEvidenceV1>> {
    if operation_id.trim().is_empty() {
        return Err(invalid("operation identity is empty"));
    }
    let Some(receipt) = fences.read_fence_receipt(operation_id)? else {
        return Ok(None);
    };
    if receipt.request.op_id != operation_id {
        return Err(invalid("fence receipt differs from requested operation"));
    }
    Ok(Some(FlowingHostFenceEvidenceV1::from_retained(&receipt)?))
}

impl FlowingHostFenceEvidenceV1 {
    fn from_retained(receipt: &FlowingFenceReceipt) -> StoreResult<Self> {
        let request = &receipt.request;
        let state = &receipt.state;
        if missing_transition_field(request).is_some()
            || request.source_branch_id != state.source_branch_id
            || request.incarnation_id != state.incarnation_id
            || state.owner.trim().is_empty()
            || request.expected_eligibility_epoch < 0
            || request.expected_owner_epoch < 0
        {
            return Err(invalid("fence receipt identity or epoch differs"));
        }
        let eligibility = request.expected_eligibility_epoch;
        let owner = request.expected_owner_epoch;
        let action = match &request.action {
            FlowingFenceAction::Hold
                if state.held
                    && state.owner_epoch == owner
                    && same_or_next(eligibility, state.eligibility_epoch)? =>
            {
                FlowingHostFenceActionV1::Hold
            }
            FlowingFenceAction::ReleaseHold
                if !state.held
                    && state.owner_epoch == owner
                    && same_or_next(eligibility, state.eligibility_epoch)? =>
            {
                FlowingHostFenceActionV1::ReleaseHold
            }
            FlowingFenceAction::BeginRevision {
                before_cut_id,
                after_cut_id,
            } if state.eligibility_epoch == next(eligibility)?
                && state.owner_epoch == owner
                && state.revision.as_ref().is_some_and(|revision| {
                    revision.begin_op_id == request.op_id
                        && revision.before_cut_id == *before_cut_id
                        && revision.after_cut_id == *after_cut_id
                }) =>
            {
                FlowingHostFenceActionV1::BeginRevision {
                    before_cut_id: before_cut_id.clone(),
                    after_cut_id: after_cut_id.clone(),
                }
            }
            FlowingFenceAction::FinishRevision { begin_op_id }
                if state.revision.is_none()
                    && state.eligibility_epoch == next(eligibility)?
                    && state.owner_epoch == owner =>
            {
                FlowingHostFenceActionV1::FinishRevision {
                    begin_op_id: begin_op_id.clone(),
                }
            }
            FlowingFenceAction::AbortRevision { begin_op_id }
                if state.revision.is_none()
                    && state.eligibility_epoch == next(eligibility)?
                    && state.owner_epoch == owner =>
            {
                FlowingHostFenceActionV1::AbortRevision {
                    begin_op_id: begin_op_id.clone(),
                }
            }
            FlowingFenceAction::Takeover { new_owner }
                if state.owner == *new_owner
                    && state.owner_epoch == next(owner)?
                    && state.eligibility_epoch == next(eligibility)? =>
            {
                FlowingHostFenceActionV1::Takeover {
                    new_owner: new_owner.clone(),
                }
            }
            FlowingFenceAction::InvalidateEligibility { reason }
                if !reason.trim().is_empty()
                    && state.owner_epoch == owner
                    && state.eligibility_epoch == next(eligibility)? =>
            {
                FlowingHostFenceActionV1::InvalidateEligibility {
                    reason_digest: digest("flowing-host-fence-reason-v1", reason)?,
                }
            }
            FlowingFenceAction::DisableAdmission
                if !state.admission_enabled
                    && state.revision.is_none()
                    && state.owner_epoch == owner
                    && same_or_next(eligibility, state.eligibility_epoch)? =>
            {
                FlowingHostFenceActionV1::DisableAdmission
            }
            _ => return Err(invalid("fence transition and retained state differ")),
        };
        let evidence = Self {
            schema: FLOWING_FENCE_EVIDENCE_V1.into(),
            operation_id: request.op_id.clone(),
            source_branch_id: request.source_branch_id.clone(),
            incarnation_id: request.incarnation_id.clone(),
            source_kind: state.kind.clone(),
            action,
            expected_eligibility_epoch: eligibility,
            resulting_eligibility_epoch: state.eligibility_epoch,
            expected_owner_epoch: owner,
            resulting_owner_epoch: state.owner_epoch,
            resulting_owner: state.owner.clone(),
            resulting_held: state.held,
            resulting_admission_enabled: state.admission_enabled,
            resulting_revision: state
                .revision
                .as_ref()
                .map(|revision| FlowingHostRevisionV1 {
                    begin_op_id: revision.begin_op_id.clone(),
                    before_cut_id: revision.before_cut_id.clone(),
                    after_cut_id: revision.after_cut_id.clone(),
                }),
            request_digest: digest("flowing-host-fence-request-v1", request)?,
            state_digest: digest("flowing-host-fence-state-v1", state)?,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Strict decoding checks shape only; it cannot authenticate ref history.
    pub fn decode(bytes: &[u8]) -> StoreResult<Self> {
        let value: Value = serde_json::from_slice(bytes)?;
        if !known_action_fields(&value) {
            return Err(invalid("fence action has unknown or missing fields"));
        }
        let evidence: Self = serde_json::from_value(value)?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> StoreResult<()> {
        if self.schema != FLOWING_FENCE_EVIDENCE_V1 {
            return Err(invalid("wrong fence evidence schema"));
        }
        for value in [
            &self.operation_id,
            &self.source_branch_id,
            &self.incarnation_id,
            &self.resulting_owner,
        ] {
            if value.trim().is_empty() {
                return Err(invalid("required fence evidence identity is empty"));
            }
        }
        if !valid_digest(&self.request_digest) || !valid_digest(&self.state_digest) {
            return Err(invalid("fence evidence digest is invalid"));
        }
        if self.expected_eligibility_epoch < 0
            || self.resulting_eligibility_epoch < self.expected_eligibility_epoch
            || self.expected_owner_epoch < 0
            || self.resulting_owner_epoch < self.expected_owner_epoch
        {
            return Err(invalid("fence evidence epoch is invalid"));
        }
        if let Some(revision) = &self.resulting_revision {
            if revision.begin_op_id.trim().is_empty() || revision.after_cut_id.trim().is_empty() {
                return Err(invalid("fence revision identity is empty"));
            }
        }
        let eligibility = self.expected_eligibility_epoch;
        let owner = self.expected_owner_epoch;
        let valid = match &self.action {
            FlowingHostFenceActionV1::Hold => {
                self.resulting_held
                    && self.resulting_owner_epoch == owner
                    && same_or_next(eligibility, self.resulting_eligibility_epoch)?
            }
            FlowingHostFenceActionV1::ReleaseHold => {
                !self.resulting_held
                    && self.resulting_owner_epoch == owner
                    && same_or_next(eligibility, self.resulting_eligibility_epoch)?
            }
            FlowingHostFenceActionV1::BeginRevision {
                before_cut_id,
                after_cut_id,
            } => {
                !after_cut_id.trim().is_empty()
                    && self.resulting_owner_epoch == owner
                    && self.resulting_eligibility_epoch == next(eligibility)?
                    && self.resulting_revision.as_ref().is_some_and(|revision| {
                        revision.begin_op_id == self.operation_id
                            && revision.before_cut_id == *before_cut_id
                            && revision.after_cut_id == *after_cut_id
                    })
            }
            FlowingHostFenceActionV1::FinishRevision { begin_op_id }
            | FlowingHostFenceActionV1::AbortRevision { begin_op_id } => {
                !begin_op_id.trim().is_empty()
                    && self.resulting_owner_epoch == owner
                    && self.resulting_eligibility_epoch == next(eligibility)?
                    && self.resulting_revision.is_none()
            }
            FlowingHostFenceActionV1::Takeover { new_owner } => {
                !new_owner.trim().is_empty()
                    && self.resulting_owner == *new_owner
                    && self.resulting_owner_epoch == next(owner)?
                    && self.resulting_eligibility_epoch == next(eligibility)?
            }
            FlowingHostFenceActionV1::InvalidateEligibility { reason_digest } => {
                valid_digest(reason_digest)
                    && self.resulting_owner_epoch == owner
                    && self.resulting_eligibility_epoch == next(eligibility)?
            }
            FlowingHostFenceActionV1::DisableAdmission => {
                !self.resulting_admission_enabled
                    && self.resulting_revision.is_none()
                    && self.resulting_owner_epoch == owner
                    && same_or_next(eligibility, self.resulting_eligibility_epoch)?
            }
        };
        if !valid {
            return Err(invalid("fence evidence action and state differ"));
        }
        Ok(())
    }
}

fn known_action_fields(evidence: &Value) -> bool {
    let Some(action) = evidence.get("action").and_then(Value::as_object) else {
        return false;
    };
    let Some(kind) = action.get("kind").and_then(Value::as_str) else {
        return false;
    };
    action.keys().all(|field| {
        field == "kind"
            || match kind {
                "begin_revision" => matches!(field.as_str(), "before_cut_id" | "after_cut_id"),
                "finish_revision" | "abort_revision" => field == "begin_op_id",
                "takeover" => field == "new_owner",
                "invalidate_eligibility" => field == "reason_digest",
                _ => false,
            }
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::branches::flowing_fence::{
        decide, FlowingFenceState, FlowingFenceTransition, FlowingRevision,
    };

    struct Reader(Option<FlowingFenceReceipt>);

    impl FlowingFenceEvidenceReader for Reader {
        fn read_fence_receipt(
            &self,
            _operation_id: &str,
        ) -> StoreResult<Option<FlowingFenceReceipt>> {
            Ok(self.0.clone())
        }
    }

    fn assert_refusal(error: StoreError, expected: &str) {
        assert!(
            matches!(error, StoreError::Conflict(message) if message.contains(expected)),
            "expected refusal containing {expected}"
        );
    }

    fn state() -> FlowingFenceState {
        FlowingFenceState {
            source_branch_id: "branch-a".into(),
            incarnation_id: "incarnation-a".into(),
            kind: FlowingSourceKind::Branch,
            owner: "owner-a".into(),
            owner_epoch: 0,
            eligibility_epoch: 0,
            held: false,
            revision: None,
            admission_enabled: true,
            opened_at: "2026-10-06T00:00:00Z".into(),
        }
    }

    fn request(
        op_id: &str,
        state: &FlowingFenceState,
        action: FlowingFenceAction,
    ) -> FlowingFenceTransition {
        FlowingFenceTransition {
            op_id: op_id.into(),
            source_branch_id: state.source_branch_id.clone(),
            incarnation_id: state.incarnation_id.clone(),
            expected_eligibility_epoch: state.eligibility_epoch,
            expected_owner_epoch: state.owner_epoch,
            actor: "member-a".into(),
            action,
            recorded_at: "2026-10-06T00:01:00Z".into(),
        }
    }

    #[test]
    fn hold_and_invalidation_project_without_free_form_reason() {
        let before = state();
        let hold = request("hold-a", &before, FlowingFenceAction::Hold);
        let held = decide(&before, &hold, Some("cut-a")).unwrap();
        let receipt = FlowingFenceReceipt {
            request: hold,
            state: held.clone(),
        };
        let evidence = read_fence_evidence(&Reader(Some(receipt)), "hold-a")
            .unwrap()
            .unwrap();
        assert_eq!(evidence.action, FlowingHostFenceActionV1::Hold);
        assert!(evidence.resulting_held);
        assert_eq!(evidence.resulting_eligibility_epoch, 1);

        let hold_again = request("hold-again", &held, FlowingFenceAction::Hold);
        let still_held = decide(&held, &hold_again, Some("cut-a")).unwrap();
        let repeated = FlowingHostFenceEvidenceV1::from_retained(&FlowingFenceReceipt {
            request: hold_again,
            state: still_held,
        })
        .unwrap();
        assert_eq!(repeated.expected_eligibility_epoch, 1);
        assert_eq!(repeated.resulting_eligibility_epoch, 1);

        let reason = "private revision explanation";
        let invalidate = request(
            "invalidate-a",
            &held,
            FlowingFenceAction::InvalidateEligibility {
                reason: reason.into(),
            },
        );
        let after = decide(&held, &invalidate, Some("cut-a")).unwrap();
        let receipt = FlowingFenceReceipt {
            request: invalidate,
            state: after,
        };
        let evidence = read_fence_evidence(&Reader(Some(receipt)), "invalidate-a")
            .unwrap()
            .unwrap();
        let bytes = serde_json::to_vec(&evidence).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(reason));
        assert!(matches!(
            evidence.action,
            FlowingHostFenceActionV1::InvalidateEligibility { .. }
        ));
        assert_eq!(
            FlowingHostFenceEvidenceV1::decode(&bytes).unwrap(),
            evidence
        );
    }

    #[test]
    fn revision_evidence_binds_exact_cuts_and_refuses_mismatched_state() {
        let before = state();
        let begin = request(
            "begin-a",
            &before,
            FlowingFenceAction::BeginRevision {
                before_cut_id: Some("cut-a".into()),
                after_cut_id: "cut-b".into(),
            },
        );
        let revising = decide(&before, &begin, Some("cut-a")).unwrap();
        let receipt = FlowingFenceReceipt {
            request: begin,
            state: revising.clone(),
        };
        let evidence = FlowingHostFenceEvidenceV1::from_retained(&receipt).unwrap();
        assert_eq!(
            evidence.resulting_revision,
            Some(FlowingHostRevisionV1 {
                begin_op_id: "begin-a".into(),
                before_cut_id: Some("cut-a".into()),
                after_cut_id: "cut-b".into(),
            })
        );
        let mut changed = receipt;
        changed.state.revision = Some(FlowingRevision {
            begin_op_id: "other".into(),
            before_cut_id: Some("cut-a".into()),
            after_cut_id: "cut-b".into(),
        });
        assert_refusal(
            FlowingHostFenceEvidenceV1::from_retained(&changed).unwrap_err(),
            "fence transition and retained state differ",
        );

        let mut invalid_wire = serde_json::to_value(&evidence).unwrap();
        invalid_wire["resulting_revision"]["begin_op_id"] = json!("");
        assert_refusal(
            FlowingHostFenceEvidenceV1::decode(&serde_json::to_vec(&invalid_wire).unwrap())
                .unwrap_err(),
            "fence revision identity is empty",
        );

        let finish = request(
            "finish-a",
            &revising,
            FlowingFenceAction::FinishRevision {
                begin_op_id: "begin-a".into(),
            },
        );
        let after = decide(&revising, &finish, Some("cut-b")).unwrap();
        let evidence = FlowingHostFenceEvidenceV1::from_retained(&FlowingFenceReceipt {
            request: finish,
            state: after,
        })
        .unwrap();
        assert!(evidence.resulting_revision.is_none());
        assert_eq!(evidence.resulting_eligibility_epoch, 2);
    }

    #[test]
    fn strict_wire_and_authoritative_lookup_refuse_missing_or_forged_evidence() {
        let before = state();
        let hold = request("hold-a", &before, FlowingFenceAction::Hold);
        let held = decide(&before, &hold, Some("cut-a")).unwrap();
        let receipt = FlowingFenceReceipt {
            request: hold,
            state: held,
        };
        assert_refusal(
            read_fence_evidence(&Reader(None), "").unwrap_err(),
            "operation identity is empty",
        );
        assert!(read_fence_evidence(&Reader(None), "hold-a")
            .unwrap()
            .is_none());
        assert!(read_fence_evidence(&Reader(Some(receipt.clone())), "wrong-op").is_err());
        let mut mismatched = receipt.clone();
        mismatched.state.source_branch_id = "other-branch".into();
        assert_refusal(
            FlowingHostFenceEvidenceV1::from_retained(&mismatched).unwrap_err(),
            "fence receipt identity or epoch differs",
        );
        let evidence = FlowingHostFenceEvidenceV1::from_retained(&receipt).unwrap();
        let original = serde_json::to_value(evidence).unwrap();
        let mut extra = original.clone();
        extra["reason"] = json!("private");
        assert!(FlowingHostFenceEvidenceV1::decode(&serde_json::to_vec(&extra).unwrap()).is_err());
        let mut nested_extra = original.clone();
        nested_extra["action"]["reason"] = json!("private");
        assert!(
            FlowingHostFenceEvidenceV1::decode(&serde_json::to_vec(&nested_extra).unwrap())
                .is_err()
        );
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove("request_digest");
        assert!(
            FlowingHostFenceEvidenceV1::decode(&serde_json::to_vec(&missing).unwrap()).is_err()
        );
        let mut wrong_schema = original.clone();
        wrong_schema["schema"] = json!("whipplescript.flowing_fence_evidence.v2");
        assert_refusal(
            FlowingHostFenceEvidenceV1::decode(&serde_json::to_vec(&wrong_schema).unwrap())
                .unwrap_err(),
            "wrong fence evidence schema",
        );
        let mut empty = original.clone();
        empty["source_branch_id"] = json!("");
        assert_refusal(
            FlowingHostFenceEvidenceV1::decode(&serde_json::to_vec(&empty).unwrap()).unwrap_err(),
            "required fence evidence identity is empty",
        );
        let mut stale = original;
        stale["resulting_eligibility_epoch"] = json!(-1);
        assert_refusal(
            FlowingHostFenceEvidenceV1::decode(&serde_json::to_vec(&stale).unwrap()).unwrap_err(),
            "fence evidence epoch is invalid",
        );
        stale["resulting_eligibility_epoch"] = json!(1);
        stale["resulting_held"] = json!(false);
        assert!(FlowingHostFenceEvidenceV1::decode(&serde_json::to_vec(&stale).unwrap()).is_err());
        stale["resulting_held"] = json!(true);
        stale["state_digest"] = json!("sha256:invalid");
        assert!(FlowingHostFenceEvidenceV1::decode(&serde_json::to_vec(&stale).unwrap()).is_err());
    }
}
