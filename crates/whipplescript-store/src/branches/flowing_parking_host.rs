//! Body-free historical evidence of a ref-owned parked-unit transfer.
//! The retained ref receipt proves the transfer at its transaction boundary;
//! this projection does not authorize current use or settle the unit.

use serde::{Deserialize, Serialize};

use super::flowing_parking::{receipt_matches_keys, FlowingParkReceipt, FlowingParking};
use crate::{StoreError, StoreResult};

pub const FLOWING_PARKING_EVIDENCE_V1: &str = "whipplescript.flowing_parking_evidence.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostParkingEvidenceV1 {
    pub schema: String,
    pub operation_id: String,
    pub unit_id: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub source_cut_id: String,
    pub source_manifest_hash: String,
    pub parked_holder_id: String,
    pub holder_cut_id: String,
    pub holder_manifest_hash: String,
    pub expected_eligibility_epoch: i64,
    pub resulting_eligibility_epoch: i64,
    pub expected_owner_epoch: i64,
    pub resulting_owner_epoch: i64,
    pub recorded_at: String,
    pub request_digest: String,
    pub former_holder_digest: String,
    pub resulting_fence_digest: String,
}

fn invalid(reason: &str) -> StoreError {
    StoreError::Conflict(format!("flowing parking host evidence refuses: {reason}"))
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

pub fn read_parking_evidence(
    parking: &impl FlowingParking,
    operation_id: &str,
) -> StoreResult<Option<FlowingHostParkingEvidenceV1>> {
    if operation_id.trim().is_empty() {
        return Err(invalid("operation identity is empty"));
    }
    let Some(receipt) = parking.flowing_park_receipt(operation_id)? else {
        return Ok(None);
    };
    Ok(Some(FlowingHostParkingEvidenceV1::from_retained(
        operation_id,
        &receipt,
    )?))
}

impl FlowingHostParkingEvidenceV1 {
    fn from_retained(operation_id: &str, receipt: &FlowingParkReceipt) -> StoreResult<Self> {
        let request = &receipt.request;
        if !receipt_matches_keys(receipt, &request.unit_id, operation_id)
            || request.expected_eligibility_epoch < 0
            || request.expected_owner_epoch < 0
            || receipt.source_fence_after.owner_epoch != request.expected_owner_epoch
            || receipt.source_fence_after.eligibility_epoch
                != request
                    .expected_eligibility_epoch
                    .checked_add(1)
                    .ok_or_else(|| invalid("epoch overflow"))?
            || receipt.source_fence_after.revision.is_some()
        {
            return Err(invalid("retained parking receipt is inconsistent"));
        }
        let evidence = Self {
            schema: FLOWING_PARKING_EVIDENCE_V1.into(),
            operation_id: request.op_id.clone(),
            unit_id: request.unit_id.clone(),
            source_branch_id: request.source_branch_id.clone(),
            source_incarnation_id: request.source_incarnation_id.clone(),
            source_cut_id: request.source_cut_id.clone(),
            source_manifest_hash: request.source_manifest_hash.clone(),
            parked_holder_id: request.parked_holder_id.clone(),
            holder_cut_id: receipt.former_holder.holder_cut_id.clone(),
            holder_manifest_hash: receipt.former_holder.holder_manifest_hash.clone(),
            expected_eligibility_epoch: request.expected_eligibility_epoch,
            resulting_eligibility_epoch: receipt.source_fence_after.eligibility_epoch,
            expected_owner_epoch: request.expected_owner_epoch,
            resulting_owner_epoch: receipt.source_fence_after.owner_epoch,
            recorded_at: request.recorded_at.clone(),
            request_digest: digest("flowing-host-parking-request-v1", request)?,
            former_holder_digest: digest(
                "flowing-host-parking-former-holder-v1",
                &receipt.former_holder,
            )?,
            resulting_fence_digest: digest(
                "flowing-host-parking-resulting-fence-v1",
                &receipt.source_fence_after,
            )?,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Strict wire validation does not authenticate the owning ref store.
    pub fn decode(bytes: &[u8]) -> StoreResult<Self> {
        let evidence: Self = serde_json::from_slice(bytes)?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> StoreResult<()> {
        if self.schema != FLOWING_PARKING_EVIDENCE_V1
            || [
                &self.operation_id,
                &self.unit_id,
                &self.source_branch_id,
                &self.source_incarnation_id,
                &self.source_cut_id,
                &self.source_manifest_hash,
                &self.parked_holder_id,
                &self.holder_cut_id,
                &self.holder_manifest_hash,
                &self.recorded_at,
            ]
            .into_iter()
            .any(|value| value.trim().is_empty())
            || self.parked_holder_id == self.source_branch_id
            || self.expected_eligibility_epoch < 0
            || self.expected_owner_epoch < 0
            || self.resulting_eligibility_epoch
                != self
                    .expected_eligibility_epoch
                    .checked_add(1)
                    .ok_or_else(|| invalid("epoch overflow"))?
            || self.resulting_owner_epoch != self.expected_owner_epoch
            || !valid_digest(&self.request_digest)
            || !valid_digest(&self.former_holder_digest)
            || !valid_digest(&self.resulting_fence_digest)
        {
            return Err(invalid("parking evidence shape is invalid"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_fence::{FlowingFenceState, FlowingSourceKind};
    use crate::branches::flowing_holders::FlowingUnitHolder;
    use crate::branches::flowing_parking::ParkFlowingUnit;

    fn retained() -> FlowingParkReceipt {
        FlowingParkReceipt {
            request: ParkFlowingUnit {
                op_id: "park-a".into(),
                unit_id: "unit-a".into(),
                source_branch_id: "branch".into(),
                source_incarnation_id: "inc".into(),
                source_cut_id: "head-cut".into(),
                source_manifest_hash: "head-manifest".into(),
                basis_digest: "basis".into(),
                principal: "author".into(),
                intent: "private intent".into(),
                expected_eligibility_epoch: 0,
                expected_owner_epoch: 0,
                parked_holder_id: "park:owner".into(),
                actor: "coordinator".into(),
                recorded_at: "t1".into(),
            },
            former_holder: FlowingUnitHolder {
                unit_id: "unit-a".into(),
                holder_branch_id: "branch".into(),
                holder_cut_id: "owed-cut".into(),
                holder_manifest_hash: "owed-manifest".into(),
                handoff_op_id: None,
                proof_digest: "proof".into(),
            },
            source_fence_after: FlowingFenceState {
                source_branch_id: "branch".into(),
                incarnation_id: "inc".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator".into(),
                owner_epoch: 0,
                eligibility_epoch: 1,
                held: false,
                revision: None,
                admission_enabled: true,
                opened_at: "t0".into(),
            },
        }
    }

    #[test]
    fn inconsistent_retained_receipt_refuses_before_host_projection() {
        let mut receipt = retained();
        assert!(FlowingHostParkingEvidenceV1::from_retained("park-a", &receipt).is_ok());
        receipt.source_fence_after.owner_epoch = 1;
        let error = FlowingHostParkingEvidenceV1::from_retained("park-a", &receipt).unwrap_err();
        assert!(format!("{error:?}").contains("retained parking receipt is inconsistent"));
    }
}
