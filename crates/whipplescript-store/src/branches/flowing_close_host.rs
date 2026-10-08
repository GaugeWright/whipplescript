//! Body-free host projection of one terminal flowing source disposition.
//!
//! The owning ref store validates the immutable close receipt before this
//! projection is made. Decoding JSON alone does not grant close authority or
//! prove that the source's retained work remains available.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::flowing_admission::FlowingUnitOutcome;
use super::flowing_close_roster::FlowingCloseUnitState;
use super::flowing_fence::FlowingSourceKind;
use super::flowing_final_close::{
    preflight, receipt_matches_snapshot, FlowingFinalClose, FlowingFinalCloseReceipt,
};
use super::flowing_host::unit_digest;
use super::MAINLINE_BRANCH_ID;
use crate::{StoreError, StoreResult};

pub const FLOWING_CLOSE_EVIDENCE_V1: &str = "whipplescript.flowing_close_evidence.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FlowingHostCloseDispositionV1 {
    Admitted {
        operation_id: String,
        outcome: FlowingUnitOutcome,
        unit_witness_digest: String,
    },
    Parked {
        operation_id: String,
        holder_id: String,
    },
    Transferred {
        operation_id: String,
        target_branch_id: String,
        target_cut_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostClosedUnitV1 {
    pub unit_id: String,
    pub original_source_branch_id: String,
    pub disposition: FlowingHostCloseDispositionV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostClosedMemberV1 {
    pub branch_id: String,
    pub park_operation_id: String,
    pub parked_holder_id: String,
    pub retained_head_cut_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostCloseEvidenceV1 {
    pub schema: String,
    pub operation_id: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub source_kind: FlowingSourceKind,
    pub source_parent_branch_id: String,
    pub close_request_operation_id: String,
    pub eligibility_epoch: i64,
    pub owner_epoch: i64,
    pub roster_digest: String,
    pub final_receipt_digest: String,
    pub retained_head_cut_id: Option<String>,
    pub retained_head_manifest_hash: Option<String>,
    pub units: Vec<FlowingHostClosedUnitV1>,
    pub members: Vec<FlowingHostClosedMemberV1>,
}

fn invalid(reason: &str) -> StoreError {
    StoreError::Conflict(format!("flowing close host evidence refuses: {reason}"))
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 32
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// The reader must be backed by the owning ref authority, whose close receipt
/// method checks the current terminal row and retained roster evidence.
pub fn read_close_evidence(
    source: &impl FlowingFinalClose,
    source_branch_id: &str,
) -> StoreResult<Option<FlowingHostCloseEvidenceV1>> {
    if source_branch_id.trim().is_empty() {
        return Err(invalid("source identity is empty"));
    }
    let Some(receipt) = source.flowing_final_close_receipt(source_branch_id)? else {
        return Ok(None);
    };
    if receipt.request.source_branch_id != source_branch_id {
        return Err(invalid("close receipt differs from requested source"));
    }
    Ok(Some(FlowingHostCloseEvidenceV1::from_retained(&receipt)?))
}

impl FlowingHostCloseEvidenceV1 {
    pub fn from_retained(receipt: &FlowingFinalCloseReceipt) -> StoreResult<Self> {
        if preflight(&receipt.roster, &receipt.request).is_err()
            || receipt.roster.digest()? != receipt.request.expected_roster_digest
            || !receipt_matches_snapshot(receipt)
        {
            return Err(invalid("close receipt has an unresolved or changed roster"));
        }
        // The shared close predicate above already proves these fields and
        // exact unit/receipt membership. The projection only removes bodies.
        let close_request = receipt
            .roster
            .close_request
            .as_ref()
            .expect("validated close request");
        let mut admitted_units = BTreeMap::new();
        for admission in &receipt.unit_evidence.admissions {
            for selected in &admission.request.units {
                admitted_units.insert(
                    (admission.request.op_id.as_str(), selected.unit_id.as_str()),
                    selected,
                );
            }
        }
        let handoffs: BTreeMap<_, _> = receipt
            .unit_evidence
            .handoffs
            .iter()
            .map(|handoff| (handoff.unit_id.as_str(), handoff))
            .collect();
        let mut units = Vec::with_capacity(receipt.roster.units.len());
        for unit in &receipt.roster.units {
            let disposition = match &unit.state {
                FlowingCloseUnitState::Admitted { op_id } => {
                    let selected = admitted_units
                        .get(&(op_id.as_str(), unit.unit_id.as_str()))
                        .expect("validated admitted unit");
                    FlowingHostCloseDispositionV1::Admitted {
                        operation_id: op_id.clone(),
                        outcome: selected.outcome,
                        unit_witness_digest: unit_digest(selected)?,
                    }
                }
                FlowingCloseUnitState::Parked { op_id, holder_id } => {
                    FlowingHostCloseDispositionV1::Parked {
                        operation_id: op_id.clone(),
                        holder_id: holder_id.clone(),
                    }
                }
                FlowingCloseUnitState::Transferred { target_branch_id } => {
                    let handoff = handoffs
                        .get(unit.unit_id.as_str())
                        .expect("validated transferred unit");
                    FlowingHostCloseDispositionV1::Transferred {
                        operation_id: handoff.op_id.clone(),
                        target_branch_id: target_branch_id.clone(),
                        target_cut_id: handoff.target_after_cut_id.clone(),
                    }
                }
                FlowingCloseUnitState::OwedBySource
                | FlowingCloseUnitState::OwedByMember { .. } => {
                    unreachable!("validated close receipt has no owed units");
                }
            };
            units.push(FlowingHostClosedUnitV1 {
                unit_id: unit.unit_id.clone(),
                original_source_branch_id: unit.original_source_branch_id.clone(),
                disposition,
            });
        }
        let members = receipt
            .roster
            .members
            .iter()
            .map(|member| {
                let park = member.parked.as_ref().expect("validated parked member");
                FlowingHostClosedMemberV1 {
                    branch_id: member.branch_id.clone(),
                    park_operation_id: park.request.op_id.clone(),
                    parked_holder_id: park.request.parked_holder_id.clone(),
                    retained_head_cut_id: member.head_cut_id.clone(),
                }
            })
            .collect();
        let evidence = Self {
            schema: FLOWING_CLOSE_EVIDENCE_V1.into(),
            operation_id: receipt.request.op_id.clone(),
            source_branch_id: receipt.request.source_branch_id.clone(),
            source_incarnation_id: receipt.request.source_incarnation_id.clone(),
            source_kind: receipt.roster.source_fence.kind.clone(),
            source_parent_branch_id: receipt
                .roster
                .source_parent_branch_id
                .clone()
                .expect("validated direct source parent"),
            close_request_operation_id: close_request.request.op_id.clone(),
            eligibility_epoch: receipt.roster.source_fence.eligibility_epoch,
            owner_epoch: receipt.roster.source_fence.owner_epoch,
            roster_digest: receipt.request.expected_roster_digest.clone(),
            final_receipt_digest: receipt.digest()?,
            retained_head_cut_id: receipt.roster.source_head_cut_id.clone(),
            retained_head_manifest_hash: receipt.roster.source_head_manifest_hash.clone(),
            units,
            members,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Strict decoding checks shape; only an authoritative read authenticates
    /// the operation, its unit receipts and its retained source cut.
    pub fn decode(bytes: &[u8]) -> StoreResult<Self> {
        let evidence: Self = serde_json::from_slice(bytes)?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> StoreResult<()> {
        if self.schema != FLOWING_CLOSE_EVIDENCE_V1
            || self.operation_id.trim().is_empty()
            || self.source_branch_id.trim().is_empty()
            || self.source_incarnation_id.trim().is_empty()
            || self.source_parent_branch_id != MAINLINE_BRANCH_ID
            || self.close_request_operation_id.trim().is_empty()
            || self.eligibility_epoch < 0
            || self.owner_epoch < 0
            || !valid_digest(&self.roster_digest)
            || !valid_digest(&self.final_receipt_digest)
            || self.retained_head_cut_id.is_some() != self.retained_head_manifest_hash.is_some()
        {
            return Err(invalid(
                "close evidence has invalid identity, epoch or digest",
            ));
        }
        if self
            .retained_head_cut_id
            .as_deref()
            .is_some_and(|id| id.trim().is_empty())
            || self
                .retained_head_manifest_hash
                .as_deref()
                .is_some_and(|hash| hash.trim().is_empty())
        {
            return Err(invalid("close evidence has an empty retained head"));
        }
        let mut previous = None;
        for unit in &self.units {
            if unit.unit_id.trim().is_empty()
                || unit.original_source_branch_id.trim().is_empty()
                || previous.is_some_and(|id: &str| id >= unit.unit_id.as_str())
            {
                return Err(invalid("close evidence has invalid or duplicate units"));
            }
            previous = Some(unit.unit_id.as_str());
            match &unit.disposition {
                FlowingHostCloseDispositionV1::Admitted {
                    operation_id,
                    unit_witness_digest,
                    ..
                } if operation_id.trim().is_empty() || !valid_digest(unit_witness_digest) => {
                    return Err(invalid("admitted close unit has invalid evidence"));
                }
                FlowingHostCloseDispositionV1::Parked {
                    operation_id,
                    holder_id,
                } if operation_id.trim().is_empty() || holder_id.trim().is_empty() => {
                    return Err(invalid("parked close unit has invalid evidence"));
                }
                FlowingHostCloseDispositionV1::Transferred {
                    operation_id,
                    target_branch_id,
                    target_cut_id,
                } if operation_id.trim().is_empty()
                    || target_branch_id.trim().is_empty()
                    || target_cut_id.trim().is_empty() =>
                {
                    return Err(invalid("transferred close unit has invalid evidence"));
                }
                _ => {}
            }
        }
        let mut previous = None;
        for member in &self.members {
            if member.branch_id.trim().is_empty()
                || member.park_operation_id.trim().is_empty()
                || member.parked_holder_id.trim().is_empty()
                || member
                    .retained_head_cut_id
                    .as_deref()
                    .is_some_and(|id| id.trim().is_empty())
                || previous.is_some_and(|id: &str| id >= member.branch_id.as_str())
            {
                return Err(invalid("close evidence has invalid or duplicate members"));
            }
            previous = Some(member.branch_id.as_str());
        }
        if self.source_kind == FlowingSourceKind::Twig && !self.members.is_empty() {
            return Err(invalid("direct twig close has branch members"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> FlowingHostCloseEvidenceV1 {
        FlowingHostCloseEvidenceV1 {
            schema: FLOWING_CLOSE_EVIDENCE_V1.into(),
            operation_id: "final-close".into(),
            source_branch_id: "twig".into(),
            source_incarnation_id: "twig-inc".into(),
            source_kind: FlowingSourceKind::Twig,
            source_parent_branch_id: MAINLINE_BRANCH_ID.into(),
            close_request_operation_id: "request-close".into(),
            eligibility_epoch: 1,
            owner_epoch: 0,
            roster_digest: format!("sha256:{}", "0".repeat(32)),
            final_receipt_digest: format!("sha256:{}", "1".repeat(32)),
            retained_head_cut_id: None,
            retained_head_manifest_hash: None,
            units: Vec::new(),
            members: Vec::new(),
        }
    }

    #[test]
    fn close_codec_rejects_unknown_missing_and_ambiguous_evidence() {
        let evidence = evidence();
        let bytes = serde_json::to_vec(&evidence).unwrap();
        assert_eq!(
            FlowingHostCloseEvidenceV1::decode(&bytes).unwrap(),
            evidence
        );

        let mut value = serde_json::to_value(&evidence).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(FlowingHostCloseEvidenceV1::decode(&serde_json::to_vec(&value).unwrap()).is_err());

        let mut value = serde_json::to_value(&evidence).unwrap();
        value.as_object_mut().unwrap().remove("roster_digest");
        assert!(FlowingHostCloseEvidenceV1::decode(&serde_json::to_vec(&value).unwrap()).is_err());

        let mut value = evidence.clone();
        value.schema = "whipplescript.flowing_close_evidence.v2".into();
        assert!(value.validate().is_err());
        value = evidence.clone();
        value.operation_id.clear();
        assert!(value.validate().is_err());
        value = evidence.clone();
        value.source_parent_branch_id = "branch".into();
        assert!(value.validate().is_err());

        let unit = FlowingHostClosedUnitV1 {
            unit_id: "unit".into(),
            original_source_branch_id: "twig".into(),
            disposition: FlowingHostCloseDispositionV1::Parked {
                operation_id: "park-unit".into(),
                holder_id: "holder".into(),
            },
        };
        let mut nested = evidence.clone();
        nested.units.push(unit.clone());
        let mut nested = serde_json::to_value(nested).unwrap();
        nested["units"][0]["disposition"]["unexpected"] = serde_json::json!(true);
        assert!(FlowingHostCloseEvidenceV1::decode(&serde_json::to_vec(&nested).unwrap()).is_err());
        value = evidence.clone();
        value.units = vec![unit.clone(), unit.clone()];
        assert!(value.validate().is_err());
        value = evidence.clone();
        value.units.push(FlowingHostClosedUnitV1 {
            unit_id: "unit".into(),
            original_source_branch_id: "twig".into(),
            disposition: FlowingHostCloseDispositionV1::Admitted {
                operation_id: "admit".into(),
                outcome: FlowingUnitOutcome::Applied,
                unit_witness_digest: "bad-digest".into(),
            },
        });
        assert!(format!("{:?}", value.validate().unwrap_err())
            .contains("admitted close unit has invalid evidence"));
        value = evidence.clone();
        value.units.push(FlowingHostClosedUnitV1 {
            unit_id: "unit".into(),
            original_source_branch_id: "twig".into(),
            disposition: FlowingHostCloseDispositionV1::Transferred {
                operation_id: "handoff".into(),
                target_branch_id: "recipient".into(),
                target_cut_id: "".into(),
            },
        });
        assert!(format!("{:?}", value.validate().unwrap_err())
            .contains("transferred close unit has invalid evidence"));
        value = evidence.clone();
        value.units.push(FlowingHostClosedUnitV1 {
            disposition: FlowingHostCloseDispositionV1::Parked {
                operation_id: "park".into(),
                holder_id: "".into(),
            },
            ..unit.clone()
        });
        assert!(format!("{:?}", value.validate().unwrap_err())
            .contains("parked close unit has invalid evidence"));
        value = evidence.clone();
        value.retained_head_cut_id = Some("cut".into());
        assert!(value.validate().is_err());
        value.retained_head_manifest_hash = Some("manifest".into());
        value.retained_head_cut_id = Some("".into());
        assert!(value.validate().is_err());

        value = evidence.clone();
        value.members.push(FlowingHostClosedMemberV1 {
            branch_id: "member".into(),
            park_operation_id: "park-member".into(),
            parked_holder_id: "holder".into(),
            retained_head_cut_id: None,
        });
        assert!(value.validate().is_err());
        value.source_kind = FlowingSourceKind::Branch;
        value.members.push(value.members[0].clone());
        assert!(value.validate().is_err());
    }
}
