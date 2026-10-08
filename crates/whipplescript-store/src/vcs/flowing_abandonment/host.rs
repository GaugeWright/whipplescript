//! Body-free host evidence for a whole-twig abandonment.
//!
//! The source cut, every unit's atoms, and the replacement manifest are
//! verified from the owning ref and content stores before projection. A
//! decoded value remains historical evidence, never permission to abandon or
//! to treat an external effect as undone.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::branches::flowing_abandonment::{self, FlowingAbandonments};
use crate::branches::Branches;
use crate::content::ContentBlobs;
use crate::{StoreError, StoreResult};

use super::{FlowingAbandonmentLineageOutcome, WorkspaceVcs};

pub const FLOWING_ABANDONMENT_EVIDENCE_V1: &str = "whipplescript.flowing_abandonment_evidence.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostAbandonedUnitV1 {
    pub unit_id: String,
    /// Binds the retained declaration basis and exact source atoms without
    /// placing paths, content ids, principal or intent on the host wire.
    pub witness_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostAbandonmentEvidenceV1 {
    pub schema: String,
    pub operation_id: String,
    pub begin_revision_operation_id: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub source_eligibility_epoch_before_revision: i64,
    pub source_owner_epoch: i64,
    pub before_cut_id: String,
    pub before_manifest_hash: String,
    pub branch_point_cut_id: Option<String>,
    pub branch_point_manifest_hash: Option<String>,
    pub after_cut_id: String,
    pub after_manifest_hash: String,
    pub receipt_digest: String,
    pub source_atoms_digest: String,
    pub units: Vec<FlowingHostAbandonedUnitV1>,
}

fn invalid(reason: &str) -> StoreError {
    StoreError::Conflict(format!(
        "flowing abandonment host evidence refuses: {reason}"
    ))
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

impl<B: Branches + FlowingAbandonments, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// Read the retained receipt and verify its complete source lineage and
    /// replacement content before giving the host a compact disposition.
    pub fn read_abandonment_evidence(
        &self,
        operation_id: &str,
    ) -> StoreResult<Option<FlowingHostAbandonmentEvidenceV1>> {
        if operation_id.trim().is_empty() {
            return Err(invalid("operation identity is empty"));
        }
        let Some(receipt) = self.branches.flowing_abandonment_receipt(operation_id)? else {
            return Ok(None);
        };
        let FlowingAbandonmentLineageOutcome::Verified(lineage) =
            self.verify_flowing_abandonment_lineage(&receipt.after_cut_id)?
        else {
            return Err(invalid("retained source lineage is unverified"));
        };
        let receipt = lineage.receipt();
        let evidence = FlowingHostAbandonmentEvidenceV1 {
            schema: FLOWING_ABANDONMENT_EVIDENCE_V1.into(),
            operation_id: receipt.op_id.clone(),
            begin_revision_operation_id: receipt.begin_revision_op_id.clone(),
            source_branch_id: receipt.source_branch_id.clone(),
            source_incarnation_id: receipt.source_incarnation_id.clone(),
            source_eligibility_epoch_before_revision: receipt
                .source_eligibility_epoch_before_revision,
            source_owner_epoch: receipt.source_owner_epoch,
            before_cut_id: receipt.before_cut_id.clone(),
            before_manifest_hash: receipt.before_manifest_hash.clone(),
            branch_point_cut_id: receipt.branch_point_cut_id.clone(),
            branch_point_manifest_hash: receipt.branch_point_manifest_hash.clone(),
            after_cut_id: receipt.after_cut_id.clone(),
            after_manifest_hash: receipt.after_manifest_hash.clone(),
            receipt_digest: flowing_abandonment::digest(receipt),
            source_atoms_digest: digest(
                "flowing-host-abandonment-source-atoms-v1",
                &lineage.source_atoms(),
            )?,
            units: receipt
                .units
                .iter()
                .map(|unit| {
                    Ok(FlowingHostAbandonedUnitV1 {
                        unit_id: unit.unit_id().to_owned(),
                        witness_digest: digest("flowing-host-abandoned-unit-v1", unit)?,
                    })
                })
                .collect::<StoreResult<Vec<_>>>()?,
        };
        evidence.validate()?;
        Ok(Some(evidence))
    }
}

impl FlowingHostAbandonmentEvidenceV1 {
    /// Strictly decode the wire shape; only an owning-store read verifies it.
    pub fn decode(bytes: &[u8]) -> StoreResult<Self> {
        let evidence: Self = serde_json::from_slice(bytes)?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> StoreResult<()> {
        if self.schema != FLOWING_ABANDONMENT_EVIDENCE_V1 {
            return Err(invalid("wrong evidence schema"));
        }
        if [
            &self.operation_id,
            &self.begin_revision_operation_id,
            &self.source_branch_id,
            &self.source_incarnation_id,
            &self.before_cut_id,
            &self.before_manifest_hash,
            &self.after_cut_id,
            &self.after_manifest_hash,
        ]
        .into_iter()
        .any(|value| value.trim().is_empty())
            || self.before_cut_id == self.after_cut_id
            || self.branch_point_cut_id.is_some() != self.branch_point_manifest_hash.is_some()
            || self.source_eligibility_epoch_before_revision < 0
            || self.source_owner_epoch < 0
        {
            return Err(invalid("required abandonment coordinate is invalid"));
        }
        for optional in [
            self.branch_point_cut_id.as_deref(),
            self.branch_point_manifest_hash.as_deref(),
        ] {
            if optional.is_some_and(|value| value.trim().is_empty()) {
                return Err(invalid("branch point coordinate is empty"));
            }
        }
        if !valid_digest(&self.receipt_digest) || !valid_digest(&self.source_atoms_digest) {
            return Err(invalid("abandonment digest is invalid"));
        }
        if self.units.is_empty() {
            return Err(invalid("abandonment evidence has no units"));
        }
        let mut seen = BTreeSet::new();
        for unit in &self.units {
            if unit.unit_id.trim().is_empty()
                || !valid_digest(&unit.witness_digest)
                || !seen.insert(&unit.unit_id)
            {
                return Err(invalid("abandoned unit evidence is invalid or duplicated"));
            }
        }
        Ok(())
    }
}
