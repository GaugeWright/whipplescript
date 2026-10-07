//! Body-free historical evidence for a flowing source or atomic member opening.
//! The owning ref store supplies retained receipts. This does not assert the
//! source's current owner, Hold state, admission eligibility, or live cut.

use serde::{Deserialize, Serialize};

use super::flowing_fence::{
    validate_member_opening_receipt, validate_source_opening_receipt, FlowingFence,
    FlowingMemberOpeningReceipt, FlowingSourceKind, FlowingSourceOpeningReceipt,
};
use crate::{StoreError, StoreResult};

pub const FLOWING_SOURCE_OPENING_EVIDENCE_V1: &str =
    "whipplescript.flowing_source_opening_evidence.v1";
pub const FLOWING_MEMBER_OPENING_EVIDENCE_V1: &str =
    "whipplescript.flowing_member_opening_evidence.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostSourceOpeningEvidenceV1 {
    pub schema: String,
    pub source_branch_id: String,
    pub incarnation_id: String,
    pub source_kind: FlowingSourceKind,
    pub owner: String,
    pub opened_at: String,
    pub request_digest: String,
    pub initial_state_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostMemberOpeningEvidenceV1 {
    pub schema: String,
    pub member_branch_id: String,
    pub parent_branch_id: String,
    pub source_incarnation_id: String,
    pub branch_point_cut_id: Option<String>,
    pub branch_point_manifest_hash: Option<String>,
    pub created_at: String,
    /// Includes the private idempotency key without disclosing it.
    pub request_digest: String,
    pub initial_branch_digest: String,
    pub initial_source_state_digest: String,
    pub source_opening_digest: String,
}

fn invalid(reason: &str) -> StoreError {
    StoreError::Conflict(format!("flowing opening host evidence refuses: {reason}"))
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

pub fn read_source_opening_evidence(
    fences: &impl FlowingFence,
    source_branch_id: &str,
) -> StoreResult<Option<FlowingHostSourceOpeningEvidenceV1>> {
    if source_branch_id.trim().is_empty() {
        return Err(invalid("source identity is empty"));
    }
    let Some(receipt) = fences.flowing_source_opening(source_branch_id)? else {
        return Ok(None);
    };
    Ok(Some(FlowingHostSourceOpeningEvidenceV1::from_retained(
        source_branch_id,
        &receipt,
    )?))
}

pub fn read_member_opening_evidence(
    fences: &impl FlowingFence,
    member_branch_id: &str,
) -> StoreResult<Option<FlowingHostMemberOpeningEvidenceV1>> {
    if member_branch_id.trim().is_empty() {
        return Err(invalid("member identity is empty"));
    }
    let Some(member) = fences.flowing_member_opening(member_branch_id)? else {
        return Ok(None);
    };
    let source = fences
        .flowing_source_opening(member_branch_id)?
        .ok_or_else(|| invalid("member source opening receipt is missing"))?;
    Ok(Some(FlowingHostMemberOpeningEvidenceV1::from_retained(
        member_branch_id,
        &member,
        &source,
    )?))
}

impl FlowingHostSourceOpeningEvidenceV1 {
    fn from_retained(
        source_branch_id: &str,
        receipt: &FlowingSourceOpeningReceipt,
    ) -> StoreResult<Self> {
        validate_source_opening_receipt(source_branch_id, receipt)?;
        let evidence = Self {
            schema: FLOWING_SOURCE_OPENING_EVIDENCE_V1.into(),
            source_branch_id: receipt.request.source_branch_id.clone(),
            incarnation_id: receipt.request.incarnation_id.clone(),
            source_kind: receipt.request.kind.clone(),
            owner: receipt.request.owner.clone(),
            opened_at: receipt.request.opened_at.clone(),
            request_digest: digest("flowing-host-source-opening-request-v1", &receipt.request)?,
            initial_state_digest: digest("flowing-host-source-opening-state-v1", &receipt.state)?,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Strict shape validation; it does not authenticate the owning ref store.
    pub fn decode(bytes: &[u8]) -> StoreResult<Self> {
        let evidence: Self = serde_json::from_slice(bytes)?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> StoreResult<()> {
        if self.schema != FLOWING_SOURCE_OPENING_EVIDENCE_V1
            || self.source_branch_id.trim().is_empty()
            || self.incarnation_id.trim().is_empty()
            || self.owner.trim().is_empty()
            || self.opened_at.trim().is_empty()
            || !valid_digest(&self.request_digest)
            || !valid_digest(&self.initial_state_digest)
        {
            return Err(invalid("source opening evidence shape is invalid"));
        }
        Ok(())
    }
}

impl FlowingHostMemberOpeningEvidenceV1 {
    fn from_retained(
        member_branch_id: &str,
        member: &FlowingMemberOpeningReceipt,
        source: &FlowingSourceOpeningReceipt,
    ) -> StoreResult<Self> {
        validate_member_opening_receipt(member_branch_id, member)?;
        validate_source_opening_receipt(member_branch_id, source)?;
        if member.request.source != source.request || member.source != source.state {
            return Err(invalid("member and source opening receipts differ"));
        }
        let evidence = Self {
            schema: FLOWING_MEMBER_OPENING_EVIDENCE_V1.into(),
            member_branch_id: member.request.branch_id.clone(),
            parent_branch_id: member.request.parent_branch_id.clone(),
            source_incarnation_id: member.source.incarnation_id.clone(),
            branch_point_cut_id: member.branch.branch_point_cut_id.clone(),
            branch_point_manifest_hash: member.branch.branch_point_manifest_hash.clone(),
            created_at: member.request.created_at.clone(),
            request_digest: digest("flowing-host-member-opening-request-v1", &member.request)?,
            initial_branch_digest: digest("flowing-host-member-opening-branch-v1", &member.branch)?,
            initial_source_state_digest: digest(
                "flowing-host-member-opening-state-v1",
                &member.source,
            )?,
            source_opening_digest: digest("flowing-host-member-source-opening-v1", source)?,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Strict shape validation; it does not authenticate the owning ref store.
    pub fn decode(bytes: &[u8]) -> StoreResult<Self> {
        let evidence: Self = serde_json::from_slice(bytes)?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> StoreResult<()> {
        if self.schema != FLOWING_MEMBER_OPENING_EVIDENCE_V1
            || self.member_branch_id.trim().is_empty()
            || self.parent_branch_id.trim().is_empty()
            || self.source_incarnation_id.trim().is_empty()
            || self.created_at.trim().is_empty()
            || self.branch_point_cut_id.is_some() != self.branch_point_manifest_hash.is_some()
            || self
                .branch_point_cut_id
                .as_deref()
                .is_some_and(str::is_empty)
            || self
                .branch_point_manifest_hash
                .as_deref()
                .is_some_and(str::is_empty)
            || !valid_digest(&self.request_digest)
            || !valid_digest(&self.initial_branch_digest)
            || !valid_digest(&self.initial_source_state_digest)
            || !valid_digest(&self.source_opening_digest)
        {
            return Err(invalid("member opening evidence shape is invalid"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_fence::{
        initial_state, FlowingMemberOpeningRequest, OpenFlowingSource,
    };
    use crate::branches::{BranchRow, BranchStatus};

    fn retained() -> (FlowingMemberOpeningReceipt, FlowingSourceOpeningReceipt) {
        let request = OpenFlowingSource {
            source_branch_id: "member".into(),
            incarnation_id: "inc".into(),
            kind: FlowingSourceKind::Twig,
            owner: "owner".into(),
            opened_at: "t1".into(),
        };
        let state = initial_state(&request);
        let source = FlowingSourceOpeningReceipt {
            request: request.clone(),
            state: state.clone(),
        };
        let member = FlowingMemberOpeningReceipt {
            request: FlowingMemberOpeningRequest {
                branch_id: "member".into(),
                parent_branch_id: "branch".into(),
                at_cut: Some(("cut".into(), "manifest".into())),
                created_at: "t1".into(),
                idempotency_key: Some("private-key".into()),
                source: request,
            },
            branch: BranchRow {
                branch_id: "member".into(),
                name: None,
                parent_branch_id: Some("branch".into()),
                branch_point_cut_id: Some("cut".into()),
                branch_point_manifest_hash: Some("manifest".into()),
                head_cut_id: Some("cut".into()),
                head_manifest_hash: Some("manifest".into()),
                adopted_merge_cut_id: None,
                status: BranchStatus::Active,
                created_at: "t1".into(),
                updated_at: "t1".into(),
            },
            source: state,
        };
        (member, source)
    }

    #[test]
    fn opening_codecs_are_strict_and_body_free() {
        let (member, source) = retained();
        let source_evidence =
            FlowingHostSourceOpeningEvidenceV1::from_retained("member", &source).unwrap();
        let source_wire = serde_json::to_vec(&source_evidence).unwrap();
        assert_eq!(
            FlowingHostSourceOpeningEvidenceV1::decode(&source_wire).unwrap(),
            source_evidence
        );
        let member_evidence =
            FlowingHostMemberOpeningEvidenceV1::from_retained("member", &member, &source).unwrap();
        let member_wire = serde_json::to_vec(&member_evidence).unwrap();
        assert_eq!(
            FlowingHostMemberOpeningEvidenceV1::decode(&member_wire).unwrap(),
            member_evidence
        );
        assert!(!String::from_utf8(member_wire)
            .unwrap()
            .contains("private-key"));

        let mut source_json = serde_json::to_value(&source_evidence).unwrap();
        source_json["extra"] = serde_json::json!(true);
        assert!(FlowingHostSourceOpeningEvidenceV1::decode(
            &serde_json::to_vec(&source_json).unwrap()
        )
        .is_err());
        source_json.as_object_mut().unwrap().remove("extra");
        source_json["request_digest"] = serde_json::json!("bad");
        assert!(FlowingHostSourceOpeningEvidenceV1::decode(
            &serde_json::to_vec(&source_json).unwrap()
        )
        .is_err());

        let mut member_json = serde_json::to_value(&member_evidence).unwrap();
        member_json
            .as_object_mut()
            .unwrap()
            .remove("source_opening_digest");
        assert!(FlowingHostMemberOpeningEvidenceV1::decode(
            &serde_json::to_vec(&member_json).unwrap()
        )
        .is_err());
        let mut member_json = serde_json::to_value(&member_evidence).unwrap();
        member_json["branch_point_manifest_hash"] = serde_json::Value::Null;
        assert!(FlowingHostMemberOpeningEvidenceV1::decode(
            &serde_json::to_vec(&member_json).unwrap()
        )
        .is_err());
        member_json = serde_json::to_value(&member_evidence).unwrap();
        member_json["schema"] = serde_json::json!("unknown");
        assert!(FlowingHostMemberOpeningEvidenceV1::decode(
            &serde_json::to_vec(&member_json).unwrap()
        )
        .is_err());
    }

    #[test]
    fn member_evidence_requires_the_exact_source_opening() {
        let (member, mut source) = retained();
        source.request.owner = "different".into();
        source.state = initial_state(&source.request);
        assert!(matches!(
            FlowingHostMemberOpeningEvidenceV1::from_retained("member", &member, &source),
            Err(StoreError::Conflict(message)) if message == "flowing opening host evidence refuses: member and source opening receipts differ"
        ));
        let (mut member, source) = retained();
        member.branch.name = Some("forged".into());
        assert!(
            FlowingHostMemberOpeningEvidenceV1::from_retained("member", &member, &source).is_err()
        );
    }
}
