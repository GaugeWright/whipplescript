//! Body-free host projection of one durable flowing admission.
//!
//! This is a versioned evidence codec, not a command or an admission grant.
//! A host must read the receipt and candidate witness from its owning ref
//! authority. Decoding caller-supplied JSON never authenticates either.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::flowing_admission::{
    FlowingAdmissionReceipt, FlowingAdmissions, FlowingCandidateWitness, FlowingSelectedUnit,
    FlowingUnitOutcome,
};
use crate::{StoreError, StoreResult};

pub const FLOWING_ADMISSION_EVIDENCE_V1: &str = "whipplescript.flowing_admission_evidence.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostUnitOutcomeV1 {
    pub unit_id: String,
    pub outcome: FlowingUnitOutcome,
    /// Binds the full selected unit, including its retained basis, principal
    /// and intent, without placing those values on the host wire.
    pub witness_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingHostAdmissionEvidenceV1 {
    pub schema: String,
    pub operation_id: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub source_cut_id: String,
    pub source_manifest_hash: String,
    pub candidate_witness_digest: String,
    pub source_atoms_digest: String,
    pub expected_trunk_cut_id: Option<String>,
    pub resulting_trunk_cut_id: String,
    pub resulting_trunk_manifest_hash: String,
    pub gate_certificate_handle: String,
    pub units: Vec<FlowingHostUnitOutcomeV1>,
}

fn invalid(reason: &str) -> StoreError {
    StoreError::Conflict(format!("flowing host evidence refuses: {reason}"))
}

pub(crate) fn unit_digest(unit: &FlowingSelectedUnit) -> StoreResult<String> {
    let bytes = serde_json::to_vec(&("flowing-host-unit-outcome-v1", unit))?;
    Ok(format!(
        "sha256:{}",
        crate::chunking::content_hash_hex(&bytes)
    ))
}

/// The two read operations the projection needs. Native and hosted ref
/// stores implement this through FlowingAdmissions; a product adapter can
/// expose the same narrow authenticated read boundary.
pub trait FlowingAdmissionEvidenceReader {
    fn read_admission_receipt(
        &self,
        operation_id: &str,
    ) -> StoreResult<Option<FlowingAdmissionReceipt>>;
    fn read_candidate_witness(&self, digest: &str) -> StoreResult<Option<FlowingCandidateWitness>>;
}

impl<T: FlowingAdmissions> FlowingAdmissionEvidenceReader for T {
    fn read_admission_receipt(
        &self,
        operation_id: &str,
    ) -> StoreResult<Option<FlowingAdmissionReceipt>> {
        self.flowing_admission_receipt(operation_id)
    }

    fn read_candidate_witness(&self, digest: &str) -> StoreResult<Option<FlowingCandidateWitness>> {
        self.candidate_witness(digest)
    }
}

/// Read both immutable records from the same ref authority. A missing
/// admission returns None; an admission with a missing witness is corrupt
/// evidence, not an empty or provisional receipt.
pub fn read_admission_evidence(
    admissions: &impl FlowingAdmissionEvidenceReader,
    operation_id: &str,
) -> StoreResult<Option<FlowingHostAdmissionEvidenceV1>> {
    if operation_id.trim().is_empty() {
        return Err(invalid("operation identity is empty"));
    }
    let Some(receipt) = admissions.read_admission_receipt(operation_id)? else {
        return Ok(None);
    };
    if receipt.request.op_id != operation_id {
        return Err(invalid(
            "admission receipt differs from requested operation",
        ));
    }
    let witness = admissions
        .read_candidate_witness(&receipt.request.candidate_witness_digest)?
        .ok_or_else(|| invalid("admission candidate witness is missing"))?;
    Ok(Some(FlowingHostAdmissionEvidenceV1::from_retained(
        &receipt, &witness,
    )?))
}

impl FlowingHostAdmissionEvidenceV1 {
    /// Project only a receipt whose exact candidate witness is independently
    /// retained by the ref authority. The caller remains responsible for
    /// reading both from that authority and checking the ref receipt there.
    fn from_retained(
        receipt: &FlowingAdmissionReceipt,
        witness: &FlowingCandidateWitness,
    ) -> StoreResult<Self> {
        let request = &receipt.request;
        if witness.digest()? != request.candidate_witness_digest
            || !witness.matches_request(request)
        {
            return Err(invalid("admission and retained candidate witness differ"));
        }
        let evidence = Self {
            schema: FLOWING_ADMISSION_EVIDENCE_V1.into(),
            operation_id: request.op_id.clone(),
            source_branch_id: request.source_branch_id.clone(),
            source_incarnation_id: request.source_incarnation_id.clone(),
            source_cut_id: request.source_cut_id.clone(),
            source_manifest_hash: request.source_manifest_hash.clone(),
            candidate_witness_digest: request.candidate_witness_digest.clone(),
            source_atoms_digest: witness.source_atoms_digest.clone(),
            expected_trunk_cut_id: request.expected_trunk_cut_id.clone(),
            resulting_trunk_cut_id: request.candidate_cut_id.clone(),
            resulting_trunk_manifest_hash: request.candidate_manifest_hash.clone(),
            gate_certificate_handle: request.certificate_handle.clone(),
            units: request
                .units
                .iter()
                .map(|unit| {
                    Ok(FlowingHostUnitOutcomeV1 {
                        unit_id: unit.unit_id.clone(),
                        outcome: unit.outcome,
                        witness_digest: unit_digest(unit)?,
                    })
                })
                .collect::<StoreResult<Vec<_>>>()?,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Strict decoding makes a new or missing field an explicit version
    /// mismatch. The decoded value is evidence-shaped data, not authority.
    pub fn decode(bytes: &[u8]) -> StoreResult<Self> {
        let evidence: Self = serde_json::from_slice(bytes)?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> StoreResult<()> {
        if self.schema != FLOWING_ADMISSION_EVIDENCE_V1 {
            return Err(invalid("wrong evidence schema"));
        }
        for value in [
            &self.operation_id,
            &self.source_branch_id,
            &self.source_incarnation_id,
            &self.source_cut_id,
            &self.source_manifest_hash,
            &self.candidate_witness_digest,
            &self.source_atoms_digest,
            &self.resulting_trunk_cut_id,
            &self.resulting_trunk_manifest_hash,
            &self.gate_certificate_handle,
        ] {
            if value.trim().is_empty() {
                return Err(invalid("required admission evidence identity is empty"));
            }
        }
        if self.units.is_empty() {
            return Err(invalid("admission evidence has no selected units"));
        }
        let mut seen = BTreeSet::new();
        for unit in &self.units {
            if unit.unit_id.trim().is_empty()
                || unit.witness_digest.trim().is_empty()
                || !seen.insert(&unit.unit_id)
            {
                return Err(invalid("selected unit evidence is empty or duplicated"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::branches::flowing_admission::FlowingAdmissionRequest;

    struct FixtureReader {
        receipt: Option<FlowingAdmissionReceipt>,
        witness: Option<FlowingCandidateWitness>,
    }

    impl FlowingAdmissionEvidenceReader for FixtureReader {
        fn read_admission_receipt(
            &self,
            _operation_id: &str,
        ) -> StoreResult<Option<FlowingAdmissionReceipt>> {
            Ok(self.receipt.clone())
        }

        fn read_candidate_witness(
            &self,
            _digest: &str,
        ) -> StoreResult<Option<FlowingCandidateWitness>> {
            Ok(self.witness.clone())
        }
    }

    fn assert_refusal(error: StoreError, text: &str) {
        assert!(
            matches!(error, StoreError::Conflict(message) if message.contains(text)),
            "expected {text}"
        );
    }

    fn retained_pair() -> (FlowingAdmissionReceipt, FlowingCandidateWitness) {
        let unit = FlowingSelectedUnit {
            unit_id: "unit-a".into(),
            basis_digest: "sha256:basis".into(),
            principal: "member-a".into(),
            intent: "private selected intent".into(),
            outcome: FlowingUnitOutcome::Applied,
        };
        let witness = FlowingCandidateWitness {
            contribution_id: "contribution-a".into(),
            revision_sequence: 2,
            source_branch_id: "branch-a".into(),
            source_incarnation_id: "incarnation-a".into(),
            source_cut_id: "source-cut-a".into(),
            source_manifest_hash: "source-manifest-a".into(),
            expected_trunk_cut_id: Some("trunk-before".into()),
            candidate_cut_id: "trunk-after".into(),
            candidate_manifest_hash: "trunk-manifest-after".into(),
            source_atoms_digest: "sha256:atoms".into(),
            units: vec![unit],
        };
        let request = FlowingAdmissionRequest {
            op_id: "admit-a".into(),
            certificate_handle: "sha256:certificate".into(),
            candidate_witness_digest: witness.digest().unwrap(),
            contribution_id: witness.contribution_id.clone(),
            revision_sequence: witness.revision_sequence,
            source_branch_id: witness.source_branch_id.clone(),
            source_incarnation_id: witness.source_incarnation_id.clone(),
            source_cut_id: witness.source_cut_id.clone(),
            source_manifest_hash: witness.source_manifest_hash.clone(),
            expected_eligibility_epoch: 3,
            expected_owner_epoch: 4,
            coordinator: "coordinator-a".into(),
            expected_trunk_cut_id: witness.expected_trunk_cut_id.clone(),
            candidate_cut_id: witness.candidate_cut_id.clone(),
            candidate_manifest_hash: witness.candidate_manifest_hash.clone(),
            units: witness.units.clone(),
            recorded_at: "2026-10-06T00:00:00Z".into(),
        };
        (FlowingAdmissionReceipt { request }, witness)
    }

    #[test]
    fn exact_admission_projects_a_body_free_versioned_receipt() {
        let (receipt, witness) = retained_pair();
        let projection = FlowingHostAdmissionEvidenceV1::from_retained(&receipt, &witness)
            .expect("exact ref records project");
        assert_eq!(projection.resulting_trunk_cut_id, "trunk-after");
        assert_eq!(projection.source_atoms_digest, "sha256:atoms");
        assert_eq!(projection.units.len(), 1);
        let bytes = serde_json::to_vec(&projection).unwrap();
        let wire = String::from_utf8(bytes.clone()).unwrap();
        assert!(!wire.contains("private selected intent"));
        assert!(!wire.contains("member-a"));
        assert!(!wire.contains("basis_digest"));
        assert_eq!(
            FlowingHostAdmissionEvidenceV1::decode(&bytes).unwrap(),
            projection
        );
    }

    #[test]
    fn changed_candidate_or_selected_outcome_cannot_project() {
        let (receipt, witness) = retained_pair();
        let mut changed = witness.clone();
        changed.source_atoms_digest = "sha256:other".into();
        assert_refusal(
            FlowingHostAdmissionEvidenceV1::from_retained(&receipt, &changed).unwrap_err(),
            "admission and retained candidate witness differ",
        );
        let mut changed = witness;
        changed.units[0].outcome = FlowingUnitOutcome::Neutralized;
        assert_refusal(
            FlowingHostAdmissionEvidenceV1::from_retained(&receipt, &changed).unwrap_err(),
            "admission and retained candidate witness differ",
        );
    }

    #[test]
    fn authoritative_reader_refuses_empty_identity_wrong_receipt_and_missing_witness() {
        let (receipt, witness) = retained_pair();
        let reader = FixtureReader {
            receipt: None,
            witness: None,
        };
        assert_refusal(
            read_admission_evidence(&reader, "").unwrap_err(),
            "operation identity is empty",
        );
        assert!(read_admission_evidence(&reader, "unknown")
            .unwrap()
            .is_none());
        let reader = FixtureReader {
            receipt: Some(receipt.clone()),
            witness: Some(witness),
        };
        assert_refusal(
            read_admission_evidence(&reader, "other-op").unwrap_err(),
            "admission receipt differs from requested operation",
        );
        let reader = FixtureReader {
            receipt: Some(receipt),
            witness: None,
        };
        assert_refusal(
            read_admission_evidence(&reader, "admit-a").unwrap_err(),
            "admission candidate witness is missing",
        );
    }

    #[test]
    fn strict_wire_refuses_new_fields_missing_bindings_and_duplicate_units() {
        let (receipt, witness) = retained_pair();
        let projection = FlowingHostAdmissionEvidenceV1::from_retained(&receipt, &witness).unwrap();
        let original = serde_json::to_value(projection).unwrap();
        let mut extra = original.clone();
        extra
            .as_object_mut()
            .unwrap()
            .insert("body".into(), json!("secret"));
        assert!(
            FlowingHostAdmissionEvidenceV1::decode(&serde_json::to_vec(&extra).unwrap()).is_err()
        );
        let mut missing = original.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("source_atoms_digest");
        assert!(
            FlowingHostAdmissionEvidenceV1::decode(&serde_json::to_vec(&missing).unwrap()).is_err()
        );
        let mut wrong_version = original.clone();
        wrong_version["schema"] = json!("whipplescript.flowing_admission_evidence.v2");
        assert_refusal(
            FlowingHostAdmissionEvidenceV1::decode(&serde_json::to_vec(&wrong_version).unwrap())
                .unwrap_err(),
            "wrong evidence schema",
        );
        let mut empty_identity = original.clone();
        empty_identity["operation_id"] = json!("");
        assert_refusal(
            FlowingHostAdmissionEvidenceV1::decode(&serde_json::to_vec(&empty_identity).unwrap())
                .unwrap_err(),
            "required admission evidence identity is empty",
        );
        let mut no_units = original.clone();
        no_units["units"] = json!([]);
        assert_refusal(
            FlowingHostAdmissionEvidenceV1::decode(&serde_json::to_vec(&no_units).unwrap())
                .unwrap_err(),
            "admission evidence has no selected units",
        );
        let mut duplicate: Value = original;
        let unit = duplicate["units"][0].clone();
        duplicate["units"].as_array_mut().unwrap().push(unit);
        assert!(
            FlowingHostAdmissionEvidenceV1::decode(&serde_json::to_vec(&duplicate).unwrap())
                .is_err()
        );
    }
}
