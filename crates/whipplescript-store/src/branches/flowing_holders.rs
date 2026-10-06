//! Current unit-holder evidence, read from the ref store. This does not
//! establish dependency closure or the content derivation of a candidate.

use super::flowing_admission::{
    FlowingCandidateWitness, FlowingGateCertificate, FlowingSelectedUnit, FlowingUnitOutcome,
};
use super::flowing_parking::ParkFlowingUnit;
use super::flowing_read::{Reader, StoreReader};
use super::flowing_sources::FlowingSources;
use super::{BranchStatus, Branches, MAINLINE_BRANCH_ID};
use crate::StoreResult;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingUnitHolder {
    pub unit_id: String,
    pub holder_branch_id: String,
    pub holder_cut_id: String,
    pub holder_manifest_hash: String,
    pub handoff_op_id: Option<String>,
    pub proof_digest: String,
}

fn ancestor(reader: &impl Reader, older: &str, newer: &str, branch: &str) -> StoreResult<bool> {
    let mut cursor = Some(newer.to_owned());
    let mut visited = BTreeSet::new();
    while let Some(id) = cursor {
        if !visited.insert(id.clone()) {
            return Ok(false);
        }
        let Some(cut) = reader.cut(&id)? else {
            return Ok(false);
        };
        if cut.cut_id != id || cut.branch_id != branch {
            return Ok(false);
        }
        if id == older {
            return Ok(true);
        }
        cursor = cut.parent_cut_id;
    }
    Ok(false)
}

pub fn capture<B: Branches + FlowingSources>(
    branches: &B,
    witness: &FlowingCandidateWitness,
) -> StoreResult<Option<Vec<FlowingUnitHolder>>> {
    for selected in &witness.units {
        if branches.parked_flowing_unit(&selected.unit_id)?.is_some() {
            return Ok(None);
        }
    }
    capture_from(
        &StoreReader(branches),
        &witness.source_branch_id,
        &witness.source_cut_id,
        &witness.source_manifest_hash,
        &witness.units,
    )
}

fn capture_from(
    reader: &impl Reader,
    source_branch_id: &str,
    source_cut_id: &str,
    source_manifest_hash: &str,
    units: &[FlowingSelectedUnit],
) -> StoreResult<Option<Vec<FlowingUnitHolder>>> {
    let Some(holder) = reader.branch(source_branch_id)? else {
        return Ok(None);
    };
    let Some(selected_cut) = reader.cut(source_cut_id)? else {
        return Ok(None);
    };
    if selected_cut.branch_id != source_branch_id
        || selected_cut.manifest_hash != source_manifest_hash
    {
        return Ok(None);
    }
    let Some(head) = holder.head_cut_id.as_deref() else {
        return Ok(None);
    };
    if holder.branch_id != source_branch_id
        || holder.status != BranchStatus::Active
        || holder.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID)
        || !ancestor(reader, source_cut_id, head, &holder.branch_id)?
        || units.is_empty()
    {
        return Ok(None);
    }
    let mut seen = BTreeSet::new();
    let mut result = Vec::with_capacity(units.len());
    for selected in units {
        if !seen.insert(&selected.unit_id) {
            return Ok(None);
        }
        let Some((declaration, basis)) = reader.unit(&selected.unit_id)? else {
            return Ok(None);
        };
        let Some(source) = reader.branch(&declaration.source_branch_id)? else {
            return Ok(None);
        };
        let Some(cut) = reader.cut(&declaration.source_cut_id)? else {
            return Ok(None);
        };
        if declaration.unit_id != selected.unit_id
            || basis.unit_id != selected.unit_id
            || declaration.principal != selected.principal
            || declaration.intent != selected.intent
            || basis.basis_digest != selected.basis_digest
            || basis.atoms.is_empty()
            || source.branch_id != declaration.source_branch_id
            || source.name.is_some()
            || cut.cut_id != declaration.source_cut_id
            || cut.branch_id != declaration.source_branch_id
            || cut.manifest_hash != declaration.source_manifest_hash
        {
            return Ok(None);
        }
        let handoff = reader.handoff(&selected.unit_id)?;
        let (holder_cut_id, holder_manifest_hash, handoff_op_id, proof) =
            if let Some(receipt) = handoff {
                if holder.name.is_none()
                    || source.parent_branch_id.as_deref() != Some(holder.branch_id.as_str())
                    || receipt.unit_id != selected.unit_id
                    || receipt.op_id.trim().is_empty()
                    || receipt.source_branch_id != declaration.source_branch_id
                    || receipt.source_cut_id != declaration.source_cut_id
                    || receipt.source_manifest_hash != declaration.source_manifest_hash
                    || receipt.source_basis_digest != basis.basis_digest
                    || receipt.original_principal != declaration.principal
                    || receipt.target_branch_id != holder.branch_id
                    || !ancestor(
                        reader,
                        &receipt.target_after_cut_id,
                        source_cut_id,
                        &holder.branch_id,
                    )?
                {
                    return Ok(None);
                }
                let Some(target) = reader.cut(&receipt.target_after_cut_id)? else {
                    return Ok(None);
                };
                if target.manifest_hash != receipt.target_after_manifest_hash
                    || target.parent_cut_id != receipt.target_before_cut_id
                {
                    return Ok(None);
                }
                let proof = serde_json::to_value(&receipt)?;
                (
                    receipt.target_after_cut_id,
                    receipt.target_after_manifest_hash,
                    Some(receipt.op_id),
                    proof,
                )
            } else {
                if holder.name.is_some()
                    || source.branch_id != holder.branch_id
                    || source.status != BranchStatus::Active
                    || !ancestor(
                        reader,
                        &declaration.source_cut_id,
                        source_cut_id,
                        &holder.branch_id,
                    )?
                {
                    return Ok(None);
                }
                let Some(pin) = reader.pin(&declaration.pin_id)? else {
                    return Ok(None);
                };
                if pin.pin_id != declaration.pin_id
                    || pin.twig_branch_id != declaration.source_branch_id
                    || pin.cut_id != declaration.source_cut_id
                    || pin.manifest_hash != declaration.source_manifest_hash
                    || pin.principal != declaration.principal
                    || pin.released_at.is_some()
                    || pin.released_by.is_some()
                    || pin.release_reason.is_some()
                {
                    return Ok(None);
                }
                let proof = serde_json::to_value((
                    &pin.pin_id,
                    &pin.twig_branch_id,
                    &pin.cut_id,
                    &pin.manifest_hash,
                    &pin.principal,
                    &pin.retained_at,
                ))?;
                (pin.cut_id, pin.manifest_hash, None, proof)
            };
        let facts = serde_json::to_vec(&(
            "native-unit-holder-v1",
            (
                &declaration.unit_id,
                &declaration.pin_id,
                &declaration.source_branch_id,
                &declaration.source_cut_id,
                &declaration.source_manifest_hash,
                &declaration.principal,
                &declaration.intent,
                &declaration.read_basis_digest,
                &declaration.dependency_basis_digest,
                &declaration.scope_digest,
                &declaration.declared_at,
            ),
            (
                &basis.unit_id,
                &basis.basis_digest,
                &basis.atoms,
                &basis.bound_at,
            ),
            proof,
        ))?;
        result.push(FlowingUnitHolder {
            unit_id: selected.unit_id.clone(),
            holder_branch_id: holder.branch_id.clone(),
            holder_cut_id,
            holder_manifest_hash,
            handoff_op_id,
            proof_digest: format!("sha256:{}", crate::chunking::content_hash_hex(&facts)),
        });
    }
    Ok(Some(result))
}

/// Current source holder of one unit before its parking transfer. The caller
/// serializes this read with admission and persists the returned retained cut.
fn capture_one_from(
    reader: &impl Reader,
    request: &ParkFlowingUnit,
) -> StoreResult<Option<FlowingUnitHolder>> {
    let selected = FlowingSelectedUnit {
        unit_id: request.unit_id.clone(),
        basis_digest: request.basis_digest.clone(),
        principal: request.principal.clone(),
        intent: request.intent.clone(),
        outcome: FlowingUnitOutcome::Applied,
    };
    Ok(capture_from(
        reader,
        &request.source_branch_id,
        &request.source_cut_id,
        &request.source_manifest_hash,
        &[selected],
    )?
    .and_then(|holders| holders.into_iter().next()))
}

pub fn capture_one<B: Branches + FlowingSources>(
    branches: &B,
    request: &ParkFlowingUnit,
) -> StoreResult<Option<FlowingUnitHolder>> {
    capture_one_from(&StoreReader(branches), request)
}

pub fn matches_certificate(
    current: &[FlowingUnitHolder],
    certificate: &FlowingGateCertificate,
) -> bool {
    if certificate.unit_holders.is_empty() {
        !current.is_empty() && current.iter().all(|holder| holder.handoff_op_id.is_none())
    } else {
        current == certificate.unit_holders
    }
}

#[cfg(feature = "native")]
pub(crate) fn native_capture(
    connection: &rusqlite::Connection,
    witness: &FlowingCandidateWitness,
) -> StoreResult<Option<Vec<FlowingUnitHolder>>> {
    for selected in &witness.units {
        if super::flowing_parking::native::read_by_unit(connection, &selected.unit_id)?.is_some() {
            return Ok(None);
        }
    }
    capture_from(
        &super::flowing_read::NativeReader(connection),
        &witness.source_branch_id,
        &witness.source_cut_id,
        &witness.source_manifest_hash,
        &witness.units,
    )
}

#[cfg(feature = "native")]
pub(crate) fn native_capture_one(
    connection: &rusqlite::Connection,
    request: &ParkFlowingUnit,
) -> StoreResult<Option<FlowingUnitHolder>> {
    capture_one_from(&super::flowing_read::NativeReader(connection), request)
}
