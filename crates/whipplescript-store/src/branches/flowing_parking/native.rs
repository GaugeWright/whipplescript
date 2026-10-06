use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    missing_field, receipt_matches_keys, FlowingParkOutcome, FlowingParkReceipt,
    FlowingParkRefusal, FlowingParking, ParkFlowingUnit,
};
use crate::branches::flowing_fence::{self, FlowingFenceAction, FlowingFenceTransition};
use crate::branches::{flowing_admission, flowing_holders, BranchStatus, BranchStore};
use crate::{StoreError, StoreResult};

fn parse_receipt(
    connection: &Connection,
    (unit_id, op_id, holder_id, json): (String, String, String, String),
) -> StoreResult<FlowingParkReceipt> {
    let receipt: FlowingParkReceipt = serde_json::from_str(&json)?;
    if !receipt_matches_keys(&receipt, &unit_id, &op_id)
        || receipt.request.parked_holder_id != holder_id
    {
        return Err(StoreError::Conflict(
            "flowing park receipt differs from its ref keys".into(),
        ));
    }
    let cut = BranchStore::cut_by_id(connection, &receipt.former_holder.holder_cut_id)?;
    if !cut.is_some_and(|cut| {
        cut.branch_id == receipt.former_holder.holder_branch_id
            && cut.manifest_hash == receipt.former_holder.holder_manifest_hash
    }) {
        return Err(StoreError::Conflict(
            "flowing parked holder lost its retained cut".into(),
        ));
    }
    Ok(receipt)
}

fn read_receipt(
    connection: &Connection,
    column: &str,
    key: &str,
) -> StoreResult<Option<FlowingParkReceipt>> {
    let query = match column {
        "op_id" => "SELECT unit_id, op_id, holder_id, receipt_json FROM flowing_parked_units WHERE op_id = ?1",
        "unit_id" => {
            "SELECT unit_id, op_id, holder_id, receipt_json FROM flowing_parked_units WHERE unit_id = ?1"
        }
        _ => unreachable!("fixed parking receipt lookup"),
    };
    let row: Option<(String, String, String, String)> = connection
        .query_row(query, [key], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .optional()?;
    row.map(|row| parse_receipt(connection, row)).transpose()
}

pub(crate) fn read_by_unit(
    connection: &Connection,
    unit_id: &str,
) -> StoreResult<Option<FlowingParkReceipt>> {
    read_receipt(connection, "unit_id", unit_id)
}

impl FlowingParking for BranchStore {
    fn park_flowing_unit(&mut self, request: &ParkFlowingUnit) -> StoreResult<FlowingParkOutcome> {
        use FlowingParkOutcome::{AlreadyAdmitted, AlreadyParked, Existing, Parked, Refused};
        use FlowingParkRefusal as R;
        if let Some(field) = missing_field(request) {
            return Ok(Refused(R::Invalid { field }));
        }
        if request.expected_eligibility_epoch < 0 || request.expected_owner_epoch < 0 {
            return Ok(Refused(R::Invalid {
                field: "expected_epoch",
            }));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_receipt(&tx, "op_id", &request.op_id)? {
            return Ok(if existing.request == *request {
                Existing(existing)
            } else {
                Refused(R::IdentityMismatch)
            });
        }
        let admitted_op: Option<String> = tx
            .query_row(
                "SELECT op_id FROM flowing_admitted_units WHERE unit_id = ?1",
                [&request.unit_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(op_id) = admitted_op {
            let receipt =
                flowing_admission::native::read_receipt(&tx, &op_id)?.ok_or_else(|| {
                    StoreError::Conflict("admitted flowing unit lost its receipt".into())
                })?;
            return Ok(AlreadyAdmitted(receipt));
        }
        if let Some(existing) = read_by_unit(&tx, &request.unit_id)? {
            return Ok(AlreadyParked(existing));
        }
        let Some(source) = BranchStore::row_by_id(&tx, &request.source_branch_id)? else {
            return Ok(Refused(R::SourceMissing));
        };
        if source.status != BranchStatus::Active {
            return Ok(Refused(R::SourceNotActive));
        }
        if source.head_cut_id.as_deref() != Some(request.source_cut_id.as_str())
            || source.head_manifest_hash.as_deref() != Some(request.source_manifest_hash.as_str())
        {
            return Ok(Refused(R::SourceMoved));
        }
        let Some(fence) = flowing_fence::native::read_state(&tx, &request.source_branch_id)? else {
            return Ok(Refused(R::SourceMissing));
        };
        if fence.incarnation_id != request.source_incarnation_id {
            return Ok(Refused(R::WrongIncarnation));
        }
        if fence.eligibility_epoch != request.expected_eligibility_epoch {
            return Ok(Refused(R::StaleEligibilityEpoch {
                current: fence.eligibility_epoch,
            }));
        }
        if fence.owner_epoch != request.expected_owner_epoch {
            return Ok(Refused(R::StaleOwnerEpoch {
                current: fence.owner_epoch,
            }));
        }
        if fence.owner != request.actor {
            return Ok(Refused(R::WrongOwner));
        }
        if fence.revision.is_some() {
            return Ok(Refused(R::RevisionPending));
        }
        let op_taken: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM flowing_source_fence_ops WHERE op_id = ?1)",
            [&request.op_id],
            |row| row.get(0),
        )?;
        if op_taken {
            return Ok(Refused(R::IdentityMismatch));
        }
        let Some(former_holder) = flowing_holders::native_capture_one(&tx, request)? else {
            return Ok(Refused(R::UnitHolderUnavailable));
        };
        if former_holder.holder_branch_id != request.source_branch_id {
            return Ok(Refused(R::UnitNotHeldBySource));
        }
        let Some(next_epoch) = fence.eligibility_epoch.checked_add(1) else {
            return Ok(Refused(R::EpochExhausted));
        };
        let mut source_fence_after = fence;
        source_fence_after.eligibility_epoch = next_epoch;
        let transition = FlowingFenceTransition {
            op_id: request.op_id.clone(),
            source_branch_id: request.source_branch_id.clone(),
            incarnation_id: request.source_incarnation_id.clone(),
            expected_eligibility_epoch: request.expected_eligibility_epoch,
            expected_owner_epoch: request.expected_owner_epoch,
            actor: request.actor.clone(),
            action: FlowingFenceAction::InvalidateEligibility {
                reason: format!("park-unit:{}", request.unit_id),
            },
            recorded_at: request.recorded_at.clone(),
        };
        let receipt = FlowingParkReceipt {
            request: request.clone(),
            former_holder,
            source_fence_after,
        };
        tx.execute(
            "INSERT INTO flowing_parked_units (unit_id, op_id, holder_id, receipt_json) VALUES (?1, ?2, ?3, ?4)",
            params![
                &request.unit_id,
                &request.op_id,
                &request.parked_holder_id,
                serde_json::to_string(&receipt)?
            ],
        )?;
        tx.execute(
            "UPDATE flowing_source_fences SET state_json = ?2 WHERE source_branch_id = ?1",
            params![
                &request.source_branch_id,
                serde_json::to_string(&receipt.source_fence_after)?
            ],
        )?;
        tx.execute(
            "INSERT INTO flowing_source_fence_ops (op_id, request_json, state_json) VALUES (?1, ?2, ?3)",
            params![
                &request.op_id,
                serde_json::to_string(&transition)?,
                serde_json::to_string(&receipt.source_fence_after)?,
            ],
        )?;
        tx.commit()?;
        Ok(Parked(receipt))
    }

    fn parked_flowing_unit(&self, unit_id: &str) -> StoreResult<Option<FlowingParkReceipt>> {
        read_by_unit(&self.connection, unit_id)
    }

    fn flowing_park_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingParkReceipt>> {
        read_receipt(&self.connection, "op_id", op_id)
    }

    fn parked_holder_units(&self, holder_id: &str) -> StoreResult<Vec<FlowingParkReceipt>> {
        let mut statement = self.connection.prepare(
            "SELECT unit_id, op_id, holder_id, receipt_json FROM flowing_parked_units WHERE holder_id = ?1 ORDER BY unit_id",
        )?;
        let rows = statement
            .query_map([holder_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|row| parse_receipt(&self.connection, row))
            .collect()
    }
}
