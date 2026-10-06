use super::flowing_sources::exact_atomic;
use super::{flowing_fence, DoBranches};
use crate::do_store::{as_text, sql_err, text, DoSql, SqlValue};
use whipplescript_store::branches::flowing_admission::FlowingAdmissions;
use whipplescript_store::branches::flowing_fence::{FlowingFenceAction, FlowingFenceTransition};
use whipplescript_store::branches::flowing_holders;
use whipplescript_store::branches::flowing_parking::{
    missing_field, receipt_matches_keys, FlowingParkOutcome, FlowingParkReceipt,
    FlowingParkRefusal, FlowingParking, ParkFlowingUnit,
};
use whipplescript_store::branches::BranchStatus;
use whipplescript_store::{StoreError, StoreResult};

fn parse_receipt<S: DoSql>(sql: &S, row: &[SqlValue]) -> StoreResult<FlowingParkReceipt> {
    let unit_id = as_text(&row[0]);
    let op_id = as_text(&row[1]);
    let holder_id = as_text(&row[2]);
    let receipt: FlowingParkReceipt = serde_json::from_str(&as_text(&row[3]))?;
    if !receipt_matches_keys(&receipt, &unit_id, &op_id)
        || receipt.request.parked_holder_id != holder_id
    {
        return Err(StoreError::Conflict(
            "flowing park receipt differs from its ref keys".into(),
        ));
    }
    let cuts = sql
        .query(
            "SELECT branch_id, manifest_hash FROM cuts WHERE cut_id = ?1",
            &[text(&receipt.former_holder.holder_cut_id)],
        )
        .map_err(sql_err)?;
    if !cuts.first().is_some_and(|cut| {
        as_text(&cut[0]) == receipt.former_holder.holder_branch_id
            && as_text(&cut[1]) == receipt.former_holder.holder_manifest_hash
    }) {
        return Err(StoreError::Conflict(
            "flowing parked holder lost its retained cut".into(),
        ));
    }
    Ok(receipt)
}

fn read_receipt<S: DoSql>(
    sql: &S,
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
    sql.query(query, &[text(key)])
        .map_err(sql_err)?
        .first()
        .map(|row| parse_receipt(sql, row))
        .transpose()
}

impl<S: DoSql> FlowingParking for DoBranches<S> {
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
        exact_atomic(&self.sql, "flowing unit parking", || {
            if let Some(existing) = read_receipt(&self.sql, "op_id", &request.op_id)? {
                return Ok(if existing.request == *request {
                    Existing(existing)
                } else {
                    Refused(R::IdentityMismatch)
                });
            }
            let admitted = self
                .sql
                .query(
                    "SELECT op_id FROM flowing_admitted_units WHERE unit_id = ?1",
                    &[text(&request.unit_id)],
                )
                .map_err(sql_err)?;
            if let Some(row) = admitted.first() {
                let receipt = self
                    .flowing_admission_receipt(&as_text(&row[0]))?
                    .ok_or_else(|| {
                        StoreError::Conflict("admitted flowing unit lost its receipt".into())
                    })?;
                return Ok(AlreadyAdmitted(receipt));
            }
            if let Some(existing) = read_receipt(&self.sql, "unit_id", &request.unit_id)? {
                return Ok(AlreadyParked(existing));
            }
            let Some(source) = self.row_by_id(&request.source_branch_id)? else {
                return Ok(Refused(R::SourceMissing));
            };
            if source.status != BranchStatus::Active {
                return Ok(Refused(R::SourceNotActive));
            }
            if source.head_cut_id.as_deref() != Some(request.source_cut_id.as_str())
                || source.head_manifest_hash.as_deref()
                    != Some(request.source_manifest_hash.as_str())
            {
                return Ok(Refused(R::SourceMoved));
            }
            let Some(fence) = flowing_fence::read_state(&self.sql, &request.source_branch_id)?
            else {
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
            if !self
                .sql
                .query(
                    "SELECT op_id FROM flowing_source_fence_ops WHERE op_id = ?1",
                    &[text(&request.op_id)],
                )
                .map_err(sql_err)?
                .is_empty()
            {
                return Ok(Refused(R::IdentityMismatch));
            }
            let Some(former_holder) = flowing_holders::capture_one(self, request)? else {
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
            self.sql
                .execute(
                    "INSERT INTO flowing_parked_units (unit_id, op_id, holder_id, receipt_json) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        text(&request.unit_id),
                        text(&request.op_id),
                        text(&request.parked_holder_id),
                        text(&serde_json::to_string(&receipt)?),
                    ],
                )
                .map_err(sql_err)?;
            self.sql
                .execute(
                    "UPDATE flowing_source_fences SET state_json = ?2 WHERE source_branch_id = ?1",
                    &[
                        text(&request.source_branch_id),
                        text(&serde_json::to_string(&receipt.source_fence_after)?),
                    ],
                )
                .map_err(sql_err)?;
            self.sql
                .execute(
                    "INSERT INTO flowing_source_fence_ops (op_id, request_json, state_json) VALUES (?1, ?2, ?3)",
                    &[
                        text(&request.op_id),
                        text(&serde_json::to_string(&transition)?),
                        text(&serde_json::to_string(&receipt.source_fence_after)?),
                    ],
                )
                .map_err(sql_err)?;
            Ok(Parked(receipt))
        })
    }

    fn parked_flowing_unit(&self, unit_id: &str) -> StoreResult<Option<FlowingParkReceipt>> {
        read_receipt(&self.sql, "unit_id", unit_id)
    }

    fn flowing_park_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingParkReceipt>> {
        read_receipt(&self.sql, "op_id", op_id)
    }

    fn parked_holder_units(&self, holder_id: &str) -> StoreResult<Vec<FlowingParkReceipt>> {
        let rows = self
            .sql
            .query(
                "SELECT unit_id, op_id, holder_id, receipt_json FROM flowing_parked_units WHERE holder_id = ?1 ORDER BY unit_id",
                &[text(holder_id)],
            )
            .map_err(sql_err)?;
        rows.iter()
            .map(|row| parse_receipt(&self.sql, row))
            .collect()
    }
}
