//! The hosted half of the carriage registry (DR-0139, FB-6): the same rows the
//! native branch store keeps, over the durable object's SQL.

use super::flowing_sources::exact_atomic;
use super::DoBranches;
use crate::do_store::{as_text, int, sql_err, text, DoSql};
use whipplescript_store::branches::carried_cuts::{
    CarriageDirection, CarriedCutRow, CarriedCuts, RecordCarriageOutcome,
};
use whipplescript_store::StoreResult;

fn read<S: DoSql>(sql: &S, digest: &str) -> StoreResult<Option<CarriedCutRow>> {
    let rows = sql
        .query(
            "SELECT record_id, kind, direction, recorded_at FROM carried_cuts \
             WHERE digest = ?1",
            &[text(digest)],
        )
        .map_err(sql_err)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let steps = sql
        .query(
            "SELECT manifest_hash FROM carried_cut_steps WHERE digest = ?1 ORDER BY step",
            &[text(digest)],
        )
        .map_err(sql_err)?;
    Ok(Some(CarriedCutRow {
        digest: digest.to_owned(),
        record_id: as_text(&row[0]),
        kind: as_text(&row[1]),
        direction: CarriageDirection::parse(&as_text(&row[2]))?,
        step_manifest_hashes: steps.iter().map(|step| as_text(&step[0])).collect(),
        recorded_at: as_text(&row[3]),
    }))
}

impl<S: DoSql> CarriedCuts for DoBranches<S> {
    fn record_carriage(&mut self, row: &CarriedCutRow) -> StoreResult<RecordCarriageOutcome> {
        let sql = &self.sql;
        exact_atomic(sql, "carried cut registry", || {
            if let Some(existing) = read(sql, &row.digest)? {
                return Ok(RecordCarriageOutcome::AlreadyRecorded(existing));
            }
            sql.execute(
                "INSERT INTO carried_cuts (digest, record_id, kind, direction, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    text(&row.digest),
                    text(&row.record_id),
                    text(&row.kind),
                    text(row.direction.as_str()),
                    text(&row.recorded_at),
                ],
            )
            .map_err(sql_err)?;
            for (step, manifest_hash) in row.step_manifest_hashes.iter().enumerate() {
                sql.execute(
                    "INSERT INTO carried_cut_steps (digest, step, manifest_hash) \
                     VALUES (?1, ?2, ?3)",
                    &[text(&row.digest), int(step as i64), text(manifest_hash)],
                )
                .map_err(sql_err)?;
            }
            Ok(RecordCarriageOutcome::Recorded)
        })
    }

    fn carriage(&self, digest: &str) -> StoreResult<Option<CarriedCutRow>> {
        read(&self.sql, digest)
    }
}
