use crate::do_store::{recovery::atomic_result, sql_err, text, DoSql, SqlValue};
use whipplescript_store::branches::resolution_batch::{
    fault, ResolutionMemoryBatch, ResolutionMemoryOutcome, ResolutionMemoryReceipt, INSERT,
    INSERT_MEMORY, SELECT, SELECT_MEMORY,
};
use whipplescript_store::StoreResult;

pub(super) fn read(
    sql: &impl DoSql,
    operation_id: &str,
) -> StoreResult<Option<ResolutionMemoryReceipt>> {
    let rows = sql.query(SELECT, &[text(operation_id)]).map_err(sql_err)?;
    match rows.as_slice() {
        [] => Ok(None),
        [row] => match row.as_slice() {
            [SqlValue::Text(json), SqlValue::Text(digest)] => {
                ResolutionMemoryReceipt::decode(operation_id, json, digest).map(Some)
            }
            _ => Err(fault(operation_id, "invalid receipt SQL row")),
        },
        _ => Err(fault(operation_id, "duplicate receipt SQL rows")),
    }
}

pub(super) fn record(
    sql: &impl DoSql,
    request: &ResolutionMemoryBatch,
) -> StoreResult<ResolutionMemoryReceipt> {
    request.validate()?;
    atomic_result(sql, false, &mut || {
        if let Some(receipt) = read(sql, &request.operation_id)? {
            return receipt.check_retry(request);
        }
        let mut outcomes = Vec::with_capacity(request.entries.len());
        for (index, entry) in request.entries.iter().enumerate() {
            let inserted = sql
                .execute(
                    INSERT_MEMORY,
                    &[
                        text(&entry.triple_key),
                        text(&entry.resolution),
                        text(&request.recorded_at),
                    ],
                )
                .map_err(sql_err)?;
            let rows = sql
                .query(SELECT_MEMORY, &[text(&entry.triple_key)])
                .map_err(sql_err)?;
            let resolution = match rows.as_slice() {
                [row] => match row.as_slice() {
                    [SqlValue::Text(value)] if !value.trim().is_empty() => value.clone(),
                    _ => return Err(fault(&request.operation_id, "invalid memory SQL row")),
                },
                _ => return Err(fault(&request.operation_id, "missing or duplicate memory")),
            };
            if inserted != 0 {
                sql.execute(
                    whipplescript_store::branches::resolution_origin::INSERT,
                    &[
                        text(&entry.triple_key),
                        text(&request.operation_id),
                        SqlValue::Int(index as i64),
                    ],
                )
                .map_err(sql_err)?;
            }
            outcomes.push(ResolutionMemoryOutcome {
                triple_key: entry.triple_key.clone(),
                resolution,
                inserted: inserted != 0,
            });
        }
        let receipt = ResolutionMemoryReceipt {
            request: request.clone(),
            outcomes,
        };
        let (json, digest) = receipt.encode()?;
        sql.execute(
            INSERT,
            &[text(&request.operation_id), text(&json), text(&digest)],
        )
        .map_err(sql_err)?;
        Ok(receipt)
    })
}

#[cfg(test)]
mod tests;
