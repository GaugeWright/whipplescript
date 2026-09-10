use crate::do_store::{sql_err, text, DoSql, SqlValue};
use whipplescript_store::branches::resolution_batch::fault;
use whipplescript_store::branches::resolution_origin::{decode, ResolutionObservation, SELECT};
use whipplescript_store::StoreResult;

pub(super) fn read(sql: &impl DoSql, key: &str) -> StoreResult<ResolutionObservation> {
    let rows = sql.query(SELECT, &[text(key)]).map_err(sql_err)?;
    let decoded = match rows.as_slice() {
        [row] => match row.as_slice() {
            [content, operation, index, json, digest] => {
                let text = |value: &SqlValue| match value {
                    SqlValue::Null => Some(None),
                    SqlValue::Text(value) => Some(Some(value.clone())),
                    _ => None,
                };
                let index = match index {
                    SqlValue::Null => Some(None),
                    SqlValue::Int(value) => Some(Some(*value)),
                    _ => None,
                };
                text(content)
                    .zip(text(operation))
                    .zip(index)
                    .zip(text(json))
                    .zip(text(digest))
            }
            _ => None,
        },
        _ => None,
    };
    let Some(((((content, operation), index), json), digest)) = decoded else {
        return Err(fault(key, "invalid resolution origin SQL row"));
    };
    decode(
        key,
        content.as_deref(),
        operation.as_deref(),
        index,
        json.as_deref(),
        digest.as_deref(),
    )
}

#[cfg(test)]
mod tests;
