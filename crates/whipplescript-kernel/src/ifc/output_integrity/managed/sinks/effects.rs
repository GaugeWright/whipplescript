//! Resource-write payload projection. `None` records incomplete coverage;
//! `Some(empty)` is a known empty payload, still subject to selection policy.
use super::*;
use whipplescript_parser::body::{
    BodyEffectKind, EffectStmt, ExecTarget, FieldAssign, RequestHeaderValue,
};
use whipplescript_parser::managed_template::{self, Segment};

fn template(text: &str) -> Result<Vec<Expr>, Box<Diagnostic>> {
    Ok(managed_template::parse(text)
        .map_err(|message| incomplete(&message))?
        .into_iter()
        .filter_map(|segment| match segment {
            Segment::Expression { expr, .. } => Some(expr),
            Segment::Text(_) => None,
        })
        .collect())
}
// Only an authored string in a template position is interpolated. A path's
// resulting string and strings inside the interpolation are ordinary values.
fn authored(expr: &Expr) -> Result<Vec<Expr>, Box<Diagnostic>> {
    match expr {
        Expr::Literal(ExprLiteral::String(text)) => template(text),
        expr => Ok(vec![expr.clone()]),
    }
}
fn expression(source: &str) -> Result<Vec<Expr>, Box<Diagnostic>> {
    let expr =
        whipplescript_parser::parse_expression(source).map_err(|message| incomplete(&message))?;
    authored(&expr)
}
fn fields(
    fields: &[FieldAssign],
    env: &whipplescript_parser::action_plan::Environment,
) -> Result<Vec<Expr>, Box<Diagnostic>> {
    let mut result = Vec::new();
    for field in fields {
        // Reuse construction's constructor/shorthand validation before walking
        // nested field blocks; do not treat a constructor name as a binding.
        let expr = field
            .record_expression(None, &|name| env.contains_key(name))
            .map_err(|message| incomplete(&message))?;
        match &field.value {
            FieldValue::Nested { fields: nested, .. } => result.extend(self::fields(nested, env)?),
            _ => result.extend(authored(&expr)?),
        }
    }
    Ok(result)
}

pub(super) fn resource_payload(
    effect: &EffectStmt,
    env: &whipplescript_parser::action_plan::Environment,
) -> Result<Option<Vec<Expr>>, Box<Diagnostic>> {
    let payload = match &effect.kind {
        BodyEffectKind::TrackerFile { fields: values, .. }
        | BodyEffectKind::TrackerFinish { fields: values, .. }
        | BodyEffectKind::LedgerAppend { fields: values, .. }
        | BodyEffectKind::Invoke {
            payload: values, ..
        } => fields(values, env)?,
        BodyEffectKind::FileWrite { path, body, .. } => {
            let mut payload = expression(path)?;
            payload.extend(expression(body)?);
            payload
        }
        BodyEffectKind::HttpRequest {
            url, headers, body, ..
        }
        | BodyEffectKind::MintCredential {
            url, headers, body, ..
        } => {
            let mut payload = template(url)?;
            for header in headers {
                if let RequestHeaderValue::Expr { expr, .. } = &header.value {
                    payload.extend(authored(expr)?);
                }
            }
            if let Some((_, expr)) = body {
                payload.extend(authored(expr)?);
            }
            payload
        }
        BodyEffectKind::ConstructCapabilityCall {
            keyword, fields, ..
        } if keyword == "send" => {
            let mut payload = Vec::new();
            for field in fields.iter().filter(|field| field.name != "channel") {
                payload.extend(expression(&field.source)?);
            }
            payload
        }
        BodyEffectKind::Exec { target, .. } => match target {
            ExecTarget::RawCommand(command) => template(command)?,
            ExecTarget::Capability { stdin_binding, .. } => expression(stdin_binding)?,
        },
        BodyEffectKind::LeaseAcquire { key_expr, .. } => expression(key_expr)?,
        BodyEffectKind::CounterConsume {
            key_expr,
            amount_expr,
            ..
        } => {
            let mut payload = expression(key_expr)?;
            payload.extend(expression(amount_expr)?);
            payload
        }
        BodyEffectKind::RotateCredential { .. }
        | BodyEffectKind::RevokeCredential { .. }
        | BodyEffectKind::TrackerClaim { .. }
        | BodyEffectKind::TrackerRelease { .. }
        | BodyEffectKind::LeaseRenew { .. }
        | BodyEffectKind::Timer { .. } => Vec::new(),
        // These need provider/package, collection, signal, ingestion or
        // escalation contracts beyond a resource-write payload projection.
        BodyEffectKind::Tell { .. }
        | BodyEffectKind::Coerce { .. }
        | BodyEffectKind::Prompt { .. }
        | BodyEffectKind::Decide { .. }
        | BodyEffectKind::Call { .. }
        | BodyEffectKind::ConstructCapabilityCall { .. }
        | BodyEffectKind::Notify { .. }
        | BodyEffectKind::ObtainCredential { .. }
        | BodyEffectKind::FileRead { .. }
        | BodyEffectKind::FileImport { .. }
        | BodyEffectKind::FileExport { .. } => return Ok(None),
    };
    Ok(Some(payload))
}

#[cfg(test)]
mod tests;
