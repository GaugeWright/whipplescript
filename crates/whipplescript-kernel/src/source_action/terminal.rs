//! Authored workflow terminals are pure candidates until the root owned-work
//! join closes. The existing rule commit owns terminal events and discharge.
use super::{
    arguments::{strict, State},
    journal::Frame,
    progression::{Leaf, Statement},
};
use crate::lowering::{OwnedLowering, OwnedWorkflowTerminal};
use whipplescript_parser::{
    body::{BodyStmt, FieldValue, RecordStmt, TerminalKind},
    IrProgram, IrSchema, IrType, IrWorkflowContractKind,
};
use whipplescript_store::WorkflowTerminalKind;

fn ready(lowering: OwnedLowering) -> Leaf {
    Leaf::Ready {
        lowering: Box::new(lowering),
        value: None,
        work: None,
    }
}

pub fn project(statement: Statement<'_>, ir: &IrProgram, frame: &Frame) -> Result<Leaf, String> {
    let BodyStmt::Terminal(terminal) = statement.body else {
        // MUTATION-SUCCESS-EXPR: Ok(ready(OwnedLowering::default()))
        return Err("terminal projector requires a workflow terminal".into());
    };
    if statement.root_rule != Some(frame.rule.as_str())
        || !ir.rules.iter().any(|rule| rule.name == frame.rule)
    {
        // MUTATION-SUCCESS-EXPR: Ok(ready(OwnedLowering::default()))
        return Err("managed workflow terminal requires its pinned calling rule".into());
    }
    let (kind, wanted) = match terminal.kind {
        TerminalKind::Complete => (
            WorkflowTerminalKind::Completed,
            IrWorkflowContractKind::Output,
        ),
        TerminalKind::Fail => (
            WorkflowTerminalKind::Failed,
            IrWorkflowContractKind::Failure,
        ),
    };
    let contracts: Vec<_> = ir
        .workflow_contracts
        .iter()
        .filter(|contract| contract.kind == wanted && contract.name == terminal.name)
        .collect();
    let [contract] = contracts.as_slice() else {
        // MUTATION-SUCCESS-EXPR: Ok(ready(OwnedLowering::default()))
        return Err("managed workflow terminal requires exactly one matching contract".into());
    };
    let mut constructed_class = None;
    let value = if let Some(value) = &terminal.scalar {
        if !terminal.fields.is_empty() || terminal.from.is_some() {
            // MUTATION-SUCCESS-EXPR: Ok(ready(OwnedLowering::default()))
            return Err("workflow terminal mixes a value with field construction".into());
        }
        let FieldValue::Expr { expr, .. } = value else {
            // MUTATION-SUCCESS-EXPR: Ok(ready(OwnedLowering::default()))
            return Err("workflow terminal value must be a managed expression".into());
        };
        strict(vec![statement.evaluate(expr)], |mut values| {
            crate::rule_lowering::EvalValue::Json(values.remove(0))
        })
    } else {
        let IrType::Ref(name) = &contract.ty else {
            // MUTATION-SUCCESS-EXPR: Ok(ready(OwnedLowering::default()))
            return Err("workflow terminal field block requires a class contract".into());
        };
        let Some(class) = ir.schemas.iter().find_map(|schema| match schema {
            IrSchema::Class(class) if &class.name == name => Some(class),
            _ => None,
        }) else {
            // MUTATION-SUCCESS-EXPR: Ok(ready(OwnedLowering::default()))
            return Err("workflow terminal class is absent".into());
        };
        constructed_class = Some(class);
        let mut fields = std::collections::BTreeSet::new();
        if terminal
            .fields
            .iter()
            .any(|field| !fields.insert(&field.name))
        {
            // MUTATION-SUCCESS-EXPR: Ok(ready(OwnedLowering::default()))
            return Err("workflow terminal duplicates a field".into());
        }
        super::records::payload(
            &RecordStmt {
                schema: name.clone(),
                from: terminal.from.clone(),
                fields: terminal.fields.clone(),
                span: terminal.span,
            },
            class,
            &statement,
        )
    };
    let State::Ready(payload) = &value.state else {
        return Ok(Leaf::Waiting(value));
    };
    let mut errors = Vec::new();
    if let Some(class) = constructed_class {
        super::records::validate_construction(ir, payload, class, &mut errors);
    } else {
        crate::rule_lowering::validate_json_for_ir_type(
            ir,
            payload,
            &contract.ty,
            "$",
            &mut errors,
        );
    }
    if !errors.is_empty() {
        let details = errors.join("; ");
        // MUTATION-SUCCESS-EXPR: Ok(ready(OwnedLowering::default()))
        return Err(format!("workflow terminal violates contract: {details}"));
    }
    let payload_json = payload.to_string();
    let validity_json = serde_json::to_string(&value.validity)
        .expect("managed validity serialization is infallible");
    let key = crate::idempotency_key(&[
        "source-workflow-terminal-v1",
        &statement.identity,
        kind.action(),
        &terminal.name,
        &payload_json,
    ]);
    Ok(ready(OwnedLowering {
        terminal: Some(OwnedWorkflowTerminal {
            kind,
            name: terminal.name.clone(),
            payload_json,
            validity_json: Some(validity_json),
            idempotency_key: key,
        }),
        ..Default::default()
    }))
}

#[cfg(test)]
mod tests;
