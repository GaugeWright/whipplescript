//! Ordinary workflow start-input validation, shared with deterministic actions.
use crate::rule_lowering::{ir_type_name, validate_json_for_ir_type};
use serde_json::Value;
use std::collections::BTreeMap;
use whipplescript_parser::{IrProgram, IrType, IrWorkflowContract, IrWorkflowContractKind};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowInputFact {
    pub name: String,
    pub key: String,
    pub value_json: String,
}

pub fn validate_workflow_start_input(
    ir: &IrProgram,
    input: &Value,
) -> Result<Vec<WorkflowInputFact>, String> {
    let contracts = ir
        .workflow_contracts
        .iter()
        .filter(|contract| contract.kind == IrWorkflowContractKind::Input)
        .collect::<Vec<_>>();
    if contracts.is_empty() {
        return Ok(Vec::new());
    }
    // A readable shape hint, e.g. `{ "ticket": <ref<TicketRequest>> }`, so a caller
    // who omits the input-name nesting can see the expected object at a glance.
    let expected_shape = format!(
        "{{ {} }}",
        contracts
            .iter()
            .map(|contract| format!("\"{}\": <{}>", contract.name, contract.ty.display_label()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let Some(object) = input.as_object() else {
        return Err(format!(
            "workflow `{}` expects an input object keyed by declared input names: {expected_shape}",
            ir.workflow,
        ));
    };

    let mut errors = Vec::new();
    let contracts_by_name = contracts
        .iter()
        .map(|contract| (contract.name.as_str(), *contract))
        .collect::<BTreeMap<_, _>>();
    for key in object.keys() {
        if !contracts_by_name.contains_key(key.as_str()) {
            errors.push(format!("unexpected workflow input `{key}`"));
        }
    }

    let mut facts = Vec::new();
    for contract in contracts {
        let Some(value) = object.get(&contract.name) else {
            errors.push(format!(
                "missing workflow input `{}` (expected `{}`)",
                contract.name,
                contract.ty.display_label()
            ));
            continue;
        };
        validate_json_for_ir_type(ir, value, &contract.ty, &contract.name, &mut errors);
        facts.push(WorkflowInputFact {
            name: workflow_input_fact_name(contract),
            key: contract.name.clone(),
            value_json: value.to_string(),
        });
    }

    if errors.is_empty() {
        Ok(facts)
    } else {
        Err(format!(
            "invalid workflow input for `{}`: {}; expected input object {expected_shape}",
            ir.workflow,
            errors.join("; "),
        ))
    }
}

fn workflow_input_fact_name(contract: &IrWorkflowContract) -> String {
    match &contract.ty {
        IrType::Ref(name) => name.clone(),
        other => ir_type_name(other),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_workflow_start_input;
    use serde_json::json;
    use whipplescript_parser::{compile_program, IrProgram};

    /// The entry side of the admission boundary: `whip run --input` hands a
    /// caller's JSON to `validate_workflow_start_input`, which holds the workflow's
    /// declared inputs closed. A mutation sweep found its unexpected-input
    /// rejection unexercised, so a caller could name a key the workflow never
    /// declared and have it accepted in silence.
    fn ir() -> IrProgram {
        let compiled = compile_program(
            r#"
    workflow Start
    input task Task
    output result R
    class Task { id string }
    class R { ok bool }
    rule r
      when Task as t
    => { complete result { ok true } }
    "#,
        );
        assert!(
            compiled.diagnostics.is_empty(),
            "fixture must compile: {:?}",
            compiled.diagnostics
        );
        compiled.ir.expect("ir")
    }

    #[test]
    fn an_undeclared_input_key_is_refused() {
        let error = validate_workflow_start_input(&ir(), &json!({"task": {"id": "1"}, "extra": 1}))
            .expect_err("an undeclared input key must be refused");
        assert!(
            error.contains("unexpected workflow input `extra`"),
            "{error}"
        );
    }

    #[test]
    fn a_non_object_input_is_refused() {
        let error = validate_workflow_start_input(&ir(), &json!("not an object"))
            .expect_err("a non-object input must be refused");
        assert!(
            error.contains("expects an input object keyed by declared input names"),
            "{error}"
        );
    }

    /// The accept case: without it, a validator refusing every input would satisfy
    /// both rejections above.
    #[test]
    fn a_declared_input_is_accepted() {
        let facts = validate_workflow_start_input(&ir(), &json!({"task": {"id": "1"}}))
            .expect("a declared input resolves");
        assert_eq!(facts.len(), 1);
    }

    #[test]
    fn a_missing_declared_input_is_refused() {
        let error = validate_workflow_start_input(&ir(), &json!({})).expect_err("missing input");
        assert!(error.contains("missing workflow input `task`"), "{error}");
    }

    #[test]
    fn a_declared_input_with_the_wrong_field_type_is_refused() {
        assert!(validate_workflow_start_input(&ir(), &json!({"task": {"id": 1}})).is_err());
    }
}
