//! Pure managed value transformations. These bind a value in the captured
//! progression; they do not create an effect or a second persistence path.

use serde_json::{Map, Value};
use whipplescript_parser::body::BodyStmt;
use whipplescript_parser::{Expr, IrClass, IrProgram, IrSchema};

use super::arguments::{strict, Argument, FactSubjects, State};
use super::progression::{Leaf, Statement};
use crate::lowering::OwnedLowering;
use crate::rule_lowering::EvalValue;

fn pointer_token(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn projected_subjects(subjects: &FactSubjects, fields: &[String]) -> FactSubjects {
    let prefixes: Vec<_> = fields
        .iter()
        .map(|field| format!("/{}", pointer_token(field)))
        .collect();
    subjects
        .iter()
        .filter(|(path, _)| {
            prefixes
                .iter()
                .any(|prefix| *path == prefix || path.starts_with(&format!("{prefix}/")))
        })
        .map(|(path, subject)| (path.clone(), subject.clone()))
        .collect()
}

fn target_class<'a>(ir: &'a IrProgram, name: &str) -> Result<&'a IrClass, String> {
    ir.schemas
        .iter()
        .find_map(|schema| match schema {
            IrSchema::Class(class) if class.name == name => Some(class),
            _ => None,
        })
        .ok_or_else(|| "declassify projection requires a declared target class".into())
}

/// Project `redact` and `declassify` over their source value while retaining
/// the exact source, validity, and surviving subvalue-subject evidence.
pub fn project(statement: Statement<'_>, ir: &IrProgram) -> Result<Leaf, String> {
    let (source, fields, class) = match statement.body {
        BodyStmt::Redact { source, keep, .. } => (source, keep.clone(), None),
        BodyStmt::Declassify {
            source,
            target_type,
            ..
        } => {
            let class = target_class(ir, target_type)?;
            (
                source,
                class
                    .fields
                    .iter()
                    .map(|field| field.name.clone())
                    .collect(),
                Some(class),
            )
        }
        _ => return Err("value transformation projector requires redact or declassify".into()),
    };

    let input = statement.evaluate(&Expr::Path(vec![source.clone()]));
    let subjects = projected_subjects(&input.subjects, &fields);
    let selected = fields.clone();
    let mut evaluation = strict(vec![input], |mut values| {
        let value = values.remove(0);
        let Some(object) = value.as_object() else {
            return EvalValue::error(
                "managed value transformation requires a present class object",
            );
        };
        let projected: Map<String, Value> = selected
            .iter()
            .filter_map(|field| {
                object
                    .get(field)
                    .map(|value| (field.clone(), value.clone()))
            })
            .collect();
        EvalValue::Json(Value::Object(projected))
    });
    let State::Ready(payload) = &evaluation.state else {
        return Ok(Leaf::Waiting(evaluation));
    };
    if let Some(class) = class {
        let mut errors = Vec::new();
        super::records::validate_construction(ir, payload, class, &mut errors);
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
    }
    evaluation.subjects = subjects;
    let State::Ready(value) = evaluation.state else {
        unreachable!("checked ready transformation")
    };
    Ok(Leaf::Ready {
        lowering: Box::new(OwnedLowering::default()),
        value: Some(Argument {
            value,
            sources: evaluation.sources,
            subjects: evaluation.subjects,
            validity: evaluation.validity,
        }),
        work: None,
    })
}

#[cfg(test)]
mod tests;
