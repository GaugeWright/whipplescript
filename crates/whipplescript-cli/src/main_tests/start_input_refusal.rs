//! Extracted verbatim from `main.rs` (module path `start_input_refusal_tests` is unchanged).

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
