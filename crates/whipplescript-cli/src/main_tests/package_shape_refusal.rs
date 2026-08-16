//! Extracted verbatim from `main.rs` (module path `package_shape_refusal_tests` is unchanged).

use super::{
    validate_package_lock_source_shape, validate_package_set_closed_shape,
    validate_package_type_name, PACKAGE_SET_SCHEMA,
};
use serde_json::{json, Value};

/// The package-set and lock shape validators are closed: an unexpected field,
/// a wrong type, or a missing required key must be refused, because these
/// files name the code a program is allowed to load. A mutation sweep found
/// none of their refusals exercised — every caller fed them a well-formed
/// document, so deleting any single rejection changed nothing observable.
///
/// Table-driven rather than one test per rejection: the rejections are one
/// family (this field, this type, this key), so a table states the contract
/// in a form that stays readable as the shape grows. Each row is verified to
/// fail on its own.
fn valid_set() -> Value {
    json!({
        "schema": PACKAGE_SET_SCHEMA,
        "packages": [
            {"name": "notes", "source": {"type": "path", "path": "packages/notes.json"}}
        ],
    })
}

fn problems_for(value: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    validate_package_set_closed_shape(value, &mut problems);
    problems
}

#[test]
fn a_well_formed_package_set_is_accepted() {
    // The accept case. Without it, a validator that refused everything would
    // satisfy every rejection below.
    assert_eq!(problems_for(&valid_set()), Vec::<String>::new());
}

#[test]
fn the_package_set_shape_is_closed() {
    let mut set;
    let cases: Vec<(Value, &str)> = vec![
        (json!("not an object"), "package set must be a JSON object"),
        (
            json!({"packages": []}),
            "package set must have a `schema` string",
        ),
        (
            json!({"schema": "whip.packages/v99", "packages": []}),
            "package set schema must be",
        ),
        (
            {
                set = valid_set();
                set["extra"] = json!(1);
                set.clone()
            },
            "package set has unexpected field `extra`",
        ),
        (
            json!({"schema": PACKAGE_SET_SCHEMA}),
            "package set must have a `packages` array",
        ),
        (
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": {}}),
            "package set `packages` must be an array",
        ),
        (
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": ["nope"]}),
            "must be an object",
        ),
        (
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": [
                {"name": "n", "source": {"type": "path", "path": "p"}, "extra": 1}
            ]}),
            "has unexpected field `extra`",
        ),
        (
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": [
                {"name": "", "source": {"type": "path", "path": "p"}}
            ]}),
            "name must be a non-empty string",
        ),
        (
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": [
                {"name": "n", "source": "nope"}
            ]}),
            "source must be an object",
        ),
        (
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": [
                {"name": "n", "source": {"type": "path", "path": "p", "extra": 1}}
            ]}),
            "source has unexpected field `extra`",
        ),
        (
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": [
                {"name": "n", "source": {"type": "git", "path": "p"}}
            ]}),
            "source.type must be `path`",
        ),
        (
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": [
                {"name": "n", "source": {"type": 5, "path": "p"}}
            ]}),
            "source.type must be a non-empty string",
        ),
        (
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": [
                {"name": "n", "source": {"type": "path", "path": ""}}
            ]}),
            "source.path must be a non-empty string",
        ),
    ];

    for (value, expected) in cases {
        let problems = problems_for(&value);
        assert!(
            problems.iter().any(|p| p.contains(expected)),
            "expected `{expected}`, got {problems:?}"
        );
    }
}

/// The lock's source block carries the same closed shape, in its own
/// validator. Both are checked, because covering one would leave the other
/// exactly as unexercised as the sweep found it.
#[test]
fn the_lock_source_shape_is_closed() {
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({"source": "nope"}),
            "field `source` must be an object",
        ),
        (
            json!({"source": {"type": "path", "path": "p", "extra": 1}}),
            "source has unexpected field `extra`",
        ),
        (
            json!({"source": {"type": "git", "path": "p"}}),
            "source.type must be `path`",
        ),
        (
            json!({"source": {"type": 5, "path": "p"}}),
            "source.type must be a non-empty string",
        ),
        (
            json!({"source": {"type": "path", "path": ""}}),
            "source.path must be a non-empty string",
        ),
        // Containment: a lock may only name a path inside the project.
        (
            json!({"source": {"type": "path", "path": "../outside/notes.json"}}),
            "source.path must be a portable project-relative path",
        ),
        (
            json!({"source": {"type": "path", "path": "/etc/passwd"}}),
            "source.path must be a portable project-relative path",
        ),
    ];
    for (value, expected) in cases {
        let mut problems = Vec::new();
        validate_package_lock_source_shape(&value, "package `notes`", &mut problems);
        assert!(
            problems.iter().any(|p| p.contains(expected)),
            "expected `{expected}`, got {problems:?}"
        );
    }

    let mut problems = Vec::new();
    validate_package_lock_source_shape(
        &json!({"source": {"type": "path", "path": "packages/notes.json"}}),
        "package `notes`",
        &mut problems,
    );
    assert_eq!(problems, Vec::<String>::new());
}

#[test]
fn a_package_output_type_rejects_the_wrong_json_and_an_unknown_name() {
    let mut errors = Vec::new();
    validate_package_type_name(&json!("x"), "int", "$", &mut errors);
    assert!(errors.iter().any(|e| e.contains("must be")), "{errors:?}");

    let mut errors = Vec::new();
    validate_package_type_name(&json!("x"), "widget", "$", &mut errors);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("unsupported package output type")),
        "{errors:?}"
    );

    let mut errors = Vec::new();
    validate_package_type_name(&json!(1), "int", "$", &mut errors);
    assert_eq!(errors, Vec::<String>::new());
}
