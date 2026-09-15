use std::collections::BTreeSet;
use whipplescript_parser::expression_binding_roots;

#[test]
fn package_policy_provenance_reuses_nested_expression_and_template_roots() {
    for expression in [
        r#"{ assigned_to learner.people[index.value], note "{{ author.name + suffix.value }}" }"#,
        r#"[learner.people[index.value], "{{ author.name + suffix.value }}"]"#,
    ] {
        assert_eq!(
            expression_binding_roots(expression).expect("valid nested expression"),
            BTreeSet::from(["learner", "index", "author", "suffix"].map(str::to_owned))
        );
    }
    assert!(expression_binding_roots(
        r#"{ assigned_to "person:learner", expected_assignee null }"#
    )
    .expect("valid constant expression")
    .is_empty());
}

#[test]
fn unparseable_expression_never_reports_an_empty_or_partial_provenance_set() {
    assert!(expression_binding_roots("learner +").is_err());
    assert!(
        expression_binding_roots(r#"{ invalid: learner, note: "{{ author.name }}" }"#).is_err()
    );
}
