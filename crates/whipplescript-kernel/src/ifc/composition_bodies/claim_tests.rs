use super::tests::source;
use super::*;
use whipplescript_parser::action_plan::{value_flow::Origin, NodeKind};
use whipplescript_parser::body::BodyStmt;

const HEADER: &str = r#"@service
workflow Claims
tracker review { provider builtin }
tracker other { provider builtin }
class Decision { accepted bool }
class Note { text string }
class Box { item WorkItem }
agent writer { provider trusted }
"#;
const VOUCHED: &str = "grant tracker review -> tracker:/review from Reviewer";
const RAISE: &str =
    "grant fact decision -> fact:Decision from Operator\ngrant endorse review to Operator";
fn policy(text: &str) -> VerifiedEnvelope {
    VerifiedEnvelope::for_test(Envelope::from_dsl(text).unwrap())
}
fn check(text: &str, envelope: &str) -> Vec<Diagnostic> {
    let analysis = source(text);
    analyze(&analysis)
        .unwrap()
        .check_source_flows(&policy(envelope), &[])
}
fn code<'a>(errors: &'a [Diagnostic], name: &str) -> Vec<&'a Diagnostic> {
    errors.iter().filter(|e| e.code.as_str() == name).collect()
}
fn has_call(error: &Diagnostic, name: &str) -> bool {
    error
        .related
        .iter()
        .any(|r| r.message == format!("call to action `{name}`"))
}
fn adopted(marker: &str, body: &str) -> String {
    format!("{HEADER}action adopt(item WorkItem) -> WorkItem {{ claim item as held {marker}\n return item }}\nrule run when review has ready issue as item => {{ adopt(item) as chosen\n {body} }}")
}

#[test]
fn a_claim_requires_queue_vouch_marker_and_matching_raise_grant() {
    let body = "record Decision { accepted chosen.title == \"keep\" }";
    for (marker, envelope, expected) in [
        ("endorsed", format!("{VOUCHED}\n{RAISE}"), None),
        (
            "",
            format!("{VOUCHED}\n{RAISE}"),
            Some("security.integrity_injection"),
        ),
        (
            "endorsed",
            format!("{VOUCHED}\ngrant fact decision -> fact:Decision from Operator"),
            Some("security.integrity_injection"),
        ),
        (
            "endorsed",
            format!("grant tracker review -> tracker:/review\n{RAISE}"),
            Some("security.unvouched_endorsement"),
        ),
    ] {
        let errors = check(&adopted(marker, body), &envelope);
        if let Some(expected) = expected {
            assert!(
                !code(&errors, expected).is_empty(),
                "{marker}/{envelope}: {errors:?}"
            );
        } else {
            assert!(errors.is_empty(), "{errors:?}");
        }
    }
}

#[test]
fn all_claims_and_rules_keep_distinct_helper_call_locations() {
    let text = adopted("endorsed", "adopt(item) as second");
    let text =
        format!("{text}\nrule later when other has ready issue as item => {{ adopt(item) }}");
    let errors = check(&text, "");
    assert_eq!(
        code(&errors, "security.unvouched_endorsement").len(),
        3,
        "{errors:?}"
    );
    for e in &errors {
        assert!(has_call(e, "adopt"));
        assert!(text[e.span.start..e.span.end].contains("claim item"));
    }
    assert_ne!(errors[0].related, errors[1].related);
    assert!(errors.iter().any(|e| e.message.contains("other")));
}

#[test]
fn every_possible_tracker_of_a_returned_original_item_must_be_vouched() {
    let text = format!(
        r#"{HEADER}
class Flag {{ yes bool }}
input incoming Flag
action choose(flag bool, left WorkItem, right WorkItem) -> WorkItem {{ case flag {{
 true => {{ return left }}
 false => {{ return right }}
 }} }}
action wrap(item WorkItem) -> Box {{ return {{ item item }} }}
action unbox(boxed Box) -> WorkItem {{ return boxed.item }}
action adopt(boxed Box) -> WorkItem {{ unbox(boxed) as item
 claim item as held endorsed
 return item }}
rule run when review has ready issue as left when other has ready issue as right when Flag as flag => {{
 choose(flag.yes, left, right) as selected
 wrap(selected) as boxed
 adopt(boxed)
}}
"#
    );
    for (envelope, missing) in [
        (VOUCHED, "other"),
        (
            "grant tracker other -> tracker:/other from Reviewer",
            "review",
        ),
    ] {
        let errors = check(&text, envelope);
        assert_eq!(
            code(&errors, "security.unvouched_endorsement").len(),
            1,
            "{errors:?}"
        );
        assert!(errors[0].message.contains(&format!("tracker `{missing}`")));
        assert!(has_call(&errors[0], "adopt"));
    }
    assert!(check(
        &text,
        &format!("{VOUCHED}\ngrant tracker other -> tracker:/other from Reviewer")
    )
    .is_empty());
}

#[test]
fn prior_claim_handles_preserve_the_original_marked_item() {
    let text=format!("{HEADER}rule run when review has ready issue as item => {{ claim item as first\n claim first as second endorsed\n record Decision {{ accepted item.title == \"keep\" }} }}");
    let errors = check(&text, &format!("{VOUCHED}\n{RAISE}"));
    assert!(errors.is_empty(), "{errors:?}");
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let marked = claim_endorsement::check(&bodies, &policy(VOUCHED)).unwrap();
    assert_eq!(marked["run"].len(), 1);
    assert!(marked["run"]
        .iter()
        .all(|origin| matches!(origin, Origin::Input(_))));
}

#[test]
fn filed_items_still_require_their_real_queue_authority() {
    let text=format!("{HEADER}rule run when started => {{ file issue into review {{ title \"keep\" }} as item\n claim item as held endorsed }}");
    let errors = check(&text, "");
    assert_eq!(
        code(&errors, "security.unvouched_endorsement").len(),
        1,
        "{errors:?}"
    );
    assert!(check(&text, VOUCHED).is_empty());
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let marks = claim_endorsement::check(&bodies, &policy(VOUCHED)).unwrap();
    assert_eq!(marks["run"].len(), 1);
    assert!(marks["run"]
        .iter()
        .all(|origin| matches!(origin, Origin::Operation(_))));
}

#[test]
fn a_claim_marker_neither_declassifies_nor_covers_another_items_value() {
    let text = adopted(
        "endorsed",
        "record Decision { accepted chosen.title == \"keep\" }",
    );
    let envelope =
        format!("{VOUCHED} readable by Secret\n{RAISE}\ngrant declassify review to public");
    assert_eq!(
        code(&check(&text, &envelope), "security.confidentiality_leak").len(),
        1
    );
    let mixed=format!("{HEADER}rule run when review has ready issue as first when review has ready issue as second => {{ claim first as held endorsed\n record Decision {{ accepted first.title == second.title }} }}");
    let errors = check(&mixed, &format!("{VOUCHED}\n{RAISE}"));
    assert_eq!(
        code(&errors, "security.integrity_injection").len(),
        1,
        "{errors:?}"
    );
}

#[test]
fn prose_fields_follow_named_projections_and_explicit_overrides() {
    let text=format!("{HEADER}action adopt(item WorkItem) -> Note {{ claim item as held endorsed\n return {{ text item.title }} }}\naction publish(value Note) -> null {{ record Note from value {{}}\n return null }}\nrule run when review has ready issue as item => {{ adopt(item) as value\n publish(value)\n publish(value) }}");
    let errors = check(&text, VOUCHED);
    assert_eq!(
        code(&errors, "security.endorsed_prose_field").len(),
        2,
        "{errors:?}"
    );
    for e in &errors {
        assert!(e.message.contains("Note.text"));
        assert!(has_call(e, "publish"));
        assert!(has_call(e, "adopt"));
        assert!(e
            .related
            .iter()
            .any(|related| related.message == "possible claim origin for this field"));
        assert!(text[e.span.start..e.span.end].contains("record Note"));
    }
    assert_ne!(errors[0].related, errors[1].related);
    let safe = text.replace(
        "record Note from value {}",
        "record Note from value { text \"constant\" }",
    );
    assert!(check(&safe, VOUCHED).is_empty());
}

#[test]
fn every_record_field_and_replacement_is_checked() {
    let text=format!("{HEADER}class Pair {{ fixed string text string }}\nclass Pending {{ id string }}\ninput incoming Pending\nrule run when review has ready issue as item when Pending as pending => {{ claim item as held endorsed\n record Pair {{ fixed \"constant\" text item.title }}\n done pending -> record Note {{ text item.body }} }}");
    let errors = check(&text, VOUCHED);
    let prose = code(&errors, "security.endorsed_prose_field");
    assert_eq!(prose.len(), 2, "{errors:?}");
    assert!(prose.iter().any(|e| e.message.contains("Pair.text")));
    assert!(prose.iter().any(|e| e.message.contains("Note.text")));
}

#[test]
fn closed_field_policy_applies_through_arrays_objects_and_optionals() {
    for (ty, value, denied) in [
        ("string", "chosen.title", true),
        ("string?", "chosen.title", true),
        ("string[]", "[chosen.title]", true),
        ("Inner", "{ body chosen.title }", true),
        ("bool", "chosen.title == \"keep\"", false),
        ("bool[]", "[chosen.title == \"keep\"]", false),
    ] {
        let text = adopted("endorsed", &format!("record Payload {{ value {value} }}")).replace(
            "class Note",
            &format!("class Inner {{ body string }}\nclass Payload {{ value {ty} }}\nclass Note"),
        );
        let errors = check(&text, VOUCHED);
        assert_eq!(
            !code(&errors, "security.endorsed_prose_field").is_empty(),
            denied,
            "{ty}: {errors:?}"
        );
        if !denied {
            assert!(errors.is_empty(), "{errors:?}");
        }
    }
}

#[test]
fn transformations_and_pure_release_cannot_erase_claim_influence() {
    let base = adopted(
        "endorsed",
        "coerce clean(chosen.title) as cleaned\n record Note from cleaned {}",
    )
    .replace(
        "agent writer",
        "coerce clean(value string) -> Note { prompt \"Clean {{ value }}\" }\nagent writer",
    );
    assert_eq!(
        code(&check(&base, VOUCHED), "security.endorsed_prose_field").len(),
        1
    );
    let independent = base.replace("clean(chosen.title)", "clean(\"constant\")");
    assert!(check(&independent, VOUCHED).is_empty());
    let release = adopted(
        "endorsed",
        "pack(chosen) as note\n declassify note into Note as released\n record Note from released {}",
    );
    let release = release.replace(
        "rule run",
        "action pack(item WorkItem) -> Note { return { text item.title } }\nrule run",
    );
    assert_eq!(
        code(&check(&release, VOUCHED), "security.endorsed_prose_field").len(),
        1
    );
}

#[test]
fn opaque_outputs_remain_conservative_and_unused_helpers_do_not_mark_values() {
    let opaque = adopted(
        "endorsed",
        "tell writer \"Summarize\" as text\n record Note { text text }",
    );
    assert_eq!(
        code(&check(&opaque, VOUCHED), "security.endorsed_prose_field").len(),
        1
    );
    let unused = adopted("endorsed", "record Note { text item.title }")
        .replace("adopt(item) as chosen", "timer 1s as wait");
    assert!(check(&unused, VOUCHED).is_empty());
}

#[test]
fn markers_do_not_escape_the_rule_that_contains_the_claim() {
    let text=format!("{}\nrule later when review has ready issue as item => {{ record Decision {{ accepted item.title == \"keep\" }} }}",adopted("endorsed","record Decision { accepted chosen.title == \"keep\" }"));
    let errors = check(&text, &format!("{VOUCHED}\n{RAISE}"));
    assert_eq!(
        code(&errors, "security.integrity_injection").len(),
        1,
        "{errors:?}"
    );
    assert!(errors[0].message.contains("rule `later`"));
}

#[test]
fn stale_record_context_cannot_drop_claim_field_obligations() {
    let text = adopted("endorsed", "record Note { text chosen.title }");
    let analysis = source(&text);
    for missing_class in [true, false] {
        let mut body = analysis.rules()[0].clone();
        for node in &mut body.typed.plan.nodes {
            if let NodeKind::Statement(statement) = &mut node.kind {
                if let BodyStmt::Record(record) = statement.as_mut() {
                    if missing_class {
                        record.schema = "Missing".into();
                    } else {
                        record.fields[0].name = "missing".into();
                    }
                }
            }
        }
        let mut actual = analyze(&analysis).unwrap();
        let invalid = CompositionBodies {
            source: &analysis,
            rules: vec![RuleBodyAnalysis {
                rule: &body,
                inventory: actual.rules.remove(0).inventory,
            }],
        };
        let errors = claim_endorsement::check(&invalid, &policy(VOUCHED)).unwrap_err();
        assert!(
            errors.iter().any(|e| e.message.contains(if missing_class {
                "one actual class"
            } else {
                "no declared type"
            })),
            "{errors:?}"
        );
    }
}

#[test]
fn field_diagnostics_keep_all_and_only_the_attributable_claim_calls() {
    for (value, expected_calls) in [("[left.title, right.title]", 2), ("[left.title]", 1)] {
        let text = format!(
            r#"{HEADER}
class Payload {{ text string[] }}
action adopt(item WorkItem) -> WorkItem {{ claim item as held endorsed
 return item }}
rule run when review has ready issue as first when review has ready issue as second => {{
 adopt(first) as left
 adopt(second) as right
 record Payload {{ text {value} }}
}}"#
        );
        let errors = check(&text, VOUCHED);
        let prose = code(&errors, "security.endorsed_prose_field");
        assert_eq!(prose.len(), 1, "{errors:?}");
        let calls: Vec<_> = prose[0]
            .related
            .iter()
            .filter(|r| r.message == "call to action `adopt`")
            .collect();
        assert_eq!(calls.len(), expected_calls, "{errors:?}");
        let actual: BTreeSet<_> = calls.iter().map(|r| r.span.start).collect();
        let mut expected = BTreeSet::from([text.find("adopt(first)").unwrap()]);
        if expected_calls == 2 {
            expected.insert(text.find("adopt(second)").unwrap());
        }
        assert_eq!(actual, expected, "{errors:?}");
        let unique: BTreeSet<_> = prose[0]
            .related
            .iter()
            .map(|r| (r.span.start, r.span.end, &r.message))
            .collect();
        assert_eq!(unique.len(), prose[0].related.len(), "{errors:?}");
    }
}

#[test]
fn legacy_and_managed_claims_share_policy_messages() {
    let text = format!("{HEADER}rule run when review has ready issue as item => {{ claim item as held endorsed\n record Note {{ text item.title }} }}");
    let compiled = whipplescript_parser::compile_program(&text);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
    for envelope in ["", VOUCHED] {
        let verified = policy(envelope);
        let legacy = check_with_envelope_imports(&ir, &verified, &[]);
        let managed = check(&text, envelope);
        for name in [
            "security.unvouched_endorsement",
            "security.endorsed_prose_field",
        ] {
            let left = code(&legacy, name);
            let right = code(&managed, name);
            assert_eq!(left.len(), right.len(), "{legacy:?}/{managed:?}");
            for (left, right) in left.into_iter().zip(right) {
                assert_eq!(left.message, right.message);
                assert_eq!(left.suggestion, right.suggestion);
            }
        }
    }
}
