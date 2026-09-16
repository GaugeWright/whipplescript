use super::tests::source;
use super::*;
const HEADER: &str = r#"@service
workflow Selectors
signal inbound.ready { yes bool text string }
class Flag { yes bool }
class Note { text string }
coerce flag(value bool) -> Flag { prompt "Return {{ value }}" }
coerce clean(value string) -> Note { prompt "Clean {{ value }}" }
action cross() -> null { coerce clean("constant") as result endorsed
 return null }
"#;
const VOUCH: &str = "grant signal event -> signal:inbound.ready from Reviewer";
fn policy(text: &str) -> VerifiedEnvelope {
    VerifiedEnvelope::for_test(Envelope::from_dsl(text).unwrap())
}
fn all(text: &str, envelope: &str) -> Vec<Diagnostic> {
    let analysis = source(text);
    analyze(&analysis)
        .unwrap()
        .check_source_flows(&policy(envelope), &[])
}
fn selectors(text: &str, envelope: &str) -> Vec<Diagnostic> {
    all(text, envelope)
        .into_iter()
        .filter(|e| e.code.as_str() == "security.untrusted_selector")
        .collect()
}
fn rule(body: &str) -> String {
    format!("{HEADER}rule run when inbound.ready as event => {{ {body} }}")
}
fn has_call(error: &Diagnostic, name: &str) -> bool {
    error
        .related
        .iter()
        .any(|r| r.message == format!("call to action `{name}`"))
}

#[test]
fn helper_extraction_keeps_signal_selection_and_both_call_sites() {
    let text = format!("{}\nrule later when inbound.ready as event => {{ case event.yes {{ true => {{ cross() }} false => {{}} }} }}", rule("case event.yes { true => { cross()\n cross() } false => {} }"));
    let errors = selectors(&text, "");
    assert_eq!(errors.len(), 3, "{errors:?}");
    for e in &errors {
        assert!(text[e.span.start..e.span.end].contains("coerce clean"));
        assert!(has_call(e, "cross"));
        let locations: BTreeSet<_> = e
            .related
            .iter()
            .map(|r| (r.span.start, r.span.end, &r.message))
            .collect();
        assert_eq!(locations.len(), e.related.len());
        assert!(e
            .related
            .iter()
            .any(|r| r.message == "original selector input `event`"));
        assert!(e
            .related
            .iter()
            .any(|r| text[r.span.start..r.span.end].contains("case event.yes")));
    }
    assert_ne!(errors[0].related, errors[1].related);
    assert!(all(&text, VOUCH).is_empty());
}

#[test]
fn returned_projections_and_prior_arm_guards_preserve_input_influence() {
    let text = rule("box(event.yes) as value\n case value.yes { true where event.text == \"go\" => {}\n _ => { cross() } }").replace("rule run", "action box(yes bool) -> Flag { return { yes yes } }\nrule run");
    assert_eq!(selectors(&text, "").len(), 1);
    assert!(selectors(&text, VOUCH).is_empty());
    // A constant discriminant still observes an earlier failed guard.
    let guarded = text.replace("case value.yes", "case true");
    assert_eq!(selectors(&guarded, "").len(), 1);
    let unrelated =
        rule("box(event.yes) as ignored\n case true { true => { cross() } false => {} }").replace(
            "rule run",
            "action box(yes bool) -> Flag { return { yes yes } }\nrule run",
        );
    assert!(selectors(&unrelated, "").is_empty());
}

#[test]
fn a_selector_endorsement_requires_its_own_nonpublic_matching_grant() {
    for (marker, grant, denied) in [
        (
            "endorsed",
            "grant endorse signal:inbound.ready to Reviewer",
            false,
        ),
        ("", "grant endorse signal:inbound.ready to Reviewer", true),
        ("endorsed", "", true),
        ("endorsed", "grant endorse signal:other to Reviewer", true),
        (
            "endorsed",
            "grant endorse signal:inbound.ready to public",
            true,
        ),
    ] {
        let text=rule(&format!("coerce flag(event.yes) as choice {marker}\n case choice.yes {{ true => {{ cross() }} false => {{}} }}"));
        let errors = selectors(&text, grant);
        assert_eq!(!errors.is_empty(), denied, "{marker}/{grant}: {errors:?}");
    }
}

#[test]
fn a_payload_marker_cannot_endorse_its_own_control_or_a_mixed_selector() {
    let text = rule("case event.yes { true => { coerce flag(event.yes) as choice endorsed\n case choice.yes { true => { cross() } false => {} } } false => {} }");
    assert!(!selectors(&text, "grant endorse signal:inbound.ready to Reviewer").is_empty());
    let mixed = rule("coerce flag(event.yes) as choice endorsed\n both(choice.yes, event.yes) as mixed\n case mixed { true => { cross() } false => {} }" )
    .replace("rule run", "action both(left bool, right bool) -> bool { return left && right }\nrule run");
    assert_eq!(
        selectors(&mixed, "grant endorse signal:inbound.ready to Reviewer").len(),
        1
    );
    assert_eq!(selectors(&mixed, "").len(), 1);
}

#[test]
fn messages_remain_untrusted_even_if_the_channel_is_vouched() {
    let text = rule("case event.text { \"go\" => { cross() } _ => {} }")
        .replace(
            "signal inbound.ready { yes bool text string }",
            "channel inbox",
        )
        .replace(
            "when inbound.ready as event",
            "when message from inbox as event",
        );
    assert_eq!(
        selectors(&text, "grant channel inbox -> inbox from Reviewer").len(),
        1
    );
}

#[test]
fn continuations_regions_and_failure_returns_keep_selection_sources() {
    for body in [
        "echo(event.yes) as result\n after result succeeds { cross() }",
        "during event.yes { cross() } on lapse as state { timer 1s as wait }",
        "during event.yes { timer 1s as wait } on lapse as state { cross() }",
        "fail_with(event.text) as result\n after result fails { cross() }",
    ] {
        let text=rule(body).replace("rule run", "action echo(yes bool) -> bool { return yes }\naction fail_with(text string) -> bool ! string { fail text }\nrule run");
        assert!(!selectors(&text, "").is_empty(), "{body}");
        assert!(selectors(&text, VOUCH).is_empty(), "{body}");
    }
}

#[test]
fn explicit_order_and_unused_helpers_do_not_create_data_selectors() {
    let text = rule("coerce flag(event.yes) as ignored\n then ordered <- cross()");
    assert!(selectors(&text, "").is_empty());
    let text=rule("cross()").replace("rule run", "action unused(yes bool) -> null { case yes { true => { cross() } false => {} }\n return null }\nrule run");
    assert!(selectors(&text, "").is_empty());
}

#[test]
fn pure_releases_and_claim_crossings_cannot_lose_selection() {
    let text=rule("coerce flag(true) as value\n case event.yes { true => { declassify value into Flag as released } false => {} }");
    assert_eq!(selectors(&text, "").len(), 1);
    let selector_release = rule("coerce flag(event.yes) as raw\n declassify raw into Flag as released\n case released.yes { true => { cross() } false => {} }");
    assert_eq!(selectors(&selector_release, "").len(), 1);
    let text = rule("case event.yes { true => { claim item as held endorsed } false => {} }")
        .replace(
            "class Flag",
            "tracker jobs { provider builtin }\nclass Flag",
        )
        .replace(
            "when inbound.ready as event",
            "when inbound.ready as event when jobs has ready issue as item",
        );
    assert_eq!(
        selectors(&text, "grant tracker jobs -> tracker:/jobs from Reviewer").len(),
        1
    );
}

#[test]
fn invocation_selection_checks_every_actual_destination() {
    let text=rule("case request.yes { true => { write text to first at \"out\" { body \"x\" mode upsert } as a\n write text to second at \"out\" { body \"x\" mode upsert } as b } false => {} }")
 .replace("rule run when inbound.ready as event", "input request Flag\nfile store first { root \"./first\" allow write [\"**\"] }\nfile store second { root \"./second\" allow write [\"**\"] }\nrule run when Flag as request");
    for (first, second, expected) in [
        ("Operator", "Reviewer", 1),
        ("Reviewer", "Operator", 1),
        ("Operator", "Operator", 2),
        ("Reviewer", "Reviewer", 0),
    ] {
        let envelope=format!("grant invoke incoming -> invoke:Selectors from Reviewer\ngrant file_store first -> first from {first}\ngrant file_store second -> second from {second}");
        assert_eq!(selectors(&text, &envelope).len(), expected, "{envelope}");
    }
}

#[test]
fn legacy_and_managed_crossing_refusals_share_messages() {
    let text = rule(
        "case event.yes { true => { coerce clean(event.text) as result endorsed } false => {} }",
    )
    .replace(
        "action cross() -> null { coerce clean(\"constant\") as result endorsed\n return null }",
        "",
    );
    let compiled = whipplescript_parser::compile_program(&text);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
    let legacy: Vec<_> = check_with_envelope(&ir, &policy(""))
        .into_iter()
        .filter(|e| e.code.as_str() == "security.untrusted_selector")
        .collect();
    let managed = selectors(&text, "");
    assert_eq!(legacy.len(), 1);
    assert_eq!(managed.len(), 1);
    assert_eq!(legacy[0].message, managed[0].message);
    assert_eq!(legacy[0].suggestion, managed[0].suggestion);
}

#[test]
fn resource_choice_retains_the_selecting_helpers_call_site() {
    let text=rule("choose(event.yes, left, right) as selected\n claim selected as held endorsed")
 .replace("class Flag", "tracker first { provider builtin }\ntracker second { provider builtin }\nclass Flag")
 .replace("rule run", "action choose(yes bool, left WorkItem, right WorkItem) -> WorkItem { case yes { true => { return left } false => { return right } } }\nrule run")
 .replace("when inbound.ready as event", "when inbound.ready as event when first has ready issue as left when second has ready issue as right");
    let queues="grant tracker first -> tracker:/first from Reviewer\ngrant tracker second -> tracker:/second from Reviewer";
    let errors = selectors(&text, queues);
    assert!(!errors.is_empty(), "{errors:?}");
    assert!(
        errors.iter().all(|error| has_call(error, "choose")),
        "{errors:?}"
    );
    assert!(selectors(&text, &format!("{queues}\n{VOUCH}")).is_empty());
}

#[test]
fn opaque_values_keep_possible_inputs_and_later_judgments_need_all_grants() {
    let text =
        rule("tell writer \"choose\" as choice\n case choice { \"yes\" => { cross() } _ => {} }")
            .replace(
                "class Flag",
                "agent writer { provider trusted }\nclass Flag",
            );
    assert_eq!(selectors(&text, "").len(), 1);
    assert!(selectors(&text, VOUCH).is_empty());
    let marked = text.replace(
        "case choice",
        "coerce clean(choice) as judged endorsed\n case judged.text",
    );
    assert_eq!(selectors(&marked, "").len(), 1);
    assert!(selectors(&marked, "grant endorse signal:inbound.ready to Reviewer").is_empty());
}

#[test]
fn invocation_grant_sinks_are_checked_without_a_value_payload() {
    let text=rule("case request.yes { true => { tell writer \"act\" with access to first { write [\"**\"] } with access to second { write [\"**\"] } as result } false => {} }")
 .replace("rule run when inbound.ready as event", "input request Flag\nagent writer { provider trusted }\nfile store first { root \"./first\" allow write [\"**\"] }\nfile store second { root \"./second\" allow write [\"**\"] }\nrule run when Flag as request");
    let envelope="grant invoke incoming -> invoke:Selectors from Reviewer\ngrant file_store first -> first from Operator\ngrant file_store second -> second from Operator";
    let errors = selectors(&text, envelope);
    assert_eq!(errors.len(), 2, "{errors:?}");
}

#[test]
fn malformed_selector_context_refuses_with_the_actual_crossing_location() {
    use whipplescript_parser::action_plan::NodeKind;
    let text = rule("case event.yes { true => { cross() } false => {} }");
    let analysis = source(&text);
    for corrupt_types in [true, false] {
        let mut rule = analysis.rules()[0].clone();
        if corrupt_types {
            rule.typed.case_types.clear();
        } else {
            for node in &mut rule.typed.plan.nodes {
                if let NodeKind::Case { scrutinee, .. } = &mut node.kind {
                    *scrutinee = "unknown".into();
                }
            }
        }
        let inventory = analyze(&analysis).unwrap().rules.remove(0).inventory;
        let body = RuleBodyAnalysis {
            rule: &rule,
            inventory,
        };
        let context = program_context::ProgramContext::Composition(&analysis);
        let sinks = source_inputs::local_destinations(&body, context);
        let mut errors = Vec::new();
        composition_selectors::check(&body, context, policy("").envelope(), &sinks, &mut errors);
        assert!(!errors.is_empty());
        if !corrupt_types {
            assert!(text[errors[0].span.start..errors[0].span.end].contains("coerce clean"));
            assert!(has_call(&errors[0], "cross"));
        }
    }
}

#[test]
fn each_original_signal_needs_its_own_selector_grant() {
    let text=rule("coerce flag(event.yes && other.yes) as selected endorsed\n case selected.yes { true => { cross() } false => {} }")
 .replace("class Flag", "signal other.ready { yes bool }\nclass Flag")
 .replace("when inbound.ready as event", "when inbound.ready as event when other.ready as other");
    let first = "grant endorse signal:inbound.ready to Reviewer";
    let second = "grant endorse signal:other.ready to Reviewer";
    for (grant, expected) in [
        ("".to_owned(), 2),
        (first.to_owned(), 1),
        (second.to_owned(), 1),
        (format!("{first}\n{second}"), 0),
    ] {
        assert_eq!(selectors(&text, &grant).len(), expected, "{grant}");
    }
}

#[test]
fn returned_constants_retain_the_helpers_hidden_selection() {
    let text=rule("choose(event.yes) as value\n case value.yes { true => { cross() } false => {} }")
 .replace("rule run", "action choose(yes bool) -> Flag { case yes { true => { return { yes true } } false => { return { yes false } } } }\nrule run");
    let errors = selectors(&text, "");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(has_call(&errors[0], "choose"));
    assert!(has_call(&errors[0], "cross"));
    assert!(selectors(&text, VOUCH).is_empty());
}
