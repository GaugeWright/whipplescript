use super::tests::source;
use super::*;

const HEADER: &str = "@service\nworkflow Dependencies\nclass A { id string }\nclass B { id string }\nclass C { id string }\n";
fn edges(text: &str) -> Vec<(String, String, String)> {
    let analysis = source(text);
    let bodies = analyze(&analysis).unwrap();
    bodies
        .rule_dependencies()
        .iter()
        .map(|edge| {
            (
                edge.producer.clone(),
                edge.consumer.clone(),
                edge.fact.clone(),
            )
        })
        .collect()
}
fn expected(entries: &[(&str, &str, &str)]) -> Vec<(String, String, String)> {
    let mut result: Vec<_> = entries
        .iter()
        .map(|(p, c, f)| (p.to_string(), c.to_string(), f.to_string()))
        .collect();
    result.sort();
    result
}
fn legacy_edges(text: &str) -> Vec<(String, String, String)> {
    let compiled = whipplescript_parser::compile_program(text);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
    ir.rule_dependencies
        .into_iter()
        .map(|e| (e.producer, e.consumer, e.fact))
        .collect()
}

#[test]
fn table_records_replacements_and_self_edges_match_the_legacy_graph() {
    let text = format!("{HEADER}table seed as A [{{ id \"one\" }}]\nrule last when B as item => {{ record C {{ id item.id }} }}\nrule middle when A as item => {{ done item -> record B {{ id item.id }} }}\nrule self_copy when C as item => {{ record C {{ id item.id }} }}");
    let actual = edges(&text);
    assert_eq!(
        actual,
        expected(&[
            ("table_seed", "middle", "schema:A"),
            ("middle", "last", "schema:B"),
            ("last", "self_copy", "schema:C"),
            ("self_copy", "self_copy", "schema:C"),
        ])
    );
    assert_eq!(actual, legacy_edges(&text));
}

#[test]
fn nested_extraction_and_repeated_calls_preserve_the_complete_rule_graph() {
    let tail = "rule unused_target when C as item => {}\nrule last when B as item => {}\nrule first when A as item => { BODY }\nrule back when B as item => { record A { id item.id } }";
    let inline = format!(
        "{HEADER}{}",
        tail.replace("BODY", "record B { id item.id }\nrecord B { id item.id }")
    );
    let extracted = format!("{HEADER}action unused() -> null {{ record C {{ id \"unused\" }}\nreturn null }}\naction leaf(item A) -> null {{ record B {{ id item.id }}\nreturn null }}\naction wrapper(item A) -> null {{ leaf(item)\nreturn null }}\n{}",tail.replace("BODY","wrapper(item)\nwrapper(item)"));
    assert_eq!(edges(&extracted), edges(&inline));
    assert_eq!(
        edges(&extracted),
        expected(&[
            ("back", "first", "schema:A"),
            ("first", "back", "schema:B"),
            ("first", "last", "schema:B"),
        ])
    );
    assert_eq!(edges(&inline), legacy_edges(&inline));
}

#[test]
fn explicit_fact_triggers_share_class_keys_without_reclassifying_runtime_observers() {
    let text = format!("{HEADER}rule producer when started => {{ record A {{ id \"a\" }} }}\nrule explicit when fact A as item => {{}}\nrule ordinary when A as item => {{}}\nclass Able {{ id string }}\nrule prefix when Able as item => {{}}\nrule runtime when fact agent.turn.completed as event => {{}}");
    assert_eq!(
        edges(&text),
        expected(&[
            ("producer", "explicit", "schema:A"),
            ("producer", "ordinary", "schema:A"),
        ])
    );
    assert_eq!(edges(&text), legacy_edges(&text));
}

const TRACKERS: &str = "tracker jobs { provider builtin }\ntracker other { provider builtin }\nclass Box { item WorkItem }\n";

#[test]
fn file_and_release_create_availability_but_claim_renew_and_finish_do_not() {
    for (body, produces) in [
        ("file issue into jobs { title \"new\" } as filed", true),
        ("release item", true),
        ("claim item as held\nrenew held as renewed\nfinish item { summary \"done\" } as finished", false),
    ] {
        let text = format!("{HEADER}{TRACKERS}rule consume when jobs has ready issue as next => {{}}\nrule produce when jobs has ready issue as item => {{ {body} }}");
        let wanted = if produces { expected(&[("produce","consume","tracker:jobs"),("produce","produce","tracker:jobs")]) } else { vec![] };
        assert_eq!(edges(&text), wanted, "{body}");
        assert_eq!(edges(&text), legacy_edges(&text), "{body}");
    }
}

#[test]
fn returned_original_items_preserve_every_possible_queue_destination() {
    let text = format!("{HEADER}{TRACKERS}action choose(left WorkItem, right WorkItem, yes bool) -> WorkItem {{ case yes {{ true => {{ return left }} false => {{ return right }} }} }}\naction wrap(item WorkItem) -> Box {{ return {{ item item }} }}\naction unwrap(boxed Box) -> WorkItem {{ return boxed.item }}\naction put_back(boxed Box) -> null {{ unwrap(boxed) as item\nrelease item\nreturn null }}\nrule left when jobs has ready issue as item => {{}}\nrule right when other has ready issue as item => {{}}\nrule run when jobs has ready issue as a\nwhen other has ready issue as b => {{ choose(a,b,true) as selected\nwrap(selected) as boxed\nput_back(boxed) }}");
    assert_eq!(
        edges(&text),
        expected(&[
            ("run", "left", "tracker:jobs"),
            ("run", "right", "tracker:other"),
            ("run", "run", "tracker:jobs"),
            ("run", "run", "tracker:other"),
        ])
    );
}

#[test]
fn declared_channel_sends_couple_to_receivers_through_helpers() {
    let declarations = "channel inbox { provider fixture destination \"test\" }\nchannel other { provider fixture destination \"test\" }\n";
    let tail = "rule receive when message from inbox as msg => {}\nrule unrelated when message from other as msg => {}\nrule send_it when started => { BODY }";
    let inline = format!(
        "{HEADER}{declarations}{}",
        tail.replace("BODY", "send via inbox { text \"hello\" } as sent")
    );
    let extracted = format!("{HEADER}{declarations}action send_message() -> null {{ send via inbox {{ text \"hello\" }} as sent\nreturn null }}\n{}",tail.replace("BODY","send_message()"));
    assert_eq!(
        edges(&extracted),
        expected(&[("send_it", "receive", "channel:inbox")])
    );
    assert_eq!(edges(&extracted), edges(&inline));
    assert_eq!(edges(&inline), legacy_edges(&inline));
}

#[test]
fn branches_continuations_and_lapse_arms_all_contribute_possible_writes() {
    let text = format!("{HEADER}class Flag {{ yes bool }}\naction make(yes bool) -> null {{ case yes {{ true => {{ record A {{ id \"a\" }} }} false => {{ timer 1s as wait\nafter wait succeeds {{ record B {{ id \"b\" }} }} }} }}\nreturn null }}\nrule run when Flag as flag => {{ make(flag.yes)\nduring flag.yes {{}} on lapse as stopped {{ record C {{ id \"c\" }} }} }}\nrule a when A as item => {{}}\nrule b when B as item => {{}}\nrule c when C as item => {{}}");
    assert_eq!(
        edges(&text),
        expected(&[
            ("run", "a", "schema:A"),
            ("run", "b", "schema:B"),
            ("run", "c", "schema:C")
        ])
    );
}

#[test]
fn ingestion_helpers_contribute_schema_writes() {
    let text = format!("{HEADER}file store docs {{ root \"./docs\" allow read [\"**\"] }}\naction load() -> null {{ import json A from docs at \"rows.json\" as rows\nreturn null }}\nrule use_rows when A as row => {{}}\nrule load_rows when started => {{ load() }}");
    assert_eq!(
        edges(&text),
        expected(&[("load_rows", "use_rows", "schema:A")])
    );
}

#[test]
fn activation_edges_do_not_reclassify_guard_observations_or_statement_order() {
    let text = format!("{HEADER}rule observe when started where exists(A) => {{ timer 1s as first\nthen second <- timer 1s }}\nrule write when started => {{ record A {{ id \"a\" }} }}");
    assert!(edges(&text).is_empty());
}

#[test]
fn rule_order_does_not_truncate_backward_or_cyclic_dependencies() {
    let rules = [
        "rule a when A as item => { record B { id item.id } }",
        "rule b when B as item => { record C { id item.id } }",
        "rule c when C as item => { record A { id item.id } }",
    ];
    let forward = format!("{HEADER}{}", rules.join("\n"));
    let backward = format!(
        "{HEADER}{}",
        rules.into_iter().rev().collect::<Vec<_>>().join("\n")
    );
    assert_eq!(
        edges(&forward),
        expected(&[
            ("a", "b", "schema:B"),
            ("b", "c", "schema:C"),
            ("c", "a", "schema:A")
        ])
    );
    assert_eq!(edges(&forward), edges(&backward));
}
