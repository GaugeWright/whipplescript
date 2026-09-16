use super::*;
use whipplescript_parser::action_plan::analysis::{analyze_composition, CompositionAnalysis};
use whipplescript_parser::Expr;
pub(super) fn source(text: &str) -> CompositionAnalysis {
    let parsed = whipplescript_parser::parse_program(text);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    analyze_composition(&parsed.program).unwrap()
}
#[test]
fn inventories_actual_composition_rules_and_table_seeders() {
    let text = r#"@service
workflow Bodies
class Ticket { title string }
class Result { title string }
table seed as Ticket [{ title "one" }]
action publish(x Ticket) -> null { record Result { title x.title }
 return null }
rule run when Ticket as item => { publish(item) }
rule idle when started => { timer 1s as wait }
"#;
    let analysis = source(text);
    let bodies = analyze(&analysis).unwrap_or_else(|errors| panic!("{errors:?}"));
    assert!(std::ptr::eq(bodies.source(), &analysis));
    assert_eq!(bodies.rules().len(), 3);
    assert_eq!(
        bodies
            .rules()
            .iter()
            .map(|r| r.rule.root.name.name.as_str())
            .collect::<Vec<_>>(),
        ["table_seed", "run", "idle"]
    );
    assert_eq!(bodies.rules()[0].inventory.local[0].resource, "fact:Ticket");
    assert_eq!(bodies.rules()[1].inventory.local[0].resource, "fact:Result");
    assert_eq!(bodies.rules()[2].inventory.effects.len(), 1);
    for (body, rule) in bodies.rules().iter().zip(analysis.rules()) {
        assert!(std::ptr::eq(body.rule, rule));
        assert_eq!(body.inventory.effects.len(), rule.typed.effects.len());
    }
}

#[test]
fn inventories_actual_tracker_roots_and_nested_resource_values() {
    let analysis = source(
        r#"@service
workflow Bodies
tracker jobs { provider builtin }
class Box { item WorkItem }
action wrap(item WorkItem) -> Box { return { item item } }
action unwrap(boxed Box) -> WorkItem { return boxed.item }
action finish_it(item WorkItem) -> null { finish item { summary item.title } as finished
 return null }
rule run when jobs has ready issue as item => {
 wrap(item) as boxed
 unwrap(boxed) as original
 finish_it(original)
 claim original as held
 renew held as renewed
 release original
}"#,
    );
    let bodies = analyze(&analysis).unwrap();
    let inventory = &bodies.rules()[0].inventory;
    assert_eq!(inventory.effects.len(), 4);
    assert!(inventory
        .effects
        .values()
        .all(|e| e.resources == BTreeSet::from(["jobs".into()])));
    assert_eq!(inventory.local.len(), 1);
    assert_eq!(inventory.local[0].resource, "jobs");
    assert_eq!(inventory.resource_payloads.len(), 4);
    assert_eq!(
        inventory
            .resource_payloads
            .values()
            .filter(|p| p.is_empty())
            .count(),
        3
    );
}

#[test]
fn inventories_payload_projections_replacements_and_real_tool_boundaries() {
    let text = r#"workflow Bodies
class Ticket { title string }
class Result { title string }
output result Result
action publish(x Ticket) -> Result {
 record Result from x {}
 emit milestone "drafted" of Result { title x.title }
 return { title x.title }
}
rule run when Ticket as item => {
 publish(item) as result
 done item -> record Result { title result.title }
 complete result from result {}
}"#;
    for tool in [false, true] {
        let analysis = source(&format!("{}{text}", if tool { "@tool\n" } else { "" }));
        let bodies = analyze(&analysis).unwrap();
        let inventory = &bodies.rules()[0].inventory;
        let mut resources: Vec<_> = inventory
            .local
            .iter()
            .map(|s| s.resource.as_str())
            .collect();
        resources.sort();
        assert_eq!(
            resources,
            if tool {
                vec!["fact:Result", "fact:Result", "milestone:drafted"]
            } else {
                vec!["fact:Result", "fact:Result", "milestone:drafted", "result"]
            }
        );
        assert!(inventory
            .local
            .iter()
            .any(|sink| sink.resource == "fact:Result"
                && sink.payload == vec![Expr::Path(vec!["x".into(), "title".into()])]));
        assert_eq!(inventory.package_terminals.len(), usize::from(tool));
        let terminal = if tool {
            &inventory.package_terminals[0]
        } else {
            inventory
                .local
                .iter()
                .find(|sink| sink.resource == "result")
                .unwrap()
        };
        assert_eq!(
            terminal.payload,
            vec![Expr::Path(vec!["result".into(), "title".into()])]
        );
    }
}

#[test]
fn invalid_resource_in_a_sibling_refuses_the_entire_body_inventory() {
    let text = r#"@service
workflow Bodies
class Ticket { queue string id string title string }
action finish_it(item Ticket) -> null { finish item as finished
 return null }
rule good when started => { timer 1s as wait }
rule bad when Ticket as item => { finish_it(item) }
rule also_bad when Ticket as item => { finish_it(item) }
"#;
    let analysis = source(text);
    let errors = match analyze(&analysis) {
        Ok(_) => panic!("non-tracker value admitted"),
        Err(errors) => errors,
    };
    assert_eq!(errors.len(), 2, "{errors:?}");
    for error in &errors {
        assert!(
            text[error.span.start..error.span.end].contains("finish item"),
            "{error:?}"
        );
        assert!(error
            .related
            .iter()
            .any(|r| r.message == "call to action `finish_it`"));
    }
    assert_ne!(errors[0].related, errors[1].related);
}

fn provider_source(tools: bool) -> String {
    let tools = if tools { "tools [Fetcher]" } else { "" };
    format!(
        r#"@service
workflow Bodies
agent safe {{ provider trusted_model profile "reader" capacity 1 {tools} }}
agent unsafe {{ provider public_model profile "reader" capacity 1 {tools} }}
file store secret {{ root "./secret" allow read ["**"] }}
action work(target AgentRef<safe | unsafe>) -> null {{
 tell target as turn
 with access to secret {{ read ["**"] }}
 "Read"
 return null
}}
action wrap(target AgentRef<safe | unsafe>) -> null {{ work(target)
 return null }}
rule first when started => {{ wrap(safe) }}
rule second when started => {{ wrap(unsafe) }}
"#
    )
}
fn policy(clear_public: bool) -> VerifiedEnvelope {
    let public = if clear_public {
        ", \"public_model\": { \"reader\": \"confidential\" }"
    } else {
        ""
    };
    VerifiedEnvelope::for_test(Envelope::from_json(&format!(r#"{{ "resources": {{ "secret": {{ "confidential": true }}, "trusted_model": {{ "reader": "confidential" }} {public} }} }}"#)).unwrap())
}
#[test]
fn provider_egress_uses_actual_declarations_and_preserves_all_call_traces() {
    let text = provider_source(false);
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    for body in bodies.rules() {
        assert_eq!(body.inventory.effects.len(), 1);
        assert!(
            body.inventory.resource_payloads.is_empty(),
            "tell remains an uncovered resource-payload obligation"
        );
    }
    let errors = bodies.check_provider_egress(&policy(false), &[]);
    assert_eq!(errors.len(), 2, "{errors:?}");
    for error in &errors {
        assert_eq!(error.code.as_str(), "security.provider_egress_leak");
        assert!(error.message.contains("public_model"));
        assert!(text[error.span.start..error.span.end].contains("tell target"));
        for action in ["work", "wrap"] {
            for label in [
                format!("action `{action}` defined here"),
                format!("call to action `{action}`"),
            ] {
                let location = error.related.iter().find(|r| r.message == label).unwrap();
                assert!(text[location.span.start..location.span.end].contains(action));
            }
        }
    }
    assert_ne!(errors[0].related, errors[1].related);
    assert!(bodies.check_provider_egress(&policy(true), &[]).is_empty());
}
#[test]
fn provider_import_obligations_require_the_actual_complete_tool_program() {
    let text = provider_source(true).replace(" with access to secret { read [\"**\"] }\n", "");
    let analysis = source(&text);
    let bodies = analyze(&analysis).unwrap();
    let compiled = whipplescript_parser::compile_program(
        r#"@tool
workflow Fetcher {
 input request Req
 output result R
 class Req { id string }
 class R { data string }
 file store secret { root "./secret" allow read ["**"] }
 rule fetch when Req as request => {
  read text from secret at "in.txt" as loaded
  after loaded succeeds as value { complete result { data value.content } }
 }
}"#,
    );
    let tool = compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
    for imports in [vec![], vec![tool.clone(), tool.clone()]] {
        let errors = bodies.check_provider_egress(&policy(true), &imports);
        assert!(!errors.is_empty());
        assert!(
            errors
                .iter()
                .all(|e| e.message.contains("exactly one imported program")),
            "{errors:?}"
        );
    }
    let errors = bodies.check_provider_egress(&policy(false), std::slice::from_ref(&tool));
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors
        .iter()
        .all(|e| e.message.contains("tool `Fetcher`") && e.message.contains("secret")));
    assert!(bodies
        .check_provider_egress(&policy(true), &[tool])
        .is_empty());
}

#[test]
fn body_resources_match_each_actual_root_and_keep_local_census() {
    let analysis = source(
        r#"@service
workflow Bodies
tracker jobs { provider builtin }
tracker other { provider builtin }
class Key { id string }
lease slots { shared key Key slots 1 ttl 5m }
action finish_it(item WorkItem) -> null { finish item as finished
 return null }
action acquire_it(key Key) -> null { acquire slots for key until ttl as held
 return null }
rule first when jobs has ready issue as item => { finish_it(item) }
rule second when other has ready issue as item => { finish_it(item) }
rule acquire when Key as key => { acquire_it(key) }
"#,
    );
    let bodies = analyze(&analysis).unwrap();
    for (body, resource) in bodies
        .rules()
        .iter()
        .zip(["jobs", "other", "resource:slots"])
    {
        assert_eq!(body.inventory.effects.len(), 1);
        assert!(body
            .inventory
            .effects
            .values()
            .all(|e| e.resources == BTreeSet::from([resource.into()])));
    }
    assert_eq!(
        analysis.shared_coordination_usage()[0].workflow_principals,
        ["workflow:local/Bodies"]
    );
    assert!(
        bodies.rules()[2].inventory.local.is_empty(),
        "one-principal coordination is partitioned by the existing policy"
    );
    assert_eq!(bodies.rules()[2].inventory.resource_payloads.len(), 1);
}
