use super::*;
use crate::action_plan::resolved::{resolve_rule_types, TypedActionPlan};
use crate::{parse_program, Item};
const HEADER: &str = "workflow Demo\nagent reader { provider mock capabilities [\"read\"] }\nagent writer { provider mock capabilities [\"read\", \"write\"] }\n";
fn resolve(source: &str) -> TypedActionPlan {
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    resolve_rule_types(&parsed.program, "run").unwrap()
}
fn source() -> String {
    format!("{HEADER}action work(target AgentRef<reader | writer>) -> null {{\n case target {{\n reader => {{ tell target requires [\"read\"] \"Read\" as turn }}\n writer => {{ tell target requires [\"write\"] \"Write\" as turn }}\n }}\nreturn null\n}}\nrule run when started => {{ work(reader) as first\nwork(writer) as second }}")
}
#[test]
fn managed_effect_contract_targets_follow_generated_branches_and_repeated_calls() {
    let mut program = parse_program(&source()).program;
    for item in &mut program.items {
        let body = match item {
            Item::Action(a) => &mut a.body,
            Item::Rule(r) => &mut r.body,
            _ => continue,
        };
        *body = crate::BlockSource::generated(
            body.text.to_string(),
            crate::SourceSpan { start: 0, end: 0 },
        );
    }
    let typed = resolve_rule_types(&program, "run").unwrap();
    assert_eq!(typed.effects.len(), 4);
    typed.validate_structure().unwrap();
    for effect in typed.effects.values() {
        let capability = effect.contract.required_capabilities[0].as_str();
        assert_eq!(
            effect.agent_targets,
            Some(vec![if capability == "read" {
                "reader".into()
            } else {
                assert_eq!(capability, "write");
                "writer".into()
            }])
        );
        assert_eq!(effect.contract.agent.as_deref(), Some("target"));
    }
}
#[test]
fn managed_effect_contract_refuses_unknown_or_unauthorized_targets_in_unused_helpers() {
    for target in ["missing", "reader"] {
        let source = format!("{HEADER}action unused() -> null {{ tell {target} requires [\"write\"] \"Work\"\nreturn null }}\nrule run when started => {{ timer 1s as wait }}");
        assert!(resolve_rule_types(&parse_program(&source).program, "run").is_err());
    }
}
#[test]
fn managed_effect_contract_requires_exact_policy_domain_and_effect_coverage() {
    let typed = resolve(&source());
    for which in 0..6 {
        let mut bad = typed.clone();
        let first = *bad.effects.keys().next().unwrap();
        match which {
            0 => {
                bad.effects.remove(&first);
            }
            1 => {
                let effect = bad.effects[&first].clone();
                bad.effects.insert(NodeId(999), effect);
            }
            2 => bad
                .effects
                .get_mut(&first)
                .unwrap()
                .contract
                .required_capabilities
                .clear(),
            3 => bad.effects.get_mut(&first).unwrap().agent_targets = None,
            4 => {
                bad.effects.get_mut(&first).unwrap().agent_targets =
                    Some(vec!["writer".into(), "reader".into()])
            }
            _ => bad.effects.get_mut(&first).unwrap().agent_targets = Some(vec!["".into()]),
        }
        assert!(bad.validate_structure().is_err(), "mutation {which}");
    }
    let mut timer = resolve("workflow Demo\nrule run when started => { timer 1s as wait }");
    timer.effects.values_mut().next().unwrap().agent_targets = Some(vec!["reader".into()]);
    assert!(timer.validate_structure().is_err());
}
#[test]
fn managed_effect_contract_requires_the_actual_resource_binding() {
    let source = "workflow Demo\ntracker jobs { provider builtin }\nrule run when jobs has ready issue as item => { claim item as claimed\nrenew claimed as renewed }";
    let typed = resolve(source);
    assert_eq!(typed.effects.len(), 2);
    for effect in typed.effects.values() {
        assert!(effect.resource_subject.is_some());
    }
    let mut bad = typed.clone();
    bad.effects.values_mut().next().unwrap().resource_subject = None;
    assert!(bad
        .validate_structure()
        .unwrap_err()
        .contains("resource subject"));
    let bad_source = source.replace("claim item", "claim unknown");
    assert!(
        resolve_rule_types(&parse_program(&bad_source).program, "run")
            .unwrap_err()
            .iter()
            .any(|d| d.message.contains("lexical subject"))
    );
}
#[test]
fn managed_effect_contract_collection_cannot_default_a_missing_checked_domain() {
    let parsed = parse_program(&format!(
        "{HEADER}rule run when started => {{ tell reader \"Read\" }}"
    ))
    .program;
    let rule = parsed
        .items
        .iter()
        .find_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .unwrap();
    let expanded = super::super::expand(&[], super::super::Entry::Rule(rule, &[])).unwrap();
    assert!(collect(&expanded.plan, &expanded.sites, &BTreeMap::new())
        .unwrap_err()
        .iter()
        .any(|d| d.message.contains("checked agent domain")));
}

#[test]
fn managed_effect_contract_retains_a_checked_empty_domain_for_unreachable_fallback() {
    let source = format!(
        "{HEADER}action work(target AgentRef<reader | writer>) -> null {{
        case target {{
            reader => {{ tell target requires [\"read\"] \"Read\" }}
            writer => {{ tell target requires [\"write\"] \"Write\" }}
            _ => {{ tell target \"Unreachable\" }}
        }}
        return null
    }}
    rule run when started => {{ work(reader) as result }}"
    );
    let typed = resolve(&source);
    typed.validate_structure().unwrap();
    assert_eq!(typed.effects.len(), 3);
    assert_eq!(
        typed
            .effects
            .values()
            .filter(|effect| effect.agent_targets == Some(vec![]))
            .count(),
        1
    );
}
