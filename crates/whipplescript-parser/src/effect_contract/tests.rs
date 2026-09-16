use super::*;
use std::collections::BTreeSet;
fn effect(source: &str) -> body::EffectStmt {
    let (ast, errors) = body::parse_rule_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    let body::BodyStmt::Effect(effect) = ast.statements.into_iter().next().unwrap() else {
        panic!("effect")
    };
    effect
}
#[test]
fn managed_effect_contract_preserves_tell_policy_and_legacy_lowering() {
    let mut statement = effect("tell reader as turn\n with skills [\"review\", \"lint\"]\n with access to project_files { read [\"src/**\"] }\n \"Work\"");
    statement.requires = vec!["read".into(), "read".into()];
    statement.timeout_seconds = Some(5);
    let body::BodyEffectKind::Tell { on_stream, .. } = &mut statement.kind else {
        panic!("tell")
    };
    *on_stream = Some("work".into());
    let contract = Contract::from_statement(&statement);
    assert_eq!(contract.kind, IrEffectKind::AgentTell);
    assert_eq!(contract.required_capabilities, ["read"]);
    assert_eq!(contract.timeout_seconds, Some(5));
    assert_eq!(contract.on_stream.as_deref(), Some("work"));
    assert_eq!(contract.agent.as_deref(), Some("reader"));
    assert_eq!(contract.turn_skills, ["review", "lint"]);
    assert_eq!(contract.access_grants.len(), 1);
    assert_eq!(contract.access_grants[0].resource, "project_files");
    assert_eq!(contract.access_grants[0].operations[0].operation, "read");
    assert_eq!(contract.access_grants[0].operations[0].globs, ["src/**"]);
    let (legacy, edges) = collect_effects_from_ast(
        &[body::BodyStmt::Effect(statement)],
        "run",
        &BTreeMap::new(),
        &BTreeSet::new(),
    );
    assert!(edges.is_empty());
    assert_eq!(
        legacy[0].required_capabilities,
        contract.required_capabilities
    );
    assert_eq!(legacy[0].access_grants, contract.access_grants);
    assert_eq!(legacy[0].timeout_seconds, contract.timeout_seconds);
    assert_eq!(legacy[0].turn_skills, contract.turn_skills);
    assert_eq!(legacy[0].binding.as_deref(), Some("turn"));
}
#[test]
fn managed_effect_contract_keeps_bound_resources_distinct_from_absence() {
    for (source, resource) in [
        ("claim item as claim", Resource::Binding("item".into())),
        ("renew claim as renewed", Resource::Binding("claim".into())),
        ("timer 1s as wait", Resource::None),
        (
            "read text from project_files at \"note.md\" as file",
            Resource::Named("project_files".into()),
        ),
    ] {
        let contract = Contract::from_statement(&effect(source));
        assert_eq!(contract.resource, resource);
    }
    let statements = [
        body::BodyStmt::Effect(effect("claim item as claim")),
        body::BodyStmt::Effect(effect("renew claim as renewed")),
    ];
    let bindings = [
        ("item".into(), "queue".into()),
        ("claim".into(), "queue".into()),
    ]
    .into();
    let (legacy, _) = collect_effects_from_ast(&statements, "run", &bindings, &BTreeSet::new());
    assert_eq!(legacy[0].resources, ["queue"]);
    assert_eq!(legacy[1].resources, ["queue"]);
    assert_eq!(legacy[1].kind, IrEffectKind::TrackerRenew);
}
#[test]
fn managed_effect_contract_keeps_crossings_and_implicit_call_capabilities() {
    let mut statement = effect("coerce classify(\"text\") as result");
    let body::BodyEffectKind::Coerce {
        endorsed,
        declassified,
        ..
    } = &mut statement.kind
    else {
        panic!("coerce")
    };
    *endorsed = true;
    *declassified = true;
    let contract = Contract::from_statement(&statement);
    assert!(contract.endorsed && contract.declassified);
    assert_eq!(contract.coerce_target.as_deref(), Some("classify"));
    let contract = Contract::from_statement(&effect("call memory.query for text as result"));
    assert_eq!(contract.required_capabilities, ["memory.query"]);
}
