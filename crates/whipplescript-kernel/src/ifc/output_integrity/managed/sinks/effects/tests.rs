use super::super::super::tests::{check_local_sinks, compiled, policy, typed, HEADER};
use super::*;

const DECLARATIONS: &str = r#"
tracker jobs { provider builtin }
tracker other { provider builtin }
credential api { kind bearer }
channel out { provider fixture destination "test" }
file store archive { root "./archive" allow write ["**"] }
class Ticket { id string }
lease slots { key Ticket slots 1 ttl 5m }
"#;
fn context(trigger: &str) -> IrProgram {
    compiled(&format!(
        "{HEADER}{DECLARATIONS}rule run when {trigger} => {{ timer 1s as wait }}"
    ))
}
fn envelope() -> VerifiedEnvelope {
    policy("grant tracker jobs -> jobs from Operator\ngrant tracker other -> other from Operator\ngrant credential api -> credential:test/api from Operator\ngrant channel out -> smtp:out from Operator\ngrant file_store archive -> file:/archive from Operator\ngrant lease slots -> resource:slots from Operator")
}
fn plan(statement: &str) -> TypedActionPlan {
    typed(&format!(
        r#"{HEADER}{DECLARATIONS}
action produce() -> string {{ tell unsafe "draft" as raw
 return raw }}
action publish(value string) -> null {{ {statement}
 return null }}
rule run when started => {{ produce() as value
 publish(value) as sent }}"#
    ))
}
#[test]
fn managed_effect_payloads_follow_helpers_into_tracker_file_write_and_message_parts() {
    for (statement, destination) in [
        (r#"file issue into jobs { title value } as filed"#, "jobs"),
        (
            r#"file issue into jobs { title "constant" body "text {{ value }}" } as filed"#,
            "jobs",
        ),
        (
            r#"write text to archive at "{{ value }}.txt" { body "constant" mode upsert } as written"#,
            "archive",
        ),
        (
            r#"write text to archive at "fixed.txt" { body value mode upsert } as written"#,
            "archive",
        ),
        (
            r#"send via out { text "message {{ value }}" } as sent"#,
            "out",
        ),
        (
            r#"send via out { text "constant" thread_id value } as sent"#,
            "out",
        ),
    ] {
        let plan = plan(statement);
        let ir = context("started");
        let inventory = inventory(&plan, &ir).unwrap();
        assert_eq!(inventory.local.len(), 1, "{statement}");
        assert_eq!(inventory.local[0].resource, destination);
        assert_eq!(inventory.resource_payloads.len(), 1);
        assert_eq!(inventory.effects.len(), 2);
        let errors = check_local_sinks(&plan, &ir, &envelope());
        assert_eq!(errors.len(), 1, "{statement}: {errors:?}");
        assert!(errors[0].message.contains("executor `unvouched`"));
        assert!(errors[0]
            .related
            .iter()
            .any(|info| info.message == "call to action `publish`"));
    }
    // A completed owned sibling does not turn constant field text into data.
    let constant = plan(r#"file issue into jobs { title "value" } as filed"#);
    assert!(check_local_sinks(&constant, &context("started"), &envelope()).is_empty());
}
#[test]
fn managed_effect_payloads_cover_request_and_mint_url_headers_and_body() {
    for (url, headers, body) in [
        ("https://api.test/{{ value }}", "", "\"constant\""),
        (
            "https://api.test/fixed",
            "header \"X-Note\" value",
            "\"constant\"",
        ),
        ("https://api.test/fixed", "", "value"),
        ("https://api.test/fixed", "", "\"body {{ value }}\""),
    ] {
        for statement in [
            format!("request POST \"{url}\" {{ header \"Authorization\" bearer api\n {headers}\n body {body} }} as response"),
            format!("mint credential from api {{ at POST \"{url}\"\n header \"Authorization\" bearer api\n {headers}\n body {body}\n token at \"access_token\" }} as minted"),
        ] {
            let plan = plan(&statement);
            let errors = check_local_sinks(&plan, &context("started"), &envelope());
            assert_eq!(errors.len(), 1, "{statement}: {errors:?}");
            assert!(errors[0].message.contains("shapes `api`"));
        }
    }
    let constant = plan(
        r#"request POST "https://api.test/value" { header "Authorization" bearer api
 body "constant" } as response"#,
    );
    assert!(check_local_sinks(&constant, &context("started"), &envelope()).is_empty());
}
#[test]
fn managed_effect_payloads_keep_destination_selection_separate_from_endorsed_data() {
    let source = format!(
        r#"{HEADER}{DECLARATIONS}
action choose(gate string, left WorkItem, right WorkItem) -> WorkItem {{
 case gate {{ "yes" => {{ return left }} _ => {{ return right }} }} }}
rule run when jobs has ready issue as left
 when other has ready issue as right => {{ tell unsafe "choose" as raw
 choose(raw, left, right) as chosen
 coerce tidy(raw) as clean endorsed
 finish chosen {{ summary clean.value }} as finished }}"#
    );
    let plan = typed(&source);
    let ir = context("jobs has ready issue as left when other has ready issue as right");
    let inventory = inventory(&plan, &ir).unwrap();
    assert_eq!(inventory.local.len(), 2);
    assert!(inventory
        .local
        .iter()
        .all(|sink| !sink.selection.is_empty()));
    let granted = policy("grant tracker jobs -> jobs from Operator\ngrant tracker other -> other from Operator\ngrant endorse unvouched to Operator");
    let errors = check_local_sinks(&plan, &ir, &granted);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors
        .iter()
        .all(|e| e.message.contains("executor `unvouched`")));
    let direct = typed(&source.replace("choose(raw, left, right)", "choose(\"yes\", left, right)"));
    assert!(check_local_sinks(&direct, &ir, &granted).is_empty());
}
#[test]
fn managed_effect_payloads_honor_coordination_partition_and_actual_shared_usage() {
    let source = format!(
        r#"{HEADER}{DECLARATIONS}
action key() -> Ticket {{ tell unsafe "key" as raw
 return {{ id raw }} }}
rule run when started => {{ key() as key
 acquire slots for key until ttl as held }}"#
    );
    let plan = typed(&source);
    let mut ir = context("started");
    assert!(inventory(&plan, &ir).unwrap().local.is_empty());
    ir.leases[0].shared = true;
    let errors = check_local_sinks(&plan, &ir, &envelope());
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("resource:slots"));
    ir.shared_coordination_usage = vec![whipplescript_parser::IrSharedCoordinationUsage {
        resource: "resource:slots".into(),
        workflow_principals: vec!["Demo".into()],
    }];
    assert!(inventory(&plan, &ir).unwrap().local.is_empty());
    ir.shared_coordination_usage[0]
        .workflow_principals
        .push("Other".into());
    assert_eq!(check_local_sinks(&plan, &ir, &envelope()).len(), 1);
}
#[test]
fn managed_effect_payloads_distinguish_missing_coverage_and_known_empty_inputs() {
    let plan = typed(&format!(
        r#"{HEADER}{DECLARATIONS}
rule run when jobs has ready issue as item => {{ tell unsafe "text" as raw
 claim item as held
 release item
 renew held as renewed
 timer 1s as wait }}"#
    ));
    let inventory = inventory(&plan, &context("jobs has ready issue as item")).unwrap();
    assert!(inventory.local.is_empty());
    assert_eq!(inventory.effects.len(), 5);
    assert_eq!(inventory.resource_payloads.len(), 4);
    assert!(inventory.resource_payloads.values().all(Vec::is_empty));
}
#[test]
fn managed_effect_payloads_refuse_missing_destination_at_the_authored_call() {
    let mut plan = plan(
        r#"request POST "https://api.test/fixed" { header "Authorization" bearer api
 body "constant" } as response"#,
    );
    let (index, statement) = plan
        .plan
        .nodes
        .iter_mut()
        .enumerate()
        .find_map(|(i, node)| {
            let NodeKind::Statement(statement) = &mut node.kind else {
                return None;
            };
            let BodyStmt::Effect(effect) = statement.as_mut() else {
                return None;
            };
            matches!(effect.kind, BodyEffectKind::HttpRequest { .. }).then_some((i, effect))
        })
        .unwrap();
    let BodyEffectKind::HttpRequest { headers, .. } = &mut statement.kind else {
        unreachable!()
    };
    headers.clear();
    plan.effects.get_mut(&NodeId(index)).unwrap().contract =
        whipplescript_parser::effect_contract::Contract::from_statement(statement);
    let error = inventory(&plan, &context("started")).unwrap_err();
    assert!(error.message.contains("requires a resolved destination"));
    assert_eq!(error.span, plan.plan.nodes[index].span);
    assert!(error
        .related
        .iter()
        .any(|info| info.message == "call to action `publish`"));
}
#[test]
fn managed_effect_payloads_parse_authored_templates_once_and_refuse_malformed_inputs() {
    assert_eq!(
        template(r#"literal value {{ { text "}}" } }}"#)
            .unwrap()
            .len(),
        1
    );
    assert!(template("literal value").unwrap().is_empty());
    let inserted = template(r#"{{ "{{ value }}" }}"#).unwrap();
    assert_eq!(
        inserted,
        vec![Expr::Literal(ExprLiteral::String("{{ value }}".into()))]
    );
    assert!(expression("value +").is_err());
    assert!(template("{{ value").is_err());
    let field = FieldAssign {
        name: "missing".into(),
        value: FieldValue::Shorthand,
        span: SourceSpan { start: 0, end: 0 },
    };
    assert!(fields(&[field], &BTreeMap::new()).is_err());
}

#[test]
fn managed_effect_payloads_project_script_child_and_coordination_operands() {
    let plan = plan(r#"file issue into jobs { title value } as filed"#);
    let mut effect = plan
        .plan
        .nodes
        .iter()
        .find_map(|node| {
            let NodeKind::Statement(statement) = &node.kind else {
                return None;
            };
            let BodyStmt::Effect(effect) = statement.as_ref() else {
                return None;
            };
            matches!(effect.kind, BodyEffectKind::TrackerFile { .. }).then_some(effect.clone())
        })
        .unwrap();
    let expected = whipplescript_parser::parse_expression("value").unwrap();
    let field = FieldAssign {
        name: "value".into(),
        value: FieldValue::Expr {
            source: "value".into(),
            expr: expected.clone(),
        },
        span: SourceSpan { start: 0, end: 0 },
    };
    for kind in [
        BodyEffectKind::Exec {
            target: ExecTarget::RawCommand("echo {{ value }}".into()),
            parse_target: None,
            access_grants: vec![],
        },
        BodyEffectKind::Exec {
            target: ExecTarget::Capability {
                name: "script".into(),
                stdin_binding: "value".into(),
            },
            parse_target: None,
            access_grants: vec![],
        },
        BodyEffectKind::Invoke {
            workflow: "Child".into(),
            payload: vec![field.clone()],
            access_grants: vec![],
        },
        BodyEffectKind::LedgerAppend {
            ledger: "rows".into(),
            schema: "Input".into(),
            fields: vec![field.clone()],
        },
    ] {
        effect.kind = kind;
        assert_eq!(
            resource_payload(&effect, &BTreeMap::new()).unwrap(),
            Some(vec![expected.clone()])
        );
    }
    effect.kind = BodyEffectKind::CounterConsume {
        counter: "budget".into(),
        key_expr: "key".into(),
        amount_expr: "value".into(),
    };
    assert_eq!(
        resource_payload(&effect, &BTreeMap::new()).unwrap(),
        Some(vec![
            whipplescript_parser::parse_expression("key").unwrap(),
            expected,
        ])
    );
    let nested = FieldAssign {
        name: "phase".into(),
        value: FieldValue::Nested {
            schema: "Input".into(),
            fields: vec![field],
        },
        span: SourceSpan { start: 0, end: 0 },
    };
    assert_eq!(fields(&[nested], &BTreeMap::new()).unwrap().len(), 1);
    effect.kind = BodyEffectKind::FileExport {
        format: "json".into(),
        schema: "Input".into(),
        store: "archive".into(),
        path: "\"file.json\"".into(),
        predicate: None,
        mode: "upsert".into(),
    };
    assert!(resource_payload(&effect, &BTreeMap::new())
        .unwrap()
        .is_none());
}
