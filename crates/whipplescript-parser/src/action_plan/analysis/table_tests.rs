use super::*;
use crate::{compile_program, parse_program, BodyOrigin, IrRecordSource};

fn parse(source: &str) -> Program {
    let result = parse_program(source);
    assert!(
        result.diagnostics.is_empty(),
        "{source}: {:?}",
        result.diagnostics
    );
    result.program
}
const HEADER: &str = "@service\nworkflow Tables\nclass Ticket { title string }\naction value() -> int { return 1 }\n";

#[test]
fn tables_enter_the_same_analysis_in_source_order_with_actual_row_provenance() {
    let source = format!(
        r#"{HEADER}
rule before when started => {{ value() as result }}
@fixture
description "Two seed rows"
table seed as Ticket [{{ title "one" }} {{ title "two" }}]
rule between when Ticket as ticket => {{ done ticket }}
table extra as Ticket [{{ title "three" }}]
rule last when started => {{}}
"#
    );
    let program = parse(&source);
    let before = program.clone();
    let analysis = analyze_composition(&program).unwrap();
    assert_eq!(program, before, "analysis never rewrites the author's AST");
    assert_eq!(
        analysis
            .rules()
            .iter()
            .map(|rule| rule.root.name.name.as_str())
            .collect::<Vec<_>>(),
        ["before", "table_seed", "between", "table_extra", "last"]
    );
    let tables: Vec<_> = program
        .items
        .iter()
        .filter_map(|item| {
            if let Item::Table(table) = item {
                Some(table)
            } else {
                None
            }
        })
        .collect();
    let semantic = SemanticContext::from_program(&program, BTreeMap::new());
    let prepared = tables::prepare_rules(&program, &semantic, &mut Vec::new());
    let mut materialized = program.clone();
    materialized
        .items
        .retain(|item| !matches!(item, Item::Table(_) | Item::Rule(_)));
    materialized
        .items
        .extend(prepared.iter().map(|rule| Item::Rule(rule.rule.clone())));
    let legacy_source = source
        .replace("action value() -> int { return 1 }\n", "")
        .replace("value() as result", "");
    let compiled = compile_program(&legacy_source);
    let legacy = compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
    assert_eq!(
        legacy.rules[1].body,
        "record Ticket {\n  title \"one\"\n}\n\nrecord Ticket {\n  title \"two\"\n}\n"
    );
    for (index, table) in [(1, tables[0]), (3, tables[1])] {
        let rule = &analysis.rules()[index];
        let provenance = rule.table.as_ref().unwrap();
        assert_eq!(provenance.name, table.name);
        assert_eq!(
            rule.typed,
            resolved::resolve_rule_types(&materialized, &rule.root.name.name).unwrap()
        );
        assert_eq!(
            rule.root,
            resolved::resolve_rule_root(&materialized, &rule.root.name.name).unwrap()
        );
        assert_eq!(rule.root.kind, crate::RuleKind::Rule);
        assert_eq!(rule.root.whens[0].pattern, "started");
        assert_eq!(rule.fact_flow.writes.len(), 1);
        assert_eq!(rule.fact_flow.writes[0].fact, "schema:Ticket");
        assert!(!rule.fact_flow.effectful);
        assert!(rule.fact_flow.consumes.is_empty());
        assert_eq!(provenance.records.len(), table.rows.len());
        assert!(matches!(
            prepared[index].rule.body.text.origin(),
            BodyOrigin::Generated
        ));
        for (id, row) in rule.typed.plan.blocks[rule.typed.plan.root.0]
            .nodes
            .iter()
            .zip(&table.rows)
        {
            assert_eq!(
                provenance.records[id],
                IrRecordSource {
                    schema: "Ticket".into(),
                    construct: "table_row".into(),
                    span: row.span
                }
            );
            assert_eq!(
                rule.typed.plan.nodes[id.0].span, table.span,
                "generated offsets remain honest fallbacks"
            );
            assert!(source[row.span.start..row.span.end].contains("title"));
        }
        // Span differences follow from removing the action declaration for the
        // legacy source, so compare its own parsed row origins with its metadata.
        let legacy_table = parse(&legacy_source)
            .items
            .into_iter()
            .find_map(|item| {
                if let Item::Table(t) = item {
                    (t.name.name == table.name.name).then_some(t)
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(
            legacy.rules[index]
                .metadata
                .record_sources
                .iter()
                .map(|source| source.span)
                .collect::<Vec<_>>(),
            legacy_table
                .rows
                .iter()
                .map(|row| row.span)
                .collect::<Vec<_>>()
        );
    }
    for index in [0, 2, 4] {
        assert!(analysis.rules()[index].table.is_none());
    }
    assert_eq!(
        analysis
            .declarations()
            .bodies()
            .iter()
            .filter(|body| matches!(body, crate::PendingBody::Table(_)))
            .count(),
        2
    );
    assert!(analysis
        .declarations()
        .source_descriptions()
        .iter()
        .any(|description| description.value == "Two seed rows"));
    let compiled = compile_program(&source);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    assert_eq!(compiled.typed_actions.as_ref().map(BTreeMap::len), Some(5));
}

#[test]
fn invalid_tables_and_unused_rows_refuse_through_the_production_compiler() {
    for (table, code, needle) in [
        (
            "table seed as Absent [{ title \"one\" }]",
            "type.unknown_schema",
            "unknown class",
        ),
        (
            "table seed as Ticket []",
            "construct.missing_requirement",
            "no rows",
        ),
        (
            "table seed as Ticket [{ title true }]",
            "type.mismatch",
            "expects string",
        ),
        (
            "table seed as Ticket [{ title \"one\" } {}]",
            "type.missing_required_field",
            "title",
        ),
        (
            "table seed as Ticket [{ title \"one\" extra 1 }]",
            "type.unknown_field",
            "extra",
        ),
        (
            "table seed as Ticket [{ title missing }]",
            "type.mismatch",
            "cannot determine",
        ),
    ] {
        let source = format!("{HEADER}{table}\nrule run when started => {{ value() as result }}");
        let errors = analyze_composition(&parse(&source)).expect_err(&source);
        assert!(
            errors
                .iter()
                .any(|error| error.code.as_str() == code && error.message.contains(needle)),
            "{source}: {errors:?}"
        );
        assert_eq!(compile_program(&source).diagnostics, errors);
        let table_span = parse(&source)
            .items
            .iter()
            .find_map(|item| {
                if let Item::Table(t) = item {
                    Some(t.span)
                } else {
                    None
                }
            })
            .unwrap();
        if code != "type.unknown_schema" {
            assert!(
                errors.iter().all(|error| error.span == table_span),
                "generated errors may not claim unrelated file bytes: {errors:?}"
            );
        }
    }
}

#[test]
fn generated_rule_names_share_duplicate_diagnostics_with_authored_rules() {
    for body in [
        "table seed as Ticket [{ title \"one\" }]\ntable seed as Ticket [{ title \"two\" }]",
        "rule table_seed when started => {}\ntable seed as Ticket [{ title \"one\" }]",
        "table seed as Ticket [{ title \"one\" }]\nrule table_seed when started => {}",
    ] {
        let source = format!("{HEADER}{body}");
        let errors = analyze_composition(&parse(&source)).unwrap_err();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].code.as_str(), "construct.duplicate_declaration");
        assert!(errors[0].message.contains("table_seed"));
        assert_eq!(errors[0].related.len(), 1);
        assert!(errors[0].related[0].span.start < errors[0].span.start);
        for span in [errors[0].span, errors[0].related[0].span] {
            assert!(["seed", "table_seed"].contains(&&source[span.start..span.end]));
        }
        assert_eq!(compile_program(&source).diagnostics, errors);
    }
}

#[test]
fn table_elaboration_keeps_definition_failures_primary() {
    let source = format!("{HEADER}action bad() -> int {{ return true }}\ntable seed as Missing []");
    let errors = analyze_composition(&parse(&source)).unwrap_err();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].code.as_str(), "type.mismatch");
    assert_eq!(&source[errors[0].span.start..errors[0].span.end], "true");
    assert_eq!(compile_program(&source).diagnostics, errors);
}

#[test]
fn table_provenance_refuses_missing_extra_mismatched_and_wrong_rule_nodes() {
    let source = format!("{HEADER}table seed as Ticket [{{ title \"one\" }} {{ title \"two\" }}]");
    let program = parse(&source);
    let analysis = analyze_composition(&program).unwrap();
    let typed = &analysis.rules()[0].typed;
    let semantic = SemanticContext::from_program(&program, BTreeMap::new());
    let prepared = tables::prepare_rules(&program, &semantic, &mut Vec::new());
    let origin = prepared[0].table.as_ref().unwrap();
    assert_eq!(
        table_provenance(origin, typed).unwrap(),
        analysis.rules()[0].table.clone().unwrap()
    );
    for delta in [-1, 1] {
        let mut changed = origin.clone();
        if delta == -1 {
            changed.records.pop();
        } else {
            changed.records.push(changed.records[0].clone());
        }
        let errors = table_provenance(&changed, typed).unwrap_err();
        assert!(errors[0]
            .message
            .contains("incomplete generated record provenance"));
    }
    let mut changed = origin.clone();
    changed.records[1].schema = "Other".into();
    assert!(table_provenance(&changed, typed).unwrap_err()[0]
        .message
        .contains("does not match"));
    let mut changed = origin.clone();
    changed.name.name = "other".into();
    assert!(table_provenance(&changed, typed).unwrap_err()[0]
        .message
        .contains("different generated rule"));
    let mut changed = typed.clone();
    changed.plan.blocks[changed.plan.root.0].nodes[1] = NodeId(0);
    assert!(table_provenance(origin, &changed).unwrap_err()[0]
        .message
        .contains("invalid generated plan"));
    let mut changed = typed.clone();
    changed.plan.root = BlockId(usize::MAX);
    assert!(table_provenance(origin, &changed).unwrap_err()[0]
        .message
        .contains("invalid generated plan"));
}

#[test]
fn table_literals_keep_the_shared_record_value_contracts() {
    let source = r#"@service
workflow Values
agent worker { provider fixture profile "reader" capacity 1 }
enum Outcome {
  Accept
  Reject
}
class Details { id int }
class Row {
  agent AgentRef<worker>
  state "queued"
  outcome Outcome
  scores int[]
  labels map<string>
  details Details
  optional string?
}
action value() -> int { return 1 }
table seed as Row [
  { agent worker state "queued" outcome Accept scores [1, 2] labels { lane "one" } details { id 1 } optional null }
  { agent worker state "queued" outcome Reject scores [] labels {} details { id 2 } optional "why" }
]
"#;
    let analysis = analyze_composition(&parse(source)).unwrap();
    assert_eq!(analysis.rules().len(), 1);
    assert_eq!(analysis.rules()[0].table.as_ref().unwrap().records.len(), 2);
    assert_eq!(analysis.rules()[0].typed.plan.nodes.len(), 2);
    let legacy = compile_program(&source.replace("action value() -> int { return 1 }\n", ""));
    assert!(legacy.ir.is_some(), "{:?}", legacy.diagnostics);
    for (old, new) in [
        ("agent worker state", "agent \"worker\" state"),
        ("scores [1, 2]", "scores [true, 2]"),
        ("details { id 1 }", "details { id true }"),
    ] {
        let invalid = source.replace(old, new);
        let errors = analyze_composition(&parse(&invalid)).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.code.as_str() == "type.mismatch"),
            "{errors:?}"
        );
        assert_eq!(compile_program(&invalid).diagnostics, errors);
    }
}

#[test]
fn record_agent_fields_refuse_implicit_strings_at_every_container_depth() {
    let header = r#"@service
workflow AgentFields
agent worker { provider fixture profile "reader" capacity 1 }
class Assigned { who AgentRef<worker> }
class Rows { direct AgentRef<worker> optional AgentRef<worker>? list AgentRef<worker>[] lookup map<AgentRef<worker>> nested Assigned }
action pick() -> AgentRef<worker> { return "worker" }
action accept(who AgentRef<worker>) -> AgentRef<worker> { return who }
"#;
    let payload =
        "direct worker optional worker list [worker] lookup { x worker } nested { who worker }";
    let source = format!("{header}table seed as Rows [{{ {payload} }}]\nrule run when started => {{ accept(\"worker\") as who\npick() as picked }}");
    analyze_composition(&parse(&source)).unwrap();
    for (old, new) in [
        ("direct worker", "direct \"worker\""),
        ("optional worker", "optional \"worker\""),
        ("list [worker]", "list [\"worker\"]"),
        ("lookup { x worker }", "lookup { x \"worker\" }"),
        ("nested { who worker }", "nested { who \"worker\" }"),
    ] {
        for container in [
            format!("table seed as Rows [{{ {} }}]", payload.replace(old, new)),
            format!(
                "rule run when started => {{ record Rows {{ {} }} }}",
                payload.replace(old, new)
            ),
        ] {
            let source = format!("{header}{container}");
            let errors = analyze_composition(&parse(&source)).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|error| error.code.as_str() == "type.mismatch"),
                "{errors:?}"
            );
            assert_eq!(compile_program(&source).diagnostics, errors);
        }
    }
}
