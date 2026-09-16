use super::*;
use crate::action_plan::analysis::{analyze_composition, analyze_selected};
const DECLS: &str = r#"class Key { id string }
lease slots { shared key Key slots 1 ttl 5m }
lease unused { shared key Key slots 1 ttl 5m }
"#;
fn parsed(text: &str) -> Program {
    let parsed = parse_program(text);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    parsed.program
}
#[test]
fn coordination_census_follows_nested_called_actions_and_retains_other_roots() {
    let text = format!(
        r#"{DECLS}
action acquire_it(key Key) -> null {{ acquire slots for key until ttl as held
 return null }}
action wrap(key Key) -> null {{ acquire_it(key)
 return null }}
action spare(key Key) -> null {{ acquire unused for key until ttl as held
 return null }}
@service
workflow A {{ rule run when Key as key => {{ wrap(key) }} }}
@service
workflow B {{ rule run when Key as key => {{ wrap(key) }} }}
@service
workflow C {{ rule run when started => {{ timer 1s as wait }} }}
"#
    );
    let program = parsed(&text);
    let census = collect_shared_coordination_usage(&program);
    assert_eq!(
        census,
        vec![IrSharedCoordinationUsage {
            resource: "resource:slots".into(),
            workflow_principals: vec!["workflow:local/A".into(), "workflow:local/B".into()],
        }]
    );
    let selected = select_root_workflow(program.clone(), Some("A")).unwrap();
    let analysis = analyze_selected(
        &selected,
        collect_workflow_input_surfaces(&program),
        census.clone(),
    )
    .unwrap();
    assert_eq!(analysis.shared_coordination_usage(), census);
    let local = analyze_composition(&selected).unwrap();
    assert_eq!(
        local.shared_coordination_usage()[0].workflow_principals,
        ["workflow:local/A"]
    );
    let compiled = compile_program_with_root(&text, Some("A"));
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    assert!(compiled.typed_actions.is_some());
}
#[test]
fn coordination_census_follows_calls_in_each_control_body() {
    for body in [
        "then result <- acquire_it(key)",
        "timer 1s as wait\nafter wait succeeds as elapsed { acquire_it(key) }",
        "during true { acquire_it(key) } on lapse as progress { timer 1s as wait }",
        "during true { timer 1s as wait } on lapse as progress { acquire_it(key) }",
        "case key.id { \"a\" => { timer 1s as wait } _ => { acquire_it(key) } }",
    ] {
        let text = format!("@service\nworkflow A\n{DECLS}action acquire_it(key Key) -> null {{ acquire slots for key until ttl as held\n return null }}\nrule run when Key as key => {{ {body} }}");
        let program = parsed(&text);
        let census = collect_shared_coordination_usage(&program);
        assert_eq!(census.len(), 1, "{body}");
        assert_eq!(census[0].resource, "resource:slots", "{body}");
    }
}
#[test]
fn coordination_census_includes_called_legacy_helpers() {
    let text = format!(
        r#"@service
workflow A
{DECLS}
action acquire_it(key Key) {{ acquire slots for key until ttl as held }}
rule run when Key as key => {{ acquire_it(key) }}
"#
    );
    let program = parsed(&text);
    let census = collect_shared_coordination_usage(&program);
    assert_eq!(census.len(), 1);
    assert_eq!(census[0].resource, "resource:slots");
    let compiled = crate::execution_semantics::compile_recorded_program_with_root(
        &text,
        None,
        ExecutionSemantics::LegacyActionChainsV1,
    );
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
    assert_eq!(ir.shared_coordination_usage, census);
}
#[test]
fn coordination_census_recursion_terminates_and_does_not_hide_compile_errors() {
    for call in ["wrap(key)", "missing(key)"] {
        let text = format!("@service\nworkflow A\n{DECLS}action wrap(key Key) -> null {{ {call}\n return null }}\nrule run when Key as key => {{ wrap(key) }}");
        assert!(collect_shared_coordination_usage(&parsed(&text)).is_empty());
        let output = compile_program(&text);
        assert!(output.ir.is_none());
        assert!(!output.diagnostics.is_empty());
    }
}

#[test]
fn coordination_census_uses_pattern_expansion_and_workflow_scope() {
    let text = format!(
        r#"{DECLS}
pattern Lock<Input> {{
 rule lock when Input as key => {{ acquire slots for key until ttl as held }}
}}
@service
workflow A {{ apply Lock<Key> as a {{}} }}
@service
workflow B {{ apply Lock<Key> as b {{}} }}
@service
workflow C {{
 lease private_slot {{ shared key Key slots 1 ttl 5m }}
 rule lock when Key as key => {{ acquire private_slot for key until ttl as held }}
}}
"#
    );
    let census = collect_shared_coordination_usage(&parsed(&text));
    assert_eq!(
        census,
        vec![
            IrSharedCoordinationUsage {
                resource: "resource:private_slot".into(),
                workflow_principals: vec!["workflow:local/C".into()]
            },
            IrSharedCoordinationUsage {
                resource: "resource:slots".into(),
                workflow_principals: vec!["workflow:local/A".into(), "workflow:local/B".into()]
            },
        ]
    );
    let output = compile_program_with_root(&text, Some("A"));
    let ir = output
        .ir
        .unwrap_or_else(|| panic!("{:?}", output.diagnostics));
    assert_eq!(ir.shared_coordination_usage, census);
}
