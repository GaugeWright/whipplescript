use super::*;
use crate::{compile_program, parse_program};

const HEADER: &str = r#"@service
workflow Analysis
class Ticket { title string }
class Review { title string }
class Spare { title string }
agent reader { provider fixture profile "reader" capacity 1 capabilities ["read"] }
file store files { root "." }
"#;
fn program(source: &str) -> Program {
    let parsed = parse_program(source);
    assert!(
        parsed.diagnostics.is_empty(),
        "{source}: {:?}",
        parsed.diagnostics
    );
    parsed.program
}
fn analyze(source: &str) -> Result<CompositionAnalysis, Vec<Diagnostic>> {
    analyze_composition(&program(source))
}
fn text(source: &str, span: crate::SourceSpan) -> &str {
    &source[span.start..span.end]
}

#[test]
fn composition_analysis_retains_all_rules_plans_and_called_helper_footprints() {
    let source = format!(
        r#"{HEADER}
action leaf(x Ticket) -> Review {{
  timer 1s as wait
  record Review {{ title x.title }}
  return {{ title x.title }}
}}
action outer(x Ticket) -> Review {{ leaf(x) as reviewed
  return reviewed
}}
action unused() -> null {{ record Spare {{ title "unused" }}
  return null
}}
rule first when Ticket as ticket => {{
  outer(ticket) as a
  outer(ticket) as b
  case a {{ Review as checked => {{ done ticket }} }}
}}
rule second when started => {{ timer 2s as wait }}
"#
    );
    let parsed = program(&source);
    let analysis = analyze_composition(&parsed).unwrap();
    assert_eq!(analysis.rules().len(), 2);
    let first = &analysis.rules()[0];
    assert_eq!(first.root.name.name, "first");
    assert_eq!(
        first.typed,
        resolved::resolve_rule_types(&parsed, "first").unwrap()
    );
    assert_eq!(
        first.root,
        resolved::resolve_rule_root(&parsed, "first").unwrap()
    );
    assert_eq!(first.typed.effects.len(), 2, "two expanded call sites");
    assert_eq!(first.typed.case_types.len(), 1);
    assert!(first.fact_flow.effectful);
    assert_eq!(
        first.fact_flow.consumes,
        ["schema:Ticket".to_owned()].into()
    );
    assert_eq!(first.fact_flow.writes.len(), 1);
    let write = &first.fact_flow.writes[0];
    assert_eq!(write.fact, "schema:Review");
    assert!(text(&source, write.span).starts_with("record Review"));
    assert_eq!(write.calls.len(), 2);
    assert_eq!(
        write
            .calls
            .iter()
            .map(|call| text(&source, call.span))
            .collect::<Vec<_>>(),
        ["leaf", "outer"]
    );
    let second = &analysis.rules()[1];
    assert_eq!(second.root.name.name, "second");
    assert_eq!(
        second.typed,
        resolved::resolve_rule_types(&parsed, "second").unwrap()
    );
    assert!(second.fact_flow.writes.is_empty());
    assert!(second.fact_flow.consumes.is_empty());
    assert!(second.fact_flow.effectful);
    let compiled = compile_program(&source);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some());
    assert!(compiled.typed_actions.is_some());
}

#[test]
fn composition_analysis_refusals_match_the_real_compiler_phase_order() {
    for (declarations, body, code) in [
        ("action loop() -> null { loop()\nreturn null }", "loop()", "construct.invalid_expansion"),
        ("action bad() -> int { return true }", "bad()\nbad()", "type.mismatch"),
        ("action take(x Ticket) -> null { return null }", "take(true)", "type.mismatch"),
        ("action work() -> null { tell reader with access to files {} \"Work\"\nreturn null }", "work()\nwork()", "construct.missing_requirement"),
        ("action work() -> null { tell reader requires [\"write\"] \"Work\"\nreturn null }", "work()", "construct.capability_not_declared"),
        ("action work() -> null { tell reader with access to files { sing } \"Work\"\nreturn null }", "work()", "capability.invalid_grant_operation"),
        ("action finish(x Ticket) -> null { done x\nreturn null }", "finish({ title ticket.title })", "construct.invalid_expansion"),
        ("action work(x Ticket) -> null { record Ticket { title x.title }\ntimer 1s as wait\nreturn null }", "work(ticket)", "effect.unconsumed_trigger"),
    ] {
        let source = format!("{HEADER}{declarations}\nrule run when Ticket as ticket => {{ {body} }}");
        let errors = analyze(&source).expect_err(&source);
        assert_eq!(errors.len(), 1, "{source}: {errors:?}");
        assert_eq!(errors[0].code.as_str(), code, "{source}: {errors:?}");
        assert_eq!(compile_program(&source).diagnostics, errors, "same compiler owner");
    }
    let source = format!("{HEADER}action bad() -> int {{ return true }}\naction bad_grant() -> null {{ tell reader with access to files {{}} \"Work\"\nreturn null }}\nrule run when started => {{ bad()\nbad_grant() }}");
    let errors = analyze(&source).unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(text(&source, errors[0].span), "true");
    assert_eq!(compile_program(&source).diagnostics, errors);
}

#[test]
fn composition_analysis_never_drops_an_invalid_unused_definition_or_sibling_rule() {
    for (extra, needle) in [
        (
            "action untyped() { timer 1s as wait }",
            "needs a result contract",
        ),
        ("action unused() -> int { return true }", "expects int"),
        (
            "rule broken when Ticket as ticket where 42 => {}",
            "non-boolean",
        ),
        ("rule run when started => {}", "declared more than once"),
    ] {
        let source = format!("{HEADER}action good() -> int {{ return 1 }}\nrule run when started => {{ good() as result }}\n{extra}");
        let errors = analyze(&source).expect_err(extra);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].message.contains(needle), "{errors:?}");
        assert!(errors[0].span.start >= source.find(extra).unwrap());
        assert_eq!(compile_program(&source).diagnostics, errors);
    }
}

#[test]
fn composition_analysis_footprints_are_possible_branches_not_execution_or_pacing() {
    let source = format!(
        r#"{HEADER}
action unused() -> null {{ record Ticket {{ title "unused" }}
 timer 1s as wait
 return null
}}
action branch(x Ticket, flag bool) -> null {{
 case flag {{
   true => {{ record Review {{ title x.title }} }}
   false => {{ done x -> record Spare {{ title x.title }} }}
 }}
 return null
}}
rule run when Ticket as ticket => {{ branch(ticket, true) }}
rule idle when started => {{}}
"#
    );
    let analyzed = analyze(&source).unwrap();
    let flow = &analyzed.rules()[0].fact_flow;
    assert_eq!(
        flow.writes
            .iter()
            .map(|w| w.fact.as_str())
            .collect::<Vec<_>>(),
        ["schema:Review", "schema:Spare"]
    );
    assert_eq!(flow.consumes, ["schema:Ticket".to_owned()].into());
    assert!(!flow.effectful, "unused helper starts no operation");
    let idle = &analyzed.rules()[1].fact_flow;
    assert!(idle.writes.is_empty() && idle.consumes.is_empty() && !idle.effectful);
}

#[test]
fn composition_analysis_stops_at_the_first_failed_phase() {
    for (declarations, body, code, blamed) in [
        ("action loop() -> int { loop() as next\nreturn true }", "loop()", "construct.invalid_expansion", "loop"),
        ("action take(x Ticket) -> null { return null }\naction bad_grant() -> null { tell reader with access to files {} \"Work\"\nreturn null }", "take(true)\nbad_grant()", "type.mismatch", "true"),
        ("action bad_grant() -> null { tell reader requires [\"write\"] with access to files {} \"Work\"\nreturn null }", "bad_grant()", "construct.missing_requirement", "tell reader"),
    ] {
        let source = format!("{HEADER}{declarations}\nrule run when started => {{ {body} }}");
        let errors = analyze(&source).expect_err(&source);
        assert_eq!(errors.len(), 1, "{source}: {errors:?}");
        assert_eq!(errors[0].code.as_str(), code, "{errors:?}");
        assert!(text(&source, errors[0].span).contains(blamed), "{errors:?}");
        if blamed == "loop" { assert!(errors[0].message.contains("recursive action expansion")); }
        assert_eq!(compile_program(&source).diagnostics, errors);
    }
}

#[test]
fn composition_analysis_attaches_checked_tell_domains_and_grants_to_each_call() {
    let source = format!(
        r#"{HEADER}
action work(who AgentRef<reader>) -> null {{
 tell who requires ["read"] with access to files {{ read }} "Work"
 return null
}}
rule run when started => {{ work(reader)
 work(reader) }}
"#
    );
    let result = analyze(&source).unwrap();
    let rule = &result.rules()[0];
    assert_eq!(rule.typed.effects.len(), 2);
    for effect in rule.typed.effects.values() {
        assert_eq!(effect.agent_targets, Some(vec!["reader".into()]));
        assert_eq!(effect.contract.required_capabilities, ["read"]);
        assert_eq!(effect.contract.access_grants.len(), 1);
        assert_eq!(effect.contract.access_grants[0].resource, "files");
        assert_eq!(
            effect.contract.access_grants[0].operations[0].operation,
            "read"
        );
    }
    assert!(rule.fact_flow.effectful);
    assert!(rule.fact_flow.writes.is_empty());
}

#[test]
fn composition_analysis_assembly_requires_each_rules_actual_metadata() {
    let source = format!("{HEADER}rule run when Ticket as ticket => {{}}");
    let parsed = program(&source);
    let rules: Vec<_> = parsed
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .collect();
    let semantic = SemanticContext::from_program(&parsed, BTreeMap::new());
    let prepared = tables::prepare_rules(&parsed, &semantic, &mut Vec::new());
    let (errors, flows) = action_subjects::analyze(&[], &rules, &semantic);
    assert!(errors.is_empty());
    let missing_root = assemble(
        &[],
        &prepared,
        action_types::SourceTypes::default(),
        &BTreeMap::new(),
        flows,
    )
    .unwrap_err();
    assert_eq!(missing_root.len(), 1);
    assert!(missing_root[0].message.contains("no checked root analysis"));
    let (errors, types) = action_types::rule_types(&[], &rules, &semantic, false);
    assert!(errors.is_empty());
    let missing_body =
        assemble(&[], &prepared, types, &BTreeMap::new(), BTreeMap::new()).unwrap_err();
    assert_eq!(missing_body.len(), 1);
    assert!(missing_body[0]
        .message
        .contains("no checked fact-flow analysis"));
    for diagnostic in [missing_root[0].clone(), missing_body[0].clone()] {
        assert_eq!(text(&source, diagnostic.span), "run");
    }
}
