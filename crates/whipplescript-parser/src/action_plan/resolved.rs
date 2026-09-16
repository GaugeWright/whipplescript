//! Checked case types and effect contracts on the hygienic plan. This is not the
//! full program compiler: authority, IFC, conservation and runtime support
//! remain obligations of that compiler and its pinned executable version.
use super::*;
pub use crate::rule_roots::{resolve_rule_root, RuleRoot};
use crate::{action_types, binding_from_when, IrType, Item, Program, SemanticContext};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedActionPlan {
    pub plan: ActionPlan,
    pub case_types: BTreeMap<NodeId, IrType>,
    pub effects: BTreeMap<NodeId, effects::Effect>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub views: BTreeMap<String, TypedView>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedView {
    pub parameters: Vec<String>,
    pub expression: crate::Expr,
}
impl TypedActionPlan {
    /// Structural coverage only. The version owner authenticates the resolved
    /// types along with the source plan; neither may come from untrusted input.
    pub fn validate_structure(&self) -> Result<(), String> {
        self.plan.validate_structure().map_err(|e| e.to_string())?;
        let expected: Vec<_> = self
            .plan
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(n, node)| matches!(node.kind, NodeKind::Case { .. }).then_some(NodeId(n)))
            .collect();
        if self.case_types.keys().copied().collect::<Vec<_>>() != expected {
            // MUTATION-SUCCESS-EXPR: Ok(())
            return Err("typed plan must carry exactly one type for each case node".into());
        }
        effects::validate(&self.plan, &self.effects)?;
        validate_views(&self.views)
    }
}

fn validate_views(views: &BTreeMap<String, TypedView>) -> Result<(), String> {
    for (name, view) in views {
        if name.trim().is_empty()
            || view
                .parameters
                .iter()
                .any(|parameter| parameter.trim().is_empty())
            || view.parameters.iter().collect::<BTreeSet<_>>().len() != view.parameters.len()
        {
            return Err("typed parameterized view has an invalid name or parameter list".into());
        }
        let mut pending = vec![&view.expression];
        while let Some(expression) = pending.pop() {
            if let crate::Expr::Call { name: called, args } = expression {
                if let Some(callee) = views.get(called) {
                    if args.len() != callee.parameters.len() {
                        return Err("typed parameterized view call has invalid arity".into());
                    }
                } else if !matches!(called.as_str(), "count" | "exists" | "empty") {
                    return Err("typed parameterized view calls an unknown function".into());
                }
            }
            pending.extend(expression.children());
        }
    }
    let mut remaining: BTreeSet<_> = views.keys().cloned().collect();
    loop {
        let removable: Vec<_> = remaining
            .iter()
            .filter(|name| {
                let mut pending = vec![&views[*name].expression];
                while let Some(expression) = pending.pop() {
                    if let crate::Expr::Call { name: called, .. } = expression {
                        if remaining.contains(called) {
                            return false;
                        }
                    }
                    pending.extend(expression.children());
                }
                true
            })
            .cloned()
            .collect();
        if removable.is_empty() {
            break;
        }
        for name in removable {
            remaining.remove(&name);
        }
    }
    if !remaining.is_empty() {
        return Err("typed parameterized view graph is recursive".into());
    }
    Ok(())
}

/// Resolves the parsed program's rule, including all definitions' and callers'
/// type errors. Call after root/pattern selection in the compiler. This does
/// not select another source dialect or bypass the executable-source gate.
pub fn resolve_rule_types(
    program: &Program,
    name: &str,
) -> Result<TypedActionPlan, Vec<Diagnostic>> {
    let actions: Vec<_> = program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect();
    let rules: Vec<_> = program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .collect();
    let Some(rule) = rules.iter().copied().find(|rule| rule.name.name == name) else {
        let diagnostic = error(
            SourceSpan { start: 0, end: 0 },
            format!("unknown rule `{name}` for typed plan"),
        );
        // MUTATION-SUCCESS-EXPR: Ok(TypedActionPlan { plan: ActionPlan { root: BlockId(0), root_rule: Some(Ident { name: name.into(), span: SourceSpan { start: 0, end: 0 } }), root_inputs: vec![], scopes: vec![], blocks: vec![Block { scope: None, nodes: vec![], environment: BTreeMap::new() }], nodes: vec![], bindings: vec![] }, case_types: BTreeMap::new(), effects: BTreeMap::new() })
        return Err(vec![diagnostic]);
    };
    let diagnostics = crate::action_signature::validate(&actions);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    let semantic = SemanticContext::from_program(program, BTreeMap::new());
    let (diagnostics, mut types) = action_types::definition_types(&actions, &semantic, false);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    let (diagnostics, callers) = action_types::rule_types(&actions, &rules, &semantic, false);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    types.cases.extend(callers.cases);
    types.values.extend(callers.values);
    let (diagnostics, authority) = action_types::authority_types(&actions, &rules, &semantic);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    resolve_checked_rule(&actions, rule, &types, &authority.tell_targets).map(|(typed, _)| typed)
}

pub(super) fn resolve_checked_rule(
    actions: &[ActionDecl],
    rule: &crate::RuleDecl,
    types: &action_types::SourceTypes,
    targets: &BTreeMap<SourceSite, Vec<String>>,
) -> Result<(TypedActionPlan, BTreeMap<NodeId, IrType>), Vec<Diagnostic>> {
    let inputs: Vec<_> = rule
        .whens
        .iter()
        .filter_map(|when| {
            binding_from_when(&when.text).map(|(name, _)| Ident {
                name,
                span: when.span,
            })
        })
        .collect();
    let Expansion { plan, sites } = expand(actions, Entry::Rule(rule, &inputs))?;
    let effects = effects::collect(&plan, &sites, targets)?;
    let value_types = sites
        .iter()
        .filter_map(|(node, site)| types.values.get(site).map(|ty| (*node, ty.clone())))
        .collect();
    let mut case_types = BTreeMap::new();
    for (n, node) in plan.nodes.iter().enumerate() {
        if let NodeKind::Case { .. } = &node.kind {
            let Some(ty) = sites.get(&NodeId(n)).and_then(|site| types.cases.get(site)) else {
                let diagnostic = error(
                    node.span,
                    "case scrutinee has no resolved source type".into(),
                );
                // MUTATION-SUCCESS-EXPR: Ok((TypedActionPlan { plan: plan.clone(), case_types: case_types.clone(), effects: effects.clone() }, value_types))
                return Err(vec![diagnostic]);
            };
            case_types.insert(NodeId(n), ty.clone());
        }
    }
    Ok((
        TypedActionPlan {
            plan,
            case_types,
            effects,
            views: types.views.clone(),
        },
        value_types,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn resolve(source: &str) -> Result<TypedActionPlan, Vec<Diagnostic>> {
        let parsed = crate::parse_program(source);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        resolve_rule_types(&parsed.program, "run")
    }
    #[test]
    fn resolved_case_types_follow_operation_values_and_distinct_call_sites() {
        let source = r#"workflow Demo
class Ticket { title string }
action identity(x Ticket) -> Ticket { return x }
action label(x Ticket) -> string {
  identity(x) as copy
  after copy succeeds { case copy { Ticket as t => { return t.title } } }
}
rule run when Ticket as ticket => {
  label(ticket) as first
  label(ticket) as second
  case ticket { Ticket as selected => { record Ticket { title selected.title } } }
}"#;
        let typed = resolve(source).unwrap();
        typed.validate_structure().unwrap();
        assert_eq!(typed.case_types.len(), 3);
        assert!(typed
            .case_types
            .values()
            .all(|ty| *ty == IrType::Ref("Ticket".into())));
        let sites: Vec<_> = typed
            .case_types
            .keys()
            .map(|id| typed.plan.nodes[id.0].span)
            .collect();
        assert_eq!(sites[1], sites[2], "one definition expands twice");
        assert_ne!(
            typed.case_types.keys().next(),
            typed.case_types.keys().nth(1)
        );
        let mut missing = typed.clone();
        missing.case_types.pop_first();
        assert!(missing.validate_structure().is_err());
        let mut extra = typed;
        extra
            .case_types
            .insert(NodeId(999), IrType::Ref("Ticket".into()));
        assert!(extra.validate_structure().is_err());
    }
    #[test]
    fn resolved_case_types_reuse_finite_lexical_refinement() {
        let source = r#"workflow Demo
agent reader { provider mock }
agent writer { provider mock }
action choose(who AgentRef<reader | writer>) -> string {
 case who {
   reader => { case who { reader => { return "read" } } }
   writer => { return "write" }
 }
}
rule run when started => { choose(reader) as choice }
"#;
        let typed = resolve(source).unwrap();
        let types: Vec<_> = typed.case_types.values().collect();
        assert_eq!(
            types,
            vec![
                &IrType::AgentRef(vec!["reader".into(), "writer".into()]),
                &IrType::AgentRef(vec!["reader".into()])
            ]
        );
    }
    #[test]
    fn resolved_case_types_refuse_bad_definitions_callers_and_unknown_rules() {
        for source in [
            "workflow Demo\naction broken() -> int { return true }\nrule run when started => { timer 1s as wait }",
            "workflow Demo\naction take(x int) -> int { return x }\nrule run when started => { take(true) as answer }",
            "workflow Demo\nrule run when started => { case missing { _ => { timer 1s as wait } } }",
        ] { assert!(resolve(source).is_err(), "{source}"); }
        let program = crate::parse_program("workflow Demo").program;
        let errors = resolve_rule_types(&program, "missing").unwrap_err();
        assert_eq!(errors[0].message, "unknown rule `missing` for typed plan");
        let errors = resolve("workflow Demo\nrule run when started => { case missing { _ => { timer 1s as wait } } }").unwrap_err();
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("no resolved source type")),
            "{errors:?}"
        );
    }
    #[test]
    fn resolved_case_generated_spans_do_not_merge_lexical_types() {
        let source = r#"workflow Demo
agent reader { provider mock }
agent writer { provider mock }
action choose(who AgentRef<reader | writer>) -> string {
 case who {
   reader => { case who { reader => { return "read" } } }
   writer => { case who { writer => { return "write" } } }
 }
}
rule run when started => { choose(reader) as first
 choose(writer) as second }
"#;
        let generated = generated_matches_source(source);
        let fallback = SourceSpan { start: 0, end: 0 };
        assert_eq!(generated.case_types.len(), 6);
        for (id, ty) in &generated.case_types {
            let NodeKind::Case { branches, .. } = &generated.plan.nodes[id.0].kind else {
                unreachable!()
            };
            let expected = IrType::AgentRef(
                branches
                    .iter()
                    .map(|branch| branch.pattern.clone())
                    .collect(),
            );
            assert_eq!(*ty, expected, "case {id:?}");
        }
        assert!(generated
            .case_types
            .keys()
            .all(|node| generated.plan.nodes[node.0].span == fallback));
    }

    fn generated_matches_source(source: &str) -> TypedActionPlan {
        let parsed = crate::parse_program(source);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        let mut program = parsed.program;
        let before = resolve_rule_types(&program, "run").unwrap();
        for item in &mut program.items {
            let body = match item {
                Item::Action(action) => &mut action.body,
                Item::Rule(rule) => &mut rule.body,
                _ => continue,
            };
            *body = crate::BlockSource::generated(
                body.text.to_string(),
                SourceSpan { start: 0, end: 0 },
            );
        }
        let after = resolve_rule_types(&program, "run").unwrap();
        assert_eq!(after.case_types, before.case_types);
        after.validate_structure().unwrap();
        after
    }
    #[test]
    fn resolved_case_source_sites_distinguish_rule_and_action_with_the_same_name() {
        let typed = generated_matches_source(
            r#"workflow Demo
class Ticket { title string }
agent reader { provider mock }
agent writer { provider mock }
action run(who AgentRef<reader | writer>) -> string {
 case who { reader => { return "read" } writer => { return "write" } }
}
rule run when Ticket as who => {
 case who { Ticket as ticket => { run(reader) as value } }
}
"#,
        );
        assert_eq!(typed.case_types.len(), 2);
        assert!(typed
            .case_types
            .values()
            .any(|ty| *ty == IrType::Ref("Ticket".into())));
        assert!(typed
            .case_types
            .values()
            .any(|ty| *ty == IrType::AgentRef(vec!["reader".into(), "writer".into()])));
    }
    #[test]
    fn resolved_case_source_sites_follow_after_region_lapse_and_then_calls() {
        let typed = generated_matches_source(
            r#"workflow Demo
class Gate { value string }
agent reader { provider mock }
agent writer { provider mock }
action choose(who AgentRef<reader | writer>) -> string {
 case who { reader => { return "read" } writer => { return "write" } }
}
rule run when started => {
 timer 1s as wait
 after wait succeeds {
   case reader { reader => { choose(reader) as read } }
 }
 during empty(Gate) {
   case writer { writer => { choose(writer) as write } }
 } on lapse {
   case reader { reader => { then recovered <- choose(reader) } }
 }
}
"#,
        );
        assert_eq!(typed.case_types.len(), 6);
        for (id, ty) in &typed.case_types {
            let NodeKind::Case { scrutinee, .. } = &typed.plan.nodes[id.0].kind else {
                unreachable!()
            };
            let agents = if scrutinee == "who" {
                vec!["reader".into(), "writer".into()]
            } else {
                vec![scrutinee.clone()]
            };
            assert_eq!(*ty, IrType::AgentRef(agents), "case {id:?}");
        }
    }

    #[test]
    fn resolved_case_duplicate_rule_owners_are_refused_before_type_collection() {
        let mut program = crate::parse_program("workflow Demo\nclass Ticket { title string }\nclass Other { title string }\nrule run when Ticket as value => { case value { _ => { timer 1s as wait } } }\nrule other when Other as value => { case value { _ => { timer 1s as wait } } }").program;
        let original = program
            .items
            .iter()
            .find_map(|item| match item {
                Item::Rule(rule) => Some(rule.clone()),
                _ => None,
            })
            .unwrap();
        let second = program
            .items
            .iter_mut()
            .filter_map(|item| match item {
                Item::Rule(rule) => Some(rule),
                _ => None,
            })
            .nth(1)
            .unwrap();
        // Simulate two generated rules reusing one body origin and owner while
        // their trigger environments supply different nominal types.
        second.body = original.body;
        second.name = original.name;
        for same_type in [false, true] {
            if same_type {
                let rules: Vec<_> = program
                    .items
                    .iter_mut()
                    .filter_map(|item| match item {
                        Item::Rule(rule) => Some(rule),
                        _ => None,
                    })
                    .collect();
                let first = rules[0].whens.clone();
                rules.into_iter().nth(1).unwrap().whens = first;
            }
            let errors = resolve_rule_types(&program, "run").unwrap_err();
            assert_eq!(errors.len(), 1, "{errors:?}");
            assert_eq!(errors[0].code.as_str(), "construct.duplicate_declaration");
            assert_eq!(errors[0].related.len(), 1);
            assert!(errors[0]
                .suggestion
                .as_ref()
                .unwrap()
                .contains("unique name"));
        }
        let compiled = crate::compile_program("workflow Demo\naction use() -> int { return 1 }\nrule run when started => { use() as result }\nrule run when started => { use() as result }");
        assert!(compiled.ir.is_none());
        assert_eq!(compiled.diagnostics.len(), 1, "{:?}", compiled.diagnostics);
        assert_eq!(
            compiled.diagnostics[0].code.as_str(),
            "construct.duplicate_declaration"
        );
    }

    #[test]
    fn parameterized_views_are_typed_nested_and_captured_with_each_rule() {
        let source = r#"workflow Views
class Candidate { state string }
class Ticket { state string }
class Conformance { ready bool total int }
view ticket_count(wanted string) -> int {
  return count(Ticket where state == wanted)
}
view readiness(candidate Candidate) -> Conformance {
  return { ready ticket_count(candidate.state) > 0, total ticket_count(candidate.state) }
}
action inspect(candidate Candidate) -> Conformance {
  return readiness(candidate)
}
rule run when Candidate as candidate => { inspect(candidate) as result }
"#;
        let parsed = crate::parse_program(source);
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        assert_eq!(
            parsed
                .program
                .items
                .iter()
                .filter(|item| matches!(item, Item::View(_)))
                .count(),
            2
        );
        let typed = resolve_rule_types(&parsed.program, "run").unwrap();
        assert_eq!(typed.views.len(), 2);
        assert_eq!(typed.views["ticket_count"].parameters, ["wanted"]);
        typed.validate_structure().unwrap();

        let output = crate::compile_program(source);
        assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
        assert_eq!(
            output.typed_actions.as_ref().unwrap()["run"]
                .views
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["readiness", "ticket_count"]
        );
    }

    #[test]
    fn parameterized_view_diagnostics_cover_shape_arity_types_and_cycles() {
        let cases = [
            (
                "construct.parameterized_view_body",
                "view bad(x int) -> int { return x\nreturn x }",
            ),
            (
                "construct.duplicate_binding",
                "view bad(x int, x int) -> int { return x }",
            ),
            (
                "construct.recursive_view",
                "view first(x int) -> int { return second(x) }\nview second(x int) -> int { return first(x) }",
            ),
            (
                "expr.arity_mismatch",
                "view one(x int) -> int { return x }\naction use() -> int { return one() }",
            ),
            (
                "type.mismatch",
                "view one(x int) -> int { return x }\naction use() -> int { return one(\"wrong\") }",
            ),
        ];
        for (code, declarations) in cases {
            let source = format!(
                "workflow Views\n{declarations}\nrule run when started => {{ timer 1s as wait }}"
            );
            let output = crate::compile_program(&source);
            assert!(output.ir.is_none(), "{code} unexpectedly compiled");
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|error| error.code.as_str() == code),
                "missing {code}: {:?}",
                output.diagnostics
            );
        }
    }

    #[test]
    fn parameterized_view_names_are_unique_and_do_not_shadow_query_builtins() {
        for declarations in [
            "view same(x int) -> int { return x }\nview same(x int) -> int { return x }",
            "view count(x int) -> int { return x }",
        ] {
            let source = format!(
                "workflow Views\n{declarations}\nrule run when started => {{ timer 1s as wait }}"
            );
            let output = crate::compile_program(&source);
            assert!(output.ir.is_none());
            assert!(
                output
                    .diagnostics
                    .iter()
                    .any(|error| error.code.as_str() == "construct.duplicate_declaration"),
                "{:?}",
                output.diagnostics
            );
        }
    }

    #[test]
    fn parameterized_view_artifact_structure_refuses_every_damaged_graph_shape() {
        let output = crate::compile_program(
            r#"workflow Views
view identity(value int) -> int { return value }
view outer(value int) -> int { return identity(value) }
action inspect(value int) -> int { return outer(value) }
rule run when started => { inspect(1) as result }
"#,
        );
        assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
        let typed = output.typed_actions.unwrap().into_values().next().unwrap();
        for (damage, expected) in [
            (0, "invalid name or parameter list"),
            (1, "invalid arity"),
            (2, "unknown function"),
            (3, "graph is recursive"),
        ] {
            let mut bad = typed.clone();
            match damage {
                0 => {
                    bad.views.get_mut("identity").unwrap().parameters =
                        vec!["value".into(), "value".into()]
                }
                1 => {
                    bad.views.get_mut("outer").unwrap().expression = crate::Expr::Call {
                        name: "identity".into(),
                        args: Vec::new(),
                    }
                }
                2 => {
                    bad.views.get_mut("outer").unwrap().expression = crate::Expr::Call {
                        name: "missing".into(),
                        args: Vec::new(),
                    }
                }
                _ => {
                    bad.views.get_mut("outer").unwrap().expression = crate::Expr::Call {
                        name: "outer".into(),
                        args: vec![crate::Expr::Literal(crate::ExprLiteral::Number("1".into()))],
                    }
                }
            }
            let error = bad.validate_structure().unwrap_err();
            assert!(error.contains(expected), "damage {damage}: {error}");
        }
    }
}
