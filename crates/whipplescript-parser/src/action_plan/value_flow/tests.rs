use super::*;
use crate::action_plan::resolved::{resolve_rule_types, TypedActionPlan};

fn resolve(source: &str) -> TypedActionPlan {
    let parsed = crate::parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    resolve_rule_types(&parsed.program, "run").unwrap()
}
fn root(typed: &TypedActionPlan, name: &str) -> BindingId {
    typed.plan.blocks[typed.plan.root.0].environment[name]
}
fn sources(origin: Origin, fields: &[&str]) -> BTreeSet<ValuePath> {
    BTreeSet::from([ValuePath {
        origin,
        fields: fields.iter().map(|s| (*s).into()).collect(),
    }])
}
fn expr(source: &str) -> Expr {
    crate::parse_expression(source).unwrap()
}
fn fixture() -> TypedActionPlan {
    resolve(
        r#"workflow Demo
class Ticket { public string private string }
action box(x Ticket) -> Ticket { return { public x.public private x.private } }
action pick(x Ticket) -> string { box(x) as packed
return packed.public }
rule run when Ticket as input => { pick(input) as first
pick(input) as second }"#,
    )
}
#[test]
fn managed_value_flow_nested_fields_match_inline_and_keep_distinct_call_joins() {
    let typed = fixture();
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let expected = sources(Origin::Input(root(&typed, "input")), &["public"]);
    let first = graph.trace_binding(root(&typed, "first")).unwrap();
    let second = graph.trace_binding(root(&typed, "second")).unwrap();
    assert!(first.may_have_value);
    assert_eq!(first.sources, expected);
    assert_eq!(second.sources, expected);
    assert_eq!(first.controls.len(), 2);
    assert_eq!(second.controls.len(), 2);
    assert!(first.controls.is_disjoint(&second.controls));
    let call = typed.plan.blocks[typed.plan.root.0].nodes[0];
    let inline = graph.trace_at(call, &expr("input.public")).unwrap();
    assert_eq!(inline.sources, first.sources);
    assert!(inline.controls.is_empty());
}
#[test]
fn managed_value_flow_ownership_and_order_are_controls_not_data() {
    let typed = resolve(
        r#"workflow Demo
action work() -> string { timer 1s as wait
return "constant" }
rule run when started => { then first <- work()
then second <- work() }"#,
    );
    let constants = BTreeSet::new();
    let graph = Graph::new(&typed, &constants).unwrap();
    let first = graph.trace_binding(root(&typed, "first")).unwrap();
    let second = graph.trace_binding(root(&typed, "second")).unwrap();
    assert!(first.may_have_value && second.may_have_value);
    assert!(first.sources.is_empty() && second.sources.is_empty());
    assert_eq!(first.controls.len(), 1);
    let first_node = typed.plan.blocks[typed.plan.root.0].nodes[0];
    assert!(second.controls.contains(&Control::OrderedAfter(first_node)));
    for (i, node) in typed.plan.nodes.iter().enumerate() {
        if let NodeKind::Statement(statement) = &node.kind {
            if matches!(statement.as_ref(), BodyStmt::Effect(_)) {
                assert_eq!(
                    graph.trace_binding(node.result.unwrap()).unwrap().sources,
                    sources(Origin::Operation(NodeId(i)), &[])
                );
            }
        }
    }
}
#[test]
fn managed_value_flow_operation_success_and_case_keep_selection_and_fields() {
    let typed = resolve(
        r#"workflow Demo
class Ticket { title string }
action identity(x Ticket) -> Ticket { return x }
action label(x Ticket) -> string { identity(x) as copy
 after copy succeeds { case copy { Ticket as t => { return t.title } } }
}
rule run when Ticket as input => { label(input) as label }"#,
    );
    let constants = BTreeSet::new();
    let graph = Graph::new(&typed, &constants).unwrap();
    let trace = graph.trace_binding(root(&typed, "label")).unwrap();
    assert_eq!(
        trace.sources,
        sources(Origin::Input(root(&typed, "input")), &["title"])
    );
    assert!(trace
        .controls
        .iter()
        .any(|c| matches!(c, Control::After(_))));
    assert!(trace
        .controls
        .iter()
        .any(|c| matches!(c, Control::Case { branch: 0, .. })));
    assert_eq!(
        trace
            .controls
            .iter()
            .filter(|c| matches!(c, Control::ScopeSuccess(_)))
            .count(),
        2
    );
}
#[test]
fn managed_value_flow_failure_alias_is_an_outcome_and_not_a_success_value() {
    let typed = resolve(
        r#"workflow Demo
action work() -> string ! string { fail "broken" }
rule run when started => { work() as result
 after result fails as problem { timer 1s as wait } }"#,
    );
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let result = root(&typed, "result");
    let trace = graph.trace_binding(result).unwrap();
    assert!(!trace.may_have_value);
    assert!(trace.sources.is_empty());
    let (index, body) = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find_map(|(i, n)| match n.kind {
            NodeKind::After { body, .. } => Some((i, body)),
            _ => None,
        })
        .unwrap();
    let inner = typed.plan.blocks[body.0].nodes[0];
    let problem = graph.trace_at(inner, &expr("problem")).unwrap();
    assert_eq!(
        problem.sources,
        sources(
            Origin::Outcome {
                observed: result,
                observer: NodeId(index)
            },
            &[]
        )
    );
    assert!(problem.controls.contains(&Control::After(NodeId(index))));
}

#[test]
fn managed_value_flow_outcome_expression_names_the_operation_and_observer() {
    let typed = resolve(
        r#"workflow Demo
action work() -> string {
  timer 1s as wait
  case outcome(wait) {
    Completed as value => { return "done" }
    Failed as problem => { return problem.summary }
    TimedOut as problem => { return problem.summary }
    Cancelled as problem => { return problem.summary }
  }
}
rule run when started => { work() as result }"#,
    );
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let (case, observed) = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| match &node.kind {
            NodeKind::Case { scrutinee, .. } if scrutinee == "outcome(wait)" => Some((
                NodeId(index),
                typed.plan.blocks[node.block.0].environment["wait"],
            )),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        graph
            .trace_at(case, &expr("outcome(wait)"))
            .unwrap()
            .sources,
        sources(
            Origin::Outcome {
                observed,
                observer: case,
            },
            &[],
        )
    );
    let malformed = graph
        .trace_at(case, &expr("outcome()"))
        .expect_err("outcome provenance must name exactly one operation");
    assert!(malformed.message.contains("exactly one named operation"));
}

#[test]
fn managed_value_flow_child_outcome_keeps_the_call_observation() {
    let typed = resolve(
        r#"workflow Demo
action parent() -> string {
  child() as result
  case outcome(result) {
    Completed as value => { return value }
    Failed as problem => { return problem.summary }
  }
}
action child() -> string ! string { fail "broken" }
rule run when started => { parent() as result }"#,
    );
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let (case, observed) = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| match &node.kind {
            NodeKind::Case { scrutinee, .. } if scrutinee == "outcome(result)" => Some((
                NodeId(index),
                typed.plan.blocks[node.block.0].environment["result"],
            )),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        graph
            .trace_at(case, &expr("outcome(result)"))
            .unwrap()
            .sources,
        sources(
            Origin::Outcome {
                observed,
                observer: case,
            },
            &[],
        )
    );
}

#[test]
fn managed_value_flow_failure_handler_joins_operation_outcomes() {
    let typed = resolve(
        r#"workflow Demo
action work() -> string {
  timer 1s as first
  timer 2s as second
  return "ok"
  on failure as problem { timer 3s as cleanup
    return problem.summary }
}
rule run when started => { work() as result }"#,
    );
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let (handler, body) = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| match node.kind {
            NodeKind::OnFailure { body, .. } => Some((NodeId(index), body)),
            _ => None,
        })
        .unwrap();
    let returned = *typed.plan.blocks[body.0].nodes.last().unwrap();
    let trace = graph.trace_at(returned, &expr("problem.summary")).unwrap();
    let expected: BTreeSet<_> = typed
        .plan
        .protected_operation_nodes(handler)
        .into_iter()
        .map(|operation| ValuePath {
            origin: Origin::Outcome {
                observed: typed.plan.nodes[operation.0].result.unwrap(),
                observer: handler,
            },
            fields: vec!["summary".into()],
        })
        .collect();
    assert_eq!(expected.len(), 2);
    assert_eq!(trace.sources, expected);
    assert!(trace.controls.contains(&Control::FailureHandler(handler)));
}

#[test]
fn managed_value_flow_rule_failure_handler_joins_root_operation_outcomes() {
    let typed = resolve(
        r#"workflow Demo
class Incident { summary string }
rule run when started => {
  timer 1s as first
  timer 2s as second
  on failure as problem { timer 3s as cleanup
    record Incident { summary problem.summary } }
}"#,
    );
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let (handler, body) = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| match node.kind {
            NodeKind::OnFailure { body, .. } => Some((NodeId(index), body)),
            _ => None,
        })
        .unwrap();
    let record = *typed.plan.blocks[body.0].nodes.last().unwrap();
    let trace = graph.trace_at(record, &expr("problem.summary")).unwrap();
    let expected: BTreeSet<_> = typed
        .plan
        .protected_operation_nodes(handler)
        .into_iter()
        .map(|operation| ValuePath {
            origin: Origin::Outcome {
                observed: typed.plan.nodes[operation.0].result.unwrap(),
                observer: handler,
            },
            fields: vec!["summary".into()],
        })
        .collect();
    assert_eq!(expected.len(), 2);
    assert_eq!(trace.sources, expected);
    assert!(trace.controls.contains(&Control::FailureHandler(handler)));
}

#[test]
fn managed_value_flow_regions_keep_both_selection_sides_and_lapse_origin() {
    let typed = resolve(
        r#"workflow Demo
class Input { gate bool }
rule run when Input as input => {
 during input.gate { timer 1s as held } on lapse as progress { timer 1s as elapsed }
}"#,
    );
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let (index, body, lapse) = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find_map(|(i, n)| match n.kind {
            NodeKind::Region {
                body, lapse_body, ..
            } => Some((i, body, lapse_body)),
            _ => None,
        })
        .unwrap();
    for (block, lapsed) in [(body, false), (lapse, true)] {
        let at = typed.plan.blocks[block.0].nodes[0];
        let trace = graph
            .trace_at(at, &expr(if lapsed { "progress" } else { "input.gate" }))
            .unwrap();
        assert!(trace.controls.contains(&Control::Region {
            node: NodeId(index),
            lapse: lapsed
        }));
        if lapsed {
            assert_eq!(trace.sources, sources(Origin::Lapse(NodeId(index)), &[]));
        }
    }
}

#[test]
fn managed_value_flow_region_exit_controls_only_the_lexical_tail() {
    let typed = resolve(
        r#"workflow Demo
class Input { gate bool }
rule run when Input as input => {
 timer 1s as before
 during input.gate { timer 1s as held } on lapse { timer 1s as lapsed }
 timer 1s as tail
}"#,
    );
    let constants = BTreeSet::new();
    let graph = Graph::new(&typed, &constants).unwrap();
    let nodes = &typed.plan.blocks[typed.plan.root.0].nodes;
    let region = nodes[1];
    assert!(graph
        .trace_binding(root(&typed, "before"))
        .unwrap()
        .controls
        .is_empty());
    assert_eq!(
        graph.trace_binding(root(&typed, "tail")).unwrap().controls,
        BTreeSet::from([Control::RegionExit(region)])
    );
    let NodeKind::Region {
        body, lapse_body, ..
    } = typed.plan.nodes[region.0].kind
    else {
        panic!("region")
    };
    for (block, lapse) in [(body, false), (lapse_body, true)] {
        let node = &typed.plan.nodes[typed.plan.blocks[block.0].nodes[0].0];
        assert_eq!(
            graph.trace_binding(node.result.unwrap()).unwrap().controls,
            BTreeSet::from([Control::Region {
                node: region,
                lapse
            }])
        );
    }
}

#[test]
fn managed_value_flow_successive_region_exits_survive_helper_extraction() {
    let typed = resolve(
        r#"workflow Demo
class Input { gate bool }
action inner() -> string { return "constant" }
action outer() -> string { inner() as value
 return value }
rule run when Input as input => {
 during input.gate { timer 1s as first } on lapse { }
 until input.gate { timer 1s as second } on lapse { }
 outer() as tail
}"#,
    );
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let nodes = &typed.plan.blocks[typed.plan.root.0].nodes;
    let exits = BTreeSet::from([Control::RegionExit(nodes[0]), Control::RegionExit(nodes[1])]);
    let trace = graph.trace_binding(root(&typed, "tail")).unwrap();
    assert!(trace.sources.is_empty());
    assert!(exits.is_subset(&trace.controls));
    for (index, node) in typed.plan.nodes.iter().enumerate() {
        if typed.plan.blocks[node.block.0].scope.is_some() {
            assert!(exits.is_subset(
                &graph
                    .trace_at(NodeId(index), &expr("null"))
                    .unwrap()
                    .controls
            ));
        }
    }
    let NodeKind::Region { body, .. } = typed.plan.nodes[nodes[1].0].kind else {
        panic!("region")
    };
    let at = typed.plan.blocks[body.0].nodes[0];
    let controls = graph.trace_at(at, &expr("null")).unwrap().controls;
    assert!(controls.contains(&Control::RegionExit(nodes[0])));
    assert!(!controls.contains(&Control::RegionExit(nodes[1])));
}

#[test]
fn managed_value_flow_region_exit_does_not_escape_its_branch() {
    let typed = resolve(
        r#"workflow Demo
class Input { gate bool }
rule run when Input as input => {
 case input.gate {
  true => { during input.gate { } on lapse { }
            timer 1s as tail }
  false => { timer 1s as sibling }
 }
 timer 1s as outside
}"#,
    );
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let mut controlled = Vec::new();
    for (index, node) in typed.plan.nodes.iter().enumerate() {
        if let NodeKind::Statement(_) = node.kind {
            let trace = graph.trace_at(NodeId(index), &expr("null")).unwrap();
            if trace
                .controls
                .iter()
                .any(|c| matches!(c, Control::RegionExit(_)))
            {
                controlled.push(
                    typed.plan.bindings[node.result.unwrap().0]
                        .name
                        .as_deref()
                        .unwrap(),
                );
            }
        }
    }
    assert_eq!(controlled, ["tail"]);
}

#[test]
fn managed_value_flow_nested_region_exit_keeps_outer_membership() {
    let typed = resolve(
        r#"workflow Demo
class Input { gate bool }
rule run when Input as input => {
 during input.gate {
  until input.gate { } on lapse { }
  timer 1s as inner_tail
 } on lapse { timer 1s as outer_lapse }
 timer 1s as outer_tail
}"#,
    );
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let outer = typed.plan.blocks[typed.plan.root.0].nodes[0];
    let NodeKind::Region {
        body, lapse_body, ..
    } = typed.plan.nodes[outer.0].kind
    else {
        panic!("region")
    };
    let inner = typed.plan.blocks[body.0].nodes[0];
    let tail = typed.plan.blocks[body.0].nodes[1];
    assert_eq!(
        graph.trace_at(tail, &expr("null")).unwrap().controls,
        BTreeSet::from([
            Control::Region {
                node: outer,
                lapse: false
            },
            Control::RegionExit(inner)
        ])
    );
    let lapse = typed.plan.blocks[lapse_body.0].nodes[0];
    assert_eq!(
        graph.trace_at(lapse, &expr("null")).unwrap().controls,
        BTreeSet::from([Control::Region {
            node: outer,
            lapse: true
        }])
    );
    assert_eq!(
        graph
            .trace_binding(root(&typed, "outer_tail"))
            .unwrap()
            .controls,
        BTreeSet::from([Control::RegionExit(outer)])
    );
}
#[test]
fn managed_value_flow_projection_handles_dynamic_keys_arrays_and_transforms() {
    let typed = fixture();
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let at = typed.plan.blocks[typed.plan.root.0].nodes[0];
    let input = Origin::Input(root(&typed, "input"));
    let fixed = graph
        .trace_at(
            at,
            &expr(r#"{ left input.public right input.private }["left"]"#),
        )
        .unwrap();
    assert_eq!(fixed.sources, sources(input.clone(), &["public"]));
    let dynamic = graph
        .trace_at(
            at,
            &expr("{ left input.public right \"safe\" }[input.private]"),
        )
        .unwrap();
    let mut expected = sources(input.clone(), &["public"]);
    expected.extend(sources(input.clone(), &["private"]));
    assert_eq!(dynamic.sources, expected);
    let array = graph
        .trace_at(at, &expr(r#"[input.public, input.private]["0"]"#))
        .unwrap();
    assert_eq!(array.sources, sources(input.clone(), &["public"]));
    let transform = Expr::Index {
        target: Box::new(Expr::Call {
            name: "count".into(),
            args: vec![expr("input")],
        }),
        key: Box::new(expr(r#""invented""#)),
    };
    assert_eq!(
        graph.trace_at(at, &transform).unwrap().sources,
        sources(input, &[])
    );
    let absent = graph
        .trace_at(at, &expr(r#"{ left input.public }["absent"]"#))
        .unwrap();
    assert!(absent.may_have_value && absent.sources.is_empty());
}
#[test]
fn managed_value_flow_redaction_selects_fields_and_crossing_stays_explicit() {
    let typed = resolve(
        r#"workflow Demo
class Ticket { public string private string }
rule run when Ticket as input => {
 redact input keep [public] as selected
 declassify input into Ticket as released
}"#,
    );
    let constants = BTreeSet::new();
    let graph = Graph::new(&typed, &constants).unwrap();
    assert_eq!(
        graph
            .trace_binding(root(&typed, "selected"))
            .unwrap()
            .sources,
        sources(Origin::Input(root(&typed, "input")), &["public"])
    );
    let released = root(&typed, "released");
    let BindingSource::Node(node) = typed.plan.bindings[released.0].source else {
        panic!("crossing")
    };
    assert_eq!(
        graph.trace_binding(released).unwrap().sources,
        sources(Origin::Crossing(node), &[])
    );
}
#[test]
fn managed_value_flow_refuses_unknown_observations_bad_ids_and_structure() {
    let typed = fixture();
    let constants = BTreeSet::from(["declared".into()]);
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let at = typed.plan.blocks[typed.plan.root.0].nodes[0];
    for expression in [
        expr("unknown"),
        Expr::Path(vec![]),
        Expr::Path(vec!["unknown".into(), "field".into()]),
    ] {
        assert!(graph.trace_at(at, &expression).is_err(), "{expression:?}");
    }
    assert!(graph.trace_at(at, &expr("outcome(input)")).is_err());
    let query = Expr::Query {
        kind: crate::QueryKind::Fact,
        head: "Ticket".into(),
        guard: None,
    };
    assert!(graph.trace_at(at, &query).is_err());
    let constant = graph.trace_at(at, &expr("declared")).unwrap();
    assert!(constant.may_have_value && constant.sources.is_empty());
    assert!(graph.trace_binding(BindingId(usize::MAX)).is_err());
    assert!(graph.trace_at(NodeId(usize::MAX), &expr("input")).is_err());
    let mut broken = typed.clone();
    broken.plan.blocks[broken.plan.root.0]
        .nodes
        .push(NodeId(usize::MAX));
    assert!(Graph::new(&broken, &constants).is_err());
}
#[test]
fn managed_value_flow_cycles_report_hygienic_bindings_instead_of_empty_provenance() {
    let typed = resolve(
        r#"workflow Demo
action identity(x string) -> string { return x }
rule run when started => { identity(b) as a
identity(a) as b }"#,
    );
    let constants = BTreeSet::new();
    let graph = Graph::new(&typed, &constants).unwrap();
    let diagnostic = graph.trace_binding(root(&typed, "a")).unwrap_err();
    assert!(diagnostic.message.contains("cycle"));
    for name in ["`a`", "`b`"] {
        assert!(diagnostic.related.iter().any(|r| r.message.contains(name)));
    }
}

#[test]
fn managed_value_flow_branch_constants_keep_controls_and_long_aliases_share_bindings() {
    let typed = resolve(
        r#"workflow Demo
class Input { gate bool }
action choose(gate bool) -> string { case gate { true => { return "yes" } false => { return "no" } } }
rule run when Input as input => { choose(input.gate) as result }"#,
    );
    let constants = BTreeSet::new();
    let graph = Graph::new(&typed, &constants).unwrap();
    let trace = graph.trace_binding(root(&typed, "result")).unwrap();
    assert!(trace.may_have_value && trace.sources.is_empty());
    for branch in [0, 1] {
        assert!(trace
            .controls
            .iter()
            .any(|c| matches!(c, Control::Case { branch: b, .. } if *b == branch)));
    }

    let mut source = String::from("workflow Demo\nclass Input { value string }\naction identity(x string) -> string { return x }\nrule run when Input as input => { identity(input.value) as v0\n");
    for i in 1..256 {
        source.push_str(&format!("identity(v{}) as v{i}\n", i - 1));
    }
    source.push('}');
    let typed = resolve(&source);
    let graph = Graph::new(&typed, &constants).unwrap();
    let trace = graph.trace_binding(root(&typed, "v255")).unwrap();
    assert_eq!(
        trace.sources,
        sources(Origin::Input(root(&typed, "input")), &["value"])
    );
    assert_eq!(trace.controls.len(), 256);
    // Binding references share cells instead of copying each earlier value tree.
    assert!(graph.cells.len() < 10 * typed.plan.bindings.len());
}

#[test]
fn managed_value_flow_case_selection_uses_guard_binders_and_rejects_invalid_sites() {
    let typed = resolve(
        r#"workflow Demo
class Input { gate bool }
rule run when Input as input => { case input {
 Input as selected where selected.gate => { timer 1s as first }
 _ => { timer 1s as second }
} }"#,
    );
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let case = typed.plan.blocks[typed.plan.root.0].nodes[0];
    let trace = graph.trace_case_selection(case, 1).unwrap();
    let mut expected = sources(Origin::Input(root(&typed, "input")), &[]);
    expected.extend(sources(Origin::Input(root(&typed, "input")), &["gate"]));
    assert_eq!(trace.sources, expected);
    assert!(graph.trace_case_selection(case, 2).is_err());
    assert!(graph.trace_case_selection(NodeId(usize::MAX), 0).is_err());
    let other = typed
        .plan
        .nodes
        .iter()
        .position(|n| matches!(n.kind, NodeKind::Statement(_)))
        .unwrap();
    assert!(graph.trace_case_selection(NodeId(other), 0).is_err());
}

#[test]
fn managed_value_flow_identity_preserves_forwarded_members_but_not_rebuilt_values() {
    let typed = resolve(
        r#"workflow Demo
class Ticket { title string }
class Box { item Ticket }
action wrap(x Ticket) -> Box { return { item x } }
action unwrap(x Box) -> Ticket { return x.item }
action rebuild(x Ticket) -> Ticket { return { title x.title } }
action singleton(x Ticket) -> Ticket[] { return [x] }
rule run when Ticket as input => { wrap(input) as boxed
unwrap(boxed) as original
rebuild(input) as rebuilt
singleton(input) as items }"#,
    );
    let constants = BTreeSet::new();
    let graph = Graph::new(&typed, &constants).unwrap();
    let expected = sources(Origin::Input(root(&typed, "input")), &[]);
    let trace = graph.identity_binding(root(&typed, "original")).unwrap();
    assert_eq!(trace.sources, expected);
    assert!(!trace.controls.is_empty());
    assert!(
        graph
            .trace_binding(root(&typed, "rebuilt"))
            .unwrap()
            .may_have_value
    );
    for name in ["boxed", "rebuilt", "items"] {
        assert!(
            graph.identity_binding(root(&typed, name)).is_err(),
            "{name}"
        );
    }
    assert!(graph.identity_binding(BindingId(usize::MAX)).is_err());
}

#[test]
fn managed_value_flow_identity_distinguishes_missing_members_transformations_and_no_success() {
    let typed = fixture();
    let constants = BTreeSet::new();
    let mut graph = Graph::new(&typed, &constants).unwrap();
    let span = SourceSpan { start: 0, end: 1 };
    let original = root(&typed, "input").0;
    let object = graph.add(
        Value::Object(BTreeMap::from([("item".into(), original)])),
        span,
    );
    let array = graph.add(Value::Array(vec![original]), span);
    let constant = graph.add(Value::Constant, span);
    for value in [
        Value::Constant,
        Value::Mix(vec![original]),
        Value::DynamicSelect {
            target: array,
            key: constant,
        },
        Value::Select {
            target: object,
            key: "missing".into(),
        },
        Value::Select {
            target: array,
            key: "1".into(),
        },
        Value::Choice(vec![original, constant]),
    ] {
        let id = graph.add(value, span);
        assert!(graph.trace_mode(id, true).is_err());
    }
    // Exercise the graph's literal-index projection separately from the
    // still-separate managed expression type checker.
    let expression = expr("[input][0]");
    let value = graph
        .expression(
            &expression,
            &typed.plan.blocks[typed.plan.root.0].environment,
            span,
            None,
        )
        .unwrap();
    assert_eq!(
        graph.trace_mode(value, true).unwrap().sources,
        sources(Origin::Input(BindingId(original)), &[])
    );
    let never = graph.add(Value::Never, span);
    assert_eq!(graph.trace_mode(never, true).unwrap(), Trace::default());
    let selected = graph.add(
        Value::Select {
            target: object,
            key: "item".into(),
        },
        span,
    );
    assert_eq!(
        graph.trace_mode(selected, true).unwrap().sources,
        sources(Origin::Input(BindingId(original)), &[])
    );
    let choices = graph.add(Value::Choice(vec![original, never]), span);
    assert_eq!(
        graph.trace_mode(choices, true).unwrap().sources,
        sources(Origin::Input(BindingId(original)), &[])
    );
}
