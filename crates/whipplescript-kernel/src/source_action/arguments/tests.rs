use super::*;
use serde_json::json;
use whipplescript_parser::{parse_expression, parse_program, Item};
use whipplescript_store::EventView;

fn source(name: &str) -> ValueSource {
    ValueSource::Fact {
        fact_id: name.into(),
        admission_event: format!("admit-{name}"),
    }
}
fn ready(value: Value, origin: &str) -> Slot {
    Slot::Ready(Argument {
        subjects: Default::default(),
        value,
        sources: BTreeSet::from([source(origin)]),
        validity: Default::default(),
    })
}
fn env() -> Environment {
    BTreeMap::from([
        ("a".into(), BindingId(0)),
        ("b".into(), BindingId(1)),
        ("c".into(), BindingId(2)),
    ])
}
fn expression(text: &str, bindings: &Bindings) -> Evaluation {
    evaluate(
        &parse_expression(text).expect("valid fixture expression"),
        &env(),
        bindings,
    )
}
fn pending(result: Evaluation, waits: &[usize]) {
    assert_eq!(
        result.state,
        State::Blocked {
            waiting: waits.iter().copied().map(BindingId).collect(),
            causes: BTreeSet::new()
        }
    );
}
fn value(result: Evaluation, value: Value) {
    assert_eq!(result.state, State::Ready(value));
}

#[test]
fn action_arguments_pending_is_never_a_scalar_or_collection_value() {
    let bindings = Bindings::from([
        (BindingId(0), Slot::Pending),
        (BindingId(1), ready(json!({"x": 1}), "b")),
    ]);
    for text in [
        "a",
        "a.x",
        "[a]",
        "{ x a }",
        "not a",
        "a == null",
        "a != null",
        "a < 4",
        "a + 1",
        "a in [1]",
        "count(a)",
        "exists(a)",
        "empty(a)",
        "a[\"x\"]",
        "b[a]",
    ] {
        pending(expression(text, &bindings), &[0]);
    }
    pending(expression("[a, c]", &bindings), &[0, 2]);
}

#[test]
fn action_arguments_absence_and_null_are_successful_optional_values() {
    let bindings = Bindings::from([(BindingId(0), ready(json!({}), "a"))]);
    assert_eq!(expression("a.missing", &bindings).state, State::Absent);
    for (text, expected) in [
        ("exists(a.missing)", json!(false)),
        ("empty(a.missing)", json!(true)),
        ("a.missing == null", json!(true)),
        ("[a.missing, null]", json!([null, null])),
        ("{ x a.missing }", json!({"x": null})),
        ("a[\"missing\"]", Value::Null),
    ] {
        let evaluated = expression(text, &bindings);
        assert_eq!(evaluated.sources, BTreeSet::from([source("a")]));
        if text == "a[\"missing\"]" {
            assert_eq!(evaluated.state, State::Absent);
        } else {
            value(evaluated, expected);
        }
    }
    value(expression("null", &Bindings::new()), Value::Null);
}

#[test]
fn action_arguments_short_circuit_reads_only_selected_values() {
    let mut bindings = Bindings::from([
        (BindingId(0), ready(json!(false), "a")),
        (BindingId(1), Slot::Pending),
    ]);
    let result = expression("a and b", &bindings);
    assert_eq!(result.reads, BTreeSet::from([BindingId(0)]));
    assert_eq!(result.sources, BTreeSet::from([source("a")]));
    value(result, json!(false));
    bindings.insert(BindingId(0), ready(json!(true), "a"));
    value(expression("a or b", &bindings), json!(true));
    pending(expression("a and b", &bindings), &[1]);
    bindings.insert(BindingId(1), ready(json!(false), "b"));
    let taken = expression("a and b", &bindings);
    assert_eq!(taken.sources, BTreeSet::from([source("a"), source("b")]));
    assert_eq!(taken.reads, BTreeSet::from([BindingId(0), BindingId(1)]));
    value(taken, json!(false));
    bindings.insert(BindingId(0), Slot::Pending);
    let unresolved = expression("a and b", &bindings);
    assert_eq!(unresolved.reads, BTreeSet::from([BindingId(0)]));
    pending(unresolved, &[0]);
    let literal = expression("42", &bindings);
    assert!(literal.reads.is_empty(), "visible values impose no wait");
    value(literal, json!(42));
}

#[test]
fn action_arguments_strict_joins_keep_all_waits_and_original_causes() {
    let failed =
        |names: &[&str]| Slot::Failed(names.iter().map(|name| CauseId((*name).into())).collect());
    let bindings = Bindings::from([
        (BindingId(0), failed(&["failure-a"])),
        (BindingId(1), failed(&["failure-a", "failure-b"])),
    ]);
    let result = expression("[a, b, c]", &bindings);
    assert_eq!(
        result.reads,
        BTreeSet::from([BindingId(0), BindingId(1), BindingId(2)])
    );
    assert_eq!(
        result.state,
        State::Blocked {
            waiting: BTreeSet::from([BindingId(2)]),
            causes: BTreeSet::from([CauseId("failure-a".into()), CauseId("failure-b".into())])
        }
    );
    let mut distinct = bindings.clone();
    distinct.insert(BindingId(1), failed(&["failure-b"]));
    let invalid = expression("[[1 / 0, a, c], b]", &distinct);
    let State::Invalid(issue) = invalid.state else {
        panic!("division error");
    };
    assert_eq!(issue.message, "division by zero");
    assert_eq!(issue.waiting, BTreeSet::from([BindingId(2)]));
    assert_eq!(
        issue.causes,
        BTreeSet::from([CauseId("failure-a".into()), CauseId("failure-b".into())])
    );
}

#[test]
fn action_arguments_share_scalar_semantics_and_preserve_origins() {
    let bindings = Bindings::from([
        (BindingId(0), ready(json!(2), "a")),
        (
            BindingId(1),
            Slot::Ready(Argument {
                subjects: Default::default(),
                value: json!(3),
                sources: BTreeSet::from([ValueSource::Operation {
                    operation_id: "op-b".into(),
                }]),
                validity: Default::default(),
            }),
        ),
    ]);
    for (text, expected) in [
        ("a + b", json!(5)),
        ("a * b", json!(6)),
        ("a < b", json!(true)),
        ("a in [b, 2]", json!(true)),
        ("a != b", json!(true)),
        ("count([a, b])", json!(2)),
    ] {
        let result = expression(text, &bindings);
        assert_eq!(result.sources.len(), 2, "{text}");
        value(result, expected);
    }
    for (text, expected) in [
        ("not false", json!(true)),
        ("5m - 1m", json!("PT240S")),
        ("5m > 1m", json!(true)),
        ("count(\"é🙂\")", json!(2)),
        ("empty([])", json!(true)),
    ] {
        value(expression(text, &bindings), expected);
    }
}

#[test]
fn action_arguments_invalid_operations_are_not_success_values() {
    let bindings = Bindings::from([
        (BindingId(0), ready(json!(1), "a")),
        (BindingId(1), Slot::Failed(BTreeSet::new())),
    ]);
    for text in [
        "1 / 0",
        "not a",
        "a and true",
        "true and a",
        "false or a",
        "count(null)",
        "count()",
        "a[\"key\"]",
        "a[1]",
        "b",
        "count(Foo where true)",
    ] {
        assert!(
            matches!(expression(text, &bindings).state, State::Invalid(_)),
            "{text}"
        );
    }
    for path in [vec![], vec!["unknown".into(), "field".into()]] {
        assert!(matches!(
            evaluate(&Expr::Path(path), &env(), &bindings).state,
            State::Invalid(_)
        ));
    }
    assert!(matches!(
        evaluate(
            &Expr::Call {
                name: "unknown".into(),
                args: vec![Expr::Literal(ExprLiteral::Null)]
            },
            &env(),
            &bindings
        )
        .state,
        State::Invalid(_)
    ));
}

fn plan(text: &str) -> ActionPlan {
    let parsed = parse_program(text);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let actions: Vec<_> = parsed
        .program
        .items
        .into_iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action),
            _ => None,
        })
        .collect();
    whipplescript_parser::action_plan::expand_syntax(&actions, "root").unwrap()
}
fn calls(plan: &ActionPlan) -> Vec<NodeId> {
    plan.nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            matches!(node.kind, NodeKind::Call { .. }).then_some(NodeId(index))
        })
        .collect()
}
fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "r".into(),
        identity: None,
        trigger_event: None,
    }
}
fn saved(journal: &mut Journal, frame: &Frame, capture: &CallCapture) {
    let context = super::super::journal::context_with_captures(
        r#"{"identity":null,"trigger_event_id":null,"bindings":[]}"#,
        frame,
        std::slice::from_ref(capture),
        capture.frontier,
    )
    .unwrap();
    journal.apply(&EventView { event_id: "event".into(), sequence: capture.frontier + 1, event_type: "rule.committed".into(), payload_json: json!({"rule":frame.rule,"context":serde_json::from_str::<Value>(&context).unwrap()}).to_string(), source:"test".into(), occurred_at:"test".into() }).unwrap();
}

#[test]
fn action_arguments_source_calls_capture_hygienic_values_and_replay_without_reads() {
    let p = plan("workflow W\naction leaf(x string, y string?) -> string { return x }\naction root(x string) -> string { leaf(x, null) as first\nleaf(\"literal\", null) as second\nreturn first }");
    let nodes = calls(&p);
    let root = p.scopes[0].parameters[0];
    let bindings = Bindings::from([(root, ready(json!("original"), "root-input"))]);
    let f = frame();
    let mut journal = Journal::default();
    let first = prepare_call(&p, nodes[0], &bindings, &journal, &f, 5).unwrap();
    let second = prepare_call(&p, nodes[1], &Bindings::new(), &journal, &f, 5).unwrap();
    assert!(first.fresh && second.fresh);
    assert_ne!(
        first.parameters.keys().collect::<Vec<_>>(),
        second.parameters.keys().collect::<Vec<_>>()
    );
    assert_eq!(first.capture.arguments[0].value, json!("original"));
    assert_eq!(
        first.capture.arguments[0].sources,
        BTreeSet::from([source("root-input")])
    );
    assert_eq!(first.capture.arguments[1].value, Value::Null);
    assert_eq!(first.capture.reads, BTreeSet::from([root.0 as u64]));
    assert!(second.capture.reads.is_empty());
    saved(&mut journal, &f, &first.capture);
    let replay = prepare_call(&p, nodes[0], &Bindings::new(), &journal, &f, 20).unwrap();
    assert!(!replay.fresh);
    assert_eq!(replay.capture, first.capture);
    assert_eq!(replay.parameters, first.parameters);
    let Slot::Ready(parameter) = replay.parameters.values().next().unwrap() else {
        panic!("ready parameter");
    };
    assert_eq!(parameter, &first.capture.arguments[0]);
    let NodeKind::Call { scope, .. } = p.nodes[nodes[0].0].kind else {
        panic!("call");
    };
    let block = &p.blocks[p.scopes[scope.0].entry.0];
    let NodeKind::Return(result) = &p.nodes[block.nodes[0].0].kind else {
        panic!("return");
    };
    let callee = evaluate(&result.expr, &block.environment, &replay.parameters);
    assert_eq!(callee.sources, first.capture.arguments[0].sources);
    value(callee, json!("original"));
}

#[test]
fn action_arguments_call_waits_for_actual_arguments_and_locates_expression_errors() {
    let text = "workflow W\naction leaf(x int, y int) -> int { return x }\naction root(a int, b int) -> int { leaf(a, b) as first\nleaf(a, 1 / 0) as second\nreturn first }";
    let p = plan(text);
    let nodes = calls(&p);
    let params = &p.scopes[0].parameters;
    let obstruction = prepare_call(
        &p,
        nodes[0],
        &Bindings::new(),
        &Journal::default(),
        &frame(),
        1,
    )
    .unwrap_err();
    assert_eq!(
        obstruction.evaluation.reads,
        params.iter().copied().collect()
    );
    pending(obstruction.evaluation, &[params[0].0, params[1].0]);
    let invalid = prepare_call(
        &p,
        nodes[1],
        &Bindings::new(),
        &Journal::default(),
        &frame(),
        1,
    )
    .unwrap_err();
    assert!(matches!(invalid.evaluation.state, State::Invalid(_)));
    assert_eq!(&text[invalid.span.start..invalid.span.end], "1 / 0");
}

#[test]
fn action_arguments_then_barrier_waits_before_argument_evaluation() {
    let p = plan("workflow W\naction leaf(x int) -> int { return x }\naction root() -> int { then first <- leaf(1)\nleaf(1 / 0) as second\nreturn second }");
    let nodes = calls(&p);
    let prior = p.nodes[nodes[0].0].result.unwrap();
    let f = frame();
    let mut journal = Journal::default();
    let obstruction = prepare_call(&p, nodes[1], &Bindings::new(), &journal, &f, 1).unwrap_err();
    pending(obstruction.evaluation, &[prior.0]);
    let bindings = Bindings::from([(prior, ready(json!(1), "prior"))]);
    assert!(matches!(
        prepare_call(&p, nodes[1], &bindings, &journal, &f, 1)
            .unwrap_err()
            .evaluation
            .state,
        State::Invalid(_)
    ));
    let mut captured = prepare_call(&p, nodes[0], &Bindings::new(), &journal, &f, 1)
        .unwrap()
        .capture;
    captured.call = nodes[1].0 as u64;
    saved(&mut journal, &f, &captured);
    assert!(
        !prepare_call(&p, nodes[1], &Bindings::new(), &journal, &f, 2)
            .unwrap()
            .fresh
    );
}

#[test]
fn action_arguments_call_obstructions_and_success_barrier_dependencies() {
    let mut p = plan("workflow W\naction leaf(x int) -> int { return x }\naction root() -> int { then first <- leaf(1)\nleaf(2) as second\nreturn second }");
    let nodes = calls(&p);
    let f = frame();
    let prior = p.nodes[nodes[0].0].result.unwrap();
    let bindings = Bindings::from([(prior, ready(json!(1), "prior"))]);
    let second = prepare_call(&p, nodes[1], &bindings, &Journal::default(), &f, 1).unwrap();
    assert_eq!(second.capture.reads, BTreeSet::from([prior.0 as u64]));
    assert!(
        second.capture.arguments[0].sources.is_empty(),
        "ordering is not value provenance"
    );
    let return_node = NodeId(
        p.nodes
            .iter()
            .position(|node| matches!(node.kind, NodeKind::Return(_)))
            .unwrap(),
    );
    assert!(matches!(
        prepare_call(&p, return_node, &bindings, &Journal::default(), &f, 1)
            .unwrap_err()
            .evaluation
            .state,
        State::Invalid(_)
    ));
    p.nodes[nodes[0].0].result = None;
    assert!(matches!(
        prepare_call(&p, nodes[1], &bindings, &Journal::default(), &f, 1)
            .unwrap_err()
            .evaluation
            .state,
        State::Invalid(_)
    ));
    let mut journal = Journal::default();
    let mut corrupt = second.capture;
    corrupt.arguments.clear();
    saved(&mut journal, &f, &corrupt);
    assert!(matches!(
        prepare_call(&p, nodes[1], &bindings, &journal, &f, 1)
            .unwrap_err()
            .evaluation
            .state,
        State::Invalid(_)
    ));
}

fn subject_argument(value: Value) -> Argument {
    Argument {
        value,
        sources: BTreeSet::from([source("a")]),
        validity: Default::default(),
        subjects: [(
            String::new(),
            FactSubject {
                fact_id: "a".into(),
                admission_event: "admit-a".into(),
            },
        )]
        .into(),
    }
}
#[test]
fn action_fact_subject_selection_and_construction_keep_exact_subvalue_identity() {
    let original = subject_argument(json!({"title":"original"}));
    let mut bindings = Bindings::from([(BindingId(0), Slot::Ready(original.clone()))]);
    assert_eq!(expression("a", &bindings).subjects, original.subjects);
    for source in [
        "a.title",
        "a[\"title\"]",
        "a.missing",
        "{title a.title}",
        "exists(a)",
        "count(a)",
        "a == a",
    ] {
        assert!(
            expression(source, &bindings).subjects.is_empty(),
            "{source}"
        );
    }
    let container = expression("{ticket a, tickets [a]}", &bindings);
    assert_eq!(
        container
            .subjects
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["/ticket", "/tickets/0"]
    );
    let State::Ready(value) = container.state else {
        panic!("container is ready")
    };
    bindings.insert(
        BindingId(1),
        Slot::Ready(Argument {
            value,
            sources: container.sources,
            subjects: container.subjects,
            validity: container.validity,
        }),
    );
    for source in ["b.ticket", "b[\"ticket\"]"] {
        assert_eq!(
            expression(source, &bindings).subjects,
            original.subjects,
            "{source}"
        );
    }
    assert_eq!(
        expression("b.tickets", &bindings)
            .subjects
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["/0"]
    );
    assert!(expression("b.ticket.title", &bindings).subjects.is_empty());
    assert!(expression("{ticket a, ticket null}", &bindings)
        .subjects
        .is_empty());
    assert_eq!(
        expression("{ticket null, ticket a}", &bindings)
            .subjects
            .len(),
        1
    );
    assert!(
        expression("[a, c]", &bindings).subjects.is_empty(),
        "pending has no subjects"
    );
}
#[test]
fn action_fact_subject_escaping_and_prefix_selection_are_unambiguous() {
    let original = subject_argument(json!({"title":"original"}));
    let mut boxed = Argument::from(json!({"a/b~c":original.value, "a":{"title":"original"},
        "ab":{"title":"original"}}));
    boxed.sources = original.sources;
    for key in ["a/b~c", "a", "ab"] {
        boxed
            .subjects
            .extend(subjects::nested(&original.subjects, key));
    }
    assert!(subjects::validate(&boxed).is_ok());
    let bindings = [(BindingId(0), Slot::Ready(boxed))].into();
    for source in ["a[\"a/b~c\"]", "a.a", "a.ab"] {
        assert_eq!(
            expression(source, &bindings).subjects,
            original.subjects,
            "{source}"
        );
    }
}
#[test]
fn action_fact_subject_computed_booleans_never_keep_input_identity() {
    for (value, source) in [
        (false, "a and true"),
        (true, "a or false"),
        (false, "a or false"),
        (true, "a and true"),
        (false, "not a"),
    ] {
        let bindings = [(BindingId(0), Slot::Ready(subject_argument(json!(value))))].into();
        assert!(
            expression(source, &bindings).subjects.is_empty(),
            "{source}"
        );
    }
}
#[test]
fn action_fact_subject_invalid_maps_refuse_before_evaluation() {
    let base = subject_argument(json!({"items":[1], "~":2}));
    for path in [
        "items",
        "/missing",
        "/items/01",
        "/items/-",
        "/items/1",
        "/items/0/child",
        "/~",
        "/~2",
    ] {
        let mut invalid = base.clone();
        let subject = invalid.subjects.remove("").unwrap();
        invalid.subjects.insert(path.into(), subject);
        let bindings = [(BindingId(0), Slot::Ready(invalid))].into();
        assert!(
            matches!(expression("a", &bindings).state, State::Invalid(_)),
            "{path}"
        );
    }
    for mutation in 0..3 {
        let mut invalid = base.clone();
        match mutation {
            0 => invalid.subjects.get_mut("").unwrap().fact_id.clear(),
            1 => invalid
                .subjects
                .get_mut("")
                .unwrap()
                .admission_event
                .clear(),
            _ => invalid.sources.clear(),
        }
        if mutation < 2 {
            let subject = &invalid.subjects[""];
            invalid.sources = BTreeSet::from([ValueSource::Fact {
                fact_id: subject.fact_id.clone(),
                admission_event: subject.admission_event.clone(),
            }]);
        }
        assert!(matches!(
            expression("a", &[(BindingId(0), Slot::Ready(invalid))].into()).state,
            State::Invalid(_)
        ));
    }
}

fn query_fact(id: &str, owner: &str) -> ProjectionFact {
    ProjectionFact {
        fact_id: id.into(),
        program_version_id: Some("v".into()),
        revision_epoch: 0,
        name: "Ticket".into(),
        key: id.into(),
        value_json: json!({"owner":owner}).to_string(),
        provenance_class: "rule".into(),
        source_span_json: None,
        validity_json: None,
        source_event_id: format!("admit-{id}"),
    }
}

fn query_effect(id: &str, kind: &str, status: &str) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: id.into(),
        kind: kind.into(),
        target: Some("agent".into()),
        input_json: "{}".into(),
        status: status.into(),
        created_by_rule: "run".into(),
        program_version_id: Some("v".into()),
        revision_epoch: 0,
        profile: None,
        cancel_requested: false,
    }
}

fn query_expression(
    source: &str,
    bindings: &Bindings,
    facts: &[ProjectionFact],
    effects: &[ProjectionEffect],
    frontier: i64,
) -> Evaluation {
    let expr = parse_expression(source).expect("query expression");
    evaluate_with_queries(
        &expr,
        &env(),
        bindings,
        QueryContext {
            frontier,
            facts,
            effects,
            views: &BTreeMap::new(),
        },
    )
}

#[test]
fn managed_fact_queries_preserve_one_frontier_and_exact_membership() {
    let facts = [query_fact("one", "alice"), query_fact("two", "bob")];
    let bindings = Bindings::from([(BindingId(0), ready(json!("alice"), "owner"))]);
    let result = query_expression("count(Ticket where owner == a)", &bindings, &facts, &[], 7);
    assert_eq!(result.state, State::Ready(json!(1)));
    assert_eq!(result.reads, BTreeSet::from([BindingId(0)]));
    assert_eq!(result.sources, BTreeSet::from([source("owner")]));
    assert_eq!(result.validity.len(), 1);
    let observation = result
        .validity
        .iter()
        .next()
        .expect("one query observation");
    assert_eq!(observation.frontier, 7);
    assert_eq!(observation.kind, ObservationKind::Fact);
    assert_eq!(observation.head, "Ticket");
    assert!(observation.guard_json.is_some());
    assert_eq!(
        observation.members,
        BTreeSet::from([ObservationMember::Fact {
            fact_id: "one".into(),
            admission_event: "admit-one".into(),
        }])
    );
}

#[test]
fn managed_fact_queries_union_every_candidate_derivation_validity() {
    let selected_upstream = QueryObservation {
        frontier: 3,
        kind: ObservationKind::Effect,
        head: "kind selected.check".into(),
        guard_json: None,
        members: Default::default(),
    };
    let rejected_upstream = QueryObservation {
        frontier: 4,
        kind: ObservationKind::Effect,
        head: "kind rejected.check".into(),
        guard_json: None,
        members: Default::default(),
    };
    let mut selected = query_fact("one", "alice");
    selected.validity_json =
        Some(serde_json::to_string(&BTreeSet::from([selected_upstream.clone()])).unwrap());
    let mut rejected = query_fact("two", "bob");
    rejected.validity_json =
        Some(serde_json::to_string(&BTreeSet::from([rejected_upstream.clone()])).unwrap());
    let bindings = Bindings::from([(BindingId(0), ready(json!("alice"), "owner"))]);
    let result = query_expression(
        "count(Ticket where owner == a)",
        &bindings,
        &[selected, rejected],
        &[],
        7,
    );
    assert_eq!(result.state, State::Ready(json!(1)));
    assert!(result.validity.contains(&selected_upstream));
    assert!(result.validity.contains(&rejected_upstream));
    assert!(result.validity.iter().any(|observation| {
        observation.kind == ObservationKind::Fact
            && observation.frontier == 7
            && observation.members.len() == 1
    }));
}

#[test]
fn managed_query_absence_is_evidence_and_composes_through_values() {
    let missing = query_expression("exists(Ticket)", &Bindings::new(), &[], &[], 11);
    assert_eq!(missing.state, State::Ready(json!(false)));
    assert!(missing
        .validity
        .iter()
        .any(|observation| observation.frontier == 11 && observation.members.is_empty()));

    let query = query_expression("empty(Ticket)", &Bindings::new(), &[], &[], 11);
    assert_eq!(query.state, State::Ready(json!(true)));
    assert!(query
        .validity
        .iter()
        .any(|observation| observation.frontier == 11 && observation.members.is_empty()));

    let expr = parse_expression("{ clear empty(Ticket), count count(Ticket) }").unwrap();
    let composed = evaluate_with_queries(
        &expr,
        &Environment::new(),
        &Bindings::new(),
        QueryContext {
            frontier: 11,
            facts: &[],
            effects: &[],
            views: &BTreeMap::new(),
        },
    );
    assert_eq!(
        composed.state,
        State::Ready(json!({"clear":true,"count":0}))
    );
    assert_eq!(
        composed.validity.len(),
        1,
        "equal reads share one observation"
    );
}

#[test]
fn managed_effect_queries_and_frontiers_remain_distinct() {
    let effects = [
        query_effect("one", "agent.tell", "completed"),
        query_effect("two", "timer.wait", "running"),
    ];
    let old = query_expression(
        "exists(effect kind agent.tell where status == \"completed\")",
        &Bindings::new(),
        &[],
        &effects,
        3,
    );
    let current = query_expression(
        "exists(effect kind agent.tell where status == \"completed\")",
        &Bindings::new(),
        &[],
        &effects,
        9,
    );
    assert_eq!(old.state, State::Ready(json!(true)));
    assert_eq!(
        old.validity.iter().next().unwrap().kind,
        ObservationKind::Effect
    );
    assert_ne!(old.validity, current.validity);
}

#[test]
fn managed_query_waits_for_outer_predicate_inputs_without_claiming_an_observation() {
    let result = query_expression(
        "exists(Ticket where owner == a)",
        &Bindings::from([(BindingId(0), Slot::Pending)]),
        &[query_fact("one", "alice")],
        &[],
        4,
    );
    assert!(matches!(
        result.state,
        State::Blocked { ref waiting, ref causes }
            if waiting == &BTreeSet::from([BindingId(0)]) && causes.is_empty()
    ));
    assert!(result.validity.is_empty());
}

#[test]
fn managed_query_refuses_missing_context_and_invalid_members() {
    assert!(matches!(
        expression("exists(Ticket)", &Bindings::new()).state,
        State::Invalid(_)
    ));
    let mut malformed = query_fact("one", "alice");
    malformed.value_json = "{".into();
    let result = query_expression("exists(Ticket)", &Bindings::new(), &[malformed], &[], 1);
    assert!(
        matches!(result.state, State::Invalid(ref issue) if issue.message.contains("invalid value JSON"))
    );
    let mut malformed_validity = query_fact("two", "bob");
    malformed_validity.validity_json = Some("{}".into());
    let result = query_expression(
        "exists(Ticket)",
        &Bindings::new(),
        &[malformed_validity],
        &[],
        1,
    );
    assert!(
        matches!(result.state, State::Invalid(ref issue) if issue.message.contains("invalid validity JSON"))
    );
    assert!(result.validity.is_empty());
}

#[test]
fn nested_parameterized_views_share_one_frontier_and_preserve_dependencies() {
    use whipplescript_parser::action_plan::resolved::TypedView;

    let views = BTreeMap::from([
        (
            "owned".into(),
            TypedView {
                parameters: vec!["expected".into()],
                expression: parse_expression("exists(Ticket where owner == expected)").unwrap(),
            },
        ),
        (
            "summary".into(),
            TypedView {
                parameters: vec!["expected".into()],
                expression: parse_expression(
                    "{ present owned(expected), absent empty(Review where owner == expected) }",
                )
                .unwrap(),
            },
        ),
    ]);
    let facts = [query_fact("one", "alice"), query_fact("two", "bob")];
    let bindings = Bindings::from([(BindingId(0), ready(json!("alice"), "owner"))]);
    let effects = [query_effect("old", "timer.wait", "completed")];
    let expression = parse_expression("summary(a)").unwrap();
    let result = evaluate_with_queries(
        &expression,
        &env(),
        &bindings,
        QueryContext {
            frontier: 23,
            facts: &facts,
            effects: &effects,
            views: &views,
        },
    );
    assert_eq!(
        result.state,
        State::Ready(json!({"present":true,"absent":true}))
    );
    assert_eq!(result.reads, BTreeSet::from([BindingId(0)]));
    assert_eq!(result.sources, BTreeSet::from([source("owner")]));
    assert_eq!(result.validity.len(), 2);
    assert!(result
        .validity
        .iter()
        .all(|observation| observation.frontier == 23));
    assert!(result
        .validity
        .iter()
        .any(|observation| observation.head == "Review" && observation.members.is_empty()));
    assert_eq!(
        effects[0].status, "completed",
        "view reads do not mutate effects"
    );
}
