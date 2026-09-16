use super::*;
use serde_json::json;
use whipplescript_parser::parse_expression;
fn read(target: Slot, key: Slot) -> Evaluation {
    let env = BTreeMap::from([("items".into(), BindingId(0)), ("key".into(), BindingId(1))]);
    super::super::evaluate(
        &parse_expression("items[key]").unwrap(),
        &env,
        &BTreeMap::from([(BindingId(0), target), (BindingId(1), key)]),
    )
}
fn ready(value: Value) -> Slot {
    Slot::Ready(value.into())
}
#[test]
fn action_indexing_runtime_distinguishes_array_positions_and_map_keys() {
    for (target, key, expected) in [
        (json!(["a", "b"]), json!(1), State::Ready(json!("b"))),
        (json!(["a"]), json!(1), State::Absent),
        (json!(["a"]), json!(-1), State::Absent),
        (json!([]), json!(0), State::Absent),
        (json!({"0":"map"}), json!("0"), State::Ready(json!("map"))),
        (json!({}), json!("missing"), State::Absent),
        (Value::Null, json!(0), State::Absent),
        (Value::Null, json!("key"), State::Absent),
    ] {
        assert_eq!(read(ready(target), ready(key)).state, expected);
    }
    for (target, key, message) in [
        (json!([1]), json!("0"), "array index requires an integer"),
        (json!([1]), json!(0.0), "array index requires an integer"),
        (json!({"0":1}), json!(0), "map index requires a string"),
        (json!({}), Value::Null, "map index requires a string"),
        (
            Value::Null,
            json!(true),
            "index key requires an integer or string",
        ),
        (
            json!("text"),
            json!(0),
            "index target requires an array or map",
        ),
    ] {
        let State::Invalid(error) = read(ready(target), ready(key)).state else {
            panic!("invalid key accepted")
        };
        assert!(error.message.contains(message), "{error:?}");
    }
}
#[test]
fn action_indexing_runtime_waits_and_failures_precede_optional_absence() {
    let cause = CauseId("original-key-failure".into());
    for target in [json!([]), Value::Null] {
        assert_eq!(
            read(ready(target.clone()), Slot::Pending).state,
            State::Blocked {
                waiting: [BindingId(1)].into(),
                causes: BTreeSet::new()
            }
        );
        assert_eq!(
            read(ready(target), Slot::Failed([cause.clone()].into())).state,
            State::Blocked {
                waiting: BTreeSet::new(),
                causes: [cause.clone()].into()
            }
        );
    }
    assert_eq!(
        read(Slot::Pending, Slot::Pending).state,
        State::Blocked {
            waiting: [BindingId(0), BindingId(1)].into(),
            causes: BTreeSet::new()
        }
    );
    assert_eq!(
        read(Slot::Pending, Slot::Failed([cause.clone()].into())).state,
        State::Blocked {
            waiting: [BindingId(0)].into(),
            causes: [cause].into()
        }
    );
}
#[test]
fn action_indexing_runtime_keeps_only_the_selected_fact_subject_and_both_sources() {
    let subject = FactSubject {
        fact_id: "ticket".into(),
        admission_event: "admitted-ticket".into(),
    };
    let key_subject = FactSubject {
        fact_id: "index".into(),
        admission_event: "admitted-index".into(),
    };
    let source = |s: &FactSubject| ValueSource::Fact {
        fact_id: s.fact_id.clone(),
        admission_event: s.admission_event.clone(),
    };
    let target = Argument {
        value: json!([{"id":"first"},{"id":"second"}]),
        subjects: [("/1".into(), subject.clone())].into(),
        sources: [source(&subject)].into(),
        validity: Default::default(),
    };
    let key = Argument {
        value: json!(1),
        subjects: [(String::new(), key_subject.clone())].into(),
        sources: [source(&key_subject)].into(),
        validity: Default::default(),
    };
    let result = read(Slot::Ready(target.clone()), Slot::Ready(key.clone()));
    assert_eq!(result.state, State::Ready(json!({"id":"second"})));
    assert_eq!(result.subjects, [(String::new(), subject.clone())].into());
    assert_eq!(
        result.sources,
        [source(&subject), source(&key_subject)].into()
    );
    for value in [0, 2, -1] {
        let mut key = key.clone();
        key.value = json!(value);
        assert!(read(Slot::Ready(target.clone()), Slot::Ready(key))
            .subjects
            .is_empty());
    }
    let mut target = target;
    target.subjects.clear();
    target.subjects.insert(String::new(), subject);
    assert!(read(Slot::Ready(target), Slot::Ready(key))
        .subjects
        .is_empty());
}
