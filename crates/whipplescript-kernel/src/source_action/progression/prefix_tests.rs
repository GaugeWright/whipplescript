use super::*;
use crate::source_action::journal::{context_with_captures, root::context_with_root};

#[test]
fn action_capture_prefix_reconstructs_before_a_later_helper_was_reached() {
    let p = plan("action helper() -> int { return 2 }\naction root() -> int { timer 1s as gate\nafter gate succeeds { helper() as child }\nreturn 1 }");
    let run = |frontier, state, journal: &Journal| {
        advance(
            &p,
            "instance",
            &frame(),
            frontier,
            &Bindings::new(),
            journal,
            |_| {
                Ok(leaf(
                    state,
                    (state == WorkState::Succeeded).then_some(Value::Null),
                ))
            },
        )
    };
    let first = run(1, WorkState::Pending, &Journal::default()).unwrap();
    let mut journal = saved(
        &first.lowering.action_captures,
        first.lowering.action_root.as_ref().unwrap(),
    );
    let next = run(4, WorkState::Succeeded, &journal).unwrap();
    assert_eq!(next.lowering.action_captures.len(), 1);
    let context = context_with_root(
        r#"{"identity":null,"trigger_event_id":null,"bindings":[]}"#,
        &frame(),
        None,
        4,
    )
    .unwrap();
    let context =
        context_with_captures(&context, &frame(), &next.lowering.action_captures, 4).unwrap();
    journal
        .apply(&whipplescript_store::EventView {
            event_id: "later".into(),
            sequence: 5,
            event_type: "rule.committed".into(),
            payload_json:
                json!({"rule":"root","context":serde_json::from_str::<Value>(&context).unwrap()})
                    .to_string(),
            source: "test".into(),
            occurred_at: "test".into(),
        })
        .unwrap();
    // Today's journal cannot be used with the old pending operation: its
    // later helper capture correctly fails the unreachable-call check.
    assert!(run(1, WorkState::Pending, &journal)
        .unwrap_err()
        .message
        .contains("unreachable"));
    let earlier = run(1, WorkState::Pending, &journal.at_evaluation(1)).unwrap();
    assert_eq!(earlier.scopes, first.scopes);
    assert_eq!(earlier.active_blocks, first.active_blocks);
    assert_eq!(earlier.bindings, first.bindings);
    assert_eq!(earlier.selected_blocks, first.selected_blocks);
    assert!(earlier.lowering.action_captures.is_empty());
    let later = run(4, WorkState::Succeeded, &journal.at_evaluation(4)).unwrap();
    assert_eq!(later.scopes, next.scopes);
    assert_eq!(later.active_blocks, next.active_blocks);
    assert!(
        later.lowering.action_captures.is_empty(),
        "the exact-frontier call remains recorded"
    );
}
