use super::*;
use crate::source_action::journal::{context_with_captures, root, CallCapture};
use serde_json::json;
use whipplescript_store::EventView;

fn frame() -> Frame {
    Frame {
        version: "v1".into(),
        revision: "0".into(),
        rule: "run".into(),
        identity: None,
        trigger_event: Some("started".into()),
    }
}
fn cut(region: u64, frontier: i64, phase: Phase) -> Cut {
    Cut {
        region,
        frontier,
        phase,
    }
}
fn admission(frontier: i64) -> RootCapture {
    RootCapture {
        inputs: vec![],
        frontier,
    }
}
fn context(frame: &Frame) -> String {
    json!({"identity":frame.identity,"trigger_event_id":frame.trigger_event,"bindings":[]})
        .to_string()
}
fn event(
    frame: &Frame,
    root: Option<&RootCapture>,
    calls: &[CallCapture],
    cuts: &[Cut],
    sequence: i64,
) -> EventView {
    let context = context_with_captures(&context(frame), frame, calls, sequence - 1).unwrap();
    let context = root::context_with_root(&context, frame, root, sequence - 1).unwrap();
    let context = context_with_regions(&context, frame, cuts, sequence - 1).unwrap();
    EventView {
        event_id: format!("event-{sequence}"),
        sequence,
        event_type: "rule.committed".into(),
        payload_json:
            json!({"rule":frame.rule,"context":serde_json::from_str::<Value>(&context).unwrap()})
                .to_string(),
        source: "test".into(),
        occurred_at: "test".into(),
    }
}
fn change(event: &EventView, mutate: impl FnOnce(&mut Value)) -> EventView {
    let mut event = event.clone();
    let mut payload: Value = serde_json::from_str(&event.payload_json).unwrap();
    mutate(&mut payload);
    event.payload_json = payload.to_string();
    event
}
fn started() -> Journal {
    let mut journal = Journal::default();
    journal
        .apply(&event(&frame(), Some(&admission(0)), &[], &[], 1))
        .unwrap();
    journal
}

#[test]
fn action_region_journal_retains_held_cuts_and_exact_old_replay() {
    for final_phase in [Phase::Exited, Phase::Lapsed] {
        let f = frame();
        let mut journal = started();
        for (frontier, phase) in [(1, Phase::Holding), (3, Phase::Holding), (5, final_phase)] {
            journal
                .apply(&event(
                    &f,
                    None,
                    &[],
                    &[cut(7, frontier, phase)],
                    frontier + 1,
                ))
                .unwrap();
        }
        let history = journal.region(&f, 7).unwrap();
        assert_eq!(history.latest(), Some(&cut(7, 5, final_phase)));
        assert_eq!(
            history.held_frontier(),
            Some(if final_phase == Phase::Exited { 5 } else { 3 })
        );
        assert_eq!(
            history.cuts().map(|c| c.frontier).collect::<Vec<_>>(),
            [1, 3, 5]
        );
        let before = journal.clone();
        journal
            .apply(&event(&f, None, &[], &[cut(7, 1, Phase::Holding)], 10))
            .unwrap();
        assert_eq!(journal, before, "replay must not replace the latest cut");
        journal
            .check_regions(&f, &[cut(7, 1, Phase::Holding)], None, 20)
            .unwrap();
    }
}

#[test]
fn action_region_journal_entry_lapse_has_no_invented_held_prefix() {
    let f = frame();
    for phase in [Phase::Lapsed, Phase::Exited] {
        let mut journal = started();
        journal
            .apply(&event(&f, None, &[], &[cut(7, 1, phase)], 2))
            .unwrap();
        assert_eq!(
            journal.region(&f, 7).unwrap().held_frontier(),
            (phase == Phase::Exited).then_some(1)
        );
    }
}

#[test]
fn action_region_journal_refuses_reopening_rewriting_and_unrecorded_past_cuts() {
    for final_phase in [Phase::Exited, Phase::Lapsed] {
        let f = frame();
        let mut journal = started();
        journal
            .apply(&event(&f, None, &[], &[cut(7, 3, final_phase)], 4))
            .unwrap();
        let before = journal.clone();
        for phase in [Phase::Holding, Phase::Exited, Phase::Lapsed] {
            assert!(journal
                .apply(&event(&f, None, &[], &[cut(7, 5, phase)], 6))
                .is_err());
            assert_eq!(journal, before);
        }
        for candidate in [cut(7, 2, Phase::Holding), cut(7, 3, Phase::Holding)] {
            assert!(journal
                .apply(&event(&f, None, &[], &[candidate], 6))
                .is_err());
            assert_eq!(journal, before);
        }
    }
    let mut journal = started();
    journal
        .apply(&event(&frame(), None, &[], &[cut(7, 3, Phase::Holding)], 4))
        .unwrap();
    assert!(journal
        .apply(&event(&frame(), None, &[], &[cut(7, 2, Phase::Holding)], 5))
        .is_err());
}

#[test]
fn action_region_journal_isolates_every_frame_coordinate_and_structural_node() {
    let original = frame();
    let mut variants = vec![];
    for field in 0..5 {
        let mut other = original.clone();
        match field {
            0 => other.version = "v2".into(),
            1 => other.revision = "1".into(),
            2 => other.rule = "another".into(),
            3 => other.identity = Some("new-fact".into()),
            _ => other.trigger_event = Some("new-admission".into()),
        }
        variants.push(other);
    }
    let mut journal = Journal::default();
    journal
        .apply(&event(
            &original,
            Some(&admission(1)),
            &[],
            &[cut(7, 1, Phase::Lapsed)],
            2,
        ))
        .unwrap();
    for other in variants {
        journal
            .apply(&event(
                &other,
                Some(&admission(1)),
                &[],
                &[cut(7, 1, Phase::Holding)],
                2,
            ))
            .unwrap();
        assert_eq!(
            journal.region(&other, 7).unwrap().latest().unwrap().phase,
            Phase::Holding
        );
        assert_eq!(
            journal
                .region(&original, 7)
                .unwrap()
                .latest()
                .unwrap()
                .phase,
            Phase::Lapsed
        );
    }
    journal
        .apply(&event(
            &original,
            None,
            &[],
            &[cut(8, 1, Phase::Holding)],
            3,
        ))
        .unwrap();
    assert_eq!(
        journal
            .region(&original, 8)
            .unwrap()
            .latest()
            .unwrap()
            .phase,
        Phase::Holding
    );
}

#[test]
fn action_region_journal_requires_admission_and_the_actual_committing_frontier() {
    let f = frame();
    assert!(Journal::default()
        .check_regions(&f, &[cut(7, 1, Phase::Holding)], None, 1)
        .is_err());
    assert!(Journal::default()
        .apply(&event(&f, None, &[], &[cut(7, 1, Phase::Holding)], 2))
        .is_err());
    assert!(Journal::default()
        .apply(&event(
            &f,
            Some(&admission(2)),
            &[],
            &[cut(7, 1, Phase::Holding)],
            3
        ))
        .is_err());
    let journal = started();
    for frontier in [-1, 1, 3] {
        assert!(journal
            .check_regions(&f, &[cut(7, frontier, Phase::Holding)], None, 2)
            .is_err());
    }
    assert!(journal
        .check_regions(&f, &[cut(7, 2, Phase::Holding)], None, 2)
        .is_ok());
    let duplicate = [cut(7, 1, Phase::Holding), cut(7, 2, Phase::Exited)];
    assert!(journal.check_regions(&f, &duplicate, None, 2).is_err());
    assert!(context_with_regions(&context(&f), &f, &duplicate, 2).is_err());
}

#[test]
fn action_region_preview_validates_without_mutating_the_durable_view() {
    let f = frame();
    let journal = started();
    let next = cut(7, 1, Phase::Holding);
    let preview = journal
        .preview_regions(&f, std::slice::from_ref(&next), None, 1)
        .expect("valid phase preview");

    assert!(journal.region(&f, 7).is_none());
    assert_eq!(preview.region(&f, 7).unwrap().latest(), Some(&next));
    assert!(journal
        .preview_regions(&f, &[cut(7, 0, Phase::Holding)], None, 1)
        .is_err());
    assert!(journal.region(&f, 7).is_none());
}

#[test]
fn action_region_journal_validates_all_commit_parts_before_publishing_any() {
    let f = frame();
    let calls = [CallCapture {
        call: 2,
        arguments: vec![],
        reads: Default::default(),
        frontier: 1,
    }];
    let valid = event(
        &f,
        Some(&admission(1)),
        &calls,
        &[cut(7, 1, Phase::Holding)],
        2,
    );
    let mut invalid = vec![
        change(&valid, |p| p["context"][FIELD]["schema"] = json!("unknown")),
        change(&valid, |p| {
            p["context"][FIELD]["cuts"][0]["phase"] = json!("cancel_requested")
        }),
        change(&valid, |p| {
            p["context"][FIELD]["cuts"][0]["frontier"] = json!(99)
        }),
        change(&valid, |p| {
            p["context"][FIELD]["cuts"][0]["extra"] = json!(true)
        }),
        change(&valid, |p| {
            p["context"][FIELD]["frame"]["version"] = json!("different")
        }),
        change(&valid, |p| {
            p["context"]["action_captures"]["calls"][0]["frontier"] = json!(-1)
        }),
        change(&valid, |p| {
            p["context"]["action_root"]["root"]["frontier"] = json!(-1)
        }),
        change(&valid, |p| {
            p["context"][FIELD]["frame"]["rule"] = json!("different")
        }),
        change(&valid, |p| {
            p["context"][FIELD]["frame"]["identity"] = json!("different")
        }),
    ];
    invalid.push(change(&valid, |p| {
        p["context"][FIELD]["cuts"][0]
            .as_object_mut()
            .unwrap()
            .remove("frontier");
    }));
    invalid.push(change(&valid, |p| {
        let cut = p["context"][FIELD]["cuts"][0].clone();
        p["context"][FIELD]["cuts"]
            .as_array_mut()
            .unwrap()
            .push(cut);
    }));
    for event in invalid {
        let mut journal = Journal::default();
        assert!(journal.apply(&event).is_err(), "{}", event.payload_json);
        assert_eq!(
            journal,
            Journal::default(),
            "no partial root, call or region publication"
        );
    }
    let mut journal = started();
    journal
        .apply(&event(&f, None, &[], &[cut(7, 1, Phase::Lapsed)], 2))
        .unwrap();
    let before = journal.clone();
    let calls = [CallCapture {
        frontier: 3,
        ..calls[0].clone()
    }];
    assert!(journal
        .apply(&event(&f, None, &calls, &[cut(7, 3, Phase::Holding)], 4))
        .is_err());
    assert_eq!(
        journal, before,
        "invalid region history must not publish a new call"
    );
}

#[test]
fn action_region_journal_checks_call_frame_even_without_a_root_delta() {
    let f = frame();
    let mut journal = started();
    let calls = [CallCapture {
        call: 2,
        arguments: vec![],
        reads: Default::default(),
        frontier: 1,
    }];
    let valid = event(&f, None, &calls, &[cut(7, 1, Phase::Holding)], 2);
    let invalid = change(&valid, |p| {
        p["context"]["action_captures"]["frame"]["version"] = json!("different")
    });
    let before = journal.clone();
    assert!(journal.apply(&invalid).is_err());
    assert_eq!(journal, before);
}

#[test]
fn action_region_journal_serialization_preserves_legacy_bytes_and_commit_identity() {
    use crate::lowering::OwnedLowering;
    let f = frame();
    let original = "{ \"identity\": null, \"trigger_event_id\": \"started\", \"bindings\": [] }";
    assert_eq!(
        context_with_regions(original, &f, &[], 2).unwrap(),
        original
    );
    let a = cut(7, 2, Phase::Holding);
    let b = cut(8, 2, Phase::Lapsed);
    assert_eq!(
        identity(&[a.clone(), b.clone()]),
        identity(&[b.clone(), a.clone()])
    );
    assert_eq!(
        context_with_regions(original, &f, &[a.clone(), b.clone()], 2).unwrap(),
        context_with_regions(original, &f, &[b, a.clone()], 2).unwrap()
    );
    let encoded = context_with_regions(original, &f, std::slice::from_ref(&a), 2).unwrap();
    assert!(context_with_regions(&encoded, &f, std::slice::from_ref(&a), 2).is_err());
    for invalid in ["[]", "broken", "{}"] {
        assert!(context_with_regions(invalid, &f, std::slice::from_ref(&a), 2).is_err());
    }
    let lowering = OwnedLowering {
        action_regions: vec![a.clone()],
        ..Default::default()
    };
    assert!(lowering.has_commit_work());
    let key = crate::rule_pass::lowering_idempotency_key(&lowering);
    assert_ne!(
        key,
        crate::rule_pass::lowering_idempotency_key(&OwnedLowering::default())
    );
    for changed in [
        cut(8, 2, Phase::Holding),
        cut(7, 1, Phase::Holding),
        cut(7, 2, Phase::Lapsed),
    ] {
        assert_ne!(
            identity(std::slice::from_ref(&a)),
            identity(std::slice::from_ref(&changed))
        );
        assert_ne!(
            key,
            crate::rule_pass::lowering_idempotency_key(&OwnedLowering {
                action_regions: vec![changed],
                ..Default::default()
            })
        );
    }
}
