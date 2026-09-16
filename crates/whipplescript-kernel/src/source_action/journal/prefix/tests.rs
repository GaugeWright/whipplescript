use super::*;
use crate::source_action::arguments::{Argument, FactSubject, ValueSource};
use crate::source_action::journal::{
    context_with_captures,
    regions::{context_with_regions, Cut, Phase},
    root::{context_with_root, RootCapture, RootInput},
    CallCapture, Frame,
};
use serde_json::{json, Value};
use whipplescript_store::EventView;

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "run".into(),
        identity: None,
        trigger_event: Some("started".into()),
    }
}
fn argument(tag: &str) -> Argument {
    Argument {
        value: json!({"tag":tag}),
        sources: [ValueSource::Fact {
            fact_id: format!("fact-{tag}"),
            admission_event: format!("event-{tag}"),
        }]
        .into(),
        validity: Default::default(),
        subjects: [(
            String::new(),
            FactSubject {
                fact_id: format!("fact-{tag}"),
                admission_event: format!("event-{tag}"),
            },
        )]
        .into(),
    }
}
fn root(frontier: i64, tag: &str) -> RootCapture {
    RootCapture {
        frontier,
        inputs: vec![RootInput {
            binding: 0,
            argument: argument(tag),
        }],
    }
}
fn call(call: u64, frontier: i64, tag: &str) -> CallCapture {
    CallCapture {
        call,
        frontier,
        arguments: vec![argument(tag)],
        reads: [0].into(),
    }
}
fn event(
    f: &Frame,
    root: Option<&RootCapture>,
    calls: &[CallCapture],
    cuts: &[Cut],
    sequence: i64,
) -> EventView {
    let context =
        json!({"identity":f.identity,"trigger_event_id":f.trigger_event,"bindings":[]}).to_string();
    let context = context_with_root(&context, f, root, sequence - 1).unwrap();
    let context = context_with_captures(&context, f, calls, sequence - 1).unwrap();
    let context = context_with_regions(&context, f, cuts, sequence - 1).unwrap();
    EventView {
        event_id: format!("commit-{sequence}"),
        sequence,
        event_type: "rule.committed".into(),
        payload_json:
            json!({"rule":f.rule,"context":serde_json::from_str::<Value>(&context).unwrap()})
                .to_string(),
        source: "test".into(),
        occurred_at: "test".into(),
    }
}
fn history() -> Journal {
    let f = frame();
    let mut journal = Journal::default();
    for event in [
        event(&f, Some(&root(1, "root")), &[], &[], 3),
        event(
            &f,
            None,
            &[call(7, 2, "early")],
            &[Cut {
                region: 9,
                frontier: 2,
                phase: Phase::Holding,
            }],
            5,
        ),
        event(
            &f,
            None,
            &[call(8, 4, "later")],
            &[Cut {
                region: 9,
                frontier: 4,
                phase: Phase::Lapsed,
            }],
            7,
        ),
    ] {
        journal.apply(&event).unwrap();
    }
    journal
}

#[test]
fn action_capture_prefix_uses_evaluation_not_publication_and_keeps_exact_boundary() {
    let f = frame();
    let journal = history();
    let before = journal.at_evaluation(0);
    assert_eq!(before, Journal::default());
    let admission = journal.at_evaluation(1);
    assert_eq!(admission.root(&f), Some(&root(1, "root")));
    assert!(admission.calls(&f).is_none());
    assert!(admission.regions(&f).is_none());
    // Both the call and held cut were published at sequence 5, after cut 2.
    let held = journal.at_evaluation(2);
    assert_eq!(held.root(&f), Some(&root(1, "root")));
    assert_eq!(held.calls(&f).unwrap(), &[(7, call(7, 2, "early"))].into());
    let region = held.region(&f, 9).unwrap();
    assert_eq!(region.latest().unwrap().phase, Phase::Holding);
    assert_eq!(region.held_frontier(), Some(2));
    assert_eq!(region.cuts().count(), 1);
    assert_eq!(journal.at_evaluation(3), held);
    assert_eq!(journal.at_evaluation(4), journal);
}

#[test]
fn action_capture_prefix_is_pure_preserves_all_history_and_cannot_restore_discarded_future() {
    let f = frame();
    let journal = history();
    let original = journal.clone();
    let held = journal.at_evaluation(2);
    assert_eq!(journal, original);
    assert_eq!(held.at_evaluation(99), held);
    assert_eq!(held.at_evaluation(1), journal.at_evaluation(1));
    assert_eq!(journal.at_evaluation(i64::MAX), original);
    assert_eq!(journal.at_evaluation(-1), Journal::default());
    let history = journal.region(&f, 9).unwrap();
    assert_eq!(
        history
            .cuts()
            .map(|cut| (cut.frontier, cut.phase))
            .collect::<Vec<_>>(),
        [(2, Phase::Holding), (4, Phase::Lapsed)]
    );
    assert_eq!(history.held_frontier(), Some(2));
    assert_eq!(
        journal.at_evaluation(2),
        held,
        "later reads cannot mutate the earlier selection"
    );
}

#[test]
fn action_capture_prefix_preserves_each_firing_axis_and_value_provenance() {
    let original = frame();
    let mut journal = Journal::default();
    let mut frames = vec![original.clone()];
    for axis in 0..5 {
        let mut f = original.clone();
        match axis {
            0 => f.version = "other".into(),
            1 => f.revision = "fork".into(),
            2 => f.rule = "other".into(),
            3 => f.identity = Some("another".into()),
            _ => f.trigger_event = Some("readmitted".into()),
        }
        frames.push(f);
    }
    for (index, f) in frames.iter().enumerate() {
        journal
            .apply(&event(
                f,
                Some(&root(1, &index.to_string())),
                &[call(7, 2, &index.to_string())],
                &[Cut {
                    region: 9,
                    frontier: 2,
                    phase: Phase::Exited,
                }],
                5,
            ))
            .unwrap();
    }
    let selected = journal.at_evaluation(2);
    for (index, f) in frames.iter().enumerate() {
        assert_eq!(selected.root(f), Some(&root(1, &index.to_string())));
        assert_eq!(
            selected.calls(f).unwrap()[&7],
            call(7, 2, &index.to_string())
        );
        assert_eq!(selected.region(f, 9).unwrap().held_frontier(), Some(2));
    }
    assert_eq!(selected, journal);
}

#[test]
fn action_capture_prefix_keeps_entry_lapse_and_legacy_calls_without_inventing_root() {
    let f = frame();
    let mut journal = Journal::default();
    journal
        .apply(&event(&f, None, &[call(7, 2, "legacy")], &[], 3))
        .unwrap();
    let legacy = journal.at_evaluation(2);
    assert!(legacy.root(&f).is_none());
    assert_eq!(legacy.calls(&f).unwrap()[&7], call(7, 2, "legacy"));
    journal
        .apply(&event(
            &f,
            Some(&root(4, "later")),
            &[],
            &[Cut {
                region: 9,
                frontier: 4,
                phase: Phase::Lapsed,
            }],
            5,
        ))
        .unwrap();
    assert_eq!(journal.at_evaluation(2), legacy);
    assert!(journal.at_evaluation(3).regions(&f).is_none());
    let lapsed = journal.at_evaluation(4);
    let history = lapsed.region(&f, 9).unwrap();
    assert_eq!(history.latest().unwrap().phase, Phase::Lapsed);
    assert_eq!(history.held_frontier(), None);
}
