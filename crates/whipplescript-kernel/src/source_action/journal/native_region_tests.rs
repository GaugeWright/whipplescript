//! The real store/commit protocol, not a claim of executable managed regions.
use super::*;
use crate::source_action::journal::{
    regions::{Cut, Phase},
    root::RootCapture,
};
use whipplescript_store::StoreError;

const SOURCE: &str = "@service\nworkflow RegionCuts\nrule finish when started => { during true { timer 1s as held } on lapse { timer 1s as lapsed } }";

fn fixture(store: SqliteStore) -> (Fixture, u64) {
    let parsed = whipplescript_parser::parse_program(SOURCE);
    assert!(parsed.diagnostics.is_empty());
    let typed =
        whipplescript_parser::action_plan::resolved::resolve_rule_types(&parsed.program, "finish")
            .expect("region fixture resolves source types");
    let region = typed
        .plan
        .nodes
        .iter()
        .position(|node| {
            matches!(
                node.kind,
                whipplescript_parser::action_plan::NodeKind::Region { .. }
            )
        })
        .expect("region fixture contains a structural region") as u64;
    (Fixture::with_source(store, SOURCE), region)
}
fn commit_at(
    f: &mut Fixture,
    lowering: &OwnedLowering,
    frontier: i64,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    let journal = f.journal();
    commit_lowering(
        &mut f.kernel,
        &f.instance,
        &f.ir,
        &f.context,
        &f.frame,
        lowering,
        &journal,
        frontier,
        RuleCommitRevisionGuard {
            evaluated_frontier: None,
            program_version_id: &f.frame.version,
            revision_epoch: 0,
        },
    )
}

#[test]
fn action_region_journal_native_cut_only_commit_is_atomic_and_exactly_replayable() {
    let (mut f, region) = fixture(SqliteStore::open_in_memory().unwrap());
    let frontier = f.events().last().unwrap().sequence;
    commit_at(
        &mut f,
        &OwnedLowering {
            action_root: Some(RootCapture {
                inputs: vec![],
                frontier,
            }),
            ..Default::default()
        },
        frontier,
    )
    .unwrap();
    let frontier = f.events().last().unwrap().sequence;
    let stale = OwnedLowering {
        action_regions: vec![Cut {
            region,
            frontier,
            phase: Phase::Holding,
        }],
        ..Default::default()
    };
    f.kernel
        .ingest_external_event(&f.instance, "external.later", "{}", Some("later"))
        .unwrap();
    let before = f.events();
    let refusal = commit_at(&mut f, &stale, frontier).unwrap_err();
    assert!(matches!(refusal, StoreError::GuardRefused { .. }));
    assert_eq!(
        f.events(),
        before,
        "a stale cut-only lowering appends nothing"
    );
    assert!(f.journal().region(&f.frame, region).is_none());

    let frontier = f.events().last().unwrap().sequence;
    let current = OwnedLowering {
        action_regions: vec![Cut {
            region,
            frontier,
            phase: Phase::Holding,
        }],
        ..Default::default()
    };
    let committed = commit_at(&mut f, &current, frontier).unwrap();
    let closed_frontier = f.events().last().unwrap().sequence;
    let closed = OwnedLowering {
        action_regions: vec![Cut {
            region,
            frontier: closed_frontier,
            phase: Phase::Lapsed,
        }],
        ..Default::default()
    };
    commit_at(&mut f, &closed, closed_frontier).unwrap();
    let before = f.events();
    assert_eq!(
        commit_at(&mut f, &current, frontier).unwrap().event_id,
        committed.event_id
    );
    assert_eq!(f.events(), before, "older exact replay has no new event");
    let journal = f.journal();
    let history = journal.region(&f.frame, region).unwrap();
    assert_eq!(history.latest().unwrap().phase, Phase::Lapsed);
    assert_eq!(history.held_frontier(), Some(frontier));
    let next_frontier = f.events().last().unwrap().sequence;
    let reopened = OwnedLowering {
        action_regions: vec![Cut {
            region,
            frontier: next_frontier,
            phase: Phase::Holding,
        }],
        ..Default::default()
    };
    let error = commit_at(&mut f, &reopened, next_frontier).unwrap_err();
    assert!(format!("{error:?}").contains("cannot advance"));
    assert_eq!(f.events(), before);
    assert!(f
        .kernel
        .store()
        .list_effects(&f.instance)
        .unwrap()
        .is_empty());
    assert!(f.kernel.store().list_facts(&f.instance).unwrap().is_empty());
}

#[test]
fn action_region_journal_native_reopen_preserves_earlier_cuts_and_terminal_history() {
    let path = std::env::temp_dir().join(format!(
        "whip-region-cuts-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (mut f, region) = fixture(SqliteStore::open(&path).unwrap());
    let frontier = f.events().last().unwrap().sequence;
    let first = OwnedLowering {
        action_root: Some(RootCapture {
            inputs: vec![],
            frontier,
        }),
        action_regions: vec![Cut {
            region,
            frontier,
            phase: Phase::Holding,
        }],
        ..Default::default()
    };
    let committed = commit_at(&mut f, &first, frontier).unwrap();
    let exit_frontier = f.events().last().unwrap().sequence;
    commit_at(
        &mut f,
        &OwnedLowering {
            action_regions: vec![Cut {
                region,
                frontier: exit_frontier,
                phase: Phase::Exited,
            }],
            ..Default::default()
        },
        exit_frontier,
    )
    .unwrap();
    let expected = f.journal();
    let Fixture {
        ir,
        instance,
        frame,
        context,
        kernel,
    } = f;
    drop(kernel);
    let mut reopened = Fixture {
        kernel: RuntimeKernel::new(wrap(SqliteStore::open(&path).unwrap())),
        ir,
        instance,
        frame,
        context,
    };
    assert_eq!(reopened.journal(), expected);
    let events = reopened.events();
    assert_eq!(
        commit_at(&mut reopened, &first, frontier).unwrap().event_id,
        committed.event_id
    );
    assert_eq!(reopened.events(), events);
    let journal = reopened.journal();
    let history = journal.region(&reopened.frame, region).unwrap();
    assert_eq!(history.held_frontier(), Some(exit_frontier));
    assert_eq!(
        history.cuts().map(|cut| cut.phase).collect::<Vec<_>>(),
        [Phase::Holding, Phase::Exited]
    );
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}
