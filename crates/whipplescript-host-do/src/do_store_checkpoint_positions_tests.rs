use super::test_support::store as test_store;
use super::*;

fn instance(store: &DoSqliteStore<impl DoSql>) {
    store.sql.execute("INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, workflow_principal, effective_authority, status, input_json) VALUES ('pair-instance','p','v',0,'root','{}','running','{}')", &[]).expect("instance fixture");
}
fn capture() -> CheckpointCapture<'static> {
    CheckpointCapture {
        instance_id: "pair-instance",
        cut_id: "cut",
        transcript_ref: Some("turn-1"),
        idempotency_key: Some("cut-key"),
    }
}
fn positions() -> CheckpointPositions<'static> {
    CheckpointPositions {
        positions_json: r#"{"tracker_event_seq":1,"coordination_ledgers":[]}"#,
        external_json: Some("null"),
        source: "cli",
        idempotency_key: "position-key",
    }
}

#[test]
fn do_checkpoint_pair_retains_original_cut_and_refuses_changed_command() {
    let mut store = test_store();
    instance(&store);
    let first = store
        .capture_checkpoint_with_positions(capture(), positions())
        .expect("capture");
    let before = store.list_events("pair-instance").expect("events");
    let original_head = store.chain_head("pair-instance").expect("head");
    assert_eq!(before.len(), 2);
    assert_eq!(before[0].event_type, "plane.positions");
    assert_eq!(before[1].sequence, first.checkpoint.sequence);
    let changed = CheckpointPositions {
        positions_json: r#"{"tracker_event_seq":99,"coordination_ledgers":[]}"#,
        ..positions()
    };
    assert_eq!(
        store
            .capture_checkpoint_with_positions(capture(), changed)
            .expect("redelivery"),
        first
    );
    for (cut, pair) in [
        (
            CheckpointCapture {
                transcript_ref: Some("turn-2"),
                ..capture()
            },
            positions(),
        ),
        (
            CheckpointCapture {
                idempotency_key: Some("different-key"),
                ..capture()
            },
            positions(),
        ),
        (
            capture(),
            CheckpointPositions {
                external_json: Some(r#"{"ledger":2}"#),
                ..positions()
            },
        ),
        (
            capture(),
            CheckpointPositions {
                source: "do",
                ..positions()
            },
        ),
    ] {
        assert!(store.capture_checkpoint_with_positions(cut, pair).is_err());
    }
    assert_eq!(
        store.list_events("pair-instance").expect("unchanged"),
        before
    );
    assert_eq!(
        store.chain_head("pair-instance").expect("unchanged head"),
        original_head
    );
}

#[test]
fn do_checkpoint_pair_busy_and_failed_cut_leave_no_carrier_or_manifest() {
    let mut store = test_store();
    instance(&store);
    let effects = [NewEffect {
        effect_id: "busy",
        kind: "timer.wait",
        target: None,
        input_json: "{}",
        status: "queued",
        idempotency_key: "busy-key",
        required_capabilities_json: "[]",
        profile: None,
        correlation_id: None,
        source_span_json: None,
        timeout_seconds: None,
    }];
    store
        .commit_rule(RuleCommit {
            instance_id: "pair-instance",
            rule: "busy",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &effects,
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("busy-rule"),
            marks: &[],
            context_json: None,
        })
        .expect("ordinary rule admission");
    store
        .start_run(RunStart {
            instance_id: "pair-instance",
            effect_id: "busy",
            run_id: "busy-run",
            provider: "test",
            worker_id: "worker",
            lease_id: "lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        })
        .expect("ordinary run start");
    let before = store.list_events("pair-instance").expect("events");
    let original_head = store.chain_head("pair-instance").expect("head");
    assert!(store
        .capture_checkpoint_with_positions(capture(), positions())
        .is_err());
    assert_eq!(
        store.list_events("pair-instance").expect("no orphan"),
        before
    );
    assert_eq!(
        store.chain_head("pair-instance").expect("unchanged head"),
        original_head
    );
    // A separate quiescent instance exercises real SQL failure AFTER the carrier.
    let mut store = test_store();
    instance(&store);
    store.sql.execute("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON events WHEN NEW.event_type='context.checkpoint' BEGIN SELECT RAISE(ABORT,'owned checkpoint append fault'); END;", &[]).expect("fault trigger");
    assert!(store
        .capture_checkpoint_with_positions(capture(), positions())
        .is_err());
    assert!(store
        .list_events("pair-instance")
        .expect("rollback events")
        .is_empty());
    assert_eq!(
        store
            .chain_head("pair-instance")
            .expect("rolled back head")
            .sequence,
        None
    );
    let rows = store
        .sql
        .query("SELECT COUNT(*) FROM content_blobs", &[])
        .expect("manifest count");
    assert_eq!(as_i64(&rows[0][0]), 0);
    store
        .sql
        .execute("DROP TRIGGER reject_checkpoint", &[])
        .expect("restore fault");
    store
        .capture_checkpoint_with_positions(capture(), positions())
        .expect("retry after rollback");
}

#[test]
fn do_checkpoint_pair_refuses_legacy_unpaired_and_orphan_carriers() {
    let mut store = test_store();
    instance(&store);
    store
        .capture_checkpoint(capture())
        .expect("legacy unpaired");
    let before = store.list_events("pair-instance").expect("events");
    let original_head = store.chain_head("pair-instance").expect("head");
    assert!(store
        .capture_checkpoint_with_positions(capture(), positions())
        .is_err());
    assert_eq!(
        store.list_events("pair-instance").expect("no relabel"),
        before
    );
    assert_eq!(
        store.chain_head("pair-instance").expect("unchanged head"),
        original_head
    );
    let mut store = test_store();
    instance(&store);
    let payload = checkpoint_positions::payload(capture(), positions()).expect("payload");
    store
        .append_event(NewEvent {
            instance_id: "pair-instance",
            event_type: "plane.positions",
            payload_json: &payload,
            source: "cli",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("position-key"),
        })
        .expect("historical orphan");
    let before = store.list_events("pair-instance").expect("events");
    let original_head = store.chain_head("pair-instance").expect("head");
    assert!(store
        .capture_checkpoint_with_positions(capture(), positions())
        .is_err());
    assert_eq!(
        store.list_events("pair-instance").expect("unchanged"),
        before
    );
    assert_eq!(
        store.chain_head("pair-instance").expect("unchanged head"),
        original_head
    );
}

#[test]
fn paired_checkpoint_requires_an_executed_atomic_bridge() {
    struct Unsupported;
    impl DoSql for Unsupported {
        fn execute(&self, _: &str, _: &[SqlValue]) -> Result<u64, String> {
            panic!("must refuse before body")
        }
        fn query(&self, _: &str, _: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            panic!("must refuse before body")
        }
    }
    assert!(DoSqliteStore::new(Unsupported)
        .capture_checkpoint_with_positions(capture(), positions())
        .is_err());
    struct Silent;
    impl DoSql for Silent {
        fn atomic(&self, _: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
            Ok(())
        }
        fn execute(&self, _: &str, _: &[SqlValue]) -> Result<u64, String> {
            panic!("silent bridge")
        }
        fn query(&self, _: &str, _: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            panic!("silent bridge")
        }
    }
    assert!(DoSqliteStore::new(Silent)
        .capture_checkpoint_with_positions(capture(), positions())
        .is_err());
}

fn retained_manifest_fault_is_refused(corrupt: bool) {
    let mut store = test_store();
    instance(&store);
    let first = store
        .capture_checkpoint_with_positions(capture(), positions())
        .expect("real paired capture");
    let manifest = store
        .get_content(&first.checkpoint.manifest_hash)
        .expect("original manifest read")
        .expect("original manifest exists");
    assert_eq!(stable_hash_hex(&manifest), first.checkpoint.manifest_hash);
    let before = store.list_events("pair-instance").expect("original events");
    let head = store.chain_head("pair-instance").expect("original head");
    if corrupt {
        store
            .sql
            .execute(
                "UPDATE content_blobs SET body = ?1 WHERE id = ?2",
                &[
                    text("owned corrupt manifest"),
                    text(&first.checkpoint.manifest_hash),
                ],
            )
            .expect("owned retained blob corruption");
    } else {
        store
            .sql
            .execute(
                "DELETE FROM content_blobs WHERE id = ?1",
                &[text(&first.checkpoint.manifest_hash)],
            )
            .expect("owned retained blob removal");
    }
    let faulty_blob = store
        .get_content(&first.checkpoint.manifest_hash)
        .expect("fault read");
    let error = store
        .capture_checkpoint_with_positions(capture(), positions())
        .expect_err("missing or corrupt retained manifest must refuse replay");
    assert!(
        matches!(error, StoreError::Conflict(ref message)
        if message == "retained checkpoint manifest is unavailable"),
        "{error:?}"
    );
    assert_eq!(
        store.list_events("pair-instance").expect("no append"),
        before
    );
    assert_eq!(
        store.chain_head("pair-instance").expect("no head advance"),
        head
    );
    assert_eq!(
        store
            .get_content(&first.checkpoint.manifest_hash)
            .expect("no silent repair"),
        faulty_blob
    );
    store
        .sql
        .execute(
            "INSERT OR REPLACE INTO content_blobs (id, body, byte_len) VALUES (?1, ?2, ?3)",
            &[
                text(&first.checkpoint.manifest_hash),
                text(&manifest),
                int(manifest.len() as i64),
            ],
        )
        .expect("restore exact retained manifest");
    assert_eq!(
        store
            .capture_checkpoint_with_positions(capture(), positions())
            .expect("restored exact replay"),
        first
    );
    assert_eq!(
        store
            .list_events("pair-instance")
            .expect("restored replay no append"),
        before
    );
    assert_eq!(
        store
            .chain_head("pair-instance")
            .expect("restored replay unchanged head"),
        head
    );
}

#[test]
fn do_checkpoint_pair_refuses_missing_retained_manifest() {
    retained_manifest_fault_is_refused(false);
}

#[test]
fn do_checkpoint_pair_refuses_corrupt_retained_manifest() {
    retained_manifest_fault_is_refused(true);
}
