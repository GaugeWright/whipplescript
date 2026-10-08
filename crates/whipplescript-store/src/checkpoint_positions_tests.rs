use super::*;

fn instance(store: &mut SqliteStore) {
    let version = store.create_program_version(NewProgramVersion {
        program_name: "CheckpointPositions", source_hash: "source", ir_hash: "ir",
        ir_snapshot: None, compiler_version: "test", declared_capabilities_json: "[]",
        declared_profiles_json: "[]", declared_skills_json: "[]", declared_schemas_json: "[]",
        analysis_summary_json: r#"{"workflow":"CheckpointPositions","workflow_contracts":[],"schemas":[]}"#,
        generated_artifacts_json: "[]", artifact_root: None,
    }).expect("program version");
    store.connection.execute("INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, workflow_principal, effective_authority, status, input_json) VALUES ('pair-instance',?1,?2,0,'root','{}','running','{}')", params![version.program_id, version.version_id]).expect("instance fixture");
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
fn checkpoint_pair_retains_original_cut_and_refuses_changed_command() {
    let mut store = SqliteStore::open_in_memory().expect("store");
    instance(&mut store);
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
fn checkpoint_pair_busy_and_failed_cut_leave_no_carrier_or_manifest() {
    let mut store = SqliteStore::open_in_memory().expect("store");
    instance(&mut store);
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
    let mut store = SqliteStore::open_in_memory().expect("store");
    instance(&mut store);
    store.connection.execute_batch("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON events WHEN NEW.event_type='context.checkpoint' BEGIN SELECT RAISE(ABORT,'owned checkpoint append fault'); END;").expect("fault trigger");
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
    let blobs: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM content_blobs", [], |row| row.get(0))
        .expect("manifest count");
    assert_eq!(blobs, 0);
    store
        .connection
        .execute_batch("DROP TRIGGER reject_checkpoint")
        .expect("restore fault");
    store
        .capture_checkpoint_with_positions(capture(), positions())
        .expect("retry after rollback");
}

#[test]
fn checkpoint_pair_refuses_legacy_unpaired_and_orphan_carriers() {
    let mut store = SqliteStore::open_in_memory().expect("store");
    instance(&mut store);
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
    let mut store = SqliteStore::open_in_memory().expect("store");
    instance(&mut store);
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

fn paired_state(
    store: &SqliteStore,
) -> (
    Vec<EventView>,
    event_chain::ChainHead,
    Vec<(String, String)>,
) {
    let blobs = store
        .connection
        .prepare("SELECT id, body FROM content_blobs ORDER BY id")
        .expect("blob snapshot")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("blob rows")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("blob snapshot rows");
    (
        store.list_events("pair-instance").expect("event snapshot"),
        store.chain_head("pair-instance").expect("chain snapshot"),
        blobs,
    )
}

#[test]
fn checkpoint_pair_requires_stable_identity_before_publication() {
    let mut store = SqliteStore::open_in_memory().expect("store");
    instance(&mut store);
    let before = paired_state(&store);
    for (cut, pair) in [
        (
            CheckpointCapture {
                idempotency_key: None,
                ..capture()
            },
            positions(),
        ),
        (
            CheckpointCapture {
                idempotency_key: Some(""),
                ..capture()
            },
            positions(),
        ),
        (
            capture(),
            CheckpointPositions {
                idempotency_key: "",
                ..positions()
            },
        ),
        (
            capture(),
            CheckpointPositions {
                source: "",
                ..positions()
            },
        ),
    ] {
        let error = store
            .capture_checkpoint_with_positions(cut, pair)
            .expect_err("invalid identity refuses");
        assert!(
            format!("{error:?}").contains("paired checkpoint requires stable command identities"),
            "{error:?}"
        );
        assert_eq!(paired_state(&store), before);
    }
    store
        .capture_checkpoint_with_positions(capture(), positions())
        .expect("valid original pair");
}

#[test]
fn checkpoint_pair_requires_object_positions_before_publication() {
    let mut store = SqliteStore::open_in_memory().expect("store");
    instance(&mut store);
    let before = paired_state(&store);
    for value in ["[]", "null", "true", "1", "\"positions\""] {
        let pair = CheckpointPositions {
            positions_json: value,
            ..positions()
        };
        let error = store
            .capture_checkpoint_with_positions(capture(), pair)
            .expect_err("nonobject refuses");
        assert!(
            format!("{error:?}").contains("checkpoint positions must be an object"),
            "{error:?}"
        );
        assert_eq!(paired_state(&store), before);
    }
    store
        .capture_checkpoint_with_positions(capture(), positions())
        .expect("valid original pair");
}

fn corrupt_retained_checkpoint(field: &str) {
    let mut store = SqliteStore::open_in_memory().expect("store");
    instance(&mut store);
    let original = store
        .capture_checkpoint_with_positions(capture(), positions())
        .expect("actual paired cut");
    let event = store
        .list_events("pair-instance")
        .expect("actual events")
        .into_iter()
        .find(|event| event.event_type == "context.checkpoint")
        .expect("actual cut event");
    let raw: String = store
        .connection
        .query_row(
            "SELECT payload_json FROM events WHERE event_id=?1",
            [&event.event_id],
            |row| row.get(0),
        )
        .expect("original stored bytes");
    let mut value: serde_json::Value =
        serde_json::from_str(&event.payload_json).expect("actual cut payload");
    let diagnostic = if field == "manifest" {
        value["manifest"] = serde_json::json!({"owned-fault-path":"owned-fault-digest"});
        value["file_count"] = serde_json::json!(1);
        "retained checkpoint manifest identity differs"
    } else {
        value["file_count"] = serde_json::json!(original.checkpoint.file_count + 1);
        "retained checkpoint manifest count differs"
    };
    let altered = value.to_string();
    store.connection.execute("UPDATE events SET payload_json=whip_runtime_event_seal(event_id,event_type,?1) WHERE event_id=?2", params![altered, event.event_id]).expect("owned retained-record corruption");
    let before = paired_state(&store);
    let error = store
        .capture_checkpoint_with_positions(capture(), positions())
        .expect_err("corrupt retained pair refuses");
    assert!(format!("{error:?}").contains(diagnostic), "{error:?}");
    assert_eq!(paired_state(&store), before);
    store
        .connection
        .execute(
            "UPDATE events SET payload_json=?1 WHERE event_id=?2",
            params![raw, event.event_id],
        )
        .expect("restore exact retained bytes");
    assert_eq!(
        store
            .capture_checkpoint_with_positions(capture(), positions())
            .expect("exact original redelivery"),
        original
    );
}

#[test]
fn checkpoint_pair_verifies_retained_manifest_identity() {
    corrupt_retained_checkpoint("manifest");
}

#[test]
fn checkpoint_pair_verifies_retained_manifest_count() {
    corrupt_retained_checkpoint("file_count");
}
