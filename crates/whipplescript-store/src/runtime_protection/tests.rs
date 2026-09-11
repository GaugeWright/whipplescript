use super::*;
use crate::payload_protection::PayloadCodec;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Default)]
struct Codec {
    erased: AtomicBool,
}
// Reversible test codec only; actual authenticated cryptography is host-owned.
impl PayloadCodec for Codec {
    fn seal(&self, aad: &[u8], body: &[u8]) -> StoreResult<Vec<u8>> {
        if self.erased.load(Ordering::SeqCst) {
            return Err(StoreError::fault("fixture", "erased"));
        }
        Ok(serde_json::to_vec(&(
            aad,
            body.iter().map(|b| b ^ 93).collect::<Vec<_>>(),
        ))?)
    }
    fn open(&self, aad: &[u8], body: &[u8]) -> StoreResult<Vec<u8>> {
        if self.erased.load(Ordering::SeqCst) {
            return Err(StoreError::fault("fixture", "erased"));
        }
        let (expected, body): (Vec<u8>, Vec<u8>) = serde_json::from_slice(body)?;
        if aad != expected {
            return Err(StoreError::fault("fixture", "coordinate changed"));
        }
        Ok(body.iter().map(|b| b ^ 93).collect())
    }
    fn retain(&self, callback: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
        callback()
    }
}
fn protection(codec: Arc<Codec>) -> PayloadProtection {
    PayloadProtection::new("project", codec).unwrap()
}

#[test]
fn protected_runtime_retains_original_event_bytes_chain_and_content() {
    use crate::log_append::LogAppend;
    let codec = Arc::new(Codec::default());
    let store = SqliteStore::open_in_memory_protected(protection(codec.clone())).unwrap();
    let raw = "{ \"body\": \"private-runtime-canary\" }\n";
    store
        .append_event(NewEvent {
            instance_id: "workflow",
            event_type: "message.created",
            payload_json: raw,
            source: "human",
            causation_id: Some("cause"),
            correlation_id: None,
            idempotency_key: Some("once"),
        })
        .unwrap();
    let original = store.chain_prefix("workflow").unwrap();
    assert_eq!(original[0].payload_json, raw);
    assert_eq!(
        store.chain_head("workflow").unwrap(),
        event_chain::fold_owned("workflow", &original)
    );
    store.repair_event_chain().unwrap();
    assert_eq!(
        store.chain_head("workflow").unwrap(),
        event_chain::fold_owned("workflow", &original)
    );
    let id = store.put_content("private-source-canary").unwrap();
    assert_eq!(
        store.get_content(&id).unwrap().as_deref(),
        Some("private-source-canary")
    );
    let meta = store.event_metadata("workflow").unwrap();
    assert_eq!(meta[0].source, "human");
    assert_eq!(meta[0].causation_id.as_deref(), Some("cause"));
    for query in [
        "SELECT payload_json FROM events",
        "SELECT body FROM content_blobs",
    ] {
        let raw: rusqlite::types::Value =
            store.connection.query_row(query, [], |r| r.get(0)).unwrap();
        assert!(!format!("{raw:?}").contains("private-"));
    }
    codec.erased.store(true, Ordering::SeqCst);
    assert!(store.chain_prefix("workflow").is_err());
    assert!(store.get_content(&id).is_err());
    assert!(store.put_content("private-after-erasure-canary").is_err());
    assert_eq!(store.event_metadata("workflow").unwrap(), meta);
}

fn program(store: &mut SqliteStore) -> ProgramVersionRecord {
    let source = "private-source-canary";
    let ir = "private-ir-canary";
    store.put_content(source).unwrap();
    store
        .create_program_version(NewProgramVersion {
            program_name: "ProtectedProgram",
            source_hash: &stable_hash_hex(source),
            ir_hash: &stable_hash_hex(ir),
            compiler_version: "fixture",
            ir_snapshot: Some(ir),
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: r#"{"analysis":"private-analysis-canary"}"#,
            generated_artifacts_json: r#"["private-artifact-canary"]"#,
            artifact_root: Some("private-root-canary"),
        })
        .unwrap()
}
fn instance(store: &mut SqliteStore) -> String {
    let version = program(store);
    store
        .create_instance_with_authority(
            NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: r#"{"input":"private-input-canary"}"#,
            },
            NewInstanceAuthority {
                workflow_principal: "person:learner",
                effective_authority_json: "[]",
            },
        )
        .unwrap()
        .instance_id
}
fn no_canaries(store: &SqliteStore) {
    let tables: Vec<String> = store
        .connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for table in tables {
        let mut statement = store
            .connection
            .prepare(&format!("SELECT * FROM {table}"))
            .unwrap();
        let count = statement.column_count();
        let rows = statement
            .query_map([], |r| {
                (0..count)
                    .map(|i| r.get::<_, rusqlite::types::Value>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        for row in rows {
            for value in row.unwrap() {
                let bytes = match &value {
                    rusqlite::types::Value::Text(text) => text.as_bytes(),
                    rusqlite::types::Value::Blob(bytes) => bytes.as_slice(),
                    _ => continue,
                };
                assert!(
                    !bytes.windows(8).any(|part| part == b"private-"),
                    "plaintext in {table}: {value:?}"
                );
            }
        }
    }
}

#[test]
fn protected_facts_effects_runs_and_replay_preserve_their_payloads() {
    let mut store =
        SqliteStore::open_in_memory_protected(protection(Arc::new(Codec::default()))).unwrap();
    let instance = instance(&mut store);
    store
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "fixture.execute",
            description: "private-capability-canary",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    store
        .register_effect_provider(EffectProviderRegistration {
            provider_id: "fixture",
            effect_kind: "fixture.effect",
            provider: "fixture",
            capability: "fixture.execute",
            config_json: r#"{"value":"private-provider-canary"}"#,
            registered_by_package_id: None,
        })
        .unwrap();
    store
        .bind_capability(CapabilityBinding {
            binding_id: "binding",
            program_id: None,
            capability: "fixture.execute",
            provider: "fixture",
            config_json: r#"{"value":"private-binding-canary"}"#,
        })
        .unwrap();
    let body = r#"{"text":"private-fact-canary"}"#;
    let span = r#"{"path":"private-span-canary"}"#;
    let fact = NewFact {
        fact_id: "fact",
        name: "Input",
        key: "private-natural-key-canary",
        value_json: body,
        schema_id: None,
        provenance_class: "derived",
        correlation_id: None,
        source_span_json: Some(span),
    };
    let effect = NewEffect {
        effect_id: "effect",
        kind: "fixture.effect",
        target: None,
        input_json: r#"{"body":"private-effect-canary"}"#,
        status: "queued",
        idempotency_key: "effect",
        required_capabilities_json: r#"["fixture.execute"]"#,
        profile: None,
        correlation_id: None,
        source_span_json: None,
        timeout_seconds: None,
    };
    let commit = RuleCommit {
        instance_id: &instance,
        rule: "start",
        trigger_event_id: None,
        facts: &[fact],
        consumed_fact_ids: &[],
        effects: &[effect],
        dependencies: &[],
        terminal: None,
        idempotency_key: Some("start"),
        marks: &[],
        context_json: None,
    };
    store.commit_rule(commit).unwrap();
    assert_eq!(store.list_facts(&instance).unwrap()[0].value_json, body);
    assert_eq!(
        store.list_effects(&instance).unwrap()[0].input_json,
        effect.input_json
    );
    assert_eq!(
        store.claimable_effects(&instance).unwrap()[0].input_json,
        effect.input_json
    );
    store
        .start_run(RunStart {
            instance_id: &instance,
            effect_id: "effect",
            run_id: "run",
            provider: "fixture",
            worker_id: "worker",
            lease_id: "lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: r#"{"value":"private-run-canary"}"#,
        })
        .unwrap();
    store
        .complete_effect(EffectCompletion {
            instance_id: &instance,
            effect_id: "effect",
            run_id: "run",
            provider: "fixture",
            worker_id: "worker",
            status: "completed",
            exit_code: Some(0),
            summary: Some("private-summary-canary"),
            metadata_json: r#"{"value":"private-result-canary"}"#,
            idempotency_key: Some("terminal"),
        })
        .unwrap();
    let facts = store.list_facts(&instance).unwrap();
    let effects = store.list_effects(&instance).unwrap();
    let runs = store.list_runs(&instance).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&runs[0].metadata_json).unwrap()["value"],
        "private-result-canary"
    );
    let events = store.list_events(&instance).unwrap();
    no_canaries(&store);
    store.rebuild_projections(&instance).unwrap();
    assert_eq!(store.list_facts(&instance).unwrap(), facts);
    assert_eq!(store.list_effects(&instance).unwrap(), effects);
    assert_eq!(store.list_runs(&instance).unwrap(), runs);
    assert_eq!(store.list_events(&instance).unwrap(), events);
    no_canaries(&store);
    // Reviving a consumed fact changes its admission id, while the retained
    // source span remains keyed to the stable logical fact.
    store
        .commit_rule(RuleCommit {
            rule: "consume",
            facts: &[],
            effects: &[],
            consumed_fact_ids: &["fact"],
            idempotency_key: Some("consume"),
            ..commit
        })
        .unwrap();
    store
        .commit_rule(RuleCommit {
            rule: "revive",
            facts: &[NewFact {
                fact_id: "revived",
                ..fact
            }],
            effects: &[],
            idempotency_key: Some("revive"),
            ..commit
        })
        .unwrap();
    assert!(store
        .list_facts(&instance)
        .unwrap()
        .iter()
        .any(|f| f.fact_id == "revived" && f.value_json == body));
    no_canaries(&store);
}

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "whip-runtime-protection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("runtime.sqlite")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn protected_runtime_reopens_without_plaintext_fallback() {
    let fixture = Fixture::new();
    let codec = Arc::new(Codec::default());
    let mut store =
        SqliteStore::create_protected(fixture.path(), protection(codec.clone())).unwrap();
    let instance = instance(&mut store);
    let events = store.list_events(&instance).unwrap();
    for path in [fixture.path(), fixture.path().with_extension("sqlite-wal")] {
        let bytes = std::fs::read(path).unwrap();
        assert!(!bytes.windows(8).any(|s| s == b"private-"));
    }
    assert!(SqliteStore::open(fixture.path()).is_err());
    assert!(SqliteStore::open_existing(fixture.path()).is_err());
    assert!(SqliteStore::open_read_only(fixture.path()).is_err());
    assert!(SqliteStore::open_initialized(fixture.path()).is_err());
    let readonly =
        SqliteStore::open_read_only_protected(fixture.path(), protection(codec.clone())).unwrap();
    assert_eq!(readonly.list_events(&instance).unwrap(), events);
    drop(readonly);
    drop(store);
    let mut store =
        SqliteStore::open_existing_protected(fixture.path(), protection(codec)).unwrap();
    store.rebuild_projections(&instance).unwrap();
    assert_eq!(store.list_events(&instance).unwrap(), events);
    assert_eq!(
        store.get_instance(&instance).unwrap().unwrap().input_json,
        r#"{"input":"private-input-canary"}"#
    );
    no_canaries(&store);
}

#[test]
fn protected_natural_keys_preserve_batch_deduplication_order_and_replay() {
    let codec = Arc::new(Codec::default());
    let mut store = SqliteStore::open_in_memory_protected(protection(codec.clone())).unwrap();
    let instance = instance(&mut store);
    let rows = [
        FactBatchRow {
            fact_id: "z",
            key: "private-z-key",
            value_json: "{}",
        },
        FactBatchRow {
            fact_id: "a",
            key: "private-a-key",
            value_json: "{}",
        },
    ];
    let batch = FactBatch {
        instance_id: &instance,
        source: "import",
        causation_id: None,
        correlation_id: None,
        schema_name: "Input",
        schema_id: None,
        rows: &rows,
    };
    assert_eq!(
        store.admit_fact_batch(batch).unwrap(),
        FactBatchOutcome {
            admitted: 2,
            skipped: 0
        }
    );
    let repeated = [FactBatchRow {
        fact_id: "repeat",
        ..rows[0]
    }];
    assert_eq!(
        store
            .admit_fact_batch(FactBatch {
                rows: &repeated,
                ..batch
            })
            .unwrap(),
        FactBatchOutcome {
            admitted: 0,
            skipped: 1
        }
    );
    let facts = store.list_facts(&instance).unwrap();
    assert_eq!(
        facts.iter().map(|f| f.key.as_str()).collect::<Vec<_>>(),
        vec!["private-a-key", "private-z-key"]
    );
    let meta = store.event_metadata(&instance).unwrap();
    assert!(meta
        .iter()
        .filter(|e| e.event_type == "fact.derived")
        .all(|e| e.operational.get("key").is_none()));
    no_canaries(&store);
    store.rebuild_projections(&instance).unwrap();
    assert_eq!(store.list_facts(&instance).unwrap(), facts);
    no_canaries(&store);
    codec.erased.store(true, Ordering::SeqCst);
    assert!(store.list_facts(&instance).is_err());
    assert_eq!(store.event_metadata(&instance).unwrap(), meta);
}

#[test]
fn protected_repair_scope_upsert_keeps_paths_out_of_storage() {
    let mut store =
        SqliteStore::open_in_memory_protected(protection(Arc::new(Codec::default()))).unwrap();
    let instance = instance(&mut store);
    for (branch, slice, source) in [
        ("branch", "path(private-first)", "private-first.whip"),
        ("branch-2", "path(private-second)", "private-second.whip"),
    ] {
        store
            .record_repair_scope(&instance, branch, slice, source)
            .unwrap();
        assert_eq!(
            store.repair_scope(&instance).unwrap(),
            Some((branch.into(), slice.into(), source.into()))
        );
        no_canaries(&store);
    }
}

#[test]
fn protected_runtime_content_authentication_also_checks_plaintext_identity() {
    let store =
        SqliteStore::open_in_memory_protected(protection(Arc::new(Codec::default()))).unwrap();
    let id = store.put_content("original").unwrap();
    // Correctly authenticated at this coordinate, but not the named content.
    store.connection.execute(
        "UPDATE content_blobs SET body = whip_payload_seal('runtime.content', id, ?2) WHERE id = ?1",
        params![id, "different"],
    ).unwrap();
    assert!(
        matches!(store.get_content(&id), Err(StoreError::ContentMismatch { id: recorded, actual, source })
        if recorded == id && actual == stable_hash_hex("different") && source == "protected runtime content")
    );
}

#[derive(Default)]
struct RetentionCodec {
    inner: Codec,
    gate: std::sync::Mutex<()>,
    active: AtomicBool,
    denied: AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
    pause: std::sync::Mutex<
        Option<(
            std::sync::mpsc::SyncSender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
}
impl PayloadCodec for RetentionCodec {
    fn seal(&self, aad: &[u8], body: &[u8]) -> StoreResult<Vec<u8>> {
        assert!(
            self.active.load(Ordering::SeqCst),
            "publication outside host retention"
        );
        if let Some((entered, resume)) = self.pause.lock().unwrap().take() {
            entered.send(()).unwrap();
            resume
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
        }
        self.inner.seal(aad, body)
    }
    fn open(&self, aad: &[u8], body: &[u8]) -> StoreResult<Vec<u8>> {
        self.inner.open(aad, body)
    }
    fn retain(&self, callback: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
        let _guard = self.gate.lock().unwrap();
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.denied.load(Ordering::SeqCst) || self.inner.erased.load(Ordering::SeqCst) {
            return Err(StoreError::fault("fixture", "retention unavailable"));
        }
        self.active.store(true, Ordering::SeqCst);
        let outcome = callback();
        self.active.store(false, Ordering::SeqCst);
        outcome
    }
}

#[test]
fn protected_host_action_holds_retention_through_admission_commit() {
    let codec = Arc::new(RetentionCodec::default());
    let mut store = SqliteStore::open_in_memory_protected(
        PayloadProtection::new("project", codec.clone()).unwrap(),
    )
    .unwrap();
    let version = crate::host_actions::conformance::register(&mut store);
    let calls = codec.calls.load(Ordering::SeqCst);
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
    *codec.pause.lock().unwrap() = Some((entered_tx, resume_rx));
    let writer = std::thread::spawn(move || {
        let admission = store
            .admit_host_action(crate::host_actions::conformance::action(&version))
            .unwrap();
        (store, admission)
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    assert!(
        codec.gate.try_lock().is_err(),
        "key erasure could enter during admission"
    );
    let erasure_codec = codec.clone();
    let (waiting_tx, waiting_rx) = std::sync::mpsc::sync_channel(0);
    let eraser = std::thread::spawn(move || {
        waiting_tx.send(()).unwrap();
        let _guard = erasure_codec.gate.lock().unwrap();
        erasure_codec.inner.erased.store(true, Ordering::SeqCst);
    });
    waiting_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    assert!(!codec.inner.erased.load(Ordering::SeqCst));
    resume_tx.send(()).unwrap();
    let (store, admission) = writer.join().unwrap();
    eraser.join().unwrap();
    assert_eq!(codec.calls.load(Ordering::SeqCst), calls + 1);
    assert!(!admission.replayed);
    assert!(store
        .event_metadata(&admission.instance_id)
        .unwrap()
        .iter()
        .any(|event| event.event_id == admission.admitted.event_id));
    assert!(store.list_events(&admission.instance_id).is_err());
    let facts: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM facts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(facts, 2);
}

#[test]
fn protected_retention_refusal_and_sql_rollback_leave_no_partial_action() {
    let codec = Arc::new(RetentionCodec::default());
    let mut store = SqliteStore::open_in_memory_protected(
        PayloadProtection::new("project", codec.clone()).unwrap(),
    )
    .unwrap();
    let version = crate::host_actions::conformance::register(&mut store);
    let action = crate::host_actions::conformance::action(&version);
    codec.denied.store(true, Ordering::SeqCst);
    assert!(store.admit_host_action(action).is_err());
    assert!(store.get_instance(action.instance_id).unwrap().is_none());
    assert!(store.event_metadata(action.instance_id).unwrap().is_empty());
    codec.denied.store(false, Ordering::SeqCst);
    store.connection.execute_batch(
        "CREATE TRIGGER refuse_second_input BEFORE INSERT ON facts WHEN NEW.fact_id = 'action-second' BEGIN SELECT RAISE(ABORT, 'fixture'); END;"
    ).unwrap();
    assert!(store.admit_host_action(action).is_err());
    assert!(!store.retention_active.load(Ordering::SeqCst));
    assert!(!codec.active.load(Ordering::SeqCst));
    assert!(store.get_instance(action.instance_id).unwrap().is_none());
    assert!(store.event_metadata(action.instance_id).unwrap().is_empty());
    assert!(store.list_facts(action.instance_id).unwrap().is_empty());
    store
        .connection
        .execute_batch("DROP TRIGGER refuse_second_input")
        .unwrap();
    let admission = store.admit_host_action(action).unwrap();
    assert!(!admission.replayed);
    assert!(store.admit_host_action(action).unwrap().replayed);
    let calls = codec.calls.load(Ordering::SeqCst);
    store
        .retained_publication()
        .run(|| store.put_content("private-nested-canary"))
        .unwrap();
    assert_eq!(codec.calls.load(Ordering::SeqCst), calls + 1);
    assert!(!store.retention_active.load(Ordering::SeqCst));
    no_canaries(&store);
}

#[test]
fn protected_runtime_rejects_wrong_missing_and_foreign_bindings() {
    let fixture = Fixture::new();
    let codec = Arc::new(Codec::default());
    let protection = protection(codec.clone());
    let store = SqliteStore::create_protected(fixture.path(), protection.clone()).unwrap();
    assert!(SqliteStore::create_protected(fixture.path(), protection.clone()).is_err());
    assert!(SqliteStore::open_existing_protected(
        fixture.path(),
        PayloadProtection::new("another-project", codec.clone()).unwrap()
    )
    .is_err());
    store
        .connection
        .execute_batch("DROP TABLE runtime_payload_protection")
        .unwrap();
    drop(store);
    assert!(SqliteStore::open(fixture.path()).is_err());
    assert!(SqliteStore::open_existing_protected(fixture.path(), protection.clone()).is_err());
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch("CREATE TABLE foreign_authority (id TEXT)")
        .unwrap();
    assert!(SqliteStore::initialize_protected(connection, protection.clone()).is_err());
    let plain = Fixture::new();
    SqliteStore::open(plain.path()).unwrap();
    assert!(SqliteStore::open_existing_protected(plain.path(), protection).is_err());
}

#[test]
fn protected_runtime_rejects_moved_ciphertext_and_invalid_event_envelopes() {
    let mut store =
        SqliteStore::open_in_memory_protected(protection(Arc::new(Codec::default()))).unwrap();
    let first = instance(&mut store);
    let second = instance(&mut store);
    store.connection.execute(
        "UPDATE instances SET input_json = (SELECT input_json FROM instances WHERE instance_id = ?1) WHERE instance_id = ?2",
        params![first, second],
    ).unwrap();
    assert!(store.get_instance(&second).is_err());
    assert!(store.get_instance(&first).unwrap().is_some());
    store.connection.execute(
        "UPDATE events SET payload_json = json_set(payload_json, '$.version', 2) WHERE instance_id = ?1",
        [&first],
    ).unwrap();
    assert!(store.list_events(&first).is_err());
    assert!(store.event_metadata(&first).is_err());
    store.connection.execute(
        "UPDATE events SET payload_json = json_set(payload_json, '$.operational.status', 'tampered') WHERE instance_id = ?1",
        [&second],
    ).unwrap();
    assert!(store.list_events(&second).is_err());
}

#[test]
fn protected_dispatch_uses_decoded_inputs_and_preserves_observation_refusals() {
    let codec = Arc::new(RetentionCodec::default());
    let mut store =
        SqliteStore::open_in_memory_protected(PayloadProtection::new("project", codec).unwrap())
            .unwrap();
    crate::dispatch_definition::conformance::run_suite(&mut store);
}

#[test]
fn protected_generated_refusal_keys_do_not_copy_error_text_into_headers() {
    let mut store =
        SqliteStore::open_in_memory_protected(protection(Arc::new(Codec::default()))).unwrap();
    let instance = instance(&mut store);
    store
        .commit_rule(RuleCommit {
            instance_id: &instance,
            rule: "start",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &[NewEffect {
                effect_id: "blocked-effect",
                kind: "fixture",
                target: None,
                input_json: "{}",
                status: "queued",
                idempotency_key: "blocked-effect",
                required_capabilities_json: "[]",
                profile: None,
                correlation_id: None,
                source_span_json: None,
                timeout_seconds: None,
            }],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("start"),
            marks: &[],
            context_json: None,
        })
        .unwrap();
    let before = store.list_events(&instance).unwrap().len();
    for _ in 0..2 {
        store
            .retained_publication()
            .run(|| {
                persist_policy_block_on(
                    &store.connection,
                    &instance,
                    "blocked-effect",
                    &PolicyBlock {
                        status: "blocked_by_admission",
                        reason: "private-policy-canary".into(),
                    },
                )
            })
            .unwrap();
    }
    assert_eq!(store.list_events(&instance).unwrap().len(), before + 1);
    for attempt in 0..2 {
        let outcome = store.retained_publication().run(|| {
            store.record_terminal_refusal(
                EffectCompletion {
                    instance_id: &instance,
                    effect_id: "blocked-effect",
                    run_id: "run",
                    provider: "fixture",
                    worker_id: "worker",
                    status: "failed",
                    exit_code: None,
                    summary: None,
                    metadata_json: "{}",
                    idempotency_key: None,
                },
                "failed",
                Err(StoreError::Conflict("private-terminal-canary".into())),
            )
        });
        assert!(outcome.is_err());
        if attempt == 0 {
            assert!(matches!(outcome, Err(StoreError::Conflict(reason))
                if reason == "private-terminal-canary"));
        }
    }
    assert_eq!(store.list_events(&instance).unwrap().len(), before + 2);
    no_canaries(&store);
    let plain = SqliteStore::open_in_memory().unwrap();
    assert_eq!(
        metadata_key(&plain.connection, "legacy-key").unwrap(),
        "legacy-key"
    );
    assert_ne!(
        metadata_key(&store.connection, "legacy-key").unwrap(),
        "legacy-key"
    );
}

#[test]
fn protected_worker_open_preserves_schema_and_enforces_domain_and_wal() {
    let fixture = Fixture::new();
    let protection = protection(Arc::new(Codec::default()));
    assert!(SqliteStore::open_initialized_protected(fixture.path(), protection.clone()).is_err());
    let store = SqliteStore::create_protected(fixture.path(), protection.clone()).unwrap();
    let worker =
        SqliteStore::open_initialized_protected(fixture.path(), protection.clone()).unwrap();
    let id = worker.put_content("private-worker-canary").unwrap();
    assert_eq!(
        store.get_content(&id).unwrap().as_deref(),
        Some("private-worker-canary")
    );
    assert!(SqliteStore::open_initialized_protected(
        fixture.path(),
        PayloadProtection::new("wrong-domain", Arc::new(Codec::default())).unwrap()
    )
    .is_err());
    drop(worker);
    drop(store);
    let connection = Connection::open(fixture.path()).unwrap();
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .unwrap();
    drop(connection);
    assert!(SqliteStore::open_initialized_protected(fixture.path(), protection).is_err());
}

#[cfg(unix)]
#[test]
fn protected_runtime_creation_and_reopen_harden_file_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let protection = protection(Arc::new(Codec::default()));
    let store = SqliteStore::create_protected(fixture.path(), protection.clone()).unwrap();
    assert_eq!(
        std::fs::metadata(fixture.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(store);
    std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    SqliteStore::open_existing_protected(fixture.path(), protection).unwrap();
    assert_eq!(
        std::fs::metadata(fixture.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn protected_tracker_results_preserve_terminal_history_and_replay() {
    for status in ["running", "lease_expired", "failed"] {
        for closing in [false, true] {
            let mut store = SqliteStore::open_in_memory_protected(
                PayloadProtection::new("project", Arc::new(RetentionCodec::default())).unwrap(),
            )
            .unwrap();
            if closing {
                crate::tracker_result::closing_conformance::run_suite(&mut store, status);
            } else {
                crate::tracker_result::conformance::run_suite(&mut store, status);
            }
        }
    }
}

#[test]
fn protected_attempt_recovery_retains_original_dispatch_evidence() {
    let mut store = SqliteStore::open_in_memory_protected(
        PayloadProtection::new("project", Arc::new(RetentionCodec::default())).unwrap(),
    )
    .unwrap();
    crate::effect_recovery::conformance::check(&mut store);
}

#[test]
fn ordinary_runtime_open_refuses_before_repairing_protected_schema() {
    let fixture = Fixture::new();
    let protection = protection(Arc::new(Codec::default()));
    let store = SqliteStore::create_protected(fixture.path(), protection).unwrap();
    store
        .connection
        .execute_batch("DROP TABLE workspaces")
        .unwrap();
    assert!(SqliteStore::open(fixture.path()).is_err());
    assert!(
        !store.table_exists("workspaces").unwrap(),
        "a refused plain opener must not repair a protected store first"
    );
}

#[test]
fn protected_initialization_refuses_an_existing_schema_without_changing_it() {
    let fixture = Fixture::new();
    let observer = Connection::open(fixture.path()).unwrap();
    observer
        .execute_batch(
            "CREATE TABLE retained (value TEXT); INSERT INTO retained VALUES ('original');",
        )
        .unwrap();
    let before: String = observer
        .query_row("SELECT group_concat(sql) FROM sqlite_schema", [], |row| {
            row.get(0)
        })
        .unwrap();
    let result = SqliteStore::initialize_protected(
        Connection::open(fixture.path()).unwrap(),
        protection(Arc::new(Codec::default())),
    );
    assert!(
        result.is_err(),
        "protected initialization must not adopt an existing database"
    );
    let after: String = observer
        .query_row("SELECT group_concat(sql) FROM sqlite_schema", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(
        observer
            .query_row("SELECT value FROM retained", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        "original"
    );
}

#[test]
fn settled_effect_without_a_worker_attempt_cannot_admit_a_run() {
    for protected in [false, true] {
        let mut store = if protected {
            SqliteStore::open_in_memory_protected(protection(Arc::new(Codec::default()))).unwrap()
        } else {
            SqliteStore::open_in_memory().unwrap()
        };
        let instance = instance(&mut store);
        store
            .register_capability_schema(CapabilitySchemaRegistration {
                capability: "fixture.execute",
                description: "fixture",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .unwrap();
        store
            .register_effect_provider(EffectProviderRegistration {
                provider_id: "fixture",
                effect_kind: "fixture.effect",
                provider: "fixture",
                capability: "fixture.execute",
                config_json: "{}",
                registered_by_package_id: None,
            })
            .unwrap();
        store
            .bind_capability(CapabilityBinding {
                binding_id: "fixture",
                program_id: None,
                capability: "fixture.execute",
                provider: "fixture",
                config_json: "{}",
            })
            .unwrap();
        store
            .commit_rule(RuleCommit {
                instance_id: &instance,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    effect_id: "settled-effect",
                    kind: "fixture.effect",
                    target: None,
                    input_json: "{}",
                    status: "completed",
                    idempotency_key: "settled-effect",
                    required_capabilities_json: r#"["fixture.execute"]"#,
                    profile: None,
                    correlation_id: None,
                    source_span_json: None,
                    timeout_seconds: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("start"),
                marks: &[],
                context_json: None,
            })
            .unwrap();
        // A rule can retain an already settled inline effect without creating a
        // provider attempt. There is no prior-dispatch refusal to mask the
        // atomic claimability guard in this case.
        assert!(
            policy_block_on(&store.connection, &instance, "settled-effect")
                .unwrap()
                .is_none()
        );
        assert!(store.claimable_effects(&instance).unwrap().is_empty());
        let events = store.list_events(&instance).unwrap();
        let effects = store.list_effects(&instance).unwrap();
        assert_eq!(effects[0].status, "completed");
        let error = store
            .start_run(RunStart {
                instance_id: &instance,
                effect_id: "settled-effect",
                run_id: "run",
                provider: "fixture",
                worker_id: "worker",
                lease_id: "lease",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .unwrap_err();
        assert!(
            matches!(&error, StoreError::Conflict(reason) if reason == "effect is not claimable"),
            "{error:?}"
        );
        assert_eq!(store.list_events(&instance).unwrap(), events);
        assert_eq!(store.list_effects(&instance).unwrap(), effects);
        assert!(store.list_runs(&instance).unwrap().is_empty());
        let leases: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM leases", [], |row| row.get(0))
            .unwrap();
        assert_eq!(leases, 0);
    }
}
