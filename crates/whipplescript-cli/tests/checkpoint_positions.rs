//! Actual checkpoint operator publication and retained workspace-position retry.
#[path = "support/isolated_whip.rs"]
mod isolated_whip;
use serde_json::Value;
use whipplescript_store::coordination::CoordinationStore;
use whipplescript_store::*;

#[test]
fn checkpoint_cli_busy_refusal_and_original_position_redelivery() {
    let root = tempfile::tempdir().expect("own fixture");
    let runtime = root.path().join("runtime.sqlite");
    let coordination = root.path().join("coordination.sqlite");
    let mut store = SqliteStore::open(&runtime).expect("runtime");
    let version=store.create_program_version(NewProgramVersion {
        program_name:"CheckpointPositions",source_hash:"source",ir_hash:"ir",ir_snapshot:None,
        compiler_version:"test",declared_capabilities_json:"[]",declared_profiles_json:"[]",
        declared_skills_json:"[]",declared_schemas_json:"[]",generated_artifacts_json:"[]",
        analysis_summary_json:r#"{"workflow":"CheckpointPositions","workflow_contracts":[],"schemas":[]}"#,artifact_root:None,
    }).expect("program version");
    let busy = store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("busy instance");
    let quiet = store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("quiet instance");
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
            instance_id: &busy.instance_id,
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
        .expect("ordinary effect admission");
    store
        .start_run(RunStart {
            instance_id: &busy.instance_id,
            effect_id: "busy",
            run_id: "busy-run",
            provider: "test",
            worker_id: "worker",
            lease_id: "lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        })
        .expect("ordinary run start");
    let run = |id: &str, external: &str| {
        isolated_whip::whip_command(env!("CARGO_BIN_EXE_whip"))
            .current_dir(root.path())
            .env("WHIPPLESCRIPT_COORDINATION_STORE", &coordination)
            .args(["--store"])
            .arg(&runtime)
            .args([
                "--json",
                "checkpoint",
                id,
                "--cut-id",
                "cut",
                "--external-positions",
                external,
            ])
            .output()
            .expect("own checkpoint child")
    };
    let handles = |id: &str| {
        let output = isolated_whip::whip_command(env!("CARGO_BIN_EXE_whip"))
            .current_dir(root.path())
            .args(["--store"])
            .arg(&runtime)
            .args(["--json", "handles", id])
            .output()
            .expect("handles child");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).expect("handles JSON")
    };
    let before = store.list_events(&busy.instance_id).expect("events");
    let refused = run(&busy.instance_id, "null");
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("quiescent"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(
        store.list_events(&busy.instance_id).expect("unchanged"),
        before
    );
    assert!(
        handles(&busy.instance_id)["position_pair"].is_null(),
        "failed cut has no handle pair"
    );
    let lone = r#"{"cut_id":"historical-busy-orphan","positions":{"tracker_event_seq":777}}"#;
    store
        .append_event(NewEvent {
            instance_id: &busy.instance_id,
            event_type: "plane.positions",
            payload_json: lone,
            source: "cli",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("historical-lone-orphan"),
        })
        .expect("old orphan without cut");
    let historical = store
        .list_events(&busy.instance_id)
        .expect("historical events");
    assert!(
        handles(&busy.instance_id)["position_pair"].is_null(),
        "historical orphan alone is not a cut"
    );
    assert_eq!(
        store
            .list_events(&busy.instance_id)
            .expect("no history repair"),
        historical
    );
    let first = run(&quiet.instance_id, "null");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: Value = serde_json::from_slice(&first.stdout).expect("first receipt");
    let before = store.list_events(&quiet.instance_id).expect("cut events");
    let mut coord = CoordinationStore::open(&coordination).expect("own coordination");
    coord
        .append_for_owner("shared", "audit", "p1", "{}", "fixture", 3600)
        .expect("actual advanced workspace position");
    let repeated = run(&quiet.instance_id, "null");
    assert!(
        repeated.status.success(),
        "{}",
        String::from_utf8_lossy(&repeated.stderr)
    );
    let repeated: Value = serde_json::from_slice(&repeated.stdout).expect("repeated receipt");
    assert_eq!(
        repeated, first,
        "redelivery reports original positions despite actual ledger advance"
    );
    assert_eq!(
        store.list_events(&quiet.instance_id).expect("no append"),
        before
    );
    assert!(!run(&quiet.instance_id, r#"{"external":9}"#)
        .status
        .success());
    assert_eq!(
        store.list_events(&quiet.instance_id).expect("no relabel"),
        before
    ); // A retained historical carrier is real immutable storage, not a fabricated cut.
    let orphan = r#"{"cut_id":"old-orphan","positions":{"tracker_event_seq":999}}"#;
    store
        .append_event(NewEvent {
            instance_id: &quiet.instance_id,
            event_type: "plane.positions",
            payload_json: orphan,
            source: "cli",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("historical-orphan"),
        })
        .expect("historical orphan carrier");
    let retained = store
        .list_events(&quiet.instance_id)
        .expect("retained events");
    assert_eq!(
        handles(&quiet.instance_id)["position_pair"]["cut_id"],
        "cut",
        "later orphan cannot replace successful cut"
    );
    assert_eq!(
        handles(&quiet.instance_id)["position_pair"]["positions"],
        first["plane_positions"]
    );
    assert_eq!(
        store
            .list_events(&quiet.instance_id)
            .expect("read has no repair"),
        retained
    );
}
