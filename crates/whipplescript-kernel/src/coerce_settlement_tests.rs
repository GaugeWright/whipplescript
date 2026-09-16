use super::*;
use crate::coerce::FakeCoerceClient;
use whipplescript_store::{coerce_settlement::conformance, SqliteStore};

#[test]
fn coerce_settlement_reopens_without_a_terminal_to_result_gap() {
    for status in ["completed", "failed", "timed_out"] {
        let path = std::env::temp_dir().join(format!(
            "coerce-settlement-{}-{status}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("coerce settlement fixture")
                .as_nanos(),
        ));
        let mut store = SqliteStore::open(&path).expect("coerce settlement fixture");
        let fixture = conformance::setup(&mut store, "schema.coerce", status);
        let request =
            CoerceRequest::with_evidence_hashes("classify".into(), "{}".into(), "Answer".into());
        let execution = CoerceExecution {
            instance_id: &fixture.instance,
            effect_id: "settle-effect",
            run_id: "settle-run",
            provider: "coerce-fixture",
            worker_id: "fixture",
            lease_id: "settle-lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            request: &request,
            model: None,
        };
        // The provider result is already in hand. Retrying the store transaction
        // below never invokes the provider again.
        let mut result =
            FakeCoerceClient::succeeds(r#"{"answer":"actual output"}"#).coerce(&request);
        result.status = match status {
            "completed" => CoerceStatus::Succeeded,
            "failed" => CoerceStatus::Failed,
            "timed_out" => CoerceStatus::TimedOut,
            _ => unreachable!(),
        };
        let sql = rusqlite::Connection::open(&path).expect("coerce settlement fixture");
        sql.execute_batch("CREATE TRIGGER reject_result BEFORE INSERT ON facts BEGIN SELECT RAISE(ABORT, 'injected coerce settlement fault'); END").expect("coerce settlement fixture");
        let mut kernel = RuntimeKernel::new(store);
        let error = kernel
            .settle_coerce_result(execution, &result)
            .expect_err("coerce settlement must refuse");
        assert!(format!("{error:?}").contains("injected coerce settlement fault"));
        assert!(!kernel
            .trace()
            .iter()
            .any(|e| matches!(e.event, TraceEvent::EffectTerminal { .. })));
        drop(kernel);
        let store = SqliteStore::open(&path).expect("coerce settlement fixture");
        conformance::assert_running(&store, &fixture);
        assert!(!store
            .list_events(&fixture.instance)
            .expect("coerce settlement fixture")
            .iter()
            .any(|e| e.event_type == "effect.terminal" || e.event_type == fixture.fact().name));
        sql.execute_batch("DROP TRIGGER reject_result")
            .expect("coerce settlement fixture");
        let mut kernel = RuntimeKernel::new(store);
        kernel
            .settle_coerce_result(execution, &result)
            .expect("coerce settlement fixture");
        assert!(kernel
            .trace()
            .iter()
            .any(|e| matches!(e.event, TraceEvent::EffectTerminal { .. })));
        drop(kernel);
        let mut store = SqliteStore::open(&path).expect("coerce settlement fixture");
        let events = store
            .list_events(&fixture.instance)
            .expect("coerce settlement fixture");
        let result_event = events
            .iter()
            .find(|e| e.event_type == fixture.fact().name)
            .expect("coerce settlement fixture");
        let terminal = events
            .iter()
            .find(|e| e.event_type == "effect.terminal")
            .expect("coerce settlement fixture");
        assert_eq!(result_event.sequence, terminal.sequence + 1);
        let value: Value =
            serde_json::from_str(&result_event.payload_json).expect("coerce settlement fixture");
        assert_eq!(value["run_id"], "settle-run");
        assert_eq!(value["status"], status);
        if status == "completed" {
            assert_eq!(value["value"]["answer"], "actual output");
        }
        assert!(!terminal.payload_json.contains("actual output"));
        let facts = store
            .list_facts(&fixture.instance)
            .expect("coerce settlement fixture");
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0].fact_id,
            idempotency_key(&[&fixture.instance, "coerce", "settle-run"])
        );
        assert_eq!(facts[0].value_json, result_event.payload_json);
        store
            .rebuild_projections(&fixture.instance)
            .expect("coerce settlement fixture");
        assert_eq!(
            store
                .list_facts(&fixture.instance)
                .expect("coerce settlement fixture")[0]
                .value_json,
            result_event.payload_json
        );
        drop(store);
        drop(sql);
        std::fs::remove_file(path).expect("coerce settlement fixture");
    }
}
