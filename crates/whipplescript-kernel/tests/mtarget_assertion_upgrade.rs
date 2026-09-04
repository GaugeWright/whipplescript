use rusqlite::{types::Value, Connection};
use std::path::PathBuf;
use whipplescript_kernel::{
    coerce::{CoerceRequest, FakeCoerceClient},
    rule_pass::step_instance_generic,
    CoerceExecution, RuntimeKernel,
};
use whipplescript_parser::compile_program;
use whipplescript_store::{native_stores::NativeStores, RuntimeStore};

struct Fixture(PathBuf);

impl Fixture {
    fn load() -> Self {
        let root = std::env::temp_dir().join(format!(
            "whip-assertion-upgrade-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir(&root).expect("new fixture directory");
        for (name, sql) in [
            (
                "runtime",
                include_str!("fixtures/legacy-assertions/runtime.sql"),
            ),
            (
                "coord",
                include_str!("fixtures/legacy-assertions/coord.sql"),
            ),
            (
                "items",
                include_str!("fixtures/legacy-assertions/items.sql"),
            ),
        ] {
            Connection::open(root.join(format!("{name}.sqlite")))
                .expect("fixture database")
                .execute_batch(sql)
                .expect("restore actual old schema and rows");
        }
        let fixture = Self(root);
        // Neither an upgrade nor projection replay may rewrite old authority.
        fixture.sql().execute_batch(
            "CREATE TRIGGER keep_old_events_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'old event rewrite'); END;
             CREATE TRIGGER keep_old_events_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'old event deletion'); END;",
        ).expect("protect original event history");
        fixture
    }

    fn sql(&self) -> Connection {
        Connection::open(self.0.join("runtime.sqlite")).expect("fixture runtime")
    }

    fn rows(&self, query: &str) -> Vec<Vec<Value>> {
        let connection = self.sql();
        let mut statement = connection.prepare(query).expect("snapshot query");
        let count = statement.column_count();
        statement
            .query_map([], |row| (0..count).map(|i| row.get(i)).collect())
            .expect("read snapshot")
            .collect::<Result<_, _>>()
            .expect("snapshot values")
    }

    fn open(&self) -> RuntimeKernel<NativeStores> {
        RuntimeKernel::new(
            NativeStores::open(
                self.0.join("runtime.sqlite"),
                self.0.join("coord.sqlite"),
                self.0.join("items.sqlite"),
            )
            .expect("upgrade actual legacy stores"),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove owned temporary fixture");
    }
}

#[test]
fn pre_repair_runtime_preserves_history_and_records_only_new_firings() {
    let fixture = Fixture::load();
    let provenance: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/legacy-assertions/provenance.json"))
            .expect("fixture provenance");
    let instance = provenance["instance_id"].as_str().expect("instance id");
    let old_events = fixture.rows("SELECT * FROM events ORDER BY sequence");
    let old_effects = fixture.rows("SELECT * FROM effects ORDER BY effect_id");
    let old_versions = fixture.rows("SELECT * FROM program_versions ORDER BY version_id");
    assert_eq!(old_effects.len(), 2);
    let ir = compile_program(include_str!("fixtures/legacy-assertions/source.whip"))
        .ir
        .expect("old source still compiles");

    let mut kernel = fixture.open();
    assert!(!kernel
        .store()
        .list_events(instance)
        .expect("events")
        .iter()
        .any(|event| event.event_type == "instance.created"));
    kernel
        .store_mut()
        .runtime
        .rebuild_projections(instance)
        .expect("legacy projection replay");
    let row = kernel
        .store()
        .get_instance(instance)
        .expect("instance read")
        .expect("instance exists");
    assert_eq!(
        row.version_id,
        provenance["version_id"].as_str().expect("version id")
    );
    assert_eq!(
        step_instance_generic(&mut kernel, instance, &ir, None, None)
            .expect("old firing replay")
            .committed_rules,
        0
    );
    assert!(kernel
        .claimable_effects(instance)
        .expect("old pending effects")
        .is_empty());
    assert_eq!(
        fixture.rows("SELECT * FROM events ORDER BY sequence"),
        old_events
    );
    let replayed_effects = fixture.rows("SELECT * FROM effects ORDER BY effect_id");
    assert_eq!(
        fixture.rows("SELECT * FROM program_versions ORDER BY version_id"),
        old_versions
    );

    kernel
        .derive_fact(
            instance,
            "item.arrived",
            "second",
            r#"{"item":"second"}"#,
            None,
            Some("second"),
        )
        .expect("new firing input");
    let mut executed = 0;
    for _ in 0..6 {
        step_instance_generic(&mut kernel, instance, &ir, None, None).expect("new firing step");
        let effects = kernel.claimable_effects(instance).expect("new effects");
        if effects.is_empty() {
            break;
        }
        for effect in effects {
            let request = CoerceRequest::with_evidence_hashes(
                "choose".into(),
                "{\"text\":\"fixture\"}".into(),
                "Choice".into(),
            );
            kernel
                .run_coerce(
                    CoerceExecution {
                        instance_id: instance,
                        effect_id: &effect.effect_id,
                        run_id: &format!("run:{}", effect.effect_id),
                        provider: "fixture",
                        worker_id: "test",
                        lease_id: &format!("lease:{}", effect.effect_id),
                        lease_expires_at: "2030-01-01T00:00:00Z",
                        request: &request,
                        model: None,
                    },
                    &FakeCoerceClient::succeeds(r#"{"disposition":"keep"}"#),
                )
                .expect("new effect completion");
            executed += 1;
        }
    }
    assert_eq!(executed, 2, "only the new item's two effects execute");
    let events = kernel
        .store()
        .list_events(instance)
        .expect("events after new firing");
    for stage in ["top", "after", "nested"] {
        let matching = events
            .iter()
            .filter(|event| event.event_type == "rule.committed")
            .map(|event| {
                serde_json::from_str::<serde_json::Value>(&event.payload_json)
                    .expect("commit payload")
            })
            .filter(|commit| {
                commit["facts"]
                    .as_array()
                    .expect("facts")
                    .iter()
                    .any(|fact| {
                        fact["name"] == "Settled"
                            && fact["value"]["item"] == "second"
                            && fact["value"]["stage"] == stage
                    })
            })
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "one new settlement at {stage}");
        assert_eq!(
            matching[0]["facts"]
                .as_array()
                .expect("facts")
                .iter()
                .filter(|fact| fact["name"] == "Decision" && fact["value"]["disposition"] == "keep")
                .count(),
            1,
            "the new {stage} firing retains its own equal-valued assertion"
        );
    }
    let all_events = fixture.rows("SELECT * FROM events ORDER BY sequence");
    assert_eq!(&all_events[..old_events.len()], old_events.as_slice());
    let all_effects = fixture.rows("SELECT * FROM effects ORDER BY effect_id");
    assert_eq!(all_effects.len(), 4);
    for old in &old_effects {
        assert!(all_effects.contains(old), "old completed effect unchanged");
    }
    assert_eq!(
        replayed_effects, old_effects,
        "rebuild preserves completed effect rows"
    );
    assert_eq!(
        fixture.rows("SELECT * FROM program_versions ORDER BY version_id"),
        old_versions
    );
    drop(kernel);

    let mut kernel = fixture.open();
    assert_eq!(
        step_instance_generic(&mut kernel, instance, &ir, None, None)
            .expect("second restart")
            .committed_rules,
        0
    );
    assert!(kernel
        .claimable_effects(instance)
        .expect("no replayed effects")
        .is_empty());
    assert_eq!(
        fixture.rows("SELECT * FROM events ORDER BY sequence"),
        all_events
    );
    assert_eq!(
        fixture.rows("SELECT * FROM effects ORDER BY effect_id"),
        all_effects
    );
}
