//! The actual four file-handler entrypoints all record bounded leases on both
//! stores. The file sink is the parent module's explicit local fixture.
use super::*;
use whipplescript_kernel::effect_handlers::{
    run_file_effect_generic, run_file_export_effect_generic, run_file_import_effect_generic,
};
use whipplescript_kernel::file_lease::FileLeasePolicy;

fn check<S: RuntimeStore>(mut store: S) {
    let version = whipplescript_store::host_actions::conformance::register(&mut store);
    for kind in ["file.read", "file.write", "file.import", "file.export"] {
        store
            .register_capability_schema(whipplescript_store::CapabilitySchemaRegistration {
                capability: kind,
                description: "file lease fixture",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .expect("register file capability");
        store
            .bind_capability(whipplescript_store::CapabilityBinding {
                binding_id: kind,
                program_id: Some(&version.program_id),
                capability: kind,
                provider: "files",
                config_json: "{}",
            })
            .expect("bind file capability");
        store
            .register_effect_provider(whipplescript_store::EffectProviderRegistration {
                provider_id: kind,
                effect_kind: kind,
                provider: "files",
                capability: kind,
                config_json: "{}",
                registered_by_package_id: None,
            })
            .expect("register file provider");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("create fixture instance");
        let id = &instance.instance_id;
        let input = json!({"root":"/workspace", "path":"note.txt", "store":"docs",
            "format":if matches!(kind, "file.import" | "file.export") {"jsonl"} else {"text"},
            "mode":"upsert", "body":"draft", "allow":["**"], "schema":"Row",
            "fields":[], "required_fields":[], "natural_key_field":"key"})
        .to_string();
        store
            .commit_rule(RuleCommit {
                instance_id: id,
                rule: "fixture",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    effect_id: kind,
                    kind,
                    target: None,
                    input_json: &input,
                    status: "queued",
                    idempotency_key: kind,
                    required_capabilities_json: "[]",
                    profile: None,
                    correlation_id: None,
                    source_span_json: None,
                    timeout_seconds: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("fixture"),
                marks: &[],
                context_json: None,
            })
            .expect("commit file effect");
        let files = MergeAndCrashFiles {
            calls: Cell::new(0),
            crash_before: Cell::new(false),
            crash_after: Cell::new(false),
            return_failure: Cell::new(false),
            body: RefCell::new(Some(r#"{"key":"one"}"#.into())),
        };
        let mut kernel = RuntimeKernel::new(store);
        kernel.set_file_lease_policy(FileLeasePolicy::new(120).expect("valid file lease policy"));
        let effect = kernel
            .claimable_effects(id)
            .expect("claimable file effect")
            .remove(0);
        let before = kernel
            .store()
            .resolve_clock("now")
            .expect("clock before file operation");
        match kind {
            "file.read" => run_file_effect_generic(&mut kernel, &files, id, &effect),
            "file.write" => run_file_write_effect_generic(&mut kernel, &files, id, &effect),
            "file.import" => run_file_import_effect_generic(&mut kernel, &files, id, &effect),
            "file.export" => run_file_export_effect_generic(&mut kernel, &files, id, &effect),
            _ => unreachable!(),
        }
        .expect("settle file operation");
        let after = kernel
            .store()
            .resolve_clock("now")
            .expect("clock after file operation");
        let events = kernel
            .store()
            .list_events(id)
            .expect("recorded file history");
        let starts: Vec<_> = events
            .iter()
            .filter(|event| event.event_type == "effect.run_started")
            .collect();
        assert_eq!(starts.len(), 1, "{kind}");
        let started: Value =
            serde_json::from_str(&starts[0].payload_json).expect("recorded file start payload");
        let parse = |value: &str| {
            chrono::DateTime::parse_from_rfc3339(value).expect("valid recorded clock")
        };
        let deadline = parse(
            started["lease_expires_at"]
                .as_str()
                .expect("recorded lease deadline"),
        );
        let lifetime = chrono::Duration::seconds(120);
        assert!(deadline >= parse(&before) + lifetime, "{kind}");
        assert!(deadline <= parse(&after) + lifetime, "{kind}");
        store = kernel.into_store();
    }
}

#[test]
fn every_file_handler_records_a_current_bounded_lease_on_both_hosts() {
    check(NativeStores::open_in_memory().expect("open native runtime store"));
    check(DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()));
}
