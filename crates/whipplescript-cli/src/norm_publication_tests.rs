//! Compose the shared verified-execution fixtures with the hosted journal and
//! ledger. Transport and signatures use explicit fixture boundaries here.
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_host_do::do_store::{test_support, DoSqliteStore};
use whipplescript_kernel::norm_execution::{fixtures::*, PreparedNormExecution};
use whipplescript_kernel::norm_publication::{ObservationSigning, PreparedObservationPublication};
use whipplescript_store::norm_commands::NormCommandStore;
use whipplescript_store::RuntimeStore;

#[test]
fn norm_publication_hosted_bridge_recovers_after_ledger_commit() {
    for (actual, timeout) in [(false, false), (true, false), (true, true)] {
        let (ledger, requirement) = fixture_with_observation(Some(template()), true, true);
        let captured = history(&ledger);
        let ledger_id = captured.anchor().checkpoint.ledger;
        let artifact = artifact("def allow(user): return False");
        let execution = PreparedNormExecution::prepare(
            &captured,
            &Boundary,
            &artifact,
            &script(),
            selection(&ledger_id, &requirement),
        )
        .unwrap();
        let mut hosted = test_support::store();
        hosted
            .pin_norm_checkpoint(&ledger.norm_checkpoint().unwrap().unwrap())
            .unwrap();
        hosted
            .import_norm(&ledger.tracker_history().unwrap(), &Boundary)
            .unwrap();
        let mut kernel = journal_execution(
            hosted,
            &execution,
            &receipt(&execution, actual, timeout),
            actual || timeout,
        );
        let verified = execution
            .verify_settled(kernel.store(), "instance", "run")
            .unwrap();
        let vocabulary = Vocabulary::new(observation_vocabulary().definition)
            .unwrap()
            .reference()
            .clone();
        let actor = actor();
        let signing = || ObservationSigning {
            vocabulary: &vocabulary,
            authority: None,
            actor: &actor,
            created_at: "2026-09-10T00:00:00Z",
        };
        let prepared = PreparedObservationPublication::prepare(
            &verified,
            &captured,
            kernel.store(),
            &Boundary,
            signing(),
            |statement| {
                Ok(whipplescript_kernel::exec_http::sha256_hex(
                    &statement.signing_bytes().unwrap(),
                ))
            },
        )
        .unwrap();
        let before = kernel.store().tracker_history().unwrap().len();
        let receipt = prepared.submit(kernel.store_mut(), &Boundary).unwrap();
        let event_id = receipt.event_id().to_owned();
        // Reconstruct the store/host after the ledger has committed, dropping
        // the unacknowledged receipt and in-memory verified execution.
        let sql = kernel.store().sql.clone();
        drop(receipt);
        drop(prepared);
        drop(verified);
        drop(kernel);
        let mut restored = DoSqliteStore::new(sql);
        restored.rebuild_projections("instance").unwrap();
        let verified = PreparedNormExecution::recover_settled(
            &captured, &Boundary, &artifact, &restored, "instance", "run",
        )
        .unwrap();
        let recovered = PreparedObservationPublication::prepare(
            &verified,
            &captured,
            &restored,
            &Boundary,
            signing(),
            |_| panic!("host recovery must not sign"),
        )
        .unwrap();
        let receipt = recovered.submit(&mut restored, &Boundary).unwrap();
        assert_eq!(receipt.event_id(), event_id);
        assert_eq!(restored.tracker_history().unwrap().len(), before + 1);
        let acknowledgment = receipt.acknowledge(&restored).unwrap();
        let events = restored.list_events("instance").unwrap();
        assert_eq!(receipt.acknowledge(&restored).unwrap(), acknowledgment);
        assert_eq!(restored.list_events("instance").unwrap(), events);
    }
}

#[test]
fn norm_publication_native_process_recovers_across_both_file_backed_stores() {
    use whipplescript_kernel::{ProgramVersionInput, RuntimeKernel};
    use whipplescript_store::items::WorkItemStore;
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, ScriptCapabilityRegistration, SqliteStore,
    };
    for actual in [false, true] {
        let python = std::process::Command::new("python3")
            .args(["-c", "import sys; print(sys.version.split()[0])"])
            .output()
            .unwrap();
        assert!(python.status.success());
        let mut support = template();
        support["method"]["runtime"]["python_version"] =
            serde_json::json!(String::from_utf8(python.stdout).unwrap().trim());
        let (source_ledger, requirement) = fixture_with_observation(Some(support), true, true);
        let captured = history(&source_ledger);
        let ledger_id = captured.anchor().checkpoint.ledger;
        let artifact = artifact(if actual {
            "def allow(user): return True"
        } else {
            "def allow(user): return False"
        });
        let execution = PreparedNormExecution::prepare(
            &captured,
            &Boundary,
            &artifact,
            &script(),
            selection(&ledger_id, &requirement),
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "norm-publication-process-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let runtime_path = dir.join("runtime.sqlite");
        let ledger_path = dir.join("ledger.sqlite");
        let mut ledger = WorkItemStore::open(&ledger_path).unwrap();
        ledger
            .pin_norm_checkpoint(&source_ledger.norm_checkpoint().unwrap().unwrap())
            .unwrap();
        ledger
            .import_norm(&source_ledger.tracker_history().unwrap(), &Boundary)
            .unwrap();
        let mut kernel = RuntimeKernel::new(SqliteStore::open(&runtime_path).unwrap());
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "publication",
                source_hash: "fixture",
                ir_hash: "fixture",
                compiler_version: "fixture",
                ir_snapshot: None,
            })
            .unwrap();
        let instance = kernel.create_instance(&version, "{}").unwrap();
        kernel
            .store()
            .register_capability_schema(CapabilitySchemaRegistration {
                capability: "script.observer",
                description: "fixture observer",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .unwrap();
        kernel
            .store()
            .bind_capability(CapabilityBinding {
                binding_id: "observer",
                program_id: Some(&version.program_id),
                capability: "script.observer",
                provider: "builtin-script",
                config_json: "{}",
            })
            .unwrap();
        let script = script();
        kernel
            .store()
            .register_script_capability(ScriptCapabilityRegistration {
                name: &script.name,
                argv_json: &script.argv_json,
                sha256: &script.sha256,
                body: &script.body,
                env_json: &script.env_json,
                hermetic: false,
            })
            .unwrap();
        execution.enqueue(&mut kernel, &instance, Some(30)).unwrap();
        let effect = kernel
            .store()
            .queued_exec_command_effects(&instance)
            .unwrap()
            .remove(0);
        super::norm_exec_native::execute(&mut kernel, &instance, &effect, "epoch").unwrap();
        let run = kernel
            .store()
            .list_runs(&instance)
            .unwrap()
            .remove(0)
            .run_id;
        let verified = execution
            .verify_settled(kernel.store(), &instance, &run)
            .unwrap();
        assert_eq!(
            verified.observation().judgment.outcome,
            if actual {
                whipplescript_core::norm_evidence::TestOutcome::Fail
            } else {
                whipplescript_core::norm_evidence::TestOutcome::Pass
            }
        );
        let vocabulary = Vocabulary::new(observation_vocabulary().definition)
            .unwrap()
            .reference()
            .clone();
        let actor = actor();
        let signing = || ObservationSigning {
            vocabulary: &vocabulary,
            authority: None,
            actor: &actor,
            created_at: "2026-09-10T00:00:00Z",
        };
        let prepared = PreparedObservationPublication::prepare(
            &verified,
            &captured,
            kernel.store(),
            &Boundary,
            signing(),
            |statement| {
                Ok(whipplescript_kernel::exec_http::sha256_hex(
                    &statement.signing_bytes().unwrap(),
                ))
            },
        )
        .unwrap();
        let signed = prepared.event().clone();
        let before = ledger.tracker_history().unwrap().len();
        drop(prepared);
        drop(verified);
        drop(kernel);
        drop(ledger);
        // Reopen after durable preparation, before any ledger submission.
        let runtime = SqliteStore::open(&runtime_path).unwrap();
        let verified = PreparedNormExecution::recover_settled(
            &captured, &Boundary, &artifact, &runtime, &instance, &run,
        )
        .unwrap();
        let prepared = PreparedObservationPublication::prepare(
            &verified,
            &captured,
            &runtime,
            &Boundary,
            signing(),
            |_| panic!("recovery before append must not sign"),
        )
        .unwrap();
        assert_eq!(prepared.event(), &signed);
        let mut ledger = WorkItemStore::open(&ledger_path).unwrap();
        let receipt = prepared.submit(&mut ledger, &Boundary).unwrap();
        let event_id = receipt.event_id().to_owned();
        drop(receipt);
        drop(prepared);
        drop(verified);
        drop(runtime);
        drop(ledger);
        // Reopen again after ledger commit, before runtime acknowledgment.
        let runtime = SqliteStore::open(&runtime_path).unwrap();
        let verified = PreparedNormExecution::recover_settled(
            &captured, &Boundary, &artifact, &runtime, &instance, &run,
        )
        .unwrap();
        let prepared = PreparedObservationPublication::prepare(
            &verified,
            &captured,
            &runtime,
            &Boundary,
            signing(),
            |_| panic!("recovery after append must not sign"),
        )
        .unwrap();
        let mut ledger = WorkItemStore::open(&ledger_path).unwrap();
        let receipt = prepared.submit(&mut ledger, &Boundary).unwrap();
        assert_eq!(receipt.event_id(), event_id);
        assert_eq!(ledger.tracker_history().unwrap().len(), before + 1);
        let acknowledged = receipt.acknowledge(&runtime).unwrap();
        assert_eq!(receipt.acknowledge(&runtime).unwrap(), acknowledged);
        assert_eq!(
            runtime.list_runs(&instance).unwrap().len(),
            1,
            "recovery must not execute again"
        );
        drop(runtime);
        drop(ledger);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
