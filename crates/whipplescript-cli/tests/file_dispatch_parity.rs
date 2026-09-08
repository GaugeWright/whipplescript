//! File-handler execution contract on both runtime stores. The sink below is
//! an explicit crash/merge fixture, not the production admitted-file adapter.
use std::cell::{Cell, RefCell};
use std::io;
use std::path::Path;

use serde_json::{json, Value};
use whipplescript_host_do::do_store::{test_support::RusqliteDoSql, DoSqliteStore};
use whipplescript_kernel::effect_handlers::run_file_write_effect_generic;
use whipplescript_kernel::{idempotency_key, RuntimeKernel};
use whipplescript_store::effect_recovery::{
    fold_attempts, DispositionEvidence, EvidenceDisposition, ExternalDisposition,
};
use whipplescript_store::files::FileStore;
use whipplescript_store::native_stores::NativeStores;
use whipplescript_store::{
    NewEffect, NewEvent, NewInstance, RetryEffect, RuleCommit, RunStart, RuntimeStore,
};

const ACCEPTED: &str = "the merged text accepted by the target";
struct MergeAndCrashFiles {
    calls: Cell<usize>,
    crash_before: Cell<bool>,
    crash_after: Cell<bool>,
    return_failure: Cell<bool>,
    body: RefCell<Option<String>>,
}
impl FileStore for MergeAndCrashFiles {
    fn read_to_string(&self, _: &Path) -> io::Result<String> {
        self.body
            .borrow()
            .clone()
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }
    fn exists(&self, _: &Path) -> bool {
        self.body.borrow().is_some()
    }
    fn create_dir_all(&self, _: &Path) -> io::Result<()> {
        Ok(())
    }
    fn write(&self, _: &Path, bytes: &[u8]) -> io::Result<()> {
        self.calls.set(self.calls.get() + 1);
        *self.body.borrow_mut() = Some(
            String::from_utf8(bytes.to_vec())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
        Ok(())
    }
    fn write_text(&self, _: &Path, _: &str) -> io::Result<String> {
        self.calls.set(self.calls.get() + 1);
        if self.return_failure.replace(false) {
            return Err(io::ErrorKind::Other.into());
        }
        assert!(
            !self.crash_before.replace(false),
            "injected interruption before application"
        );
        *self.body.borrow_mut() = Some(ACCEPTED.into());
        assert!(
            !self.crash_after.replace(false),
            "injected interruption after application"
        );
        Ok(ACCEPTED.into())
    }
    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut body = self.body.borrow().clone().unwrap_or_default().into_bytes();
        body.extend_from_slice(bytes);
        self.write(path, &body)
    }
    fn remove(&self, _: &Path) -> io::Result<()> {
        self.body.borrow_mut().take();
        Ok(())
    }
}

fn journey<S: RuntimeStore>(
    mut store: S,
    interrupted: Option<bool>,
    returned_failure: bool,
) -> Value {
    let version = whipplescript_store::host_actions::conformance::register(&mut store);
    store
        .register_capability_schema(whipplescript_store::CapabilitySchemaRegistration {
            capability: "file.write",
            description: "file-handler fixture",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .expect("register file capability");
    store
        .bind_capability(whipplescript_store::CapabilityBinding {
            binding_id: "fixture-files",
            program_id: Some(&version.program_id),
            capability: "file.write",
            provider: "files",
            config_json: "{}",
        })
        .expect("bind file capability");
    store
        .register_effect_provider(whipplescript_store::EffectProviderRegistration {
            provider_id: "fixture-files",
            effect_kind: "file.write",
            provider: "files",
            capability: "file.write",
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
        .expect("create file fixture instance");
    let id = instance.instance_id.as_str();
    let input = json!({"root":"/workspace", "path":"note.txt", "store":"docs", "format":"text", "mode":"upsert", "body":"submitted draft", "allow":["**"]}).to_string();
    store
        .commit_rule(RuleCommit {
            instance_id: id,
            rule: "fixture",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &[NewEffect {
                effect_id: "save",
                kind: "file.write",
                target: None,
                input_json: &input,
                status: "queued",
                idempotency_key: "save-command",
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
    let mut kernel = RuntimeKernel::new(store);
    let effect = kernel
        .claimable_effects(id)
        .expect("list claimable effects")
        .into_iter()
        .find(|e| e.effect_id == "save")
        .expect("file fixture must be claimable");
    let files = MergeAndCrashFiles {
        calls: Cell::new(0),
        crash_before: Cell::new(interrupted == Some(false) && !returned_failure),
        crash_after: Cell::new(interrupted == Some(true)),
        return_failure: Cell::new(returned_failure),
        body: RefCell::new(None),
    };
    // The handler must compare the snapshot it actually executes, not merely
    // claim an effect with the same ID and then use stale content or routing.
    let before_stale = kernel
        .store()
        .list_events(id)
        .expect("events before stale dispatch");
    let mut stale = effect.clone();
    let mut stale_input: Value = serde_json::from_str(&stale.input_json).expect("file input");
    stale_input["body"] = json!("an earlier draft");
    stale.input_json = stale_input.to_string();
    assert!(
        run_file_write_effect_generic(&mut kernel, &files, id, &stale).is_err(),
        "stale handler observation refuses"
    );
    assert_eq!(
        files.calls.get(),
        0,
        "stale dispatch cannot reach the target"
    );
    assert_eq!(
        kernel
            .store()
            .list_events(id)
            .expect("events after stale dispatch"),
        before_stale
    );
    if let Some(applied) = interrupted {
        if returned_failure {
            run_file_write_effect_generic(&mut kernel, &files, id, &effect)
                .expect("record the returned target failure");
            assert!(kernel
                .store()
                .list_facts(id)
                .expect("read failed file fact")
                .iter()
                .any(|f| f.name == "file.write.failed"));
        } else {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_file_write_effect_generic(&mut kernel, &files, id, &effect)
            }));
            assert!(outcome.is_err(), "fixture must interrupt inside the target");
        }
        assert_eq!(files.calls.get(), 1);
        assert_eq!(files.body.borrow().is_some(), applied);
        let events = kernel
            .store()
            .list_events(id)
            .expect("read interrupted history");
        let first = fold_attempts(id, "save", &events).expect("fold interrupted attempt");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].disposition, ExternalDisposition::Unknown);
        // Even exact reattachment coordinates do not authorize fresh I/O.
        let run_id = idempotency_key(&[id, "save", "file-run"]);
        let lease_id = idempotency_key(&[id, "save", "file-lease"]);
        assert!(kernel
            .start_dispatch(RunStart {
                instance_id: id,
                effect_id: "save",
                run_id: &run_id,
                provider: "files",
                worker_id: "whip-files",
                lease_id: &lease_id,
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: r#"{"path":"/workspace/note.txt","mode":"upsert"}"#
            })
            .is_err());
        assert_eq!(
            kernel
                .store()
                .list_events(id)
                .expect("verify fresh-dispatch refusal is inert"),
            events
        );
        let mut store = kernel.into_store();
        store
            .rebuild_projections(id)
            .expect("rebuild interrupted history");
        kernel = RuntimeKernel::new(store);
        assert!(run_file_write_effect_generic(&mut kernel, &files, id, &effect).is_err());
        assert_eq!(
            files.calls.get(),
            1,
            "restart must not redispatch an uncertain write"
        );
        kernel
            .expire_leases(id, "2031-01-01T00:00:00Z")
            .expect("expire interrupted worker");
        let retry = RetryEffect {
            instance_id: id,
            effect_id: "save",
            retry_after: None,
            idempotency_key: Some("retry"),
        };
        assert!(kernel.retry_effect(retry).is_err());
        if applied {
            return json!({"calls":files.calls.get(), "disposition":"unknown", "body":files.body.borrow().clone()});
        }
        // Seed evidence already checked by the reconciliation authority. This
        // fixture stopped before application and its stack unwound, so that
        // call cannot later apply. Expiry closes the runtime attempt. Real
        // target fencing and authentication have separate qualification.
        let evidence = DispositionEvidence {
            frame: first[0]
                .dispatch
                .as_ref()
                .expect("recorded dispatch frame")
                .frame
                .clone(),
            disposition: EvidenceDisposition::NotApplied,
            evidence_ref: "fixture:absence".into(),
            evidence_digest: "fixture:absence-digest".into(),
            authority_ref: "fixture:target".into(),
        };
        kernel
            .store()
            .append_event(NewEvent {
                instance_id: id,
                event_type: "effect.disposition.recorded",
                payload_json: &serde_json::to_string(&evidence)
                    .expect("encode verified absence fixture"),
                source: "kernel",
                causation_id: Some(&run_id),
                correlation_id: None,
                idempotency_key: Some("fixture-absence"),
            })
            .expect("append verified absence fixture");
        kernel
            .retry_effect(retry)
            .expect("retry after proved absence");
    }
    let event = run_file_write_effect_generic(&mut kernel, &files, id, &effect)
        .expect("complete fresh file attempt");
    let expected_calls = if interrupted.is_some() { 2 } else { 1 };
    assert_eq!(files.calls.get(), expected_calls);
    assert_eq!(files.body.borrow().as_deref(), Some(ACCEPTED));
    let events = kernel
        .store()
        .list_events(id)
        .expect("read completed history");
    let terminal = events
        .iter()
        .find(|e| e.event_id == event.event_id)
        .expect("recorded terminal event");
    let payload: Value =
        serde_json::from_str(&terminal.payload_json).expect("decode terminal content evidence");
    let value = &payload["metadata"]["value"];
    assert_eq!(value["bytes"], ACCEPTED.len());
    assert_eq!(
        kernel
            .store()
            .get_content(
                value["content_hash"]
                    .as_str()
                    .expect("recorded content hash")
            )
            .expect("resolve recorded accepted content")
            .as_deref(),
        Some(ACCEPTED)
    );
    let facts = kernel.store().list_facts(id).expect("read file facts");
    let saved: Value = serde_json::from_str(
        &facts
            .iter()
            .find(|f| f.name == "file.write.completed")
            .expect("recorded completion fact")
            .value_json,
    )
    .expect("decode completion fact");
    assert_eq!(saved["value"], *value);
    let attempts = fold_attempts(id, "save", &events).expect("fold all file attempts");
    assert_eq!(attempts.len(), expected_calls);
    assert_eq!(
        attempts.last().expect("completed attempt").disposition,
        ExternalDisposition::Unknown,
        "a returned body is not target reconciliation proof"
    );
    if attempts.len() == 2 {
        assert_ne!(attempts[0].run_id, attempts[1].run_id);
    }
    assert!(run_file_write_effect_generic(&mut kernel, &files, id, &effect).is_err());
    assert_eq!(files.calls.get(), expected_calls);
    assert_eq!(
        kernel
            .store()
            .list_events(id)
            .expect("verify completed retry refusal is inert"),
        events
    );
    json!({"calls":expected_calls,"value":value,"body":files.body.borrow().clone()})
}

#[test]
fn file_dispatch_and_accepted_content_have_native_hosted_parity() {
    for (interruption, returned_failure) in [
        (None, false),
        (Some(false), false),
        (Some(true), false),
        (Some(false), true),
    ] {
        let native = journey(
            NativeStores::open_in_memory().expect("open native runtime stores"),
            interruption,
            returned_failure,
        );
        let hosted = journey(
            DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
            interruption,
            returned_failure,
        );
        assert_eq!(native, hosted);
    }
}
