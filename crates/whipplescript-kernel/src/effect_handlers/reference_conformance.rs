//! Reference codec boundaries over both real runtime stores. The deliberately
//! hostile file fixture proves diagnostics and unsupported paths cannot fall
//! back to body I/O; versioned_save exercises the actual target adapter.
use crate::{
    effect_handlers::{run_file_effect_generic, run_file_write_effect_generic},
    RuntimeKernel,
};
use serde_json::{json, Value};
use std::{cell::Cell, io, path::Path};
use whipplescript_store::{
    files::{
        FileContentReference, FileReferenceWriteAccepted, FileStore, FileWriteContext,
        FileWriteFailure,
    },
    log_append::LogAppend,
    CapturedCheckpoint, CheckpointCapture, NewEffect, NewInstance, RuleCommit, RuntimeStore,
};

const SECRET: &str = "protected content must never become a diagnostic";
fn reference() -> FileContentReference {
    FileContentReference {
        content_hash: whipplescript_store::stable_hash_hex(SECRET),
        label_ref: "result-private".into(),
    }
}
struct References {
    calls: Cell<usize>,
    returned: FileContentReference,
    fail: bool,
    policy_refused: bool,
}
impl FileStore for References {
    fn path_policy_error(&self, _: &Path, _: &Path, _: &str, _: &str) -> Option<String> {
        self.policy_refused.then(|| SECRET.to_owned())
    }
    fn read_content_reference(&self, _: &Path) -> io::Result<FileContentReference> {
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            Err(io::Error::other(SECRET))
        } else {
            Ok(self.returned.clone())
        }
    }
    fn write_content_reference(
        &self,
        _: &Path,
        _: &FileContentReference,
        context: FileWriteContext<'_>,
    ) -> Result<FileReferenceWriteAccepted, FileWriteFailure> {
        self.calls.set(self.calls.get() + 1);
        assert!(!context.started_event_id.is_empty());
        if self.fail {
            Err(io::Error::other(SECRET).into())
        } else {
            Ok(FileReferenceWriteAccepted {
                reference: self.returned.clone(),
                byte_len: SECRET.len(),
                evidence: None,
            })
        }
    }
    fn read_to_string(&self, _: &Path) -> io::Result<String> {
        panic!("inline read bypass")
    }
    fn exists(&self, _: &Path) -> bool {
        true
    }
    fn create_dir_all(&self, _: &Path) -> io::Result<()> {
        panic!("unadmitted parent creation")
    }
    fn write(&self, _: &Path, _: &[u8]) -> io::Result<()> {
        panic!("inline write bypass")
    }
    fn append(&self, _: &Path, _: &[u8]) -> io::Result<()> {
        panic!("inline append bypass")
    }
    fn remove(&self, _: &Path) -> io::Result<()> {
        panic!("inline remove bypass")
    }
}

fn refuse_legacy_restore<S: RuntimeStore + LogAppend>(
    store: &mut S,
    id: &str,
    cut: &CapturedCheckpoint,
) {
    let head = store.chain_head(id).expect("head before refused restore");
    assert!(
        store
            .capture_checkpoint(CheckpointCapture {
                instance_id: id,
                cut_id: "unsupported",
                transcript_ref: None,
                idempotency_key: Some("unsupported"),
            })
            .is_err(),
        "capture must preserve the authority boundary"
    );
    assert!(
        store.plan_restore(id, &cut.cut_id).is_err(),
        "an older cut cannot erase admitted intent"
    );
    assert!(
        store
            .commit_restore(
                id,
                cut.sequence,
                &cut.cut_id,
                &head.digest,
                Some("unsupported")
            )
            .is_err(),
        "direct commit cannot bypass the planner's authority boundary"
    );
    assert_eq!(
        store.chain_head(id).expect("head after refused restore"),
        head
    );
}

fn execute<S: RuntimeStore + LogAppend>(
    mut store: S,
    kind: &str,
    input: Value,
    files: &dyn FileStore,
) -> Value {
    let version = whipplescript_store::host_actions::conformance::register(&mut store);
    store
        .register_capability_schema(whipplescript_store::CapabilitySchemaRegistration {
            capability: kind,
            description: "reference codec fixture",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .expect("register reference capability");
    store
        .bind_capability(whipplescript_store::CapabilityBinding {
            binding_id: "fixture-files",
            program_id: Some(&version.program_id),
            capability: kind,
            provider: "files",
            config_json: "{}",
        })
        .expect("bind reference capability");
    store
        .register_effect_provider(whipplescript_store::EffectProviderRegistration {
            provider_id: "fixture-files",
            effect_kind: kind,
            provider: "files",
            capability: kind,
            config_json: "{}",
            registered_by_package_id: None,
        })
        .expect("register reference provider");
    let instance = store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("create reference instance");
    let id = &instance.instance_id;
    let cut = store
        .capture_checkpoint(CheckpointCapture {
            instance_id: id,
            cut_id: "before-reference",
            transcript_ref: None,
            idempotency_key: Some("before-reference"),
        })
        .expect("ordinary empty context can be captured");
    store
        .commit_rule(RuleCommit {
            instance_id: id,
            rule: "fixture",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &[NewEffect {
                effect_id: "file",
                kind,
                target: None,
                input_json: &input.to_string(),
                status: "queued",
                idempotency_key: "file-command",
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
        .expect("admit reference effect");
    if kind == "file.write" {
        refuse_legacy_restore(&mut store, id, &cut);
    }
    let mut kernel = RuntimeKernel::new(store);
    let effect = kernel
        .claimable_effects(id)
        .expect("claim reference effect")
        .remove(0);
    let terminal = if kind == "file.read" {
        run_file_effect_generic(&mut kernel, files, id, &effect)
    } else {
        run_file_write_effect_generic(&mut kernel, files, id, &effect)
    }
    .expect("settle reference attempt");
    let events = kernel
        .store()
        .list_events(id)
        .expect("read reference history");
    let terminal = events
        .iter()
        .find(|e| e.event_id == terminal.event_id)
        .expect("find committed terminal");
    assert!(!terminal.payload_json.contains(SECRET));
    assert!(kernel
        .store()
        .get_content(&reference().content_hash)
        .expect("query runtime content")
        .is_none());
    let result = serde_json::from_str(&terminal.payload_json).expect("decode reference terminal");
    if kind == "file.write" {
        // A body already present in legacy CAS does not grant target authority.
        assert_eq!(
            kernel
                .store()
                .put_content(SECRET)
                .expect("seed unrelated legacy body"),
            reference().content_hash
        );
        refuse_legacy_restore(kernel.store_mut(), id, &cut);
    }
    result
}

fn historical_binding_survives_restore_marker<S: RuntimeStore + LogAppend>(
    mut store: S,
    binding: Value,
) {
    let version = whipplescript_store::host_actions::conformance::register(&mut store);
    let instance = store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("historical binding instance");
    let id = &instance.instance_id;
    let cut = store
        .capture_checkpoint(CheckpointCapture {
            instance_id: id,
            cut_id: "before-bound-result",
            transcript_ref: None,
            idempotency_key: Some("before-bound-result"),
        })
        .expect("ordinary historical cut");
    let owner = store.claim_instance_ownership(id).expect("fixture owner");
    for (event_type, payload) in [
        (
            "fact.derived",
            json!({"name":"file.write.completed", "value":{"value":binding}}),
        ),
        (
            "context.restored",
            json!({"cut_id":cut.cut_id,"restored_to_sequence":cut.sequence}),
        ),
    ] {
        let head = store.chain_head(id).expect("historical head");
        store
            .append_event_fenced(
                owner,
                &head.digest,
                whipplescript_store::NewEvent {
                    instance_id: id,
                    event_type,
                    payload_json: &payload.to_string(),
                    source: "fixture",
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: None,
                },
            )
            .expect("import historical evidence and old restore marker");
    }
    refuse_legacy_restore(&mut store, id, &cut);
}

pub fn check<S: RuntimeStore + LogAppend>(make: impl Fn() -> S) {
    for binding in [
        json!({"format":"reference", "path":"note.txt", "content_hash":reference().content_hash}),
        json!({"content_reference":reference(), "path":"note.txt", "content_hash":reference().content_hash}),
        json!({"format":"text", "path":"note.txt", "content_hash":reference().content_hash,
            "receipt":{"schema_ref":whipplescript_store::vcs_file_save::SAVE_RECEIPT_SCHEMA}}),
    ] {
        historical_binding_survives_restore_marker(make(), binding);
    }

    let input = json!({"format":"reference", "store":"docs", "root":"/workspace", "path":"note.txt", "mode":"upsert", "allow":["**"], "body_ref":{"content_hash":whipplescript_store::stable_hash_hex("submitted draft"), "label_ref":"input-private"}});
    for kind in ["file.read", "file.write"] {
        for case in [
            "success",
            "backend-error",
            "host-policy",
            "bad-result-hash",
            "bad-result-label",
            "escape",
            "denied",
        ] {
            let mut returned = reference();
            if case == "bad-result-hash" {
                returned.content_hash = SECRET.into();
            }
            if case == "bad-result-label" {
                returned.label_ref = " ".into();
            }
            let files = References {
                calls: Cell::new(0),
                returned,
                fail: case == "backend-error",
                policy_refused: case == "host-policy",
            };
            let mut input = input.clone();
            if case == "escape" {
                input["path"] = json!("../outside");
            }
            if case == "denied" {
                input["allow"] = json!(["other"]);
            }
            let result = execute(make(), kind, input, &files);
            assert_eq!(
                result["status"],
                if case == "success" {
                    "completed"
                } else {
                    "failed"
                },
                "{kind}/{case}: {result}"
            );
            assert_eq!(
                files.calls.get(),
                if matches!(case, "escape" | "denied" | "host-policy") {
                    0
                } else {
                    1
                }
            );
            if case == "backend-error" {
                let operation = kind.trim_start_matches("file.");
                assert_eq!(
                    result["metadata"]["failure"]["message"],
                    format!("file reference {operation} failed: Other"),
                    "retain the operation and I/O kind without the backend's body-bearing message",
                );
            }
            if case == "success" {
                assert_eq!(
                    result["metadata"]["value"]["content_reference"],
                    json!(reference())
                );
                assert!(result["metadata"]["value"].get("content").is_none());
                if kind == "file.write" {
                    assert_eq!(result["metadata"]["value"]["bytes"], SECRET.len());
                } else {
                    assert!(result["metadata"]["value"].get("bytes").is_none());
                }
            }
        }
        // The ordinary native store implements neither reference operation.
        // A write must refuse without attempting to mkdir this absolute path.
        let result = execute(
            make(),
            kind,
            input.clone(),
            &whipplescript_store::files::NativeFileStore,
        );
        assert_eq!(result["status"], "failed");
        assert!(result.to_string().contains("Unsupported"));
    }
    for case in [
        "append",
        "inline",
        "expression",
        "missing",
        "string",
        "extra",
        "hash",
        "label",
        "create",
        "unknown-mode",
    ] {
        let files = References {
            calls: Cell::new(0),
            returned: reference(),
            fail: false,
            policy_refused: false,
        };
        let mut input = input.clone();
        match case {
            "append" => input["mode"] = json!("append"),
            "inline" => input["body"] = json!(SECRET),
            "expression" => input["body_expr"] = json!(SECRET),
            "missing" => {
                input
                    .as_object_mut()
                    .expect("object-shaped reference input")
                    .remove("body_ref");
            }
            "string" => input["body_ref"] = json!(SECRET),
            "extra" => input["body_ref"]["body"] = json!(SECRET),
            "hash" => input["body_ref"]["content_hash"] = json!(SECRET),
            "label" => input["body_ref"]["label_ref"] = json!(" "),
            "create" => input["mode"] = json!("create"),
            "unknown-mode" => input["mode"] = json!("overwrite"),
            _ => unreachable!(),
        }
        let result = execute(make(), "file.write", input, &files);
        assert_eq!(result["status"], "failed", "{case}: {result}");
        assert_eq!(files.calls.get(), 0, "{case}");
    }
}
