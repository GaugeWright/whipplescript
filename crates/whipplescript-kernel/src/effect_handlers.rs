//! Host-agnostic effect-handler cores (DR-0033 chunk 5b).
//!
//! The store-only effect handlers, lifted out of the CLI so BOTH host bindings
//! can execute effects over their held store handle: the native `InstanceDriver`
//! dispatches them over `RuntimeKernel<NativeStores>`, the DO's `DoInstanceDriver`
//! over `RuntimeKernel<DoSqliteStore>`. Each core settles one ready effect to its
//! terminal synchronously (no external I/O), reading only its `EffectConfig`
//! (host-neutral) — so it runs identically on both hosts. HTTP-bearing effects
//! (coerce/agent) and the recursion handlers are lifted separately.

use serde_json::{json, Value};

use std::path::Path;

use whipplescript_store::coordination::Coordination;
use whipplescript_store::files::FileStore;
use whipplescript_store::items::WorkItems;
use whipplescript_store::{
    ClaimableEffect, EffectCompletion, FactView, RunStart, RuntimeStore, StoreError, StoredEvent,
};

use crate::effect_config::EffectConfig;
use crate::idempotency_key;
use crate::rule_lowering::{
    effect_binding_value, empty_ir_program, eval_expr_value, guard_result, interpolate_prompt,
    json_from_str, parse_field_value, stable_hash_hex, EvalScope, GuardStatus, RuleContext,
};
use crate::RuntimeKernel;

/// The local-workflow package name (matches the CLI's `LOCAL_WORKFLOW_PACKAGE`).
const LOCAL_WORKFLOW_PACKAGE: &str = "local";

/// `event.emit`: ingest a durable event, settle the effect, and derive the
/// `event.emit.succeeded` + `<event_type>` facts (kernel methods only).
pub fn run_event_effect_generic<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    effect: &ClaimableEffect,
    config: &EffectConfig,
) -> Result<StoredEvent, StoreError> {
    let input = json_from_str(&effect.input_json);
    let event_type = input
        .get("event_type")
        .and_then(Value::as_str)
        .or(effect.target.as_deref())
        .unwrap_or("event.emitted");
    let payload = input
        .get("payload")
        .cloned()
        .unwrap_or_else(|| json!({"effect_id": effect.effect_id, "event_type": event_type}));
    let run_id = idempotency_key(&[instance_id, &effect.effect_id, "event-run"]);
    let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "event-lease"]);
    kernel.start_run(RunStart {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: &config.provider,
        worker_id: "whip-worker",
        lease_id: &lease_id,
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: &json!({
            "event_type": event_type,
            "input": input,
        })
        .to_string(),
    })?;

    let emitted = kernel.ingest_external_event(
        instance_id,
        event_type,
        &payload.to_string(),
        Some(&idempotency_key(&[
            instance_id,
            &effect.effect_id,
            event_type,
            "event.emit",
        ])),
    )?;
    let metadata_json = json!({
        "event_type": event_type,
        "event_id": emitted.event_id,
        "input": input,
        "value": payload,
    })
    .to_string();
    let terminal = kernel.complete_run(EffectCompletion {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: &config.provider,
        worker_id: "whip-worker",
        status: "completed",
        exit_code: Some(0),
        summary: Some("fixture event emitted"),
        metadata_json: &metadata_json,
        idempotency_key: Some(&idempotency_key(&[
            instance_id,
            &effect.effect_id,
            "terminal",
        ])),
    })?;
    let mut emitted_value = payload.as_object().cloned().unwrap_or_default();
    emitted_value.insert(
        "event_id".to_owned(),
        Value::String(emitted.event_id.clone()),
    );
    emitted_value.insert(
        "event_type".to_owned(),
        Value::String(event_type.to_owned()),
    );
    emitted_value.insert("payload".to_owned(), payload.clone());
    let value_json = json!({
        "effect_id": effect.effect_id,
        "run_id": run_id,
        "event_id": emitted.event_id,
        "event_type": event_type,
        "status": "completed",
        "value": Value::Object(emitted_value),
        "summary": "fixture event emitted",
    })
    .to_string();
    kernel.derive_fact(
        instance_id,
        "event.emit.succeeded",
        &effect.effect_id,
        &value_json,
        Some(&terminal.event_id),
        Some(&idempotency_key(&[
            instance_id,
            &effect.effect_id,
            "event.emit.succeeded",
        ])),
    )?;
    kernel.derive_fact(
        instance_id,
        event_type,
        &effect.effect_id,
        &value_json,
        Some(&emitted.event_id),
        Some(&idempotency_key(&[
            instance_id,
            &effect.effect_id,
            event_type,
            "fact",
        ])),
    )?;
    Ok(terminal)
}

// -- store-only handler cores + helpers (batch lift, DR-0033 chunk 5b) -------

/// Full-string wildcard match where `*` matches any (possibly empty) run of
/// characters; every other character is literal. The classic backtracking
/// two-pointer matcher (`workflow-testing.md` defines `*` as the only wildcard).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub fn coordination_owner_from_principal(principal: &str) -> Option<String> {
    let principal = principal.trim();
    if principal.is_empty() {
        return None;
    }
    principal
        .strip_prefix("workflow:")
        .filter(|owner| !owner.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| Some(principal.to_owned()))
}

pub fn coordination_owner_for_instance<S: RuntimeStore>(
    store: &S,
    instance_id: &str,
) -> Result<String, StoreError> {
    let instance = store
        .get_instance(instance_id)?
        .ok_or_else(|| StoreError::Conflict(format!("instance `{instance_id}` not found")))?;
    if let Some(owner) = coordination_owner_from_principal(&instance.workflow_principal) {
        return Ok(owner);
    }
    let version = store
        .get_program_version(&instance.version_id)?
        .ok_or_else(|| {
            StoreError::Conflict(format!(
                "program version `{}` for instance `{instance_id}` not found",
                instance.version_id
            ))
        })?;
    Ok(format!("{LOCAL_WORKFLOW_PACKAGE}/{}", version.program_name))
}

/// Host-agnostic core (DR-0033 chunk 3): fold an `after`-binding into the effect
/// input using facts read from a held store. Read-only, so `&S` suffices.
pub fn resolve_effect_input_after_bindings_generic<S: RuntimeStore>(
    store: &S,
    instance_id: &str,
    effect: &ClaimableEffect,
) -> Result<String, StoreError> {
    let mut input = json_from_str(&effect.input_json);
    let Some(after) = input.get("after").cloned() else {
        return Ok(effect.input_json.clone());
    };
    let Some(binding) = after.get("binding").and_then(Value::as_str) else {
        return Ok(effect.input_json.clone());
    };
    let Some(predicate) = after.get("predicate").and_then(Value::as_str) else {
        return Ok(effect.input_json.clone());
    };
    let Some(upstream_effect_id) = after.get("upstream_effect_id").and_then(Value::as_str) else {
        return Ok(effect.input_json.clone());
    };
    let facts = store.list_facts(instance_id)?;
    let Some(binding_value) = effect_binding_value(&facts, upstream_effect_id, predicate) else {
        return Ok(effect.input_json.clone());
    };
    if let Some(bindings) = input.get_mut("bindings").and_then(Value::as_object_mut) {
        bindings.insert(binding.to_owned(), binding_value.clone());
    }
    let mut context = context_from_input_bindings(&input);
    context.bindings.push((
        binding.to_owned(),
        FactView {
            fact_id: upstream_effect_id.to_owned(),
            program_version_id: None,
            revision_epoch: 0,
            name: binding.to_owned(),
            key: upstream_effect_id.to_owned(),
            value_json: binding_value.to_string(),
            provenance_class: "effect".to_owned(),
            source_span_json: None,
            source_event_id: String::new(),
        },
    ));
    if let Some(argument_exprs) = input.get("argument_exprs").and_then(Value::as_array) {
        let mut arguments = serde_json::Map::new();
        for (index, expr) in argument_exprs.iter().filter_map(Value::as_str).enumerate() {
            arguments.insert(format!("arg{index}"), parse_field_value(expr, &context));
        }
        if let Some(object) = input.as_object_mut() {
            object.insert("arguments".to_owned(), Value::Object(arguments));
        }
    }
    if let Some(prompt) = input
        .get("prompt")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        if let Some(object) = input.as_object_mut() {
            object.insert(
                "prompt".to_owned(),
                Value::String(interpolate_prompt(&prompt, &context)),
            );
        }
    }
    Ok(input.to_string())
}

pub fn context_from_input_bindings(input: &Value) -> RuleContext {
    let mut context = RuleContext {
        trigger_event_id: None,
        identity: None,
        bindings: Vec::new(),
    };
    let Some(bindings) = input.get("bindings").and_then(Value::as_object) else {
        return context;
    };
    for (binding, value) in bindings {
        context.bindings.push((
            binding.clone(),
            FactView {
                fact_id: binding.clone(),
                program_version_id: None,
                revision_epoch: 0,
                name: binding.clone(),
                key: binding.clone(),
                value_json: value.to_string(),
                provenance_class: "input".to_owned(),
                source_span_json: None,
                source_event_id: String::new(),
            },
        ));
    }
    context
}

/// Executes a `read` file effect (std.files, piece 4): the local file provider
/// reads `<store root>/<path>` and completes the effect with the content as its
/// typed outcome (`succeeds` branch). A read error is a branchable `fails`
/// outcome, not a workflow failure.
/// The `file store` scope check shared by `read`/`write`: a path that is
/// absolute or climbs out of the root with `..` is refused, and — when the store
/// declares an `allow read/write [...]` list — the path must match one of the
/// globs. An empty allow list means any path inside the root. Returns the
/// failure reason, or `None` when the path is permitted.
pub fn file_path_policy_error(
    path: &str,
    store_name: &str,
    allow_globs: &[String],
    operation: &str,
) -> Option<String> {
    if Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Some(format!(
            "path `{path}` escapes the `{store_name}` store root"
        ));
    }
    // S4 (language-refinement follow-on): a store is READ-ONLY by default.
    // Reads with no declared globs are allowed anywhere inside the root (the
    // mount was deliberate), but WRITES fail closed unless the store declares
    // an `allow write [...]` policy — mutation is never ambient authority.
    if operation == "write" && allow_globs.is_empty() {
        return Some(format!(
            "store `{store_name}` permits no writes: declare `allow write [...]` \
             (writes are denied by default)"
        ));
    }
    if !allow_globs.is_empty() && !allow_globs.iter().any(|glob| glob_match(glob, path)) {
        return Some(format!(
            "path `{path}` is not in the `{store_name}` store's `allow {operation}` policy"
        ));
    }
    None
}

pub fn effect_allow_globs(input: &Value) -> Vec<String> {
    input
        .get("allow")
        .and_then(Value::as_array)
        .map(|globs| {
            globs
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Host-agnostic core (DR-0033 chunk 3): read a file through the `FileStore` seam
/// and record the terminal/fact over a held `RuntimeKernel<S>`. Native passes
/// `NativeFileStore`; the DO passes `DoFileStore`.
pub fn run_file_effect_generic<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    files: &dyn FileStore,
    instance_id: &str,
    effect: &ClaimableEffect,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    let input = json_from_str(&effect.input_json);
    let root = input
        .get("root")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let format = input
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("text")
        .to_owned();
    let store_name = input
        .get("store")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let full = Path::new(root).join(path);
    let run_id = idempotency_key(&[instance_id, &effect.effect_id, "file-run"]);
    let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "file-lease"]);
    kernel.start_run(RunStart {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "files",
        worker_id: "whip-files",
        lease_id: &lease_id,
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: &json!({ "path": full.display().to_string() }).to_string(),
    })?;
    let terminal_key = idempotency_key(&[instance_id, &effect.effect_id, "terminal"]);
    let fact_key = idempotency_key(&[instance_id, &effect.effect_id, "file-fact"]);
    // The `file store` root + `allow read` policy is the scope boundary
    // (spec/std-library/files.md), checked before any disk access.
    let allow = effect_allow_globs(&input);
    let read_outcome = match file_path_policy_error(path, store_name, &allow, "read")
        .or_else(|| files.path_policy_error(Path::new(root), Path::new(path), store_name, "read"))
    {
        Some(reason) => Err(reason),
        None => files
            .read_to_string(&full)
            .map_err(|error| format!("read of `{}` failed: {error}", full.display())),
    };
    match read_outcome {
        Ok(content) => {
            let value = json!({
                "store": store_name,
                "path": path,
                "format": format,
                "content": content,
                "bytes": content.len(),
            });
            let terminal = kernel.complete_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "files",
                worker_id: "whip-files",
                status: "completed",
                exit_code: Some(0),
                summary: Some(&format!(
                    "read {} bytes from {}",
                    content.len(),
                    full.display()
                )),
                metadata_json: &json!({ "value": value }).to_string(),
                idempotency_key: Some(&terminal_key),
            })?;
            // The settled effect becomes a `file.read.completed` fact (keyed by
            // effect id) so `after <binding> succeeds as r` can bind `r.content`.
            // Mirrors run_exec_effect's `exec.command.completed` projection.
            kernel.derive_fact(
                instance_id,
                "file.read.completed",
                &effect.effect_id,
                &json!({
                    "effect_id": effect.effect_id,
                    "run_id": run_id,
                    "status": "completed",
                    "value": value,
                })
                .to_string(),
                Some(&terminal.event_id),
                Some(&fact_key),
            )?;
            Ok(terminal)
        }
        Err(reason) => {
            let terminal = kernel.fail_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "files",
                worker_id: "whip-files",
                status: "failed",
                exit_code: None,
                summary: Some(&reason),
                metadata_json: &json!({ "failure": { "message": reason } }).to_string(),
                idempotency_key: Some(&terminal_key),
            })?;
            kernel.derive_fact(
                instance_id,
                "file.read.failed",
                &effect.effect_id,
                &json!({
                    "effect_id": effect.effect_id,
                    "run_id": run_id,
                    "status": "failed",
                    "value": effect_failure_base("file.read", &reason, &reason, &effect.effect_id, &run_id),
                    "error": { "message": reason },
                })
                .to_string(),
                Some(&terminal.event_id),
                Some(&fact_key),
            )?;
            Ok(terminal)
        }
    }
}

/// Host-agnostic core (DR-0033 chunk 3): write/append a file through the
/// `FileStore` seam + record the terminal over a held `RuntimeKernel<S>`.
pub fn run_file_write_effect_generic<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    files: &dyn FileStore,
    instance_id: &str,
    effect: &ClaimableEffect,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    let input = json_from_str(&effect.input_json);
    let root = input
        .get("root")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let format = input
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("text")
        .to_owned();
    let store_name = input
        .get("store")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mode = input
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("create")
        .to_owned();
    let body = input
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let full = Path::new(root).join(path);
    let run_id = idempotency_key(&[instance_id, &effect.effect_id, "file-run"]);
    let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "file-lease"]);
    kernel.start_run(RunStart {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "files",
        worker_id: "whip-files",
        lease_id: &lease_id,
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: &json!({ "path": full.display().to_string(), "mode": mode }).to_string(),
    })?;
    let terminal_key = idempotency_key(&[instance_id, &effect.effect_id, "terminal"]);
    let fact_key = idempotency_key(&[instance_id, &effect.effect_id, "file-fact"]);
    let allow = effect_allow_globs(&input);
    let write_outcome: Result<(), String> = if let Some(reason) =
        file_path_policy_error(path, store_name, &allow, "write").or_else(|| {
            files.path_policy_error(Path::new(root), Path::new(path), store_name, "write")
        }) {
        Err(reason)
    } else {
        let exists = files.exists(&full);
        // Mode policy (spec/std-library/files.md): no silent overwrite.
        let mode_ok = match mode.as_str() {
            "create" if exists => Err(format!(
                "write mode `create` requires `{path}` to not already exist"
            )),
            "replace" if !exists => Err(format!(
                "write mode `replace` requires `{path}` to already exist"
            )),
            "create" | "replace" | "upsert" | "append" => Ok(()),
            other => Err(format!("unknown write mode `{other}`")),
        };
        mode_ok.and_then(|()| {
            if let Some(parent) = full.parent() {
                files
                    .create_dir_all(parent)
                    .map_err(|error| format!("create parent of `{path}`: {error}"))?;
            }
            let result = if mode == "append" {
                files.append(&full, body.as_bytes())
            } else {
                files.write(&full, body.as_bytes())
            };
            result.map_err(|error| format!("write of `{}` failed: {error}", full.display()))
        })
    };
    match write_outcome {
        Ok(()) => {
            // Restorable-context RC-1: capture the written body content-addressed
            // into the runtime store's file-history blob table, keyed by the SAME
            // `stable_hash_hex` the `file.write.completed` fact records below. The
            // live path->bytes store overwrites in place; this sidecar preserves
            // the superseded version so a later restore slice can `get_content`
            // the bytes back. Captured BEFORE the fact commits (and, natively, in
            // the same SQLite as the fact), so no committed manifest hash is ever
            // referenced without its bytes present (restorable-context INV-4). A
            // capture failure aborts before the fact, never leaving a dangling
            // hash. Identical bytes dedupe; an overwrite keeps both versions.
            kernel.store().put_content(&body)?;
            let value = json!({
                "store": store_name,
                "path": path,
                // RC-5: the full resolved path (root-joined) so restore is
                // self-contained and writes the body back to the exact location.
                // `path` stays the workflow-visible relative path.
                "full_path": full.display().to_string(),
                "format": format,
                "mode": mode,
                "bytes": body.len(),
                "content_hash": stable_hash_hex(&body),
            });
            let terminal = kernel.complete_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "files",
                worker_id: "whip-files",
                status: "completed",
                exit_code: Some(0),
                summary: Some(&format!("wrote {} bytes to {}", body.len(), full.display())),
                metadata_json: &json!({ "value": value }).to_string(),
                idempotency_key: Some(&terminal_key),
            })?;
            kernel.derive_fact(
                instance_id,
                "file.write.completed",
                &effect.effect_id,
                &json!({
                    "effect_id": effect.effect_id,
                    "run_id": run_id,
                    "status": "completed",
                    "value": value,
                })
                .to_string(),
                Some(&terminal.event_id),
                Some(&fact_key),
            )?;
            Ok(terminal)
        }
        Err(reason) => {
            let terminal = kernel.fail_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "files",
                worker_id: "whip-files",
                status: "failed",
                exit_code: None,
                summary: Some(&reason),
                metadata_json: &json!({ "failure": { "message": reason } }).to_string(),
                idempotency_key: Some(&terminal_key),
            })?;
            kernel.derive_fact(
                instance_id,
                "file.write.failed",
                &effect.effect_id,
                &json!({
                    "effect_id": effect.effect_id,
                    "run_id": run_id,
                    "status": "failed",
                    "value": effect_failure_base("file.write", &reason, &reason, &effect.effect_id, &run_id),
                    "error": { "message": reason },
                })
                .to_string(),
                Some(&terminal.event_id),
                Some(&fact_key),
            )?;
            Ok(terminal)
        }
    }
}

/// Split one CSV record into fields with RFC-4180-style quoting: fields may be
/// double-quoted, a quoted field may contain commas, and `""` inside a quoted
/// field is a literal quote. v0 assumes one record per line (no embedded
/// newlines) and all values decode as strings.
pub fn split_csv_record(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut field));
            }
            other => field.push(other),
        }
    }
    fields.push(field);
    fields
}

/// Decode a structured import file into rows (std.files). v0 decodes `jsonl`
/// (one JSON value per non-blank line), `json` (a top-level array of values),
/// and `csv` (a header row mapped over each subsequent record; values are
/// strings).
pub fn decode_import_rows(format: &str, content: &str) -> Result<Vec<Value>, String> {
    match format {
        "jsonl" => content
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(index, line)| {
                serde_json::from_str::<Value>(line.trim())
                    .map_err(|error| format!("row {index} is not valid JSON: {error}"))
            })
            .collect(),
        "json" => match serde_json::from_str::<Value>(content.trim()) {
            Ok(Value::Array(rows)) => Ok(rows),
            Ok(_) => Err("a `json` import must be a top-level array of rows".to_owned()),
            Err(error) => Err(format!("import file is not valid JSON: {error}")),
        },
        "csv" => {
            let mut lines = content.lines().filter(|line| !line.trim().is_empty());
            let Some(header_line) = lines.next() else {
                return Ok(Vec::new());
            };
            let header = split_csv_record(header_line);
            let mut rows = Vec::new();
            for (index, line) in lines.enumerate() {
                let values = split_csv_record(line);
                if values.len() != header.len() {
                    return Err(format!(
                        "csv row {index} has {} fields but the header declares {}",
                        values.len(),
                        header.len()
                    ));
                }
                let object = header
                    .iter()
                    .cloned()
                    .zip(values.into_iter().map(Value::String))
                    .collect::<serde_json::Map<String, Value>>();
                rows.push(Value::Object(object));
            }
            Ok(rows)
        }
        other => Err(format!("unknown import format `{other}`")),
    }
}

/// Host-agnostic core (DR-0033 chunk 3): import a file's content into facts
/// through the `FileStore` seam over a held `RuntimeKernel<S>`.
pub fn run_file_import_effect_generic<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    files: &dyn FileStore,
    instance_id: &str,
    effect: &ClaimableEffect,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    use whipplescript_store::{FactBatch, FactBatchRow};

    let input = json_from_str(&effect.input_json);
    let root = input
        .get("root")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let format = input
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("jsonl")
        .to_owned();
    let schema = input
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let store_name = input
        .get("store")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let allow = effect_allow_globs(&input);
    let required_fields = input
        .get("required_fields")
        .and_then(Value::as_array)
        .map(|fields| {
            fields
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let natural_key_field = input
        .get("natural_key_field")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let full = Path::new(root).join(path);
    let run_id = idempotency_key(&[instance_id, &effect.effect_id, "file-run"]);
    let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "file-lease"]);
    kernel.start_run(RunStart {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "files",
        worker_id: "whip-files",
        lease_id: &lease_id,
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: &json!({ "path": full.display().to_string(), "schema": schema }).to_string(),
    })?;
    let terminal_key = idempotency_key(&[instance_id, &effect.effect_id, "terminal"]);
    let fact_key = idempotency_key(&[instance_id, &effect.effect_id, "file-fact"]);

    // Decode + validate every row before admitting any (all-or-nothing).
    let decoded: Result<Vec<Value>, String> = (|| {
        if let Some(reason) =
            file_path_policy_error(path, store_name, &allow, "read").or_else(|| {
                files.path_policy_error(Path::new(root), Path::new(path), store_name, "read")
            })
        {
            return Err(reason);
        }
        let content = files
            .read_to_string(&full)
            .map_err(|error| format!("read of `{}` failed: {error}", full.display()))?;
        let rows = decode_import_rows(&format, &content)?;
        for (index, row) in rows.iter().enumerate() {
            let object = row
                .as_object()
                .ok_or_else(|| format!("row {index} is not a JSON object"))?;
            for field in &required_fields {
                if !object.contains_key(field) {
                    return Err(format!(
                        "row {index} is missing required field `{field}` for schema `{schema}`"
                    ));
                }
            }
        }
        Ok(rows)
    })();

    match decoded {
        Ok(rows) => {
            // Per-row admission key + recorded key. When the schema declares a
            // `@key` field, key by that field's value (H(effect_key,
            // natural_key)); otherwise by row index (H(effect_key, row_index)).
            let row_identity = |index: usize, row: &Value| -> String {
                if natural_key_field.is_empty() {
                    return index.to_string();
                }
                match row.get(&natural_key_field) {
                    Some(Value::String(text)) => text.clone(),
                    Some(other) => other.to_string(),
                    None => index.to_string(),
                }
            };
            let keys = rows
                .iter()
                .enumerate()
                .map(|(index, row)| row_identity(index, row))
                .collect::<Vec<_>>();
            let fact_ids = keys
                .iter()
                .enumerate()
                .map(|(index, key)| {
                    if natural_key_field.is_empty() {
                        idempotency_key(&[&effect.effect_id, "row", &index.to_string()])
                    } else {
                        idempotency_key(&[&effect.effect_id, "natkey", key])
                    }
                })
                .collect::<Vec<_>>();
            let values = rows.iter().map(Value::to_string).collect::<Vec<_>>();
            let batch_rows = (0..rows.len())
                .map(|index| FactBatchRow {
                    fact_id: &fact_ids[index],
                    key: &keys[index],
                    value_json: &values[index],
                })
                .collect::<Vec<_>>();
            let admitted = kernel.admit_fact_batch(FactBatch {
                instance_id,
                source: "files",
                causation_id: Some(&effect.effect_id),
                correlation_id: Some(&effect.effect_id),
                schema_name: &schema,
                schema_id: Some(&schema),
                rows: &batch_rows,
            })?;
            let value = json!({
                "store": store_name,
                "path": path,
                "format": format,
                "schema": schema,
                "row_count": rows.len(),
                "admitted": admitted.admitted,
                "skipped": admitted.skipped,
            });
            let terminal = kernel.complete_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "files",
                worker_id: "whip-files",
                status: "completed",
                exit_code: Some(0),
                summary: Some(&format!(
                    "imported {} rows from {}",
                    rows.len(),
                    full.display()
                )),
                metadata_json: &json!({ "value": value }).to_string(),
                idempotency_key: Some(&terminal_key),
            })?;
            kernel.derive_fact(
                instance_id,
                "file.import.completed",
                &effect.effect_id,
                &json!({
                    "effect_id": effect.effect_id,
                    "run_id": run_id,
                    "status": "completed",
                    "value": value,
                })
                .to_string(),
                Some(&terminal.event_id),
                Some(&fact_key),
            )?;
            Ok(terminal)
        }
        Err(reason) => {
            let terminal = kernel.fail_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "files",
                worker_id: "whip-files",
                status: "failed",
                exit_code: None,
                summary: Some(&reason),
                metadata_json: &json!({ "failure": { "message": reason } }).to_string(),
                idempotency_key: Some(&terminal_key),
            })?;
            kernel.derive_fact(
                instance_id,
                "file.import.failed",
                &effect.effect_id,
                &json!({
                    "effect_id": effect.effect_id,
                    "run_id": run_id,
                    "status": "failed",
                    "value": effect_failure_base("file.import", &reason, &reason, &effect.effect_id, &run_id),
                    "error": { "message": reason },
                })
                .to_string(),
                Some(&terminal.event_id),
                Some(&fact_key),
            )?;
            Ok(terminal)
        }
    }
}

/// Evaluate a `proj_query` predicate against one projection/fact row, reusing the
/// guard expression kernel restricted to the row's fields. Returns `Err` on a
/// predicate that cannot be parsed or does not evaluate to a boolean — never a
/// silent false.
pub fn evaluate_proj_predicate(predicate: &str, row: &Value) -> Result<bool, String> {
    let expr = whipplescript_parser::parse_expression(predicate)
        .map_err(|error| format!("could not parse predicate `{predicate}`: {error}"))?;
    let empty_ir = empty_ir_program();
    let scope = EvalScope {
        context: None,
        facts: &[],
        effects: &[],
        ir: &empty_ir,
        projection: Some(row),
        projection_schema: None,
    };
    match guard_result(eval_expr_value(&expr, &scope)) {
        (GuardStatus::Matched, _, _) => Ok(true),
        (GuardStatus::False, _, _) => Ok(false),
        (GuardStatus::Error, _, error) => {
            Err(error.unwrap_or_else(|| "predicate did not evaluate to a boolean".to_owned()))
        }
    }
}

/// CSV-escape one field (inverse of `split_csv_record`): quote when the value
/// contains a comma, quote, or newline; double embedded quotes.
fn csv_escape_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// Serialize export rows (std.files), the inverse of `decode_import_rows`. `jsonl`
/// = one JSON object per line; `json` = a top-level array; `csv` = a header line
/// from `fields` then one record per row (stable column order, values stringified).
pub fn encode_export_rows(
    format: &str,
    rows: &[Value],
    fields: &[String],
) -> Result<String, String> {
    let cell = |row: &Value, field: &str| -> String {
        match row.as_object().and_then(|object| object.get(field)) {
            Some(Value::String(text)) => text.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        }
    };
    match format {
        "jsonl" => {
            let mut out = rows
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            if !rows.is_empty() {
                out.push('\n');
            }
            Ok(out)
        }
        "json" => serde_json::to_string(&Value::Array(rows.to_vec()))
            .map(|mut text| {
                text.push('\n');
                text
            })
            .map_err(|error| format!("json export serialize failed: {error}")),
        "csv" => {
            let mut out = fields
                .iter()
                .map(|field| csv_escape_field(field))
                .collect::<Vec<_>>()
                .join(",");
            out.push('\n');
            for row in rows {
                let record = fields
                    .iter()
                    .map(|field| csv_escape_field(&cell(row, field)))
                    .collect::<Vec<_>>()
                    .join(",");
                out.push_str(&record);
                out.push('\n');
            }
            Ok(out)
        }
        other => Err(format!("unknown export format `{other}`")),
    }
}

/// Host-agnostic core (DR-0033 chunk 3; relocated from the CLI in std.files
/// slice F4 — crate location, not shape): export a `<Schema>` fact collection
/// (optionally filtered by the `where` predicate, ordered deterministically by
/// the store's `(name, key)` ordering — DR-0022) to a file through the
/// `FileStore` seam over a held `RuntimeKernel<S>`. A success settles
/// `file.export.completed` with the row count and a content hash; living in
/// the kernel, it builds for wasm32 so exports run on the DO plane too.
pub fn run_file_export_effect_generic<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    files: &dyn FileStore,
    instance_id: &str,
    effect: &ClaimableEffect,
) -> Result<StoredEvent, StoreError> {
    let input = json_from_str(&effect.input_json);
    let root = input
        .get("root")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let format = input
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("jsonl")
        .to_owned();
    let schema = input
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let store_name = input
        .get("store")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mode = input
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("create")
        .to_owned();
    let predicate = input
        .get("predicate")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let allow = effect_allow_globs(&input);
    let fields = input
        .get("fields")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let full = Path::new(root).join(path);
    let run_id = idempotency_key(&[instance_id, &effect.effect_id, "file-run"]);
    let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "file-lease"]);
    kernel.start_run(RunStart {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "files",
        worker_id: "whip-files",
        lease_id: &lease_id,
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: &json!({ "path": full.display().to_string(), "schema": schema }).to_string(),
    })?;
    let terminal_key = idempotency_key(&[instance_id, &effect.effect_id, "terminal"]);
    let fact_key = idempotency_key(&[instance_id, &effect.effect_id, "file-fact"]);

    let outcome: Result<(usize, String), String> = (|| {
        if let Some(reason) =
            file_path_policy_error(path, store_name, &allow, "write").or_else(|| {
                files.path_policy_error(Path::new(root), Path::new(path), store_name, "write")
            })
        {
            return Err(reason);
        }
        // Resolve the collection: facts of <schema> [where predicate], ordered by
        // the store's deterministic (name, key) ordering for reproducible output.
        let facts = kernel
            .store()
            .list_facts(instance_id)
            .map_err(|error| format!("{error:?}"))?;
        let mut rows = Vec::new();
        for fact in facts.iter().filter(|fact| fact.name == schema) {
            let value: Value = serde_json::from_str(&fact.value_json)
                .map_err(|error| format!("fact value is not JSON: {error}"))?;
            if predicate.is_empty() || evaluate_proj_predicate(&predicate, &value)? {
                rows.push(value);
            }
        }
        let exists = files.exists(&full);
        match mode.as_str() {
            "create" if exists => {
                return Err(format!(
                    "write mode `create` requires `{path}` to not already exist"
                ))
            }
            "replace" if !exists => {
                return Err(format!(
                    "write mode `replace` requires `{path}` to already exist"
                ))
            }
            "create" | "replace" | "upsert" | "append" => {}
            other => return Err(format!("unknown write mode `{other}`")),
        }
        let serialized = encode_export_rows(&format, &rows, &fields)?;
        if let Some(parent) = full.parent() {
            files
                .create_dir_all(parent)
                .map_err(|error| format!("create parent of `{path}`: {error}"))?;
        }
        if mode == "append" {
            files
                .append(&full, serialized.as_bytes())
                .map_err(|error| format!("append to `{}` failed: {error}", full.display()))?;
        } else {
            files
                .write(&full, serialized.as_bytes())
                .map_err(|error| format!("write of `{}` failed: {error}", full.display()))?;
        }
        Ok((rows.len(), stable_hash_hex(&serialized)))
    })();

    match outcome {
        Ok((row_count, content_hash)) => {
            let value = json!({
                "store": store_name,
                "path": path,
                "format": format,
                "schema": schema,
                "mode": mode,
                "row_count": row_count,
                "content_hash": content_hash,
            });
            let terminal = kernel.complete_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "files",
                worker_id: "whip-files",
                status: "completed",
                exit_code: Some(0),
                summary: Some(&format!("exported {row_count} rows to {}", full.display())),
                metadata_json: &json!({ "value": value }).to_string(),
                idempotency_key: Some(&terminal_key),
            })?;
            kernel.derive_fact(
                instance_id,
                "file.export.completed",
                &effect.effect_id,
                &json!({
                    "effect_id": effect.effect_id,
                    "run_id": run_id,
                    "status": "completed",
                    "value": value,
                })
                .to_string(),
                Some(&terminal.event_id),
                Some(&fact_key),
            )?;
            Ok(terminal)
        }
        Err(reason) => {
            let terminal = kernel.fail_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "files",
                worker_id: "whip-files",
                status: "failed",
                exit_code: None,
                summary: Some(&reason),
                metadata_json: &json!({ "failure": { "message": reason } }).to_string(),
                idempotency_key: Some(&terminal_key),
            })?;
            kernel.derive_fact(
                instance_id,
                "file.export.failed",
                &effect.effect_id,
                &json!({
                    "effect_id": effect.effect_id,
                    "run_id": run_id,
                    "status": "failed",
                    "value": effect_failure_base("file.export", &reason, &reason, &effect.effect_id, &run_id),
                    "error": { "message": reason },
                })
                .to_string(),
                Some(&terminal.event_id),
                Some(&fact_key),
            )?;
            Ok(terminal)
        }
    }
}

/// Host-agnostic core (DR-0033 chunk 3): the lease/ledger/counter op + its terminal
/// over a held `RuntimeKernel<S>`; coordination is the DO's own store there, so
/// `S: RuntimeStore + Coordination` unifies both surfaces.
/// std.coord slice 3: the counter reset-period boundary, computed from the
/// INJECTED `now` (never wall clock — the period an outcome resolves against
/// is recorded on the outcome, so replay re-reads instead of re-deriving) in
/// the counter's declared timezone, DST-correct via the same chrono-tz
/// machinery the clock sources use. `None` = the timezone does not name an
/// IANA zone or `now` does not parse — malformed input, failed typed.
pub fn counter_period(reset: &str, timezone: &str, now: &str) -> Option<String> {
    let instant = crate::time_pass::parse_clock_instant(now)?;
    let tz: chrono_tz::Tz = timezone.parse().ok()?;
    let local = instant.with_timezone(&tz);
    let format = match reset {
        "hourly" => "%Y-%m-%dT%H",
        "weekly" => "%Y-W%W",
        "monthly" => "%Y-%m",
        _ => "%Y-%m-%d",
    };
    Some(local.format(format).to_string())
}

/// Fail a coordination effect with the DR-0032 typed base (handler honesty,
/// spec/std-coord.md v1 slice 2): opens the run, fails it, and derives the
/// `{kind}.failed` fact whose `value` is the uniform `EffectError` base — the
/// same terminal shape every other failing effect kind produces, so
/// `after <acquire> fails as f` binds a typed `f`.
fn fail_coordination_effect<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    effect: &ClaimableEffect,
    reason: &str,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    let run_id = idempotency_key(&[instance_id, &effect.effect_id, "coord-run"]);
    let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "coord-lease"]);
    kernel.start_run(RunStart {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "coordination",
        worker_id: "whip-coordination",
        lease_id: &lease_id,
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: &json!({"kind": effect.kind}).to_string(),
    })?;
    let terminal = kernel.fail_run(EffectCompletion {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "coordination",
        worker_id: "whip-coordination",
        status: "failed",
        exit_code: None,
        summary: Some(reason),
        metadata_json: &json!({ "failure": { "message": reason } }).to_string(),
        idempotency_key: Some(&idempotency_key(&[
            instance_id,
            &effect.effect_id,
            "terminal",
        ])),
    })?;
    kernel.derive_fact(
        instance_id,
        &format!("{}.failed", effect.kind),
        &effect.effect_id,
        &json!({
            "effect_id": effect.effect_id,
            "run_id": run_id,
            "status": "failed",
            "value": effect_failure_base(&effect.kind, reason, reason, &effect.effect_id, &run_id),
            "error": { "message": reason },
        })
        .to_string(),
        Some(&terminal.event_id),
        Some(&idempotency_key(&[
            instance_id,
            &effect.effect_id,
            "coord-fact",
        ])),
    )?;
    Ok(terminal)
}

pub fn run_coordination_effect_generic<S: RuntimeStore + Coordination>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    effect: &ClaimableEffect,
    now: &str,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    run_coordination_effect_generic_ctx(kernel, instance_id, effect, now, None)
}

/// A host hook mapping one contending holder id to its workspace context.
pub type HolderContextResolver<'a> = &'a dyn Fn(&str) -> Option<Value>;

/// [`run_coordination_effect_generic`] with an optional HOLDER-CONTEXT
/// resolver (DR-0052 S6): on a `Contended` outcome, each holder id is
/// offered to the resolver, which may return workspace context — the
/// holder's line, its last cut's actor (who, as which session) and
/// intent (why) — so the `contended` arm's author can write a real
/// policy instead of blind retry. `None` (the DO host, tests) keeps the
/// bare outcome; the enrichment is additive fields, never a variant
/// change.
pub fn run_coordination_effect_generic_ctx<S: RuntimeStore + Coordination>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    effect: &ClaimableEffect,
    now: &str,
    holder_context: Option<HolderContextResolver<'_>>,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    use whipplescript_store::coordination::{AcquireOutcome, ConsumeOutcome};

    let input = json_from_str(&effect.input_json);
    let workflow_owner = coordination_owner_for_instance(kernel.store(), instance_id)?;
    let field = |name: &str| {
        input
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    // Handler honesty (spec/std-coord.md v1 slice 2): a missing/mistyped
    // numeric field is MALFORMED input — well-formed lowering always emits it
    // from the declaration — and fails the effect with a typed DR-0032 error
    // instead of running under a smuggled default (the old slots=1 / ttl=600 /
    // retain=86400 / cap=0). Pre-release one-way break per M4 posture.
    macro_rules! require_i64 {
        ($source:expr, $name:literal) => {
            match $source.get($name).and_then(Value::as_i64) {
                Some(value) => value,
                None => {
                    return fail_coordination_effect(
                        kernel,
                        instance_id,
                        effect,
                        &format!(
                            "malformed `{}` input: missing or non-integer `{}`",
                            effect.kind, $name
                        ),
                    )
                }
            }
        };
    }
    let owner = {
        let declared = field("coordination_owner");
        if declared.is_empty() {
            workflow_owner.clone()
        } else {
            declared
        }
    };
    let value = match effect.kind.as_str() {
        "lease.acquire" => {
            let resource = field("resource");
            let key = field("key");
            let slots = require_i64!(input, "slots");
            let ttl_seconds = require_i64!(input, "ttl_seconds");
            let outcome = kernel.store_mut().try_acquire_for_owner(
                &owner,
                &resource,
                &key,
                slots,
                ttl_seconds,
                instance_id,
            )?;
            match outcome {
                AcquireOutcome::Held => json!({
                    "variant": "Held",
                    "resource": resource,
                    "key": key,
                }),
                AcquireOutcome::Contended { holders } => {
                    // `wait <duration>` (spec/coordination.md): bounded retry on
                    // contention. While the creation-anchored wait deadline has not
                    // passed, do not complete the effect — soft-defer so the next
                    // worker pass re-attempts the acquire (mirrors the capacity
                    // soft-defer: `run_claimable_effect` maps `CapacityBlocked` to a
                    // re-claimable `Ok(None)`). The deadline reuses the effect's
                    // `timeout_seconds` via the store's `due_time_effects` clock
                    // machinery, so it honors the injected virtual clock and never
                    // reads wall time here. Once the deadline passes we fall through
                    // and complete `Contended` (give up), exactly as an acquire with
                    // no `wait` does on its first attempt.
                    let waits = input
                        .get("wait_seconds")
                        .and_then(Value::as_i64)
                        .is_some_and(|seconds| seconds > 0);
                    if waits {
                        let deadline_passed = kernel
                            .store()
                            .due_time_effects(instance_id, now)?
                            .iter()
                            .any(|due| due.effect_id == effect.effect_id);
                        if !deadline_passed {
                            return Err(StoreError::CapacityBlocked {
                                effect_id: effect.effect_id.clone(),
                                reason: format!(
                                    "lease `{resource}` contended; waiting for a free slot"
                                ),
                            });
                        }
                    }
                    // DR-0052 S6: the arm gets INFORMATION, not an
                    // arbiter — who holds it, on what line, under what
                    // intent, when the host can resolve it.
                    let holder_details: Vec<Value> = holder_context
                        .map(|resolve| {
                            holders
                                .iter()
                                .map(|holder| {
                                    resolve(holder).unwrap_or_else(|| json!({ "holder": holder }))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    json!({
                        "variant": "Contended",
                        "resource": resource,
                        "key": key,
                        "holders": holders,
                        "holder_details": holder_details,
                    })
                }
            }
        }
        "lease.release" => {
            // The release names its acquire; resource and key come from the
            // recorded acquire input, so they cannot drift.
            let acquire_effect_id = field("acquire_effect_id");
            let acquire_input = kernel
                .store()
                .list_effects(instance_id)?
                .into_iter()
                .find(|candidate| candidate.effect_id == acquire_effect_id)
                .map(|candidate| json_from_str(&candidate.input_json))
                .unwrap_or(Value::Null);
            let resource = acquire_input
                .get("resource")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let key = acquire_input
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let acquire_owner = acquire_input
                .get("coordination_owner")
                .and_then(Value::as_str)
                .filter(|owner| !owner.is_empty())
                .unwrap_or(&workflow_owner)
                .to_owned();
            // Handler honesty (slice 2): the pre-partitioning shared-owner
            // fallback — retrying an owner-scoped miss as an any-owner
            // release — is dropped; a release only ever frees its own
            // acquire's owner-scoped lease. One-way break per M4 posture.
            let released = kernel.store_mut().release_for_owner(
                &acquire_owner,
                &resource,
                &key,
                instance_id,
            )?;
            json!({
                "variant": "Released",
                "resource": resource,
                "key": key,
                "released": released,
            })
        }
        "lease.renew" => {
            // Renew names its acquire; resource/key/owner come from the recorded
            // acquire input so they cannot drift (mirrors `lease.release`). The
            // new TTL is the renew's own `ttl_seconds`, falling back to the
            // acquire's declared TTL.
            let acquire_effect_id = field("acquire_effect_id");
            let acquire_input = kernel
                .store()
                .list_effects(instance_id)?
                .into_iter()
                .find(|candidate| candidate.effect_id == acquire_effect_id)
                .map(|candidate| json_from_str(&candidate.input_json))
                .unwrap_or(Value::Null);
            let resource = acquire_input
                .get("resource")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let key = acquire_input
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let acquire_owner = acquire_input
                .get("coordination_owner")
                .and_then(Value::as_str)
                .filter(|owner| !owner.is_empty())
                .unwrap_or(&workflow_owner)
                .to_owned();
            // A renew without its own `until` duration inherits the acquire's
            // declared TTL — that is the renew contract, not a default. Both
            // missing is malformed input (well-formed lowering always records
            // the acquire's TTL) and fails typed, per slice 2.
            let ttl_seconds = match input
                .get("ttl_seconds")
                .and_then(Value::as_i64)
                .or_else(|| acquire_input.get("ttl_seconds").and_then(Value::as_i64))
            {
                Some(ttl_seconds) => ttl_seconds,
                None => return fail_coordination_effect(
                    kernel,
                    instance_id,
                    effect,
                    "malformed `lease.renew` input: no `ttl_seconds` on the renew or its acquire",
                ),
            };
            // The pre-partitioning DEFAULT-owner retry is dropped alongside
            // release's shared-owner fallback (slice 2): a renew only ever
            // extends its own acquire's owner-scoped lease.
            let expires_at = kernel.store_mut().renew_lease_for_owner(
                &acquire_owner,
                &resource,
                &key,
                ttl_seconds,
                instance_id,
            )?;
            match expires_at {
                Some(expires_at) => json!({
                    "variant": "Renewed",
                    "resource": resource,
                    "key": key,
                    "expires_at": expires_at,
                }),
                None => json!({
                    "variant": "NotHeld",
                    "resource": resource,
                    "key": key,
                }),
            }
        }
        "ledger.append" => {
            let ledger = field("ledger");
            let partition = field("partition");
            let entry = input.get("entry").cloned().unwrap_or(Value::Null);
            let retain_seconds = require_i64!(input, "retain_seconds");
            let seq = kernel.store_mut().append_for_owner_idempotent(
                &owner,
                &ledger,
                &partition,
                &entry.to_string(),
                instance_id,
                retain_seconds,
                &effect.effect_id,
            )?;
            json!({
                "variant": "Appended",
                "ledger": ledger,
                "partition": partition,
                "seq": seq,
            })
        }
        "counter.consume" => {
            let counter = field("counter");
            let key = field("key");
            let amount = require_i64!(input, "amount");
            let cap = require_i64!(input, "cap");
            // The period comes from the INJECTED `now` in the counter's
            // declared timezone (pre-slice-3 inputs carry no timezone: UTC),
            // and is RECORDED on the outcome below — replay re-reads the
            // resolved period instead of re-deriving one from a later `now`.
            let timezone = {
                let declared = field("timezone");
                if declared.is_empty() {
                    "UTC".to_owned()
                } else {
                    declared
                }
            };
            let Some(period) = counter_period(&field("reset"), &timezone, now) else {
                return fail_coordination_effect(
                    kernel,
                    instance_id,
                    effect,
                    &format!(
                        "malformed `counter.consume` input: `{timezone}` is not an IANA timezone (or the pass instant `{now}` does not parse)"
                    ),
                );
            };
            let outcome = kernel.store_mut().consume_for_owner_idempotent(
                &owner,
                &counter,
                &key,
                amount,
                cap,
                &period,
                &effect.effect_id,
            )?;
            match outcome {
                ConsumeOutcome::Ok { remaining } => json!({
                    "variant": "Ok",
                    "counter": counter,
                    "key": key,
                    "remaining": remaining,
                    "period": period,
                }),
                ConsumeOutcome::Over { remaining } => json!({
                    "variant": "Over",
                    "counter": counter,
                    "key": key,
                    "remaining": remaining,
                    "period": period,
                }),
            }
        }
        other => {
            return Err(StoreError::Conflict(format!(
                "unknown coordination effect kind `{other}`"
            )))
        }
    };

    let run_id = idempotency_key(&[instance_id, &effect.effect_id, "coord-run"]);
    let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "coord-lease"]);
    kernel.start_run(RunStart {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "coordination",
        worker_id: "whip-coordination",
        lease_id: &lease_id,
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: &json!({"kind": effect.kind, "owner": owner}).to_string(),
    })?;
    let terminal = kernel.complete_run(EffectCompletion {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "coordination",
        worker_id: "whip-coordination",
        status: "completed",
        exit_code: Some(0),
        summary: Some(&format!(
            "{} -> {}",
            effect.kind,
            value.get("variant").and_then(Value::as_str).unwrap_or("?")
        )),
        metadata_json: &value.to_string(),
        idempotency_key: Some(&idempotency_key(&[
            instance_id,
            &effect.effect_id,
            "terminal",
        ])),
    })?;
    let fact = json!({
        "effect_id": effect.effect_id,
        "run_id": run_id,
        "status": "completed",
        "value": value,
    });
    kernel.derive_fact(
        instance_id,
        &format!("{}.completed", effect.kind),
        &effect.effect_id,
        &fact.to_string(),
        Some(&terminal.event_id),
        Some(&idempotency_key(&[
            instance_id,
            &effect.effect_id,
            "coord-fact",
        ])),
    )?;
    Ok(terminal)
}

/// Host-agnostic core (DR-0033 chunk 3): claim/release/finish a work item + record
/// the terminal over a held `RuntimeKernel<S>`. The queue is the DO's own store on
/// that host, so `S: RuntimeStore + WorkItems` unifies both surfaces.
/// Resolve an absolute claim/renew deadline from the INJECTED `now` and a TTL in
/// seconds, formatted as SQLite's `datetime('now')` shape (`YYYY-MM-DD HH:MM:SS`)
/// so it compares lexically against the store's own clock. `None` ttl (or an
/// unparseable `now`) means no deadline — the untimed backstop lease.
fn tracker_expires_from_now(now: &str, ttl_seconds: Option<i64>) -> Option<String> {
    let ttl_seconds = ttl_seconds?;
    let instant = crate::time_pass::parse_clock_instant(now)?;
    Some(
        (instant + chrono::Duration::seconds(ttl_seconds))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
    )
}

pub fn run_queue_effect_generic<S: RuntimeStore + WorkItems>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    effect: &ClaimableEffect,
    now: &str,
    _config: &EffectConfig,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    use whipplescript_store::items::{ClaimOutcome, RenewOutcome};
    let input = json_from_str(&effect.input_json);
    let run_id = idempotency_key(&[instance_id, &effect.effect_id, "queue-run"]);
    let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "queue-lease"]);
    kernel.start_run(RunStart {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "queue",
        worker_id: "whip-queue",
        lease_id: &lease_id,
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: &effect.input_json,
    })?;

    let outcome: Result<Value, String> = match effect.kind.as_str() {
        "tracker.file" => {
            let queue = effect.target.clone().unwrap_or_default();
            let item = input.get("item").cloned().unwrap_or_else(|| json!({}));
            let title = item
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let body = item.get("body").and_then(Value::as_str).unwrap_or_default();
            let labels = item
                .get("labels")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let metadata = item.get("metadata").cloned().unwrap_or_else(|| json!({}));
            let filed_by = format!("workflow:{instance_id}");
            kernel
                .store_mut()
                .file_item(&queue, title, body, &labels, &metadata, Some(&filed_by))
                .map(|filed| {
                    json!({
                        "queue": filed.queue,
                        "id": filed.id,
                        "title": filed.title,
                    })
                })
                .map_err(|error| format!("file failed: {error:?}"))
        }
        "tracker.claim" => {
            let id = input.get("id").and_then(Value::as_str).unwrap_or_default();
            // Claim TTL (T3): `expires_at = now + ttl` from the injected clock,
            // or `None` (untimed backstop lease) when no `ttl` clause was given.
            let expires =
                tracker_expires_from_now(now, input.get("ttl_seconds").and_then(Value::as_i64));
            match kernel
                .store_mut()
                .claim_item(id, instance_id, expires.as_deref())
            {
                Ok(ClaimOutcome::Claimed) => {
                    Ok(json!({"id": id, "claimed_by": instance_id, "expires_at": expires}))
                }
                Ok(ClaimOutcome::AlreadyClaimed { holder }) => {
                    Err(format!("already claimed by `{holder}`"))
                }
                Ok(ClaimOutcome::NotFound) => Err(format!("item `{id}` not found")),
                Err(error) => Err(format!("claim failed: {error:?}")),
            }
        }
        "tracker.renew" => {
            // Holder heartbeat (T3): re-affirm the holder's active claim without
            // moving its deadline (`expires = None`). `not_held`/`not_monotonic`
            // are typed failures; the store enforces holder-only + monotonicity.
            let id = input.get("id").and_then(Value::as_str).unwrap_or_default();
            match kernel.store_mut().renew_claim(id, instance_id, None) {
                Ok(RenewOutcome::Renewed { expires_at }) => {
                    Ok(json!({"id": id, "renewed": true, "expires_at": expires_at}))
                }
                Ok(RenewOutcome::NotHeld) => Err(format!(
                    "not held: no active claim on `{id}` by this holder"
                )),
                Ok(RenewOutcome::NotMonotonic) => {
                    Err(format!("renew of `{id}` would move the deadline backward"))
                }
                Err(error) => Err(format!("renew failed: {error:?}")),
            }
        }
        "tracker.release" => {
            let id = input.get("id").and_then(Value::as_str).unwrap_or_default();
            match kernel.store_mut().release_item(id) {
                Ok(true) => Ok(json!({"id": id, "status": "open"})),
                Ok(false) => Err(format!("item `{id}` was not in progress")),
                Err(error) => Err(format!("release failed: {error:?}")),
            }
        }
        "tracker.finish" => {
            let id = input.get("id").and_then(Value::as_str).unwrap_or_default();
            let summary = input
                .pointer("/payload/summary")
                .and_then(Value::as_str)
                .map(str::to_owned);
            match kernel.store_mut().finish_item(id, summary.as_deref()) {
                Ok(true) => Ok(json!({"id": id, "status": "done", "summary": summary})),
                Ok(false) => Err(format!("item `{id}` cannot finish from its current status")),
                Err(error) => Err(format!("finish failed: {error:?}")),
            }
        }
        other => Err(format!("unknown queue effect kind `{other}`")),
    };

    match outcome {
        Ok(value) => {
            let terminal = kernel.complete_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "queue",
                worker_id: "whip-queue",
                status: "completed",
                exit_code: Some(0),
                summary: Some("queue operation completed"),
                metadata_json: &value.to_string(),
                idempotency_key: Some(&idempotency_key(&[
                    instance_id,
                    &effect.effect_id,
                    "terminal",
                ])),
            })?;
            let fact_value = json!({
                "effect_id": effect.effect_id,
                "run_id": run_id,
                "status": "completed",
                "value": value,
            })
            .to_string();
            kernel.derive_fact(
                instance_id,
                &format!("{}.completed", effect.kind),
                &effect.effect_id,
                &fact_value,
                Some(&terminal.event_id),
                Some(&idempotency_key(&[
                    instance_id,
                    &effect.effect_id,
                    "queue-fact",
                ])),
            )?;
            Ok(terminal)
        }
        Err(reason) => {
            let terminal = kernel.fail_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: "queue",
                worker_id: "whip-queue",
                status: "failed",
                exit_code: Some(1),
                summary: Some(&reason),
                metadata_json: &json!({"failure": {"message": reason}}).to_string(),
                idempotency_key: Some(&idempotency_key(&[
                    instance_id,
                    &effect.effect_id,
                    "terminal",
                ])),
            })?;
            let fact_value = json!({
                "effect_id": effect.effect_id,
                "run_id": run_id,
                "status": "failed",
                "value": effect_failure_base(&effect.kind, &reason, &reason, &effect.effect_id, &run_id),
                "error": {"message": reason},
            })
            .to_string();
            kernel.derive_fact(
                instance_id,
                &format!("{}.failed", effect.kind),
                &effect.effect_id,
                &fact_value,
                Some(&terminal.event_id),
                Some(&idempotency_key(&[
                    instance_id,
                    &effect.effect_id,
                    "queue-fact",
                ])),
            )?;
            Ok(terminal)
        }
    }
}

/// The `EffectError` base object (DR-0032) every effect `.failed` fact carries
/// under its `value` key, so a downstream `after <effect> fails as f` binds a
/// uniform `f` with `{reason, summary, effect_id, run_id, kind}`. Per-kind extras
/// (exit_code, stderr, …) stay elsewhere on the fact and are not read by `f` until a
/// variant exposes them. Mirrors the kernel-side `effect_failure_base`.
pub fn effect_failure_base(
    kind: &str,
    reason: &str,
    summary: &str,
    effect_id: &str,
    run_id: &str,
) -> Value {
    json!({
        "reason": reason,
        "summary": summary,
        "effect_id": effect_id,
        "run_id": run_id,
        "kind": kind,
    })
}

// -- notify + delivery governance (batch lift, DR-0033 chunk 5b) --------------

/// Host projection of the "may this internal-workflow delivery proceed?" check.
/// The native host answers from its signed governance envelope (env); the DO from
/// its bindings/secrets. Projecting it (like `EffectConfig`) keeps the notify core
/// host-neutral instead of reaching into the CLI's `ifc` governance module.
pub trait DeliveryGovernance {
    /// Whether any of `resources` names an internal workflow (delivery-forbidden
    /// across package boundaries). `Err` is a rejected/tampered governance policy.
    fn any_internal_workflow(&self, resources: &[String]) -> Result<bool, String>;
}

pub fn package_from_workflow_principal(principal: &str) -> Option<String> {
    principal
        .trim()
        .strip_prefix("workflow:")
        .and_then(|identity| identity.split_once('/').map(|(package, _)| package))
        .filter(|package| !package.trim().is_empty())
        .map(str::to_owned)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRuntimeIdentity {
    pub package: String,
    pub workflow: String,
}

pub fn workflow_identity_for_instance<S: RuntimeStore>(
    store: &S,
    instance_id: &str,
) -> Result<WorkflowRuntimeIdentity, StoreError> {
    let instance = store
        .get_instance(instance_id)?
        .ok_or_else(|| StoreError::Conflict(format!("instance `{instance_id}` not found")))?;
    let version = store
        .get_program_version(&instance.version_id)?
        .ok_or_else(|| {
            StoreError::Conflict(format!(
                "program version `{}` for instance `{instance_id}` not found",
                instance.version_id
            ))
        })?;
    Ok(WorkflowRuntimeIdentity {
        package: package_from_workflow_principal(&instance.workflow_principal)
            .unwrap_or_else(|| LOCAL_WORKFLOW_PACKAGE.to_owned()),
        workflow: version.program_name,
    })
}

pub fn invoke_resources_for_identity(identity: &WorkflowRuntimeIdentity) -> Vec<String> {
    vec![
        format!("invoke:{}/{}", identity.package, identity.workflow),
        format!("invoke:{}", identity.workflow),
    ]
}

/// Validates ingested JSON against the embedded structural shape — the
/// worker-side mirror of `validate_json_for_ir_type`, reading the contract
/// the effect carries instead of the program IR.
pub fn validate_ingest_value(value: &Value, shape: &Value, path: &str, errors: &mut Vec<String>) {
    match shape {
        Value::String(primitive) => {
            let valid = match primitive.as_str() {
                "int" => value.as_i64().is_some(),
                "float" => value.as_f64().is_some(),
                "bool" => value.is_boolean(),
                "null" => value.is_null(),
                "time" => value
                    .as_str()
                    .is_some_and(whipplescript_parser::body::is_iso8601_instant),
                "json" => true,
                // string plus media/duration primitives serialize as strings
                _ => value.is_string(),
            };
            if !valid {
                errors.push(format!("{path} must be {primitive}"));
            }
        }
        Value::Object(map) => {
            if let Some(literal) = map.get("literal") {
                if value != literal {
                    errors.push(format!("{path} must be literal {literal}"));
                }
            } else if let Some(variants) = map.get("enum").and_then(Value::as_array) {
                if !variants.iter().any(|candidate| candidate == value) {
                    errors.push(format!(
                        "{path} must be one of: {}",
                        variants
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            } else if let Some(inner) = map.get("optional") {
                if !value.is_null() {
                    validate_ingest_value(value, inner, path, errors);
                }
            } else if let Some(inner) = map.get("array") {
                match value.as_array() {
                    Some(items) => {
                        for (index, item) in items.iter().enumerate() {
                            validate_ingest_value(item, inner, &format!("{path}[{index}]"), errors);
                        }
                    }
                    None => errors.push(format!("{path} must be an array")),
                }
            } else if let Some(inner) = map.get("map") {
                match value.as_object() {
                    Some(entries) => {
                        for (key, item) in entries {
                            validate_ingest_value(item, inner, &format!("{path}.{key}"), errors);
                        }
                    }
                    None => errors.push(format!("{path} must be an object map")),
                }
            } else if let Some(options) = map.get("union").and_then(Value::as_array) {
                let matches_any = options.iter().any(|option| {
                    let mut probe = Vec::new();
                    validate_ingest_value(value, option, path, &mut probe);
                    probe.is_empty()
                });
                if !matches_any {
                    errors.push(format!("{path} matches no arm of the declared union"));
                }
            } else if let Some(fields) = map.get("fields").and_then(Value::as_object) {
                let label = map
                    .get("class")
                    .and_then(Value::as_str)
                    .map(|class| format!(" ({class})"))
                    .unwrap_or_default();
                let Some(object) = value.as_object() else {
                    errors.push(format!("{path} must be an object{label}"));
                    return;
                };
                for key in object.keys() {
                    if !fields.contains_key(key) {
                        errors.push(format!("{path}.{key} is not declared{label}"));
                    }
                }
                for (name, field_shape) in fields {
                    let field_path = format!("{path}.{name}");
                    match object.get(name) {
                        Some(field_value) => {
                            validate_ingest_value(field_value, field_shape, &field_path, errors)
                        }
                        None if field_shape.get("optional").is_some() => {}
                        None => errors.push(format!("{field_path} is required")),
                    }
                }
            }
        }
        _ => {}
    }
}

pub fn internal_workflow_delivery_violation<S: RuntimeStore>(
    store: &S,
    sender_instance_id: &str,
    target_instance_id: &str,
    governance: &dyn DeliveryGovernance,
) -> Result<Option<String>, StoreError> {
    let sender = workflow_identity_for_instance(store, sender_instance_id)?;
    let target = workflow_identity_for_instance(store, target_instance_id)?;
    if sender.package == target.package {
        return Ok(None);
    }
    let resources = invoke_resources_for_identity(&target);
    match governance.any_internal_workflow(&resources) {
        Ok(true) => Ok(Some(format!(
            "target workflow `{}/{}` is internal and cannot be notified from workflow package `{}`",
            target.package, target.workflow, sender.package
        ))),
        Ok(false) => Ok(None),
        Err(message) => Ok(Some(format!(
            "governance envelope rejected before internal workflow delivery check: {message}"
        ))),
    }
}

/// Host-agnostic core (DR-0033 chunk 3): validate + inject a durable event into a
/// peer instance over a held `RuntimeKernel<S>` (runtime-store-only).
pub fn run_notify_effect_generic<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    effect: &ClaimableEffect,
    governance: &dyn DeliveryGovernance,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    let input = json_from_str(&effect.input_json);
    let target = input
        .get("target_instance")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let event_name = input
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let payload = input.get("payload").cloned().unwrap_or(Value::Null);
    let shape = input.get("shape").cloned().unwrap_or(Value::Null);

    let run_id = idempotency_key(&[instance_id, &effect.effect_id, "notify-run"]);
    let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "notify-lease"]);
    kernel.start_run(RunStart {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "notify",
        worker_id: "whip-notify",
        lease_id: &lease_id,
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: &json!({"target": target, "event": event_name}).to_string(),
    })?;

    let mut errors = Vec::new();
    validate_ingest_value(&payload, &shape, "$", &mut errors);
    let target_exists = kernel.store().get_instance(&target)?.is_some();
    if !target_exists {
        errors.push(format!("target instance `{target}` not found"));
    } else if let Some(reason) =
        internal_workflow_delivery_violation(kernel.store(), instance_id, &target, governance)?
    {
        errors.push(reason);
    }
    if !errors.is_empty() {
        let reason = format!("notify of `{event_name}` rejected: {}", errors.join("; "));
        let terminal = kernel.fail_run(EffectCompletion {
            instance_id,
            effect_id: &effect.effect_id,
            run_id: &run_id,
            provider: "notify",
            worker_id: "whip-notify",
            status: "failed",
            exit_code: None,
            summary: Some(&reason),
            metadata_json: &json!({"failure": {"message": reason}}).to_string(),
            idempotency_key: Some(&idempotency_key(&[
                instance_id,
                &effect.effect_id,
                "terminal",
            ])),
        })?;
        // DR-0032: derive the `.failed` fact so `after <notify> fails as f` has
        // something to bind (previously this path emitted no fact at all). `value`
        // is the EffectError base.
        kernel.derive_fact(
            instance_id,
            "signal.emit.failed",
            &effect.effect_id,
            &json!({
                "effect_id": effect.effect_id,
                "run_id": run_id,
                "status": "failed",
                "value": effect_failure_base("signal.emit", &reason, &reason, &effect.effect_id, &run_id),
                "error": {"message": reason},
            })
            .to_string(),
            Some(&terminal.event_id),
            Some(&idempotency_key(&[
                instance_id,
                &effect.effect_id,
                "notify-fact",
            ])),
        )?;
        return Ok(terminal);
    }

    let payload_json = payload.to_string();
    let received = kernel.ingest_external_event(
        &target,
        &event_name,
        &payload_json,
        Some(&idempotency_key(&[&target, "notify", &effect.effect_id])),
    )?;
    kernel.derive_fact(
        &target,
        &event_name,
        &received.event_id,
        &payload_json,
        Some(&received.event_id),
        Some(&idempotency_key(&[
            &target,
            "notify-fact",
            &effect.effect_id,
        ])),
    )?;
    let terminal = kernel.complete_run(EffectCompletion {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: "notify",
        worker_id: "whip-notify",
        status: "completed",
        exit_code: Some(0),
        summary: Some(&format!("notified {target} with `{event_name}`")),
        metadata_json: &json!({"target": target, "event": event_name}).to_string(),
        idempotency_key: Some(&idempotency_key(&[
            instance_id,
            &effect.effect_id,
            "terminal",
        ])),
    })?;
    kernel.derive_fact(
        instance_id,
        "signal.emit.completed",
        &effect.effect_id,
        &json!({
            "effect_id": effect.effect_id,
            "run_id": run_id,
            "status": "completed",
            "value": {"target": target, "event": event_name},
        })
        .to_string(),
        Some(&terminal.event_id),
        Some(&idempotency_key(&[
            instance_id,
            &effect.effect_id,
            "notify-self-fact",
        ])),
    )?;
    Ok(terminal)
}

// -- capability core + contract projection (batch lift, DR-0033 chunk 5b) -----

/// Host projection of capability-output validation. Native validates the fixture
/// output against the workflow's package-lock capability contract; the DO validates
/// against the contract carried in its program metadata. Projecting it (like
/// `DeliveryGovernance`) keeps the capability core out of the CLI package-lock types.
pub trait CapabilityContract {
    /// `Some(reason)` if `value` violates the declared capability contract for
    /// `effect.target`, else `None` (no contract / satisfied).
    fn validate_output(&self, effect: &ClaimableEffect, value: &Value) -> Option<String>;
}

/// Outcome of a capability host projection: either a produced success value (which
/// still flows through `CapabilityContract::validate_output`) or a provider-side
/// failure. Mirrors the two arms the fixture drives today.
pub enum CapabilityOutcome {
    /// Provider produced a success value (fed to the contract before completion).
    Produced(Value),
    /// Provider failed before producing a value.
    Failed { error_kind: String, message: String },
}

/// Host projection of the capability provider (mirrors `CapabilityContract`). The
/// capability core no longer fabricates the fixture output/failure itself; it asks
/// the provider what to produce, then validates + settles the terminal identically.
///
/// Provider *selection* (a `capability_bound` row carrying provider name + config)
/// is intentionally NOT modeled here: with only the fixture provider it would be
/// decorative. It lands with the first real provider (the `std.memory` tail).
pub trait CapabilityProvider {
    /// Produce the capability outcome for `effect` under `config`.
    fn produce(&self, effect: &ClaimableEffect, config: &EffectConfig) -> CapabilityOutcome;

    /// The provider label recorded in completion summaries ("<label>
    /// capability completed"). Defaults to `fixture` — the historical
    /// hardcode — so existing fixture-driven records stay byte-identical;
    /// real providers override so the record names who actually ran.
    fn label(&self) -> &'static str {
        "fixture"
    }
}

/// The fixture capability provider: the behavior the capability core hardcoded
/// before the seam existed. Failure when `config.outcome_failed`, else the fixed
/// fixture context value. Shared by the native worker and the durable object so
/// neither redefines the fixture values.
pub struct FixtureCapabilityProvider;
impl CapabilityProvider for FixtureCapabilityProvider {
    fn produce(&self, effect: &ClaimableEffect, config: &EffectConfig) -> CapabilityOutcome {
        if config.outcome_failed {
            CapabilityOutcome::Failed {
                error_kind: "fixture_failure".to_owned(),
                message: "fixture capability failure".to_owned(),
            }
        } else {
            CapabilityOutcome::Produced(json!({
                "summary": "Fixture capability context",
                "target": effect.target,
            }))
        }
    }
}

/// One recall item's JSON (spec/std-memory.md): the pre-seam record shape
/// (`message_id`/`pool`/`source`/`note`, the message id recomputed
/// deterministically from the write-effect id) plus the MemoryContext
/// enrichment (memory_id, text, created_at, provenance). Shared so native and
/// the DO render an identical item.
pub fn memory_item_json(row: &whipplescript_store::memory::MemoryEntryRow) -> Value {
    let mut item = serde_json::Map::new();
    if let Some(effect_id) = &row.source_effect_id {
        item.insert(
            "message_id".to_owned(),
            Value::String(idempotency_key(&[effect_id, "memory-message"])),
        );
    }
    item.insert("memory_id".to_owned(), json!(row.memory_id));
    item.insert("pool".to_owned(), Value::String(row.pool.clone()));
    item.insert("text".to_owned(), Value::String(row.text.clone()));
    item.insert(
        "source".to_owned(),
        row.source.clone().map(Value::String).unwrap_or(Value::Null),
    );
    if let Some(note) = &row.note {
        item.insert("note".to_owned(), Value::String(note.clone()));
    }
    item.insert(
        "created_at".to_owned(),
        Value::String(row.created_at.clone()),
    );
    item.insert(
        "provenance".to_owned(),
        json!({
            "source_instance_id": row.source_instance_id,
            "source_effect_id": row.source_effect_id,
            "source_run_id": row.source_run_id,
            "author_actor": row.author_actor,
        }),
    );
    Value::Object(item)
}

/// The `std.memory` capability provider's outcome, host-agnostic over any
/// [`MemoryStore`](whipplescript_store::memory::MemoryStore) backend: native's
/// file-backed `SqliteMemoryStore` and the DO's `DoMemoryStore` both call this,
/// so recall/learn/curate behave identically on either host (the only
/// difference is FTS5 vs LIKE lexical match inside the store). `memory.write`
/// stores one entry (effect-plane determinism: empty `created_at`, provenance
/// from the effect id); `memory.query` returns a MemoryContext; `memory.curate`
/// dedupes the pool by content identity.
pub fn run_memory_capability(
    store: &mut dyn whipplescript_store::memory::MemoryStore,
    effect: &ClaimableEffect,
) -> CapabilityOutcome {
    use whipplescript_store::memory::{CurateStrategy, NewMemoryEntry};
    let input = json_from_str(&effect.input_json);
    let pool = input
        .get("pool")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    // Deterministic message id: derived from the effect id, never wall-clock.
    let message_id = idempotency_key(&[&effect.effect_id, "memory-message"]);
    match effect.target.as_deref() {
        Some("memory.write") => {
            // `source` is the resolved `from <source>` value; `note` the
            // optional `{ note <expr> }` field; the matchable body carries
            // BOTH (a recall may name the source or words from the note).
            let source = input.get("source").and_then(Value::as_str);
            let note = input.get("note").and_then(Value::as_str);
            let text = match (source, note) {
                (Some(source), Some(note)) => format!("{source}\n{note}"),
                (Some(source), None) => source.to_owned(),
                (None, Some(note)) => note.to_owned(),
                (None, None) => input
                    .get("source")
                    .cloned()
                    .unwrap_or(Value::Null)
                    .to_string(),
            };
            let entry = NewMemoryEntry {
                pool: &pool,
                text: &text,
                created_at: "",
                source_instance_id: None,
                source_effect_id: Some(&effect.effect_id),
                source_run_id: None,
                author_actor: None,
                source,
                note,
            };
            if let Err(error) = store.write(&entry) {
                return CapabilityOutcome::Failed {
                    error_kind: "memory".to_owned(),
                    message: format!("memory write failed: {error:?}"),
                };
            }
            CapabilityOutcome::Produced(json!({
                "pool": pool,
                "message_id": message_id,
                "stored": true,
            }))
        }
        Some("memory.query") => {
            let query_text = input
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let limit = input
                .get("context_limit")
                .and_then(Value::as_u64)
                .map(|limit| limit as usize);
            match store.query(&pool, query_text, limit) {
                Ok(rows) => {
                    let items: Vec<Value> = rows.iter().map(memory_item_json).collect();
                    CapabilityOutcome::Produced(json!({
                        "pool": pool,
                        "count": items.len(),
                        "items": items,
                    }))
                }
                Err(error) => CapabilityOutcome::Failed {
                    error_kind: "memory".to_owned(),
                    message: format!("memory query failed: {error:?}"),
                },
            }
        }
        Some("memory.curate") => match store.curate(&pool, CurateStrategy::DedupeBySourceNote) {
            Ok(report) => CapabilityOutcome::Produced(json!({
                "pool": pool,
                "removed": report.removed,
                "kept": report.kept,
            })),
            Err(error) => CapabilityOutcome::Failed {
                error_kind: "memory".to_owned(),
                message: format!("memory curate failed: {error:?}"),
            },
        },
        other => CapabilityOutcome::Failed {
            error_kind: "memory".to_owned(),
            message: format!(
                "memory-provider does not handle capability `{}`",
                other.unwrap_or_default()
            ),
        },
    }
}

/// Host-agnostic core (DR-0033 chunk 3): run the capability call + its terminal
/// over a held `RuntimeKernel<S>` (only kernel methods, so `S: RuntimeStore`).
pub fn run_capability_effect_generic<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    effect: &ClaimableEffect,
    config: &EffectConfig,
    contract: &dyn CapabilityContract,
    provider: &dyn CapabilityProvider,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    let input = json_from_str(&effect.input_json);
    let completed_summary = format!("{} capability completed", provider.label());
    let validation_summary = format!("{} capability output validation failed", provider.label());
    let run_id = idempotency_key(&[instance_id, &effect.effect_id, "capability-run"]);
    let lease_id = idempotency_key(&[instance_id, &effect.effect_id, "capability-lease"]);
    kernel.start_run(RunStart {
        instance_id,
        effect_id: &effect.effect_id,
        run_id: &run_id,
        provider: &config.provider,
        worker_id: "whip-worker",
        lease_id: &lease_id,
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: &json!({
            "target": effect.target,
            "input": input,
        })
        .to_string(),
    })?;

    let terminal = match provider.produce(effect, config) {
        CapabilityOutcome::Failed {
            error_kind,
            message,
        } => {
            let metadata_json = json!({
                "failure": {
                    "phase": "provider.capability.failed",
                    "error_kind": &error_kind,
                    "message": &message
                },
                "target": effect.target,
                "input": input,
            })
            .to_string();
            let terminal = kernel.fail_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: &config.provider,
                worker_id: "whip-worker",
                status: "failed",
                exit_code: Some(1),
                summary: Some(message.as_str()),
                metadata_json: &metadata_json,
                idempotency_key: Some(&idempotency_key(&[
                    instance_id,
                    &effect.effect_id,
                    "terminal",
                ])),
            })?;
            let value_json = json!({
                "effect_id": effect.effect_id,
                "run_id": run_id,
                "target": effect.target,
                "status": "failed",
                "value": effect_failure_base("capability.call", &message, &message, &effect.effect_id, &run_id),
                "error": {
                    "kind": &error_kind,
                    "message": &message
                },
                "summary": &message
            })
            .to_string();
            kernel.derive_fact(
                instance_id,
                "capability.call.failed",
                &effect.effect_id,
                &value_json,
                Some(&terminal.event_id),
                Some(&idempotency_key(&[
                    instance_id,
                    &effect.effect_id,
                    "capability.call.failed",
                ])),
            )?;
            terminal
        }
        CapabilityOutcome::Produced(value) => {
            if let Some(error) = contract.validate_output(effect, &value) {
                let metadata_json = json!({
                    "failure": {
                        "phase": "provider.capability.output_validation",
                        "error_kind": "provider_output_validation",
                        "message": error,
                    },
                    "target": effect.target,
                    "input": input,
                    "value": value,
                })
                .to_string();
                let terminal = kernel.fail_run(EffectCompletion {
                    instance_id,
                    effect_id: &effect.effect_id,
                    run_id: &run_id,
                    provider: &config.provider,
                    worker_id: "whip-worker",
                    status: "failed",
                    exit_code: Some(1),
                    summary: Some(&validation_summary),
                    metadata_json: &metadata_json,
                    idempotency_key: Some(&idempotency_key(&[
                        instance_id,
                        &effect.effect_id,
                        "terminal",
                    ])),
                })?;
                let value_json = json!({
                "effect_id": effect.effect_id,
                "run_id": run_id,
                "target": effect.target,
                "status": "failed",
                "value": effect_failure_base("capability.call", &error, &validation_summary, &effect.effect_id, &run_id),
                "error": {
                    "kind": "provider_output_validation",
                    "message": error,
                },
                "summary": validation_summary
            })
            .to_string();
                kernel.derive_fact(
                    instance_id,
                    "capability.call.failed",
                    &effect.effect_id,
                    &value_json,
                    Some(&terminal.event_id),
                    Some(&idempotency_key(&[
                        instance_id,
                        &effect.effect_id,
                        "capability.call.failed",
                    ])),
                )?;
                return Ok(terminal);
            }
            let metadata_json = json!({
                "target": effect.target,
                "input": input,
                "value": value,
            })
            .to_string();
            let terminal = kernel.complete_run(EffectCompletion {
                instance_id,
                effect_id: &effect.effect_id,
                run_id: &run_id,
                provider: &config.provider,
                worker_id: "whip-worker",
                status: "completed",
                exit_code: Some(0),
                summary: Some(&completed_summary),
                metadata_json: &metadata_json,
                idempotency_key: Some(&idempotency_key(&[
                    instance_id,
                    &effect.effect_id,
                    "terminal",
                ])),
            })?;
            let value_json = json!({
                "effect_id": effect.effect_id,
                "run_id": run_id,
                "target": effect.target,
                "status": "completed",
                "value": value,
                "error": null,
                "summary": "fixture capability completed"
            })
            .to_string();
            kernel.derive_fact(
                instance_id,
                "capability.call.succeeded",
                &effect.effect_id,
                &value_json,
                Some(&terminal.event_id),
                Some(&idempotency_key(&[
                    instance_id,
                    &effect.effect_id,
                    "capability.call.succeeded",
                ])),
            )?;
            terminal
        }
    };
    Ok(terminal)
}

#[cfg(test)]
mod file_policy_tests {
    use super::file_path_policy_error;

    /// S4: stores are read-only by default — an empty write policy DENIES the
    /// write (fail closed), while an empty read policy allows any path inside
    /// the root. Declared write globs permit and bound writes.
    #[test]
    fn write_is_denied_by_default_and_read_is_not() {
        assert!(file_path_policy_error("out.txt", "docs", &[], "write")
            .expect("write denied")
            .contains("permits no writes"));
        assert_eq!(file_path_policy_error("in.txt", "docs", &[], "read"), None);
        assert_eq!(
            file_path_policy_error("out.txt", "docs", &["**".to_owned()], "write"),
            None
        );
        assert!(
            file_path_policy_error("other/x.txt", "docs", &["out/**".to_owned()], "write")
                .expect("out-of-glob write denied")
                .contains("allow write")
        );
    }
}
