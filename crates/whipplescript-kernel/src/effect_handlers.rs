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
/// The write-mode policy shared by `write` and `export` (spec/files.md): no
/// silent overwrite. `create` refuses a path that is already there and `replace`
/// refuses one that is not, so an author who meant to add a file cannot quietly
/// clobber one — and an unknown mode is refused rather than defaulted. `exists`
/// is the store's answer for the resolved path.
pub fn write_mode_policy(mode: &str, path: &str, exists: bool) -> Result<(), String> {
    match mode {
        "create" if exists => Err(format!(
            "write mode `create` requires `{path}` to not already exist"
        )),
        "replace" if !exists => Err(format!(
            "write mode `replace` requires `{path}` to already exist"
        )),
        "create" | "replace" | "upsert" | "append" => Ok(()),
        other => Err(format!("unknown write mode `{other}`")),
    }
}

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

/// The failure terminal + `.failed` fact every std.files effect settles on; the
/// four handlers differ only in the effect kind (`file.read`, `file.write`, …).
/// One copy is what keeps their failure paths from drifting apart.
#[allow(clippy::too_many_arguments)]
fn settle_failed_file_effect<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    effect: &ClaimableEffect,
    kind: &str,
    reason: &str,
    run_id: &str,
    terminal_key: &str,
    fact_key: &str,
) -> Result<StoredEvent, StoreError> {
    let terminal = kernel.fail_run(EffectCompletion {
        instance_id,
        effect_id: &effect.effect_id,
        run_id,
        provider: "files",
        worker_id: "whip-files",
        status: "failed",
        exit_code: None,
        summary: Some(reason),
        metadata_json: &json!({ "failure": { "message": reason } }).to_string(),
        idempotency_key: Some(terminal_key),
    })?;
    kernel.derive_fact(
        instance_id,
        &format!("{kind}.failed"),
        &effect.effect_id,
        &json!({
            "effect_id": effect.effect_id,
            "run_id": run_id,
            "status": "failed",
            "value": effect_failure_base(kind, reason, reason, &effect.effect_id, run_id),
            "error": { "message": reason },
        })
        .to_string(),
        Some(&terminal.event_id),
        Some(fact_key),
    )?;
    Ok(terminal)
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
    // (spec/files.md), checked before any disk access.
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
        Err(reason) => settle_failed_file_effect(
            kernel,
            instance_id,
            effect,
            "file.read",
            &reason,
            &run_id,
            &terminal_key,
            &fact_key,
        ),
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
        write_mode_policy(&mode, path, exists).and_then(|()| {
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
        Err(reason) => settle_failed_file_effect(
            kernel,
            instance_id,
            effect,
            "file.write",
            &reason,
            &run_id,
            &terminal_key,
            &fact_key,
        ),
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
        Err(reason) => settle_failed_file_effect(
            kernel,
            instance_id,
            effect,
            "file.import",
            &reason,
            &run_id,
            &terminal_key,
            &fact_key,
        ),
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
        write_mode_policy(&mode, path, exists)?;
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
        Err(reason) => settle_failed_file_effect(
            kernel,
            instance_id,
            effect,
            "file.export",
            &reason,
            &run_id,
            &terminal_key,
            &fact_key,
        ),
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
    use whipplescript_store::items::{ClaimOutcome, FinishOutcome, ReleaseOutcome, RenewOutcome};
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
            // `None`: the in-program `release` effect is the program acting on
            // its own tracker, not one agent reaching across another's claim.
            match kernel.store_mut().release_item(id, None) {
                Ok(ReleaseOutcome::Released) => Ok(json!({"id": id, "status": "open"})),
                Ok(ReleaseOutcome::NotHeld) => Err(format!("item `{id}` was not in progress")),
                Ok(ReleaseOutcome::HeldByOther { holder }) => {
                    Err(format!("item `{id}` is held by {holder}"))
                }
                Err(error) => Err(format!("release failed: {error:?}")),
            }
        }
        "tracker.finish" => {
            let id = input.get("id").and_then(Value::as_str).unwrap_or_default();
            let summary = input
                .pointer("/payload/summary")
                .and_then(Value::as_str)
                .map(str::to_owned);
            match kernel.store_mut().finish_item(id, summary.as_deref(), None) {
                Ok(FinishOutcome::Finished) => {
                    Ok(json!({"id": id, "status": "done", "summary": summary}))
                }
                Ok(FinishOutcome::NotOpen) => {
                    Err(format!("item `{id}` cannot finish from its current status"))
                }
                Ok(FinishOutcome::HeldByOther { holder }) => {
                    Err(format!("item `{id}` is held by {holder}"))
                }
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
            // DR-0053 §11: an `obtain credential` is a governance escalation,
            // and the tracker item alone is only half of it. The fact is what
            // makes the escalation RULE-MATCHABLE, so a program can react to
            // its own missing authority — react, not wait, which is the whole
            // difference from the blocking shape DR-0050 removed.
            //
            // Derived after the item is filed, never before: a fact claiming an
            // escalation was raised when the filing failed would be the one
            // wrong thing this could record.
            if let Some(credential) = input.get("credential").and_then(Value::as_str) {
                let requested = json!({
                    "credential": credential,
                    "queue": input.get("queue").cloned().unwrap_or(Value::Null),
                    "item": value.get("id").cloned().unwrap_or(Value::Null),
                    "effect_id": effect.effect_id,
                    "run_id": run_id,
                })
                .to_string();
                kernel.derive_fact(
                    instance_id,
                    "credential.requested",
                    credential,
                    &requested,
                    Some(&terminal.event_id),
                    Some(&idempotency_key(&[
                        instance_id,
                        &effect.effect_id,
                        "credential-requested-fact",
                    ])),
                )?;
            }
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
/// variant exposes them.
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

/// The `std.custody` capability provider (DR-0074 §12), host-agnostic over any
/// [`CustodyTransport`] — native's unix socket and the in-process transport both
/// call this, so `seal` behaves identically on either.
///
/// Only `custody.wrap` is handled. `custody.unwrap` is deliberately absent:
/// opening is DR-0074 §3's `open` region, which is Slice 2 and is governed by a
/// type-narrowed grant. A provider that could unwrap before the region existed
/// would be the over-grant this whole record removes.
///
/// The wrapping key never reaches whip. What comes back is the envelope, and
/// only its identity and non-secret metadata cross into the effect's output —
/// the ciphertext is the payload whip stores, not something it interprets.
/// An effect input whose sealed values have been opened for the provider call
/// (DR-0074 §4, the worker arm: "inside a worker executing one run, having
/// opened a sealed effect input").
///
/// **The type is the guarantee.** §4's other arm — the interpreter — is
/// enforced by the checker, but nothing structural stops a worker writing
/// opened plaintext back into a durable record, and the obvious implementation
/// does exactly that: the natural resolution point is
/// `resolve_effect_input_after_bindings`, whose output reaches `start_run`'s
/// `metadata_json`. That is not an exotic mistake, it is the first thing anyone
/// would write.
///
/// So this carries no `Serialize`, no `Clone`, no `Display`, and a `Debug` that
/// prints nothing of the payload. The only way to the bytes is
/// [`provider_payload`](Self::provider_payload), whose name says where they are
/// allowed to go. Persisting one is a compile error rather than a review miss.
pub struct OpenedEffectInput(String);

impl OpenedEffectInput {
    /// The request body for the provider call, and nothing else. Every other
    /// consumer — the run's metadata, a diagnostic, an event payload — is a §4
    /// violation, which is why there is no other accessor.
    pub fn provider_payload(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for OpenedEffectInput {
    /// Redacted rather than absent: something eventually formats a struct that
    /// holds one, and a `{:?}` that printed opened plaintext into a log would
    /// be a §4 violation nobody had to write deliberately.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpenedEffectInput(<opened>)")
    }
}

/// The unwrap grants an effect carries, as `payload type -> credential`.
///
/// Read from the effect's own durable row: the lowering records `access_grants`
/// with the operation and its narrowed `target`, so the authorization travels
/// with the work rather than being re-derived from the program here.
fn effect_unwrap_grants(input: &Value) -> std::collections::BTreeMap<String, String> {
    let mut grants = std::collections::BTreeMap::new();
    for grant in input
        .get("access_grants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(credential) = grant
            .get("resource")
            .and_then(Value::as_str)
            .and_then(|resource| resource.strip_prefix("credential "))
        else {
            continue;
        };
        for op in grant
            .get("operations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if op.get("operation").and_then(Value::as_str) != Some("unwrap") {
                continue;
            }
            // A bare `unwrap` never reaches here — the checker refuses it — but
            // skipping rather than admitting keeps the runtime fail-closed on
            // its own terms.
            if let Some(target) = op.get("target").and_then(Value::as_str) {
                grants.insert(target.to_owned(), credential.to_owned());
            }
        }
    }
    grants
}

/// A transport that reaches no custodian.
///
/// Exists so a host with no custody transport takes the SAME code path as one
/// that has it: `open_sealed_effect_inputs` returns early when a turn carries
/// no unwrap grant, so an ordinary turn never touches this, and a granted turn
/// fails here rather than silently sending ciphertext. Refusing inside the
/// resolver rather than at the call site is what keeps the "grants present?"
/// decision in one place.
pub struct NoCustodyTransport;

impl whipplescript_custody::CustodyTransport for NoCustodyTransport {
    fn call(
        &self,
        _call: whipplescript_custody::CustodyCall,
    ) -> Result<whipplescript_custody::CustodyReply, whipplescript_custody::TransportError> {
        Err(whipplescript_custody::TransportError::Unavailable(
            "this host has no custody transport; run the turn where a custodian is \
             reachable"
                .to_owned(),
        ))
    }
}

/// Open the sealed values in an effect's input for the provider call
/// (DR-0074 §4, worker arm).
///
/// Runs AFTER the run's metadata is recorded, deliberately: the durable row
/// keeps the envelopes, and only the value handed to the provider carries
/// plaintext. That ordering is the whole design, and
/// [`OpenedEffectInput`] is what keeps it from being an ordering anyone can
/// forget.
///
/// A sealed value is recognised by its envelope shape and opened only when the
/// effect carries an `unwrap` grant naming the CREDENTIAL it was sealed under.
/// The type narrowing is the checker's — `validate_sealed_effect_inputs`
/// refuses a sealed input whose payload type no grant on that effect names — so
/// what remains here is the credential match, which is the part a runtime can
/// answer from the envelope itself.
pub fn open_sealed_effect_inputs(
    transport: &dyn whipplescript_custody::CustodyTransport,
    effect: &ClaimableEffect,
    input_json: &str,
    run_id: &str,
) -> Result<OpenedEffectInput, String> {
    use whipplescript_custody::{
        CredentialName, CustodyCall, CustodyOk, CustodyOp, Envelope, UseAttribution,
    };

    let mut input = json_from_str(input_json);
    let grants = effect_unwrap_grants(&input);
    if grants.is_empty() {
        return Ok(OpenedEffectInput(input_json.to_owned()));
    }
    let granted_credentials: std::collections::BTreeSet<&String> = grants.values().collect();

    // The envelope shape `seal` produces. Structural rather than tagged, and
    // narrowed by the credential match below: an envelope under a credential
    // this effect was not granted is left sealed rather than opened.
    fn envelope_of(value: &Value) -> Option<Envelope> {
        let object = value.as_object()?;
        for field in ["credential", "context", "nonce_b64", "ciphertext_b64"] {
            object.get(field)?.as_str()?;
        }
        serde_json::from_value(value.clone()).ok()
    }

    let mut failure: Option<String> = None;
    fn walk(
        value: &mut Value,
        granted: &std::collections::BTreeSet<&String>,
        open: &mut dyn FnMut(Envelope) -> Result<Value, String>,
        failure: &mut Option<String>,
    ) {
        if failure.is_some() {
            return;
        }
        if let Some(envelope) = envelope_of(value) {
            if granted.contains(&envelope.credential.as_str().to_owned()) {
                match open(envelope) {
                    Ok(plaintext) => *value = plaintext,
                    Err(error) => *failure = Some(error),
                }
                return;
            }
        }
        match value {
            Value::Object(map) => {
                for (_, child) in map.iter_mut() {
                    walk(child, granted, open, failure);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, granted, open, failure);
                }
            }
            _ => {}
        }
    }

    let mut open = |envelope: Envelope| -> Result<Value, String> {
        let credential = envelope.credential.clone();
        let context = envelope.context.clone();
        let call = CustodyCall::new(
            UseAttribution {
                run_id: run_id.to_owned(),
                actor: None,
                effect_key: Some(effect.effect_id.clone()),
            },
            CustodyOp::Unwrap {
                credential: CredentialName::new(credential.as_str())
                    .map_err(|error| format!("custody unwrap: {error}"))?,
                envelope,
                context,
            },
        );
        match transport
            .call(call)
            .map_err(|error| format!("custody unwrap: transport: {error}"))?
            .outcome
        {
            Err(error) => Err(format!("custody unwrap refused: {error}")),
            Ok(CustodyOk::Unwrapped { plaintext_b64, .. }) => {
                let bytes = crate::exec_http::base64_decode(&plaintext_b64)
                    .ok_or_else(|| "custody unwrap: payload is not base64".to_owned())?;
                let text = String::from_utf8(bytes)
                    .map_err(|_| "custody unwrap: payload is not UTF-8".to_owned())?;
                // `seal` wrapped the value's JSON, so the payload parses back
                // into the value the author sealed rather than a string of it.
                Ok(json_from_str(&text))
            }
            Ok(other) => Err(format!(
                "custody unwrap: custodian answered with a non-unwrap result: {other:?}"
            )),
        }
    };

    walk(&mut input, &granted_credentials, &mut open, &mut failure);
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(OpenedEffectInput(input.to_string()))
}

pub fn run_custody_capability(
    transport: &dyn whipplescript_custody::CustodyTransport,
    effect: &ClaimableEffect,
    run_id: &str,
) -> CapabilityOutcome {
    use whipplescript_custody::{
        CredentialName, CustodyCall, CustodyOk, CustodyOp, UseAttribution,
    };

    let fail = |message: String| CapabilityOutcome::Failed {
        error_kind: "custody".to_owned(),
        message,
    };

    match effect.target.as_deref() {
        Some("custody.wrap") => {
            let input = json_from_str(&effect.input_json);
            let Some(credential) = input.get("credential").and_then(Value::as_str) else {
                return fail("custody wrap: no credential named".to_owned());
            };
            let credential = match CredentialName::new(credential) {
                Ok(name) => name,
                Err(error) => return fail(format!("custody wrap: {error}")),
            };
            // The value is whip's own application data; the custodian never
            // interprets it, so it crosses as opaque bytes.
            let plaintext = input.get("value").cloned().unwrap_or(Value::Null);
            let plaintext_b64 = crate::exec_http::base64_encode(plaintext.to_string().as_bytes());
            // §13's context binding: the effect key is what an envelope is bound
            // to, so a ciphertext produced for one effect cannot be unwrapped
            // under another.
            let context = effect.effect_id.clone();
            // The label rides with the envelope (§13 carriage). Slice 2 fills
            // this from the IFC layer; until `open` exists there is nothing to
            // restore it to, so it is explicitly null rather than fabricated.
            let label = Value::Null;

            let call = CustodyCall::new(
                UseAttribution {
                    run_id: run_id.to_owned(),
                    actor: None,
                    effect_key: Some(effect.effect_id.clone()),
                },
                CustodyOp::Wrap {
                    credential,
                    plaintext_b64,
                    label,
                    context: context.clone(),
                },
            );

            match transport.call(call) {
                Err(error) => fail(format!("custody wrap: transport: {error}")),
                Ok(reply) => match reply.outcome {
                    Err(error) => fail(format!("custody wrap refused: {error}")),
                    // The WHOLE envelope, `label` included. Slice 1 emitted
                    // four of the five fields, which made the stored value
                    // un-round-trippable: `Envelope` will not deserialize
                    // without its label, so nothing could reconstruct one to
                    // unwrap. The label is DR-0053 §13's carriage — the
                    // boundary does not launder — so dropping it also dropped
                    // what `unwrap` is supposed to restore.
                    Ok(CustodyOk::Wrapped { envelope }) => CapabilityOutcome::Produced(json!({
                        "credential": envelope.credential.as_str(),
                        "context": envelope.context,
                        "label": envelope.label,
                        "nonce_b64": envelope.nonce_b64,
                        "ciphertext_b64": envelope.ciphertext_b64,
                    })),
                    Ok(other) => fail(format!(
                        "custody wrap: custodian answered with a non-wrap result: {other:?}"
                    )),
                },
            }
        }
        // DR-0074 §3 says `open`'s output is TRANSIENT — "available to its
        // `after` block, never written to the event". That cannot be built on
        // the current execution model, and the reason is checkable rather than
        // a matter of effort: `rule_lowering::effect_binding_value` resolves
        // EVERY `after` binding out of `facts.value_json`, so a durable fact is
        // the only channel an effect output has to its own `after` block.
        //
        // The two things this handler could return are both wrong. Producing
        // the plaintext writes it into that fact, which is precisely the §4
        // violation the record exists to prevent. Producing envelope identity
        // instead satisfies §4 but LIES: the checker types the binding at the
        // `into <Type>` class, so `patient.notes` would read null at run time
        // with nothing reporting it.
        //
        // So it refuses, for the same reason the hosted path refuses in Slice 1
        // — a security operation must not appear to have happened. The
        // custodian's own `unwrap` is exercised by `whipplescript-custodian`'s
        // tests; what is missing is a non-durable channel from an effect's
        // result to its `after` block, and that is a decision DR-0074 does not
        // contain rather than code nobody has written.
        Some("custody.unwrap") => fail(
            "custody unwrap: opening is compiled and checked, but not executable — an `after` \
             binding resolves from a durable fact, so an open's plaintext has no non-durable \
             channel to its region (DR-0074 §3's transient output). Refusing rather than \
             recording plaintext or binding an envelope the checker types as its payload."
                .to_owned(),
        ),
        other => fail(format!(
            "custody-provider does not handle capability `{}`",
            other.unwrap_or_default()
        )),
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
mod write_mode_policy_tests {
    use super::write_mode_policy;

    /// `write_mode_policy` is the no-silent-overwrite refusal (spec/files.md:250:
    /// "The mode is **required** — omitting it is a check error"). It is the only
    /// thing standing between an author who meant `create` and a file they
    /// silently clobbered.
    ///
    /// The `new-refusals` sweep found it unexercised: every path that reached it
    /// in the whole workspace suite fed it a mode/exists pair it accepted, so
    /// deleting either rejection changed nothing observable. These cases assert
    /// each rejection by its message, and the accept cases keep them from passing
    /// by refusing everything.
    #[test]
    fn create_refuses_a_path_that_is_already_there() {
        assert_eq!(
            write_mode_policy("create", "notes/a.txt", true),
            Err("write mode `create` requires `notes/a.txt` to not already exist".to_owned())
        );
    }

    #[test]
    fn replace_refuses_a_path_that_is_not_there() {
        assert_eq!(
            write_mode_policy("replace", "notes/a.txt", false),
            Err("write mode `replace` requires `notes/a.txt` to already exist".to_owned())
        );
    }

    #[test]
    fn an_unknown_mode_is_refused_rather_than_defaulted() {
        assert_eq!(
            write_mode_policy("clobber", "notes/a.txt", false),
            Err("unknown write mode `clobber`".to_owned())
        );
    }

    /// The accepting half. Without these a policy that refused everything would
    /// pass the three cases above.
    #[test]
    fn every_mode_is_admitted_on_the_existence_it_declares() {
        for (mode, exists) in [
            ("create", false),
            ("replace", true),
            ("upsert", false),
            ("upsert", true),
            ("append", false),
            ("append", true),
        ] {
            assert_eq!(
                write_mode_policy(mode, "notes/a.txt", exists),
                Ok(()),
                "mode `{mode}` with exists={exists}"
            );
        }
    }
}

#[cfg(test)]
mod ingest_admission_tests {
    use super::validate_ingest_value;
    use serde_json::{json, Value};

    /// `validate_ingest_value` is the effect-output admission gate: the authority
    /// that decides whether a provider's JSON becomes a durable typed fact
    /// (spec/type-system.md, "Boundary Validation"). WhippleScript cannot make an
    /// illegal state unrepresentable — the producer is a model — so this refusal
    /// is what stands in for a private constructor.
    ///
    /// A mutation sweep found that NONE of its rejections were exercised. Every
    /// path that reached it fed it valid input, so deleting any single rejection
    /// changed nothing observable in the whole workspace suite. These cases assert
    /// each rejection by message, and the accept cases keep them from passing by
    /// rejecting everything.
    fn errors_for(value: Value, shape: Value) -> Vec<String> {
        let mut errors = Vec::new();
        validate_ingest_value(&value, &shape, "$", &mut errors);
        errors
    }

    fn rejects(value: Value, shape: Value, expected: &str) {
        let errors = errors_for(value, shape);
        assert!(
            errors.iter().any(|e| e == expected),
            "expected `{expected}`, got {errors:?}"
        );
    }

    fn accepts(value: Value, shape: Value) {
        assert_eq!(errors_for(value, shape), Vec::<String>::new());
    }

    #[test]
    fn scalar_shapes_reject_the_wrong_json_type() {
        rejects(json!("7"), json!("int"), "$ must be int");
        rejects(json!("x"), json!("float"), "$ must be float");
        rejects(json!("true"), json!("bool"), "$ must be bool");
        rejects(json!(0), json!("null"), "$ must be null");
        rejects(json!(1), json!("string"), "$ must be string");
        // `time` is a string that must parse as an instant, not merely a string.
        rejects(json!("tuesday"), json!("time"), "$ must be time");

        accepts(json!(7), json!("int"));
        accepts(json!(1.5), json!("float"));
        accepts(json!(true), json!("bool"));
        accepts(json!(null), json!("null"));
        accepts(json!("x"), json!("string"));
        accepts(json!("2027-01-01T00:00:00Z"), json!("time"));
        // `json` accepts any shape by construction — it is the opaque escape.
        accepts(json!({"anything": [1, 2]}), json!("json"));
    }

    #[test]
    fn literal_and_enum_shapes_reject_values_outside_their_domain() {
        rejects(
            json!("rollback"),
            json!({"literal": "deploy"}),
            "$ must be literal \"deploy\"",
        );
        rejects(
            json!("urgent"),
            json!({"enum": ["low", "high"]}),
            "$ must be one of: low, high",
        );

        accepts(json!("deploy"), json!({"literal": "deploy"}));
        accepts(json!("high"), json!({"enum": ["low", "high"]}));
    }

    #[test]
    fn container_shapes_reject_the_wrong_container() {
        rejects(
            json!({"a": 1}),
            json!({"array": "int"}),
            "$ must be an array",
        );
        rejects(json!([1]), json!({"map": "int"}), "$ must be an object map");

        // Containers validate their contents, and the path names the offender.
        rejects(json!([1, "x"]), json!({"array": "int"}), "$[1] must be int");
        rejects(json!({"k": "x"}), json!({"map": "int"}), "$.k must be int");

        accepts(json!([1, 2]), json!({"array": "int"}));
        accepts(json!({"k": 1}), json!({"map": "int"}));
    }

    #[test]
    fn a_union_rejects_a_value_matching_no_arm() {
        let shape = json!({"union": ["int", {"literal": "none"}]});
        rejects(
            json!("other"),
            shape.clone(),
            "$ matches no arm of the declared union",
        );
        accepts(json!(3), shape.clone());
        accepts(json!("none"), shape);
    }

    #[test]
    fn a_class_shape_rejects_a_non_object() {
        rejects(
            json!("not an object"),
            json!({"class": "Report", "fields": {"id": "string"}}),
            "$ must be an object (Report)",
        );
    }

    /// The closed-class rejection. spec/type-system.md makes this the gate that
    /// "rejects unknown fields AFTER any backend normalization" — a provider that
    /// invents a field must not have it silently admitted.
    #[test]
    fn a_closed_class_rejects_an_undeclared_field() {
        rejects(
            json!({"id": "1", "smuggled": true}),
            json!({"class": "Report", "fields": {"id": "string"}}),
            "$.smuggled is not declared (Report)",
        );
        accepts(
            json!({"id": "1"}),
            json!({"class": "Report", "fields": {"id": "string"}}),
        );
    }

    #[test]
    fn a_missing_required_field_is_rejected_and_an_optional_one_is_not() {
        let shape = json!({
            "fields": {"id": "string", "note": {"optional": "string"}}
        });
        rejects(json!({"note": "n"}), shape.clone(), "$.id is required");
        // An optional field may be absent, and may be null when present.
        accepts(json!({"id": "1"}), shape.clone());
        accepts(json!({"id": "1", "note": null}), shape.clone());
        // Present-but-wrong is still rejected through the optional.
        rejects(
            json!({"id": "1", "note": 5}),
            shape,
            "$.note must be string",
        );
    }

    /// Nesting is where a boundary check usually stops being honest: the path has
    /// to name the offending leaf, or a rejection cannot be acted on.
    #[test]
    fn nested_shapes_report_the_path_to_the_offending_value() {
        rejects(
            json!({"rows": [{"id": 1}]}),
            json!({"fields": {"rows": {"array": {"fields": {"id": "string"}}}}}),
            "$.rows[0].id must be string",
        );
    }
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

#[cfg(test)]
mod custody_capability_tests {
    use super::*;
    use std::sync::Arc;
    use whipplescript_custodian::store::SealedStore;
    use whipplescript_custodian::{Custodian, DeniedEgress, InProcessTransport};
    use whipplescript_custody::{CredentialKind, CredentialName};

    fn effect(target: &str, input_json: &str) -> ClaimableEffect {
        ClaimableEffect {
            effect_id: "effect-seal-1".to_owned(),
            kind: "capability.call".to_owned(),
            target: Some(target.to_owned()),
            profile: None,
            input_json: input_json.to_owned(),
            required_capabilities_json: "[]".to_owned(),
            declared_profiles_json: "[]".to_owned(),
        }
    }

    fn custodian_with_wrapping_key() -> InProcessTransport {
        let mut store = SealedStore::create(None, "pw").expect("store");
        store
            .register(
                CredentialName::new("phi_key").expect("name"),
                // `raw` and `hmac_sha256` are the only kinds `supports` admits
                // for wrap/unwrap; there is no dedicated symmetric kind yet.
                CredentialKind::Raw,
                zeroize::Zeroizing::new(vec![7u8; 32]),
                None,
                None,
            )
            .expect("register");
        InProcessTransport::new(Arc::new(Custodian::new(store, Box::new(DeniedEgress))))
    }

    /// Seal a value through the real custodian and return the envelope, so the
    /// worker-side tests open something that was genuinely sealed rather than a
    /// hand-built fixture that could drift from the wire form.
    fn sealed_envelope(transport: &InProcessTransport, plaintext: &str) -> Value {
        let CapabilityOutcome::Produced(envelope) = run_custody_capability(
            transport,
            &effect(
                "custody.wrap",
                &format!(r#"{{"credential":"phi_key","value":{plaintext}}}"#),
            ),
            "run-1",
        ) else {
            panic!("expected a wrapped envelope");
        };
        envelope
    }

    fn granted_effect(envelope: &Value, target: &str) -> whipplescript_store::ClaimableEffect {
        let input = json!({
            "prompt": "Summarize",
            "bindings": { "record": envelope },
            "access_grants": [{
                "resource": "credential phi_key",
                "operations": [{ "operation": "unwrap", "target": target, "globs": [] }],
            }],
        });
        let mut claimable = effect("agent.tell", &input.to_string());
        claimable.kind = "agent.tell".to_owned();
        claimable
    }

    #[test]
    fn a_granted_turn_opens_its_sealed_input_for_the_provider() {
        // DR-0074 §4's worker arm: "inside a worker executing one run, having
        // opened a sealed effect input".
        let transport = custodian_with_wrapping_key();
        let envelope = sealed_envelope(&transport, r#"{"notes":"chest pain"}"#);
        let opened = open_sealed_effect_inputs(
            &transport,
            &granted_effect(&envelope, "PatientRecord"),
            &granted_effect(&envelope, "PatientRecord").input_json,
            "run-1",
        )
        .expect("opened");
        assert!(
            opened.provider_payload().contains("chest pain"),
            "the provider sees the record, not ciphertext"
        );
    }

    #[test]
    fn an_ungranted_turn_leaves_the_envelope_sealed() {
        // Fail-closed on the runtime's own terms. The checker refuses this
        // program, but a worker must not open on the strength of holding a
        // transport — the grant travels with the effect, in its durable row.
        let transport = custodian_with_wrapping_key();
        let envelope = sealed_envelope(&transport, r#"{"notes":"chest pain"}"#);
        let input = json!({
            "prompt": "Summarize",
            "bindings": { "record": envelope },
            "access_grants": [],
        })
        .to_string();
        let opened =
            open_sealed_effect_inputs(&transport, &effect("agent.tell", &input), &input, "run-1")
                .expect("no grant is not an error");
        assert!(
            !opened.provider_payload().contains("chest pain"),
            "an ungranted envelope stays sealed"
        );
        assert!(opened.provider_payload().contains("ciphertext_b64"));
    }

    #[test]
    fn opening_never_touches_the_input_that_gets_persisted() {
        // The load-bearing test, and the one the design exists for. The
        // obvious implementation resolves plaintext into the effect input,
        // whose value reaches `start_run`'s durable `metadata_json`. Opening
        // returns a SEPARATE value; the input string is untouched.
        let transport = custodian_with_wrapping_key();
        let envelope = sealed_envelope(&transport, r#"{"notes":"chest pain"}"#);
        let claimable = granted_effect(&envelope, "PatientRecord");
        let persisted = claimable.input_json.clone();
        let opened =
            open_sealed_effect_inputs(&transport, &claimable, &persisted, "run-1").expect("opened");
        assert!(opened.provider_payload().contains("chest pain"));
        assert!(
            !persisted.contains("chest pain"),
            "the durable input still holds the envelope: {persisted}"
        );
        assert_eq!(persisted, claimable.input_json, "the input was not mutated");
    }

    #[test]
    fn a_turn_that_opens_nothing_needs_no_custodian() {
        // The ordinary path must not acquire a custody dependency. A turn with
        // no unwrap grant returns early, before any transport is consulted —
        // which is why a host with no custodian can still run every turn that
        // does not open.
        let input = json!({ "prompt": "hello", "bindings": {} }).to_string();
        let opened = open_sealed_effect_inputs(
            &NoCustodyTransport,
            &effect("agent.tell", &input),
            &input,
            "run-1",
        )
        .expect("no grants, no custodian needed");
        assert_eq!(opened.provider_payload(), input);
    }

    #[test]
    fn a_granted_turn_without_a_custodian_fails_rather_than_sending_ciphertext() {
        // The other side of the same decision. Proceeding would hand the
        // provider an envelope and collect a confident answer about nothing.
        let transport = custodian_with_wrapping_key();
        let envelope = sealed_envelope(&transport, r#"{"notes":"chest pain"}"#);
        let claimable = granted_effect(&envelope, "PatientRecord");
        let error = open_sealed_effect_inputs(
            &NoCustodyTransport,
            &claimable,
            &claimable.input_json,
            "run-1",
        )
        .expect_err("a granted turn needs a custodian");
        assert!(error.contains("custodian"), "{error}");
    }

    #[test]
    fn a_debug_format_of_an_opened_input_discloses_nothing() {
        // Something eventually formats a struct holding one. A `{:?}` that
        // printed opened plaintext into a log would be a §4 violation nobody
        // had to write deliberately.
        let transport = custodian_with_wrapping_key();
        let envelope = sealed_envelope(&transport, r#"{"notes":"chest pain"}"#);
        let claimable = granted_effect(&envelope, "PatientRecord");
        let opened =
            open_sealed_effect_inputs(&transport, &claimable, &claimable.input_json, "run-1")
                .expect("opened");
        assert_eq!(format!("{opened:?}"), "OpenedEffectInput(<opened>)");
    }

    #[test]
    fn seal_produces_an_envelope_and_never_the_plaintext() {
        let transport = custodian_with_wrapping_key();
        let outcome = run_custody_capability(
            &transport,
            &effect(
                "custody.wrap",
                r#"{"credential":"phi_key","value":{"notes":"confidential"}}"#,
            ),
            "run-1",
        );

        let CapabilityOutcome::Produced(value) = outcome else {
            panic!("expected a wrapped envelope");
        };
        assert_eq!(
            value.get("credential").and_then(Value::as_str),
            Some("phi_key")
        );
        assert!(
            value.get("ciphertext_b64").is_some(),
            "envelope carries ciphertext"
        );
        assert!(
            value.get("nonce_b64").is_some(),
            "envelope carries its nonce"
        );

        // The point of the whole record: what the effect produces is an
        // envelope, and the plaintext is nowhere in it.
        let rendered = value.to_string();
        assert!(
            !rendered.contains("confidential"),
            "plaintext must not appear in the effect output: {rendered}"
        );
    }

    #[test]
    fn seal_binds_the_envelope_to_its_effect() {
        // §13's AEAD context binding, carried by the effect id: a ciphertext
        // produced for one effect cannot be opened under another.
        let transport = custodian_with_wrapping_key();
        let CapabilityOutcome::Produced(value) = run_custody_capability(
            &transport,
            &effect("custody.wrap", r#"{"credential":"phi_key","value":"x"}"#),
            "run-1",
        ) else {
            panic!("expected a wrapped envelope");
        };
        assert_eq!(
            value.get("context").and_then(Value::as_str),
            Some("effect-seal-1")
        );
    }

    #[test]
    fn the_custody_provider_refuses_to_unwrap_rather_than_leak_or_lie() {
        // The `open` region is now compiled and checked, but opening is still
        // not EXECUTABLE, and the refusal says so instead of guessing.
        //
        // `rule_lowering::effect_binding_value` resolves every `after` binding
        // out of `facts.value_json`, so a durable fact is the only channel an
        // effect result has to its own `after` block. Producing the plaintext
        // would write it there — the §4 violation the record exists to prevent.
        // Producing envelope identity instead would satisfy §4 and LIE, because
        // the checker types that binding at the `into <Type>` class, so
        // `patient.notes` would read null with nothing reporting it.
        let transport = custodian_with_wrapping_key();
        let outcome = run_custody_capability(
            &transport,
            &effect("custody.unwrap", r#"{"credential":"phi_key"}"#),
            "run-1",
        );
        let CapabilityOutcome::Failed { message, .. } = outcome else {
            panic!("custody.unwrap must refuse until the transient channel exists");
        };
        assert!(message.contains("no non-durable channel"), "{message}");
    }

    #[test]
    fn an_unknown_credential_is_refused_by_the_custodian() {
        let transport = custodian_with_wrapping_key();
        let outcome = run_custody_capability(
            &transport,
            &effect(
                "custody.wrap",
                r#"{"credential":"no_such_key","value":"x"}"#,
            ),
            "run-1",
        );
        let CapabilityOutcome::Failed {
            error_kind,
            message,
        } = outcome
        else {
            panic!("expected a refusal");
        };
        assert_eq!(error_kind, "custody");
        assert!(message.contains("custody wrap refused"), "got: {message}");
    }
}
