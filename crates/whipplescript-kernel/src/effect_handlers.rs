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
use whipplescript_store::vcs::FrontierRead;
use whipplescript_store::workstreams::Workstreams;
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
                // G4 of spec/output-attribution-research-note.md: the identity
                // of what this read OBSERVED. `file.write.completed` has always
                // carried the same digest under the same key, and until now a
                // read recorded only the bytes, so nothing could say which write
                // produced what a reader saw. Same construction, so the two join
                // — and it is the `FileContent` locator coordinate (§8.2), whose
                // content half was otherwise unaddressable.
                "content_hash": stable_hash_hex(&content),
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

/// DR-0086 F4: the intent-stamp lookup, generic so both hosts stamp
/// identically. Kernel-driven claims hold as the bare instance id; the
/// harness todo tool holds as `agent:<instance id>` — the union spans the
/// doors, and EXACTLY one held subject is an unambiguous intent (zero or
/// several stamp nothing; ambiguity is never guessed).
pub fn claim_intent_for<S: WorkItems + ?Sized>(store: &S, instance_id: &str) -> Option<String> {
    let mut held = store.active_claim_subjects(instance_id).ok()?;
    if let Ok(agent_held) = store.active_claim_subjects(&format!("agent:{instance_id}")) {
        held.extend(agent_held);
    }
    held.sort();
    held.dedup();
    (held.len() == 1).then(|| held.remove(0))
}

/// The prepared finish-attest arguments (DR-0086 F4: one plan, every door).
pub struct FinishAttestPlan {
    pub reference: String,
    pub basis: Option<String>,
    pub at_cut: Option<String>,
    pub fingerprint_json: Option<String>,
}

/// Plan the finish auto-attest — pure reads over the two views, so every
/// door computes the SAME evidence: `None` when the subject was never
/// claimed or is unknown; keyed when a mainline frontier exists and the
/// subject carries subject-role anchors, unkeyed otherwise.
pub fn plan_finish_attest<W: WorkItems + ?Sized, F: FrontierRead + ?Sized>(
    items: &W,
    frontier: &F,
    id: &str,
) -> Option<FinishAttestPlan> {
    if !items.was_ever_claimed(id).ok()? {
        return None;
    }
    let content_id = items.subject_content_id(id).ok()??;
    let reference = format!("intent({content_id})");
    let basis = items
        .anchors(id)
        .ok()
        .map(|anchors| {
            anchors
                .into_iter()
                .filter(|anchor| anchor.role == "subject")
                .map(|anchor| format!("({})", anchor.region))
                .collect::<Vec<_>>()
        })
        .filter(|regions| !regions.is_empty())
        .map(|regions| regions.join(" | "));
    let keyed = basis.as_ref().and_then(|basis_text| {
        let expr = whipplescript_store::selection::parse(basis_text).ok()?;
        let (at_cut, content) = frontier
            .frontier_content(whipplescript_store::branches::MAINLINE_BRANCH_ID)
            .ok()??;
        let fingerprint = whipplescript_store::freshness::resolve_basis(&expr, &content).ok()?;
        let fingerprint_json = serde_json::to_string(&fingerprint).ok()?;
        Some((at_cut, fingerprint_json))
    });
    let (at_cut, fingerprint_json) = match keyed {
        Some((at_cut, fingerprint_json)) => (at_cut, Some(fingerprint_json)),
        None => (None, None),
    };
    Some(FinishAttestPlan {
        reference,
        basis: if fingerprint_json.is_some() {
            basis
        } else {
            None
        },
        at_cut,
        fingerprint_json,
    })
}

/// DR-0086 F5: one frontier context per read, shared by every verification
/// view — the content maps plus the change-unit window the witness scans.
pub fn frontier_context<F: FrontierRead + ?Sized>(
    frontier: &F,
    branch_id: &str,
) -> Option<(
    whipplescript_store::freshness::FrontierContent,
    Vec<whipplescript_store::selection::ChangeUnit>,
)> {
    let (_at_cut, content) = frontier.frontier_content(branch_id).ok()??;
    let units = frontier
        .frontier_change_units(branch_id, 10_000)
        .unwrap_or_default();
    Some((content, units))
}

/// DR-0086 F5: the witness scan — post-at-cut change units the basis
/// selects, with actor and intent (attribution, never the freshness
/// definition). Conservative when the at-cut has left the window: every
/// matching unit is reported, more candidates rather than fewer.
pub fn witness_units(
    basis: Option<&str>,
    at_cut: Option<&str>,
    units: &[whipplescript_store::selection::ChangeUnit],
) -> Vec<serde_json::Value> {
    let Some(basis) = basis else {
        return Vec::new();
    };
    let Ok(expr) = whipplescript_store::selection::parse(basis) else {
        return Vec::new();
    };
    let boundary = at_cut.and_then(|cut| units.iter().position(|unit| unit.cut_id == cut));
    whipplescript_store::selection::eval(&expr, units)
        .into_iter()
        .filter(|&index| boundary.is_none_or(|b| index > b))
        .map(|index| {
            let unit = &units[index];
            serde_json::json!({
                "cut": unit.cut_id, "path": unit.path,
                "actor": unit.actor, "intent": unit.intent,
            })
        })
        .collect()
}

/// DR-0086 F5: the verification view, generic so both hosts render the
/// SAME report — per-evidence fresh/stale/unkeyed with mismatched entries,
/// moved advisories, and the witness; subject status verified/stale/
/// unverified. Derived, never stored. `None` = the subject's evidence is
/// unreadable (unknown subjects report as unverified-with-no-rows, which
/// is what an empty evidence list honestly is).
pub fn verification_report<W: WorkItems + ?Sized>(
    items: &W,
    frontier: &whipplescript_store::freshness::FrontierContent,
    units: &[whipplescript_store::selection::ChangeUnit],
    subject: &str,
) -> Option<serde_json::Value> {
    use whipplescript_store::freshness::{evaluate, Freshness};
    let evidence = items.evidence(subject).ok()?;
    let mut any_fresh = false;
    let mut any_keyed = false;
    let mut rows = Vec::new();
    for row in &evidence {
        let Some(fingerprint_json) = &row.basis_fingerprint_json else {
            rows.push(serde_json::json!({
                "evidence_id": row.id, "kind": row.kind, "freshness": "unkeyed",
            }));
            continue;
        };
        let Ok(fingerprint) =
            serde_json::from_str::<std::collections::BTreeMap<String, String>>(fingerprint_json)
        else {
            rows.push(serde_json::json!({
                "evidence_id": row.id, "kind": row.kind, "freshness": "unkeyed",
                "note": "unreadable fingerprint",
            }));
            continue;
        };
        any_keyed = true;
        match evaluate(&fingerprint, frontier) {
            Freshness::Fresh => {
                any_fresh = true;
                rows.push(serde_json::json!({
                    "evidence_id": row.id, "kind": row.kind, "freshness": "fresh",
                    "at_cut": row.at_cut,
                }));
            }
            Freshness::Stale { mismatched, moved } => {
                rows.push(serde_json::json!({
                    "evidence_id": row.id, "kind": row.kind, "freshness": "stale",
                    "at_cut": row.at_cut,
                    "mismatched": mismatched,
                    "moved": moved
                        .iter()
                        .map(|(from, to)| serde_json::json!({ "from": from, "moved_to": to }))
                        .collect::<Vec<_>>(),
                    "witness": witness_units(row.basis.as_deref(), row.at_cut.as_deref(), units),
                }));
            }
        }
    }
    let status = if any_fresh {
        "verified"
    } else if any_keyed {
        "stale"
    } else {
        "unverified"
    };
    Some(serde_json::json!({ "status": status, "evidence": rows }))
}

/// DR-0086 F4: the staleness deltas a proposal cut caused, generic over the
/// two read views so the native provider and the DO handler report the SAME
/// receipt advisory — every keyed evidence row among `subjects` that is
/// stale at the branch's frontier AND whose witness includes `cut_id`.
/// Read-only; empty on any missing prerequisite (a receipt never fails
/// over its advisory).
pub fn staleness_deltas_generic<W: WorkItems + ?Sized, F: FrontierRead + ?Sized>(
    items: &W,
    frontier: &F,
    subjects: &[String],
    branch_id: &str,
    cut_id: &str,
) -> Vec<serde_json::Value> {
    use whipplescript_store::freshness::{evaluate, Freshness};
    if cut_id.is_empty() {
        return Vec::new();
    }
    let Ok(Some((_at_cut, content))) = frontier.frontier_content(branch_id) else {
        return Vec::new();
    };
    let units = frontier
        .frontier_change_units(branch_id, 10_000)
        .unwrap_or_default();
    let mut deltas = Vec::new();
    for subject in subjects {
        let Ok(rows) = items.evidence(subject) else {
            continue;
        };
        for row in rows {
            let Some(fingerprint_json) = &row.basis_fingerprint_json else {
                continue;
            };
            let Ok(fingerprint) = serde_json::from_str::<std::collections::BTreeMap<String, String>>(
                fingerprint_json,
            ) else {
                continue;
            };
            let Freshness::Stale { .. } = evaluate(&fingerprint, &content) else {
                continue;
            };
            // Witness: post-at-cut units the basis selects; conservative
            // when the at-cut has left the window.
            let hit = row.basis.as_deref().is_some_and(|basis| {
                let Ok(expr) = whipplescript_store::selection::parse(basis) else {
                    return false;
                };
                let boundary = row
                    .at_cut
                    .as_deref()
                    .and_then(|cut| units.iter().position(|unit| unit.cut_id == cut));
                whipplescript_store::selection::eval(&expr, &units)
                    .into_iter()
                    .filter(|&index| boundary.is_none_or(|b| index > b))
                    .any(|index| units[index].cut_id == cut_id)
            });
            if hit {
                deltas.push(serde_json::json!({
                    "subject": subject,
                    "evidence_id": row.id,
                }));
            }
        }
    }
    deltas
}

/// DR-0086 F3: the finish auto-attest, generic over the store bound so
/// every door mints the same evidence — the CLI and agent doors carried
/// this natively since DR-0084 I1; the effect door was the deferral this
/// discharges. On a subject that was ever claimed: `kind: "cuts"` evidence
/// referencing the `intent(<content-id>)` selection, KEYED over the
/// subject's subject-role anchors when a mainline frontier exists, unkeyed
/// otherwise (degraded and tagged). Advisory by contract: errors are
/// swallowed — a finish never fails over its evidence trail.
pub fn auto_attest_finish_generic<S: WorkItems + FrontierRead>(
    store: &mut S,
    id: &str,
    actor: Option<&str>,
) {
    let Some(plan) = plan_finish_attest(&*store, &*store, id) else {
        return;
    };
    let _ = store.attest(
        id,
        Some("cuts"),
        Some(&plan.reference),
        None,
        actor,
        plan.at_cut.as_deref(),
        plan.basis.as_deref(),
        plan.fingerprint_json.as_deref(),
    );
}

pub fn run_queue_effect_generic<S: RuntimeStore + WorkItems + FrontierRead>(
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

    // G3: scope every tracker event this effect writes to this effect. The
    // window is exactly the dispatch below — no arm propagates with `?`, so the
    // clear after the match is reached on every path, and a value can never
    // outlive the effect that set it. That matters more than it looks: a stale
    // attribution names the WRONG effect, which is worse than naming none.
    kernel
        .store_mut()
        .set_event_effect_id(Some(&effect.effect_id));
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
                    // DR-0086 F3: the effect door mints the same cut-trail
                    // evidence the CLI and agent doors do (advisory).
                    auto_attest_finish_generic(kernel.store_mut(), id, Some(instance_id));
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
    kernel.store_mut().set_event_effect_id(None);

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

// ---------------------------------------------------------------------------
// The `vcs.promote` governed door (DR-0091 W1): one choreography, every host.
// ---------------------------------------------------------------------------

/// What a host door supplies to the promote choreography. Every field is
/// identity-bearing or scope-bearing and therefore MINTED BY THE DOOR, never
/// by the kernel: `reservation_id` and `proposed_main` are exactly-once keys
/// (a changed spelling is a changed identity), `at` follows the host's time
/// discipline (wall clock native, deterministic on the DO), and
/// `receipt_scope` names the workspace the boundary receipt speaks for.
pub struct PromoteDoorRequest<'a> {
    pub stream_id: &'a str,
    pub reservation_id: &'a str,
    /// The Main cut id to propose when reserving from `Active`. Used only on
    /// that path; every later state replays the coordinate the reservation
    /// row recorded.
    pub proposed_main: &'a str,
    pub at: &'a str,
    pub receipt_scope: &'a str,
}

/// The promote choreography's result. `Refused` is data — the door completes
/// the effect either way; only a `Err(String)` from the runner is a failure.
#[derive(Debug)]
pub enum BoundaryRunOutcome {
    Promoted {
        receipt: Box<whipplescript_store::workstreams::WorkstreamBoundaryReceiptV1>,
        member_branches: Vec<String>,
        /// True when the receipt was recovered from an already-archived
        /// stream rather than minted by this run.
        recovered: bool,
    },
    Conflicted {
        conflicts: Vec<whipplescript_store::merge::PathConflict>,
    },
    Refused(String),
}

/// DR-0091 Decision 2, as a seam: the kernel owns the promotion PROTOCOL
/// (the reservation, the exact CAS, the receipts); the host owns the
/// SCHEDULER. A host that supplies no serialization gets a refused CAS,
/// never a torn ref — the reservation is what makes the host's
/// serialization sufficient, not the other way around.
pub trait PromotionSerialization {
    /// `Ok(None)` = held, proceed. `Ok(Some(refusal))` = contended — the
    /// door refuses as data and the caller retries. `Err` = the
    /// serialization mechanism itself is unavailable.
    fn acquire(&mut self) -> Result<Option<String>, String>;
    fn release(&mut self);
}

/// The serialization of a host whose execution is already serial (the DO's
/// single-writer turn): nothing to acquire, nothing to release.
pub struct SingleWriterSerialization;

impl PromotionSerialization for SingleWriterSerialization {
    fn acquire(&mut self) -> Result<Option<String>, String> {
        Ok(None)
    }
    fn release(&mut self) {}
}

/// The stream a `vcs.promote` effect input names, in either spelling the
/// lowering produces (`/message/stream` from the boundary-hop sugar, bare
/// `stream` from direct capability calls).
pub fn promote_stream_id(input: &Value) -> Option<&str> {
    input
        .pointer("/message/stream")
        .or_else(|| input.get("stream"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn promote_cut_value(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

/// DR-0078's promotion coordinator, kernel-generic (DR-0091 W1) — the ONE
/// implementation of the boundary hop, for every host door. The workstream
/// reservation freezes the line before preflight; `promote_line_exact` owns
/// the single Main CAS; the `ref_advanced` row makes every post-CAS crash
/// close forward on retry. The bound is taken here, per-handler, and joins
/// no blanket kernel bound — the scheduler tier stays read-only (DR-0091
/// Decision 1).
pub fn run_reserved_boundary_promotion_generic<W, B, C>(
    streams: &mut W,
    vcs: &mut whipplescript_store::vcs::WorkspaceVcs<B, C>,
    request: &PromoteDoorRequest<'_>,
    serialization: &mut dyn PromotionSerialization,
) -> Result<BoundaryRunOutcome, String>
where
    W: Workstreams + ?Sized,
    B: whipplescript_store::branches::Branches,
    C: whipplescript_store::content::ContentBlobs,
{
    use whipplescript_store::branches::MAINLINE_BRANCH_ID;
    use whipplescript_store::workstreams::{
        BoundaryReservation, ClosePromotedOutcome, RecordRefAdvancedOutcome,
        ReserveBoundaryOutcome, StreamStatus,
    };

    let stream_id = request.stream_id;
    let at = request.at;
    vcs.init(at)
        .map_err(|error| format!("workspace unavailable: {error:?}"))?;
    let mut stream = streams
        .get_stream(stream_id)
        .map_err(|error| format!("workstream read failed: {error:?}"))?
        .ok_or_else(|| format!("no such stream `{stream_id}`"))?;

    if stream.status == StreamStatus::Archived {
        if let Some(reservation_id) = stream.reservation_id.as_deref() {
            let _ = vcs.release_branch_head_reservation(&stream.line_branch_id, reservation_id);
        }
        let receipt = stream
            .boundary_receipt(request.receipt_scope)
            .ok_or_else(|| format!("stream `{stream_id}` is archived"))?;
        return Ok(BoundaryRunOutcome::Promoted {
            receipt: Box::new(receipt),
            member_branches: Vec::new(),
            recovered: true,
        });
    }

    if stream.status == StreamStatus::Active {
        let line = vcs
            .get_branch(&stream.line_branch_id)
            .map_err(|error| format!("stream line read failed: {error:?}"))?
            .ok_or_else(|| format!("stream `{stream_id}` has no line"))?;
        let main = vcs
            .get_branch(MAINLINE_BRANCH_ID)
            .map_err(|error| format!("Main read failed: {error:?}"))?
            .ok_or_else(|| "Main is missing".to_owned())?;
        let expected_line = line.head_cut_id.unwrap_or_default();
        let expected_main = main.head_cut_id.unwrap_or_default();
        match streams
            .reserve_boundary(
                stream_id,
                BoundaryReservation {
                    reservation_id: request.reservation_id,
                    expected_line_cut: &expected_line,
                    expected_main_cut: &expected_main,
                    proposed_main_cut: request.proposed_main,
                    at,
                },
            )
            .map_err(|error| format!("boundary reservation failed: {error:?}"))?
        {
            ReserveBoundaryOutcome::Reserved(row) | ReserveBoundaryOutcome::Existing(row) => {
                stream = row;
            }
            other => {
                return Ok(BoundaryRunOutcome::Refused(format!(
                    "boundary reservation refused: {other:?}"
                )))
            }
        }
    }

    if stream.status == StreamStatus::RefAdvanced {
        let reservation_id = stream.reservation_id.as_deref().unwrap_or_default();
        match streams
            .close_promoted(stream_id, reservation_id, at)
            .map_err(|error| format!("post-CAS close failed: {error:?}"))?
        {
            ClosePromotedOutcome::Closed { rehomed_branch_ids } => {
                vcs.release_branch_head_reservation(&stream.line_branch_id, reservation_id)
                    .map_err(|error| {
                        format!("stream-line reservation release failed: {error:?}")
                    })?;
                let receipt = streams
                    .get_stream(stream_id)
                    .map_err(|error| format!("receipt read failed: {error:?}"))?
                    .and_then(|row| row.boundary_receipt(request.receipt_scope))
                    .ok_or_else(|| "closed promotion has no receipt".to_owned())?;
                return Ok(BoundaryRunOutcome::Promoted {
                    receipt: Box::new(receipt),
                    member_branches: rehomed_branch_ids,
                    recovered: false,
                });
            }
            ClosePromotedOutcome::AlreadyClosed => {
                vcs.release_branch_head_reservation(&stream.line_branch_id, reservation_id)
                    .map_err(|error| {
                        format!("stream-line reservation release failed: {error:?}")
                    })?;
                let receipt = streams
                    .get_stream(stream_id)
                    .map_err(|error| format!("receipt read failed: {error:?}"))?
                    .and_then(|row| row.boundary_receipt(request.receipt_scope))
                    .ok_or_else(|| "closed promotion has no receipt".to_owned())?;
                return Ok(BoundaryRunOutcome::Promoted {
                    receipt: Box::new(receipt),
                    member_branches: Vec::new(),
                    recovered: false,
                });
            }
            other => {
                return Ok(BoundaryRunOutcome::Refused(format!(
                    "post-CAS close refused: {other:?}"
                )))
            }
        }
    }

    if stream.status != StreamStatus::BoundaryReserved {
        return Ok(BoundaryRunOutcome::Refused(format!(
            "stream `{stream_id}` cannot promote from {}",
            stream.status.as_str()
        )));
    }
    let reservation_id = stream.reservation_id.clone().unwrap_or_default();
    let expected_line = stream.expected_line_cut.clone().unwrap_or_default();
    let expected_main = stream.expected_main_cut.clone().unwrap_or_default();
    let proposed_main = stream.proposed_main_cut.clone().unwrap_or_default();
    if reservation_id.is_empty() || proposed_main.is_empty() {
        return Ok(BoundaryRunOutcome::Refused(
            "reserved stream is missing its durable recovery coordinate".to_owned(),
        ));
    }

    // DR-0078 (GWPW residuals): the stream line's HEAD is reserved for this
    // promotion before any host serialization, so a concurrent writer on the
    // line itself is refused by the engine rather than raced.
    match vcs
        .reserve_branch_head(&stream.line_branch_id, &reservation_id, at)
        .map_err(|error| format!("stream-line reservation failed: {error:?}"))?
    {
        whipplescript_store::branches::HeadReservationOutcome::Reserved
        | whipplescript_store::branches::HeadReservationOutcome::Existing => {}
        other => {
            let _ = streams.release_boundary(stream_id, &reservation_id, at);
            return Ok(BoundaryRunOutcome::Refused(format!(
                "stream-line reservation refused: {other:?}"
            )));
        }
    }

    match serialization.acquire() {
        Ok(None) => {}
        Ok(Some(refusal)) => return Ok(BoundaryRunOutcome::Refused(refusal)),
        Err(error) => return Err(error),
    }

    let operation = (|| -> Result<BoundaryRunOutcome, String> {
        // Crash recovery after the CAS: observe the proposed immutable cut and
        // record it without issuing a second CAS.
        if let Some((position, handle)) = vcs
            .boundary_ref_evidence(
                &stream.line_branch_id,
                promote_cut_value(&expected_main),
                &proposed_main,
            )
            .map_err(|error| format!("boundary recovery read failed: {error:?}"))?
        {
            match streams
                .record_ref_advanced(stream_id, &reservation_id, position, &handle, at)
                .map_err(|error| format!("ref receipt record failed: {error:?}"))?
            {
                RecordRefAdvancedOutcome::Recorded(_) | RecordRefAdvancedOutcome::Existing(_) => {}
                other => {
                    return Ok(BoundaryRunOutcome::Refused(format!(
                        "ref receipt record refused: {other:?}"
                    )))
                }
            }
        } else {
            let outcome = vcs
                .promote_line_exact(
                    &stream.line_branch_id,
                    &reservation_id,
                    promote_cut_value(&expected_line),
                    promote_cut_value(&expected_main),
                    &proposed_main,
                    at,
                )
                .map_err(|error| format!("promotion failed: {error:?}"))?;
            match outcome {
                whipplescript_store::vcs::BoundaryPromotionOutcome::Promoted {
                    ref_position,
                    ref_receipt_handle,
                    ..
                } => match streams
                    .record_ref_advanced(
                        stream_id,
                        &reservation_id,
                        ref_position,
                        &ref_receipt_handle,
                        at,
                    )
                    .map_err(|error| format!("ref receipt record failed: {error:?}"))?
                {
                    RecordRefAdvancedOutcome::Recorded(_)
                    | RecordRefAdvancedOutcome::Existing(_) => {}
                    other => {
                        return Ok(BoundaryRunOutcome::Refused(format!(
                            "ref receipt record refused: {other:?}"
                        )))
                    }
                },
                whipplescript_store::vcs::BoundaryPromotionOutcome::Conflicted { conflicts } => {
                    let _ = streams.release_boundary(stream_id, &reservation_id, at);
                    let _ = vcs
                        .release_branch_head_reservation(&stream.line_branch_id, &reservation_id);
                    return Ok(BoundaryRunOutcome::Conflicted { conflicts });
                }
                whipplescript_store::vcs::BoundaryPromotionOutcome::ExpectedCutsMoved {
                    ..
                } => {
                    let _ = streams.release_boundary(stream_id, &reservation_id, at);
                    let _ = vcs
                        .release_branch_head_reservation(&stream.line_branch_id, &reservation_id);
                    return Ok(BoundaryRunOutcome::Refused(
                        "the exact stream/Main cut moved before promotion; retry from active"
                            .to_owned(),
                    ));
                }
                other => {
                    let _ = streams.release_boundary(stream_id, &reservation_id, at);
                    let _ = vcs
                        .release_branch_head_reservation(&stream.line_branch_id, &reservation_id);
                    return Ok(BoundaryRunOutcome::Refused(format!(
                        "promotion refused: {other:?}"
                    )));
                }
            }
        }

        let members = streams
            .members(stream_id)
            .map_err(|error| format!("member read failed: {error:?}"))?;
        match streams
            .close_promoted(stream_id, &reservation_id, at)
            .map_err(|error| format!("post-CAS close failed: {error:?}"))?
        {
            ClosePromotedOutcome::Closed { .. } | ClosePromotedOutcome::AlreadyClosed => {}
            other => {
                return Ok(BoundaryRunOutcome::Refused(format!(
                    "post-CAS close refused: {other:?}"
                )))
            }
        }
        vcs.release_branch_head_reservation(&stream.line_branch_id, &reservation_id)
            .map_err(|error| format!("stream-line reservation release failed: {error:?}"))?;
        let receipt = streams
            .get_stream(stream_id)
            .map_err(|error| format!("receipt read failed: {error:?}"))?
            .and_then(|row| row.boundary_receipt(request.receipt_scope))
            .ok_or_else(|| "closed promotion has no receipt".to_owned())?;
        Ok(BoundaryRunOutcome::Promoted {
            receipt: Box::new(receipt),
            member_branches: members,
            recovered: false,
        })
    })();
    serialization.release();
    operation
}

/// One conflict projection for every door — the eight-field shape the native
/// CLI has always emitted. Lifting it exposed the first drift specimen: the
/// DO's inline copy carried only the first four fields, so a DO conflict
/// receipt named the paths but not which side at which cut.
pub fn promote_conflict_json(conflict: &whipplescript_store::merge::PathConflict) -> Value {
    json!({
        "path": conflict.path,
        "base": conflict.base,
        "ours": conflict.ours,
        "theirs": conflict.theirs,
        "ours_branch": conflict.ours_side.label,
        "ours_cut": conflict.ours_side.cut_id,
        "theirs_branch": conflict.theirs_side.label,
        "theirs_cut": conflict.theirs_side.cut_id,
    })
}

/// Render a promote run as the effect door's outcome — one output shape for
/// every host, so receipt parity is by construction rather than lockstep.
/// `Refused` and `Err` both complete as `Failed` with the `vcs_promote`
/// error kind, exactly as both host doors always have.
pub fn promote_effect_outcome(
    stream_id: &str,
    result: &Result<BoundaryRunOutcome, String>,
) -> CapabilityOutcome {
    let failed = |message: &str| CapabilityOutcome::Failed {
        error_kind: "vcs_promote".to_owned(),
        message: message.to_owned(),
    };
    match result {
        Ok(BoundaryRunOutcome::Promoted {
            receipt, recovered, ..
        }) => CapabilityOutcome::Produced(json!({
            "variant": "Promoted",
            "stream": stream_id,
            "sync_cut_id": receipt.proposed_main_cut,
            "detail": if *recovered { "recovered" } else { "" },
            "boundary_receipt": receipt,
        })),
        Ok(BoundaryRunOutcome::Conflicted { conflicts }) => CapabilityOutcome::Produced(json!({
            "variant": "Conflicted",
            "stream": stream_id,
            "sync_cut_id": "",
            "detail": serde_json::to_string(
                &conflicts.iter().map(promote_conflict_json).collect::<Vec<_>>()
            ).unwrap_or_default(),
        })),
        Ok(BoundaryRunOutcome::Refused(message)) => failed(message),
        Err(message) => failed(message),
    }
}

// ---------------------------------------------------------------------------
// The selective governed doors, `vcs.undo` / `vcs.transport` (DR-0091 W2).
// ---------------------------------------------------------------------------

/// The selection a selective effect names, checked the way both doors always
/// checked it: present, parseable, and free of unexpanded `region()` atoms
/// (DR-0084 — a region literal expands at effect-input build; one that
/// reaches a door names a region the program never declared, and silently
/// matching empty is the failure the refusal exists to prevent).
pub fn selective_selection(
    input: &Value,
) -> Result<whipplescript_store::selection::SelExpr, String> {
    let Some(selection) = input
        .get("selection")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return Err("the effect names no selection".to_owned());
    };
    let expr = whipplescript_store::selection::parse(selection)
        .map_err(|error| format!("selection does not parse: {error}"))?;
    if let Some(name) = whipplescript_store::selection::contains_region_atom(&expr) {
        return Err(format!(
            "`region({name})` did not resolve: the program declares no region by that name"
        ));
    }
    Ok(expr)
}

/// The staleness advisory's host seam: given the vcs, a line, and the cut
/// just minted, list the receipt's staleness deltas (the host supplies the
/// subject listing; the evaluation is `staleness_deltas_generic`).
pub type StalenessAdvisory<'a, B, C> =
    dyn FnMut(&whipplescript_store::vcs::WorkspaceVcs<B, C>, &str, &str) -> Vec<Value> + 'a;

/// The selective verbs' choreography, kernel-generic (DR-0091 W2) — one
/// implementation of `vcs.undo` / `vcs.transport` for every host door, with
/// the same output shape by construction. The host resolves the acting
/// branch (ambient line or repair scope), stamps actor/intent on the vcs,
/// and mints the identity-bearing `cut_id`/`at` under its own time
/// discipline; the two seams it supplies are the stream-line resolver (how
/// `onto <stream>` finds a line on this host) and the staleness advisory's
/// subject listing (`staleness_deltas_generic` over the host's stores).
/// `Err` is the door's refusal text; refusal-shaped engine outcomes render
/// as data exactly as both doors always rendered them.
#[allow(clippy::too_many_arguments)]
pub fn run_selective_verb_generic<B, C>(
    vcs: &mut whipplescript_store::vcs::WorkspaceVcs<B, C>,
    target: Option<&str>,
    input: &Value,
    expr: &whipplescript_store::selection::SelExpr,
    branch_id: &str,
    cut_id: &str,
    at: &str,
    resolve_stream_line: &mut dyn FnMut(&str) -> Option<String>,
    staleness: &mut StalenessAdvisory<'_, B, C>,
) -> Result<Value, String>
where
    B: whipplescript_store::branches::Branches,
    C: whipplescript_store::content::ContentBlobs,
{
    use whipplescript_store::vcs::{TransportOutcome, UndoSelectionOutcome};

    if target == Some("vcs.undo") {
        match vcs.apply_undo_selection(branch_id, expr, cut_id, at) {
            Ok(UndoSelectionOutcome::Proposed {
                cut_id,
                reverted_paths,
                ..
            }) => Ok(json!({
                "variant": "Applied",
                "cut_id": cut_id,
                "detail": serde_json::to_string(&reverted_paths).unwrap_or_default(),
                // DR-0084 O1: what this proposal cut staled (advisory).
                "staleness": staleness(vcs, branch_id, &cut_id),
            })),
            Ok(UndoSelectionOutcome::WouldStrand { stranded }) => Ok(json!({
                "variant": "Stranded",
                "cut_id": "",
                // Three fields, attribution included — the shape native
                // always emitted; the DO's inline copy dropped `by`.
                "detail": serde_json::to_string(
                    &stranded
                        .iter()
                        .map(|unit| json!({
                            "path": unit.path,
                            "cut": unit.cut_id,
                            "by": unit.actor,
                        }))
                        .collect::<Vec<_>>()
                )
                .unwrap_or_default(),
            })),
            Ok(UndoSelectionOutcome::NothingSelected) => Ok(json!({
                "variant": "Applied",
                "cut_id": "",
                "detail": "nothing_selected",
            })),
            Ok(other) => Err(format!("undo refused: {other:?}")),
            Err(error) => Err(format!("undo failed: {error:?}")),
        }
    } else {
        let onto = input
            .get("onto")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let onto_line = if onto == "mainline" {
            whipplescript_store::branches::MAINLINE_BRANCH_ID.to_owned()
        } else {
            match resolve_stream_line(onto) {
                Some(line) => line,
                None => return Err(format!("`onto {onto}` names no stream")),
            }
        };
        match vcs.transport_selection(branch_id, expr, &onto_line, cut_id, at) {
            Ok(TransportOutcome::Transported {
                cut_id,
                moved_paths,
                ..
            }) => Ok(json!({
                "variant": "Applied",
                "cut_id": cut_id,
                "detail": serde_json::to_string(&moved_paths).unwrap_or_default(),
                // DR-0084 O1: what landed content staled on the
                // DESTINATION line (advisory).
                "staleness": staleness(vcs, &onto_line, &cut_id),
            })),
            Ok(TransportOutcome::Conflicted { conflicts }) => Ok(json!({
                "variant": "Conflicted",
                "cut_id": "",
                "detail": serde_json::to_string(
                    &conflicts
                        .iter()
                        .map(|conflict| json!({"path": conflict.path}))
                        .collect::<Vec<_>>()
                )
                .unwrap_or_default(),
            })),
            Ok(TransportOutcome::UpToDate | TransportOutcome::NothingSelected) => Ok(json!({
                "variant": "Applied",
                "cut_id": "",
                "detail": "nothing_to_move",
            })),
            Ok(other) => Err(format!("transport refused: {other:?}")),
            Err(error) => Err(format!("transport failed: {error:?}")),
        }
    }
}

/// Render a selective run as the effect door's outcome — the `vcs_selective`
/// failure kind both doors always used.
pub fn selective_effect_outcome(result: Result<Value, String>) -> CapabilityOutcome {
    match result {
        Ok(value) => CapabilityOutcome::Produced(value),
        Err(message) => CapabilityOutcome::Failed {
            error_kind: "vcs_selective".to_owned(),
            message,
        },
    }
}

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

#[cfg(test)]
mod queue_effect_refusal_tests {
    //! The two refusals `run_queue_effect_generic` carries on its failure paths.
    //! Neither was exercised until the sweep's widened site matching (#309)
    //! attributed them to a change that scoped tracker writes to their effect.

    use super::*;
    use whipplescript_store::native_stores::NativeStores;
    use whipplescript_store::{NewEffect, RuleCommit};

    fn queued(kind: &'static str, input_json: &'static str) -> NewEffect<'static> {
        NewEffect {
            effect_id: "eff",
            kind,
            target: None,
            input_json,
            status: "queued",
            idempotency_key: "rule=start;effect=eff",
            required_capabilities_json: "[]",
            profile: None,
            correlation_id: None,
            source_span_json: None,
            timeout_seconds: None,
        }
    }

    /// Runs one queued effect through the queue handler and returns every event
    /// payload it recorded, which is where a refusal's text lands.
    fn run_and_collect(kind: &'static str, input_json: &'static str) -> String {
        let store = NativeStores::open_in_memory().expect("stores open");
        let mut kernel = RuntimeKernel::new(store);
        let effects = [queued(kind, input_json)];
        kernel
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let claimable = kernel
            .claimable_effects("instance-a")
            .expect("claimable effects load");
        run_queue_effect_generic(
            &mut kernel,
            "instance-a",
            &claimable[0],
            "2026-01-01T00:00:00Z",
            &EffectConfig::default(),
        )
        .expect("the handler settles the effect rather than erroring out");
        kernel
            .store()
            .list_events("instance-a")
            .expect("events load")
            .iter()
            .map(|event| event.payload_json.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_store_failure_finishing_an_item_surfaces_as_the_effect_s_failure() {
        // The arm this pins cannot be DELETED — the match needs it — but it can
        // be changed to answer `Ok`, which would report a store failure to the
        // program as a finish that worked. That is the silent weakening the
        // sweep exists to catch, so the arm earns a pin despite being
        // unreachable by any ordinary path.
        //
        // Reaching it takes an issue that is open (so the status check passes)
        // whose alias no longer resolves (so appending its `issue.closed` event
        // fails). Nothing produces that, so the test constructs it, with SQL
        // rather than by widening the store's API for a test's benefit.
        let base = std::env::temp_dir().join(format!(
            "whip-queue-store-failure-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&base).expect("scratch dir");
        let items = base.join("items.sqlite");
        let stores = NativeStores::open(
            base.join("runtime.sqlite"),
            base.join("coord.sqlite"),
            &items,
        )
        .expect("stores open");
        let mut kernel = RuntimeKernel::new(stores);
        let filed = kernel
            .store_mut()
            .file_item("q", "t", "", &[], &serde_json::json!({}), None)
            .expect("file an item");

        rusqlite::Connection::open(&items)
            .expect("open the items store")
            .execute(
                "DELETE FROM tracker_aliases WHERE alias = ?1",
                rusqlite::params![&filed.id],
            )
            .expect("drop the alias mapping");

        let effects = [NewEffect {
            effect_id: "eff",
            kind: "tracker.finish",
            target: None,
            input_json: "{}",
            status: "queued",
            idempotency_key: "rule=start;effect=eff",
            required_capabilities_json: "[]",
            profile: None,
            correlation_id: None,
            source_span_json: None,
            timeout_seconds: None,
        }];
        let input = format!(r#"{{"id":"{}"}}"#, filed.id);
        let effects = [NewEffect {
            input_json: &input,
            ..effects[0]
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let claimable = kernel
            .claimable_effects("instance-a")
            .expect("claimable effects load");
        run_queue_effect_generic(
            &mut kernel,
            "instance-a",
            &claimable[0],
            "2026-01-01T00:00:00Z",
            &EffectConfig::default(),
        )
        .expect("the handler settles the effect rather than erroring out");
        let recorded = kernel
            .store()
            .list_events("instance-a")
            .expect("events load")
            .iter()
            .map(|event| event.payload_json.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            recorded.contains("finish failed"),
            "a store failure reaches the effect's failure: {recorded}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_unrecognised_queue_effect_kind_is_refused_by_name() {
        // A defensive arm: lowering only ever routes the five `tracker.*` kinds
        // here. It earns its place by naming what arrived — a kind that reached
        // this dispatch without a branch is a wiring bug, and a silent success
        // would settle the effect as though the work had happened.
        let recorded = run_and_collect("tracker.bogus", "{}");
        assert!(
            recorded.contains("unknown queue effect kind"),
            "the refusal names the kind it could not dispatch: {recorded}"
        );
    }
}

#[cfg(test)]
mod promote_door_tests {
    //! DR-0091 W1: the door pieces every host shares. The choreography
    //! itself is bound by the workstream engine tests and both host door
    //! tests; these pin the shared input reading and the ONE output shape
    //! receipt parity rests on.

    use super::*;

    #[test]
    fn promote_stream_id_reads_both_spellings_and_refuses_empty() {
        let sugar = json!({ "message": { "stream": "triage" } });
        assert_eq!(promote_stream_id(&sugar), Some("triage"));
        let bare = json!({ "stream": "triage" });
        assert_eq!(promote_stream_id(&bare), Some("triage"));
        assert_eq!(promote_stream_id(&json!({ "stream": "" })), None);
        assert_eq!(promote_stream_id(&json!({})), None);
    }

    fn receipt() -> Box<whipplescript_store::workstreams::WorkstreamBoundaryReceiptV1> {
        Box::new(
            whipplescript_store::workstreams::WorkstreamBoundaryReceiptV1 {
                schema: "workstream-boundary-receipt.v1".to_owned(),
                workspace_authority_id: "test-workspace".to_owned(),
                stream_id: "triage".to_owned(),
                reservation_id: "effect-eff-1".to_owned(),
                outcome: "promoted".to_owned(),
                expected_stream_cut: "cut-line".to_owned(),
                expected_main_cut: "cut-main".to_owned(),
                proposed_main_cut: "cut-seed-promote".to_owned(),
                main_ref_position: Some(3),
                ref_receipt_handle: Some("handle-3".to_owned()),
                recorded_at: "t9".to_owned(),
            },
        )
    }

    #[test]
    fn promoted_output_shape_is_the_one_both_hosts_emit() {
        let fresh = Ok(BoundaryRunOutcome::Promoted {
            receipt: receipt(),
            member_branches: vec!["b1".to_owned()],
            recovered: false,
        });
        let CapabilityOutcome::Produced(value) = promote_effect_outcome("triage", &fresh) else {
            panic!("promoted renders as produced");
        };
        assert_eq!(value["variant"], "Promoted");
        assert_eq!(value["stream"], "triage");
        assert_eq!(value["sync_cut_id"], "cut-seed-promote");
        assert_eq!(value["detail"], "");
        assert_eq!(
            value["boundary_receipt"]["reservation_id"], "effect-eff-1",
            "the receipt rides the output whole"
        );

        let recovered = Ok(BoundaryRunOutcome::Promoted {
            receipt: receipt(),
            member_branches: Vec::new(),
            recovered: true,
        });
        let CapabilityOutcome::Produced(value) = promote_effect_outcome("triage", &recovered)
        else {
            panic!("recovered renders as produced");
        };
        assert_eq!(
            value["detail"], "recovered",
            "an archived stream's replay says so"
        );
    }

    #[test]
    fn conflict_detail_carries_both_sides_with_provenance() {
        let conflicts = vec![whipplescript_store::merge::PathConflict {
            path: "contested.md".to_owned(),
            base: None,
            ours: Some("h-ours".to_owned()),
            theirs: Some("h-theirs".to_owned()),
            ours_side: whipplescript_store::merge::MergeSide {
                label: "line-conflict".to_owned(),
                cut_id: Some("cut-2".to_owned()),
            },
            theirs_side: whipplescript_store::merge::MergeSide {
                label: "main".to_owned(),
                cut_id: Some("cut-3".to_owned()),
            },
        }];
        let result = Ok(BoundaryRunOutcome::Conflicted { conflicts });
        let CapabilityOutcome::Produced(value) = promote_effect_outcome("conflict", &result) else {
            panic!("conflict renders as produced — refusal is data");
        };
        assert_eq!(value["variant"], "Conflicted");
        let detail: Value =
            serde_json::from_str(value["detail"].as_str().expect("detail is a string"))
                .expect("detail parses");
        // The eight-field shape the native CLI always emitted; the DO's
        // inline copy carried only the first four until the W1 lift.
        assert_eq!(detail[0]["path"], "contested.md");
        assert_eq!(detail[0]["ours_branch"], "line-conflict");
        assert_eq!(detail[0]["ours_cut"], "cut-2");
        assert_eq!(detail[0]["theirs_branch"], "main");
        assert_eq!(detail[0]["theirs_cut"], "cut-3");
    }

    #[test]
    fn refusal_and_error_both_fail_with_the_promote_kind() {
        for result in [
            Ok(BoundaryRunOutcome::Refused(
                "adoption lease held; retry".to_owned(),
            )),
            Err("workspace unavailable".to_owned()),
        ] {
            let CapabilityOutcome::Failed {
                error_kind,
                message,
            } = promote_effect_outcome("triage", &result)
            else {
                panic!("refusal/error render as failed");
            };
            assert_eq!(error_kind, "vcs_promote");
            assert!(!message.is_empty());
        }
    }
}

#[cfg(test)]
mod selective_door_tests {
    //! DR-0091 W2: the selective doors' shared pieces — the selection gate's
    //! three refusals (each message-pinned for the mutation sweep) and the
    //! verb choreography end to end over a real workspace.

    use super::*;

    #[test]
    fn selective_selection_gate_refuses_by_reason() {
        let missing = selective_selection(&json!({})).expect_err("no selection");
        assert_eq!(missing, "the effect names no selection");
        let empty = selective_selection(&json!({"selection": ""})).expect_err("empty");
        assert_eq!(empty, "the effect names no selection");
        let unparseable = selective_selection(&json!({"selection": "path((("})).expect_err("parse");
        assert!(
            unparseable.starts_with("selection does not parse:"),
            "{unparseable}"
        );
        let region =
            selective_selection(&json!({"selection": "region(nope)"})).expect_err("region");
        assert_eq!(
            region,
            "`region(nope)` did not resolve: the program declares no region by that name"
        );
        assert!(selective_selection(&json!({"selection": "path(src/**)"})).is_ok());
    }

    fn temp_vcs(
        tag: &str,
    ) -> (
        whipplescript_store::vcs::NativeWorkspaceVcs,
        std::path::PathBuf,
    ) {
        let dir =
            std::env::temp_dir().join(format!("whip-selective-door-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let mut vcs = whipplescript_store::vcs::NativeWorkspaceVcs::open(
            dir.join("branches.sqlite"),
            dir.join("content.sqlite"),
        )
        .expect("open vcs");
        vcs.init("t0").expect("init");
        (vcs, dir)
    }

    #[test]
    fn selective_verb_runs_undo_and_refuses_unknown_onto() {
        let (mut vcs, _dir) = temp_vcs("undo");
        vcs.create_branch(
            "line-a",
            None,
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            "t1",
        )
        .expect("branch");
        vcs.write("line-a", "src/lib.rs", Some("v1"), "cut_1", "t2")
            .expect("write");
        let expr = selective_selection(&json!({"selection": "path(src/**)"})).expect("parse");

        let mut staleness_calls = 0;
        let value = run_selective_verb_generic(
            &mut vcs,
            Some("vcs.undo"),
            &json!({"selection": "path(src/**)"}),
            &expr,
            "line-a",
            "cut-undo-1",
            "t3",
            &mut |_| None,
            &mut |_, _, _| {
                staleness_calls += 1;
                Vec::new()
            },
        )
        .expect("undo applies");
        assert_eq!(value["variant"], "Applied");
        assert!(value["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("src/lib.rs"));
        assert_eq!(staleness_calls, 1, "the applied cut gets its advisory");

        // Undoing what no longer matches selects nothing — data, not failure.
        let nothing = run_selective_verb_generic(
            &mut vcs,
            Some("vcs.undo"),
            &json!({"selection": "path(docs/**)"}),
            &selective_selection(&json!({"selection": "path(docs/**)"})).expect("parse"),
            "line-a",
            "cut-undo-2",
            "t4",
            &mut |_| None,
            &mut |_, _, _| Vec::new(),
        )
        .expect("nothing selected is data");
        assert_eq!(nothing["detail"], "nothing_selected");

        // Transport onto a stream this host cannot resolve refuses by name.
        let refusal = run_selective_verb_generic(
            &mut vcs,
            Some("vcs.transport"),
            &json!({"selection": "path(src/**)", "onto": "ghost"}),
            &expr,
            "line-a",
            "cut-t-1",
            "t5",
            &mut |_| None,
            &mut |_, _, _| Vec::new(),
        )
        .expect_err("unresolvable stream refuses");
        assert_eq!(refusal, "`onto ghost` names no stream");
    }

    /// The verb runner's four catch-all arms: an engine outcome the door
    /// does not render as data refuses with the verb's name, and a store
    /// that fails mid-verb fails with it too. The store failure is forced
    /// the house way (`queue_effect_refusal_tests`): break the store's
    /// invariant directly — here, drop the branches table out from under
    /// the open composition.
    #[test]
    fn selective_verb_catch_alls_name_the_verb_and_disposition() {
        let (mut vcs, dir) = temp_vcs("catchall");
        vcs.create_branch(
            "line-a",
            None,
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            "t1",
        )
        .expect("branch");
        vcs.write("line-a", "src/lib.rs", Some("v1"), "cut_1", "t2")
            .expect("write");
        let expr = selective_selection(&json!({"selection": "path(src/**)"})).expect("parse");

        // Undo on a branch the workspace does not have: refused, by name.
        let refused = run_selective_verb_generic(
            &mut vcs,
            Some("vcs.undo"),
            &json!({"selection": "path(src/**)"}),
            &expr,
            "no-such-line",
            "cut-r1",
            "t3",
            &mut |_| None,
            &mut |_, _, _| Vec::new(),
        )
        .expect_err("missing branch refuses");
        assert_eq!(refused, "undo refused: BranchMissing");

        // Transport onto a line the resolver names but the workspace lacks.
        let refused = run_selective_verb_generic(
            &mut vcs,
            Some("vcs.transport"),
            &json!({"selection": "path(src/**)", "onto": "ghost"}),
            &expr,
            "line-a",
            "cut-r2",
            "t4",
            &mut |_| Some("ghost-line".to_owned()),
            &mut |_, _, _| Vec::new(),
        )
        .expect_err("missing target refuses");
        assert_eq!(refused, "transport refused: TargetMissing");

        // Break the store under the open composition: every verb now FAILS
        // rather than refusing, and says which verb.
        rusqlite::Connection::open(dir.join("branches.sqlite"))
            .expect("second connection")
            .execute_batch("DROP TABLE branches;")
            .expect("drop");
        let failed = run_selective_verb_generic(
            &mut vcs,
            Some("vcs.undo"),
            &json!({"selection": "path(src/**)"}),
            &expr,
            "line-a",
            "cut-f1",
            "t5",
            &mut |_| None,
            &mut |_, _, _| Vec::new(),
        )
        .expect_err("broken store fails undo");
        assert!(failed.starts_with("undo failed:"), "{failed}");
        let failed = run_selective_verb_generic(
            &mut vcs,
            Some("vcs.transport"),
            &json!({"selection": "path(src/**)", "onto": "mainline"}),
            &expr,
            "line-a",
            "cut-f2",
            "t6",
            &mut |_| None,
            &mut |_, _, _| Vec::new(),
        )
        .expect_err("broken store fails transport");
        assert!(failed.starts_with("transport failed:"), "{failed}");
    }
}
