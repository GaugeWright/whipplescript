//! DO parity P4: the in-isolate agent-turn tool executor.
//!
//! The durable-object counterpart to the native CLI `FileToolExecutor`
//! (`whipplescript-cli/src/harness_tools.rs`): the concrete [`ToolExecutor`] the
//! kernel's brokered turn drives when an agent runs ON the durable object. Where
//! the native executor is `std::fs`-coupled and rooted at a workspace directory,
//! this one runs entirely against the DO's synchronous SQLite over the SAME
//! shared `Rc<DoSql>` handle the runtime store and file plane use (P1), so a tool
//! call is an in-isolate SQLite round with no `fetch` and no filesystem.
//!
//! The workspace IS the flat `files` table (key TEXT PRIMARY KEY, content TEXT):
//! a path argument is the key directly, with no root-join and no path policy in
//! v1 — the DO file plane is itself the sandbox. `ls`/`find`/`grep` therefore
//! work over that flat key space (prefix filter + glob/substring), not a tree.
//!
//! Tool SCHEMAS mirror the native set exactly (so a program's model sees the same
//! tools on either backend); the schemas are the contract, this is a second
//! implementation of the same behavior. `bash` runs through the shared
//! placement-neutral `WhipShell` adapter over a preloaded workspace snapshot.
//!
//! A tool ERROR is a `ToolOutcome { status: Error, .. }`, never a Rust error: a
//! failed tool result is informative to the model (it retries), not a turn
//! failure (DR-0024 boundary corollary). All returned content is capped at
//! [`DEFAULT_MAX_BYTES`].

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::Duration;

use serde_json::{json, Value};
use whipplescript_kernel::effect_handlers::glob_match;
use whipplescript_kernel::harness_loop::{
    ToolCall, ToolExecutor, ToolOutcome, ToolSpec, ToolStatus,
};
use whipplescript_kernel::host_package::workspace_tool_specs_from_registry;
use whipplescript_kernel::whip_shell::{ShellFile, ShellRequest, WhipShell};
use whipplescript_store::items::{ClaimOutcome, FinishOutcome, ReleaseOutcome, WorkItems};
use whipplescript_store::RuntimeStore;

use crate::do_store::{DoSql, DoSqliteStore, SqlValue};

// Tool names, mirroring the native constants (`harness_tools.rs`).
const TOOL_READ: &str = "read";
const TOOL_WRITE: &str = "write";
const TOOL_EDIT: &str = "edit";
const TOOL_GREP: &str = "grep";
const TOOL_FIND: &str = "find";
const TOOL_LS: &str = "ls";
const TOOL_RECALL: &str = "recall";
const TOOL_LIST_TODOS: &str = "list_todos";
const TOOL_ADD_TODO: &str = "add_todo";
const TOOL_UPDATE_TODO: &str = "update_todo";
const TOOL_BASH: &str = "bash";

/// Default cap on a single tool's returned content (mirrors native).
const DEFAULT_MAX_BYTES: usize = 50_000;
/// Bound on `files` rows visited by `find`/`grep` so a huge workspace cannot
/// stall a turn (mirrors native's tree-walk bound, applied to the flat table).
const MAX_FILES_WALKED: usize = 5_000;
/// Default line window for `read` when no explicit `limit` is given.
const DEFAULT_READ_LINE_LIMIT: usize = 2_000;
/// Cap on a single emitted `grep` line.
const GREP_MAX_LINE_CHARS: usize = 500;
/// Leading bytes sniffed for a NUL byte to refuse reading binary content as text.
const BINARY_SNIFF_BYTES: usize = 8_192;

/// The single tracker queue the DO agent's todos live in. The durable object
/// holds exactly one workflow instance, so one queue suffices; `add_todo` files
/// into it and `list_todos` reads it back.
const DO_TRACKER_QUEUE: &str = "agent";
/// Attribution for agent-filed tracker items (mirrors native's `agent:<holder>`),
/// so `list_todos` can distinguish agent- from rule-filed items.
const DO_TRACKER_HOLDER: &str = "agent";

/// The complete model-facing tool set used only when a caller does not supply a
/// package-derived ability ceiling. Workspace schemas come from the same kernel
/// registry used by public and native package resolution.
pub fn do_tool_specs() -> Vec<ToolSpec> {
    let mut specs = workspace_tool_specs_from_registry(true, true, true);
    specs.extend(tracker_tool_specs());
    specs
}

/// The tracker tools (mirror native `tracker_tool_specs()` exactly).
fn tracker_tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: TOOL_LIST_TODOS.into(),
            description: "List work-tracker items (optionally filtered by status).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string", "enum": ["pending", "in_progress", "completed"] }
                },
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: TOOL_ADD_TODO.into(),
            description:
                "File a new work-tracker item (a durable to-do the workflow can react to).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "content": { "type": "string" },
                    "status": { "type": "string", "enum": ["pending"] }
                },
                "required": ["content"],
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: TOOL_UPDATE_TODO.into(),
            description: "Change a tracker item's status by id.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "status": { "type": "string", "enum": ["pending", "in_progress", "completed"] }
                },
                "required": ["id", "status"],
                "additionalProperties": false
            }),
        },
    ]
}

/// The durable-object tool executor. Holds the shared `Rc<DoSql>` handle (the
/// same one the runtime store + file plane use), so every tool is an in-isolate
/// SQLite round against the one DO SQLite.
pub struct DoToolExecutor<Sql: DoSql> {
    sql: Rc<Sql>,
    key_prefix: String,
}

impl<Sql: DoSql> DoToolExecutor<Sql> {
    pub fn new(sql: Rc<Sql>) -> Self {
        Self {
            sql,
            key_prefix: String::new(),
        }
    }

    pub fn for_instance(sql: Rc<Sql>, instance_id: &str) -> Self {
        Self {
            sql,
            key_prefix: format!("{instance_id}/"),
        }
    }

    fn storage_key(&self, path: &str) -> String {
        format!("{}{path}", self.key_prefix)
    }

    /// A store view over the shared handle, for the content-blob (`put_content` /
    /// `get_content`) and work-item (`WorkItems`) surfaces. Cheap — it wraps a
    /// clone of the `Rc`, hitting the same DO SQLite.
    fn store(&self) -> DoSqliteStore<Rc<Sql>> {
        DoSqliteStore::new(Rc::clone(&self.sql))
    }

    fn dispatch(&self, call: &ToolCall) -> Result<String, String> {
        let args = &call.arguments;
        match call.name.as_str() {
            TOOL_READ => self.read(args),
            TOOL_WRITE => self.write(args),
            TOOL_EDIT => self.edit(args),
            TOOL_GREP => self.grep(args),
            TOOL_FIND => self.find(args),
            TOOL_LS => self.ls(args),
            TOOL_RECALL => self.recall(args),
            TOOL_LIST_TODOS => self.list_todos(args),
            TOOL_ADD_TODO => self.add_todo(args),
            TOOL_UPDATE_TODO => self.update_todo(args),
            TOOL_BASH => self.bash(args),
            other => Err(format!("unknown tool `{other}`")),
        }
    }

    // -- file plane over the flat `files` table ----------------------------

    /// Current content of `key`, or `None` if the row does not exist.
    fn file_content(&self, key: &str) -> Result<Option<String>, String> {
        let storage_key = self.storage_key(key);
        let rows = self
            .sql
            .query(
                "SELECT content FROM files WHERE key = ?1",
                &[SqlValue::Text(storage_key)],
            )
            .map_err(|error| format!("read of `{key}` failed: {error}"))?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    /// Upsert `content` into the `files` table AND capture RC-1 file history
    /// (the body content-addressed in `content_blobs`), exactly as the
    /// `file.write` effect does — the blob is captured in the same DO SQLite as
    /// the row, so no history hash is referenced without its bytes.
    fn store_file(&self, key: &str, content: &str) -> Result<(), String> {
        self.store()
            .put_content(content)
            .map_err(|error| format!("history capture of `{key}` failed: {error:?}"))?;
        self.sql
            .execute(
                "INSERT INTO files (key, content) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET content = excluded.content",
                &[
                    SqlValue::Text(self.storage_key(key)),
                    SqlValue::Text(content.to_owned()),
                ],
            )
            .map_err(|error| format!("write of `{key}` failed: {error}"))?;
        Ok(())
    }

    /// All `files` keys, sorted, capped at [`MAX_FILES_WALKED`].
    fn all_keys(&self) -> Result<Vec<String>, String> {
        let rows = if self.key_prefix.is_empty() {
            self.sql.query(
                "SELECT key FROM files ORDER BY key LIMIT ?1",
                &[SqlValue::Int((MAX_FILES_WALKED + 1) as i64)],
            )
        } else {
            self.sql.query(
                "SELECT substr(key, length(?1) + 1) FROM files \
                 WHERE key LIKE ?1 || '%' ORDER BY key LIMIT ?2",
                &[
                    SqlValue::Text(self.key_prefix.clone()),
                    SqlValue::Int((MAX_FILES_WALKED + 1) as i64),
                ],
            )
        }
        .map_err(|error| format!("list files failed: {error}"))?;
        if rows.len() > MAX_FILES_WALKED {
            return Err(format!(
                "workspace contains more than the supported {MAX_FILES_WALKED} files"
            ));
        }
        Ok(rows.iter().map(|row| as_text(&row[0])).collect())
    }

    fn bash(&self, args: &Value) -> Result<String, String> {
        let command = str_arg(args, "command")?.trim();
        let timeout = args
            .get("timeout")
            .and_then(Value::as_u64)
            .unwrap_or(30)
            .clamp(1, 30);
        let keys = self.all_keys()?;
        let mut before = BTreeMap::new();
        let mut files = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(content) = self.file_content(&key)? else {
                continue;
            };
            before.insert(key.clone(), content.clone().into_bytes());
            files.push(ShellFile {
                path: key,
                content: content.into_bytes(),
                writable: true,
            });
        }

        let output = WhipShell::default().execute(ShellRequest {
            command: command.to_owned(),
            files,
            timeout: Duration::from_secs(timeout),
        })?;

        // Validate the complete result before importing any delta. The v1 DO
        // file plane is UTF-8 text; a binary result fails honestly instead of
        // corrupting the flat SQLite representation.
        let mut after = BTreeMap::new();
        for (path, bytes) in output.files {
            let content = String::from_utf8(bytes)
                .map_err(|_| format!("bash produced binary workspace file `{path}`"))?;
            after.insert(path, content);
        }
        for (path, content) in &after {
            if before.get(path).map(Vec::as_slice) != Some(content.as_bytes()) {
                self.store_file(path, content)?;
            }
        }
        let remaining = after.keys().cloned().collect::<BTreeSet<_>>();
        for removed in before.keys().filter(|path| !remaining.contains(*path)) {
            let storage_key = self.storage_key(removed);
            self.sql
                .execute(
                    "DELETE FROM files WHERE key = ?1",
                    &[SqlValue::Text(storage_key)],
                )
                .map_err(|error| format!("delete of `{removed}` failed: {error}"))?;
        }

        let mut combined = output.stdout;
        combined.push_str(&output.stderr);
        if output.exit_code == 0 {
            Ok(combined)
        } else {
            Err(format!(
                "command exited with status {}\n{combined}",
                output.exit_code
            ))
        }
    }

    fn read(&self, args: &Value) -> Result<String, String> {
        let path = str_arg(args, "path")?;
        let content = self
            .file_content(path)?
            .ok_or_else(|| format!("no such file: {path}"))?;
        // Binary guard (pi-conformance): a NUL byte in the head means this is not
        // text — refuse with a clean error rather than emit garbage.
        let sniff = content.len().min(BINARY_SNIFF_BYTES);
        if content.as_bytes()[..sniff].contains(&0) {
            return Err(format!("cannot read binary file `{path}` as text"));
        }
        let offset = usize_arg(args, "offset");
        let limit = usize_arg(args, "limit");
        read_line_window(&content, offset, limit)
    }

    fn write(&self, args: &Value) -> Result<String, String> {
        let path = str_arg(args, "path")?;
        let content = str_arg(args, "content")?;
        self.store_file(path, content)?;
        Ok(format!("wrote {} bytes to {path}", content.len()))
    }

    fn edit(&self, args: &Value) -> Result<String, String> {
        let path = str_arg(args, "path")?;
        let edits_value = edits_argument(args)?;
        let edits = edits_value
            .as_array()
            .ok_or_else(|| "`edits` must be an array".to_string())?;
        let mut content = self
            .file_content(path)?
            .ok_or_else(|| format!("no such file: {path}"))?;
        // A UTF-8 BOM is invisible in the model's view: strip it before matching
        // so an edit anchored at the file start applies, restore it on write.
        const BOM: &str = "\u{feff}";
        let had_bom = content.starts_with(BOM);
        if had_bom {
            content = content[BOM.len()..].to_string();
        }
        // Regions already rewritten, in current-content coordinates. A later edit
        // whose match intersects one is editing an earlier edit's output.
        let mut replaced: Vec<(usize, std::ops::Range<usize>)> = Vec::new();
        let mut applied = 0usize;
        for (index, edit) in edits.iter().enumerate() {
            let old = str_arg(edit, "oldText")?;
            let new = str_arg(edit, "newText")?;
            if old.is_empty() {
                return Err(format!("edit {index}: oldText must not be empty"));
            }
            let matches = content.matches(old).count();
            if matches == 0 {
                return Err(format!("edit {index}: oldText not found in `{path}`"));
            }
            if matches > 1 {
                return Err(format!(
                    "edit {index}: oldText matches {matches} times in `{path}`; make it unique"
                ));
            }
            let start = content
                .find(old)
                .ok_or_else(|| format!("edit {index}: oldText not found in `{path}`"))?;
            let end = start + old.len();
            for (earlier, region) in &replaced {
                if start < region.end && region.start < end {
                    return Err(format!(
                        "edit {earlier} and edit {index} overlap in `{path}`; merge them \
                         into one edit or target disjoint regions"
                    ));
                }
            }
            content.replace_range(start..end, new);
            let delta = new.len() as isize - old.len() as isize;
            for (_, region) in replaced.iter_mut() {
                if region.start >= end {
                    region.start = (region.start as isize + delta) as usize;
                    region.end = (region.end as isize + delta) as usize;
                }
            }
            replaced.push((index, start..start + new.len()));
            applied += 1;
        }
        let output = if had_bom {
            format!("{BOM}{content}")
        } else {
            content
        };
        self.store_file(path, &output)?;
        Ok(format!("applied {applied} edit(s) to {path}"))
    }

    /// List `files` keys under a prefix (flat-key `ls`): keys starting with the
    /// given path, or all keys when none is given. Sorted, capped.
    fn ls(&self, args: &Value) -> Result<String, String> {
        let prefix = directory_prefix(optional_str_arg(args, "path"));
        let limit = usize_arg(args, "limit").unwrap_or(500);
        let mut entries = BTreeSet::new();
        for key in self.all_keys()? {
            let Some(relative) = key.strip_prefix(&prefix) else {
                continue;
            };
            if relative.is_empty() {
                continue;
            }
            match relative.split_once('/') {
                Some((directory, _)) => {
                    entries.insert(format!("{directory}/"));
                }
                None => {
                    entries.insert(relative.to_owned());
                }
            }
        }
        Ok(entries
            .into_iter()
            .take(limit)
            .collect::<Vec<_>>()
            .join("\n"))
    }

    /// Find `files` keys matching a glob pattern (flat-key `find`): the classic
    /// `*`-wildcard match over the key, optionally prefix-filtered by `path`.
    fn find(&self, args: &Value) -> Result<String, String> {
        let pattern = str_arg(args, "pattern")?;
        let prefix = directory_prefix(optional_str_arg(args, "path"));
        let limit = usize_arg(args, "limit").unwrap_or(1000);
        let mut hits: Vec<String> = self
            .all_keys()?
            .into_iter()
            .filter(|key| key.starts_with(&prefix) && glob_match(pattern, key))
            .collect();
        hits.truncate(limit);
        if hits.is_empty() {
            Ok("No files found".to_string())
        } else {
            Ok(hits.join("\n"))
        }
    }

    /// Search line contents across `files` rows (flat-key `grep`): emit
    /// `key:lineno:line` for matches (and `key-lineno-line` for context lines),
    /// per-line char cap, match-count limit. A valid pattern is a regular
    /// expression; an invalid pattern falls back to a literal substring so a
    /// pasted code fragment remains searchable.
    fn grep(&self, args: &Value) -> Result<String, String> {
        let pattern = str_arg(args, "pattern")?;
        let prefix = directory_prefix(optional_str_arg(args, "path"));
        let ignore_case = args
            .get("ignoreCase")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let limit = usize_arg(args, "limit").unwrap_or(100);
        let context = usize_arg(args, "context").unwrap_or(0);
        let matcher = GrepMatcher::new(pattern, ignore_case);
        let keys: Vec<String> = self
            .all_keys()?
            .into_iter()
            .filter(|key| key.starts_with(&prefix))
            .collect();
        let mut hits: Vec<String> = Vec::new();
        let mut matches_found = 0usize;
        for key in keys {
            if matches_found >= limit {
                break;
            }
            let Some(content) = self.file_content(&key)? else {
                continue;
            };
            let lines: Vec<&str> = content.lines().collect();
            let matched: Vec<bool> = lines.iter().map(|line| matcher.is_match(line)).collect();
            // The match limit counts matches; context lines ride along free.
            // Overlapping context windows are merged (each line emitted once).
            let mut emit: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
            for (index, &hit) in matched.iter().enumerate() {
                if !hit {
                    continue;
                }
                if matches_found >= limit {
                    break;
                }
                matches_found += 1;
                let from = index.saturating_sub(context);
                let to = (index + context).min(lines.len().saturating_sub(1));
                emit.extend(from..=to);
            }
            for index in emit {
                let line = cap_grep_line(lines[index]);
                if matched[index] {
                    hits.push(format!("{key}:{}:{line}", index + 1));
                } else {
                    hits.push(format!("{key}-{}-{line}", index + 1));
                }
            }
        }
        if hits.is_empty() {
            Ok("No matches".to_string())
        } else {
            Ok(hits.join("\n"))
        }
    }

    /// Read a content-addressed blob from `content_blobs` by its id/hash (RC-1
    /// history / captured tool output). Optional 1-based line offset/limit page
    /// through a large blob.
    fn recall(&self, args: &Value) -> Result<String, String> {
        let id = str_arg(args, "id")?;
        let body = self
            .store()
            .get_content(id)
            .map_err(|error| format!("recall failed: {error:?}"))?
            .ok_or_else(|| format!("no stored output with id `{id}`"))?;
        let offset = usize_arg(args, "offset");
        let limit = usize_arg(args, "limit");
        Ok(slice_lines(&body, offset, limit))
    }

    // -- tracker todos over the DO WorkItems surface -----------------------

    fn add_todo(&self, args: &Value) -> Result<String, String> {
        let content = str_arg(args, "content")?;
        let holder = format!("agent:{DO_TRACKER_HOLDER}");
        let item = self
            .store()
            .file_item(
                DO_TRACKER_QUEUE,
                content,
                "",
                &[],
                &json!({}),
                Some(&holder),
            )
            .map_err(|error| format!("file_item: {error:?}"))?;
        Ok(json!({ "id": item.id }).to_string())
    }

    fn list_todos(&self, args: &Value) -> Result<String, String> {
        let status_filter = args
            .get("status")
            .and_then(Value::as_str)
            .map(todo_to_item_status);
        let items = self
            .store()
            .list_items(Some(DO_TRACKER_QUEUE), status_filter.as_deref())
            .map_err(|error| format!("list_items: {error:?}"))?;
        let rows: Vec<Value> = items
            .iter()
            .map(|item| {
                json!({
                    "id": item.id,
                    "content": item.title,
                    "status": item_to_todo_status(&item.status),
                    "source": if item.filed_by.as_deref().is_some_and(|f| f.starts_with("agent")) {
                        "agent"
                    } else {
                        "rule"
                    },
                })
            })
            .collect();
        Ok(Value::Array(rows).to_string())
    }

    fn update_todo(&self, args: &Value) -> Result<String, String> {
        let id = str_arg(args, "id")?;
        let status = str_arg(args, "status")?;
        let holder = format!("agent:{DO_TRACKER_HOLDER}");
        let mut store = self.store();
        match status {
            // Parity with the native tool: the lease outcome IS the answer. A
            // claim refused because another holder — a workflow instance, a
            // native actor on the same store — has the item must reach the
            // model, or it works an item it does not own. Re-claiming what this
            // holder already has stays idempotent.
            "in_progress" => match store
                .claim_item(id, &holder, None)
                .map_err(|error| format!("claim: {error:?}"))?
            {
                ClaimOutcome::Claimed => {}
                ClaimOutcome::AlreadyClaimed { holder: current } if current == holder => {}
                ClaimOutcome::AlreadyClaimed { holder: current } => {
                    return Err(format!("`{id}` is already claimed by {current}"));
                }
                ClaimOutcome::NotFound => return Err(format!("`{id}` was not found")),
            },
            // Holder-scoped, at parity with the native path
            // (`tracker-lease.maude` I4): closing releases the lease, so an
            // unguarded close ends work another holder is still doing.
            "completed" => match store
                .finish_item(id, None, Some(&holder))
                .map_err(|error| format!("finish: {error:?}"))?
            {
                FinishOutcome::Finished => {}
                FinishOutcome::NotOpen => {
                    return Err(format!("`{id}` is not open (missing, or already closed)"));
                }
                FinishOutcome::HeldByOther { holder: current } => {
                    return Err(format!(
                        "`{id}` is claimed by {current}, so this turn cannot close it"
                    ));
                }
            },
            // A release with no active lease stays a no-op success, as natively:
            // the requested end state — this holder holding nothing — holds. A
            // lease held by another holder is refused, also as natively: a
            // refusal enforced on only one host is one an agent evades by
            // running on the other.
            "pending" => match store
                .release_item(id, Some(&holder))
                .map_err(|error| format!("release: {error:?}"))?
            {
                ReleaseOutcome::Released | ReleaseOutcome::NotHeld => {}
                ReleaseOutcome::HeldByOther { holder: current } => {
                    return Err(format!(
                        "`{id}` is claimed by {current}, so this turn cannot release it"
                    ));
                }
            },
            other => return Err(format!("unknown status `{other}`")),
        }
        Ok(json!({ "id": id, "status": status }).to_string())
    }
}

impl<Sql: DoSql> DoToolExecutor<Sql> {
    /// Cap a tool output at [`DEFAULT_MAX_BYTES`], capturing the FULL output
    /// content-addressed first so the truncation footer can hand the model a
    /// `recall` id (mirrors native `cap_and_capture`). A small output is returned
    /// unchanged and nothing is captured.
    fn cap_and_capture(&self, text: &str) -> String {
        if text.len() <= DEFAULT_MAX_BYTES {
            return text.to_string();
        }
        // Capture the full bytes so `recall id=<id>` can page through them; on a
        // capture failure fall back to an id-less truncation (still honest).
        let id = self.store().put_content(text).ok();
        middle_truncate(text, DEFAULT_MAX_BYTES, id.as_deref())
    }
}

impl<Sql: DoSql> ToolExecutor for DoToolExecutor<Sql> {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        // The kernel runs tools without yielding to the shell, so this is the
        // only point at which "a tool is running, and it is this one" is true
        // and reportable (DR 0061). The name is the whole value: a turn that
        // sits for ten seconds reads very differently as "running a command"
        // than as an unexplained pause.
        self.sql.activity("running_tool", Some(&call.name));
        match self.dispatch(call) {
            Ok(content) => ToolOutcome {
                status: ToolStatus::Ok,
                content: self.cap_and_capture(&content),
            },
            // A tool error is an informative result, not a Rust error: the model
            // sees it and retries (anti-idempotence, DR-0024). Errors are capped
            // id-less — an error message is not evidence worth capturing.
            Err(message) => ToolOutcome {
                status: ToolStatus::Error,
                content: middle_truncate(&message, DEFAULT_MAX_BYTES, None),
            },
        }
    }
}

// -- argument + formatting helpers (mirror native `harness_tools.rs`) --------

/// The text of a `SqlValue` scalar (empty for non-text), local mirror of the
/// do_store helper so this module does not reach into store internals.
fn as_text(value: &SqlValue) -> String {
    match value {
        SqlValue::Text(s) => s.clone(),
        _ => String::new(),
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing required string argument `{key}`"))
}

fn optional_str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

/// Convert an optional directory argument into an unambiguous flat-key prefix.
/// The trailing slash prevents `references` from also selecting `references2`.
fn directory_prefix(path: Option<&str>) -> String {
    let path = path.unwrap_or(".").trim();
    if path.is_empty() || path == "." {
        String::new()
    } else {
        format!("{}/", path.trim_end_matches('/'))
    }
}

fn usize_arg(args: &Value, key: &str) -> Option<usize> {
    args.get(key)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
}

/// Native and DO grep share the same forgiving contract: compile a real regex
/// when possible and treat invalid regex syntax as the literal text users often
/// paste from source files.
enum GrepMatcher {
    Regex(regex::Regex),
    Literal { needle: String, ignore_case: bool },
}

impl GrepMatcher {
    fn new(pattern: &str, ignore_case: bool) -> Self {
        match regex::RegexBuilder::new(pattern)
            .case_insensitive(ignore_case)
            .build()
        {
            Ok(regex) => Self::Regex(regex),
            Err(_) => Self::Literal {
                needle: if ignore_case {
                    pattern.to_lowercase()
                } else {
                    pattern.to_owned()
                },
                ignore_case,
            },
        }
    }

    fn is_match(&self, line: &str) -> bool {
        match self {
            Self::Regex(regex) => regex.is_match(line),
            Self::Literal {
                needle,
                ignore_case,
            } => {
                if *ignore_case {
                    line.to_lowercase().contains(needle)
                } else {
                    line.contains(needle)
                }
            }
        }
    }
}

/// Resolve the `edits` argument with pi's tolerance: a real array, an array
/// double-encoded as a JSON string, or the legacy single-edit top-level shape.
fn edits_argument(args: &Value) -> Result<Value, String> {
    match args.get("edits") {
        Some(Value::Array(items)) => Ok(Value::Array(items.clone())),
        Some(Value::String(raw)) => {
            let parsed: Value = serde_json::from_str(raw)
                .map_err(|e| format!("`edits` is a string but not valid JSON: {e}"))?;
            if parsed.is_array() {
                Ok(parsed)
            } else {
                Err("`edits` must be an array".to_string())
            }
        }
        Some(_) => Err("`edits` must be an array".to_string()),
        None => match (
            optional_str_arg(args, "oldText"),
            optional_str_arg(args, "newText"),
        ) {
            (Some(old), Some(new)) => Ok(json!([{ "oldText": old, "newText": new }])),
            _ => Err("`edits` must be an array".to_string()),
        },
    }
}

/// Cap a single grep output line at [`GREP_MAX_LINE_CHARS`] characters
/// (char-boundary safe), marking the cut.
fn cap_grep_line(line: &str) -> String {
    match line.char_indices().nth(GREP_MAX_LINE_CHARS) {
        Some((byte_index, _)) => format!("{}... [truncated]", &line[..byte_index]),
        None => line.to_string(),
    }
}

/// Apply the `read` line window: a 1-based `offset`, an explicit `limit`, or the
/// default [`DEFAULT_READ_LINE_LIMIT`]-line window. Head truncation appends a
/// continuation notice; an offset past the end of the file is an error.
fn read_line_window(
    content: &str,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<String, String> {
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    if let Some(requested) = offset {
        if requested > total {
            return Err(format!(
                "Offset {requested} is beyond end of file ({total} lines total)"
            ));
        }
    }
    let start = offset.unwrap_or(1).max(1) - 1;
    let window = limit.unwrap_or(DEFAULT_READ_LINE_LIMIT);
    let end = (start + window).min(total);
    let mut out = lines[start..end].join("\n");
    let remaining = total - end;
    if remaining > 0 {
        if limit.is_some() {
            out.push_str(&format!(
                "\n[{remaining} more lines in file. Use offset={} to continue.]",
                end + 1
            ));
        } else {
            out.push_str(&format!(
                "\n[Showing lines {}-{end} of {total}. Use offset={} to continue.]",
                start + 1,
                end + 1
            ));
        }
    }
    Ok(out)
}

/// Apply a 1-based line offset and a line limit to blob content (for `recall`).
fn slice_lines(content: &str, offset: Option<usize>, limit: Option<usize>) -> String {
    if offset.is_none() && limit.is_none() {
        return content.to_string();
    }
    let start = offset.unwrap_or(1).saturating_sub(1);
    let lines: Vec<&str> = content.lines().collect();
    let end = match limit {
        Some(limit) => (start + limit).min(lines.len()),
        None => lines.len(),
    };
    if start >= lines.len() {
        return String::new();
    }
    lines[start..end].join("\n")
}

/// Middle-truncate a tool output to at most ~`max_bytes` (deterministic,
/// always-on capture-time cap): keep a head and a tail with an elision marker
/// between. A small output is returned unchanged. When `recall_id` is present
/// the full bytes were captured content-addressed and the footer tells the model
/// how to page through them with the `recall` tool.
fn middle_truncate(text: &str, max_bytes: usize, recall_id: Option<&str>) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let keep = max_bytes.saturating_sub(128);
    let head_len = keep / 2;
    let tail_len = keep - head_len;
    let mut head_end = head_len.min(text.len());
    while head_end > 0 && !text.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = text.len().saturating_sub(tail_len);
    while tail_start < text.len() && !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    let elided = tail_start.saturating_sub(head_end);
    let footer = match recall_id {
        Some(id) => format!(
            "[... {elided} of {} bytes elided; recall id={id} for the full output ...]",
            text.len()
        ),
        None => format!("[... {elided} of {} bytes elided ...]", text.len()),
    };
    format!("{}\n{footer}\n{}", &text[..head_end], &text[tail_start..])
}

/// Map a TodoWrite-style status to the builtin tracker's item status.
fn todo_to_item_status(todo: &str) -> String {
    match todo {
        "pending" => "open",
        "in_progress" => "in_progress",
        "completed" => "closed",
        other => other,
    }
    .to_string()
}

/// Map a tracker issue status back to the TodoWrite-style status.
fn item_to_todo_status(item: &str) -> &'static str {
    match item {
        "in_progress" => "in_progress",
        "closed" | "canceled" | "archived" => "completed",
        _ => "pending",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::do_store::test_support::store;
    use whipplescript_kernel::harness_loop::ToolCall;

    /// Build an executor over a fresh schema-applied DO SQLite (the same test
    /// handle the store tests use), sharing the `Rc` the way `create` does.
    fn executor() -> DoToolExecutor<crate::do_store::test_support::RusqliteDoSql> {
        DoToolExecutor::new(Rc::new(store().sql))
    }

    fn call(name: &str, arguments: Value) -> ToolCall {
        ToolCall {
            id: "tc".into(),
            name: name.into(),
            arguments,
        }
    }

    /// A `DoSql` that records the live-turn observations published through it,
    /// forwarding the SQL itself to a real handle so tools still run.
    struct RecordingSql {
        inner: crate::do_store::test_support::RusqliteDoSql,
        activity: std::cell::RefCell<Vec<(String, Option<String>)>>,
    }

    impl DoSql for RecordingSql {
        fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
            self.inner.execute(sql, params)
        }
        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            self.inner.query(sql, params)
        }
        fn activity(&self, kind: &str, detail: Option<&str>) {
            self.activity
                .borrow_mut()
                .push((kind.to_owned(), detail.map(str::to_owned)));
        }
    }

    #[test]
    fn every_dispatched_tool_announces_itself_by_name_before_it_runs() {
        let sql = Rc::new(RecordingSql {
            inner: store().sql,
            activity: std::cell::RefCell::new(Vec::new()),
        });
        let executor = DoToolExecutor::new(Rc::clone(&sql));

        executor.execute(&call(
            "write",
            serde_json::json!({
                "path": "note.txt",
                "content": "hello",
            }),
        ));
        executor.execute(&call("read", serde_json::json!({ "path": "note.txt" })));
        // A tool that fails still ran, so it is still announced — the reader was
        // waiting through it either way.
        executor.execute(&call("read", serde_json::json!({ "path": "absent.txt" })));

        assert_eq!(
            sql.activity.borrow().as_slice(),
            &[
                ("running_tool".to_owned(), Some("write".to_owned())),
                ("running_tool".to_owned(), Some("read".to_owned())),
                ("running_tool".to_owned(), Some("read".to_owned())),
            ],
            "the kernel runs tools without yielding, so this announcement is the \
             only point at which a host can say which tool is running",
        );
    }

    #[test]
    fn do_workspace_tool_schemas_are_the_kernel_registry_schemas() {
        let expected = workspace_tool_specs_from_registry(true, true, true);
        let actual = do_tool_specs();
        for expected_tool in expected {
            let actual_tool = actual
                .iter()
                .find(|tool| tool.name == expected_tool.name)
                .expect("DO advertises every admitted workspace tool");
            assert_eq!(actual_tool, &expected_tool);
        }
    }

    #[test]
    fn write_then_read_round_trips() {
        let exec = executor();
        let out = exec.execute(&call(
            "write",
            json!({ "path": "a.txt", "content": "hello" }),
        ));
        assert_eq!(out.status, ToolStatus::Ok);
        assert!(out.content.contains("wrote 5 bytes to a.txt"));

        let read = exec.execute(&call("read", json!({ "path": "a.txt" })));
        assert_eq!(read.status, ToolStatus::Ok);
        assert_eq!(read.content, "hello");
    }

    #[test]
    fn governed_host_instances_do_not_share_workspace_keys() {
        let sql = Rc::new(store().sql);
        let first = DoToolExecutor::for_instance(Rc::clone(&sql), "instance-a");
        let second = DoToolExecutor::for_instance(sql, "instance-b");
        assert_eq!(
            first
                .execute(&call(
                    "write",
                    json!({ "path": "same.txt", "content": "a" })
                ))
                .status,
            ToolStatus::Ok,
        );
        assert_eq!(
            second
                .execute(&call("read", json!({ "path": "same.txt" })))
                .status,
            ToolStatus::Error,
        );
        second.execute(&call(
            "write",
            json!({ "path": "same.txt", "content": "b" }),
        ));
        assert_eq!(
            first
                .execute(&call("read", json!({ "path": "same.txt" })))
                .content,
            "a",
        );
        assert_eq!(
            second
                .execute(&call("read", json!({ "path": "same.txt" })))
                .content,
            "b",
        );
    }

    #[test]
    fn write_captures_rc1_history_blob() {
        let exec = executor();
        exec.execute(&call(
            "write",
            json!({ "path": "a.txt", "content": "history me" }),
        ));
        // The body is captured content-addressed, recallable by its id.
        let id = exec
            .store()
            .put_content("history me")
            .expect("hash the same bytes");
        let recalled = exec.execute(&call("recall", json!({ "id": id })));
        assert_eq!(recalled.status, ToolStatus::Ok);
        assert_eq!(recalled.content, "history me");
    }

    #[test]
    fn read_windows_a_long_file() {
        let exec = executor();
        let body: String = (1..=50).map(|n| format!("line {n}\n")).collect();
        exec.execute(&call(
            "write",
            json!({ "path": "long.txt", "content": body }),
        ));
        let read = exec.execute(&call(
            "read",
            json!({ "path": "long.txt", "offset": 1, "limit": 10 }),
        ));
        assert_eq!(read.status, ToolStatus::Ok);
        assert!(read.content.starts_with("line 1\nline 2\n"));
        assert!(read.content.contains("line 10"));
        assert!(!read.content.contains("line 11\n"));
        assert!(read.content.contains("more lines in file. Use offset=11"));
    }

    #[test]
    fn read_missing_file_is_an_error_outcome() {
        let exec = executor();
        let read = exec.execute(&call("read", json!({ "path": "nope.txt" })));
        assert_eq!(read.status, ToolStatus::Error);
        assert!(read.content.contains("no such file"));
    }

    #[test]
    fn edit_unique_match_replaces() {
        let exec = executor();
        exec.execute(&call(
            "write",
            json!({ "path": "e.txt", "content": "alpha beta gamma" }),
        ));
        let edit = exec.execute(&call(
            "edit",
            json!({ "path": "e.txt", "edits": [{ "oldText": "beta", "newText": "BETA" }] }),
        ));
        assert_eq!(edit.status, ToolStatus::Ok);
        assert!(edit.content.contains("applied 1 edit(s)"));
        let read = exec.execute(&call("read", json!({ "path": "e.txt" })));
        assert_eq!(read.content, "alpha BETA gamma");
    }

    #[test]
    fn edit_ambiguous_match_is_an_error_outcome() {
        let exec = executor();
        exec.execute(&call(
            "write",
            json!({ "path": "e.txt", "content": "x x x" }),
        ));
        let edit = exec.execute(&call(
            "edit",
            json!({ "path": "e.txt", "edits": [{ "oldText": "x", "newText": "y" }] }),
        ));
        assert_eq!(edit.status, ToolStatus::Error);
        assert!(edit.content.contains("matches 3 times"));
    }

    #[test]
    fn edit_not_found_is_an_error_outcome() {
        let exec = executor();
        exec.execute(&call("write", json!({ "path": "e.txt", "content": "abc" })));
        let edit = exec.execute(&call(
            "edit",
            json!({ "path": "e.txt", "edits": [{ "oldText": "zzz", "newText": "y" }] }),
        ));
        assert_eq!(edit.status, ToolStatus::Error);
        assert!(edit.content.contains("not found"));
    }

    #[test]
    fn ls_lists_immediate_entries_and_keeps_directory_prefixes_distinct() {
        let exec = executor();
        for key in ["src/a.rs", "src/nested/b.rs", "docs/c.md", "src2/d.rs"] {
            exec.execute(&call("write", json!({ "path": key, "content": "x" })));
        }
        let all = exec.execute(&call("ls", json!({})));
        assert_eq!(all.content, "docs/\nsrc/\nsrc2/");
        let under_src = exec.execute(&call("ls", json!({ "path": "src/" })));
        assert_eq!(under_src.content, "a.rs\nnested/");
    }

    #[test]
    fn discovery_reports_the_workspace_walk_ceiling_instead_of_silently_omitting_files() {
        let exec = executor();
        for index in 0..=MAX_FILES_WALKED {
            exec.sql
                .execute(
                    "INSERT INTO files (key, content) VALUES (?1, 'x')",
                    &[SqlValue::Text(format!("file-{index:04}.md"))],
                )
                .expect("seed file");
        }
        let result = exec.execute(&call("find", json!({ "pattern": "*.md" })));
        assert_eq!(result.status, ToolStatus::Error);
        assert!(result.content.contains("supported 5000 files"));
    }

    #[test]
    fn find_matches_a_glob_pattern() {
        let exec = executor();
        for key in ["src/a.rs", "src/b.rs", "docs/c.md"] {
            exec.execute(&call("write", json!({ "path": key, "content": "x" })));
        }
        let hits = exec.execute(&call("find", json!({ "pattern": "src/*.rs" })));
        assert_eq!(hits.status, ToolStatus::Ok);
        assert_eq!(hits.content, "src/a.rs\nsrc/b.rs");
        let none = exec.execute(&call("find", json!({ "pattern": "*.toml" })));
        assert_eq!(none.content, "No files found");
    }

    #[test]
    fn grep_emits_key_lineno_line_matches() {
        let exec = executor();
        exec.execute(&call(
            "write",
            json!({ "path": "f.txt", "content": "one\ntwo needle\nthree" }),
        ));
        exec.execute(&call(
            "write",
            json!({ "path": "g.txt", "content": "no hits here" }),
        ));
        let hits = exec.execute(&call("grep", json!({ "pattern": "needle" })));
        assert_eq!(hits.status, ToolStatus::Ok);
        assert_eq!(hits.content, "f.txt:2:two needle");
        let miss = exec.execute(&call("grep", json!({ "pattern": "absent" })));
        assert_eq!(miss.content, "No matches");
    }

    #[test]
    fn grep_supports_regex_case_context_and_exact_directory_scope() {
        let exec = executor();
        for (path, content) in [
            (
                ".agents/skills/theory-a/references/core.md",
                "before\nCoordination cost falls\nafter",
            ),
            (
                ".agents/skills/theory-a/references2/noise.md",
                "COORDINATION cost rises",
            ),
        ] {
            exec.execute(&call("write", json!({ "path": path, "content": content })));
        }
        let hits = exec.execute(&call(
            "grep",
            json!({
                "pattern": "coordination\\s+cost (falls|drops)",
                "path": ".agents/skills/theory-a/references",
                "ignoreCase": true,
                "context": 1,
                "limit": 1
            }),
        ));
        assert_eq!(hits.status, ToolStatus::Ok);
        assert!(hits.content.contains("core.md:2:Coordination cost falls"));
        assert!(hits.content.contains("core.md-1-before"));
        assert!(hits.content.contains("core.md-3-after"));
        assert!(!hits.content.contains("references2"));
    }

    #[test]
    fn invalid_grep_regex_falls_back_to_literal_text() {
        let exec = executor();
        exec.execute(&call(
            "write",
            json!({ "path": "code.md", "content": "Use value[0] exactly." }),
        ));
        let hits = exec.execute(&call("grep", json!({ "pattern": "value[0" })));
        assert_eq!(hits.status, ToolStatus::Ok);
        assert_eq!(hits.content, "code.md:1:Use value[0] exactly.");
    }

    #[test]
    fn read_only_panel_can_discover_and_read_a_progressively_disclosed_skill() {
        let exec = executor();
        for (path, content) in [
            (
                ".agents/skills/theory-a/SKILL.md",
                "---\nname: theory-a\ndescription: Explain AI-native operating models.\n---\nRead the relevant reference before answering.",
            ),
            (
                ".agents/skills/theory-a/references/governance.md",
                "# Governance\nDecision rights move toward the best available information.",
            ),
            (
                ".agents/skills/theory-a/references/operating-model.md",
                "# Operating model\nCoordination becomes a designed information flow.",
            ),
        ] {
            exec.execute(&call(
                "write",
                json!({ "path": path, "content": content }),
            ));
        }

        let read_only_names = workspace_tool_specs_from_registry(true, false, false)
            .into_iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>();
        assert_eq!(read_only_names, ["read", "grep", "find", "ls", "recall"]);

        let references = exec.execute(&call(
            "find",
            json!({
                "path": ".agents/skills/theory-a/references",
                "pattern": "**/*.md"
            }),
        ));
        assert!(references.content.contains("governance.md"));
        assert!(references.content.contains("operating-model.md"));

        let match_ = exec.execute(&call(
            "grep",
            json!({
                "path": ".agents/skills/theory-a/references",
                "pattern": "decision rights",
                "ignoreCase": true
            }),
        ));
        assert!(match_.content.contains("governance.md:2:"));

        let reference = exec.execute(&call(
            "read",
            json!({ "path": ".agents/skills/theory-a/references/governance.md" }),
        ));
        assert_eq!(
            reference.content,
            "# Governance\nDecision rights move toward the best available information."
        );
    }

    #[test]
    fn recall_reads_a_put_content_blob() {
        let exec = executor();
        let id = exec.store().put_content("blob body").expect("put");
        let recalled = exec.execute(&call("recall", json!({ "id": id })));
        assert_eq!(recalled.status, ToolStatus::Ok);
        assert_eq!(recalled.content, "blob body");
        let missing = exec.execute(&call("recall", json!({ "id": "deadbeef" })));
        assert_eq!(missing.status, ToolStatus::Error);
        assert!(missing.content.contains("no stored output"));
    }

    #[test]
    fn todos_add_list_and_update() {
        let exec = executor();
        let added = exec.execute(&call("add_todo", json!({ "content": "do the thing" })));
        assert_eq!(added.status, ToolStatus::Ok);
        let id = serde_json::from_str::<Value>(&added.content).expect("add_todo json")["id"]
            .as_str()
            .expect("id string")
            .to_owned();

        let listed = exec.execute(&call("list_todos", json!({})));
        assert_eq!(listed.status, ToolStatus::Ok);
        let rows: Value = serde_json::from_str(&listed.content).expect("list json");
        assert_eq!(rows[0]["id"], json!(id));
        assert_eq!(rows[0]["content"], json!("do the thing"));
        assert_eq!(rows[0]["status"], json!("pending"));
        assert_eq!(rows[0]["source"], json!("agent"));

        let updated = exec.execute(&call(
            "update_todo",
            json!({ "id": id, "status": "in_progress" }),
        ));
        assert_eq!(updated.status, ToolStatus::Ok);
        let in_progress = exec.execute(&call("list_todos", json!({ "status": "in_progress" })));
        let rows: Value = serde_json::from_str(&in_progress.content).expect("in_progress json");
        assert_eq!(rows.as_array().expect("array").len(), 1);
        assert_eq!(rows[0]["status"], json!("in_progress"));

        let done = exec.execute(&call(
            "update_todo",
            json!({ "id": id, "status": "completed" }),
        ));
        assert_eq!(done.status, ToolStatus::Ok);
        let completed = exec.execute(&call("list_todos", json!({ "status": "completed" })));
        let rows: Value = serde_json::from_str(&completed.content).expect("completed json");
        assert_eq!(rows.as_array().expect("array").len(), 1);
    }

    /// Parity with the native harness tool: a claim the store refused reaches
    /// the model instead of being reported as a successful `in_progress`. On
    /// the DO the holder is a constant, so the reachable conflict is a lease
    /// held by someone else on the same store — a workflow instance, or a
    /// native actor.
    #[test]
    fn update_todo_surfaces_a_refused_claim_and_a_closed_item() {
        let sql = Rc::new(store().sql);
        let exec = DoToolExecutor::new(Rc::clone(&sql));
        let added = exec.execute(&call("add_todo", json!({ "content": "one job" })));
        assert_eq!(added.status, ToolStatus::Ok, "{}", added.content);
        let id = serde_json::from_str::<Value>(&added.content).expect("add_todo json")["id"]
            .as_str()
            .expect("id string")
            .to_owned();

        // Someone else takes the lease first.
        let mut other = DoSqliteStore::new(Rc::clone(&sql));
        assert!(matches!(
            other.claim_item(&id, "instance:wf-1", None),
            Ok(ClaimOutcome::Claimed)
        ));
        let taken = exec.execute(&call(
            "update_todo",
            json!({ "id": id, "status": "in_progress" }),
        ));
        assert_eq!(taken.status, ToolStatus::Error, "{}", taken.content);
        assert!(
            taken.content.contains("already claimed by instance:wf-1"),
            "{}",
            taken.content
        );

        // A claim on an item that does not exist is not a success either.
        let missing = exec.execute(&call(
            "update_todo",
            json!({ "id": "no-such-item", "status": "in_progress" }),
        ));
        assert_eq!(missing.status, ToolStatus::Error, "{}", missing.content);
        assert!(
            missing.content.contains("was not found"),
            "{}",
            missing.content
        );

        // Nor is CLOSING an item whose lease someone else holds
        // (`tracker-lease.maude` I4). Closing releases the lease, so an
        // unguarded close would end work `instance:wf-1` is still doing —
        // which is exactly what this path did before the holder precondition.
        let stolen = exec.execute(&call(
            "update_todo",
            json!({ "id": id, "status": "completed" }),
        ));
        assert_eq!(stolen.status, ToolStatus::Error, "{}", stolen.content);
        assert!(
            stolen.content.contains("claimed by instance:wf-1"),
            "{}",
            stolen.content
        );
        // And the refusal left it alone rather than half-closing it.
        assert_eq!(
            WorkItems::get_item(&other, &id)
                .expect("get")
                .expect("row")
                .status,
            "in_progress"
        );
        // Releasing another actor's lease is refused for the same reason.
        let unclaim = exec.execute(&call(
            "update_todo",
            json!({ "id": id, "status": "pending" }),
        ));
        assert_eq!(unclaim.status, ToolStatus::Error, "{}", unclaim.content);
        assert!(
            unclaim.content.contains("claimed by instance:wf-1"),
            "{}",
            unclaim.content
        );

        // With the lease cleared through the operator path, the close lands —
        // and closing what is already closed is still the ordinary miss.
        assert_eq!(
            WorkItems::release_item(&mut other, &id, None).expect("operator release"),
            ReleaseOutcome::Released
        );
        let done = exec.execute(&call(
            "update_todo",
            json!({ "id": id, "status": "completed" }),
        ));
        assert_eq!(done.status, ToolStatus::Ok, "{}", done.content);
        let again = exec.execute(&call(
            "update_todo",
            json!({ "id": id, "status": "completed" }),
        ));
        assert_eq!(again.status, ToolStatus::Error, "{}", again.content);
        assert!(again.content.contains("not open"), "{}", again.content);
    }

    #[test]
    fn a_large_tool_output_is_captured_and_recallable_by_its_footer_id() {
        let exec = executor();
        // A file bigger than the output cap: reading it truncates, and the footer
        // hands back a recall id that pages the full bytes.
        let big = "z".repeat(DEFAULT_MAX_BYTES + 500);
        exec.execute(&call("write", json!({ "path": "big.txt", "content": big })));
        let read = exec.execute(&call("read", json!({ "path": "big.txt", "limit": 1 })));
        assert_eq!(read.status, ToolStatus::Ok);
        assert!(read.content.len() <= DEFAULT_MAX_BYTES);
        let id = read
            .content
            .split("recall id=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("footer carries a recall id")
            .to_owned();
        let recalled = exec.execute(&call("recall", json!({ "id": id, "limit": 1 })));
        assert_eq!(recalled.status, ToolStatus::Ok);
        assert!(recalled.content.starts_with("zzz"));
    }

    #[test]
    fn bash_uses_the_do_workspace_and_imports_its_delta() {
        let exec = executor();
        exec.execute(&call(
            "write",
            json!({ "path": "input.txt", "content": "hello\n" }),
        ));
        let out = exec.execute(&call(
            "bash",
            json!({ "command": "cat input.txt | tr a-z A-Z > output.txt" }),
        ));
        assert_eq!(out.status, ToolStatus::Ok);
        let read = exec.execute(&call("read", json!({ "path": "output.txt" })));
        assert_eq!(read.content, "HELLO");
    }

    #[test]
    fn bash_environment_is_closed_and_has_no_host_credentials() {
        let out = executor().execute(&call("bash", json!({ "command": "env" })));
        assert_eq!(out.status, ToolStatus::Ok);
        assert!(out.content.lines().any(|line| line == "HOME=/workspace"));
        for forbidden in [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "WHIP_EXECUTOR_TOKEN",
            "canary-provider-secret",
        ] {
            assert!(
                !out.content.contains(forbidden),
                "virtual bash inherited forbidden host material: {forbidden}"
            );
        }
    }

    #[test]
    fn do_tool_specs_advertises_virtual_bash() {
        let names: Vec<String> = do_tool_specs().into_iter().map(|s| s.name).collect();
        for expected in [
            "read",
            "write",
            "edit",
            "grep",
            "find",
            "ls",
            "recall",
            "list_todos",
            "add_todo",
            "update_todo",
            "bash",
        ] {
            assert!(names.contains(&expected.to_string()), "missing {expected}");
        }
    }
}
