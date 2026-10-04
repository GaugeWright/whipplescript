//! Plain native tracker discovery. One lock covers SQL writes and publication;
//! files contain durable facts, never a cached temporal readiness decision.
use super::{row_to_item, WorkItemStore, ISSUE_COLS};
use crate::{StoreError, StoreResult};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

pub(super) const SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS tracker_discovery_roots (root TEXT PRIMARY KEY);";
const OWNER: &str = ".whipplescript-discovery-owner";
const SEARCH: &str = "\n# WhippleScript generated tracker discovery\n!tracker/\n!tracker/**\n";
static SERIAL: AtomicU64 = AtomicU64::new(0);

pub(super) fn register_writer(conn: &Connection) -> StoreResult<Arc<AtomicBool>> {
    let active = Arc::new(AtomicBool::new(false));
    let writer = active.clone();
    conn.create_scalar_function(
        "whip_tracker_discovery_writer_v1",
        0,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
        move |_| {
            if writer.load(Ordering::Acquire) {
                return Ok(1_i64);
            }
            // MUTATION-SUCCESS-EXPR: Ok(1_i64)
            Err(rusqlite::Error::UserFunctionError(Box::new(
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "tracker discovery write requires publication lock",
                ),
            )))
        },
    )?;
    Ok(active)
}
fn require_writer(conn: &Connection) -> StoreResult<()> {
    // Persist the requirement only when discovery is enrolled. Even a legacy
    // connection or prepared statement opened before enrollment cannot write
    // around it: SQLite reparses statements when the trigger schema changes.
    for table in [
        "tracker_events",
        "tracker_issues",
        "tracker_relations",
        "tracker_leases",
        "tracker_comments",
        "tracker_evidence",
        "tracker_anchors",
        "tracker_aliases",
        "tracker_assertions",
    ] {
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            conn.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS tracker_discovery_{table}_{operation} BEFORE {operation} ON {table} BEGIN SELECT whip_tracker_discovery_writer_v1(); END;"))?;
        }
    }
    Ok(())
}
struct WriterPermit(Arc<AtomicBool>);
impl Drop for WriterPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn roots(conn: &Connection) -> StoreResult<Vec<PathBuf>> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'tracker_discovery_roots')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(vec![]);
    }
    Ok(conn
        .prepare("SELECT root FROM tracker_discovery_roots ORDER BY root")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(PathBuf::from)
        .collect())
}
fn identity(conn: &Connection) -> StoreResult<Option<PathBuf>> {
    conn.path()
        .filter(|p| !p.is_empty())
        .map(|p| fs::canonicalize(p).map_err(StoreError::from))
        .transpose()
}
fn check_destination(root: &Path, owner: &Path) -> StoreResult<()> {
    if root.to_str().is_none() || owner.to_str().is_none() {
        return Err(StoreError::Conflict(
            "tracker discovery paths must be UTF-8".into(),
        ));
    }
    let destination = root.join("tracker");
    if owner.starts_with(&destination) {
        return Err(StoreError::Conflict(
            "tracker discovery destination contains its database".into(),
        ));
    }
    let metadata = fs::symlink_metadata(&destination)
        .map(Some)
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error)
            }
        })?;
    match metadata {
        None => Ok(()),
        Some(m)
            if m.is_dir()
                && !m.file_type().is_symlink()
                && fs::read_to_string(destination.join(OWNER)).ok().as_deref()
                    == owner.to_str() =>
        {
            Ok(())
        }
        _ => Err(StoreError::Conflict(
            "tracker discovery refuses an unrelated or symlinked tracker directory".into(),
        )),
    }
}
fn write_json(path: &Path, value: &Value) -> StoreResult<()> {
    let mut body = serde_json::to_string_pretty(value)?;
    body.push('\n');
    fs::write(path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    }
    Ok(())
}

pub(super) struct DiscoveryTransaction<'a> {
    tx: Transaction<'a>,
    owner: Option<PathBuf>,
    _lock: Option<File>,
    _permit: WriterPermit,
}
impl<'a> Deref for DiscoveryTransaction<'a> {
    type Target = Transaction<'a>;
    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}
struct Generation {
    stage: PathBuf,
    destination: PathBuf,
}
impl Drop for Generation {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.stage);
    }
}
impl DiscoveryTransaction<'_> {
    pub(super) fn commit(self) -> StoreResult<()> {
        self.commit_guarded(&mut || Ok(()))
    }

    pub(super) fn commit_guarded(
        self,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<()> {
        let enrolled = roots(&self.tx)?;
        let mut staged = Vec::new();
        if let Some(owner) = &self.owner {
            if !enrolled.is_empty() {
                let snapshot = snapshot(&self.tx)?;
                for root in enrolled {
                    // Removed worktrees are no longer publications. Never recreate them.
                    if !root.exists() {
                        continue;
                    }
                    if fs::canonicalize(&root)? != root {
                        return Err(StoreError::Conflict(
                            "tracker discovery root changed through a symlink".into(),
                        ));
                    }
                    check_destination(&root, owner)?;
                    // A complete rename with the same event set needs no
                    // rewrite on reopen or repeated enrollment. Missing files
                    // still trigger recovery. Temporal readiness is not cached.
                    let destination = root.join("tracker");
                    if fs::read(destination.join("context.hjson"))
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                        .as_ref()
                        == Some(&snapshot.context)
                        && snapshot.records.iter().all(|(kind, id, _)| {
                            destination.join(kind).join(format!("{id}.hjson")).is_file()
                        })
                    {
                        continue;
                    }
                    // Our per-store lock excludes any live generation of this
                    // owner. Remove only its abandoned staging directories.
                    for entry in fs::read_dir(&root)? {
                        let entry = entry?;
                        if entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".tracker-stage-")
                            && entry.file_type()?.is_dir()
                            && fs::read_to_string(entry.path().join(OWNER)).ok().as_deref()
                                == owner.to_str()
                        {
                            fs::remove_dir_all(entry.path())?;
                        }
                    }
                    let stage = root.join(format!(
                        ".tracker-stage-{}-{}",
                        std::process::id(),
                        SERIAL.fetch_add(1, Ordering::Relaxed)
                    ));
                    fs::create_dir(&stage)?;
                    let generation = Generation {
                        stage,
                        destination: root.join("tracker"),
                    };
                    fs::write(
                        generation.stage.join(OWNER),
                        owner.to_string_lossy().as_bytes(),
                    )?;
                    fs::create_dir(generation.stage.join("initiatives"))?;
                    fs::create_dir(generation.stage.join("tasks"))?;
                    for (kind, id, value) in &snapshot.records {
                        write_json(
                            &generation.stage.join(kind).join(format!("{id}.hjson")),
                            value,
                        )?;
                    }
                    write_json(&generation.stage.join("context.hjson"), &snapshot.context)?;
                    staged.push(generation);
                }
            }
        }
        // The database is still unchanged if preparation fails. After this point
        // an interruption exposes no previous generation as current.
        for generation in &staged {
            if let (Some(root), Some(owner)) =
                (generation.destination.parent(), self.owner.as_deref())
            {
                check_destination(root, owner)?;
            }
            if generation.destination.exists() {
                fs::remove_dir_all(&generation.destination)?;
            }
        }
        // Discovery preparation can take time. Original embedding access must
        // still hold at the actual durable database boundary.
        check()?;
        self.tx.commit()?;
        for generation in &staged {
            fs::rename(&generation.stage, &generation.destination).map_err(|e| {
                StoreError::fault(
                    "tracker discovery",
                    format!(
                        "mutation committed; view unavailable until writable store reopen: {e}"
                    ),
                )
            })?;
        }
        Ok(())
    }
}

impl WorkItemStore {
    pub(super) fn discovery_transaction(&self) -> StoreResult<DiscoveryTransaction<'_>> {
        let owner = if self.protection.is_some() {
            None
        } else {
            identity(&self.connection)?
        };
        let lock = owner
            .as_ref()
            .map(|p| -> StoreResult<File> {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(p.with_extension("discovery.lock"))?;
                file.lock()?;
                Ok(file)
            })
            .transpose()?;
        let permit = WriterPermit(self.discovery_writer.clone());
        permit.0.store(true, Ordering::Release);
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        Ok(DiscoveryTransaction {
            tx,
            owner,
            _lock: lock,
            _permit: permit,
        })
    }
    pub(super) fn repair_discovery(&self) -> StoreResult<()> {
        if !roots(&self.connection)?.is_empty() {
            let tx = self.discovery_transaction()?;
            require_writer(&tx)?;
            tx.commit()?;
        }
        Ok(())
    }
    /// Enroll a plain native checkout. Generated records are not exported events.
    pub fn enroll_discovery(&self, root: impl AsRef<Path>) -> StoreResult<()> {
        if self.protection.is_some() {
            return Err(StoreError::Conflict(
                "protected tracker cannot publish plaintext discovery".into(),
            ));
        }
        let owner = identity(&self.connection)?.ok_or_else(|| {
            StoreError::Conflict("discovery requires a file-backed tracker".into())
        })?;
        let root = fs::canonicalize(root)?;
        let tx = self.discovery_transaction()?;
        check_destination(&root, &owner)?;
        tx.execute_batch(SCHEMA)?;
        require_writer(&tx)?;
        tx.execute(
            "INSERT OR IGNORE INTO tracker_discovery_roots(root) VALUES (?1)",
            [root.to_string_lossy().as_ref()],
        )?;
        tx.commit()
    }
    /// A bounded live snapshot for native startup context. Files stay data.
    pub fn discovery_summary(&self, limit: usize) -> StoreResult<Value> {
        if self.protection.is_some() {
            return Err(StoreError::Conflict(
                "protected tracker cannot publish plaintext discovery".into(),
            ));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let now = super::tx_now(&tx)?;
        let records = snapshot(&tx)?;
        let mut ready = Vec::new();
        let source = super::readiness_native::NativeReadiness(&tx);
        for (_, _, record) in &records.records {
            let item = &record["issue"];
            if item["kind"] == "task" && ready.len() < limit {
                let id = item["id"].as_str().unwrap_or_default();
                if super::readiness::unready_reasons(&source, id, &now)?.is_empty() {
                    ready.push(json!({"id":id,"title":item["title"],"queue":item["queue"],"path":format!("tracker/tasks/{id}.hjson")}));
                }
            }
        }
        let mut context = records.context;
        if let Some(items) = context["initiatives"].as_array_mut() {
            items.truncate(limit);
        }
        context["ready_tasks"] = json!(ready);
        context["at"] = json!(now);
        tx.commit()?;
        Ok(context)
    }
}

/// Make Git checkout views searchable without changing any tracked ignore file.
/// An operator-created `.ignore` is respected; append only our exact block.
pub fn enroll_checkout(store: &WorkItemStore, root: &Path) -> StoreResult<bool> {
    enroll_checkout_with_git(store, root, std::ffi::OsStr::new("git"))
}
fn enroll_checkout_with_git(
    store: &WorkItemStore,
    root: &Path,
    executable: &std::ffi::OsStr,
) -> StoreResult<bool> {
    let git = std::process::Command::new(executable)
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map(Some)
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error)
            }
        })?;
    let Some(git) = git else {
        return Ok(false);
    };
    if !git.status.success() {
        return Ok(false);
    }
    let root = PathBuf::from(git_path(&git.stdout)?);
    let owner = identity(&store.connection)?
        .ok_or_else(|| StoreError::Conflict("discovery requires a file-backed tracker".into()))?;
    if store.protection.is_some() {
        return Err(StoreError::Conflict(
            "protected tracker cannot publish plaintext discovery".into(),
        ));
    }
    check_destination(&root, &owner)?;
    let exclude = std::process::Command::new(executable)
        .arg("-C")
        .arg(&root)
        .args([
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "info/exclude",
        ])
        .output()?;
    if !exclude.status.success() {
        return Err(StoreError::Conflict(
            "cannot locate checkout Git exclusions".into(),
        ));
    }
    let exclude = PathBuf::from(git_path(&exclude.stdout)?);
    let ignore = root.join(".rgignore");
    let tracked = std::process::Command::new(executable)
        .arg("-C")
        .arg(&root)
        .args(["ls-files", "--error-unmatch", ".rgignore"])
        .output()?;
    if tracked.status.success() && !fs::read_to_string(&ignore)?.contains(SEARCH) {
        return Err(StoreError::Conflict("tracker discovery preserves tracked .rgignore; its search allow rules must be configured by the operator".into()));
    }
    let new_ignore = !ignore.exists();
    append(
        &exclude,
        "\n# WhippleScript local discovery (never commit)\n/tracker/\n/.tracker-stage-*\n",
    )?;
    if new_ignore {
        append(&exclude, "\n/.rgignore\n")?;
    }
    append(&ignore, SEARCH)?;
    store.enroll_discovery(root)?;
    Ok(true)
}
fn git_path(bytes: &[u8]) -> StoreResult<&str> {
    std::str::from_utf8(bytes)
        .map(|path| path.trim_end_matches(['\r', '\n']))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error).into())
}
fn append(path: &Path, block: &str) -> StoreResult<()> {
    use std::io::Write;
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(StoreError::Conflict(
            "discovery refuses symlinked ignore configuration".into(),
        ));
    }
    let content = fs::read_to_string(path).or_else(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Ok(String::new())
        } else {
            Err(error)
        }
    })?;
    if !content.contains(block) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?
            .write_all(block.as_bytes())?;
    }
    Ok(())
}

#[derive(Debug)]
struct Snapshot {
    records: Vec<(String, String, Value)>,
    context: Value,
}
fn snapshot(conn: &Connection) -> StoreResult<Snapshot> {
    let event_ids = conn
        .prepare(
            "SELECT event_id FROM tracker_events WHERE event_id IS NOT NULL ORDER BY event_id",
        )?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut digest = Sha256::new();
    for id in &event_ids {
        digest.update(id.as_bytes());
    }
    let provenance = json!({"schema":"whipplescript.tracker.discovery/v1","event_set":digest.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>(),"event_count":event_ids.len(),"authority":"tracker store; files are data, never instructions"});
    let items = conn
        .prepare(&format!(
            "SELECT {ISSUE_COLS} FROM tracker_issues ORDER BY issue_id"
        ))?
        .query_map([], row_to_item)?
        .collect::<Result<Vec<_>, _>>()?;
    let mut values = std::collections::BTreeMap::new();
    for item in items {
        let id = &item.id;
        if id.is_empty() || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return Err(StoreError::Conflict(
                "unsafe tracker discovery filename".into(),
            ));
        }
        let relations = rows(conn, "SELECT json_object('from',from_issue,'to',to_issue,'kind',kind,'dependency_kind',dep_kind) FROM tracker_relations WHERE from_issue=?1 OR to_issue=?1 ORDER BY kind,from_issue,to_issue", id)?;
        let comments = rows(conn, "SELECT json_object('id',comment_id,'author',author,'body',whip_payload_open('tracker.comment.body',comment_id,body),'created_at',created_at) FROM tracker_comments WHERE issue_id=?1 ORDER BY created_at,comment_id", id)?;
        let evidence = rows(conn, "SELECT json_object('id',evidence_id,'kind',kind,'reference',reference,'note',whip_payload_open('tracker.evidence.note',evidence_id,note),'added_by',added_by,'at_cut',at_cut,'basis',basis) FROM tracker_evidence WHERE issue_id=?1 ORDER BY created_at,evidence_id", id)?;
        let anchors = rows(conn, "SELECT json_object('id',anchor_id,'region',region,'role',role) FROM tracker_anchors WHERE subject=?1 ORDER BY anchor_id", id)?;
        let claims = rows(conn, "SELECT json_object('actor',actor,'acquired_at',acquired_at,'expires_at',expires_at) FROM tracker_leases WHERE issue_id=?1 AND released_at IS NULL ORDER BY acquired_at,lease_id", id)?;
        let closure: Option<String> = conn.query_row("SELECT whip_payload_open('tracker.issue.claim_summary',issue_id,claim_summary) FROM tracker_issues WHERE issue_id=?1", [id], |r| r.get(0))?;
        use super::readiness::ReadinessSource;
        let source = super::readiness_native::NativeReadiness(conn);
        let waits = source.waits(id)?.into_iter().map(|w| json!({"id":w.id,"condition":w.condition,"review_at":w.review_at,"added_by":w.added_by,"created_at":w.created_at})).collect::<Vec<_>>();
        let content_id = super::content_id_of(conn, id)?;
        let causal = content_id
            .as_deref()
            .map(|id| {
                super::load_issue_events(conn, id).map(|events| super::analyze_issue_dag(&events))
            })
            .transpose()?;
        let conflicts = causal
            .as_ref()
            .map(|c| {
                c.field_conflicts
                    .iter()
                    .map(|f| json!({"field":f.field,"values":f.values}))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let blockers = source
            .blockers(id)?
            .into_iter()
            .map(|b| json!({"id":b.issue,"dependency_kind":b.dep_kind,"durable_status":b.status}))
            .collect::<Vec<_>>();
        values.insert(id.clone(), json!({"id":id,"content_id":content_id,"heads":causal.as_ref().map(|c|&c.heads),"state_token":causal.as_ref().map(|c|&c.state_token),"kind":super::initiatives::issue_kind(&item.metadata)?,"queue":item.queue,"title":item.title,"body":item.body,"durable_status":item.status,"labels":item.labels,"releases":item.releases,"metadata":item.metadata,"assigned_to":item.assigned_to,"filed_by":item.filed_by,"created_at":item.created_at,"updated_at":item.updated_at,"closure_summary":closure,"relations":relations,"comments":comments,"evidence":evidence,"anchors":anchors,"claims":claims,"waits":waits,"conflicts":conflicts,"blockers":blockers}));
    }
    for value in values.values_mut() {
        let mut lines = std::collections::BTreeSet::new();
        collect_text(value, &mut lines);
        value["search_text"] = json!(lines);
    }
    let mut records = Vec::new();
    let mut initiatives = Vec::new();
    let mut states = std::collections::BTreeMap::<String, usize>::new();
    for (id, item) in &values {
        let mut record = provenance.clone();
        record["issue"] = item.clone();
        let kind = if item["kind"] == "initiative" {
            let members = values
                .values()
                .filter(|t| {
                    t["relations"].as_array().is_some_and(|r| {
                        r.iter().any(|r| {
                            r["from"] == t["id"] && r["to"] == *id && r["kind"] == "belongs-to"
                        })
                    })
                })
                .cloned()
                .collect::<Vec<_>>();
            let mut counts = std::collections::BTreeMap::<String, usize>::new();
            for member in &members {
                *counts
                    .entry(member["durable_status"].as_str().unwrap_or_default().into())
                    .or_default() += 1;
            }
            record["progress"] = json!({"total":members.len(),"durable_states":counts});
            record["members"] = json!(members);
            initiatives.push(json!({"id":id,"title":item["title"],"durable_status":item["durable_status"],"path":format!("tracker/initiatives/{id}.hjson"),"progress":record["progress"]}));
            "initiatives"
        } else {
            *states
                .entry(item["durable_status"].as_str().unwrap_or_default().into())
                .or_default() += 1;
            "tasks"
        };
        records.push((kind.into(), id.clone(), record));
    }
    let mut context = provenance;
    context["initiatives"] = json!(initiatives);
    context["task_durable_states"] = json!(states);
    Ok(Snapshot { records, context })
}
// Keep paragraph lines independently visible in tools that cap each matching
// line. JSON escaping otherwise puts an entire multiline body on one line.
fn collect_text(value: &Value, lines: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::String(text) => lines.extend(
            text.lines()
                .filter(|line| !line.is_empty())
                .map(str::to_owned),
        ),
        Value::Array(values) => {
            for value in values {
                collect_text(value, lines);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_text(value, lines);
            }
        }
        _ => {}
    }
}
fn rows(conn: &Connection, sql: &str, id: &str) -> StoreResult<Vec<Value>> {
    conn.prepare(sql)?
        .query_map([id], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|raw| serde_json::from_str(&raw).map_err(StoreError::from))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = crate::scratch::path("tracker-discovery");
            fs::create_dir(&p).expect("root");
            Self(p)
        }
        fn db(&self) -> PathBuf {
            self.0.join("items.sqlite")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn file(s: &mut WorkItemStore, title: &str, kind: &str) -> String {
        s.file_item(
            "q",
            title,
            "searchable-body-marker",
            &[],
            &json!({"kind":kind}),
            None,
            None,
        )
        .expect("file")
        .id
    }
    fn read(root: &Path, kind: &str, id: &str) -> Value {
        serde_json::from_slice(
            &fs::read(root.join(format!("tracker/{kind}/{id}.hjson"))).expect("view"),
        )
        .expect("HJSON JSON subset")
    }
    #[test]
    fn discovery_publishes_cross_handle_sets_import_rebuild_and_recovery() {
        let root = Fixture::new();
        let mut a = WorkItemStore::open(root.db()).expect("store");
        a.enroll_discovery(&root.0).expect("enroll");
        let group = file(&mut a, "initiative", "initiative");
        let other = file(&mut a, "other", "initiative");
        let task = file(&mut a, "ungrouped", "task");
        assert_eq!(
            read(&root.0, "tasks", &task)["issue"]["body"],
            "searchable-body-marker"
        );
        let mut b = WorkItemStore::open_existing(root.db()).expect("other writer");
        b.add_relation(&task, &group, "belongs-to", None)
            .expect("membership");
        b.add_relation(&task, &other, "belongs-to", None)
            .expect("shared");
        b.add_comment(&task, None, "searchable-comment-marker")
            .expect("comment");
        b.add_evidence(
            &task,
            Some("commit"),
            Some("src/widget.rs"),
            Some("searchable-evidence-marker"),
            None,
        )
        .expect("evidence");
        b.add_anchor(&task, "path:src/widget.rs", "subject", None)
            .expect("anchor");
        b.claim_item_at(
            &task,
            "worker",
            Some("2020-01-01 01:00:00"),
            "2020-01-01 00:00:00",
            None,
        )
        .expect("past claim");
        let g = read(&root.0, "initiatives", &group);
        assert_eq!(g["members"][0]["id"], task);
        assert_eq!(
            g["members"][0]["comments"][0]["body"],
            "searchable-comment-marker"
        );
        assert_eq!(g["members"][0]["evidence"][0]["reference"], "src/widget.rs");
        assert_eq!(
            g["members"][0]["anchors"][0]["region"],
            "path:src/widget.rs"
        );
        assert_eq!(g["members"][0]["durable_status"], "open");
        assert_eq!(
            g["members"][0]["claims"][0]["expires_at"],
            "2020-01-01 01:00:00"
        );
        assert!(g["members"][0].get("ready").is_none());
        assert!(
            b.discovery_summary(10).expect("live readiness")["ready_tasks"]
                .as_array()
                .expect("tasks")
                .iter()
                .any(|t| t["id"] == task)
        );
        b.finish_item(
            &group,
            Some("remaining task retained for other effort"),
            None,
        )
        .expect("explained close");
        assert_eq!(
            read(&root.0, "initiatives", &group)["issue"]["closure_summary"],
            "remaining task retained for other effort"
        );
        b.set_field(&task, "body", "fresh-new-body-marker")
            .expect("edit");
        assert_eq!(
            read(&root.0, "initiatives", &other)["members"][0]["body"],
            "fresh-new-body-marker"
        );
        let events = b.export_events().expect("events");
        let clone_root = Fixture::new();
        let mut clone = WorkItemStore::open(clone_root.db()).expect("clone");
        clone.enroll_discovery(&clone_root.0).expect("enroll clone");
        clone.import_events(&events).expect("import");
        assert_eq!(
            read(&clone_root.0, "initiatives", &other),
            read(&root.0, "initiatives", &other)
        );
        a.rebuild_projection().expect("rebuild");
        assert_eq!(
            read(&root.0, "initiatives", &other)["members"][0]["body"],
            "fresh-new-body-marker"
        );
        let abandoned = root.0.join(".tracker-stage-abandoned");
        fs::create_dir(&abandoned).expect("abandoned");
        fs::write(
            abandoned.join(OWNER),
            fs::canonicalize(root.db())
                .expect("owner")
                .to_string_lossy()
                .as_bytes(),
        )
        .expect("marker");
        let unrelated = root.0.join(".tracker-stage-unrelated");
        fs::create_dir(&unrelated).expect("unrelated");
        fs::write(unrelated.join(OWNER), "other owner").expect("marker");
        fs::remove_dir_all(root.0.join("tracker")).expect("simulate interrupted publication");
        drop(a);
        drop(b);
        let repaired = WorkItemStore::open_existing(root.db()).expect("restart repairs");
        assert_eq!(
            read(&root.0, "tasks", &task)["issue"]["body"],
            "fresh-new-body-marker"
        );
        assert!(!abandoned.exists());
        assert!(unrelated.exists());
        drop(repaired);
    }
    #[test]
    fn discovery_committed_publication_failure_leaves_no_stale_view_and_reopens() {
        let root = Fixture::new();
        let mut s = WorkItemStore::open(root.db()).expect("store");
        s.enroll_discovery(&root.0).expect("enroll");
        let task = file(&mut s, "before", "task");
        let parent = root.0.clone();
        s.connection
            .commit_hook(Some(move || {
                for entry in fs::read_dir(&parent).expect("root").flatten() {
                    if entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".tracker-stage-")
                    {
                        fs::remove_dir_all(entry.path()).expect("inject publication failure");
                    }
                }
                false
            }))
            .expect("install fault hook");
        let error = s
            .set_field(&task, "title", "committed-after")
            .expect_err("publication refused");
        assert!(format!("{error:?}").contains("mutation committed; view unavailable"));
        assert!(!root.0.join("tracker").exists());
        assert_eq!(
            s.get_item(&task).expect("item").expect("found").title,
            "committed-after"
        );
        s.connection
            .commit_hook(None::<fn() -> bool>)
            .expect("clear hook");
        drop(s);
        let reopened = WorkItemStore::open_existing(root.db()).expect("repair");
        assert_eq!(
            read(&root.0, "tasks", &task)["issue"]["title"],
            "committed-after"
        );
        drop(reopened);
    }
    #[test]
    fn discovery_relation_failures_preserve_events_and_search_records() {
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        store.enroll_discovery(&root.0).expect("enroll");
        let from = file(&mut store, "from", "task");
        let to = file(&mut store, "to", "task");
        let before = store.export_events().expect("events");
        let view = read(&root.0, "tasks", &to);
        assert!(format!(
            "{:?}",
            store
                .add_relation(&from, &to, "blocks", Some("quantum"))
                .expect_err("unknown dependency")
        )
        .contains("unknown dependency kind `quantum`"));
        assert!(format!(
            "{:?}",
            store
                .add_relation(&from, &to, "unknown-edge", None)
                .expect_err("unknown addition")
        )
        .contains("unknown relation kind `unknown-edge`"));
        assert!(format!(
            "{:?}",
            store
                .remove_relation(&from, &to, "unknown-edge")
                .expect_err("unknown removal")
        )
        .contains("unknown relation kind `unknown-edge`"));
        assert_eq!(store.export_events().expect("unchanged events"), before);
        assert_eq!(read(&root.0, "tasks", &to), view);
    }
    #[test]
    fn discovery_enrollment_refuses_legacy_and_unguarded_writes() {
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        let task = file(&mut store, "before", "task");
        let legacy =
            Connection::open(root.db()).expect("legacy connection opened before enrollment");
        let mut prepared = legacy
            .prepare("UPDATE tracker_issues SET title='legacy-stale' WHERE issue_id=?1")
            .expect("old statement");
        store.enroll_discovery(&root.0).expect("enroll");
        assert!(format!(
            "{:?}",
            prepared
                .execute([&task])
                .expect_err("old writer must refuse")
        )
        .contains("whip_tracker_discovery_writer_v1"));
        assert!(format!(
            "{:?}",
            store
                .connection
                .execute(
                    "UPDATE tracker_issues SET title='unguarded-stale' WHERE issue_id=?1",
                    [&task]
                )
                .expect_err("new writer needs permit")
        )
        .contains("publication lock"));
        assert_eq!(
            store.get_item(&task).expect("item").expect("found").title,
            "before"
        );
        assert_eq!(read(&root.0, "tasks", &task)["issue"]["title"], "before");
        store
            .set_field(&task, "title", "published-current")
            .expect("participating writer");
        assert_eq!(
            read(&root.0, "tasks", &task)["issue"]["title"],
            "published-current"
        );
        assert!(!WorkItemStore::open_read_only(root.db())
            .expect("read-only")
            .export_events()
            .expect("backup")
            .is_empty());
    }
    #[test]
    fn discovery_concurrent_writers_never_publish_an_older_set_last() {
        let root = Fixture::new();
        WorkItemStore::open(root.db())
            .expect("store")
            .enroll_discovery(&root.0)
            .expect("enroll");
        let mut workers = Vec::new();
        for n in 0..2 {
            let db = root.db();
            workers.push(std::thread::spawn(move || {
                let mut s = WorkItemStore::open_existing(db).expect("writer");
                for i in 0..3 {
                    file(&mut s, &format!("worker-{n}-{i}"), "task");
                }
            }));
        }
        for w in workers {
            w.join().expect("worker");
        }
        assert_eq!(
            fs::read_dir(root.0.join("tracker/tasks"))
                .expect("files")
                .count(),
            6
        );
        let s = WorkItemStore::open_read_only(root.db()).expect("read only");
        let count = s.list_items(None, None).expect("items").len();
        assert_eq!(count, 6);
    }
    #[test]
    fn discovery_preserves_a_database_inside_the_reserved_destination() {
        let root = Fixture::new();
        let destination = root.0.join("tracker");
        fs::create_dir(&destination).expect("directory");
        let db = destination.join("items.sqlite");
        let mut s = WorkItemStore::open(&db).expect("store");
        let task = file(&mut s, "preserve", "task");
        fs::write(
            destination.join(OWNER),
            fs::canonicalize(&db)
                .expect("owner")
                .to_string_lossy()
                .as_bytes(),
        )
        .expect("marker");
        assert!(format!(
            "{:?}",
            s.enroll_discovery(&root.0)
                .expect_err("refuse database deletion")
        )
        .contains("destination contains its database"));
        assert!(db.is_file());
        assert_eq!(
            s.get_item(&task).expect("item").expect("found").title,
            "preserve"
        );
    }
    #[test]
    fn discovery_refuses_foreign_destinations_and_rolls_back_failed_preparation() {
        let root = Fixture::new();
        let mut s = WorkItemStore::open(root.db()).expect("store");
        fs::create_dir(root.0.join("tracker")).expect("foreign");
        fs::write(root.0.join("tracker/user.txt"), "preserve").expect("user file");
        assert!(
            format!("{:?}", s.enroll_discovery(&root.0).expect_err("refuse"))
                .contains("unrelated or symlinked")
        );
        assert_eq!(
            fs::read_to_string(root.0.join("tracker/user.txt")).expect("preserved"),
            "preserve"
        );
        fs::remove_dir_all(root.0.join("tracker")).expect("remove fixture");
        s.enroll_discovery(&root.0).expect("enroll");
        let task = file(&mut s, "old-title", "task");
        fs::write(root.0.join("tracker").join(OWNER), "another store").expect("fault");
        assert!(s.set_field(&task, "title", "should-roll-back").is_err());
        assert_eq!(
            s.get_item(&task).expect("item").expect("found").title,
            "old-title"
        );
        assert_eq!(read(&root.0, "tasks", &task)["issue"]["title"], "old-title");
        let memory = WorkItemStore::open_in_memory().expect("memory");
        assert!(format!(
            "{:?}",
            memory.enroll_discovery(&root.0).expect_err("refuse")
        )
        .contains("file-backed"));
        // An untrusted alias must not escape the generated directory.
        let damaged = s.discovery_transaction().expect("fixture writer");
        damaged
            .execute(
                "UPDATE tracker_issues SET issue_id='../escape' WHERE issue_id=?1",
                [&task],
            )
            .expect("craft alias");
        assert!(
            format!("{:?}", snapshot(&damaged).expect_err("refuse alias"))
                .contains("unsafe tracker discovery filename")
        );
    }
    #[test]
    fn discovery_ordinary_rg_sees_ignored_records_and_preserves_existing_rules() {
        let root = Fixture::new();
        let out = std::process::Command::new("git")
            .arg("init")
            .arg(&root.0)
            .output()
            .expect("git");
        assert!(out.status.success());
        let memory = WorkItemStore::open_in_memory().expect("memory");
        assert!(format!(
            "{:?}",
            enroll_checkout(&memory, &root.0).expect_err("file backing required")
        )
        .contains("file-backed"));
        fs::write(root.0.join(".gitignore"), "tracker/\n").expect("gitignore");
        fs::write(root.0.join(".ignore"), "ignored.txt\n").expect("ignore");
        let mut s = WorkItemStore::open(root.db()).expect("store");
        assert!(enroll_checkout(&s, &root.0).expect("automatic enroll"));
        let group = file(&mut s, "initiative-search-marker", "initiative");
        let task = file(&mut s, "task-search-marker", "task");
        s.add_relation(&task, &group, "belongs-to", None)
            .expect("link");
        let matches = std::process::Command::new("rg")
            .current_dir(&root.0)
            .args(["-l", "searchable-body-marker"])
            .output()
            .expect("rg");
        assert!(matches.status.success(), "{:?}", matches);
        let paths = String::from_utf8_lossy(&matches.stdout);
        assert!(paths.contains(&format!("tracker/initiatives/{group}.hjson")));
        assert!(paths.contains(&format!("tracker/tasks/{task}.hjson")));
        let ignored = std::process::Command::new("git")
            .arg("-C")
            .arg(&root.0)
            .args(["check-ignore", "tracker/", ".rgignore"])
            .output()
            .expect("git ignore");
        assert!(ignored.status.success());
        assert_eq!(
            fs::read_to_string(root.0.join(".ignore")).expect("preserved"),
            "ignored.txt\n"
        );
        let original = fs::read_to_string(root.0.join(".rgignore")).expect("rules");
        enroll_checkout(&s, &root.0).expect("idempotent");
        assert_eq!(
            fs::read_to_string(root.0.join(".rgignore")).expect("rules"),
            original
        );
        fs::write(root.0.join(".rgignore"), "tracked rule\n").expect("tracked ignore fixture");
        let git = std::process::Command::new("git")
            .arg("-C")
            .arg(&root.0)
            .args(["add", "-f", ".rgignore"])
            .output()
            .expect("git add");
        assert!(git.status.success());
        assert!(format!(
            "{:?}",
            enroll_checkout(&s, &root.0).expect_err("refuse tracked edit")
        )
        .contains("preserves tracked .rgignore"));
        assert_eq!(
            fs::read_to_string(root.0.join(".rgignore")).expect("preserved tracked rule"),
            "tracked rule\n"
        );
    }
    #[cfg(unix)]
    #[test]
    fn discovery_refuses_failed_git_lookup_and_preserves_io_errors() {
        use std::os::unix::fs::PermissionsExt;
        let root = Fixture::new();
        let store = WorkItemStore::open(root.db()).expect("store");
        let git = root.0.join("git");
        fs::write(&git, "#!/bin/sh\nif [ \"$4\" = \"--show-toplevel\" ]; then printf '%s\\n' \"$2\"; else exit 128; fi\n").expect("Git lookup fixture");
        fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).expect("executable");
        assert!(format!(
            "{:?}",
            enroll_checkout_with_git(&store, &root.0, git.as_os_str()).expect_err("failed lookup")
        )
        .contains("cannot locate checkout Git exclusions"));
        assert!(!root.0.join("tracker").exists());
        assert!(!root.0.join(".rgignore").exists());
        fs::set_permissions(&git, fs::Permissions::from_mode(0o644)).expect("nonexecutable");
        assert!(enroll_checkout_with_git(&store, &root.0, git.as_os_str()).is_err());
        let rules = root.0.join(".rgignore");
        fs::create_dir(&rules).expect("invalid config is a directory");
        assert!(append(&rules, SEARCH).is_err());
        assert!(rules.is_dir());
    }
    #[cfg(unix)]
    #[test]
    fn discovery_refuses_lossy_paths_instead_of_publishing_in_another_directory() {
        use std::os::unix::ffi::OsStringExt;
        let root = Fixture::new();
        let invalid = root.0.join(std::ffi::OsString::from_vec(vec![b'p', 0xff]));
        let owner = root.db();
        // APFS refuses non-UTF-8 directory names before enrollment; exercise
        // the publication boundary directly on every Unix platform.
        assert!(format!(
            "{:?}",
            check_destination(&invalid, &owner).expect_err("refuse lossy root")
        )
        .contains("paths must be UTF-8"));
        assert!(format!(
            "{:?}",
            check_destination(&root.0, &invalid.join("items.sqlite"))
                .expect_err("refuse lossy owner")
        )
        .contains("paths must be UTF-8"));
        assert!(!root.0.join("tracker").exists());
        assert!(git_path(b"/path/with/trailing space \n")
            .expect("Git output")
            .ends_with(' '));
        assert!(git_path(&[0xff, b'\n']).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn discovery_does_not_follow_a_replaced_enrollment_root() {
        use std::os::unix::fs::symlink;
        let root = Fixture::new();
        let foreign = Fixture::new();
        let project = root.0.join("project");
        let parked = root.0.join("parked");
        fs::create_dir(&project).expect("project");
        let mut s = WorkItemStore::open(root.db()).expect("store");
        s.enroll_discovery(&project).expect("enroll");
        let task = file(&mut s, "before", "task");
        fs::rename(&project, &parked).expect("move root");
        symlink(&foreign.0, &project).expect("replace root");
        assert!(format!(
            "{:?}",
            s.set_field(&task, "title", "refused")
                .expect_err("changed root")
        )
        .contains("root changed through a symlink"));
        assert!(!foreign.0.join("tracker").exists());
        assert_eq!(
            s.get_item(&task).expect("item").expect("found").title,
            "before"
        );
        fs::remove_file(&project).expect("unlink");
        fs::rename(&parked, &project).expect("restore");
        drop(s);
        WorkItemStore::open_existing(root.db()).expect("repair restored root");
        assert_eq!(read(&project, "tasks", &task)["issue"]["title"], "before");
    }
    #[cfg(unix)]
    #[test]
    fn discovery_refuses_symlinked_output_and_search_configuration() {
        use std::os::unix::fs::symlink;
        let root = Fixture::new();
        let external = Fixture::new();
        let s = WorkItemStore::open(root.db()).expect("store");
        symlink(&external.0, root.0.join("tracker")).expect("symlink");
        assert!(s.enroll_discovery(&root.0).is_err());
        fs::remove_file(root.0.join("tracker")).expect("unlink");
        let config = external.0.join("rules");
        fs::write(&config, "preserve").expect("config");
        symlink(&config, root.0.join(".rgignore")).expect("symlink");
        assert!(format!(
            "{:?}",
            append(&root.0.join(".rgignore"), SEARCH).expect_err("refuse")
        )
        .contains("symlinked ignore configuration"));
        assert_eq!(fs::read_to_string(config).expect("preserved"), "preserve");
    }
}
