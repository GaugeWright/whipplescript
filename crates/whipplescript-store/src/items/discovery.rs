//! Plain native tracker discovery. One lock covers SQL writes and publication;
//! files contain durable facts, never a cached temporal readiness decision.
use super::{row_to_item, WorkItemStore, ISSUE_COLS};
use crate::{StoreError, StoreResult};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
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
const OWNER_MARKER_REFUSAL: &str = "tracker cleanup refuses a symlinked ownership marker";
const VIEW_SCHEMA: &str = "whipplescript.tracker.discovery/v2";
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
    // These triggers are protocol 1: a build without the writer function
    // cannot write past them.
    raise_write_protocol(conn, 1)
}

/// The highest tracker write protocol this build speaks (DR-0186). A store
/// records the protocol its installed write rules require; a write through a
/// build that speaks less is refused before it changes anything, and reads are
/// never refused for it. Raise this, and the store's protocol where the rule is
/// installed, when a change to the write rules would let an older writer
/// fail or write incorrectly.
pub const TRACKER_WRITE_PROTOCOL: i64 = 1;

/// The `UnsupportedVersion` subject of a write refused under a newer protocol.
/// The subject goes on to name the `whip` that raised the protocol.
pub const TRACKER_WRITE_PROTOCOL_SUBJECT: &str = "tracker store write protocol";

const WRITE_PROTOCOL_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS tracker_write_protocol (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version INTEGER NOT NULL,
    raised_by TEXT NOT NULL
);";

/// Only code that installs a write rule raises the protocol. A newer build
/// writing an older store leaves it where it is, so older builds keep writing
/// every store whose rules they understand.
fn raise_write_protocol(conn: &Connection, to: i64) -> StoreResult<()> {
    conn.execute_batch(WRITE_PROTOCOL_SCHEMA)?;
    conn.execute(
        "INSERT INTO tracker_write_protocol (singleton, version, raised_by) VALUES (1, ?1, ?2)
         ON CONFLICT (singleton) DO UPDATE
         SET version = excluded.version, raised_by = excluded.raised_by
         WHERE excluded.version > tracker_write_protocol.version",
        params![to, crate::WRITER_VERSION],
    )?;
    Ok(())
}

/// The refusal a write through this build meets, when the store requires a
/// protocol it does not speak. A store without the table is at protocol 0.
pub(super) fn write_refusal(conn: &Connection) -> StoreResult<Option<StoreError>> {
    let recorded: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'tracker_write_protocol')",
        [],
        |r| r.get(0),
    )?;
    if !recorded {
        return Ok(None);
    }
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT version, raised_by FROM tracker_write_protocol WHERE singleton = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row
        .filter(|(found, _)| *found > TRACKER_WRITE_PROTOCOL)
        .map(|(found, raised_by)| StoreError::UnsupportedVersion {
            subject: format!("{TRACKER_WRITE_PROTOCOL_SUBJECT} (raised by whip {raised_by})"),
            found,
            supported: TRACKER_WRITE_PROTOCOL,
        }))
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
fn render(value: &Value) -> StoreResult<Vec<u8>> {
    let mut body = serde_json::to_string_pretty(value)?;
    body.push('\n');
    Ok(body.into_bytes())
}
fn write_bytes(path: &Path, bytes: &[u8]) -> StoreResult<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What a view has published, written last so that its presence means the
/// view is complete (DR-0187). Hidden from ordinary search.
const MANIFEST: &str = ".manifest.json";
#[derive(serde::Serialize, serde::Deserialize, PartialEq)]
struct Manifest {
    schema: String,
    context: String,
    records: std::collections::BTreeMap<String, String>,
}
fn read_manifest(destination: &Path) -> Option<Manifest> {
    fs::read(destination.join(MANIFEST))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Manifest>(&bytes).ok())
        .filter(|manifest| manifest.schema == VIEW_SCHEMA)
}

pub(super) struct DiscoveryTransaction<'a> {
    tx: Transaction<'a>,
    owner: Option<PathBuf>,
    /// Reopening repairs: confirm every file a manifest names still exists.
    verify: bool,
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
    /// `None` replaces the whole view. Otherwise the files that change and
    /// those whose records left, as paths relative to the view.
    incremental: Option<(Vec<String>, Vec<String>)>,
}
/// Garbage is detached by atomic rename while publication is serialized. Its
/// recursive deletion happens only after both the SQL and publisher locks are
/// released, including when preparation, authority checking or commit fails.
struct DiscoveryCleanup {
    owner: Option<PathBuf>,
    roots: Vec<PathBuf>,
}
struct PendingStages {
    owner: Option<PathBuf>,
    paths: Vec<PathBuf>,
}
impl Drop for PendingStages {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            for stage in &self.paths {
                let _ = retire(stage, owner);
            }
        }
    }
}
/// An ownership write that fails before creating a file leaves an empty stage.
/// Release that stage without recursive work inside publication's critical section.
fn write_stage_owner(stage: &Path, owner: &Path) -> StoreResult<()> {
    if let Err(error) = fs::write(stage.join(OWNER), owner.to_string_lossy().as_bytes()) {
        let _ = fs::remove_dir(stage);
        return Err(error.into());
    }
    Ok(())
}

fn retire(path: &Path, owner: &Path) -> std::io::Result<()> {
    let Some(root) = path.parent() else {
        return Ok(());
    };
    if fs::canonicalize(root)? != root {
        return Err(std::io::Error::other(
            "tracker cleanup root changed through a symlink",
        ));
    }
    let metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        result => result?,
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || fs::read_to_string(path.join(OWNER)).ok().as_deref() != owner.to_str()
    {
        return Err(std::io::Error::other(
            "tracker cleanup refuses an unrelated or symlinked directory",
        ));
    }
    // Reserve a container atomically: PID reuse or a foreign name must never
    // cause rename to replace an existing directory, even an empty one.
    let retired = loop {
        let retired = root.join(format!(
            ".tracker-retired-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&retired) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            result => {
                result?;
                break retired;
            }
        }
    };
    if let Err(error) = fs::rename(path, retired.join("view")) {
        let _ = fs::remove_dir(&retired);
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error)
        };
    }
    // Ownership becomes visible atomically with the payload. A concurrent
    // cleaner may collect it now; no post-rename write depends on it surviving.
    #[cfg(test)]
    RETIRE_TEST_HOOK.with(|hook| {
        if let Some(hook) = &mut *hook.borrow_mut() {
            hook();
        }
    });
    Ok(())
}
fn retired_owned(path: &Path, owner: &Path) -> bool {
    match fs::read_to_string(path.join(OWNER)) {
        Ok(marker) => Some(marker.as_str()) == owner.to_str(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let view = path.join("view");
            fs::symlink_metadata(&view)
                .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                && fs::read_to_string(view.join(OWNER)).ok().as_deref() == owner.to_str()
        }
        Err(_) => false,
    }
}
/// Keep ownership outside the recursively removed payload, so interrupted or
/// refused deletion can be retried without borrowing publication's lock.
fn collect_retired(path: &Path, owner: &Path) -> std::io::Result<()> {
    let marker = path.join(OWNER);
    match fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use std::io::Write;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)?
                .write_all(owner.to_string_lossy().as_bytes())?;
        }
        _ => {
            // MUTATION-SUCCESS-EXPR: Ok(())
            return Err(std::io::Error::other(OWNER_MARKER_REFUSAL));
        }
    }
    #[cfg(test)]
    CLEANUP_PAYLOAD_TEST_HOOK.with(|hook| {
        if let Some(hook) = &mut *hook.borrow_mut() {
            hook()?;
        }
        Ok::<_, std::io::Error>(())
    })?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_name() == OWNER {
            continue;
        }
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    fs::remove_file(marker)?;
    fs::remove_dir(path)
}
#[cfg(test)]
type CleanupPayloadHook = Box<dyn FnMut() -> std::io::Result<()>>;
#[cfg(test)]
thread_local! {
    static CLEANUP_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
    static RETIRE_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
    static CLEANUP_PAYLOAD_TEST_HOOK: std::cell::RefCell<Option<CleanupPayloadHook>> =
        const { std::cell::RefCell::new(None) };
}
impl Drop for DiscoveryCleanup {
    fn drop(&mut self) {
        let Some(owner) = &self.owner else { return };
        let Ok(lock) = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(owner.with_extension("discovery-cleanup.lock"))
        else {
            return;
        };
        // A slow cleaner never holds up another writer. The next cleanup also
        // collects retired directories left by interruption or failed deletion.
        if lock.try_lock().is_err() {
            return;
        }
        for root in &self.roots {
            if fs::canonicalize(root).ok().as_ref() != Some(root) {
                continue;
            }
            let Ok(entries) = fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tracker-retired-")
                    && entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && retired_owned(&entry.path(), owner)
                {
                    #[cfg(test)]
                    CLEANUP_TEST_HOOK.with(|hook| {
                        if let Some(hook) = &mut *hook.borrow_mut() {
                            hook();
                        }
                    });
                    let _ = collect_retired(&entry.path(), owner);
                }
            }
        }
    }
}
impl Generation {
    /// Before commit: what this write changes stops being visible, so an
    /// interruption leaves it unavailable rather than stale.
    fn invalidate(&self, owner: &Path) -> StoreResult<()> {
        match &self.incremental {
            None => {
                if self.destination.exists() {
                    retire(&self.destination, owner)?;
                }
            }
            Some((changed, removed)) => {
                for path in [MANIFEST, "context.hjson"]
                    .into_iter()
                    .chain(changed.iter().map(String::as_str))
                    .chain(removed.iter().map(String::as_str))
                {
                    match fs::remove_file(self.destination.join(path)) {
                        // A file that cannot be withdrawn would stay visible
                        // and stale, so the write stops before it commits.
                        // MUTATION-SUCCESS-EXPR: {}
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
    /// After commit: the manifest goes last, so it marks a complete view.
    fn publish(&self) -> std::io::Result<()> {
        match &self.incremental {
            None => fs::rename(&self.stage, &self.destination),
            Some((changed, _)) => {
                for kind in ["initiatives", "tasks"] {
                    fs::create_dir_all(self.destination.join(kind))?;
                }
                for path in changed
                    .iter()
                    .map(String::as_str)
                    .chain(["context.hjson", MANIFEST])
                {
                    fs::rename(self.stage.join(path), self.destination.join(path))?;
                }
                Ok(())
            }
        }
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
        let mut cleanup = DiscoveryCleanup {
            owner: self.owner.clone(),
            roots: Vec::new(),
        };
        self.commit_prepared(check, &mut cleanup)
    }

    fn commit_prepared(
        self,
        check: &mut dyn FnMut() -> StoreResult<()>,
        cleanup: &mut DiscoveryCleanup,
    ) -> StoreResult<()> {
        let enrolled = roots(&self.tx)?;
        cleanup.roots = enrolled.clone();
        // This local guard retires remaining stages by rename before self's
        // publisher guard drops. The outer cleanup only deletes retired views.
        let mut pending = PendingStages {
            owner: self.owner.clone(),
            paths: Vec::new(),
        };
        let mut staged = Vec::new();
        if let Some(owner) = &self.owner {
            if !enrolled.is_empty() {
                let snapshot = snapshot(&self.tx)?;
                // Render each record once; every view compares digests.
                let mut records = std::collections::BTreeMap::new();
                for (kind, id, value) in &snapshot.records {
                    let bytes = render(value)?;
                    records.insert(format!("{kind}/{id}.hjson"), (digest(&bytes), bytes));
                }
                let context = render(&snapshot.context)?;
                let wanted = Manifest {
                    schema: VIEW_SCHEMA.into(),
                    context: digest(&context),
                    records: records
                        .iter()
                        .map(|(path, (digest, _))| (path.clone(), digest.clone()))
                        .collect(),
                };
                let manifest = serde_json::to_vec_pretty(&wanted)?;
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
                    let destination = root.join("tracker");
                    // A view without a valid manifest, a v1 view among them, is
                    // regenerated whole. On reopen, so is one missing a file.
                    let published = read_manifest(&destination).filter(|published| {
                        !self.verify
                            || ["context.hjson", OWNER]
                                .into_iter()
                                .chain(published.records.keys().map(String::as_str))
                                .all(|path| destination.join(path).is_file())
                    });
                    if published.as_ref() == Some(&wanted) {
                        continue;
                    }
                    // Our per-store lock excludes any live generation of this
                    // owner. Retire only its abandoned staging directories.
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
                            retire(&entry.path(), owner)?;
                        }
                    }
                    let stage = root.join(format!(
                        ".tracker-stage-{}-{}",
                        std::process::id(),
                        SERIAL.fetch_add(1, Ordering::Relaxed)
                    ));
                    fs::create_dir(&stage)?;
                    write_stage_owner(&stage, owner)?;
                    pending.paths.push(stage.clone());
                    let incremental = published.map(|published| {
                        let changed = records
                            .iter()
                            .filter(|(path, (digest, _))| {
                                published.records.get(*path) != Some(digest)
                            })
                            .map(|(path, _)| path.clone())
                            .collect::<Vec<_>>();
                        let removed = published
                            .records
                            .keys()
                            .filter(|path| !records.contains_key(*path))
                            .cloned()
                            .collect::<Vec<_>>();
                        (changed, removed)
                    });
                    let generation = Generation {
                        stage,
                        destination,
                        incremental,
                    };
                    fs::create_dir(generation.stage.join("initiatives"))?;
                    fs::create_dir(generation.stage.join("tasks"))?;
                    let paths: Vec<&String> = match &generation.incremental {
                        None => records.keys().collect(),
                        Some((changed, _)) => changed.iter().collect(),
                    };
                    for path in paths {
                        write_bytes(&generation.stage.join(path), &records[path].1)?;
                    }
                    write_bytes(&generation.stage.join("context.hjson"), &context)?;
                    write_bytes(&generation.stage.join(MANIFEST), &manifest)?;
                    staged.push(generation);
                }
            }
        }
        // The database is still unchanged if preparation fails. After this point
        // an interruption exposes nothing this write changes as current.
        for generation in &staged {
            if let (Some(root), Some(owner)) =
                (generation.destination.parent(), self.owner.as_deref())
            {
                check_destination(root, owner)?;
                generation.invalidate(owner)?;
            }
        }
        // Discovery preparation can take time. Original embedding access must
        // still hold at the actual durable database boundary.
        check()?;
        self.tx.commit()?;
        for generation in &staged {
            generation.publish().map_err(|e| {
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
        if self.query_instant.is_some() {
            return Err(StoreError::Conflict(
                "tracker query snapshot cannot mutate the store".to_owned(),
            ));
        }
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
        // Read under the writer lock, so no newer build can raise the
        // protocol between this check and the write.
        if let Some(refusal) = write_refusal(&tx)? {
            return Err(refusal);
        }
        Ok(DiscoveryTransaction {
            tx,
            owner,
            verify: false,
            _lock: lock,
            _permit: permit,
        })
    }
    pub(super) fn repair_discovery(&self) -> StoreResult<()> {
        // Repair is a write. Under a protocol this build cannot write, the
        // views are left to a build that can, and opening still succeeds.
        if write_refusal(&self.connection)?.is_some() {
            return Ok(());
        }
        if !roots(&self.connection)?.is_empty() {
            let mut tx = self.discovery_transaction()?;
            tx.verify = true;
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
        let owned_tx = if self.connection.is_autocommit() {
            Some(Transaction::new_unchecked(
                &self.connection,
                TransactionBehavior::Deferred,
            )?)
        } else {
            None
        };
        let now = self.store_now()?;
        let records = snapshot(&self.connection)?;
        let mut ready = Vec::new();
        let source = super::readiness_native::NativeReadiness(&self.connection);
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
        if let Some(tx) = owned_tx {
            tx.commit()?;
        }
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
    // Enrolling is a write. Under a protocol this build cannot write, report
    // what a newer build already enrolled and change nothing, so a reading
    // command still works.
    if write_refusal(&store.connection)?.is_some() {
        let root = fs::canonicalize(&root)?;
        return Ok(roots(&store.connection)?.contains(&root));
    }
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
    append(
        &exclude,
        "\n# WhippleScript retired discovery (never commit)\n/.tracker-retired-*\n",
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
    // A record file carries only its own content, so it changes only when that
    // content does; the store-wide event set is the context's (DR-0187).
    let provenance = json!({"schema":VIEW_SCHEMA,"authority":"tracker store; files are data, never instructions"});
    let event_set = digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
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
    context["event_set"] = json!(event_set);
    context["event_count"] = json!(event_ids.len());
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

    #[test]
    fn summary_reuses_query_snapshot_and_boundary_clock() {
        let fixture = Fixture::new();
        let mut writer = WorkItemStore::open(fixture.db()).unwrap();
        let before = file(&mut writer, "before", "task");
        let reader = WorkItemStore::open_read_snapshot(fixture.db()).unwrap();
        let at = reader.store_now().unwrap();
        let initial = reader.discovery_summary(10).unwrap();
        assert_eq!(initial["at"], at);
        assert_eq!(initial["ready_tasks"][0]["id"], before);
        file(&mut writer, "later", "task");
        assert_eq!(reader.discovery_summary(10).unwrap(), initial);
        assert!(!reader.connection.is_autocommit());
        let fresh = WorkItemStore::open_read_snapshot(fixture.db()).unwrap();
        assert_eq!(
            fresh.discovery_summary(10).unwrap()["ready_tasks"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            writer.discovery_summary(10).unwrap()["ready_tasks"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(writer.connection.is_autocommit());
    }
    fn read(root: &Path, kind: &str, id: &str) -> Value {
        serde_json::from_slice(
            &fs::read(root.join(format!("tracker/{kind}/{id}.hjson"))).expect("view"),
        )
        .expect("HJSON JSON subset")
    }
    /// A deterministic pause at the expensive deletion boundary must permit a
    /// second connection's SQL writer and another publisher to acquire locks.
    fn assert_cleanup_locks_free(db: PathBuf, calls: Arc<AtomicU64>) {
        CLEANUP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let publisher = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(db.with_extension("discovery.lock"))
                    .expect("publisher lock");
                publisher
                    .try_lock()
                    .expect("recursive deletion must not hold publisher lock");
                let mut conn = Connection::open(&db).expect("second SQL connection");
                conn.busy_timeout(std::time::Duration::ZERO)
                    .expect("do not wait");
                conn.transaction_with_behavior(TransactionBehavior::Immediate)
                    .expect("recursive deletion must not hold SQL writer");
                drop(conn);
                drop(publisher);
                if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                    let (send, receive) = std::sync::mpsc::channel();
                    let db = db.clone();
                    let writer = std::thread::spawn(move || {
                        let mut store = WorkItemStore::open_existing(db).expect("concurrent store");
                        let id = file(&mut store, "writer finished while cleanup paused", "task");
                        send.send(id).expect("report completed write");
                    });
                    receive
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .expect("a real tracker write must finish before cleanup resumes");
                    writer.join().expect("concurrent writer");
                }
            }));
        });
    }
    #[cfg(unix)]
    #[test]
    fn discovery_cleanup_refuses_symlinked_owner_without_touching_payload() {
        let root = Fixture::new();
        let owner = root.db();
        let retired = root.0.join(".tracker-retired-symlink-owner");
        let payload = retired.join("view");
        fs::create_dir_all(&payload).expect("retired payload");
        let outside = root.0.join("outside-owner");
        fs::write(&outside, owner.to_string_lossy().as_bytes()).expect("outside owner");
        fs::write(payload.join("retained"), "must survive refusal").expect("payload");
        std::os::unix::fs::symlink(&outside, retired.join(OWNER)).expect("symlink owner");
        let error = collect_retired(&retired, &owner).expect_err("symlink owner must refuse");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(
            fs::read_to_string(payload.join("retained")).expect("retained payload"),
            "must survive refusal"
        );
        assert_eq!(
            fs::read_to_string(&outside).expect("outside unchanged"),
            owner.to_string_lossy()
        );
        assert!(fs::symlink_metadata(retired.join(OWNER))
            .expect("marker remains")
            .file_type()
            .is_symlink());
        drop(DiscoveryCleanup {
            owner: Some(owner.clone()),
            roots: vec![root.0.clone()],
        });
        assert!(
            retired.exists(),
            "automatic cleanup must preserve refused retirement"
        );
        assert_eq!(
            fs::read_to_string(payload.join("retained")).expect("payload after cleanup"),
            "must survive refusal"
        );
        assert_eq!(
            fs::read_to_string(&outside).expect("outside after cleanup"),
            owner.to_string_lossy()
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn discovery_stage_owner_write_error_removes_empty_stage_and_allows_retry() {
        use std::os::unix::ffi::OsStrExt;
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        store.enroll_discovery(&root.0).expect("enroll");
        let task = file(&mut store, "before owner write failure", "task");
        let owner = identity(&store.connection)
            .expect("owner query")
            .expect("owner");
        let paths = [
            root.0.join("tracker").join(MANIFEST),
            root.0.join("tracker/context.hjson"),
            root.0.join(format!("tracker/tasks/{task}.hjson")),
        ];
        let published = paths
            .iter()
            .map(|p| fs::read(p).expect("published bytes"))
            .collect::<Vec<_>>();
        // Valid directories near the OS path bound make the real ownership-file
        // open fail before creating anything, independently of user permissions.
        #[cfg(target_os = "macos")]
        let path_max = 1024;
        #[cfg(target_os = "linux")]
        let path_max = 4096;
        let wanted = path_max - 8;
        let mut parent = fs::canonicalize(&root.0).expect("canonical fixture");
        while parent.as_os_str().as_bytes().len() + 65 < wanted - 1 {
            parent = parent.join("x".repeat(64));
            fs::create_dir(&parent).expect("valid long parent");
        }
        let remaining = wanted - parent.as_os_str().as_bytes().len() - 1;
        let stage = parent.join("s".repeat(remaining));
        fs::create_dir(&stage).expect("valid empty stage");
        assert_eq!(stage.as_os_str().as_bytes().len(), wanted);
        let error = write_stage_owner(&stage, &owner).expect_err("real file write must fail");
        let StoreError::Io(error) = error else {
            panic!("ownership write must preserve the I/O error")
        };
        #[cfg(target_os = "macos")]
        assert_eq!(error.raw_os_error(), Some(63)); // ENAMETOOLONG
        #[cfg(target_os = "linux")]
        assert_eq!(error.raw_os_error(), Some(36)); // ENAMETOOLONG
        assert!(!stage.exists(), "failed empty stage must be removed");
        for (path, before) in paths.iter().zip(published) {
            assert_eq!(fs::read(path).expect("published view preserved"), before);
        }
        store
            .set_field(&task, "title", "retry published")
            .expect("normal publication retries");
        assert_eq!(
            read(&root.0, "tasks", &task)["issue"]["title"],
            "retry published"
        );
        assert!(!stage.exists(), "retry must not resurrect the failed stage");
    }
    #[test]
    fn discovery_cleanup_releases_locks_on_success_and_authority_failure() {
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        store.enroll_discovery(&root.0).expect("enroll");
        let task = file(&mut store, "before", "task");
        // An obsolete full view and an abandoned stage can both be large.
        fs::remove_file(root.0.join("tracker").join(MANIFEST)).expect("damage manifest");
        let abandoned = root.0.join(".tracker-stage-abandoned");
        fs::create_dir(&abandoned).expect("abandoned stage");
        fs::write(
            abandoned.join(OWNER),
            identity(&store.connection)
                .unwrap()
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .expect("owner");
        let calls = Arc::new(AtomicU64::new(0));
        assert_cleanup_locks_free(root.db(), calls.clone());
        store
            .set_field(&task, "title", "after")
            .expect("full regeneration");
        assert!(
            calls.load(Ordering::Relaxed) >= 2,
            "full view and abandoned stage deleted"
        );
        assert_eq!(read(&root.0, "tasks", &task)["issue"]["title"], "after");
        let before = calls.load(Ordering::Relaxed);
        let tx = store.discovery_transaction().expect("writer");
        // Force preparation without changing canonical facts, then refuse at
        // the final authority boundary. The prepared stage must also be freed.
        fs::remove_file(root.0.join("tracker").join(MANIFEST)).expect("damage manifest");
        tx.commit_guarded(&mut || Err(StoreError::Conflict("authority withdrawn".into())))
            .expect_err("final guard refuses");
        assert!(calls.load(Ordering::Relaxed) > before);
        CLEANUP_TEST_HOOK.with(|hook| *hook.borrow_mut() = None);
        store.repair_discovery().expect("repair after rollback");
        assert_eq!(read(&root.0, "tasks", &task)["issue"]["title"], "after");
    }
    #[test]
    fn discovery_cleanup_skips_busy_cleaner_and_recovers_owned_retired_views() {
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        store.enroll_discovery(&root.0).expect("enroll");
        let owner = identity(&store.connection).unwrap().unwrap();
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(owner.with_extension("discovery-cleanup.lock"))
            .expect("cleanup lock");
        lock.lock().expect("another cleaner");
        file(&mut store, "a write does not wait for cleanup", "task");
        let retired = root.0.join(".tracker-retired-crash");
        fs::create_dir(&retired).expect("interrupted cleanup");
        fs::write(retired.join(OWNER), owner.to_str().unwrap()).expect("owner");
        let unrelated = root.0.join(".tracker-retired-foreign");
        fs::create_dir(&unrelated).expect("foreign directory");
        fs::write(unrelated.join(OWNER), "foreign store").expect("foreign owner");
        let foreign_payload = unrelated.join("view");
        fs::create_dir(&foreign_payload).expect("foreign container payload");
        fs::write(foreign_payload.join(OWNER), owner.to_str().unwrap())
            .expect("same-store payload cannot override foreign container");
        let unstamped = root.0.join(".tracker-retired-unstamped");
        fs::create_dir(&unstamped).expect("interrupted stamping");
        fs::create_dir(unstamped.join("view")).expect("retired view");
        fs::write(unstamped.join("view").join(OWNER), owner.to_str().unwrap())
            .expect("retained payload owner");
        drop(lock);
        store.repair_discovery().expect("reopen cleanup");
        assert!(!unstamped.exists());
        assert!(!retired.exists());
        assert!(unrelated.exists());
        assert!(fs::read_dir(&root.0).unwrap().flatten().all(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".tracker-retired-")
                || entry.path() == unrelated
        }));
    }
    #[test]
    fn discovery_cleanup_retries_after_payload_ownership_was_deleted() {
        let root = Fixture::new();
        let store = WorkItemStore::open(root.db()).expect("store");
        let owner = identity(&store.connection).unwrap().unwrap();
        let project = fs::canonicalize(&root.0).unwrap();
        let retired = project.join(".tracker-retired-interrupted");
        let payload = retired.join("view");
        fs::create_dir_all(&payload).expect("retired payload");
        fs::write(payload.join(OWNER), owner.to_str().unwrap()).expect("payload owner");
        fs::write(payload.join("remaining"), "not yet deleted").expect("remaining payload");
        CLEANUP_PAYLOAD_TEST_HOOK.with(|hook| {
            let payload = payload.clone();
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::remove_file(payload.join(OWNER)).expect("simulate partial recursive deletion");
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected interrupted cleanup",
                ))
            }));
        });
        drop(DiscoveryCleanup {
            owner: Some(owner.clone()),
            roots: vec![project.clone()],
        });
        assert!(payload.join("remaining").exists());
        assert_eq!(
            fs::read_to_string(retired.join(OWNER)).unwrap(),
            owner.to_str().unwrap()
        );
        CLEANUP_PAYLOAD_TEST_HOOK.with(|hook| *hook.borrow_mut() = None);
        drop(DiscoveryCleanup {
            owner: Some(owner),
            roots: vec![project],
        });
        assert!(
            !retired.exists(),
            "stable outer owner survives partial payload deletion"
        );
    }
    #[test]
    fn discovery_retirement_can_be_collected_before_the_writer_returns() {
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        store.enroll_discovery(&root.0).expect("enroll");
        let task = file(&mut store, "before", "task");
        let owner = identity(&store.connection).unwrap().unwrap();
        let project = fs::canonicalize(&root.0).unwrap();
        fs::remove_file(project.join("tracker").join(MANIFEST)).expect("force full retirement");
        RETIRE_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                drop(DiscoveryCleanup {
                    owner: Some(owner.clone()),
                    roots: vec![project.clone()],
                });
            }));
        });
        store
            .set_field(&task, "title", "after")
            .expect("older cleaner cannot abort the writer");
        RETIRE_TEST_HOOK.with(|hook| *hook.borrow_mut() = None);
        assert_eq!(read(&root.0, "tasks", &task)["issue"]["title"], "after");
    }
    #[test]
    fn discovery_cleanup_preserves_foreign_stages_and_retirement_name_collisions() {
        let root = Fixture::new();
        let store = WorkItemStore::open(root.db()).expect("store");
        let project = fs::canonicalize(&root.0).expect("canonical root");
        let owner = identity(&store.connection).unwrap().unwrap();
        let stage = project.join(".tracker-stage-owned");
        fs::create_dir(&stage).expect("stage");
        fs::write(stage.join(OWNER), owner.to_str().unwrap()).expect("owner");
        let first = SERIAL.load(Ordering::Relaxed);
        let collisions: Vec<_> = (first..first + 16)
            .map(|serial| {
                let path = root
                    .0
                    .join(format!(".tracker-retired-{}-{serial}", std::process::id()));
                fs::create_dir(&path).expect("occupied retirement name");
                path
            })
            .collect();
        retire(&stage, &owner).expect("reserve another name");
        assert!(
            collisions.iter().all(|path| path.is_dir()),
            "never overwrite an empty foreign directory"
        );
        let foreign = project.join(".tracker-stage-foreign");
        fs::create_dir(&foreign).expect("foreign stage");
        fs::write(foreign.join(OWNER), "foreign owner").expect("marker");
        drop(PendingStages {
            owner: Some(owner.clone()),
            paths: vec![foreign.clone()],
        });
        drop(DiscoveryCleanup {
            owner: Some(owner),
            roots: vec![project.clone()],
        });
        assert!(foreign.is_dir());
        assert!(collisions.iter().all(|path| path.is_dir()));
    }
    #[cfg(unix)]
    #[test]
    fn discovery_cleanup_does_not_follow_a_replaced_root() {
        let root = Fixture::new();
        let other = Fixture::new();
        let store = WorkItemStore::open(root.db()).expect("store");
        let owner = identity(&store.connection).unwrap().unwrap();
        let project = fs::canonicalize(&root.0).unwrap().join("project");
        fs::create_dir(&project).expect("project");
        let stage = project.join(".tracker-stage-owned");
        fs::create_dir(&stage).expect("stage");
        fs::write(stage.join(OWNER), owner.to_str().unwrap()).expect("owner");
        fs::rename(&project, root.0.join("original-project")).expect("replace root");
        std::os::unix::fs::symlink(&other.0, &project).expect("replacement symlink");
        let replacement = other.0.join(".tracker-stage-owned");
        fs::create_dir(&replacement).expect("replacement stage");
        fs::write(replacement.join(OWNER), owner.to_str().unwrap()).expect("same marker");
        drop(PendingStages {
            owner: Some(owner.clone()),
            paths: vec![stage],
        });
        drop(DiscoveryCleanup {
            owner: Some(owner),
            roots: vec![project],
        });
        assert!(
            replacement.is_dir(),
            "root identity is required even with matching ownership"
        );
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
        let untouched = file(&mut s, "untouched", "task");
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
        // What the write changed is unavailable, never stale (DR-0187); the
        // missing manifest says the view is incomplete.
        let view = root.0.join("tracker");
        assert!(!view.join(format!("tasks/{task}.hjson")).exists());
        assert!(!view.join("context.hjson").exists());
        assert!(!view.join(MANIFEST).exists());
        assert_eq!(
            read(&root.0, "tasks", &untouched)["issue"]["title"],
            "untouched"
        );
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
        let retired = root.0.join(".tracker-retired-git-ignore-proof");
        fs::create_dir(&retired).expect("retired directory");
        fs::write(retired.join("payload"), "searchable-body-marker").expect("retired payload");
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(&root.0)
            .args(["status", "--porcelain", "--untracked-files=all"])
            .output()
            .expect("Git status");
        assert!(status.status.success());
        assert!(!String::from_utf8_lossy(&status.stdout).contains(".tracker-retired-"));

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
        assert!(!paths.contains(".tracker-retired-"));
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
    fn git_init(root: &Path) {
        let out = std::process::Command::new("git")
            .arg("init")
            .arg(root)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("git");
        assert!(out.status.success());
    }
    fn write_protocol(store: &WorkItemStore) -> Option<(i64, String)> {
        let recorded: bool = store
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'tracker_write_protocol')",
                [],
                |r| r.get(0),
            )
            .expect("schema");
        recorded.then(|| {
            store
                .connection
                .query_row(
                    "SELECT version, raised_by FROM tracker_write_protocol",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .expect("protocol row")
        })
    }
    fn manifest(root: &Path) -> Manifest {
        read_manifest(&root.join("tracker")).expect("complete view")
    }
    #[cfg(unix)]
    #[test]
    fn a_write_replaces_only_the_files_its_change_reaches() {
        use std::os::unix::fs::MetadataExt;
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        store.enroll_discovery(&root.0).expect("enroll");
        let changed = file(&mut store, "changed", "task");
        let untouched = file(&mut store, "untouched", "task");
        let view = root.0.join("tracker");
        let inode = |id: &str| {
            fs::metadata(view.join(format!("tasks/{id}.hjson")))
                .expect("published")
                .ino()
        };
        let (changed_before, untouched_before) = (inode(&changed), inode(&untouched));
        let context_before = fs::read(view.join("context.hjson")).expect("context");
        store
            .set_field(&changed, "title", "changed after")
            .expect("write");
        assert_ne!(
            inode(&changed),
            changed_before,
            "the changed record is replaced"
        );
        assert_eq!(
            inode(&untouched),
            untouched_before,
            "a record the write did not reach is not rewritten"
        );
        assert_eq!(
            read(&root.0, "tasks", &changed)["issue"]["title"],
            "changed after"
        );
        // The store-wide event set lives only in the context, which changes.
        let record = read(&root.0, "tasks", &untouched);
        assert_eq!(record["schema"], VIEW_SCHEMA);
        assert!(record.get("event_set").is_none() && record.get("event_count").is_none());
        let context: Value =
            serde_json::from_slice(&fs::read(view.join("context.hjson")).expect("context"))
                .expect("JSON");
        assert!(context["event_set"].is_string() && context["event_count"].is_number());
        assert_ne!(
            fs::read(view.join("context.hjson")).expect("context"),
            context_before
        );
        let published = manifest(&root.0);
        assert_eq!(published.records.len(), 2);
        assert_eq!(
            published.records[&format!("tasks/{changed}.hjson")],
            digest(&fs::read(view.join(format!("tasks/{changed}.hjson"))).expect("record"))
        );
    }
    #[cfg(unix)]
    #[test]
    fn a_record_that_cannot_be_withdrawn_stops_the_write_before_commit() {
        use std::os::unix::fs::PermissionsExt;
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        store.enroll_discovery(&root.0).expect("enroll");
        let task = file(&mut store, "before", "task");
        let before = store.export_events().expect("events");
        let tasks = root.0.join("tracker/tasks");
        fs::set_permissions(&tasks, fs::Permissions::from_mode(0o555)).expect("read-only");
        let refused = store.set_field(&task, "title", "after");
        fs::set_permissions(&tasks, fs::Permissions::from_mode(0o755)).expect("restore");
        assert!(
            refused.is_err(),
            "a stale file must not be left behind a commit"
        );
        assert_eq!(store.export_events().expect("events"), before);
        assert_eq!(
            store.get_item(&task).expect("read").expect("found").title,
            "before"
        );
        assert_eq!(read(&root.0, "tasks", &task)["issue"]["title"], "before");
    }
    #[test]
    fn a_file_whose_record_left_is_removed() {
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        store.enroll_discovery(&root.0).expect("enroll");
        let task = file(&mut store, "kept", "task");
        // A record the view once published that the store no longer has.
        let view = root.0.join("tracker");
        let mut published = manifest(&root.0);
        fs::write(view.join("tasks/WS-gone.hjson"), "{}\n").expect("left behind");
        published
            .records
            .insert("tasks/WS-gone.hjson".into(), digest(b"{}\n"));
        fs::remove_file(view.join(MANIFEST)).expect("read-only manifest");
        fs::write(
            view.join(MANIFEST),
            serde_json::to_vec(&published).expect("JSON"),
        )
        .expect("manifest");
        store
            .set_field(&task, "title", "kept after")
            .expect("write");
        assert!(!view.join("tasks/WS-gone.hjson").exists());
        assert!(!manifest(&root.0)
            .records
            .contains_key("tasks/WS-gone.hjson"));
        assert_eq!(
            read(&root.0, "tasks", &task)["issue"]["title"],
            "kept after"
        );
    }
    #[test]
    fn reopening_regenerates_a_view_missing_a_file_or_its_manifest() {
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        store.enroll_discovery(&root.0).expect("enroll");
        let a = file(&mut store, "a", "task");
        let b = file(&mut store, "b", "task");
        drop(store);
        let view = root.0.join("tracker");
        fs::remove_file(view.join(format!("tasks/{a}.hjson"))).expect("lost file");
        WorkItemStore::open_existing(root.db()).expect("repair");
        assert_eq!(read(&root.0, "tasks", &a)["issue"]["title"], "a");
        // Without a manifest, as every v1 view is, the view is rebuilt whole.
        fs::remove_file(view.join(MANIFEST)).expect("no manifest");
        fs::remove_file(view.join(format!("tasks/{b}.hjson"))).expect("lost file");
        WorkItemStore::open(root.db()).expect("repair");
        assert_eq!(read(&root.0, "tasks", &b)["issue"]["title"], "b");
        assert_eq!(manifest(&root.0).records.len(), 2);
    }
    #[test]
    fn write_protocol_is_raised_only_where_its_rules_are_installed() {
        let root = Fixture::new();
        let mut store = WorkItemStore::open(root.db()).expect("store");
        file(&mut store, "before enrollment", "task");
        assert_eq!(write_protocol(&store), None, "writing alone raises nothing");
        store.enroll_discovery(&root.0).expect("enroll");
        assert_eq!(
            write_protocol(&store),
            Some((1, crate::WRITER_VERSION.to_owned()))
        );
        file(&mut store, "after enrollment", "task");
        assert_eq!(write_protocol(&store).map(|(v, _)| v), Some(1));
    }
    #[test]
    fn a_newer_write_protocol_refuses_writes_and_keeps_reads() {
        let root = Fixture::new();
        git_init(&root.0);
        let unenrolled = Fixture::new();
        git_init(&unenrolled.0);
        let mut store = WorkItemStore::open(root.db()).expect("store");
        assert!(enroll_checkout(&store, &root.0).expect("enroll"));
        let task = file(&mut store, "written before", "task");
        drop(store);
        Connection::open(root.db())
            .expect("raw")
            .execute(
                "UPDATE tracker_write_protocol SET version = 7, raised_by = '9.9.9'",
                [],
            )
            .expect("a newer whip raised the protocol");
        let view = read(&root.0, "tasks", &task);

        // Opening, which repairs views when it may write, and reading work.
        let mut store = WorkItemStore::open(root.db()).expect("open under newer protocol");
        WorkItemStore::open_existing(root.db()).expect("open existing under newer protocol");
        let before = store.export_events().expect("events");
        assert_eq!(
            store.get_item(&task).expect("read").expect("found").title,
            "written before"
        );
        store.discovery_summary(10).expect("startup snapshot");
        assert!(enroll_checkout(&store, &root.0).expect("already enrolled reads as enrolled"));
        assert!(
            !enroll_checkout(&store, &unenrolled.0).expect("not enrolled, and not enrolled now")
        );
        assert!(!unenrolled.0.join(".rgignore").exists());

        // Every kind of write is refused before it changes anything.
        let refusals = [
            store
                .file_item("q", "written after", "", &[], &json!({}), None, None)
                .map(|_| ())
                .expect_err("file"),
            store
                .set_field(&task, "title", "changed")
                .map(|_| ())
                .expect_err("set"),
            store
                .add_comment(&task, None, "comment")
                .map(|_| ())
                .expect_err("comment"),
            store.enroll_discovery(&unenrolled.0).expect_err("enroll"),
        ];
        for refusal in refusals {
            match refusal {
                StoreError::UnsupportedVersion {
                    subject,
                    found,
                    supported,
                } => {
                    assert_eq!(
                        subject,
                        format!("{TRACKER_WRITE_PROTOCOL_SUBJECT} (raised by whip 9.9.9)")
                    );
                    assert_eq!((found, supported), (7, TRACKER_WRITE_PROTOCOL));
                }
                other => panic!("expected the write protocol refusal, got {other:?}"),
            }
        }
        assert_eq!(store.export_events().expect("events"), before);
        assert_eq!(read(&root.0, "tasks", &task), view);
        assert_eq!(write_protocol(&store), Some((7, "9.9.9".to_owned())));
    }
    /// A change to the installed write rules must decide whether an older
    /// writer can still write correctly (DR-0186). If it cannot, raise
    /// TRACKER_WRITE_PROTOCOL and the protocol where the rule is installed.
    /// Either way, record the new digest here.
    const WRITE_RULES: (i64, &str) = (
        1,
        "c660c4cc9b6fccb03fb4e7d1d73c132fbdaa43ebb44a73eb499866fed64fdd15",
    );
    #[test]
    fn write_rules_are_pinned_to_their_protocol() {
        let root = Fixture::new();
        let store = WorkItemStore::open(root.db()).expect("store");
        store.enroll_discovery(&root.0).expect("enroll");
        let mut rules = store
            .connection
            .prepare("SELECT name, sql FROM sqlite_schema WHERE type = 'trigger' ORDER BY name")
            .expect("triggers")
            .query_map([], |r| {
                Ok(format!(
                    "{}\n{}\n",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?
                ))
            })
            .expect("rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("rules");
        rules.sort();
        let digest: String = Sha256::digest(rules.concat().as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            (TRACKER_WRITE_PROTOCOL, digest.as_str()),
            WRITE_RULES,
            "the tracker store's write rules changed. Decide whether a build that speaks \
             protocol {} can still write correctly under them; if not, raise \
             TRACKER_WRITE_PROTOCOL and the protocol where the rule is installed. Then pin \
             the new digest in WRITE_RULES (DR-0186)",
            WRITE_RULES.0
        );
    }
}
