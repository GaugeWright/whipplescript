//! The reviewed-contribution record under DR-0141 and DR-0145. WhippleScript
//! source cuts and units are the primary candidate authority. Git is a
//! compatibility source; authenticated transport and admission remain open.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::source_review_git::{GitCandidatePins, GitPin};
use crate::StoreError;

const SCHEMA_VERSION: i64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Native,
    Git,
}

impl SourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Git => "git",
        }
    }

    fn parse(value: &str) -> ReviewResult<Self> {
        match value {
            "native" => Ok(Self::Native),
            "git" => Ok(Self::Git),
            _ => Err(ReviewError::Corrupt(format!("unknown source kind {value}"))),
        }
    }
}

#[derive(Debug)]
pub enum ReviewError {
    Invalid(String),
    Missing(String),
    Conflict(String),
    Corrupt(String),
    Git(String),
    Sqlite(rusqlite::Error),
    Store(StoreError),
    Io(std::io::Error),
}

impl From<rusqlite::Error> for ReviewError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<StoreError> for ReviewError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<std::io::Error> for ReviewError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub type ReviewResult<T> = Result<T, ReviewError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contribution {
    pub id: String,
    pub author: String,
    pub intent: String,
    pub source_kind: SourceKind,
    pub target_scope: String,
    pub predecessors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitRevision {
    pub contribution_id: String,
    pub sequence: i64,
    pub upload_id: String,
    pub actor: String,
    pub source_ref: String,
    pub commit_oid: String,
    pub tree_oid: String,
    pub pin_ref: String,
}

#[derive(Clone, Copy)]
struct GitUploadRequest<'a> {
    contribution_id: &'a str,
    upload_id: &'a str,
    actor: &'a str,
    source_ref: &'a str,
    commit_oid: &'a str,
}

pub struct ReviewStore {
    pub(crate) connection: Connection,
}

impl ReviewStore {
    pub fn open(path: impl AsRef<Path>) -> ReviewResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut connection = Connection::open(path)?;
        crate::establish_wal(&connection)?;
        crate::stamp_satellite_schema(&connection, "source-review", SCHEMA_VERSION)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS contributions (
                id TEXT PRIMARY KEY,
                author TEXT NOT NULL,
                intent TEXT NOT NULL,
                target_ref TEXT NOT NULL,
                source_kind TEXT NOT NULL DEFAULT 'git',
                created_at INTEGER NOT NULL DEFAULT (unixepoch())
            );
            CREATE TABLE IF NOT EXISTS predecessors (
                contribution_id TEXT NOT NULL REFERENCES contributions(id),
                predecessor_id TEXT NOT NULL REFERENCES contributions(id),
                PRIMARY KEY (contribution_id, predecessor_id)
            );
            CREATE TABLE IF NOT EXISTS pending_git_uploads (
                contribution_id TEXT NOT NULL REFERENCES contributions(id),
                upload_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                commit_oid TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                PRIMARY KEY (contribution_id, upload_id)
            );
            CREATE TABLE IF NOT EXISTS git_revisions (
                contribution_id TEXT NOT NULL REFERENCES contributions(id),
                sequence INTEGER NOT NULL,
                upload_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                commit_oid TEXT NOT NULL,
                tree_oid TEXT NOT NULL,
                pin_ref TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                PRIMARY KEY (contribution_id, sequence),
                UNIQUE (contribution_id, upload_id)
            );
            CREATE TABLE IF NOT EXISTS native_revisions (
                contribution_id TEXT NOT NULL REFERENCES contributions(id),
                sequence INTEGER NOT NULL,
                upload_id TEXT NOT NULL,
                revision_json TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                PRIMARY KEY (contribution_id, sequence),
                UNIQUE (contribution_id, upload_id)
            );",
        )?;
        let migration = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let has_source_kind = migration
            .prepare("PRAGMA table_info(contributions)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|name| name == "source_kind");
        if !has_source_kind {
            migration.execute(
                "ALTER TABLE contributions ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'git'",
                [],
            )?;
        }
        migration.commit()?;
        Ok(Self { connection })
    }

    /// Author is the identity supplied by a trusted caller. This store does
    /// not authenticate a network request or infer authority from Git authors.
    pub fn create_contribution(
        &mut self,
        id: &str,
        author: &str,
        intent: &str,
        target_ref: &str,
        predecessors: &[&str],
    ) -> ReviewResult<Contribution> {
        self.create_with_kind(
            id,
            author,
            intent,
            SourceKind::Git,
            target_ref,
            predecessors,
        )
    }

    pub fn create_native_contribution(
        &mut self,
        id: &str,
        author: &str,
        intent: &str,
        target_branch_id: &str,
        predecessors: &[&str],
    ) -> ReviewResult<Contribution> {
        self.create_with_kind(
            id,
            author,
            intent,
            SourceKind::Native,
            target_branch_id,
            predecessors,
        )
    }

    fn create_with_kind(
        &mut self,
        id: &str,
        author: &str,
        intent: &str,
        source_kind: SourceKind,
        target_scope: &str,
        predecessors: &[&str],
    ) -> ReviewResult<Contribution> {
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(ReviewError::Invalid(
                "id must be an opaque 1-64 character ASCII token".into(),
            ));
        }
        if author.trim().is_empty() || intent.trim().is_empty() {
            return Err(ReviewError::Invalid(
                "author and intent are required".into(),
            ));
        }
        match source_kind {
            SourceKind::Git
                if !target_scope.starts_with("refs/heads/") || target_scope == "refs/heads/" =>
            {
                return Err(ReviewError::Invalid(
                    "target must name a full branch ref".into(),
                ));
            }
            SourceKind::Native
                if target_scope.trim().is_empty() || target_scope.starts_with("refs/") =>
            {
                return Err(ReviewError::Invalid(
                    "target must name a WhippleScript branch id".into(),
                ));
            }
            _ => {}
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO contributions (id, author, intent, target_ref, source_kind)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, author, intent, target_scope, source_kind.as_str()],
        )?;
        for predecessor in predecessors {
            if *predecessor == id {
                return Err(ReviewError::Invalid(
                    "a contribution cannot precede itself".into(),
                ));
            }
            tx.execute(
                "INSERT INTO predecessors (contribution_id, predecessor_id) VALUES (?1, ?2)",
                params![id, predecessor],
            )?;
        }
        tx.commit()?;
        self.contribution(id)
    }

    pub fn contribution(&self, id: &str) -> ReviewResult<Contribution> {
        let value = self
            .connection
            .query_row(
                "SELECT id, author, intent, target_ref, source_kind FROM contributions WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let (id, author, intent, target_scope, kind) =
            value.ok_or_else(|| ReviewError::Missing(format!("contribution {id}")))?;
        let mut value = Contribution {
            id,
            author,
            intent,
            target_scope,
            source_kind: SourceKind::parse(&kind)?,
            predecessors: Vec::new(),
        };
        let mut statement = self.connection.prepare(
            "SELECT predecessor_id FROM predecessors
             WHERE contribution_id=?1 ORDER BY predecessor_id",
        )?;
        value.predecessors = statement
            .query_map([value.id.as_str()], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(value)
    }

    /// The caller supplies an authenticated actor. A pending row precedes the
    /// Git ref, so a restart can finish publication of an already-created pin.
    pub fn upload_git_revision(
        &mut self,
        pins: &GitCandidatePins,
        contribution_id: &str,
        upload_id: &str,
        actor: &str,
        source_ref: &str,
        commit_oid: &str,
    ) -> ReviewResult<GitRevision> {
        if upload_id.is_empty()
            || upload_id.len() > 64
            || !upload_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(ReviewError::Invalid("invalid upload id".into()));
        }
        if actor.trim().is_empty() {
            return Err(ReviewError::Invalid("upload actor is required".into()));
        }
        if !source_ref.starts_with("refs/heads/") || source_ref == "refs/heads/" {
            return Err(ReviewError::Invalid(
                "upload source must be a branch".into(),
            ));
        }
        let contribution = self.contribution(contribution_id)?;
        if contribution.source_kind != SourceKind::Git {
            return Err(ReviewError::Invalid(
                "Git revision needs a Git contribution".into(),
            ));
        }
        if actor != contribution.author {
            return Err(ReviewError::Invalid("only the author may upload".into()));
        }
        if let Some(existing) = revision_by_upload(&self.connection, contribution_id, upload_id)? {
            same_upload(&existing, actor, source_ref, commit_oid)?;
            pins.verify(&existing.pin())?;
            return Ok(existing);
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending: Option<(String, String, String)> = tx
            .query_row(
                "SELECT actor, source_ref, commit_oid FROM pending_git_uploads
                 WHERE contribution_id=?1 AND upload_id=?2",
                params![contribution_id, upload_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some(old) = pending {
            if (old.0.as_str(), old.1.as_str(), old.2.as_str()) != (actor, source_ref, commit_oid) {
                return Err(ReviewError::Conflict(
                    "upload id changed while pending".into(),
                ));
            }
        } else {
            tx.execute(
                "INSERT INTO pending_git_uploads
                 (contribution_id, upload_id, actor, source_ref, commit_oid)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![contribution_id, upload_id, actor, source_ref, commit_oid],
            )?;
        }
        tx.commit()?;

        let pin = match pins.recover(contribution_id, upload_id, source_ref, commit_oid)? {
            Some(existing) => existing,
            None => pins.pin(contribution_id, upload_id, source_ref, commit_oid)?,
        };
        pins.verify(&pin)?;
        self.finish_git_revision(
            pins,
            GitUploadRequest {
                contribution_id,
                upload_id,
                actor,
                source_ref,
                commit_oid,
            },
            &pin,
        )
    }

    fn finish_git_revision(
        &mut self,
        pins: &GitCandidatePins,
        request: GitUploadRequest<'_>,
        pin: &GitPin,
    ) -> ReviewResult<GitRevision> {
        let GitUploadRequest {
            contribution_id,
            upload_id,
            actor,
            source_ref,
            commit_oid,
        } = request;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = revision_by_upload(&tx, contribution_id, upload_id)? {
            same_upload(&existing, actor, source_ref, commit_oid)?;
            pins.verify(&existing.pin())?;
            return Ok(existing);
        }
        let pending: Option<(String, String, String)> = tx
            .query_row(
                "SELECT actor, source_ref, commit_oid FROM pending_git_uploads
                 WHERE contribution_id=?1 AND upload_id=?2",
                params![contribution_id, upload_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if pending
            .as_ref()
            .map(|(a, s, c)| (a.as_str(), s.as_str(), c.as_str()))
            != Some((actor, source_ref, commit_oid))
        {
            return Err(ReviewError::Corrupt("pending upload changed".into()));
        }
        let sequence: i64 = tx.query_row(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM git_revisions WHERE contribution_id=?1",
            [contribution_id],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO git_revisions
             (contribution_id, sequence, upload_id, actor, source_ref, commit_oid, tree_oid, pin_ref)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![contribution_id, sequence, upload_id, actor, source_ref,
                commit_oid, pin.tree_oid, pin.pin_ref],
        )?;
        tx.execute(
            "DELETE FROM pending_git_uploads WHERE contribution_id=?1 AND upload_id=?2",
            params![contribution_id, upload_id],
        )?;
        tx.commit()?;
        self.git_revision(pins, contribution_id, sequence)
    }

    pub fn git_revision(
        &self,
        pins: &GitCandidatePins,
        contribution_id: &str,
        sequence: i64,
    ) -> ReviewResult<GitRevision> {
        let revision: Option<GitRevision> = self
            .connection
            .query_row(
                "SELECT contribution_id, sequence, upload_id, actor, source_ref,
                        commit_oid, tree_oid, pin_ref FROM git_revisions
                 WHERE contribution_id=?1 AND sequence=?2",
                params![contribution_id, sequence],
                revision_row,
            )
            .optional()?;
        let revision = revision.ok_or_else(|| {
            ReviewError::Missing(format!("revision {contribution_id}/{sequence}"))
        })?;
        pins.verify(&revision.pin())?;
        Ok(revision)
    }
}

impl GitRevision {
    fn pin(&self) -> crate::source_review_git::GitPin {
        crate::source_review_git::GitPin {
            contribution_id: self.contribution_id.clone(),
            upload_id: self.upload_id.clone(),
            source_ref: self.source_ref.clone(),
            commit_oid: self.commit_oid.clone(),
            tree_oid: self.tree_oid.clone(),
            pin_ref: self.pin_ref.clone(),
        }
    }
}

fn revision_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GitRevision> {
    Ok(GitRevision {
        contribution_id: row.get(0)?,
        sequence: row.get(1)?,
        upload_id: row.get(2)?,
        actor: row.get(3)?,
        source_ref: row.get(4)?,
        commit_oid: row.get(5)?,
        tree_oid: row.get(6)?,
        pin_ref: row.get(7)?,
    })
}

fn revision_by_upload(
    connection: &Connection,
    contribution_id: &str,
    upload_id: &str,
) -> ReviewResult<Option<GitRevision>> {
    Ok(connection
        .query_row(
            "SELECT contribution_id, sequence, upload_id, actor, source_ref,
                    commit_oid, tree_oid, pin_ref FROM git_revisions
             WHERE contribution_id=?1 AND upload_id=?2",
            params![contribution_id, upload_id],
            revision_row,
        )
        .optional()?)
}

fn same_upload(
    revision: &GitRevision,
    actor: &str,
    source_ref: &str,
    commit_oid: &str,
) -> ReviewResult<()> {
    if (
        revision.actor.as_str(),
        revision.source_ref.as_str(),
        revision.commit_oid.as_str(),
    ) != (actor, source_ref, commit_oid)
    {
        return Err(ReviewError::Conflict(
            "upload id already names another revision".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn store_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "whipplescript-source-review-{}-{}.sqlite",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    struct GitFixture {
        root: PathBuf,
        bare: PathBuf,
        work: PathBuf,
        database: PathBuf,
    }

    impl GitFixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "whipplescript-review-upload-{}-{}",
                std::process::id(),
                NEXT_FILE.fetch_add(1, Ordering::Relaxed)
            ));
            let bare = root.join("source.git");
            let work = root.join("work");
            let database = root.join("review.sqlite");
            std::fs::create_dir_all(&work).expect("fixture directory");
            git(
                None,
                &["init", "--bare", "-q", bare.to_str().expect("bare path")],
            );
            git(Some(&work), &["init", "-q"]);
            git(Some(&work), &["config", "user.name", "Author"]);
            git(
                Some(&work),
                &["config", "user.email", "author@example.test"],
            );
            git(Some(&work), &["checkout", "-qb", "work"]);
            Self {
                root,
                bare,
                work,
                database,
            }
        }

        fn commit(&self, content: &str) -> String {
            std::fs::write(self.work.join("story.txt"), content).expect("write");
            git(Some(&self.work), &["add", "story.txt"]);
            git(Some(&self.work), &["commit", "-qm", "candidate"]);
            git(
                Some(&self.work),
                &[
                    "push",
                    "-q",
                    self.bare.to_str().expect("bare path"),
                    "HEAD:refs/heads/work",
                ],
            );
            git(Some(&self.work), &["rev-parse", "HEAD"])
        }

        fn pins(&self) -> GitCandidatePins {
            GitCandidatePins::open(&self.bare).expect("bare pins")
        }

        fn store(&self) -> ReviewStore {
            ReviewStore::open(&self.database).expect("review store")
        }
    }

    impl Drop for GitFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).expect("remove fixture");
        }
    }

    fn git(work: Option<&Path>, args: &[&str]) -> String {
        let mut command = Command::new("git");
        if let Some(work) = work {
            command.arg("-C").arg(work);
        }
        let output = command.args(args).output().expect("run Git");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().into()
    }

    #[test]
    fn contribution_identity_and_dependencies_survive_restart() {
        let path = store_path();
        let mut store = ReviewStore::open(&path).expect("open");
        store
            .create_contribution("A", "alice", "First", "refs/heads/main", &[])
            .expect("first");
        let b = store
            .create_contribution("B", "bob", "Second", "refs/heads/main", &["A"])
            .expect("dependent");
        assert_eq!(b.predecessors, vec!["A"]);
        drop(store);
        let reopened = ReviewStore::open(&path).expect("reopen");
        assert_eq!(reopened.contribution("B").expect("read"), b);
        std::fs::remove_file(path).expect("remove db");
    }

    #[test]
    fn old_git_contributions_keep_their_kind_when_native_scope_is_added() {
        let path = store_path();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE contributions (
                    id TEXT PRIMARY KEY,
                    author TEXT NOT NULL,
                    intent TEXT NOT NULL,
                    target_ref TEXT NOT NULL,
                    created_at INTEGER NOT NULL DEFAULT (unixepoch())
                );
                INSERT INTO contributions (id, author, intent, target_ref)
                VALUES ('old', 'alice', 'before native', 'refs/heads/main');",
            )
            .unwrap();
        drop(connection);
        let mut store = ReviewStore::open(&path).unwrap();
        let old = store.contribution("old").unwrap();
        assert_eq!(old.source_kind, SourceKind::Git);
        assert_eq!(old.target_scope, "refs/heads/main");
        let native = store
            .create_native_contribution("new", "alice", "native", "main", &[])
            .unwrap();
        assert_eq!(native.source_kind, SourceKind::Native);
        assert_eq!(native.target_scope, "main");
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn source_kind_and_target_scope_refuse_invalid_records() {
        let mut store = ReviewStore::open(":memory:").unwrap();
        match store.create_contribution("git-bad", "alice", "change", "refs/tags/v1", &[]) {
            Err(ReviewError::Invalid(message)) => {
                assert_eq!(message, "target must name a full branch ref")
            }
            other => panic!("expected Git target refusal, found {other:?}"),
        }
        assert!(matches!(
            store.contribution("git-bad"),
            Err(ReviewError::Missing(_))
        ));
        match store.create_native_contribution(
            "native-bad",
            "alice",
            "change",
            "refs/heads/main",
            &[],
        ) {
            Err(ReviewError::Invalid(message)) => {
                assert_eq!(message, "target must name a WhippleScript branch id")
            }
            other => panic!("expected native target refusal, found {other:?}"),
        }
        assert!(matches!(
            store.contribution("native-bad"),
            Err(ReviewError::Missing(_))
        ));
        store
            .create_contribution("git", "alice", "change", "refs/heads/main", &[])
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE contributions SET source_kind='unknown' WHERE id='git'",
                [],
            )
            .unwrap();
        match store.contribution("git") {
            Err(ReviewError::Corrupt(message)) => {
                assert_eq!(message, "unknown source kind unknown")
            }
            other => panic!("expected unknown source kind refusal, found {other:?}"),
        }
    }

    #[test]
    fn git_upload_refuses_a_native_contribution() {
        let fixture = GitFixture::new();
        let commit = fixture.commit("one\n");
        let mut store = fixture.store();
        store
            .create_native_contribution("native", "alice", "change", "main", &[])
            .unwrap();
        assert!(matches!(
            store.upload_git_revision(
                &fixture.pins(),
                "native",
                "upload",
                "alice",
                "refs/heads/work",
                &commit
            ),
            Err(ReviewError::Invalid(_))
        ));
    }

    #[test]
    fn invalid_identity_scope_and_dependency_leave_no_record() {
        let path = store_path();
        let mut store = ReviewStore::open(&path).expect("open");
        assert!(matches!(
            store.create_contribution("../bad", "alice", "First", "refs/heads/main", &[]),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            store.create_contribution("A", "", "First", "refs/heads/main", &[]),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            store.create_contribution("A", "alice", "", "refs/heads/main", &[]),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            store.create_contribution("A", "alice", "First", "refs/tags/v1", &[]),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            store.create_contribution("A", "alice", "First", "refs/heads/main", &["A"]),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            store.create_contribution("A", "alice", "First", "refs/heads/main", &["missing"]),
            Err(ReviewError::Sqlite(_))
        ));
        assert!(matches!(
            store.contribution("A"),
            Err(ReviewError::Missing(_))
        ));
        store
            .create_contribution("A", "alice", "First", "refs/heads/main", &[])
            .expect("failed writes rolled back");
        assert!(matches!(
            store.create_contribution("A", "alice", "Different", "refs/heads/main", &[]),
            Err(ReviewError::Sqlite(_))
        ));
        std::fs::remove_file(path).expect("remove db");
    }

    #[test]
    fn git_revisions_are_append_only_and_survive_restart() {
        let fixture = GitFixture::new();
        let first = fixture.commit("one\n");
        let pins = fixture.pins();
        let mut store = fixture.store();
        store
            .create_contribution("C1", "alice", "Intent", "refs/heads/main", &[])
            .expect("contribution");
        let revision = store
            .upload_git_revision(
                &pins,
                "C1",
                "upload-one",
                "alice",
                "refs/heads/work",
                &first,
            )
            .expect("first revision");
        assert_eq!(revision.sequence, 1);
        assert_eq!(revision.commit_oid, first);
        drop(store);
        let second = fixture.commit("one\ntwo\n");
        let mut reopened = fixture.store();
        assert_eq!(
            reopened
                .git_revision(&pins, "C1", 1)
                .expect("read revision"),
            revision
        );
        assert_eq!(
            reopened
                .upload_git_revision(
                    &pins,
                    "C1",
                    "upload-one",
                    "alice",
                    "refs/heads/work",
                    &first
                )
                .expect("retry"),
            revision
        );
        let next = reopened
            .upload_git_revision(
                &pins,
                "C1",
                "upload-two",
                "alice",
                "refs/heads/work",
                &second,
            )
            .expect("next revision");
        assert_eq!(next.sequence, 2);
        assert_ne!(next.tree_oid, revision.tree_oid);
        assert_eq!(
            reopened.git_revision(&pins, "C1", 1).expect("old revision"),
            revision
        );
    }

    #[test]
    fn pending_upload_recovers_after_pin_and_source_rewrite() {
        let fixture = GitFixture::new();
        let first = fixture.commit("one\n");
        let pins = fixture.pins();
        let mut store = fixture.store();
        store
            .create_contribution("C1", "alice", "Intent", "refs/heads/main", &[])
            .expect("contribution");
        store.connection.execute(
            "INSERT INTO pending_git_uploads (contribution_id, upload_id, actor, source_ref, commit_oid) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["C1", "upload-one", "alice", "refs/heads/work", first],
        ).expect("simulate committed pending phase");
        pins.pin("C1", "upload-one", "refs/heads/work", &first)
            .expect("simulate pin before crash");
        drop(store);
        git(
            Some(&fixture.work),
            &["checkout", "--orphan", "replacement"],
        );
        std::fs::write(fixture.work.join("story.txt"), "unrelated\n").expect("rewrite");
        git(Some(&fixture.work), &["add", "story.txt"]);
        git(Some(&fixture.work), &["commit", "-qm", "replacement"]);
        git(
            Some(&fixture.work),
            &[
                "push",
                "-q",
                "--force",
                fixture.bare.to_str().expect("bare path"),
                "HEAD:refs/heads/work",
            ],
        );
        let mut reopened = fixture.store();
        let recovered = reopened
            .upload_git_revision(
                &pins,
                "C1",
                "upload-one",
                "alice",
                "refs/heads/work",
                &first,
            )
            .expect("recover pin");
        assert_eq!(recovered.commit_oid, first);
        assert_eq!(recovered.sequence, 1);
    }

    #[test]
    fn changed_upload_and_moved_pin_are_refused() {
        let fixture = GitFixture::new();
        let first = fixture.commit("one\n");
        let pins = fixture.pins();
        let mut store = fixture.store();
        store
            .create_contribution("C1", "alice", "Intent", "refs/heads/main", &[])
            .expect("contribution");
        assert!(
            matches!(store.upload_git_revision(&pins, "C1", "upload-one", "bob", "refs/heads/work", &first), Err(ReviewError::Invalid(message)) if message == "only the author may upload")
        );
        let revision = store
            .upload_git_revision(
                &pins,
                "C1",
                "upload-one",
                "alice",
                "refs/heads/work",
                &first,
            )
            .expect("upload");
        store
            .connection
            .execute(
                "UPDATE git_revisions SET tree_oid='not-the-tree' WHERE contribution_id='C1' AND sequence=1",
                [],
            )
            .expect("simulate corrupt metadata");
        assert!(matches!(
            store.git_revision(&pins, "C1", 1),
            Err(ReviewError::Corrupt(message)) if message == "candidate tree disagrees with its commit"
        ));
        store
            .connection
            .execute(
                "UPDATE git_revisions SET tree_oid=?1 WHERE contribution_id='C1' AND sequence=1",
                [&revision.tree_oid],
            )
            .expect("restore metadata");
        let second = fixture.commit("two\n");
        assert!(
            matches!(store.upload_git_revision(&pins, "C1", "upload-one", "alice", "refs/heads/work", &second), Err(ReviewError::Conflict(message)) if message == "upload id already names another revision")
        );
        git(
            None,
            &[
                "--git-dir",
                fixture.bare.to_str().expect("bare path"),
                "update-ref",
                &revision.pin_ref,
                &second,
                &first,
            ],
        );
        assert!(
            matches!(store.git_revision(&pins, "C1", 1), Err(ReviewError::Corrupt(message)) if message == "candidate pin is missing or moved")
        );
    }

    #[test]
    fn invalid_and_conflicting_upload_requests_are_refused() {
        let fixture = GitFixture::new();
        let first = fixture.commit("one\n");
        let pins = fixture.pins();
        let mut store = fixture.store();
        store
            .create_contribution("C1", "alice", "Intent", "refs/heads/main", &[])
            .expect("contribution");
        assert!(matches!(
            store.upload_git_revision(&pins, "C1", "../bad", "alice", "refs/heads/work", &first),
            Err(ReviewError::Invalid(message)) if message == "invalid upload id"
        ));
        assert!(matches!(
            store.upload_git_revision(&pins, "C1", "blank-actor", "", "refs/heads/work", &first),
            Err(ReviewError::Invalid(message)) if message == "upload actor is required"
        ));
        assert!(matches!(
            store.upload_git_revision(&pins, "C1", "bad-source", "alice", "refs/tags/v1", &first),
            Err(ReviewError::Invalid(message)) if message == "upload source must be a branch"
        ));
        assert!(matches!(
            store.upload_git_revision(&pins, "unknown", "upload-one", "alice", "refs/heads/work", &first),
            Err(ReviewError::Missing(message)) if message == "contribution unknown"
        ));
        let second = fixture.commit("two\n");
        store.connection.execute(
            "INSERT INTO pending_git_uploads (contribution_id, upload_id, actor, source_ref, commit_oid) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["C1", "upload-one", "alice", "refs/heads/work", first],
        ).expect("pending upload");
        assert!(matches!(
            store.upload_git_revision(&pins, "C1", "upload-one", "alice", "refs/heads/work", &second),
            Err(ReviewError::Conflict(message)) if message == "upload id changed while pending"
        ));
        assert!(matches!(
            store.git_revision(&pins, "C1", 1),
            Err(ReviewError::Missing(message)) if message == "revision C1/1"
        ));
    }

    #[test]
    fn publication_refuses_a_changed_pending_upload() {
        let fixture = GitFixture::new();
        let first = fixture.commit("one\n");
        let pins = fixture.pins();
        let pin = pins
            .pin("C1", "upload-one", "refs/heads/work", &first)
            .expect("candidate pin");
        let second = fixture.commit("two\n");
        let mut store = fixture.store();
        store
            .create_contribution("C1", "alice", "Intent", "refs/heads/main", &[])
            .expect("contribution");
        store
            .connection
            .execute(
                "INSERT INTO pending_git_uploads (contribution_id, upload_id, actor, source_ref, commit_oid) VALUES (?1, ?2, ?3, ?4, ?5)",
                params!["C1", "upload-one", "alice", "refs/heads/work", second],
            )
            .expect("simulate changed pending row");
        assert!(matches!(
            store.finish_git_revision(
                &pins,
                GitUploadRequest {
                    contribution_id: "C1",
                    upload_id: "upload-one",
                    actor: "alice",
                    source_ref: "refs/heads/work",
                    commit_oid: &first,
                },
                &pin,
            ),
            Err(ReviewError::Corrupt(message)) if message == "pending upload changed"
        ));
    }
}
