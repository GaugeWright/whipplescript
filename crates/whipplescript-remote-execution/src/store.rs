//! The endpoint's blob store under the five rules of DR-0124 §14.3.
//!
//! Bytes are stored once, by digest. What a principal may do with them is a
//! separate fact: a *use* — one principal's admitted relationship to one
//! blob, carrying the labels the blob acquired in that use. Possession of a
//! digest grants nothing (rule 1); identical bytes under two uses carry two
//! labels (rule 3); what a view has no use of is missing under that view, and
//! its upload is accepted (rule 4). Rules 2 and 5 live in `cache.rs`.
//!
//! Uses are rows of the endpoint's database (`db.rs`), so they outlive the
//! process; a use belongs to the principal's name, which a restart keeps.
//! Handles are the process's own: a token minted for a principal, remembered
//! in memory, and gone when the process is. A read the database cannot answer
//! is answered as missing, which grants nothing; a write it cannot make is
//! refused.
//!
//! The bytes live in one of two places. An endpoint on its own keeps them in
//! its database. An endpoint serving a Home shares the artifact plane's
//! content store (§14.3): the bytes are stored there once, under the
//! workspace's content id, which is the first half of the same SHA-256 the
//! protocol names them by, so no mapping is kept and every read is checked
//! against the full digest. Sharing the bytes shares their erasure: bytes the
//! workspace erased read as missing under every view, and neither an upload
//! nor an execution can store them again. It shares nothing else — the
//! content store answers who may read nothing, so a blob the workspace holds
//! is still missing under a view with no use of it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, OptionalExtension};

use whipplescript_store::content::{BlobStatus, ContentBlobs, ContentStore};
use whipplescript_store::StoreError;

use crate::db::{labels_from_text, labels_to_text, Db};
use crate::digest::Digest;

/// A set of labels; the join of two is their union.
pub type Labels = BTreeSet<String>;

/// A principal the endpoint acts for: a name and the labels it holds.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Principal {
    pub name: String,
    #[serde(default)]
    pub labels: Labels,
}

impl Principal {
    pub fn holds(&self, labels: &Labels) -> bool {
        labels.is_subset(&self.labels)
    }
}

/// An authorized handle: a token naming an admitted principal, whose uses
/// are the view every answer is scoped to.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HandleId(pub String);

/// The store: blobs and uses in the database, handles in the process.
pub struct Store {
    db: Db,
    shared: Option<Mutex<ContentStore>>,
    handles: Mutex<BTreeMap<HandleId, Principal>>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

/// The store's size, as the operator reads it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct StoreStats {
    pub blobs: usize,
    pub bytes: usize,
    pub uses: usize,
    pub principals: usize,
    pub handles: usize,
}

/// A view over the store: one handle, its principal, the principal's uses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct View {
    pub handle: HandleId,
    pub principal: Principal,
}

/// A write the database refused, in the words every refusal of one uses.
pub(crate) fn written<T>(what: &str, result: rusqlite::Result<T>) -> Result<T, String> {
    result.map_err(|error| format!("cannot write {what} to the endpoint's state: {error}"))
}

/// A write the workspace's content store refused, in its own words.
fn shared_written<T>(what: &str, result: Result<T, StoreError>) -> Result<T, String> {
    result.map_err(|error| {
        let reason = match error {
            StoreError::Conflict(reason) => reason,
            other => format!("{other:?}"),
        };
        format!("cannot write {what} to the workspace's content store: {reason}")
    })
}

/// The workspace's content id for a digest: the first 128 bits of the same
/// SHA-256, which is how the artifact plane truncates its hashes. None for a
/// digest that is not a SHA-256 in hex, which no stored bytes can have.
fn content_id(digest: &Digest) -> Option<&str> {
    (digest.hash.len() == 64)
        .then(|| digest.hash.get(..32))
        .flatten()
}

impl Store {
    /// A store that lives as long as the process.
    pub fn new() -> Self {
        Self::over(Db::in_memory())
    }

    /// A store over the endpoint's database.
    pub fn over(db: Db) -> Self {
        Self {
            db,
            shared: None,
            handles: Mutex::new(BTreeMap::new()),
        }
    }

    /// A store whose uses are the endpoint's database and whose bytes are the
    /// workspace's content store. Bytes an earlier process kept in the
    /// database move into the content store first — except bytes the
    /// workspace has erased, which are dropped rather than restored — so after
    /// this there is one copy of every blob, and it is the workspace's.
    pub fn sharing(db: Db, content: ContentStore) -> Result<Self, String> {
        let kept: Vec<(String, Vec<u8>)> = db
            .lock()
            .prepare("SELECT hash, bytes FROM blobs")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .and_then(Iterator::collect)
            })
            .map_err(|error| format!("cannot read the endpoint's own blobs: {error}"))?;
        for (hash, bytes) in kept {
            let digest = Digest::of(&bytes);
            let what = format!("blob {digest}");
            // A row whose bytes are not the digest it is filed under is
            // damage, and bytes the workspace erased stay erased: both are
            // dropped rather than carried across.
            if digest.hash == hash {
                let erased = content_id(&digest)
                    .map(|id| shared_written(&what, content.erased_byte_len(id)))
                    .transpose()?
                    .flatten()
                    .is_some();
                if !erased {
                    shared_written(&what, content.put_unerased(&bytes))?;
                }
            }
            written(
                &what,
                db.lock()
                    .execute("DELETE FROM blobs WHERE hash = ?1", params![hash]),
            )?;
        }
        Ok(Self {
            db,
            shared: Some(Mutex::new(content)),
            handles: Mutex::new(BTreeMap::new()),
        })
    }

    fn content(&self) -> Option<MutexGuard<'_, ContentStore>> {
        self.shared.as_ref().map(|content| {
            content
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        })
    }

    fn handles(&self) -> MutexGuard<'_, BTreeMap<HandleId, Principal>> {
        self.handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Admit a principal under a handle. A handle is minted once; admitting
    /// the same handle for a different principal is refused, so a token
    /// never changes hands, and one process admits a name with one set of
    /// labels. The principal is recorded as declared: a later process's
    /// declaration is the operator's, and replaces it.
    pub fn admit(&self, handle: HandleId, principal: Principal) -> Result<View, String> {
        let mut handles = self.handles();
        if let Some(existing) = handles.get(&handle) {
            if existing != &principal {
                return Err(format!(
                    "handle {} is already admitted for {}",
                    handle.0, existing.name
                ));
            }
        }
        if handles
            .values()
            .any(|admitted| admitted.name == principal.name && admitted != &principal)
        {
            return Err(format!(
                "{} is already admitted here with other labels",
                principal.name
            ));
        }
        written(
            &format!("principal {}", principal.name),
            self.db.lock().execute(
                "INSERT INTO principals (name, labels) VALUES (?1, ?2)
                 ON CONFLICT (name) DO UPDATE SET labels = excluded.labels",
                params![principal.name, labels_to_text(&principal.labels)],
            ),
        )?;
        handles.insert(handle.clone(), principal.clone());
        Ok(View { handle, principal })
    }

    /// The view a handle names, or none: an unknown handle sees nothing.
    pub fn view(&self, handle: &HandleId) -> Option<View> {
        self.handles().get(handle).map(|principal| View {
            handle: handle.clone(),
            principal: principal.clone(),
        })
    }

    /// Join labels into the principal's use of a stored blob.
    fn join_use(
        connection: &rusqlite::Connection,
        principal: &str,
        digest: &Digest,
        labels: &Labels,
    ) -> rusqlite::Result<()> {
        let mut joined: Labels = connection
            .query_row(
                "SELECT labels FROM uses WHERE principal = ?1 AND hash = ?2",
                params![principal, digest.hash],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|text| labels_from_text(&text))
            .unwrap_or_default();
        joined.extend(labels.iter().cloned());
        connection.execute(
            "INSERT INTO uses (principal, hash, labels) VALUES (?1, ?2, ?3)
             ON CONFLICT (principal, hash) DO UPDATE SET labels = excluded.labels",
            params![principal, digest.hash, labels_to_text(&joined)],
        )?;
        Ok(())
    }

    /// Store bytes under the view's use with the labels given. Bytes already
    /// present are not stored twice, and the duplicate is accepted exactly as
    /// the first upload was (rule 4); the use's labels are the join of every
    /// admission of this blob under this principal (rule 3 keeps other
    /// principals' uses apart).
    pub fn put(&self, view: &View, bytes: &[u8], labels: &Labels) -> Result<Digest, String> {
        let digest = Digest::of(bytes);
        if let Some(content) = self.content() {
            // The workspace refuses an identity it erased; that refusal is
            // the endpoint's, so erased bytes are never stored again.
            shared_written(&format!("blob {digest}"), content.put_unerased(bytes))?;
            drop(content);
            return written(
                &format!("a use of {digest}"),
                Self::join_use(&self.db.lock(), &view.principal.name, &digest, labels),
            )
            .map(|()| digest);
        }
        let mut connection = self.db.lock();
        written(
            &format!("blob {digest}"),
            connection.transaction().and_then(|transaction| {
                transaction.execute(
                    "INSERT OR IGNORE INTO blobs (hash, bytes) VALUES (?1, ?2)",
                    params![digest.hash, bytes],
                )?;
                Self::join_use(&transaction, &view.principal.name, &digest, labels)?;
                transaction.commit()
            }),
        )?;
        Ok(digest)
    }

    /// Grant a view a use of a blob it did not upload — an output the view
    /// may read, or a cut's encoding projected under it — with the labels of
    /// that use. Refused when the bytes are not stored: a use of nothing is
    /// not a fact.
    pub fn grant(&self, view: &View, digest: &Digest, labels: &Labels) -> Result<(), String> {
        if !self.stored(digest) {
            return Err(format!("no blob {digest} to grant a use of"));
        }
        written(
            &format!("a use of {digest}"),
            Self::join_use(&self.db.lock(), &view.principal.name, digest, labels),
        )
    }

    /// The labels of the view's use of a blob, or none when the view has no
    /// use of it — which is what "missing" means under that view.
    pub fn use_of(&self, view: &View, digest: &Digest) -> Option<Labels> {
        if digest.is_empty() {
            return Some(Labels::new());
        }
        self.db
            .lock()
            .query_row(
                "SELECT labels FROM uses WHERE principal = ?1 AND hash = ?2",
                params![view.principal.name, digest.hash],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten()
            .map(|text| labels_from_text(&text))
    }

    /// The bytes, under a view that holds a use of them and whose principal
    /// holds the use's labels. Anything else is missing under that view.
    pub fn get(&self, view: &View, digest: &Digest) -> Option<Vec<u8>> {
        if digest.is_empty() {
            return Some(Vec::new());
        }
        let labels = self.use_of(view, digest)?;
        if !view.principal.holds(&labels) {
            return None;
        }
        self.bytes(digest)
    }

    /// The stored bytes for a digest, from wherever they live, and only when
    /// they are the bytes the full digest names.
    fn bytes(&self, digest: &Digest) -> Option<Vec<u8>> {
        let bytes = match self.content() {
            Some(content) => content.get(content_id(digest)?).ok().flatten()?,
            None => self
                .db
                .lock()
                .query_row(
                    "SELECT bytes FROM blobs WHERE hash = ?1",
                    params![digest.hash],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .ok()
                .flatten()?,
        };
        (Digest::of(&bytes) == *digest).then_some(bytes)
    }

    /// Which of the digests are missing under the view: every one the view
    /// has no readable use of, whether or not the bytes are stored (rule 4),
    /// and every one whose bytes are gone — erased, or collected — whatever
    /// use the view held of them.
    pub fn missing<'d>(
        &self,
        view: &View,
        digests: impl IntoIterator<Item = &'d Digest>,
    ) -> Vec<Digest> {
        digests
            .into_iter()
            .filter(|digest| {
                !digest.is_empty()
                    && (self
                        .use_of(view, digest)
                        .is_none_or(|labels| !view.principal.holds(&labels))
                        || !self.stored(digest))
            })
            .cloned()
            .collect()
    }

    /// What the store holds, for the operator's eyes: never an answer given
    /// to a caller.
    pub fn stats(&self) -> StoreStats {
        let handles = self.handles();
        let handles = handles.len();
        let (uses, principals, own) = {
            let connection = self.db.lock();
            let count = |sql: &str| -> usize {
                connection
                    .query_row(sql, [], |row| row.get::<_, i64>(0))
                    .map(|n| usize::try_from(n).unwrap_or(0))
                    .unwrap_or(0)
            };
            let own = (
                count("SELECT COUNT(*) FROM blobs"),
                count("SELECT COALESCE(SUM(LENGTH(bytes)), 0) FROM blobs"),
            );
            (
                count("SELECT COUNT(*) FROM uses"),
                count("SELECT COUNT(*) FROM principals"),
                own,
            )
        };
        // Shared bytes are counted as the blobs some use names that the
        // workspace still holds: the endpoint's share of the content store.
        let (blobs, bytes) = match self.content() {
            None => own,
            Some(content) => {
                let hashes: Vec<String> = {
                    let connection = self.db.lock();
                    connection
                        .prepare("SELECT DISTINCT hash FROM uses")
                        .and_then(|mut statement| {
                            statement
                                .query_map([], |row| row.get::<_, String>(0))
                                .and_then(Iterator::collect)
                        })
                        .unwrap_or_default()
                };
                hashes
                    .iter()
                    .filter_map(|hash| match content.status(hash.get(..32)?).ok()? {
                        BlobStatus::Live { byte_len } => usize::try_from(byte_len).ok(),
                        BlobStatus::Erased { .. } | BlobStatus::Unknown => None,
                    })
                    .fold((0, 0), |(blobs, bytes), len| (blobs + 1, bytes + len))
            }
        };
        StoreStats {
            blobs,
            bytes,
            uses,
            principals,
            handles,
        }
    }

    /// Whether the bytes are stored at all: the store's own knowledge, never
    /// an answer given to a caller.
    pub fn stored(&self, digest: &Digest) -> bool {
        if digest.is_empty() {
            return true;
        }
        match self.content() {
            Some(content) => content_id(digest).is_some_and(|id| {
                matches!(
                    content.status(id),
                    Ok(BlobStatus::Live { byte_len })
                        if i64::try_from(byte_len).ok() == Some(digest.size_bytes)
                )
            }),
            None => self
                .db
                .lock()
                .query_row(
                    "SELECT 1 FROM blobs WHERE hash = ?1",
                    params![digest.hash],
                    |_| Ok(()),
                )
                .optional()
                .ok()
                .flatten()
                .is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(list: &[&str]) -> Labels {
        list.iter().map(|l| l.to_string()).collect()
    }

    fn principal(name: &str, held: &[&str]) -> Principal {
        Principal {
            name: name.into(),
            labels: labels(held),
        }
    }

    #[test]
    fn a_digest_grants_nothing_and_identical_bytes_keep_their_uses_apart() {
        let store = Store::new();
        let owner = store
            .admit(
                HandleId("h-owner".into()),
                principal("owner", &["protected"]),
            )
            .unwrap();
        let dev = store
            .admit(HandleId("h-dev".into()), principal("dev", &[]))
            .unwrap();
        assert_eq!(
            store
                .admit(HandleId("h-dev".into()), principal("other", &[]))
                .unwrap_err(),
            "handle h-dev is already admitted for dev"
        );
        assert_eq!(store.view(&HandleId("h-dev".into())), Some(dev.clone()));
        assert_eq!(store.view(&HandleId("nobody".into())), None);
        let digest = store
            .put(&owner, b"secret bytes", &labels(&["protected"]))
            .unwrap();
        // Rule 1: dev knows the digest and reads nothing by it.
        assert_eq!(store.get(&dev, &digest), None);
        assert_eq!(store.missing(&dev, [&digest]), vec![digest.clone()]);
        assert!(store.stored(&digest));
        // Rule 4: dev's upload of the same bytes is accepted, and rule 3: their
        // use carries their labels, not owner's.
        let again = store.put(&dev, b"secret bytes", &labels(&[])).unwrap();
        assert_eq!(again, digest);
        assert_eq!(
            store.get(&dev, &digest).as_deref(),
            Some(&b"secret bytes"[..])
        );
        assert_eq!(store.use_of(&dev, &digest), Some(labels(&[])));
        assert_eq!(store.use_of(&owner, &digest), Some(labels(&["protected"])));
        assert!(store.missing(&dev, [&digest]).is_empty());
        // A use granted with labels the principal does not hold reads nothing.
        let output = store
            .put(&owner, b"an output", &labels(&["protected"]))
            .unwrap();
        store.grant(&dev, &output, &labels(&["protected"])).unwrap();
        assert_eq!(store.get(&dev, &output), None);
        assert_eq!(store.missing(&dev, [&output]), vec![output.clone()]);
        assert_eq!(
            store
                .grant(&dev, &Digest::of(b"never stored"), &labels(&[]))
                .unwrap_err(),
            format!("no blob {} to grant a use of", Digest::of(b"never stored"))
        );
        // The empty blob is always present, as the protocol promises.
        assert_eq!(store.get(&dev, &Digest::empty()), Some(Vec::new()));
        assert!(store.missing(&dev, [&Digest::empty()]).is_empty());
        // One process admits a name with one set of labels.
        assert_eq!(
            store
                .admit(HandleId("h-dev-2".into()), principal("dev", &["protected"]))
                .unwrap_err(),
            "dev is already admitted here with other labels"
        );
        store
            .admit(HandleId("h-dev-3".into()), principal("dev", &[]))
            .expect("a second handle for the same declaration");
    }

    #[test]
    fn uses_outlive_the_process_under_the_principals_name_and_a_refused_write_says_so() {
        let dir = tempfile::tempdir().expect("scratch");
        let path = dir.path().join("endpoint.sqlite");
        let digest = {
            let store = Store::over(Db::open(&path).unwrap());
            let owner = store
                .admit(
                    HandleId("first-token".into()),
                    principal("owner", &["protected"]),
                )
                .unwrap();
            store
                .put(&owner, b"kept bytes", &labels(&["protected"]))
                .unwrap()
        };
        // A new process mints new tokens; the use is the principal's, not the
        // old token's, and the old token names nobody.
        let store = Store::over(Db::open(&path).unwrap());
        assert_eq!(store.view(&HandleId("first-token".into())), None);
        let owner = store
            .admit(
                HandleId("second-token".into()),
                principal("owner", &["protected"]),
            )
            .unwrap();
        let dev = store
            .admit(HandleId("dev-token".into()), principal("dev", &[]))
            .unwrap();
        assert_eq!(
            store.get(&owner, &digest).as_deref(),
            Some(&b"kept bytes"[..])
        );
        assert_eq!(store.missing(&dev, [&digest]), vec![digest.clone()]);
        assert_eq!(
            store.stats(),
            StoreStats {
                blobs: 1,
                bytes: 10,
                uses: 1,
                principals: 2,
                handles: 2,
            }
        );
        // A principal redeclared without the label it held reads nothing by
        // the use it had.
        let demoted = Store::over(Db::open(&path).unwrap());
        let owner = demoted
            .admit(HandleId("third-token".into()), principal("owner", &[]))
            .unwrap();
        assert_eq!(demoted.get(&owner, &digest), None);
        store.db.refuse_writes();
        assert_eq!(
            store.put(&dev, b"new bytes", &labels(&[])).unwrap_err(),
            format!(
                "cannot write blob {} to the endpoint's state: attempt to write a readonly database",
                Digest::of(b"new bytes")
            )
        );
    }

    #[test]
    fn shared_bytes_live_once_in_the_workspace_and_its_erasure_is_the_endpoints() {
        let dir = tempfile::tempdir().expect("scratch");
        let state = dir.path().join("endpoint.sqlite");
        let content_path = dir.path().join("vcs-content.sqlite");
        let workspace = ContentStore::open(&content_path).unwrap();
        // An earlier endpoint kept its own bytes: one the workspace has since
        // erased, one it has not.
        let (carried, erased_before) = {
            let store = Store::over(Db::open(&state).unwrap());
            let owner = store
                .admit(HandleId("t0".into()), principal("owner", &["protected"]))
                .unwrap();
            let carried = store
                .put(&owner, b"carried bytes", &labels(&["protected"]))
                .unwrap();
            let erased_before = store.put(&owner, b"erased before", &labels(&[])).unwrap();
            let id = workspace.put(b"erased before").unwrap();
            assert_eq!(id, erased_before.hash[..32]);
            workspace.erase(&id, "t1").unwrap();
            (carried, erased_before)
        };
        let db = Db::open(&state).unwrap();
        let store = Store::sharing(db.clone(), ContentStore::open(&content_path).unwrap()).unwrap();
        let own: i64 = db
            .lock()
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(own, 0, "every blob now has one copy, the workspace's");
        let owner = store
            .admit(HandleId("t1".into()), principal("owner", &["protected"]))
            .unwrap();
        let dev = store
            .admit(HandleId("t2".into()), principal("dev", &[]))
            .unwrap();
        assert_eq!(
            store.get(&owner, &carried).as_deref(),
            Some(&b"carried bytes"[..])
        );
        assert_eq!(
            workspace.get(&carried.hash[..32]).unwrap().as_deref(),
            Some(&b"carried bytes"[..])
        );
        assert_eq!(store.get(&owner, &erased_before), None);
        assert_eq!(
            store.missing(&owner, [&erased_before]),
            vec![erased_before.clone()]
        );
        // Rule 1 across the planes: bytes the workspace holds are missing
        // under a view with no use of them, and their upload is accepted.
        let id = workspace.put(b"workspace bytes").unwrap();
        let held = Digest::of(b"workspace bytes");
        assert_eq!(id, held.hash[..32]);
        assert!(store.stored(&held));
        assert_eq!(store.missing(&dev, [&held]), vec![held.clone()]);
        assert_eq!(
            store.put(&dev, b"workspace bytes", &labels(&[])).unwrap(),
            held
        );
        assert_eq!(
            store.get(&dev, &held).as_deref(),
            Some(&b"workspace bytes"[..])
        );
        // The workspace's erasure is the endpoint's: the bytes read as missing
        // under every view and cannot be uploaded again.
        let doomed = store.put(&owner, b"to be erased", &labels(&[])).unwrap();
        workspace.erase(&doomed.hash[..32], "t2").unwrap();
        assert_eq!(store.get(&owner, &doomed), None);
        assert!(!store.stored(&doomed));
        assert_eq!(
            store.put(&owner, b"to be erased", &labels(&[])).unwrap_err(),
            format!(
                "cannot write blob {doomed} to the workspace's content store: derived content identity was erased"
            )
        );
        assert_eq!(
            store.stats(),
            StoreStats {
                blobs: 2,
                bytes: 13 + 15,
                uses: 4,
                principals: 2,
                handles: 2,
            }
        );
        // A digest that is not a SHA-256 names nothing in either plane.
        let malformed = Digest {
            hash: "abc".into(),
            size_bytes: 3,
        };
        assert_eq!(store.get(&owner, &malformed), None);
        let broken = Db::open(&dir.path().join("broken.sqlite")).unwrap();
        broken.lock().execute_batch("DROP TABLE blobs").unwrap();
        assert_eq!(
            Store::sharing(broken, ContentStore::open(&content_path).unwrap())
                .err()
                .expect("refused"),
            "cannot read the endpoint's own blobs: no such table: blobs"
        );
    }
}
