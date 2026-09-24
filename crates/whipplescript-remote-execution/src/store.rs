//! The endpoint's blob store under the five rules of DR-0124 §14.3.
//!
//! Bytes are stored once, by digest. What a principal may do with them is a
//! separate fact: a *use* — one principal's admitted relationship to one
//! blob, carrying the labels the blob acquired in that use. Possession of a
//! digest grants nothing (rule 1); identical bytes under two uses carry two
//! labels (rule 3); what a view has no use of is missing under that view, and
//! its upload is accepted (rule 4). Rules 2 and 5 live in `cache.rs`.
//!
//! Blobs and uses are rows of the endpoint's database (`db.rs`), so they
//! outlive the process; a use belongs to the principal's name, which a
//! restart keeps. Handles are the process's own: a token minted for a
//! principal, remembered in memory, and gone when the process is. A read the
//! database cannot answer is answered as missing, which grants nothing; a
//! write it cannot make is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, OptionalExtension};

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

impl Store {
    /// A store that lives as long as the process.
    pub fn new() -> Self {
        Self::over(Db::in_memory())
    }

    /// A store over the endpoint's database.
    pub fn over(db: Db) -> Self {
        Self {
            db,
            handles: Mutex::new(BTreeMap::new()),
        }
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
        self.db
            .lock()
            .query_row(
                "SELECT bytes FROM blobs WHERE hash = ?1",
                params![digest.hash],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Which of the digests are missing under the view: every one the view
    /// has no readable use of, whether or not the bytes are stored (rule 4).
    pub fn missing<'d>(
        &self,
        view: &View,
        digests: impl IntoIterator<Item = &'d Digest>,
    ) -> Vec<Digest> {
        digests
            .into_iter()
            .filter(|digest| {
                !digest.is_empty()
                    && self
                        .use_of(view, digest)
                        .is_none_or(|labels| !view.principal.holds(&labels))
            })
            .cloned()
            .collect()
    }

    /// What the store holds, for the operator's eyes: never an answer given
    /// to a caller.
    pub fn stats(&self) -> StoreStats {
        let handles = self.handles().len();
        let connection = self.db.lock();
        let count = |sql: &str| -> usize {
            connection
                .query_row(sql, [], |row| row.get::<_, i64>(0))
                .map(|n| usize::try_from(n).unwrap_or(0))
                .unwrap_or(0)
        };
        StoreStats {
            blobs: count("SELECT COUNT(*) FROM blobs"),
            bytes: count("SELECT COALESCE(SUM(LENGTH(bytes)), 0) FROM blobs"),
            uses: count("SELECT COUNT(*) FROM uses"),
            principals: count("SELECT COUNT(*) FROM principals"),
            handles,
        }
    }

    /// Whether the bytes are stored at all: the store's own knowledge, never
    /// an answer given to a caller.
    pub fn stored(&self, digest: &Digest) -> bool {
        digest.is_empty()
            || self
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
                .is_some()
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
}
