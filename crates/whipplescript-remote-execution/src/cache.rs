//! The action cache under rules 2 and 5 of DR-0124 §14.3.
//!
//! An entry records where its result came from — executed by the endpoint's
//! approved executor, or submitted by a client — because a matching digest
//! does not authenticate the producer (rule 2): a submitted result is served
//! back to the view that submitted it and to no one else, and it is never
//! evidence. An entry binds the classification of the result it caches, the
//! join of the labels of everything that shaped it (rule 5, and §14.2), and
//! is served only to a view whose principal holds that classification.

use prost::Message;
use rusqlite::{params, OptionalExtension};

use crate::db::Db;
use crate::digest::Digest;
use crate::proto::re;
use crate::store::{written, Labels, View};

/// Who produced a cached result.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Origin {
    /// The endpoint's own executor ran the action.
    Executed { executor: String },
    /// A client wrote the result: a claim, not an observation.
    Submitted { by: String },
}

/// What classified a cached result: the labels, and the inputs and platform
/// properties they were joined over — the analysis dependencies a cached
/// output must not lose.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Classification {
    pub labels: Labels,
    pub inputs: Vec<Digest>,
    pub platform: Vec<(String, String)>,
}

pub const CLASSIFICATION_TYPE_URL: &str = "whipplescript.build.classification/v1";

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub result: re::ActionResult,
    pub origin: Origin,
    pub classification: Classification,
    /// The principal a submitted result is scoped to; none for an executed
    /// one. A name, not a handle, so the scope outlives the process.
    pub submitted_by: Option<String>,
}

/// The action cache: rows of the endpoint's database, keyed by action digest.
pub struct ActionCache {
    db: Db,
}

impl Default for ActionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionCache {
    /// A cache that lives as long as the process.
    pub fn new() -> Self {
        Self::over(Db::in_memory())
    }

    /// A cache over the endpoint's database.
    pub fn over(db: Db) -> Self {
        Self { db }
    }

    fn write(&self, action: &Digest, entry: &Entry) -> Result<(), String> {
        written(
            &format!("the result of {action}"),
            self.db.lock().execute(
                "INSERT INTO actions (hash, result, origin, classification, submitted_by)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (hash) DO UPDATE SET result = excluded.result,
                   origin = excluded.origin, classification = excluded.classification,
                   submitted_by = excluded.submitted_by",
                params![
                    action.hash,
                    entry.result.encode_to_vec(),
                    serde_json::to_string(&entry.origin).unwrap_or_default(),
                    serde_json::to_string(&entry.classification).unwrap_or_default(),
                    entry.submitted_by,
                ],
            ),
        )
        .map(|_| ())
    }

    /// The stored entry for an action. A row that does not decode is no
    /// entry: it is served to no one and vouches for nothing.
    fn read(&self, action: &Digest) -> Option<Entry> {
        let (result, origin, classification, submitted_by) = self
            .db
            .lock()
            .query_row(
                "SELECT result, origin, classification, submitted_by FROM actions WHERE hash = ?1",
                params![action.hash],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten()?;
        let origin: Origin = serde_json::from_str(&origin).ok()?;
        // An executed row names no submitter and a submitted row names one;
        // a row that says otherwise is damaged.
        if matches!(origin, Origin::Executed { .. }) != submitted_by.is_none() {
            return None;
        }
        Some(Entry {
            result: re::ActionResult::decode(result.as_slice()).ok()?,
            origin,
            classification: serde_json::from_str(&classification).ok()?,
            submitted_by,
        })
    }

    /// Record what the approved executor produced. An executed entry
    /// replaces a submitted one for the same action: an observation outranks
    /// a claim.
    pub fn record_executed(
        &self,
        action: &Digest,
        executor: &str,
        result: re::ActionResult,
        classification: Classification,
    ) -> Result<(), String> {
        self.write(
            action,
            &Entry {
                result,
                origin: Origin::Executed {
                    executor: executor.to_owned(),
                },
                classification,
                submitted_by: None,
            },
        )
    }

    /// Accept a client's result under its own view. It never displaces an
    /// executed entry, and it is never evidence.
    pub fn record_submitted(
        &self,
        view: &View,
        action: &Digest,
        result: re::ActionResult,
        classification: Classification,
    ) -> Result<(), String> {
        if self.evidence(action).is_some() {
            return Err(format!(
                "action {action} has an executed result; a submitted one does not replace it"
            ));
        }
        self.write(
            action,
            &Entry {
                result,
                origin: Origin::Submitted {
                    by: view.principal.name.clone(),
                },
                classification,
                submitted_by: Some(view.principal.name.clone()),
            },
        )
    }

    /// The entry a view may read: an executed one whose classification the
    /// principal holds, or the principal's own submission. Anything else is
    /// not found under that view.
    pub fn lookup(&self, view: &View, action: &Digest) -> Option<Entry> {
        let entry = self.read(action)?;
        match &entry.submitted_by {
            Some(principal) if principal != &view.principal.name => return None,
            _ => {}
        }
        if !view.principal.holds(&entry.classification.labels) {
            return None;
        }
        Some(entry)
    }

    /// How many results the cache holds by origin: (executed, submitted).
    pub fn counts(&self) -> (usize, usize) {
        self.db
            .lock()
            .query_row(
                "SELECT COUNT(*) FILTER (WHERE submitted_by IS NULL),
                        COUNT(*) FILTER (WHERE submitted_by IS NOT NULL) FROM actions",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map(|(executed, submitted)| {
                (
                    usize::try_from(executed).unwrap_or(0),
                    usize::try_from(submitted).unwrap_or(0),
                )
            })
            .unwrap_or((0, 0))
    }

    /// Every action the endpoint's executor ran, in no particular order.
    pub fn executed_actions(&self) -> Vec<(Digest, Entry)> {
        let hashes: Vec<String> = {
            let connection = self.db.lock();
            let Ok(mut statement) =
                connection.prepare("SELECT hash FROM actions WHERE submitted_by IS NULL")
            else {
                return Vec::new();
            };
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .map(|rows| rows.filter_map(Result::ok).collect())
                .unwrap_or_default()
        };
        hashes
            .into_iter()
            .filter_map(|hash| {
                let digest = Digest {
                    hash,
                    size_bytes: -1,
                };
                let entry = self.evidence(&digest)?;
                Some((digest, entry))
            })
            .collect()
    }

    /// What the endpoint can vouch for: the executed result of an action,
    /// and never a submitted one (rule 2). This is the only door from the
    /// cache toward the norm plane.
    pub fn evidence(&self, action: &Digest) -> Option<Entry> {
        self.read(action)
            .filter(|entry| matches!(entry.origin, Origin::Executed { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{HandleId, Principal, Store};

    fn view(store: &Store, name: &str, labels: &[&str]) -> View {
        store
            .admit(
                HandleId(format!("h-{name}")),
                Principal {
                    name: name.into(),
                    labels: labels.iter().map(|l| l.to_string()).collect(),
                },
            )
            .unwrap()
    }

    fn classified(labels: &[&str]) -> Classification {
        Classification {
            labels: labels.iter().map(|l| l.to_string()).collect(),
            inputs: vec![Digest::of(b"input")],
            platform: vec![],
        }
    }

    fn result(code: i32) -> re::ActionResult {
        re::ActionResult {
            exit_code: code,
            ..Default::default()
        }
    }

    #[test]
    fn a_submitted_result_is_its_submitters_alone_and_never_evidence_and_a_cached_result_keeps_its_classification(
    ) {
        let store = Store::new();
        let dev = view(&store, "dev", &[]);
        let other = view(&store, "other", &[]);
        let owner = view(&store, "owner", &["protected"]);
        let cache = ActionCache::new();
        let action = Digest::of(b"action");
        cache
            .record_submitted(&dev, &action, result(0), classified(&[]))
            .unwrap();
        assert_eq!(
            cache.lookup(&dev, &action).map(|e| e.result.exit_code),
            Some(0)
        );
        assert_eq!(cache.lookup(&other, &action), None);
        assert_eq!(cache.evidence(&action), None);
        // The executor's observation replaces the claim and is evidence.
        cache
            .record_executed(&action, "endpoint", result(3), classified(&["protected"]))
            .unwrap();
        let evidence = cache.evidence(&action).expect("executed is evidence");
        assert_eq!(evidence.result.exit_code, 3);
        assert_eq!(
            evidence.origin,
            Origin::Executed {
                executor: "endpoint".into()
            }
        );
        assert_eq!(evidence.classification.inputs, vec![Digest::of(b"input")]);
        // Rule 5: served only to a principal holding the classification.
        assert_eq!(cache.lookup(&dev, &action), None);
        assert_eq!(
            cache.lookup(&owner, &action).map(|e| e.result.exit_code),
            Some(3)
        );
        assert_eq!(
            cache
                .record_submitted(&dev, &action, result(0), classified(&[]))
                .unwrap_err(),
            format!("action {action} has an executed result; a submitted one does not replace it")
        );
    }

    #[test]
    fn a_cached_result_outlives_the_process_and_a_submission_stays_its_principals() {
        let dir = tempfile::tempdir().expect("scratch");
        let path = dir.path().join("endpoint.sqlite");
        let submitted = Digest::of(b"submitted action");
        let executed = Digest::of(b"executed action");
        {
            let db = Db::open(&path).unwrap();
            let store = Store::over(db.clone());
            let cache = ActionCache::over(db);
            let dev = view(&store, "dev", &[]);
            cache
                .record_submitted(&dev, &submitted, result(0), classified(&[]))
                .unwrap();
            cache
                .record_executed(&executed, "endpoint", result(0), classified(&["protected"]))
                .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let store = Store::over(db.clone());
        let cache = ActionCache::over(db.clone());
        // dev under a new handle is still the submitter; other never was.
        let dev = store
            .admit(
                HandleId("a-new-token".into()),
                Principal {
                    name: "dev".into(),
                    labels: Labels::new(),
                },
            )
            .unwrap();
        let other = view(&store, "other", &[]);
        let owner = view(&store, "owner", &["protected"]);
        assert_eq!(
            cache.lookup(&dev, &submitted).and_then(|e| e.submitted_by),
            Some("dev".into())
        );
        assert_eq!(cache.lookup(&other, &submitted), None);
        assert_eq!(cache.evidence(&submitted), None);
        assert_eq!(cache.lookup(&dev, &executed), None);
        assert!(cache.lookup(&owner, &executed).is_some());
        assert_eq!(cache.counts(), (1, 1));
        assert_eq!(
            cache
                .executed_actions()
                .into_iter()
                .map(|(digest, _)| digest.hash)
                .collect::<Vec<_>>(),
            vec![executed.hash.clone()]
        );
        // A row whose origin and submitter disagree is served to no one and
        // vouches for nothing.
        db.lock()
            .execute(
                "UPDATE actions SET submitted_by = 'dev' WHERE hash = ?1",
                params![executed.hash],
            )
            .unwrap();
        assert_eq!(cache.evidence(&executed), None);
        assert_eq!(cache.lookup(&dev, &executed), None);
        db.refuse_writes();
        assert_eq!(
            cache
                .record_executed(&executed, "endpoint", result(0), classified(&[]))
                .unwrap_err(),
            format!(
                "cannot write the result of {executed} to the endpoint's state: attempt to write a readonly database"
            )
        );
    }
}
