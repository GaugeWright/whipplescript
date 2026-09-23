//! The action cache under rules 2 and 5 of DR-0124 §14.3.
//!
//! An entry records where its result came from — executed by the endpoint's
//! approved executor, or submitted by a client — because a matching digest
//! does not authenticate the producer (rule 2): a submitted result is served
//! back to the view that submitted it and to no one else, and it is never
//! evidence. An entry binds the classification of the result it caches, the
//! join of the labels of everything that shaped it (rule 5, and §14.2), and
//! is served only to a view whose principal holds that classification.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::digest::Digest;
use crate::proto::re;
use crate::store::{HandleId, Labels, View};

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
    /// The view a submitted result is scoped to; none for an executed one.
    pub submitted_under: Option<HandleId>,
}

#[derive(Default)]
pub struct ActionCache {
    entries: Mutex<HashMap<String, Entry>>,
}

impl ActionCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
    ) {
        self.lock().insert(
            action.hash.clone(),
            Entry {
                result,
                origin: Origin::Executed {
                    executor: executor.to_owned(),
                },
                classification,
                submitted_under: None,
            },
        );
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
        let mut entries = self.lock();
        if let Some(existing) = entries.get(&action.hash) {
            if matches!(existing.origin, Origin::Executed { .. }) {
                return Err(format!(
                    "action {action} has an executed result; a submitted one does not replace it"
                ));
            }
        }
        entries.insert(
            action.hash.clone(),
            Entry {
                result,
                origin: Origin::Submitted {
                    by: view.principal.name.clone(),
                },
                classification,
                submitted_under: Some(view.handle.clone()),
            },
        );
        Ok(())
    }

    /// The entry a view may read: an executed one whose classification the
    /// principal holds, or the view's own submission. Anything else is not
    /// found under that view.
    pub fn lookup(&self, view: &View, action: &Digest) -> Option<Entry> {
        let entries = self.lock();
        let entry = entries.get(&action.hash)?;
        match &entry.submitted_under {
            Some(handle) if handle != &view.handle => return None,
            _ => {}
        }
        if !view.principal.holds(&entry.classification.labels) {
            return None;
        }
        Some(entry.clone())
    }

    /// Every action the endpoint's executor ran, in no particular order.
    pub fn executed_actions(&self) -> Vec<(Digest, Entry)> {
        self.lock()
            .iter()
            .filter(|(_, entry)| matches!(entry.origin, Origin::Executed { .. }))
            .map(|(hash, entry)| {
                (
                    Digest {
                        hash: hash.clone(),
                        size_bytes: -1,
                    },
                    entry.clone(),
                )
            })
            .collect()
    }

    /// What the endpoint can vouch for: the executed result of an action,
    /// and never a submitted one (rule 2). This is the only door from the
    /// cache toward the norm plane.
    pub fn evidence(&self, action: &Digest) -> Option<Entry> {
        let entries = self.lock();
        entries
            .get(&action.hash)
            .filter(|entry| matches!(entry.origin, Origin::Executed { .. }))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Principal, Store};

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
        cache.record_executed(&action, "endpoint", result(3), classified(&["protected"]));
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
}
