//! The endpoint's blob store under the five rules of DR-0124 §14.3.
//!
//! Bytes are stored once, by digest. What a principal may do with them is a
//! separate fact: a *use* — one handle's admitted relationship to one blob,
//! carrying the labels the blob acquired in that use. Possession of a digest
//! grants nothing (rule 1); identical bytes under two uses carry two labels
//! (rule 3); what a handle has no use of is missing under that handle's view,
//! and its upload is accepted (rule 4). Rules 2 and 5 live in `cache.rs`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, MutexGuard};

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

/// An authorized handle: a principal, admitted to the endpoint, whose uses
/// are the view every answer is scoped to.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HandleId(pub String);

#[derive(Default)]
struct Inner {
    blobs: HashMap<String, Vec<u8>>,
    /// (handle, digest hash) → the labels of that handle's use of the blob.
    uses: HashMap<(HandleId, String), Labels>,
    handles: BTreeMap<HandleId, Principal>,
}

/// The store: blobs, uses and handles, behind one lock.
#[derive(Default)]
pub struct Store {
    inner: Mutex<Inner>,
}

/// A view over the store: one handle, its principal, its uses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct View {
    pub handle: HandleId,
    pub principal: Principal,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Admit a principal under a handle. A handle is minted once; admitting
    /// the same handle for a different principal is refused, so a token
    /// never changes hands.
    pub fn admit(&self, handle: HandleId, principal: Principal) -> Result<View, String> {
        let mut inner = self.lock();
        if let Some(existing) = inner.handles.get(&handle) {
            if existing != &principal {
                return Err(format!(
                    "handle {} is already admitted for {}",
                    handle.0, existing.name
                ));
            }
        }
        inner.handles.insert(handle.clone(), principal.clone());
        Ok(View { handle, principal })
    }

    /// The view a handle names, or none: an unknown handle sees nothing.
    pub fn view(&self, handle: &HandleId) -> Option<View> {
        self.lock().handles.get(handle).map(|principal| View {
            handle: handle.clone(),
            principal: principal.clone(),
        })
    }

    /// Store bytes under the view's use with the labels given. Bytes already
    /// present are not stored twice, and the duplicate is accepted exactly as
    /// the first upload was (rule 4); the use's labels are the join of every
    /// admission of this blob under this handle (rule 3 keeps other handles'
    /// uses apart).
    pub fn put(&self, view: &View, bytes: &[u8], labels: &Labels) -> Digest {
        let digest = Digest::of(bytes);
        let mut inner = self.lock();
        inner
            .blobs
            .entry(digest.hash.clone())
            .or_insert_with(|| bytes.to_vec());
        inner
            .uses
            .entry((view.handle.clone(), digest.hash.clone()))
            .or_default()
            .extend(labels.iter().cloned());
        digest
    }

    /// Grant a view a use of a blob it did not upload — an output the view
    /// may read, or a cut's encoding projected under it — with the labels of
    /// that use. Refused when the bytes are not stored: a use of nothing is
    /// not a fact.
    pub fn grant(&self, view: &View, digest: &Digest, labels: &Labels) -> Result<(), String> {
        let mut inner = self.lock();
        if !inner.blobs.contains_key(&digest.hash) {
            return Err(format!("no blob {digest} to grant a use of"));
        }
        inner
            .uses
            .entry((view.handle.clone(), digest.hash.clone()))
            .or_default()
            .extend(labels.iter().cloned());
        Ok(())
    }

    /// The labels of the view's use of a blob, or none when the view has no
    /// use of it — which is what "missing" means under that view.
    pub fn use_of(&self, view: &View, digest: &Digest) -> Option<Labels> {
        if digest.is_empty() {
            return Some(Labels::new());
        }
        self.lock()
            .uses
            .get(&(view.handle.clone(), digest.hash.clone()))
            .cloned()
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
        self.lock().blobs.get(&digest.hash).cloned()
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

    /// Whether the bytes are stored at all: the store's own knowledge, never
    /// an answer given to a caller.
    pub fn stored(&self, digest: &Digest) -> bool {
        digest.is_empty() || self.lock().blobs.contains_key(&digest.hash)
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
        let digest = store.put(&owner, b"secret bytes", &labels(&["protected"]));
        // Rule 1: dev knows the digest and reads nothing by it.
        assert_eq!(store.get(&dev, &digest), None);
        assert_eq!(store.missing(&dev, [&digest]), vec![digest.clone()]);
        assert!(store.stored(&digest));
        // Rule 4: dev's upload of the same bytes is accepted, and rule 3: their
        // use carries their labels, not owner's.
        let again = store.put(&dev, b"secret bytes", &labels(&[]));
        assert_eq!(again, digest);
        assert_eq!(
            store.get(&dev, &digest).as_deref(),
            Some(&b"secret bytes"[..])
        );
        assert_eq!(store.use_of(&dev, &digest), Some(labels(&[])));
        assert_eq!(store.use_of(&owner, &digest), Some(labels(&["protected"])));
        assert!(store.missing(&dev, [&digest]).is_empty());
        // A use granted with labels the principal does not hold reads nothing.
        let output = store.put(&owner, b"an output", &labels(&["protected"]));
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
    }
}
