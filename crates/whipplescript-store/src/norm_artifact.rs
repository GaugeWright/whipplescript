//! Verified, bounded materialization of an immutable stored cut for norm runs.
//! Cut-row authority is supplied by the host's Branches implementation. This
//! verifies content and manifest closure, not runtime dependency closure.
use std::collections::BTreeMap;

use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::branches::Branches;
use crate::content::{verify_body, ContentBlobs};
use crate::{StoreError, StoreResult};

#[derive(Clone, Copy, Debug)]
pub struct ArtifactLimits {
    pub max_nodes: usize,
    pub max_files: usize,
    pub max_bytes: usize,
}
impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_nodes: 100_000,
            max_files: 100_000,
            max_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBasis {
    pub cut: String,
    pub manifest: String,
}

/// No Deserialize or public constructor: a manifest supplied as a list of files
/// cannot claim to have traversed the host's stored cut. Files are owned so later
/// branch movement or blob erasure cannot change an already prepared candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedArtifact {
    basis: ArtifactBasis,
    files: BTreeMap<String, String>,
}
impl CapturedArtifact {
    pub fn basis(&self) -> &ArtifactBasis {
        &self.basis
    }
    pub fn files(&self) -> &BTreeMap<String, String> {
        &self.files
    }
}

struct FlatManifest(BTreeMap<String, String>);
impl<'de> Deserialize<'de> for FlatManifest {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Entries;
        impl<'de> Visitor<'de> for Entries {
            type Value = FlatManifest;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a unique path-to-content map")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut entries = BTreeMap::new();
                while let Some((path, id)) = map.next_entry::<String, String>()? {
                    let previous = entries.insert(path, id);
                    if previous.is_some() {
                        return Err(A::Error::custom("artifact manifest repeats a path"));
                    }
                }
                Ok(FlatManifest(entries))
            }
        }
        decoder.deserialize_map(Entries)
    }
}

pub(crate) fn canonical_path(path: &str) -> bool {
    !path.contains(['\\', ':', '\0'])
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn read_blob<C: ContentBlobs + ?Sized>(
    content: &C,
    id: &str,
    used: &mut usize,
    limit: usize,
) -> StoreResult<String> {
    let Some(body) = content.get(id)? else {
        return Err(StoreError::Conflict(format!(
            "artifact blob {id:?} is unavailable"
        )));
    };
    let next = used.checked_add(body.len());
    if next.is_none_or(|bytes| bytes > limit) {
        return Err(StoreError::Conflict(
            "artifact capture exceeds its byte budget".into(),
        ));
    }
    *used = next.expect("bounded byte count");
    verify_body(id, &body, "norm artifact capture")?;
    // The content store holds protected BYTES since the payload-protection
    // work. An artifact body that is not valid UTF-8 is refused rather than
    // lossily decoded: a mangled capture would verify and then mean something
    // else downstream.
    String::from_utf8(body)
        .map_err(|_| StoreError::Conflict(format!("artifact blob {id:?} is not valid UTF-8")))
}

struct PendingNode {
    id: String,
    level: Option<u32>,
    lower: Option<String>,
    upper: Option<String>,
}

pub fn capture_cut<B: Branches + ?Sized, C: ContentBlobs + ?Sized>(
    branches: &B,
    content: &C,
    cut_id: &str,
    limits: ArtifactLimits,
) -> StoreResult<CapturedArtifact> {
    if limits.max_nodes == 0 || limits.max_files == 0 || limits.max_bytes == 0 {
        return Err(StoreError::Conflict(
            "artifact capture needs positive budgets".into(),
        ));
    }
    let Some(cut) = branches.get_cut(cut_id)? else {
        return Err(StoreError::Conflict(format!(
            "artifact cut {cut_id:?} is not recorded"
        )));
    };
    let mut bytes = 0;
    let mut visited = 0usize;
    let mut manifest = BTreeMap::new();
    let mut pending = vec![PendingNode {
        id: cut.manifest_hash.clone(),
        level: None,
        lower: None,
        upper: None,
    }];
    while let Some(expected) = pending.pop() {
        visited += 1;
        let body = read_blob(content, &expected.id, &mut bytes, limits.max_bytes)?;
        let entries = match crate::manifest_tree::parse_node(&body) {
            Some(node) => {
                if expected.level.is_some_and(|level| level != node.level)
                    || (node.level > 0 && node.entries.is_empty())
                    || node.entries.windows(2).any(|pair| pair[0].0 >= pair[1].0)
                    || expected.lower.as_ref().is_some_and(|lower| {
                        node.entries.first().is_none_or(|entry| &entry.0 <= lower)
                    })
                    || expected.upper.as_ref().is_some_and(|upper| {
                        node.entries.last().is_none_or(|entry| &entry.0 != upper)
                    })
                {
                    return Err(StoreError::Conflict(
                        "artifact manifest has inconsistent levels or key ranges".into(),
                    ));
                }
                if node.level > 0 {
                    let scheduled = visited
                        .checked_add(pending.len())
                        .and_then(|count| count.checked_add(node.entries.len()));
                    if scheduled.is_none_or(|count| count > limits.max_nodes) {
                        return Err(StoreError::Conflict(
                            "artifact manifest exceeds its scheduled node budget".into(),
                        ));
                    }
                    let mut lower = expected.lower;
                    for (upper, id) in node.entries {
                        pending.push(PendingNode {
                            id,
                            level: Some(node.level - 1),
                            lower: lower.clone(),
                            upper: Some(upper.clone()),
                        });
                        lower = Some(upper);
                    }
                    continue;
                }
                node.entries
            }
            None => {
                if expected.level.is_some() {
                    return Err(StoreError::Conflict(
                        "artifact manifest child is not a known tree node".into(),
                    ));
                }
                serde_json::from_str::<FlatManifest>(&body)?
                    .0
                    .into_iter()
                    .collect()
            }
        };
        for (path, id) in entries {
            if !canonical_path(&path) {
                return Err(StoreError::Conflict(format!(
                    "artifact path {path:?} is not canonical"
                )));
            }
            let duplicate = manifest.insert(path, id).is_some();
            if duplicate || manifest.len() > limits.max_files {
                return Err(StoreError::Conflict(
                    "artifact manifest repeats a file or exceeds its file budget".into(),
                ));
            }
        }
    }
    let mut files = BTreeMap::new();
    for (path, id) in manifest {
        files.insert(path, read_blob(content, &id, &mut bytes, limits.max_bytes)?);
    }
    Ok(CapturedArtifact {
        basis: ArtifactBasis {
            cut: cut_id.into(),
            manifest: cut.manifest_hash,
        },
        files,
    })
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::branches::{BranchStore, CutRecord, MAINLINE_BRANCH_ID};
    use std::cell::RefCell;

    #[derive(Default)]
    struct Blobs(RefCell<BTreeMap<String, Vec<u8>>>);
    impl ContentBlobs for Blobs {
        // The seam is bytes; ids are unchanged for text because the digest was
        // always taken over `as_bytes()`.
        fn put(&self, body: &[u8]) -> StoreResult<String> {
            let id = crate::stable_hash_bytes_hex(body);
            self.0.borrow_mut().insert(id.clone(), body.to_vec());
            Ok(id)
        }
        fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
            Ok(self.0.borrow().get(id).cloned())
        }
    }

    impl Blobs {
        /// These fixtures capture source text; the seam itself stays bytes.
        fn put_text(&self, body: &str) -> StoreResult<String> {
            self.put(body.as_bytes())
        }
    }
    #[test]
    fn artifact_capture_blob_double_conforms() {
        crate::content::conformance::run_suite(Blobs::default).expect("artifact capture fixture");
    }

    fn cut(root: &str) -> BranchStore {
        let mut branches = BranchStore::open_in_memory().expect("artifact capture fixture");
        branches
            .ensure_mainline("t0")
            .expect("artifact capture fixture");
        branches
            .record_cut(CutRecord {
                cut_id: "cut",
                change_id: "change",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: root,
                parent_cut_id: None,
                origin: None,
                actor: None,
                intent: None,
                recorded_at: "t1",
            })
            .expect("artifact capture fixture");
        branches
    }
    fn node(blobs: &Blobs, level: u32, entries: &[(&str, &str)]) -> String {
        blobs
            .put_text(
                &serde_json::json!({
                    "tag": "whipplescript.manifest-tree.v2", "level": level, "entries": entries
                })
                .to_string(),
            )
            .expect("artifact capture fixture")
    }
    #[test]
    fn artifact_capture_owns_verified_tree_and_flat_bytes() {
        let blobs = Blobs::default();
        let file = blobs
            .put_text("print(1)")
            .expect("artifact capture fixture");
        let leaf = node(&blobs, 0, &[("main.py", &file)]);
        let root = node(&blobs, 1, &[("main.py", &leaf)]);
        let captured = capture_cut(&cut(&root), &blobs, "cut", ArtifactLimits::default())
            .expect("artifact capture fixture");
        assert_eq!(captured.basis().manifest, root);
        assert_eq!(captured.files()["main.py"], "print(1)");
        let flat = blobs
            .put_text(&serde_json::json!({"main.py":file}).to_string())
            .expect("artifact capture fixture");
        assert_eq!(
            capture_cut(&cut(&flat), &blobs, "cut", ArtifactLimits::default())
                .expect("artifact capture fixture")
                .files(),
            captured.files()
        );
        blobs.0.borrow_mut().remove(&file);
        assert!(capture_cut(&cut(&root), &blobs, "cut", ArtifactLimits::default()).is_err());
        assert_eq!(captured.files()["main.py"], "print(1)");
    }
    #[test]
    fn artifact_capture_uses_exact_known_manifest_codec() {
        let blobs = Blobs::default();
        for tag in [
            "whipplescript.manifest-tree.v1",
            "whipplescript.manifest-tree.v2",
        ] {
            let mut encoded = serde_json::json!({"tag":tag,"level":0,"entries":[]});
            let root = blobs
                .put_text(&encoded.to_string())
                .expect("artifact capture fixture");
            assert!(capture_cut(&cut(&root), &blobs, "cut", ArtifactLimits::default()).is_ok());
            encoded["ignored"] = serde_json::json!(true);
            let root = blobs
                .put_text(&encoded.to_string())
                .expect("artifact capture fixture");
            assert!(capture_cut(&cut(&root), &blobs, "cut", ArtifactLimits::default()).is_err());
        }
        let root = blobs
            .put_text(r#"{"tag":"whipplescript.manifest-tree.v3","level":0,"entries":[]}"#)
            .expect("artifact capture fixture");
        assert!(capture_cut(&cut(&root), &blobs, "cut", ArtifactLimits::default()).is_err());
    }

    #[test]
    fn artifact_capture_refuses_damaged_content_and_unknown_cut() {
        let blobs = Blobs::default();
        let file = blobs
            .put_text("original")
            .expect("artifact capture fixture");
        let root = node(&blobs, 0, &[("a", &file)]);
        let branches = cut(&root);
        assert!(matches!(
            capture_cut(&branches, &blobs, "unknown", ArtifactLimits::default()),
            Err(StoreError::Conflict(message)) if message == "artifact cut \"unknown\" is not recorded"
        ));
        blobs.0.borrow_mut().insert(file, "changed".into());
        assert!(capture_cut(&branches, &blobs, "cut", ArtifactLimits::default()).is_err());
        blobs.0.borrow_mut().insert(root.clone(), "{}".into());
        assert!(capture_cut(&branches, &blobs, "cut", ArtifactLimits::default()).is_err());
        blobs.0.borrow_mut().remove(&root);
        assert!(matches!(
            capture_cut(&branches, &blobs, "cut", ArtifactLimits::default()),
            Err(StoreError::Conflict(message)) if message == format!("artifact blob {root:?} is unavailable")
        ));
    }
    #[test]
    fn artifact_capture_refuses_malformed_ranges_paths_and_budgets() {
        let blobs = Blobs::default();
        let file = blobs.put_text("body").expect("artifact capture fixture");
        let valid = node(&blobs, 0, &[("a", &file), ("b", &file)]);
        let defaults = ArtifactLimits::default();
        for limits in [
            ArtifactLimits {
                max_nodes: 0,
                ..defaults
            },
            ArtifactLimits {
                max_files: 0,
                ..defaults
            },
            ArtifactLimits {
                max_bytes: 0,
                ..defaults
            },
            ArtifactLimits {
                max_files: 1,
                ..defaults
            },
            ArtifactLimits {
                max_bytes: 1,
                ..defaults
            },
        ] {
            assert!(capture_cut(&cut(&valid), &blobs, "cut", limits).is_err());
        }
        let leaf = node(&blobs, 0, &[("a", &file)]);
        let wrong_level = node(&blobs, 2, &[("a", &leaf)]);
        let wrong_upper = node(&blobs, 1, &[("b", &leaf)]);
        let overlap = node(&blobs, 1, &[("a", &leaf), ("b", &valid)]);
        let missing = node(&blobs, 1, &[("a", "missing")]);
        let flat = blobs.put_text("{}").expect("artifact capture fixture");
        let flat_child = node(&blobs, 1, &[("a", &flat)]);
        let duplicate = blobs
            .put_text(&format!("{{\"a\":\"{file}\",\"a\":\"{file}\"}}"))
            .expect("artifact capture fixture");
        for root in [
            wrong_level,
            wrong_upper,
            overlap,
            missing,
            flat_child,
            duplicate,
            node(&blobs, 1, &[]),
            node(&blobs, 0, &[("b", &file), ("a", &file)]),
            node(&blobs, 0, &[("a", &file), ("a", &file)]),
        ] {
            assert!(
                capture_cut(&cut(&root), &blobs, "cut", defaults).is_err(),
                "{root}"
            );
        }
        for path in [
            "", "/a", "a/", "a//b", "../a", "a/./b", "a:b", "a\\b", "a\0b",
        ] {
            let root = node(&blobs, 0, &[(path, &file)]);
            assert!(
                capture_cut(&cut(&root), &blobs, "cut", defaults).is_err(),
                "{path:?}"
            );
        }
        let root = node(&blobs, 1, &[("a", &leaf)]);
        assert!(capture_cut(
            &cut(&root),
            &blobs,
            "cut",
            ArtifactLimits {
                max_nodes: 1,
                ..defaults
            }
        )
        .is_err());
        assert!(capture_cut(
            &cut(&root),
            &blobs,
            "cut",
            ArtifactLimits {
                max_nodes: 2,
                ..defaults
            }
        )
        .is_ok());
        assert!(capture_cut(&cut(&flat), &blobs, "cut", defaults)
            .expect("artifact capture fixture")
            .files()
            .is_empty());
    }
}
