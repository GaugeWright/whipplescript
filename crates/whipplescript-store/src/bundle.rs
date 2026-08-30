//! Workspace export/import bundles — the handoff carrier
//! (untie-substrate readiness tracker Phase 2; un-tie's
//! `STATE_BEFORE_HOME` ships manifest + reachable blobs, cleaner than
//! `git bundle`).
//!
//! A bundle is one self-contained JSON document: the branch row
//! (lineage snapshot), its head manifest, every reachable blob, and the
//! branch's recorded cuts so CHANGE IDENTITY travels (dual identity: a
//! bundle-imported change reunifies at a later merge instead of
//! re-conflicting as an ancestry-less duplicate). It is
//! **erasure-respecting by construction**: an erased blob travels as a
//! tombstone entry — hash + size, NO body — so the bytes that were
//! erased never escape through the handoff path again (the leak un-tie
//! documented in ADR 0008/0018 and could not fix over git).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::branches::{BranchRow, CutRow};
use crate::content::{BlobStatus, ContentBlobs};
use crate::StoreResult;

pub const BUNDLE_FORMAT: &str = "whipplescript.bundle.v1";

/// One blob in the bundle. `body: None` + `erased: true` is the
/// tombstone shape — identity travels, payload does not. A chunk ROOT
/// entry carries its ordered chunk ids instead of a body (the chunks
/// are their own entries); `omitted: true` marks an entry the receiver
/// declared it already has (pull-missing / rsync-class delta transfer),
/// so only structure travels.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BundleBlob {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub byte_len: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub erased: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub omitted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceBundle {
    pub format: String,
    /// The exported branch's row at export time (lineage snapshot).
    pub branch: BranchRow,
    /// The head change id, so intent identity survives the handoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_change_id: Option<String>,
    pub manifest: BTreeMap<String, String>,
    pub blobs: Vec<BundleBlob>,
    /// The branch's recorded cuts (identity + provenance travel).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cuts: Vec<CutRow>,
}

/// Collect the manifest's reachable blobs through the content seam,
/// erasure-respecting (tombstoned payloads never travel), with pull-missing
/// (rsync-class incremental): every transferable unit — plain blob OR
/// individual chunk — whose id is in `have` travels as structure only
/// (`omitted: true`, no body). Chunk roots always carry their chunk lists
/// (structure is cheap; the receiver re-links without re-chunking) and
/// never a body.
pub fn collect_blobs_delta(
    manifest: &BTreeMap<String, String>,
    content: &dyn ContentBlobs,
    have: &std::collections::BTreeSet<String>,
) -> StoreResult<Vec<BundleBlob>> {
    let mut ids: Vec<&String> = manifest.values().collect();
    ids.sort();
    ids.dedup();
    let mut blobs = Vec::new();
    let mut carried_chunks = std::collections::BTreeSet::new();
    for id in ids {
        let status = content.status(id)?;
        // A chunk root: carry the structure, then each chunk as its own
        // (delta-eligible) entry.
        if let Some(chunk_ids) = content.chunk_ids(id)? {
            let (byte_len, erased) = match status {
                BlobStatus::Live { byte_len } => (byte_len, false),
                BlobStatus::Erased { byte_len } => (byte_len, true),
                BlobStatus::Unknown => (0, false),
            };
            blobs.push(BundleBlob {
                id: id.clone(),
                body: None,
                byte_len,
                erased,
                chunk_ids: Some(chunk_ids.clone()),
                omitted: false,
            });
            if erased {
                // Erased root: the chunks' payloads are gone by
                // definition; nothing more travels.
                continue;
            }
            for chunk_id in chunk_ids {
                if !carried_chunks.insert(chunk_id.clone()) {
                    continue;
                }
                blobs.push(unit_entry(&chunk_id, content, have)?);
            }
            continue;
        }
        blobs.push(unit_entry(id, content, have)?);
    }
    Ok(blobs)
}

/// One transferable unit (plain blob or chunk), honoring the have-set
/// and erasure.
fn unit_entry(
    id: &str,
    content: &dyn ContentBlobs,
    have: &std::collections::BTreeSet<String>,
) -> StoreResult<BundleBlob> {
    Ok(match content.status(id)? {
        BlobStatus::Live { byte_len } => {
            if have.contains(id) {
                BundleBlob {
                    id: id.to_owned(),
                    body: None,
                    byte_len,
                    erased: false,
                    chunk_ids: None,
                    omitted: true,
                }
            } else {
                BundleBlob {
                    id: id.to_owned(),
                    body: content.get(id)?,
                    byte_len,
                    erased: false,
                    chunk_ids: None,
                    omitted: false,
                }
            }
        }
        BlobStatus::Erased { byte_len } => BundleBlob {
            id: id.to_owned(),
            body: None,
            byte_len,
            erased: true,
            chunk_ids: None,
            omitted: false,
        },
        // A hash the store has never seen: carried as an honest
        // zero-knowledge tombstone rather than silently dropped — the
        // receiving side sees the manifest references it.
        BlobStatus::Unknown => BundleBlob {
            id: id.to_owned(),
            body: None,
            byte_len: 0,
            erased: false,
            chunk_ids: None,
            omitted: false,
        },
    })
}

/// The transferable-unit ids a manifest reaches that this store can
/// serve (plain blobs and individual chunks; roots expand). The
/// receiver runs this over its own store and sends the result as the
/// sender's `have` set — pull-missing negotiation in one round trip.
pub fn transferable_ids(
    manifest: &BTreeMap<String, String>,
    content: &dyn ContentBlobs,
) -> StoreResult<Vec<String>> {
    let mut ids = std::collections::BTreeSet::new();
    for id in manifest.values() {
        if let Some(chunk_ids) = content.chunk_ids(id)? {
            for chunk_id in chunk_ids {
                if matches!(content.status(&chunk_id)?, BlobStatus::Live { .. }) {
                    ids.insert(chunk_id);
                }
            }
            continue;
        }
        if matches!(content.status(id)?, BlobStatus::Live { .. }) {
            ids.insert(id.clone());
        }
    }
    Ok(ids.into_iter().collect())
}

/// The receiver's half of pull-missing: given the sender's digest (all
/// transferable-unit ids), the subset this store already holds live.
pub fn held_subset(ids: &[String], content: &dyn ContentBlobs) -> StoreResult<Vec<String>> {
    let mut held = Vec::new();
    for id in ids {
        if matches!(content.status(id)?, BlobStatus::Live { .. }) {
            held.push(id.clone());
        }
    }
    Ok(held)
}

/// Outcome of importing a bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleImportOutcome {
    Imported {
        branch_id: String,
        cut_id: String,
        manifest_hash: String,
    },
    /// Idempotent re-materialization: the branch already carries the
    /// bundle's state.
    AlreadyPresent { branch_id: String },
    /// The branch exists locally with DIFFERENT content: refused
    /// honestly (import never clobbers local work).
    DivergentBranch {
        branch_id: String,
        local_head_manifest_hash: Option<String>,
    },
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::content::EraseOutcome;
    use crate::vcs::NativeWorkspaceVcs;

    fn vcs(tag: &str) -> NativeWorkspaceVcs {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-bundle-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        NativeWorkspaceVcs::open(dir.join("branches.sqlite"), dir.join("content.sqlite"))
            .expect("open vcs")
    }

    /// The handoff loop: export a branch, import it into a FRESH
    /// workspace, get an identical working state — idempotently (the
    /// second import is `AlreadyPresent`), with change identity carried
    /// (dual identity: the imported head resolves to its original
    /// change id).
    #[test]
    fn export_import_rematerializes_idempotently_with_identity() {
        let mut source = vcs("src");
        source.init("t0").expect("init");
        source
            .create_branch("draft_a", Some("handoff"), "main", "t1")
            .expect("create");
        source
            .write("draft_a", "a.md", Some("state before home"), "cut_a1", "t2")
            .expect("write");
        source
            .write("draft_a", "b.md", Some("second file"), "cut_a2", "t3")
            .expect("write");
        let bundle = source
            .export_bundle("draft_a")
            .expect("export")
            .expect("branch exists");
        assert_eq!(bundle.format, BUNDLE_FORMAT);
        assert_eq!(bundle.manifest.len(), 2);
        assert!(bundle.blobs.iter().all(|blob| blob.body.is_some()));
        assert_eq!(bundle.head_change_id.as_deref(), Some("cut_a2"));

        // The bundle is a plain JSON document (the wire shape).
        let wire = serde_json::to_string(&bundle).expect("encode");
        let decoded: WorkspaceBundle = serde_json::from_str(&wire).expect("decode");

        let mut target = vcs("dst");
        target.init("t4").expect("init");
        let outcome = target.import_bundle(&decoded, "t5").expect("import");
        assert!(matches!(outcome, BundleImportOutcome::Imported { .. }));
        assert_eq!(
            target.read("draft_a", "a.md").expect("read").as_deref(),
            Some("state before home")
        );
        assert_eq!(
            target.read("draft_a", "b.md").expect("read").as_deref(),
            Some("second file")
        );
        // Change identity traveled: the imported head carries the
        // ORIGINAL change id, not a fresh one.
        let report = target
            .status_report("draft_a")
            .expect("status")
            .expect("branch");
        assert_eq!(report.head_change_id.as_deref(), Some("cut_a2"));
        // Idempotent re-materialization.
        assert_eq!(
            target.import_bundle(&decoded, "t6").expect("re-import"),
            BundleImportOutcome::AlreadyPresent {
                branch_id: "draft_a".to_owned()
            }
        );
        // Local divergence is refused, never clobbered.
        target
            .write("draft_a", "a.md", Some("local edit"), "cut_local", "t7")
            .expect("write");
        assert!(matches!(
            target.import_bundle(&decoded, "t8").expect("import"),
            BundleImportOutcome::DivergentBranch { .. }
        ));
        assert_eq!(
            target.read("draft_a", "a.md").expect("read").as_deref(),
            Some("local edit")
        );
    }

    /// Un-tie's content-erasure invariants discharged over the
    /// substrate:
    /// - `HISTORY_PRESERVED` — after per-blob erasure, every manifest,
    ///   cut, op, and lineage record still reads; only the payload is
    ///   gone, and reads degrade honestly.
    /// - `EXPORTED_COPY_NOT_RECALLED` — a bundle exported BEFORE erasure
    ///   keeps its payload (erasure is local, honestly so); a bundle
    ///   exported AFTER carries a tombstone — the erased bytes never
    ///   travel again.
    #[test]
    fn erasure_preserves_history_and_respects_exports() {
        let mut vcs = vcs("erase");
        vcs.init("t0").expect("init");
        vcs.create_branch("draft_a", None, "main", "t1")
            .expect("create");
        vcs.write("draft_a", "secret.md", Some("the payload"), "cut_a1", "t2")
            .expect("write");
        vcs.write("draft_a", "kept.md", Some("stays"), "cut_a2", "t3")
            .expect("write");
        let before = vcs
            .export_bundle("draft_a")
            .expect("export")
            .expect("branch");
        // Erase the secret's payload.
        let (hash, outcome) = vcs
            .erase_path("draft_a", "secret.md", "t4")
            .expect("erase")
            .expect("path exists");
        assert!(matches!(outcome, EraseOutcome::Erased { byte_len: 11 }));
        // The retry is honest.
        let (_, retry) = vcs
            .erase_path("draft_a", "secret.md", "t5")
            .expect("erase")
            .expect("path exists");
        assert_eq!(retry, EraseOutcome::AlreadyErased);

        // HISTORY_PRESERVED: the manifest still references the hash, the
        // cuts and ops still read, the branch still works.
        let manifest = vcs.manifest("draft_a").expect("manifest").expect("branch");
        assert_eq!(manifest.get("secret.md"), Some(&hash));
        assert_eq!(
            vcs.read("draft_a", "secret.md").expect("read"),
            None,
            "the payload is honestly gone"
        );
        assert_eq!(
            vcs.read("draft_a", "kept.md").expect("read").as_deref(),
            Some("stays")
        );
        assert!(vcs.get_cut("cut_a1").expect("cut").is_some());
        assert!(!vcs.list_ops(20).expect("ops").is_empty());
        let diff = vcs
            .diff_against("draft_a", None, 3)
            .expect("diff")
            .expect("branch");
        let secret_entry = diff
            .iter()
            .find(|entry| entry.path == "secret.md")
            .expect("entry");
        assert!(
            secret_entry.payload_unavailable,
            "the diff degrades honestly, never fabricates"
        );
        vcs.write("draft_a", "secret.md", Some("rewritten"), "cut_a3", "t6")
            .expect("the branch keeps working after erasure");

        // EXPORTED_COPY_NOT_RECALLED: the pre-erasure bundle still
        // carries the payload — erasure is local and the system does not
        // pretend otherwise...
        let exported_secret = before
            .blobs
            .iter()
            .find(|blob| blob.id == hash)
            .expect("exported blob");
        assert_eq!(exported_secret.body.as_deref(), Some("the payload"));
        // ...and it re-materializes elsewhere untouched by the erasure.
        let mut elsewhere = vcs2();
        elsewhere.init("t0").expect("init");
        elsewhere.import_bundle(&before, "t1").expect("import");
        assert_eq!(
            elsewhere
                .read("draft_a", "secret.md")
                .expect("read")
                .as_deref(),
            Some("the payload"),
            "the exported copy is not recalled"
        );

        // ...but a NEW export after erasure carries the tombstone: hash
        // and size travel, the bytes do not. (The head moved past the
        // erased state above, so export the recorded pre-rewrite cut's
        // manifest via a fresh branch pinned at it.)
        vcs.fork_with_lineage("audit", None, "draft_a", Some("cut_a2"), "t7")
            .expect("fork at the erased-payload cut");
        let after = vcs.export_bundle("audit").expect("export").expect("branch");
        let tombstone = after
            .blobs
            .iter()
            .find(|blob| blob.id == hash)
            .expect("tombstone entry");
        assert_eq!(tombstone.body, None, "tombstoned bytes never travel");
        assert!(tombstone.erased);
        assert_eq!(tombstone.byte_len, 11, "identity and size retained");
    }

    fn vcs2() -> NativeWorkspaceVcs {
        vcs("elsewhere")
    }

    /// A bundle whose blob body does not hash to its claimed content id is
    /// refused: content ids commit to their bytes, so import verifies each
    /// blob rather than trusting the attacker-supplied id
    /// (content-addressing forgery).
    #[test]
    fn import_refuses_forged_plain_blob_id() {
        let mut source = vcs("forge-src");
        source.init("t0").expect("init");
        source
            .create_branch("draft_a", None, "main", "t1")
            .expect("create");
        source
            .write("draft_a", "a.md", Some("honest bytes"), "cut_a1", "t2")
            .expect("write");
        let bundle = source.export_bundle("draft_a").expect("export").expect("b");

        let mut tampered = bundle.clone();
        let blob = tampered
            .blobs
            .iter_mut()
            .find(|b| b.body.is_some())
            .expect("a carried body");
        blob.body = Some("attacker-substituted bytes".to_owned());

        let mut target = vcs("forge-dst");
        target.init("t0").expect("init");
        let err = target.import_bundle(&tampered, "t1");
        assert!(
            err.is_err(),
            "a blob whose body does not match its id must be refused"
        );
    }

    /// A manifest key that would escape the workspace root on materialize
    /// (`..` traversal) is refused at import, before any state is stored —
    /// closing the arbitrary-file-write path through materialize-on-exec.
    #[test]
    fn import_refuses_traversal_manifest_key() {
        let mut source = vcs("trav-src");
        source.init("t0").expect("init");
        source
            .create_branch("draft_a", None, "main", "t1")
            .expect("create");
        source
            .write("draft_a", "a.md", Some("bytes"), "cut_a1", "t2")
            .expect("write");
        let bundle = source.export_bundle("draft_a").expect("export").expect("b");

        let mut tampered = bundle.clone();
        let id = tampered.manifest.values().next().cloned().expect("an id");
        tampered
            .manifest
            .insert("../../../etc/whip-escape".to_owned(), id);

        let mut target = vcs("trav-dst");
        target.init("t0").expect("init");
        assert!(
            target.import_bundle(&tampered, "t1").is_err(),
            "a `..` manifest key must be refused at import"
        );
    }

    /// A chunk root that declares a size over the blob ceiling is refused at
    /// import (fail-fast on the honest-oversize case, before any work).
    #[test]
    fn import_refuses_oversize_chunk_root() {
        use crate::chunking::ChunkingConfig;
        let config = ChunkingConfig {
            whole_blob_threshold: 256,
            min_size: 64,
            avg_size: 256,
            max_size: 1024,
        };
        let mut source = vcs("oversize-src");
        source.init("t0").expect("init");
        source
            .create_branch("draft_a", None, "main", "t1")
            .expect("create");
        let big = "0123456789abcdef-".repeat(600);
        let root = source
            .content_store()
            .put_chunked(&big, &config)
            .expect("chunk");
        let mut changed = BTreeMap::new();
        changed.insert("big.dat".to_owned(), root.clone());
        source
            .import_diff("draft_a", &changed, &[], "cut_a1", "t2")
            .expect("diff");
        let mut bundle = source.export_bundle("draft_a").expect("export").expect("b");
        // Tamper the declared size to far over the 256 MiB default ceiling.
        for blob in &mut bundle.blobs {
            if blob.id == root {
                blob.byte_len = 300 * 1024 * 1024;
            }
        }
        let mut target = vcs("oversize-dst");
        target.init("t0").expect("init");
        assert!(
            target.import_bundle(&bundle, "t1").is_err(),
            "an oversize chunk root must be refused at import"
        );
    }

    /// A bundle that rebinds a locally-erased content id is refused:
    /// erasure is honest and permanent, so an import must not resurrect the
    /// bytes (defeats the erasure-never-recalled invariant).
    #[test]
    fn import_refuses_erased_blob_resurrection() {
        // Source still holds the payload and exports it.
        let mut source = vcs("resurrect-src");
        source.init("t0").expect("init");
        source
            .create_branch("draft_a", None, "main", "t1")
            .expect("create");
        source
            .write("draft_a", "secret.md", Some("the payload"), "cut_a1", "t2")
            .expect("write");
        let bundle = source.export_bundle("draft_a").expect("export").expect("b");

        // Target once held the same bytes and has ERASED them.
        let mut target = vcs("resurrect-dst");
        target.init("t0").expect("init");
        target
            .create_branch("local", None, "main", "t1")
            .expect("create");
        target
            .write("local", "secret.md", Some("the payload"), "cut_l1", "t2")
            .expect("write");
        target
            .erase_path("local", "secret.md", "t3")
            .expect("erase")
            .expect("path exists");

        assert!(
            target.import_bundle(&bundle, "t4").is_err(),
            "importing a bundle that rebinds the erased id must be refused"
        );
    }

    /// Chunk-granular transfer: a chunk-rooted file travels as
    /// structure-plus-chunks; a delta export against the receiver's
    /// have-set moves ONLY the missing chunks (rsync-class incremental);
    /// the receiver re-links roots without re-chunking and reads whole.
    #[test]
    fn delta_bundles_move_only_missing_chunks() {
        use crate::chunking::ChunkingConfig;
        use std::collections::BTreeMap;
        use std::collections::BTreeSet;

        let config = ChunkingConfig {
            whole_blob_threshold: 256,
            min_size: 64,
            avg_size: 256,
            max_size: 1024,
        };
        let mut source = vcs("chunk-src");
        source.init("t0").expect("init");
        source
            .create_branch("draft_a", None, "main", "t1")
            .expect("create");
        // A large body enters through the chunk tier; its ROOT id lands
        // in the manifest via import_diff (the exec import path).
        let big = "0123456789abcdef-".repeat(600);
        let root = source
            .content_store()
            .put_chunked(&big, &config)
            .expect("put chunked");
        let mut changed = BTreeMap::new();
        changed.insert("big.dat".to_owned(), root.clone());
        source
            .import_diff("draft_a", &changed, &[], "cut_a1", "t2")
            .expect("import diff");
        assert_eq!(
            source.read("draft_a", "big.dat").expect("read").as_deref(),
            Some(big.as_str()),
            "reads are transparent over the chunk tier"
        );

        // Full export carries the root structure + every chunk body.
        let full = source
            .export_bundle("draft_a")
            .expect("export")
            .expect("branch");
        let root_entry = full
            .blobs
            .iter()
            .find(|blob| blob.id == root)
            .expect("root entry");
        let chunk_count = root_entry.chunk_ids.as_ref().expect("chunk ids").len();
        assert!(chunk_count > 1);
        assert_eq!(root_entry.body, None, "roots carry structure, not bytes");
        let carried_bodies = full.blobs.iter().filter(|b| b.body.is_some()).count();
        assert_eq!(carried_bodies, chunk_count);

        // Receiver materializes the full bundle...
        let mut target = vcs("chunk-dst");
        target.init("t0").expect("init");
        target.import_bundle(&full, "t1").expect("import");
        assert_eq!(
            target.read("draft_a", "big.dat").expect("read").as_deref(),
            Some(big.as_str()),
            "the receiver re-links the root and reads whole"
        );

        // ...the source's file grows a tail (most chunks unchanged)...
        let grown = format!("{big}THE-NEW-TAIL");
        let grown_root = source
            .content_store()
            .put_chunked(&grown, &config)
            .expect("put grown");
        let mut changed = BTreeMap::new();
        changed.insert("big.dat".to_owned(), grown_root.clone());
        source
            .import_diff("draft_a", &changed, &[], "cut_a2", "t3")
            .expect("import diff");

        // ...pull-missing: the sender's digest, filtered by the receiver
        // to what it holds, drives a delta export that omits shared
        // chunk bodies.
        let digest = source
            .transferable_ids("draft_a")
            .expect("digest")
            .expect("branch");
        let have: BTreeSet<String> = held_subset(
            &digest,
            target.content_store() as &dyn crate::content::ContentBlobs,
        )
        .expect("held")
        .into_iter()
        .collect();
        assert!(!have.is_empty(), "the receiver already holds most chunks");
        let delta = source
            .export_bundle_delta("draft_a", &have)
            .expect("export")
            .expect("branch");
        let omitted = delta.blobs.iter().filter(|blob| blob.omitted).count();
        let carried = delta
            .blobs
            .iter()
            .filter(|blob| blob.body.is_some())
            .count();
        assert_eq!(omitted, have.len());
        assert!(
            carried < chunk_count,
            "only the tail's chunks travel ({carried} carried, {omitted} omitted)"
        );
        // The receiver folds the delta in: divergent-branch refusal
        // protects local work, so re-point via a fresh workspace check —
        // here the branch head moved on the source, so import refuses...
        assert!(matches!(
            target.import_bundle(&delta, "t2").expect("import"),
            BundleImportOutcome::DivergentBranch { .. }
        ));
        // ...but a fresh receiver with the same have-set (seeded by the
        // first bundle) materializes the delta completely.
        let mut fresh = vcs("chunk-fresh");
        fresh.init("t0").expect("init");
        fresh.import_bundle(&full, "t1").expect("seed");
        // Drop the stale branch pointer, keep the content: the delta
        // re-creates the branch at the new head.
        fresh.discard_branch("draft_a", "t2").expect("discard");
        let renamed = {
            let mut bundle = delta.clone();
            bundle.branch.branch_id = "draft_a_v2".to_owned();
            bundle.branch.name = None;
            bundle
        };
        fresh.import_bundle(&renamed, "t3").expect("delta import");
        assert_eq!(
            fresh
                .read("draft_a_v2", "big.dat")
                .expect("read")
                .as_deref(),
            Some(grown.as_str()),
            "the delta bundle + local chunks reassemble the grown file"
        );
    }
}
