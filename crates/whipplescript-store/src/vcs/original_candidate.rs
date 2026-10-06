//! Original saved results become isolated whole-branch candidates. The caller
//! supplies original authorization at every publication; evidence grants none.
use super::*;
use crate::branches::write_evidence::WriteEvidenceRef;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalWorkspaceCandidate {
    /// Immutable branch state at creation, not the candidate's current state.
    pub branch: BranchRow,
    pub cut: CutRow,
    pub operation: OpRow,
    pub evidence: WriteEvidenceRef,
}

fn digest(value: &impl serde::Serialize) -> StoreResult<String> {
    Ok(Sha256::digest(serde_json::to_vec(value)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn retain_manifest(
    content: &impl ContentBlobs,
    hash: &str,
    retained: &mut Vec<String>,
) -> StoreResult<()> {
    let body = content
        .get(hash)?
        .ok_or_else(|| StoreError::Conflict("original candidate manifest unavailable".into()))?;
    crate::content::verify_body(hash, &body, "original candidate manifest")?;
    if crate::manifest_tree::is_node(&String::from_utf8_lossy(&body)) {
        retained.extend(crate::manifest_tree::reachable_ids(content, hash)?);
    } else {
        let manifest: BTreeMap<String, String> = serde_json::from_slice(&body)?;
        retained.push(hash.to_owned());
        retained.extend(manifest.into_values());
    }
    Ok(())
}

fn changes(
    changed: &BTreeMap<String, String>,
    removed: &[String],
) -> StoreResult<BTreeMap<String, Option<String>>> {
    let mut changes: BTreeMap<_, _> = changed
        .iter()
        .map(|(p, h)| (p.clone(), Some(h.clone())))
        .collect();
    let mut seen: BTreeSet<&String> = BTreeSet::new();
    for path in removed {
        if changed.contains_key(path) || !seen.insert(path) {
            return Err(StoreError::Conflict(
                "original candidate has ambiguous path changes".into(),
            ));
        }
        changes.insert(path.clone(), None);
    }
    Ok(changes)
}

fn candidate_branch(original: &BranchRow, actor: &str, intent: &str) -> StoreResult<String> {
    if actor.trim().is_empty() || intent.trim().is_empty() {
        return Err(StoreError::Conflict(
            "original candidate requires actor and command".into(),
        ));
    }
    Ok(format!(
        "original-candidate-{}",
        digest(&("original-candidate/v1", &original.branch_id, actor, intent))?
    ))
}

fn proposal(
    original: &BranchRow,
    manifest_hash: String,
    evidence: &WriteEvidenceRef,
    actor: &str,
    intent: &str,
    at: &str,
) -> StoreResult<(OriginalWorkspaceCandidate, String)> {
    let branch_id = candidate_branch(original, actor, intent)?;
    let cut_id = format!("cut-{branch_id}");
    let meaning = format!(
        "original-candidate:{}",
        digest(&(
            "original-candidate-meaning/v1",
            original,
            &manifest_hash,
            evidence,
            actor,
            intent,
            &branch_id,
            &cut_id
        ))?
    );
    let branch = BranchRow {
        branch_id: branch_id.clone(),
        name: None,
        parent_branch_id: original.parent_branch_id.clone(),
        branch_point_cut_id: original.branch_point_cut_id.clone(),
        branch_point_manifest_hash: original.branch_point_manifest_hash.clone(),
        head_cut_id: Some(cut_id.clone()),
        head_manifest_hash: Some(manifest_hash.clone()),
        adopted_merge_cut_id: None,
        status: BranchStatus::Active,
        created_at: at.into(),
        updated_at: at.into(),
    };
    let cut = CutRow {
        cut_id: cut_id.clone(),
        change_id: cut_id.clone(),
        branch_id: branch_id.clone(),
        manifest_hash,
        parent_cut_id: original.head_cut_id.clone(),
        origin: Some(meaning.clone()),
        actor: Some(actor.into()),
        intent: Some(intent.into()),
        recorded_at: at.into(),
    };
    let operation = OpRow {
        seq: 0,
        op_id: format!("op-{cut_id}"),
        kind: "original-candidate".into(),
        deltas: vec![OpBranchDelta {
            branch_id,
            before: None,
            after: OpBranchState::of(&branch),
        }],
        origin: Some(meaning.clone()),
        recorded_at: at.into(),
    };
    let proposed = OriginalWorkspaceCandidate {
        branch,
        cut,
        operation,
        evidence: evidence.clone(),
    };
    Ok((proposed, meaning))
}

impl NativeWorkspaceVcs {
    /// Exact original metadata under an independently admitted current reader.
    /// This performs no creation, preparation, repair or projection. Its value
    /// grants no payload access; re-observe under fenced retained publication
    /// before releasing bytes. Supports existing read-only stores.
    #[allow(clippy::too_many_arguments)] // Complete original creation binding.
    pub fn observe_original_candidate_guarded(
        &self,
        original: &BranchRow,
        changed: &BTreeMap<String, String>,
        removed: &[String],
        evidence: &WriteEvidenceRef,
        actor: &str,
        intent: &str,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<OriginalWorkspaceCandidate> {
        check()?;
        evidence.validate()?;
        let branch = candidate_branch(original, actor, intent)?;
        let cut = self
            .branches
            .get_cut(&format!("cut-{branch}"))?
            .ok_or_else(|| StoreError::Conflict("original candidate receipt missing".into()))?;
        let base = original
            .head_manifest_hash
            .as_deref()
            .ok_or_else(|| StoreError::Conflict("original candidate base unavailable".into()))?;
        let mut expected = self.load_manifest(Some(base))?;
        for (path, hash) in changes(changed, removed)? {
            if let Some(hash) = hash {
                expected.insert(path, hash);
            } else {
                expected.remove(&path);
            }
        }
        if self.cut_manifest(&cut.cut_id)?.as_ref() != Some(&expected) {
            return Err(StoreError::Conflict(
                "original candidate complete tree differs".into(),
            ));
        }
        // Prove evidence and all referenced content remain available without
        // granting or returning any file bytes to this observer's caller.
        let mut retained = Vec::new();
        retain_manifest(&self.content, base, &mut retained)?;
        retain_manifest(&self.content, &cut.manifest_hash, &mut retained)?;
        if let Some(hash) = &original.branch_point_manifest_hash {
            retain_manifest(&self.content, hash, &mut retained)?;
        }
        let body = self.content.get(&evidence.content_hash)?.ok_or_else(|| {
            StoreError::Conflict("original candidate evidence unavailable".into())
        })?;
        crate::content::verify_body(&evidence.content_hash, &body, "original candidate evidence")?;
        let payloads: BTreeMap<String, String> = serde_json::from_slice(&body)?;
        retained.push(evidence.content_hash.clone());
        retained.extend(payloads.into_values());
        for id in retained {
            if !self.content.cached_read_available(&id)? {
                return Err(StoreError::Conflict(
                    "original candidate retained content unavailable".into(),
                ));
            }
        }
        let (proposed, meaning) = proposal(
            original,
            cut.manifest_hash,
            evidence,
            actor,
            intent,
            &cut.recorded_at,
        )?;
        let result = crate::branches::original_candidate::observe(
            &self.branches,
            original,
            &proposed,
            &meaning,
        )?;
        check()?;
        Ok(result)
    }

    /// Prepare content before the atomic reference transaction. No filesystem
    /// reads or source mutations occur. `original` must come from the host's
    /// sealed startup evidence. The callback must retain that same authority
    /// and must not reacquire these native stores or perform external work.
    pub fn import_original_candidate_guarded(
        &mut self,
        original: &BranchRow,
        changed: &BTreeMap<String, String>,
        removed: &[String],
        evidence: &WriteEvidenceRef,
        at: &str,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<OriginalWorkspaceCandidate> {
        check()?;
        evidence.validate()?;
        let (Some(actor), Some(intent)) = (&self.actor, &self.intent) else {
            return Err(StoreError::Conflict(
                "original candidate requires actor and command".into(),
            ));
        };
        // Validate through the canonical identity before preparing any content.
        candidate_branch(original, actor, intent)?;
        let Some(base) = &original.head_manifest_hash else {
            return Err(StoreError::Conflict(
                "original candidate base unavailable".into(),
            ));
        };
        let changes = changes(changed, removed)?;
        let prepared = crate::content::publication::PreparedBlobs::new(&self.content);
        let manifest_hash = self.advance_manifest_using(&prepared, Some(base), &changes)?;
        let mut retained = prepared.ids();
        retain_manifest(&self.content, base, &mut retained)?;
        retain_manifest(&self.content, &manifest_hash, &mut retained)?;
        if let Some(hash) = &original.branch_point_manifest_hash {
            retain_manifest(&self.content, hash, &mut retained)?;
        }
        // A flat evidence manifest stays a GC retention root, rather than an
        // opaque nested envelope whose payloads collection cannot follow.
        let body = self.content.get(&evidence.content_hash)?.ok_or_else(|| {
            StoreError::Conflict("original candidate evidence unavailable".into())
        })?;
        crate::content::verify_body(&evidence.content_hash, &body, "original candidate evidence")?;
        let payloads: BTreeMap<String, String> = serde_json::from_slice(&body)?;
        retained.push(evidence.content_hash.clone());
        retained.extend(payloads.into_values());
        let (proposed, meaning) = proposal(original, manifest_hash, evidence, actor, intent, at)?;
        self.content.publish_retained(&retained, || {
            crate::branches::original_candidate::commit(
                &mut self.branches,
                original,
                &proposed,
                &meaning,
                check,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (
        super::super::tests::TempVcs,
        BranchRow,
        BTreeMap<String, String>,
        WriteEvidenceRef,
    ) {
        let mut vcs = super::super::tests::vcs();
        vcs.init("t0").expect("init");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "shared.txt",
            Some("parent"),
            "parent-base",
            "t1",
        )
        .expect("parent");
        vcs.create_branch("source", None, MAINLINE_BRANCH_ID, "t2")
            .expect("source");
        vcs.write(
            "source",
            "earlier.txt",
            Some("earlier unpromoted"),
            "original-base",
            "t3",
        )
        .expect("earlier");
        let original = vcs.get_branch("source").expect("row").expect("source");
        let body = vcs.content.put_text("saved result").expect("body");
        let evidence_hash = vcs
            .content
            .put(&serde_json::to_vec(&BTreeMap::from([("saved.txt", &body)])).expect("json"))
            .expect("evidence");
        vcs.set_actor(Some("staff:original".into()));
        vcs.set_intent(Some("command:original".into()));
        (
            vcs,
            original,
            BTreeMap::from([("saved.txt".into(), body)]),
            WriteEvidenceRef {
                schema_ref: "result/v1".into(),
                label_ref: "private".into(),
                content_hash: evidence_hash,
            },
        )
    }

    #[test]
    fn original_candidate_observer_reopens_read_only_after_later_work_without_writing() {
        let (mut vcs, original, changes, evidence) = setup();
        let created = vcs
            .import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "t7",
                &mut || Ok(()),
            )
            .unwrap();
        vcs.create_branch("other-parent", None, MAINLINE_BRANCH_ID, "t8")
            .unwrap();
        vcs.branches
            .retarget_branch("source", "other-parent", "t9")
            .unwrap();
        for branch in ["source", MAINLINE_BRANCH_ID, &created.branch.branch_id] {
            vcs.write(
                branch,
                "later.txt",
                Some("independent later work"),
                &format!("later-{branch}"),
                "t10",
            )
            .unwrap();
        }
        let before_branches = vcs.list_branches(None).unwrap();
        let before_ops = vcs.branches.list_ops(100).unwrap();
        let before_files: Vec<_> = [
            "branches.sqlite",
            "content.sqlite",
            "branches.sqlite-wal",
            "content.sqlite-wal",
        ]
        .iter()
        .map(|file| (file, std::fs::read(vcs.dir.join(file)).ok()))
        .collect();
        let reader = NativeWorkspaceVcs::open_read_only(
            vcs.dir.join("branches.sqlite"),
            vcs.dir.join("content.sqlite"),
        )
        .unwrap();
        let mut calls = 0;
        let observed = reader
            .observe_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "staff:original",
                "command:original",
                &mut || {
                    calls += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(observed, created);
        assert_eq!(calls, 2);
        assert_eq!(reader.list_branches(None).unwrap(), before_branches);
        assert_eq!(reader.branches.list_ops(100).unwrap(), before_ops);
        drop(reader);
        for (file, bytes) in before_files {
            assert_eq!(
                std::fs::read(vcs.dir.join(file)).ok(),
                bytes,
                "observer wrote {file}"
            );
        }
        let publisher = NativeWorkspaceVcs::open_for_recorded_review(
            vcs.dir.join("branches.sqlite"),
            vcs.dir.join("content.sqlite"),
        )
        .unwrap();
        let retained = vec![
            created.cut.manifest_hash.clone(),
            evidence.content_hash.clone(),
            changes["saved.txt"].clone(),
        ];
        let body = publisher
            .publish_retained_recorded_observation(&retained, |held| {
                let observed = held.observe_original_candidate_guarded(
                    &original,
                    &changes,
                    &[],
                    &evidence,
                    "staff:original",
                    "command:original",
                    &mut || Ok(()),
                )?;
                assert_eq!(observed, created);
                let competing = rusqlite::Connection::open(vcs.dir.join("branches.sqlite"))?;
                competing.busy_timeout(std::time::Duration::from_millis(10))?;
                assert!(
                    competing
                        .execute("UPDATE branches SET name=name WHERE branch_id='source'", [])
                        .is_err(),
                    "branch writer escaped retained observation"
                );
                let competing = rusqlite::Connection::open(vcs.dir.join("content.sqlite"))?;
                competing.busy_timeout(std::time::Duration::from_millis(10))?;
                assert!(
                    competing
                        .execute(
                            "UPDATE content_blobs SET body=body WHERE id=?1",
                            [&changes["saved.txt"]]
                        )
                        .is_err(),
                    "content writer escaped retained observation"
                );
                held.content
                    .get(&changes["saved.txt"])?
                    .ok_or_else(|| StoreError::Conflict("original body unavailable".into()))
            })
            .unwrap();
        assert_eq!(body, b"saved result");
        assert_eq!(vcs.list_branches(None).unwrap(), before_branches);
        assert_eq!(vcs.branches.list_ops(100).unwrap(), before_ops);
    }

    #[test]
    fn original_candidate_observer_refuses_missing_changed_and_ended_evidence_without_repair() {
        for case in [
            "absent",
            "branch",
            "cut",
            "operation",
            "evidence",
            "cut-actor",
            "cut-intent",
            "cut-parent",
            "cut-origin",
            "op-origin",
            "op-deltas",
            "evidence-label",
            "body-erased",
            "evidence-erased",
            "changed-tree",
            "removed-input",
            "chunk-child-loss",
            "changed-lineage",
            "wrong-actor",
            "wrong-command",
            "empty-actor",
            "empty-command",
            "missing-base",
            "entry-ended",
            "release-ended",
            "source-discarded",
            "parent-discarded",
            "candidate-discarded",
        ] {
            let (mut vcs, mut original, mut changes, mut evidence) = setup();
            if case == "chunk-child-loss" {
                let root = vcs
                    .content
                    .put_chunked(
                        &"original chunked result-".repeat(16),
                        &crate::chunking::ChunkingConfig {
                            whole_blob_threshold: 8,
                            min_size: 4,
                            avg_size: 8,
                            max_size: 32,
                        },
                    )
                    .unwrap();
                assert!(
                    vcs.content
                        .chunk_root_info(&root)
                        .unwrap()
                        .unwrap()
                        .chunk_ids
                        .len()
                        > 1
                );
                changes.insert("saved.txt".into(), root.clone());
                evidence.content_hash = vcs
                    .content
                    .put(&serde_json::to_vec(&BTreeMap::from([("saved.txt", root)])).unwrap())
                    .unwrap();
            }
            let created = if case != "absent" {
                Some(
                    vcs.import_original_candidate_guarded(
                        &original,
                        &changes,
                        &[],
                        &evidence,
                        "t7",
                        &mut || Ok(()),
                    )
                    .unwrap(),
                )
            } else {
                None
            };
            let db = rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).unwrap();
            if let Some(result) = &created {
                match case {
                    "branch" => {
                        db.execute(
                            "DELETE FROM branches WHERE branch_id=?1",
                            [&result.branch.branch_id],
                        )
                        .unwrap();
                    }
                    "cut" => {
                        db.execute("DELETE FROM cuts WHERE cut_id=?1", [&result.cut.cut_id])
                            .unwrap();
                    }
                    "operation" => {
                        db.execute("DELETE FROM ops WHERE op_id=?1", [&result.operation.op_id])
                            .unwrap();
                    }
                    "evidence" => {
                        db.execute(
                            "DELETE FROM cut_evidence WHERE cut_id=?1",
                            [&result.cut.cut_id],
                        )
                        .unwrap();
                    }
                    "cut-actor" => {
                        db.execute(
                            "UPDATE cuts SET actor='other' WHERE cut_id=?1",
                            [&result.cut.cut_id],
                        )
                        .unwrap();
                    }
                    "cut-intent" => {
                        db.execute(
                            "UPDATE cuts SET intent='other' WHERE cut_id=?1",
                            [&result.cut.cut_id],
                        )
                        .unwrap();
                    }
                    "cut-parent" => {
                        db.execute(
                            "UPDATE cuts SET parent_cut_id=NULL WHERE cut_id=?1",
                            [&result.cut.cut_id],
                        )
                        .unwrap();
                    }
                    "cut-origin" => {
                        db.execute(
                            "UPDATE cuts SET origin='other' WHERE cut_id=?1",
                            [&result.cut.cut_id],
                        )
                        .unwrap();
                    }
                    "op-origin" => {
                        db.execute(
                            "UPDATE ops SET origin='other' WHERE op_id=?1",
                            [&result.operation.op_id],
                        )
                        .unwrap();
                    }
                    "op-deltas" => {
                        db.execute(
                            "UPDATE ops SET deltas='[]' WHERE op_id=?1",
                            [&result.operation.op_id],
                        )
                        .unwrap();
                    }
                    "evidence-label" => {
                        db.execute(
                            "UPDATE cut_evidence SET label_ref='other' WHERE cut_id=?1",
                            [&result.cut.cut_id],
                        )
                        .unwrap();
                    }
                    "chunk-child-loss" => {
                        let root = &changes["saved.txt"];
                        let chunk = vcs
                            .content
                            .chunk_root_info(root)
                            .unwrap()
                            .unwrap()
                            .chunk_ids[0]
                            .clone();
                        rusqlite::Connection::open(vcs.dir.join("content.sqlite"))
                            .unwrap()
                            .execute("DELETE FROM content_blobs WHERE id=?1", [&chunk])
                            .unwrap();
                        assert!(
                            matches!(
                                vcs.content.status(root).unwrap(),
                                crate::content::BlobStatus::Live { .. }
                            ),
                            "fixture must retain a live root header"
                        );
                    }
                    "body-erased" => {
                        vcs.content.erase(&changes["saved.txt"], "t8").unwrap();
                    }
                    "evidence-erased" => {
                        vcs.content.erase(&evidence.content_hash, "t8").unwrap();
                    }
                    "changed-tree" => {
                        changes.clear();
                    }
                    "missing-base" => original.head_manifest_hash = None,
                    "changed-lineage" => {
                        original.branch_point_cut_id = None;
                        original.branch_point_manifest_hash = None;
                    }
                    "source-discarded" | "parent-discarded" | "candidate-discarded" => {
                        let branch = match case {
                            "source-discarded" => "source",
                            "parent-discarded" => MAINLINE_BRANCH_ID,
                            _ => &result.branch.branch_id,
                        };
                        db.execute(
                            "UPDATE branches SET status='discarded' WHERE branch_id=?1",
                            [branch],
                        )
                        .unwrap();
                    }
                    _ => {}
                }
            }
            let branches = vcs.list_branches(None).unwrap();
            let ops = vcs.branches.list_ops(100).unwrap();
            let reader = NativeWorkspaceVcs::open_read_only(
                vcs.dir.join("branches.sqlite"),
                vcs.dir.join("content.sqlite"),
            )
            .unwrap();
            let mut calls = 0;
            let removed = if case == "removed-input" {
                vec!["shared.txt".into()]
            } else {
                Vec::new()
            };
            let result = reader.observe_original_candidate_guarded(
                &original,
                &changes,
                &removed,
                &evidence,
                if case == "wrong-actor" {
                    "other"
                } else if case == "empty-actor" {
                    " "
                } else {
                    "staff:original"
                },
                if case == "wrong-command" {
                    "other"
                } else if case == "empty-command" {
                    " "
                } else {
                    "command:original"
                },
                &mut || {
                    calls += 1;
                    if (case == "entry-ended" && calls == 1)
                        || (case == "release-ended" && calls == 2)
                    {
                        Err(StoreError::Conflict("current reader ended".into()))
                    } else {
                        Ok(())
                    }
                },
            );
            let error = result.expect_err(&format!("{case} accepted original result evidence"));
            let expected = match case {
                "absent" | "cut" | "wrong-actor" | "wrong-command" => {
                    Some("original candidate receipt missing")
                }
                "missing-base" => Some("original candidate base unavailable"),
                "empty-actor" | "empty-command" => {
                    Some("original candidate requires actor and command")
                }
                "evidence-erased" => Some("original candidate evidence unavailable"),
                _ => None,
            };
            if let Some(expected) = expected {
                assert!(format!("{error:?}").contains(expected), "{case}: {error:?}");
            }
            assert_eq!(
                vcs.list_branches(None).unwrap(),
                branches,
                "{case} repaired branches"
            );
            assert_eq!(
                vcs.branches.list_ops(100).unwrap(),
                ops,
                "{case} repaired operations"
            );
        }
    }

    #[test]
    fn original_candidate_preserves_whole_base_and_original_topology_after_later_work() {
        let (mut vcs, original, changes, evidence) = setup();
        vcs.create_branch("other-parent", None, MAINLINE_BRANCH_ID, "t4")
            .expect("later parent");
        vcs.branches
            .retarget_branch("source", "other-parent", "t5")
            .expect("retarget");
        vcs.write(
            "source",
            "later.txt",
            Some("later staff work"),
            "later-cut",
            "t6",
        )
        .expect("later");
        let before_source = vcs.get_branch("source").expect("source");
        let before_parent = vcs.get_branch(MAINLINE_BRANCH_ID).expect("parent");
        let result = vcs
            .import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "t7",
                &mut || Ok(()),
            )
            .expect("candidate");
        assert_eq!(result.branch.parent_branch_id, original.parent_branch_id);
        assert_eq!(
            result.branch.branch_point_cut_id,
            original.branch_point_cut_id
        );
        assert_eq!(
            result.branch.branch_point_manifest_hash,
            original.branch_point_manifest_hash
        );
        assert_eq!(result.cut.parent_cut_id, original.head_cut_id);
        let manifest = vcs
            .load_manifest(Some(&result.cut.manifest_hash))
            .expect("manifest");
        assert_eq!(manifest.len(), 3);
        assert_eq!(
            vcs.content
                .get_text(&manifest["earlier.txt"])
                .expect("body")
                .text(),
            Some("earlier unpromoted".into())
        );
        assert_eq!(manifest["saved.txt"], changes["saved.txt"]);
        assert!(!manifest.contains_key("later.txt"));
        assert_eq!(vcs.get_branch("source").expect("source"), before_source);
        assert_eq!(
            vcs.get_branch(MAINLINE_BRANCH_ID).expect("parent"),
            before_parent
        );
        assert_eq!(
            vcs.import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "new-clock",
                &mut || Ok(())
            )
            .expect("retry"),
            result
        );
        // A later candidate head does not erase its immutable original receipt.
        vcs.write(
            &result.branch.branch_id,
            "candidate-later.txt",
            Some("new"),
            "candidate-later",
            "t8",
        )
        .expect("candidate later");
        let later_candidate = vcs.get_branch(&result.branch.branch_id).expect("candidate");
        assert_eq!(
            vcs.import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "retry",
                &mut || Ok(())
            )
            .expect("historical retry"),
            result
        );
        assert_eq!(
            vcs.get_branch(&result.branch.branch_id).expect("candidate"),
            later_candidate
        );
    }

    #[test]
    fn original_candidate_rejects_changed_meaning_missing_payload_and_partial_receipts() {
        let (mut vcs, original, changes, evidence) = setup();
        let result = vcs
            .import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "t7",
                &mut || Ok(()),
            )
            .expect("candidate");
        let before = vcs.list_branches(None).expect("branches");
        let changed = BTreeMap::from([("other.txt".into(), changes["saved.txt"].clone())]);
        let error = vcs
            .import_original_candidate_guarded(
                &original,
                &changed,
                &[],
                &evidence,
                "t8",
                &mut || Ok(()),
            )
            .expect_err("changed meaning");
        assert!(format!("{error:?}").contains("retry changes original meaning"));
        let mut changed_original = original.clone();
        changed_original.updated_at = "changed-original".into();
        assert!(vcs
            .import_original_candidate_guarded(
                &changed_original,
                &changes,
                &[],
                &evidence,
                "t8",
                &mut || Ok(())
            )
            .is_err());
        let changed_evidence = WriteEvidenceRef {
            label_ref: "different".into(),
            ..evidence.clone()
        };
        assert!(vcs
            .import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &changed_evidence,
                "t8",
                &mut || Ok(())
            )
            .is_err());
        assert_eq!(vcs.list_branches(None).expect("unchanged"), before);
        rusqlite::Connection::open(vcs.dir.join("branches.sqlite"))
            .expect("fault connection")
            .execute(
                "DELETE FROM cut_evidence WHERE cut_id = ?1",
                [&result.cut.cut_id],
            )
            .expect("partial receipt");
        let error = vcs
            .import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "t8",
                &mut || Ok(()),
            )
            .expect_err("partial receipt");
        assert!(format!("{error:?}").contains("partial original receipt"));
        assert!(vcs
            .write_evidence(&result.cut.cut_id)
            .expect("no repair")
            .is_none());
        assert_eq!(vcs.list_branches(None).expect("unchanged"), before);
        let (mut vcs, original, changes, evidence) = setup();
        vcs.content
            .erase(&changes["saved.txt"], "t4")
            .expect("erase");
        assert!(vcs
            .import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "t7",
                &mut || Ok(())
            )
            .is_err());
        assert_eq!(vcs.list_branches(None).expect("branches").len(), 2);
    }

    #[test]
    fn original_candidate_atomic_rollback_and_original_access_checks() {
        for table in ["branches", "cuts", "ops", "cut_evidence"] {
            for moment in ["BEFORE", "AFTER"] {
                let (mut vcs, original, changes, evidence) = setup();
                let before = vcs.list_branches(None).expect("branches");
                let ops = vcs.branches.list_ops(100).expect("ops");
                rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).expect("fault connection").execute_batch(&format!("CREATE TRIGGER fail_candidate {moment} INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'injected'); END")).expect("inject");
                assert!(
                    vcs.import_original_candidate_guarded(
                        &original,
                        &changes,
                        &[],
                        &evidence,
                        "t7",
                        &mut || Ok(())
                    )
                    .is_err(),
                    "{moment} {table}"
                );
                assert_eq!(vcs.list_branches(None).expect("unchanged"), before);
                assert_eq!(vcs.branches.list_ops(100).expect("unchanged ops"), ops);
                assert_eq!(
                    rusqlite::Connection::open(vcs.dir.join("branches.sqlite"))
                        .expect("fault connection")
                        .query_row("SELECT COUNT(*) FROM cut_evidence", [], |row| row
                            .get::<_, i64>(0))
                        .expect("count"),
                    0
                );
            }
        }
        // Revoke separately at every callback: entry, branch transaction entry,
        // and final commit. No successful preflight supplies later authority.
        for fail_at in 1..=3 {
            let (mut vcs, original, changes, evidence) = setup();
            let before = vcs.list_branches(None).expect("branches");
            let mut calls = 0;
            assert!(vcs
                .import_original_candidate_guarded(
                    &original,
                    &changes,
                    &[],
                    &evidence,
                    "t7",
                    &mut || {
                        calls += 1;
                        if calls == fail_at {
                            Err(StoreError::Conflict("access removed".into()))
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err());
            assert_eq!(calls, fail_at);
            assert_eq!(vcs.list_branches(None).expect("unchanged"), before);
        }
    }
    #[test]
    fn original_candidate_refuses_reserved_discarded_and_controlled_custody() {
        for replay in [false, true] {
            for custody in ["source", MAINLINE_BRANCH_ID, "candidate"] {
                for condition in ["reserved", "discarded", "controlled"] {
                    let (mut vcs, original, changes, evidence) = setup();
                    let candidate = if replay {
                        Some(
                            vcs.import_original_candidate_guarded(
                                &original,
                                &changes,
                                &[],
                                &evidence,
                                "t7",
                                &mut || Ok(()),
                            )
                            .expect("candidate"),
                        )
                    } else {
                        None
                    };
                    if custody == "candidate" && candidate.is_none() {
                        continue;
                    }
                    let id = if custody == "candidate" {
                        candidate
                            .as_ref()
                            .expect("candidate")
                            .branch
                            .branch_id
                            .as_str()
                    } else {
                        custody
                    };
                    match condition {
                        "reserved" => {
                            vcs.branches
                                .reserve_head(id, "separate-owner", "t8")
                                .expect("reserve");
                        }
                        "discarded" => {
                            vcs.branches.discard_branch(id, "t8").expect("discard");
                        }
                        _ => {
                            // Inject the exact typed native fence to model custody
                            // transferred after the original startup was sealed.
                            let state = crate::branches::flowing_fence::FlowingFenceState {
                                source_branch_id: id.into(),
                                incarnation_id: "new-custody".into(),
                                kind: crate::branches::flowing_fence::FlowingSourceKind::Twig,
                                owner: "separate-owner".into(),
                                owner_epoch: 1,
                                eligibility_epoch: 1,
                                held: false,
                                revision: None,
                                admission_enabled: true,
                                opened_at: "t8".into(),
                            };
                            rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).expect("fixture connection")
                                .execute("INSERT INTO flowing_source_fences (source_branch_id, state_json) VALUES (?1, ?2)",
                                    rusqlite::params![id, serde_json::to_string(&state).expect("state")]).expect("fence");
                        }
                    }
                    let before = vcs.list_branches(None).expect("branches");
                    let error = vcs
                        .import_original_candidate_guarded(
                            &original,
                            &changes,
                            &[],
                            &evidence,
                            "t9",
                            &mut || Ok(()),
                        )
                        .expect_err("separate custody");
                    let expected = if condition == "discarded" {
                        "custody discarded"
                    } else {
                        "controlled or reserved custody"
                    };
                    assert!(
                        format!("{error:?}").contains(expected),
                        "{replay} {custody} {condition}: {error:?}"
                    );
                    if replay {
                        let reader = NativeWorkspaceVcs::open_read_only(
                            vcs.dir.join("branches.sqlite"),
                            vcs.dir.join("content.sqlite"),
                        )
                        .unwrap();
                        let error = reader
                            .observe_original_candidate_guarded(
                                &original,
                                &changes,
                                &[],
                                &evidence,
                                "staff:original",
                                "command:original",
                                &mut || Ok(()),
                            )
                            .expect_err("observation under separate custody");
                        assert!(
                            format!("{error:?}").contains(expected),
                            "observer {custody} {condition}: {error:?}"
                        );
                    }
                    assert_eq!(vcs.list_branches(None).expect("unchanged"), before);
                }
            }
        }
    }

    #[test]
    fn original_candidate_validates_original_coordinates_and_unambiguous_changes() {
        for condition in [
            "base-cut",
            "base-hash",
            "base-source",
            "parent",
            "self-parent",
            "divergence-cut",
            "divergence-hash",
            "half-divergence",
            "original-status",
        ] {
            let (mut vcs, mut original, changes, evidence) = setup();
            match condition {
                "base-cut" => original.head_cut_id = Some("missing".into()),
                "base-hash" => original.head_manifest_hash = Some(evidence.content_hash.clone()),
                "base-source" => {
                    original.head_cut_id = original.branch_point_cut_id.clone();
                    original.head_manifest_hash = original.branch_point_manifest_hash.clone();
                }
                "parent" => original.parent_branch_id = Some("missing".into()),
                "self-parent" => original.parent_branch_id = Some("source".into()),
                "divergence-cut" => original.branch_point_cut_id = Some("missing".into()),
                "divergence-hash" => {
                    original.branch_point_manifest_hash = Some(evidence.content_hash.clone())
                }
                "half-divergence" => original.branch_point_cut_id = None,
                _ => original.status = BranchStatus::Discarded,
            }
            let before = vcs.list_branches(None).expect("branches");
            assert!(
                vcs.import_original_candidate_guarded(
                    &original,
                    &changes,
                    &[],
                    &evidence,
                    "t7",
                    &mut || Ok(())
                )
                .is_err(),
                "{condition}"
            );
            assert_eq!(vcs.list_branches(None).expect("unchanged"), before);
        }
        let (mut vcs, original, changes, evidence) = setup();
        for removed in [
            vec!["saved.txt".into()],
            vec!["same.txt".into(), "same.txt".into()],
        ] {
            assert!(vcs
                .import_original_candidate_guarded(
                    &original,
                    &changes,
                    &removed,
                    &evidence,
                    "t7",
                    &mut || Ok(())
                )
                .is_err());
        }
        vcs.set_actor(None);
        assert!(vcs
            .import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "t7",
                &mut || Ok(())
            )
            .is_err());
        vcs.set_actor(Some("staff:original".into()));
        vcs.set_intent(Some(" ".into()));
        assert!(vcs
            .import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "t7",
                &mut || Ok(())
            )
            .is_err());
    }

    #[test]
    fn original_candidate_checks_both_real_writers_on_fresh_and_retry() {
        let (mut vcs, original, changes, evidence) = setup();
        for attempt in ["fresh", "retry"] {
            let branch_rival =
                rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).expect("branch rival");
            let content_rival =
                rusqlite::Connection::open(vcs.dir.join("content.sqlite")).expect("content rival");
            for rival in [&branch_rival, &content_rival] {
                rival
                    .busy_timeout(std::time::Duration::ZERO)
                    .expect("no wait");
            }
            let mut calls = 0;
            vcs.import_original_candidate_guarded(&original, &changes, &[], &evidence, attempt, &mut || {
                calls += 1;
                if calls > 1 {
                    for rival in [&branch_rival, &content_rival] {
                        assert!(matches!(rival.execute_batch("BEGIN IMMEDIATE"), Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::DatabaseBusy), "{attempt}: both writers must be excluded");
                    }
                }
                Ok(())
            }).expect("publication");
            assert_eq!(calls, 3);
        }
    }
    #[test]
    fn original_candidate_missing_inputs_refuse_with_no_reference_repair() {
        let (mut vcs, original, changes, evidence) = setup();
        let mut references = Vec::new();
        let error = retain_manifest(&vcs.content, "absent-manifest", &mut references)
            .expect_err("absent manifest");
        assert!(format!("{error:?}").contains("original candidate manifest unavailable"));
        for field in ["actor", "manifest", "base-id", "half-divergence"] {
            let mut original = original.clone();
            match field {
                "actor" => vcs.set_actor(None),
                "manifest" => original.head_manifest_hash = None,
                "base-id" => original.head_cut_id = None,
                _ => original.branch_point_cut_id = None,
            }
            let error = vcs
                .import_original_candidate_guarded(
                    &original,
                    &changes,
                    &[],
                    &evidence,
                    "t7",
                    &mut || Ok(()),
                )
                .expect_err("missing input");
            let message = match field {
                "actor" => "original candidate requires actor and command",
                "manifest" => "original candidate base unavailable",
                "base-id" => "original base missing",
                _ => "incomplete original divergence",
            };
            assert!(format!("{error:?}").contains(message), "{field}: {error:?}");
            vcs.set_actor(Some("staff:original".into()));
        }
        vcs.content
            .erase(&evidence.content_hash, "t4")
            .expect("erase evidence");
        let error = vcs
            .import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "t7",
                &mut || Ok(()),
            )
            .expect_err("absent evidence");
        assert!(format!("{error:?}").contains("original candidate evidence unavailable"));
        assert_eq!(vcs.list_branches(None).expect("unchanged").len(), 2);
    }
    #[test]
    fn original_candidate_joins_recorded_review_settlement_and_reopened_history() {
        let (mut vcs, original, changes, evidence) = setup();
        let result = vcs
            .import_original_candidate_guarded(
                &original,
                &changes,
                &[],
                &evidence,
                "t7",
                &mut || Ok(()),
            )
            .expect("candidate");
        let retained = vec![evidence.content_hash.clone()];
        let review = vcs
            .prepare_recorded_merge_review(
                &result.branch.branch_id,
                &result.cut.cut_id,
                &retained,
                &mut || Ok(()),
            )
            .expect("existing review owner");
        assert_eq!(review.review().target_branch_id, MAINLINE_BRANCH_ID);
        assert!(review
            .review()
            .diff
            .iter()
            .any(|entry| entry.path == "earlier.txt"));
        assert!(review
            .review()
            .diff
            .iter()
            .any(|entry| entry.path == "saved.txt"));
        let prepared = vcs
            .prepare_recorded_settlement(
                &result.branch.branch_id,
                &result.cut.cut_id,
                &retained,
                "candidate-settlement",
                "staff:original",
                "command:original",
                "t8",
                &mut || Ok(()),
            )
            .expect("existing settlement owner");
        let super::super::recorded_review::RecordedSettlementOutcome::Applied(applied) = vcs
            .apply_prepared_recorded_settlement(
                &prepared,
                &mut || Ok(()),
                &mut super::super::NoNormLedger,
            )
            .expect("settle")
        else {
            panic!("fixture has no norm ledger and a clean candidate");
        };
        let settled_candidate = vcs
            .get_branch(&result.branch.branch_id)
            .expect("candidate")
            .expect("row");
        assert_eq!(settled_candidate.status, BranchStatus::Active);
        assert_eq!(
            settled_candidate.head_cut_id.as_deref(),
            Some("candidate-settlement")
        );
        vcs.write(
            &result.branch.branch_id,
            "candidate-after.txt",
            Some("later candidate work"),
            "candidate-after",
            "t9",
        )
        .expect("later candidate work");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "home-after.txt",
            Some("later home work"),
            "home-after",
            "t10",
        )
        .expect("later home work");
        let current_candidate = vcs
            .get_branch(&result.branch.branch_id)
            .expect("later candidate");
        assert_eq!(
            vcs.get_branch("source").expect("source"),
            Some(original.clone())
        );
        let mut reopened = NativeWorkspaceVcs::open_for_recorded_review(
            vcs.dir.join("branches.sqlite"),
            vcs.dir.join("content.sqlite"),
        )
        .expect("reopen existing owners");
        reopened.set_actor(Some("staff:original".into()));
        reopened.set_intent(Some("command:original".into()));
        let before = reopened.list_branches(None).expect("branches");
        assert_eq!(
            reopened
                .import_original_candidate_guarded(
                    &original,
                    &changes,
                    &[],
                    &evidence,
                    "new-clock",
                    &mut || Ok(())
                )
                .expect("immutable original candidate"),
            result
        );
        assert_eq!(
            reopened
                .get_branch(&result.branch.branch_id)
                .expect("candidate"),
            current_candidate
        );
        let history = reopened
            .recover_historical_recorded_settlement(
                &result.branch.branch_id,
                &result.cut.cut_id,
                &retained,
                "candidate-settlement",
                "staff:original",
                "command:original",
                &mut || Ok(()),
            )
            .expect("existing historical owner");
        assert_eq!(history.cut(), applied.cut());
        assert_eq!(history.operation(), applied.operation());
        assert_eq!(reopened.list_branches(None).expect("unchanged"), before);
        reopened
            .branches
            .adopt_branch(&result.branch.branch_id, "candidate-settlement", "t11")
            .expect("explicit adoption");
        let adopted = reopened
            .get_branch(&result.branch.branch_id)
            .expect("adopted")
            .expect("row");
        assert_eq!(adopted.status, BranchStatus::Adopted);
        assert_eq!(
            reopened
                .import_original_candidate_guarded(
                    &original,
                    &changes,
                    &[],
                    &evidence,
                    "retry",
                    &mut || Ok(())
                )
                .expect("immutable adopted candidate receipt"),
            result
        );
        assert_eq!(
            reopened
                .get_branch(&result.branch.branch_id)
                .expect("adopted unchanged"),
            Some(adopted)
        );
    }
}
