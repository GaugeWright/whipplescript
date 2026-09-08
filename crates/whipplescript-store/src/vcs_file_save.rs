//! Confined backing for an admitted read/replace workflow. The trusted host
//! binds this descriptor to the command and current authority; this storage
//! adapter neither authenticates a caller nor turns dispatch coordinates into
//! a grant. It preserves the existing merge engine and atomic write receipt.
mod recovery;
pub use recovery::{read_committed_save, RecoveredSave, SaveResultBinding};

use std::cell::RefCell;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::branches::Branches;
use crate::content::ContentBlobs;
use crate::files::{
    FileStore, FileWriteAccepted, FileWriteContext, FileWriteEvidence, FileWriteFailure,
};
use crate::text_merge::MergePiece;
use crate::vcs::{SaveWithBaseOutcome, WorkspaceVcs};

pub const SAVE_RECEIPT_SCHEMA: &str = "whipplescript.vcs-save-result.v1";
pub const SAVE_INPUT_PATH: &str = "/action/input/content";
pub const SAVE_OUTPUT_PATH: &str = "/action/output/target";

/// Already resolved by the trusted host from exact admitted references. None
/// of these strings are independently accepted as proof of authority.
#[derive(Clone, Debug)]
pub struct VersionedSaveBinding {
    pub branch_id: String,
    pub path: String,
    pub base_cut_id: String,
    pub draft: String,
    pub draft_hash: String,
    pub executing_principal: String,
    pub evidence_label: String,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SaveAttempt {
    pub instance_id: String,
    pub effect_id: String,
    pub run_id: String,
    pub started_event_id: String,
}
impl From<FileWriteContext<'_>> for SaveAttempt {
    fn from(context: FileWriteContext<'_>) -> Self {
        Self {
            instance_id: context.instance_id.into(),
            effect_id: context.effect_id.into(),
            run_id: context.run_id.into(),
            started_event_id: context.started_event_id.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SaveResult {
    Written {
        cut_id: String,
        parent_cut_id: Option<String>,
        operation_id: String,
        accepted_content_hash: String,
    },
    Merged {
        cut_id: String,
        parent_cut_id: Option<String>,
        operation_id: String,
        accepted_content_hash: String,
        pieces: Vec<MergePiece>,
    },
    Conflicted {
        head_cut_id: Option<String>,
        head_content: Option<String>,
        pieces: Vec<MergePiece>,
    },
}

/// Serialized behind a labeled content reference, never placed verbatim in
/// the command or general diagnostic message. Merge pieces can contain bodies.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SaveReceipt {
    pub protocol: String,
    pub branch_id: String,
    pub path: String,
    pub base_cut_id: String,
    pub draft_hash: String,
    pub executing_principal: String,
    pub attempt: SaveAttempt,
    pub result: SaveResult,
}

/// Recoverable target identity is fixed before execution and independent of
/// retry attempt, wall clock, actor renewal and branch-head movement.
pub fn save_cut_id(instance_id: &str, effect_id: &str) -> String {
    let coordinates = serde_json::json!([instance_id, effect_id]);
    format!(
        "action-save-{}",
        crate::items::sha256_hex(&format!("whipplescript:vcs-save:cut:v1\0{coordinates}"))
    )
}

pub struct VersionedSaveFileStore<B: Branches, C: ContentBlobs> {
    workspace: RefCell<WorkspaceVcs<B, C>>,
    binding: VersionedSaveBinding,
}

fn io_error(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}
fn denied(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

impl<B: Branches, C: ContentBlobs> VersionedSaveFileStore<B, C> {
    /// Takes a dedicated workspace handle. No storage access occurs here.
    pub fn new(workspace: WorkspaceVcs<B, C>, binding: VersionedSaveBinding) -> io::Result<Self> {
        if [
            &binding.branch_id,
            &binding.base_cut_id,
            &binding.executing_principal,
            &binding.evidence_label,
            &binding.recorded_at,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
        {
            return Err(denied(
                "save binding requires exact scope, base, principal, label and time",
            ));
        }
        if binding.path.contains('\\')
            || binding
                .path
                .split('/')
                .any(|p| matches!(p, "" | "." | ".."))
        {
            return Err(denied("save target must be a normalized relative path"));
        }
        if crate::stable_hash_hex(&binding.draft) != binding.draft_hash {
            return Err(denied("save draft does not match the immutable input hash"));
        }
        Ok(Self {
            workspace: RefCell::new(workspace),
            binding,
        })
    }

    fn body_at(&self, workspace: &WorkspaceVcs<B, C>, cut_id: &str) -> io::Result<Option<String>> {
        workspace
            .read_at_cut(cut_id, &self.binding.path)
            .map_err(io_error)
    }

    fn evidence(&self, attempt: SaveAttempt, result: SaveResult) -> io::Result<FileWriteEvidence> {
        let receipt = SaveReceipt {
            protocol: SAVE_RECEIPT_SCHEMA.into(),
            branch_id: self.binding.branch_id.clone(),
            path: self.binding.path.clone(),
            base_cut_id: self.binding.base_cut_id.clone(),
            draft_hash: self.binding.draft_hash.clone(),
            executing_principal: self.binding.executing_principal.clone(),
            attempt,
            result,
        };
        Ok(FileWriteEvidence {
            schema_ref: SAVE_RECEIPT_SCHEMA.into(),
            label_ref: self.binding.evidence_label.clone(),
            content: serde_json::to_string(&receipt).map_err(io_error)?,
        })
    }
}

impl<B: Branches, C: ContentBlobs> FileStore for VersionedSaveFileStore<B, C> {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        if path != Path::new(SAVE_INPUT_PATH) {
            return Err(denied("save binding reads only its immutable input"));
        }
        Ok(self.binding.draft.clone())
    }

    fn exists(&self, path: &Path) -> bool {
        if path == Path::new(SAVE_INPUT_PATH) {
            return true;
        }
        path == Path::new(SAVE_OUTPUT_PATH)
            && self
                .workspace
                .borrow()
                .read(&self.binding.branch_id, &self.binding.path)
                .ok()
                .flatten()
                .is_some()
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        if path != Path::new("/action/output") {
            return Err(denied("save binding has no writable directory namespace"));
        }
        Ok(())
    }

    fn write(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
        Err(denied(
            "versioned save requires governed dispatch coordinates",
        ))
    }
    fn append(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
        Err(denied("versioned replacement binding cannot append"))
    }
    fn remove(&self, _path: &Path) -> io::Result<()> {
        Err(denied("versioned replacement binding cannot delete"))
    }

    fn write_text_with_context(
        &self,
        path: &Path,
        content: &str,
        context: FileWriteContext<'_>,
    ) -> Result<FileWriteAccepted, FileWriteFailure> {
        if path != Path::new(SAVE_OUTPUT_PATH) || content != self.binding.draft {
            return Err(
                denied("save write differs from its bound target or immutable input").into(),
            );
        }
        if [
            context.instance_id,
            context.effect_id,
            context.run_id,
            context.started_event_id,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
        {
            return Err(denied("save requires complete durable dispatch coordinates").into());
        }
        let cut_id = save_cut_id(context.instance_id, context.effect_id);
        let operation_id = format!("op-{cut_id}");
        let attempt = SaveAttempt::from(context);
        let mut workspace = self.workspace.borrow_mut();
        if workspace.get_cut(&cut_id).map_err(io_error)?.is_some()
            || workspace.get_op(&operation_id).map_err(io_error)?.is_some()
        {
            return Err(io_error(
                "save identity already has target evidence; reconcile before dispatch",
            )
            .into());
        }
        // Validate the retained base before the merge engine can interpret a
        // missing content blob as an absent path. Erasure is not a deletion.
        self.body_at(&workspace, &self.binding.base_cut_id)?;
        workspace.set_actor(Some(self.binding.executing_principal.clone()));
        workspace.set_intent(Some(serde_json::to_string(&attempt).map_err(io_error)?));
        let outcome = workspace
            .save_with_base_recorded(
                &self.binding.branch_id,
                &self.binding.path,
                content,
                &self.binding.base_cut_id,
                &[],
                &cut_id,
                &self.binding.recorded_at,
                Some(&recovery::SaveEvidenceBuilder {
                    binding: &self.binding,
                    attempt: &attempt,
                }),
            )
            .map_err(io_error)?;
        match outcome {
            SaveWithBaseOutcome::Written { .. } | SaveWithBaseOutcome::Merged { .. } => (),
            SaveWithBaseOutcome::Conflicted {
                head_cut_id,
                pieces,
            } => {
                let head_content = head_cut_id
                    .as_deref()
                    .map(|cut| self.body_at(&workspace, cut))
                    .transpose()?
                    .flatten();
                return Err(FileWriteFailure {
                    error: io_error("versioned save conflicts with the observed head"),
                    evidence: Some(self.evidence(
                        attempt,
                        SaveResult::Conflicted {
                            head_cut_id,
                            head_content,
                            pieces,
                        },
                    )?),
                });
            }
            refused => return Err(io_error(refused).into()),
        };
        drop(workspace);
        let recovered = self
            .recover_result(&attempt)?
            .ok_or_else(|| io_error("accepted save cut is unavailable"))?;
        Ok(FileWriteAccepted {
            content: recovered.accepted_content,
            evidence: Some(FileWriteEvidence {
                schema_ref: recovered.reference.schema_ref,
                label_ref: recovered.reference.label_ref,
                content: recovered.receipt_json,
            }),
        })
    }
}

/// Shared storage-binding conformance. Hosts supply real branch/content
/// implementations; these are not authorization tests or a recovery proof.
pub mod conformance {
    use super::*;
    use crate::branches::MAINLINE_BRANCH_ID;
    use crate::vcs::VcsWriteOutcome;

    pub(super) const BASE: &str = "start one two three four five six seven eight nine end\n";
    const HEAD: &str = "HEAD one two three four five six seven eight nine end\n";
    pub(super) const DRAFT: &str = "start one two three four five six seven eight nine DRAFT\n";
    const MERGED: &str = "HEAD one two three four five six seven eight nine DRAFT\n";

    pub(super) fn context() -> FileWriteContext<'static> {
        FileWriteContext {
            instance_id: "action-instance",
            effect_id: "save",
            run_id: "attempt-1",
            started_event_id: "start-1",
        }
    }
    pub(super) fn binding(draft: &str) -> VersionedSaveBinding {
        VersionedSaveBinding {
            branch_id: MAINLINE_BRANCH_ID.into(),
            path: "docs/test.txt".into(),
            base_cut_id: "base".into(),
            draft: draft.into(),
            draft_hash: crate::stable_hash_hex(draft),
            executing_principal: "worker:verified".into(),
            evidence_label: "workspace-private".into(),
            recorded_at: "2026-09-06T00:00:00Z".into(),
        }
    }
    pub(super) fn seed<B: Branches, C: ContentBlobs>(workspace: &mut WorkspaceVcs<B, C>) {
        workspace.init("t0").expect("init");
        assert!(matches!(
            workspace
                .write(
                    MAINLINE_BRANCH_ID,
                    "docs/test.txt",
                    Some(BASE),
                    "base",
                    "t0"
                )
                .expect("seed"),
            VcsWriteOutcome::Written { .. }
        ));
    }
    fn receipt(evidence: FileWriteEvidence) -> SaveReceipt {
        assert_eq!(evidence.schema_ref, SAVE_RECEIPT_SCHEMA);
        assert_eq!(evidence.label_ref, "workspace-private");
        let receipt: SaveReceipt = serde_json::from_str(&evidence.content).expect("typed evidence");
        assert_eq!(receipt.protocol, SAVE_RECEIPT_SCHEMA);
        assert_eq!(receipt.attempt, SaveAttempt::from(context()));
        assert_eq!(receipt.base_cut_id, "base");
        assert_eq!(receipt.path, "docs/test.txt");
        assert_eq!(receipt.executing_principal, "worker:verified");
        receipt
    }

    pub fn check<B: Branches, C: ContentBlobs>(mut make: impl FnMut() -> WorkspaceVcs<B, C>) {
        assert_ne!(save_cut_id("a:b", "c"), save_cut_id("a", "b:c"));
        assert_ne!(save_cut_id("a", "b"), save_cut_id("b", "a"));
        for mode in ["written", "merged", "conflicted"] {
            let mut workspace = make();
            seed(&mut workspace);
            if mode != "written" {
                workspace
                    .write(
                        MAINLINE_BRANCH_ID,
                        "docs/test.txt",
                        Some(HEAD),
                        "head",
                        "t1",
                    )
                    .expect("advance");
            }
            let draft = if mode == "conflicted" {
                "DRAFT one two three four five six seven eight nine end\n"
            } else {
                DRAFT
            };
            let files = VersionedSaveFileStore::new(workspace, binding(draft)).expect("binding");
            assert_eq!(
                files
                    .read_to_string(Path::new(SAVE_INPUT_PATH))
                    .expect("read admitted body"),
                draft
            );
            assert!(files.exists(Path::new(SAVE_INPUT_PATH)));
            assert!(files.exists(Path::new(SAVE_OUTPUT_PATH)));
            assert!(!files.exists(Path::new("/etc/passwd")));
            files
                .create_dir_all(Path::new("/action/output"))
                .expect("virtual parent");
            let result =
                files.write_text_with_context(Path::new(SAVE_OUTPUT_PATH), draft, context());
            let target_id = save_cut_id(context().instance_id, context().effect_id);
            if mode == "conflicted" {
                let failure = result.expect_err("overlapping edits refuse");
                assert!(failure
                    .error
                    .to_string()
                    .contains("conflicts with the observed head"));
                let r = receipt(failure.evidence.expect("structured conflict"));
                let SaveResult::Conflicted {
                    head_cut_id,
                    head_content,
                    pieces,
                } = r.result
                else {
                    panic!("conflict receipt");
                };
                assert_eq!(head_cut_id.as_deref(), Some("head"));
                assert_eq!(head_content.as_deref(), Some(HEAD));
                assert!(pieces
                    .iter()
                    .any(|p| matches!(p, MergePiece::Conflict { .. })));
                let workspace = files.workspace.borrow();
                assert!(workspace.get_cut(&target_id).expect("query").is_none());
                assert!(workspace
                    .get_op(&format!("op-{target_id}"))
                    .expect("query")
                    .is_none());
                assert_eq!(
                    workspace
                        .read(MAINLINE_BRANCH_ID, "docs/test.txt")
                        .expect("head")
                        .as_deref(),
                    Some(HEAD)
                );
            } else {
                let accepted = result.expect("save");
                assert_eq!(
                    accepted.content,
                    if mode == "written" { DRAFT } else { MERGED }
                );
                let r = receipt(accepted.evidence.expect("cut receipt"));
                assert_eq!(r.draft_hash, crate::stable_hash_hex(draft));
                let (cut, parent, op, hash) = match r.result {
                    SaveResult::Written {
                        cut_id,
                        parent_cut_id,
                        operation_id,
                        accepted_content_hash,
                    } => {
                        assert_eq!(mode, "written");
                        (cut_id, parent_cut_id, operation_id, accepted_content_hash)
                    }
                    SaveResult::Merged {
                        cut_id,
                        parent_cut_id,
                        operation_id,
                        accepted_content_hash,
                        pieces,
                    } => {
                        assert_eq!(mode, "merged");
                        assert!(!pieces.is_empty());
                        (cut_id, parent_cut_id, operation_id, accepted_content_hash)
                    }
                    _ => panic!("accepted cut expected"),
                };
                assert_eq!(cut, target_id);
                assert_eq!(
                    parent.as_deref(),
                    Some(if mode == "written" { "base" } else { "head" })
                );
                assert_eq!(op, format!("op-{cut}"));
                assert_eq!(hash, crate::stable_hash_hex(&accepted.content));
                let workspace = files.workspace.borrow();
                let row = workspace.get_cut(&cut).expect("query").expect("cut");
                assert_eq!(row.actor.as_deref(), Some("worker:verified"));
                assert_eq!(
                    serde_json::from_str::<SaveAttempt>(row.intent.as_deref().expect("intent"))
                        .expect("attempt"),
                    r.attempt
                );
                assert!(workspace.get_op(&op).expect("query").is_some());
                drop(workspace);
                let repeated = files.write_text_with_context(
                    Path::new(SAVE_OUTPUT_PATH),
                    draft,
                    FileWriteContext {
                        run_id: "attempt-2",
                        started_event_id: "start-2",
                        ..context()
                    },
                );
                assert!(repeated
                    .expect_err("same effect must not commit twice")
                    .error
                    .to_string()
                    .contains("reconcile before dispatch"));
                assert_eq!(
                    files
                        .workspace
                        .borrow()
                        .list_cuts(MAINLINE_BRANCH_ID, 100)
                        .expect("cuts")
                        .len(),
                    if mode == "written" { 2 } else { 3 }
                );
            }
        }

        for erased in ["base", "head"] {
            let mut workspace = make();
            seed(&mut workspace);
            workspace
                .write(
                    MAINLINE_BRANCH_ID,
                    "docs/test.txt",
                    Some(HEAD),
                    "head",
                    "t1",
                )
                .expect("head");
            let hash = workspace
                .content_store()
                .put(if erased == "base" { BASE } else { HEAD })
                .expect("content id");
            assert!(matches!(
                workspace.content_store().erase(&hash, "t2").expect("erase"),
                crate::content::EraseOutcome::Erased { .. }
            ));
            let files = VersionedSaveFileStore::new(workspace, binding(DRAFT)).expect("binding");
            let failed = files
                .write_text_with_context(Path::new(SAVE_OUTPUT_PATH), DRAFT, context())
                .expect_err("erased content is not deletion");
            assert!(failed
                .error
                .to_string()
                .contains("save evidence content is unavailable or erased"));
            assert!(failed.evidence.is_none());
            assert!(files
                .workspace
                .borrow()
                .get_cut(&save_cut_id(context().instance_id, context().effect_id))
                .expect("query")
                .is_none());
        }
        for missing in ["base", "branch", "inactive"] {
            let mut workspace = make();
            seed(&mut workspace);
            let mut request = binding(DRAFT);
            match missing {
                "base" => request.base_cut_id = "unknown".into(),
                "branch" => request.branch_id = "unknown".into(),
                "inactive" => {
                    workspace
                        .create_branch("closed", None, MAINLINE_BRANCH_ID, "t1")
                        .expect("fork");
                    workspace.discard_branch("closed", "t2").expect("close");
                    request.branch_id = "closed".into();
                }
                _ => unreachable!(),
            }
            let files = VersionedSaveFileStore::new(workspace, request).expect("binding");
            let failure = files
                .write_text_with_context(Path::new(SAVE_OUTPUT_PATH), DRAFT, context())
                .expect_err("unavailable target");
            if missing == "base" {
                assert!(failure
                    .error
                    .to_string()
                    .contains("save evidence cut is unavailable"));
            }
            assert!(files
                .workspace
                .borrow()
                .get_cut(&save_cut_id(context().instance_id, context().effect_id))
                .expect("query")
                .is_none());
        }

        for field in ["branch", "base", "principal", "label", "time", "hash"] {
            let mut request = binding(DRAFT);
            match field {
                "branch" => request.branch_id.clear(),
                "base" => request.base_cut_id.clear(),
                "principal" => request.executing_principal.clear(),
                "label" => request.evidence_label.clear(),
                "time" => request.recorded_at.clear(),
                "hash" => request.draft_hash = "wrong".into(),
                _ => unreachable!(),
            }
            let error = VersionedSaveFileStore::new(make(), request)
                .err()
                .expect("invalid binding");
            assert!(
                error.to_string().contains(if field == "hash" {
                    "immutable input hash"
                } else {
                    "requires exact scope, base, principal, label and time"
                }),
                "{field}: {error}"
            );
        }
        for path in [
            "",
            "/absolute",
            "../escape",
            "a/../b",
            "a/./b",
            "a//b",
            "a/",
            "a\\b",
        ] {
            let mut request = binding(DRAFT);
            request.path = path.into();
            assert!(
                VersionedSaveFileStore::new(make(), request).is_err(),
                "{path}"
            );
        }
        let mut workspace = make();
        seed(&mut workspace);
        let files = VersionedSaveFileStore::new(workspace, binding(DRAFT)).expect("binding");
        assert!(files.read_to_string(Path::new(SAVE_OUTPUT_PATH)).is_err());
        assert!(files.create_dir_all(Path::new("/action/other")).is_err());
        assert!(files
            .write(Path::new(SAVE_OUTPUT_PATH), DRAFT.as_bytes())
            .expect_err("raw write")
            .to_string()
            .contains("requires governed dispatch coordinates"));
        assert!(files
            .write_text(Path::new(SAVE_OUTPUT_PATH), DRAFT)
            .is_err());
        assert!(files
            .append(Path::new(SAVE_OUTPUT_PATH), b"append")
            .expect_err("append")
            .to_string()
            .contains("cannot append"));
        assert!(files
            .remove(Path::new(SAVE_OUTPUT_PATH))
            .expect_err("delete")
            .to_string()
            .contains("cannot delete"));
        assert!(files
            .write_text_with_context(Path::new(SAVE_OUTPUT_PATH), "other body", context())
            .is_err());
        assert!(files
            .write_text_with_context(Path::new("/action/output/other"), DRAFT, context())
            .is_err());
        for field in ["instance", "effect", "run", "event"] {
            let mut bad = context();
            match field {
                "instance" => bad.instance_id = "",
                "effect" => bad.effect_id = "",
                "run" => bad.run_id = "",
                "event" => bad.started_event_id = "",
                _ => unreachable!(),
            }
            assert!(
                files
                    .write_text_with_context(Path::new(SAVE_OUTPUT_PATH), DRAFT, bad)
                    .expect_err("incomplete dispatch")
                    .error
                    .to_string()
                    .contains("requires complete durable dispatch coordinates"),
                "{field}"
            );
        }
        assert_eq!(
            files
                .workspace
                .borrow()
                .list_cuts(MAINLINE_BRANCH_ID, 100)
                .expect("cuts")
                .len(),
            1
        );
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    #[test]
    fn native_versioned_save_binding() {
        super::conformance::check(|| {
            crate::vcs::WorkspaceVcs::from_parts(
                crate::branches::BranchStore::open_in_memory().expect("branches"),
                crate::content::ContentStore::open(":memory:").expect("content"),
            )
        });
    }
}

#[cfg(all(test, feature = "native"))]
mod recovery_tests;
