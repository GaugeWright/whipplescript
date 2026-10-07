//! Target disposition of an unscoped versioned save, and the adapter/target
//! conformance that qualifies this adapter's declared recovery ceiling.
//!
//! `spec/host-actions.md` (External disposition) allows a ceiling stronger
//! than `unverifiable` only with conformance evidence for the actual adapter
//! and target. This module is that evidence for one adapter: the confined
//! versioned save over a workspace's branch and content stores, native and
//! hosted. It qualifies `reconcilable` and nothing more.
//!
//! Two target properties carry the claim, and the harness below proves each
//! with a negative control on whatever backend it is handed:
//!
//! - The target cut is a stable key. `save_cut_id` depends only on the
//!   instance and effect, never on the attempt, and the branch authority
//!   inserts that cut and its operation in one transaction that refuses a
//!   duplicate. At most one attempt of an effect can ever commit, even when a
//!   presumed-dead writer races a resubmission past the adapter's preflight.
//! - The cut, its operation and its retained receipt are queryable by that
//!   key. Their joint absence is therefore proof that no attempt of the
//!   effect has applied as of the read, and the stable key makes any later
//!   commit exclusive with a resubmission rather than additional to it.
//!   Their presence, bound to the exact attempt and immutable binding, is
//!   proof of application. Anything else refuses: a cut held by another
//!   attempt, a partial link, an erased receipt or a changed binding.
//!
//! Absence is a fact about the moment of the read. A late commit by the
//! original attempt after absence was recorded is contradictory evidence, and
//! the effect fold keeps both and refuses further resubmission.
//!
//! Reading this disposition authorizes nothing. The host must already have
//! authenticated current reconciliation authority and evidence access, as for
//! `read_committed_save`; this module answers only what the target holds.
use super::*;
use crate::effect_recovery::RecoveryCeiling;
use crate::effect_recovery::{DispatchFrame, DispositionEvidence, EvidenceDisposition};

/// The ceiling this adapter declares once the harness below has passed on the
/// backend in question. Scoped saves are not covered and stay `unverifiable`.
pub const VERSIONED_SAVE_RECOVERY_CEILING: RecoveryCeiling = RecoveryCeiling::Reconcilable;

pub const SAVE_ABSENCE_PROOF_SCHEMA: &str = "whipplescript.vcs-save-absence.v1";

/// What the target holds under the effect's stable save identity.
#[derive(Debug)]
pub enum SaveDisposition {
    /// No cut, operation or result reference exists under the stable key.
    NotApplied { cut_id: String },
    /// The exact attempt committed this result under the immutable binding.
    Applied(Box<RecoveredSave>),
}

impl SaveDisposition {
    /// The transient target proof whose SHA-256 a reconciliation command
    /// binds: the retained receipt bytes, or a canonical absence statement.
    pub fn proof(&self) -> String {
        match self {
            Self::Applied(recovered) => recovered.receipt_json.clone(),
            Self::NotApplied { cut_id } => {
                serde_json::json!([SAVE_ABSENCE_PROOF_SCHEMA, cut_id, format!("op-{cut_id}")])
                    .to_string()
            }
        }
    }

    /// Evidence bound to the exact recorded dispatch. The caller supplies the
    /// frame it read from the log; the observation supplies the disposition.
    pub fn evidence(&self, frame: DispatchFrame, authority_ref: &str) -> DispositionEvidence {
        let (disposition, evidence_ref) = match self {
            Self::Applied(recovered) => (
                EvidenceDisposition::Applied,
                recovered.reference.label_ref.clone(),
            ),
            Self::NotApplied { .. } => (
                EvidenceDisposition::NotApplied,
                SAVE_ABSENCE_PROOF_SCHEMA.to_owned(),
            ),
        };
        DispositionEvidence {
            frame,
            disposition,
            evidence_ref,
            evidence_digest: crate::items::sha256_hex(&self.proof()),
            authority_ref: authority_ref.into(),
        }
    }
}

/// Query the target for an attempt's disposition. Never writes.
pub fn observe_save_disposition<B: Branches, C: ContentBlobs>(
    workspace: &WorkspaceVcs<B, C>,
    binding: &SaveResultBinding,
    attempt: &SaveAttempt,
) -> io::Result<SaveDisposition> {
    let cut_id = save_cut_id(&attempt.instance_id, &attempt.effect_id);
    if let Some(recovered) = read_committed_save(workspace, binding, attempt)? {
        return Ok(SaveDisposition::Applied(Box::new(recovered)));
    }
    // `read_committed_save` already refuses a result reference without its
    // cut. An operation without its cut is the same broken link.
    if workspace
        .get_op(&format!("op-{cut_id}"))
        .map_err(io_error)?
        .is_some()
    {
        return Err(io_error("save operation exists without its committed cut"));
    }
    Ok(SaveDisposition::NotApplied { cut_id })
}

impl<B: Branches, C: ContentBlobs> VersionedSaveFileStore<B, C> {
    /// The declared ceiling of this realization. A scoped save has a separate
    /// reader this harness does not exercise, so it declares nothing stronger.
    pub fn declared_recovery_ceiling(&self) -> RecoveryCeiling {
        if self.scoped.is_some() {
            RecoveryCeiling::Unverifiable
        } else {
            VERSIONED_SAVE_RECOVERY_CEILING
        }
    }

    pub fn observe_disposition(&self, attempt: &SaveAttempt) -> io::Result<SaveDisposition> {
        if self.scoped.is_some() {
            return Err(denied("scoped saves require scoped recovery"));
        }
        observe_save_disposition(
            &self.workspace.borrow(),
            &SaveResultBinding::from(&self.binding),
            attempt,
        )
    }
}

/// The adapter/target conformance that `VERSIONED_SAVE_RECOVERY_CEILING`
/// rests on. Every backend that hosts this adapter runs it.
pub mod conformance {
    use super::super::conformance::{binding, context, seed, DRAFT};
    use super::*;
    use crate::branches::MAINLINE_BRANCH_ID;
    use crate::effect_recovery::{
        fold_attempts, require_proved_absence, unverified_dispatch_marker, ExternalDisposition,
    };
    use crate::{EventView, RunStart};
    use serde_json::json;

    fn attempt(run_id: &'static str) -> FileWriteContext<'static> {
        FileWriteContext {
            run_id,
            started_event_id: if run_id == "attempt-1" {
                "start-1"
            } else {
                "start-2"
            },
            ..context()
        }
    }

    fn head<B: Branches, C: ContentBlobs>(workspace: &WorkspaceVcs<B, C>) -> Option<String> {
        workspace
            .get_branch(MAINLINE_BRANCH_ID)
            .expect("branch")
            .expect("mainline")
            .head_cut_id
    }

    fn save<B: Branches, C: ContentBlobs>(
        workspace: WorkspaceVcs<B, C>,
        context: FileWriteContext<'_>,
    ) -> (
        Result<FileWriteAccepted, FileWriteFailure>,
        WorkspaceVcs<B, C>,
    ) {
        let files = VersionedSaveFileStore::new(workspace, binding(DRAFT)).expect("binding");
        assert_eq!(
            files.declared_recovery_ceiling(),
            RecoveryCeiling::Reconcilable
        );
        let outcome = files.write_text_with_context(Path::new(SAVE_OUTPUT_PATH), DRAFT, context);
        (outcome, files.workspace.into_inner())
    }

    fn observe<B: Branches, C: ContentBlobs>(
        workspace: &WorkspaceVcs<B, C>,
        context: FileWriteContext<'_>,
    ) -> io::Result<SaveDisposition> {
        observe_save_disposition(
            workspace,
            &SaveResultBinding::from(&binding(DRAFT)),
            &SaveAttempt::from(context),
        )
    }

    fn frame(context: FileWriteContext<'_>) -> DispatchFrame {
        unverified_dispatch_marker(
            RunStart {
                instance_id: context.instance_id,
                effect_id: context.effect_id,
                run_id: context.run_id,
                provider: "versioned-save",
                worker_id: "worker",
                lease_id: "lease",
                lease_expires_at: "later",
                metadata_json: "{}",
            },
            "file.write",
            Some(MAINLINE_BRANCH_ID),
            r#"{"path":"docs/test.txt"}"#,
            context.effect_id,
            "execution",
        )
        .expect("frame")
        .frame
    }

    fn event(kind: &str, payload: serde_json::Value) -> EventView {
        EventView {
            event_id: "event".into(),
            sequence: 1,
            event_type: kind.into(),
            payload_json: payload.to_string(),
            source: "kernel".into(),
            occurred_at: "recorded".into(),
        }
    }

    pub fn check<B: Branches, C: ContentBlobs>(mut make: impl FnMut() -> WorkspaceVcs<B, C>) {
        absence_is_proved_only_while_nothing_holds_the_key(make());
        application_is_proved_only_for_the_exact_attempt_and_binding(make());
        the_target_key_admits_one_attempt_even_past_the_preflight(make());
        a_late_commit_after_proved_absence_is_retained_as_a_contradiction(make());
    }

    fn absence_is_proved_only_while_nothing_holds_the_key<B: Branches, C: ContentBlobs>(
        mut workspace: WorkspaceVcs<B, C>,
    ) {
        seed(&mut workspace);
        let before = head(&workspace);
        let absent = observe(&workspace, attempt("attempt-1")).expect("query an untouched target");
        let SaveDisposition::NotApplied { cut_id } = &absent else {
            panic!("an untouched target holds no save: {absent:?}");
        };
        assert_eq!(cut_id, &save_cut_id("action-instance", "save"));
        assert_eq!(head(&workspace), before, "the query writes nothing");
        // Absence is per effect, not per attempt: every attempt reads the key.
        assert!(matches!(
            observe(&workspace, attempt("attempt-2")).expect("query"),
            SaveDisposition::NotApplied { .. }
        ));
        // Negative control: once any attempt holds the key, no attempt of
        // this effect can be told it is absent.
        let (saved, workspace) = save(workspace, attempt("attempt-1"));
        saved.expect("the first attempt commits");
        assert!(matches!(
            observe(&workspace, attempt("attempt-1")).expect("query"),
            SaveDisposition::Applied(_)
        ));
        assert!(
            observe(&workspace, attempt("attempt-2")).is_err(),
            "a key held by another attempt is neither absence nor this attempt's proof"
        );
    }

    fn application_is_proved_only_for_the_exact_attempt_and_binding<
        B: Branches,
        C: ContentBlobs,
    >(
        mut workspace: WorkspaceVcs<B, C>,
    ) {
        seed(&mut workspace);
        let (saved, workspace) = save(workspace, attempt("attempt-1"));
        let accepted = saved.expect("save");
        let receipt = accepted.evidence.expect("save receipt").content;
        let observed = observe(&workspace, attempt("attempt-1")).expect("query");
        let SaveDisposition::Applied(recovered) = &observed else {
            panic!("a committed save is applied: {observed:?}");
        };
        assert_eq!(
            recovered.receipt_json, receipt,
            "the original receipt bytes"
        );
        assert_eq!(recovered.accepted_content, accepted.content);
        let frame = frame(attempt("attempt-1"));
        let evidence = observed.evidence(frame.clone(), "target-authority");
        assert_eq!(evidence.frame, frame);
        assert_eq!(evidence.disposition, EvidenceDisposition::Applied);
        assert_eq!(evidence.evidence_digest, crate::items::sha256_hex(&receipt));
        assert_eq!(evidence.evidence_ref, "workspace-private");
        // Negative controls: every immutable coordinate of the binding and
        // the attempt is load-bearing.
        let exact = SaveResultBinding::from(&binding(DRAFT));
        let changed = [
            SaveResultBinding {
                draft_hash: crate::stable_hash_hex("another draft"),
                ..exact.clone()
            },
            SaveResultBinding {
                base_cut_id: "another-base".into(),
                ..exact.clone()
            },
            SaveResultBinding {
                path: "docs/other.txt".into(),
                ..exact.clone()
            },
            SaveResultBinding {
                executing_principal: "worker:other".into(),
                ..exact.clone()
            },
            SaveResultBinding {
                evidence_label: "another-label".into(),
                ..exact.clone()
            },
        ];
        for binding in changed {
            assert!(
                observe_save_disposition(
                    &workspace,
                    &binding,
                    &SaveAttempt::from(attempt("attempt-1"))
                )
                .is_err(),
                "{binding:?}"
            );
        }
        let mut moved = SaveAttempt::from(attempt("attempt-1"));
        moved.started_event_id = "another-start".into();
        assert!(observe_save_disposition(&workspace, &exact, &moved).is_err());
    }

    fn the_target_key_admits_one_attempt_even_past_the_preflight<B: Branches, C: ContentBlobs>(
        mut workspace: WorkspaceVcs<B, C>,
    ) {
        seed(&mut workspace);
        let (saved, workspace) = save(workspace, attempt("attempt-1"));
        saved.expect("first attempt");
        let held = head(&workspace);
        // The adapter's own preflight refuses a second attempt.
        let (second, mut workspace) = save(workspace, attempt("attempt-2"));
        assert!(second.is_err());
        assert_eq!(head(&workspace), held);
        // Negative control for the race the preflight cannot see: a writer
        // that read absence before the first commit reaches the target with
        // the same stable key. The target itself must refuse it.
        let cut_id = save_cut_id("action-instance", "save");
        // The racing body merges cleanly with the committed head, so nothing
        // short of the key itself stands between it and a second commit.
        let raced = workspace.save_with_base_recorded(
            MAINLINE_BRANCH_ID,
            "docs/test.txt",
            "RACE one two three four five six seven eight nine end\n",
            "base",
            &[],
            &cut_id,
            "2026-09-06T00:00:01Z",
            None,
        );
        assert!(
            raced.is_err(),
            "a duplicate stable key must not commit: {raced:?}"
        );
        assert_eq!(head(&workspace), held, "the refused race moved nothing");
        let control = workspace
            .save_with_base_recorded(
                MAINLINE_BRANCH_ID,
                "docs/test.txt",
                "RACE one two three four five six seven eight nine end\n",
                "base",
                &[],
                "another-key",
                "2026-09-06T00:00:01Z",
                None,
            )
            .expect("the same race under a fresh key");
        assert!(
            matches!(control, crate::vcs::SaveWithBaseOutcome::Merged { .. }),
            "the race reaches the commit, so only the key refused it: {control:?}"
        );
        assert!(matches!(
            observe(&workspace, attempt("attempt-1")).expect("query"),
            SaveDisposition::Applied(_)
        ));
    }

    fn a_late_commit_after_proved_absence_is_retained_as_a_contradiction<
        B: Branches,
        C: ContentBlobs,
    >(
        mut workspace: WorkspaceVcs<B, C>,
    ) {
        seed(&mut workspace);
        let original = frame(attempt("attempt-1"));
        let started = event(
            "effect.run_started",
            json!({
                "effect_id": "save",
                "run_id": "attempt-1",
                "external_dispatch": crate::effect_recovery::DispatchMarker {
                    frame: original.clone(),
                    ceiling: RecoveryCeiling::Unverifiable,
                },
            }),
        );
        let absence = observe(&workspace, attempt("attempt-1"))
            .expect("query")
            .evidence(original.clone(), "target-authority");
        assert_eq!(absence.disposition, EvidenceDisposition::NotApplied);
        let recorded = |evidence: &DispositionEvidence| {
            event(
                "effect.disposition.recorded",
                serde_json::to_value(evidence).expect("evidence"),
            )
        };
        let mut events = vec![started, recorded(&absence)];
        let attempts = fold_attempts("action-instance", "save", &events).expect("fold");
        assert_eq!(attempts[0].disposition, ExternalDisposition::NotApplied);
        require_proved_absence(&attempts).expect("proved absence permits a new attempt");
        // The presumed-dead writer commits after all.
        let (late, workspace) = save(workspace, attempt("attempt-1"));
        late.expect("the original attempt lands late");
        let applied = observe(&workspace, attempt("attempt-1"))
            .expect("query")
            .evidence(original, "target-authority");
        assert_eq!(applied.disposition, EvidenceDisposition::Applied);
        assert_ne!(applied.evidence_digest, absence.evidence_digest);
        events.push(recorded(&applied));
        let attempts = fold_attempts("action-instance", "save", &events).expect("fold");
        assert!(attempts[0].disputed, "contradiction is recorded");
        assert_eq!(
            attempts[0].disposition,
            ExternalDisposition::NotApplied,
            "the settled fact is not overwritten"
        );
        assert_eq!(attempts[0].evidence, vec![absence, applied]);
        assert!(
            require_proved_absence(&attempts).is_err(),
            "contradiction stops resubmission"
        );
        // And the resubmission the absence allowed cannot apply a second time.
        let (resubmitted, workspace) = save(workspace, attempt("attempt-2"));
        assert!(resubmitted.is_err());
        assert!(observe(&workspace, attempt("attempt-2")).is_err());
    }
}
