use super::*;
use whipplescript_store::source_review_types::{
    NativeReviewReadError, NativeReviewReader, NativeRevision,
};

fn query(
    native: &NativeFixture,
    review: Option<&dyn NativeReviewReader>,
) -> Result<SourceAdmissionPlan, String> {
    query_with_home(native, review, None)
}

fn query_with_home(
    native: &NativeFixture,
    review: Option<&dyn NativeReviewReader>,
    home: Option<&dyn ProcessCaptureAuthority>,
) -> Result<SourceAdmissionPlan, String> {
    let runtime = SqliteStore::open_in_memory().expect("read checked source-review fixture");
    let (store, record) = f::fixture(Some(f::template()), true);
    let configuration = configuration(&store, &record);
    let policy = policy();
    let verify = |_: &PythonRuntime| Ok(());
    let before = store
        .export_events()
        .expect("read checked source-review fixture");
    let result = plan_with_capture(
        &native.vcs,
        &store,
        AdmissionHost {
            now: None,
            verifier: &Boundary,
            configuration: &configuration,
            runtime: &runtime,
            policy: &policy,
            verify_runtime: &verify,
        },
        &native.witness,
        "attempt",
        SourceAdmissionCapture { home, review },
    );
    assert_eq!(
        store
            .export_events()
            .expect("read checked source-review fixture"),
        before
    );
    assert!(runtime
        .list_instances()
        .expect("read checked source-review fixture")
        .is_empty());
    assert!(native
        .branches
        .flowing_admission_receipt("attempt")
        .expect("read checked source-review fixture")
        .is_none());
    result
}

#[test]
fn owning_review_capture_verifies_direct_and_transferred_prefix_without_promoting_home_coverage() {
    for mut native in [NativeFixture::new(), NativeFixture::named()] {
        let first = query(&native, Some(&native.reviews)).unwrap();
        assert!(first.judgment().source_verification.is_some());
        assert!(!first
            .judgment()
            .blockers
            .iter()
            .any(|gap| gap.scope == "source/review-record"));
        assert!(first
            .judgment()
            .blockers
            .iter()
            .any(|gap| gap.scope == "home/reference-population"));
        if native.source_branch == "branch" {
            append_handed_tail(&mut native);
        } else {
            native
                .vcs
                .write("twig", "tail.txt", Some("later"), "tail", "t8")
                .unwrap();
        }
        let later = query(&native, Some(&native.reviews)).unwrap();
        assert_eq!(first.identity(), later.identity());
        let missing = query(&native, None).unwrap();
        assert!(missing.judgment().source_verification.is_none());
        assert!(missing
            .judgment()
            .blockers
            .iter()
            .any(|gap| gap.scope == "source/review-record"));
        assert_ne!(missing.identity(), first.identity());
    }
}

/// Failure-only wrapper around the actual owning review store. It introduces
/// unavailable, substituted or late payload states; successful proof still
/// requires real VCS derivation against the real original review authority.
struct ReviewReadFault<'a> {
    original: &'a ReviewStore,
    reads: std::cell::Cell<usize>,
    initial_unavailable: bool,
    changed_availability: bool,
    substitution: Option<&'static str>,
    late_content: Option<rusqlite::Connection>,
}
impl NativeReviewReader for ReviewReadFault<'_> {
    fn capture_native_revision(
        &self,
        contribution: &str,
        sequence: i64,
    ) -> Result<NativeRevision, NativeReviewReadError> {
        let read = self.reads.get() + 1;
        self.reads.set(read);
        let unavailable = self.initial_unavailable ^ (self.changed_availability && read > 1);
        if unavailable {
            return Err(NativeReviewReadError::Unavailable(
                "review authority unavailable".into(),
            ));
        }
        let mut revision = self
            .original
            .capture_native_revision(contribution, sequence)?;
        match self.substitution {
            Some("upload") => revision.upload_id = "another-upload".into(),
            Some("actor") => revision.actor = "another-author".into(),
            Some("intent") => revision.units[0].intent = "another-intent".into(),
            _ => {}
        }
        if read == 2 {
            if let Some(content) = &self.late_content {
                content
                    .execute("DELETE FROM content_blobs", [])
                    .expect("inject late payload loss");
            }
        }
        Ok(revision)
    }
}
fn fault(native: &NativeFixture) -> ReviewReadFault<'_> {
    ReviewReadFault {
        original: &native.reviews,
        reads: std::cell::Cell::new(0),
        initial_unavailable: false,
        changed_availability: false,
        substitution: None,
        late_content: None,
    }
}

#[test]
fn invalid_original_source_is_refused_before_any_home_capture_callback() {
    use crate::source_process::*;

    // This probe can only report a gap. Successful source proof still comes
    // from the real owning review store and VCS fixture.
    struct HomeReadProbe(std::cell::Cell<usize>);
    impl ProcessCaptureAuthority for HomeReadProbe {
        fn basis(&self, _: &str) -> Result<ProcessBasis, String> {
            self.0.set(self.0.get() + 1);
            Err("Home capture probe has no admitted population".into())
        }
        fn verify_process_basis(
            &self,
            _: &ProcessBasis,
            _: &EvidenceVersion,
        ) -> Result<(), String> {
            unreachable!("the probe never supplies a basis")
        }
        fn observe(
            &self,
            _: &ProcessBasis,
            _: CutSide,
            _: &ReferenceScope,
        ) -> Result<ScopeObservation, String> {
            unreachable!("the probe never supplies a basis")
        }
        fn verify_boundary(
            &self,
            _: &ProcessBasis,
            _: CutSide,
            _: &ReferenceScope,
            _: &ScopeObservation,
        ) -> Result<VerifiedScopeBoundary, String> {
            unreachable!("the probe never supplies a basis")
        }
        fn verify_norm_basis(
            &self,
            _: &ProcessBasis,
            _: &whipplescript_store::norm_history::NormReadAnchor,
            _: &EvidenceVersion,
        ) -> Result<(), String> {
            unreachable!("the probe never supplies a basis")
        }
        fn owner_validation(
            &self,
            _: &ProcessBasis,
            _: CutSide,
            _: &ReferenceScope,
            _: &DependencyIdentity,
        ) -> Result<Option<OwnerValidation>, String> {
            unreachable!("the probe never supplies a basis")
        }
    }
    let native = NativeFixture::new();
    let probe = HomeReadProbe(std::cell::Cell::new(0));
    let valid = query_with_home(&native, Some(&native.reviews), Some(&probe)).unwrap();
    assert!(valid.judgment().source_verification.is_some());
    assert_eq!(probe.0.get(), 1, "the valid candidate reaches Home capture");
    probe.0.set(0);
    let mut substituted = fault(&native);
    substituted.substitution = Some("upload");
    assert!(query_with_home(&native, Some(&substituted), Some(&probe)).is_err());
    assert_eq!(
        probe.0.get(),
        0,
        "source proof precedes every Home callback"
    );
}

#[test]
fn unavailable_original_review_is_a_gap_and_availability_changes_refuse_the_query() {
    let native = NativeFixture::new();
    let mut reader = fault(&native);
    reader.initial_unavailable = true;
    let gap = query(&native, Some(&reader)).unwrap();
    assert!(gap.judgment().source_verification.is_none());
    assert!(gap
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope == "source/review-record" && gap.reason.contains("unavailable")));
    for initial in [false, true] {
        reader.reads.set(0);
        reader.initial_unavailable = initial;
        reader.changed_availability = true;
        assert!(query(&native, Some(&reader))
            .unwrap_err()
            .contains("source review record changed"));
    }
}

#[test]
fn substituted_original_review_cannot_bypass_owning_vcs_verification() {
    for native in [NativeFixture::new(), NativeFixture::named()] {
        for substitution in ["upload", "actor", "intent"] {
            let mut reader = fault(&native);
            reader.substitution = Some(substitution);
            assert!(query(&native, Some(&reader)).is_err(), "{substitution}");
        }
    }
}

#[test]
fn invalid_review_target_refuses_instead_of_becoming_an_unavailable_gap() {
    let native = NativeFixture::new();
    let writer = rusqlite::Connection::open(native.root.join("review.db")).unwrap();
    writer
        .execute(
            "UPDATE contributions SET target_ref = 'foreign' WHERE id = 'review'",
            [],
        )
        .unwrap();
    assert!(query(&native, Some(&native.reviews))
        .unwrap_err()
        .contains("exact trunk contribution"));
}

#[test]
fn final_source_verification_refuses_payload_loss_after_the_norm_and_review_reads() {
    for native in [NativeFixture::new(), NativeFixture::named()] {
        let mut reader = fault(&native);
        reader.late_content =
            Some(rusqlite::Connection::open(native.root.join("content.db")).unwrap());
        assert!(query(&native, Some(&reader)).is_err());
        assert_eq!(reader.reads.get(), 2);
    }
}

fn append_handed_tail(native: &mut NativeFixture) {
    let vcs = &mut native.vcs;
    let branches = &mut native.branches;
    vcs.create_branch("tail-twig", None, "branch", "t7")
        .expect("construct accounted source tail");
    branches
        .open_flowing_source(&OpenFlowingSource {
            source_branch_id: "tail-twig".into(),
            incarnation_id: "tail-inc".into(),
            kind: FlowingSourceKind::Twig,
            owner: "coordinator".into(),
            opened_at: "t7".into(),
        })
        .expect("construct accounted source tail");
    vcs.write("tail-twig", "tail.txt", Some("later"), "tail-source", "t8")
        .expect("construct accounted source tail");
    let tail = branches
        .get_cut("tail-source")
        .expect("construct accounted source tail")
        .expect("construct accounted source tail");
    branches
        .pin_private_cut(PinPrivateCut {
            pin_id: "tail-pin",
            twig_branch_id: "tail-twig",
            cut_id: "tail-source",
            manifest_hash: &tail.manifest_hash,
            principal: "author",
            retained_at: "t9",
        })
        .expect("construct accounted source tail");
    let prior = branches
        .get_cut("target")
        .expect("construct accounted source tail")
        .expect("construct accounted source tail");
    let basis = branches
        .contribution_basis("unit")
        .expect("construct accounted source tail")
        .expect("construct accounted source tail");
    branches
        .declare_contribution(DeclareContribution {
            unit_id: "tail-unit",
            pin_id: "tail-pin",
            principal: "author",
            intent: "later",
            read_basis_digest: &native_read_basis_digest(
                Some("target"),
                Some(&prior.manifest_hash),
            ),
            dependency_basis_digest: &native_dependency_basis_digest(&[(
                "unit".into(),
                basis.basis_digest,
            )]),
            scope_digest: "tail-scope",
            declared_at: "t9",
        })
        .expect("construct accounted source tail");
    let FlowingSelectionOutcome::Selected(selection) = vcs
        .select_private_changes(
            "tail-pin",
            &whipplescript_store::selection::parse("path(tail.txt)")
                .expect("construct accounted source tail"),
        )
        .expect("construct accounted source tail")
    else {
        panic!("real tail selection")
    };
    vcs.bind_private_selection("tail-unit", &selection, "t10")
        .expect("construct accounted source tail");
    let whipplescript_store::vcs::FlowingTargetEffectsOutcome::Verified(target) = vcs
        .prepare_private_handoff_target("tail-unit", "tail-target", "coordinator", "t11")
        .expect("construct accounted source tail")
    else {
        panic!("real tail target")
    };
    assert!(matches!(
        vcs.handoff_private_selection("tail-handoff", &target, "coordinator", "t12")
            .expect("construct accounted source tail"),
        whipplescript_store::branches::flowing_sources::HandoffContributionOutcome::Transferred(_)
    ));
}
