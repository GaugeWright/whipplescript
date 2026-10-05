use super::*;
use crate::norm_execution::fixtures::{self as f, Boundary};
use crate::norm_execution_policy::ProtectedPythonPolicy;
use crate::norm_planning::PlanningConfiguration;
use crate::norm_runner::{PythonEngine, PythonRuntime};
use whipplescript_store::branches::flowing_admission::RetainFlowingAttemptOutcome;
use whipplescript_store::branches::flowing_fence::{
    FlowingFence, FlowingSourceKind, OpenFlowingSource,
};
use whipplescript_store::branches::flowing_sources::{
    DeclareContribution, FlowingSources, PinPrivateCut,
};
use whipplescript_store::branches::{BranchStore, Branches, MAINLINE_BRANCH_ID};
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::source_review::ReviewStore;
use whipplescript_store::source_review_native::{NativeCandidateRequest, NativeUpload};
use whipplescript_store::vcs::{
    native_dependency_basis_digest, native_read_basis_digest, FlowingSelectionOutcome,
    NativeCandidateOutcome,
};
use whipplescript_store::SqliteStore;

#[path = "source_validation_tests.rs"]
mod validation;

struct NativeFixture {
    root: std::path::PathBuf,
    vcs: NativeWorkspaceVcs,
    branches: BranchStore,
    reviews: ReviewStore,
    witness: String,
    source_branch: &'static str,
    source_cut: &'static str,
}
impl Drop for NativeFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
impl NativeFixture {
    fn new() -> Self {
        Self::with_path("main.py")
    }
    fn with_path(path: &str) -> Self {
        Self::with_change(path, false)
    }
    fn named() -> Self {
        Self::with_source("main.py", false, true)
    }
    fn with_change(path: &str, deleted: bool) -> Self {
        Self::with_source(path, deleted, false)
    }
    fn with_source(path: &str, deleted: bool, named: bool) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "whip-source-plan-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("fixture clock follows Unix epoch")
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).expect("create native source fixture directory");
        let mut vcs = NativeWorkspaceVcs::open(root.join("branches.db"), root.join("content.db"))
            .expect("open fixture native stores");
        vcs.init("t0").expect("initialize fixture mainline");
        if deleted {
            vcs.write(
                MAINLINE_BRANCH_ID,
                path,
                Some("def allow(value): return False\n"),
                "base",
                "t0",
            )
            .expect("write deleted subject base");
        }
        if named {
            vcs.create_branch("branch", Some("feature"), MAINLINE_BRANCH_ID, "t1")
                .expect("construct checked named-source fixture");
            BranchStore::open(root.join("branches.db"))
                .expect("construct checked named-source fixture")
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "branch".into(),
                    incarnation_id: "branch-inc".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "coordinator".into(),
                    opened_at: "t1".into(),
                })
                .expect("construct checked named-source fixture");
        }
        vcs.create_branch(
            "twig",
            None,
            if named { "branch" } else { MAINLINE_BRANCH_ID },
            "t1",
        )
        .expect("create fixture twig");
        let mut branches =
            BranchStore::open(root.join("branches.db")).expect("open fixture branch store");
        let base = branches
            .get_branch(MAINLINE_BRANCH_ID)
            .expect("read fixture mainline")
            .expect("fixture mainline exists");
        branches
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "twig".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Twig,
                owner: "coordinator".into(),
                opened_at: "t1".into(),
            })
            .expect("open fixture source incarnation");
        vcs.write(
            "twig",
            path,
            if deleted {
                None
            } else {
                Some("def allow(value):\n    return False\n")
            },
            "source",
            "t2",
        )
        .expect("write fixture source cut");
        let cut = branches
            .get_cut("source")
            .expect("read fixture source cut")
            .expect("fixture source cut exists");
        branches
            .pin_private_cut(PinPrivateCut {
                pin_id: "pin",
                twig_branch_id: "twig",
                cut_id: "source",
                manifest_hash: &cut.manifest_hash,
                principal: "author",
                retained_at: "t3",
            })
            .expect("pin fixture private cut");
        branches
            .declare_contribution(DeclareContribution {
                unit_id: "unit",
                pin_id: "pin",
                principal: "author",
                intent: "change",
                read_basis_digest: &native_read_basis_digest(
                    base.head_cut_id.as_deref(),
                    base.head_manifest_hash.as_deref(),
                ),
                dependency_basis_digest: &native_dependency_basis_digest(&[]),
                scope_digest: "scope",
                declared_at: "t3",
            })
            .expect("declare fixture contribution");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                "pin",
                &whipplescript_store::selection::parse(&format!("path({path})"))
                    .expect("parse fixture path selection"),
            )
            .expect("select fixture private changes")
        else {
            panic!("valid source selection")
        };
        vcs.bind_private_selection("unit", &selection, "t3")
            .expect("bind fixture selection");
        if named {
            let whipplescript_store::vcs::FlowingTargetEffectsOutcome::Verified(target) = vcs
                .prepare_private_handoff_target("unit", "target", "coordinator", "t4")
                .expect("construct checked named-source fixture")
            else {
                panic!("real content-verified target")
            };
            assert!(matches!(vcs.handoff_private_selection("handoff", &target, "coordinator", "t4").expect("construct checked named-source fixture"),
                whipplescript_store::branches::flowing_sources::HandoffContributionOutcome::Transferred(_)));
            let released = branches
                .release_private_cut(
                    whipplescript_store::branches::flowing_sources::ReleasePrivateCut {
                        pin_id: "pin",
                        released_by: "author",
                        reason: "transferred",
                        released_at: "t4",
                    },
                )
                .expect("construct checked named-source fixture");
            assert_eq!(
                released,
                whipplescript_store::branches::flowing_sources::ReleasePrivateCutOutcome::Released
            );
        }
        let mut fixture = Self {
            root,
            vcs,
            branches,
            reviews: ReviewStore::open(":memory:").expect("open fixture review store"),
            witness: String::new(),
            source_branch: if named { "branch" } else { "twig" },
            source_cut: if named { "target" } else { "source" },
        };
        fixture.witness = fixture.review("review", "candidate", "attempt");
        fixture
    }
    fn review(&mut self, review: &str, candidate: &str, attempt: &str) -> String {
        let actor = if self.source_branch == "branch" {
            "coordinator"
        } else {
            "author"
        };
        self.reviews
            .create_native_contribution(review, actor, "change", MAINLINE_BRANCH_ID, &[])
            .expect("create fixture review contribution");
        let upload = NativeUpload {
            contribution_id: review,
            upload_id: review,
            actor,
            source_branch_id: self.source_branch,
            source_cut_id: self.source_cut,
            unit_ids: &["unit"],
        };
        if self.source_branch == "branch" {
            self.reviews.upload_named_branch_revision(&self.vcs, upload)
        } else {
            self.reviews.upload_native_revision(&self.branches, upload)
        }
        .expect("upload fixture review revision");
        let base = self
            .vcs
            .get_branch(MAINLINE_BRANCH_ID)
            .expect("read candidate mainline")
            .expect("candidate mainline exists");
        let NativeCandidateOutcome::Prepared(prepared) = self
            .reviews
            .prepare_native_candidate(
                &mut self.vcs,
                NativeCandidateRequest {
                    contribution_id: review,
                    sequence: 1,
                    expected_trunk_cut_id: base.head_cut_id.as_deref(),
                    candidate_cut_id: candidate,
                    actor: "coordinator",
                    recorded_at: "t4",
                },
            )
            .expect("prepare fixture candidate")
        else {
            panic!("valid candidate")
        };
        assert!(matches!(
            self.vcs
                .retain_review_attempt(attempt, &prepared.candidate_witness_digest, "t4")
                .expect("retain fixture review attempt"),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        prepared.candidate_witness_digest
    }
}

fn configuration(store: &WorkItemStore, record: &str) -> PlanningConfiguration {
    let vocabulary = store
        .norm_view(&Boundary)
        .expect("read fixture norm vocabulary")
        .records[record]
        .vocabulary
        .clone();
    PlanningConfiguration::parse(&serde_json::json!({
        "capability": "observer", "roles": [{"vocabulary": vocabulary, "interpretation": "context"}]
    }).to_string()).expect("parse fixture planning configuration")
}
fn policy() -> ProtectedPythonPolicy {
    let mut runtime = f::method().runtime;
    runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/opt/reactor.wasm".into(),
        artifact_sha256: "a".repeat(64),
    };
    runtime.executable = "/usr/local/bin/whip".into();
    ProtectedPythonPolicy::new(
        &serde_json::to_string(&runtime).expect("serialize fixture runtime"),
        "t9",
    )
    .expect("construct protected fixture policy")
}

#[test]
fn native_derivation_is_read_only_and_does_not_promote_local_coverage() {
    let mut native = NativeFixture::new();
    let runtime = SqliteStore::open_in_memory().unwrap();
    let (mut store, record) = f::fixture(Some(f::template()), true);
    let configuration = configuration(&store, &record);
    let policy = policy();
    let verify = |_: &PythonRuntime| Ok(());
    let host = AdmissionHost {
        now: None,
        verifier: &Boundary,
        configuration: &configuration,
        runtime: &runtime,
        policy: &policy,
        verify_runtime: &verify,
    };
    let before = store.export_events().unwrap();
    let first = plan_native(&native.vcs, &store, host, &native.witness, "attempt").unwrap();
    assert!(first
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope == "home/process-installation"));
    native
        .vcs
        .write("twig", "later.txt", Some("tail"), "tail", "t5")
        .unwrap();
    let second = plan_native(&native.vcs, &store, host, &native.witness, "attempt").unwrap();
    assert_eq!(first.identity(), second.identity());
    assert_eq!(store.export_events().unwrap(), before);
    assert!(runtime.list_instances().unwrap().is_empty());
    let judgment = first.judgment();
    assert_eq!(judgment.subject.lineage_fences.len(), 1);
    assert_eq!(judgment.subject.unit_holders.len(), 1);
    assert_eq!(judgment.subject.unit_holders[0].unit_id, "unit");

    assert!(judgment
        .blockers
        .iter()
        .any(|gap| gap.scope == "home/reference-population"));
    assert!(judgment
        .obligations
        .values()
        .any(|obligation| obligation.record == record));
    assert!(judgment
        .obligations
        .values()
        .all(|obligation| !obligation.applicability.is_empty()));
    assert!(judgment.norm["method_gaps"].get(&record).is_some());
    // Real work in the same store closes without becoming norm evidence.
    let item = store
        .file_item(
            "checks",
            "check done",
            "",
            &[],
            &serde_json::json!({}),
            None,
            None,
        )
        .unwrap();
    store.finish_item(&item.id, Some("passed"), None).unwrap();
    let third = plan_native(&native.vcs, &store, host, &native.witness, "attempt").unwrap();
    assert_eq!(third.identity(), first.identity());
    assert!(third.judgment().norm["method_gaps"].get(&record).is_some());
}

#[test]
fn source_plan_binds_the_named_holder_after_transfer_and_pin_release() {
    use whipplescript_store::branches::flowing_fence::{
        FlowingFenceAction, FlowingFenceTransition,
    };
    let mut native = NativeFixture::named();
    let runtime = SqliteStore::open_in_memory().unwrap();
    let (store, record) = f::fixture(Some(f::template()), true);
    let configuration = configuration(&store, &record);
    let policy = policy();
    let verify = |_: &PythonRuntime| Ok(());
    let host = AdmissionHost {
        now: None,
        verifier: &Boundary,
        configuration: &configuration,
        runtime: &runtime,
        policy: &policy,
        verify_runtime: &verify,
    };
    let first = plan_native(&native.vcs, &store, host, &native.witness, "attempt").unwrap();
    assert_eq!(first.judgment().subject.lineage_fences.len(), 1);
    assert_eq!(
        first.judgment().subject.lineage_fences[0].source_branch_id,
        "branch"
    );
    assert_eq!(first.judgment().subject.unit_holders.len(), 1);
    assert_eq!(
        first.judgment().subject.unit_holders[0].holder_branch_id,
        "branch"
    );
    assert_eq!(
        first.judgment().subject.unit_holders[0]
            .handoff_op_id
            .as_deref(),
        Some("handoff")
    );
    // The original twig is provenance after transfer; its Hold does not hold the receiving branch.
    let transition = |source: &str, incarnation: &str, op: &str| FlowingFenceTransition {
        op_id: op.into(),
        source_branch_id: source.into(),
        incarnation_id: incarnation.into(),
        expected_owner_epoch: 0,
        expected_eligibility_epoch: 0,
        actor: "coordinator".into(),
        action: FlowingFenceAction::Hold,
        recorded_at: "t5".into(),
    };
    native
        .branches
        .transition_flowing_source(&transition("twig", "inc-1", "twig-hold"))
        .unwrap();
    assert!(
        native
            .branches
            .flowing_source("twig")
            .unwrap()
            .unwrap()
            .held
    );
    assert!(native
        .branches
        .private_cut_pin("pin")
        .unwrap()
        .unwrap()
        .released_at
        .is_some());
    let second = plan_native(&native.vcs, &store, host, &native.witness, "attempt").unwrap();
    assert_eq!(first.identity(), second.identity());
    native
        .branches
        .transition_flowing_source(&transition("branch", "branch-inc", "branch-hold"))
        .unwrap();
    assert!(
        plan_native(&native.vcs, &store, host, &native.witness, "attempt")
            .unwrap_err()
            .contains("source eligibility or coordinator changed")
    );
}

#[test]
fn source_holder_changes_during_norm_capture_refuse_the_judgment() {
    use std::cell::Cell;
    use whipplescript_store::items::TrackerEvent;
    use whipplescript_store::norm::{NormVerifier, NormView};
    use whipplescript_store::vcs::GateCommit;
    use whipplescript_store::StoreResult;
    struct ChangingLedger {
        store: WorkItemStore,
        branches: rusqlite::Connection,
        mutation: &'static str,
        reads: Cell<usize>,
        mutate_at: usize,
    }
    impl AdmissionLedger for ChangingLedger {
        fn bootstrapped(&self) -> StoreResult<bool> {
            Ok(self.store.norm_checkpoint()?.is_some())
        }
        fn capture(
            &self,
            verifier: &dyn NormVerifier,
        ) -> StoreResult<(NormView, Vec<TrackerEvent>)> {
            self.reads.set(self.reads.get() + 1);
            if self.reads.get() == self.mutate_at {
                self.branches.execute(self.mutation, [])?;
            }
            self.store.norm_admission_capture(verifier)
        }
        fn exclusively(
            &self,
            f: &mut dyn FnMut() -> StoreResult<GateCommit>,
        ) -> StoreResult<GateCommit> {
            f()
        }
    }
    for (mutation, mutate_at, reason) in [
        (
            "UPDATE flowing_contributions SET scope_digest = 'changed' WHERE unit_id = 'unit'",
            1,
            "source-admission premises changed during derivation",
        ),
        (
            "UPDATE flowing_private_pins SET principal = 'foreign' WHERE pin_id = 'pin'",
            1,
            "unit holder is unknown or changed",
        ),
        (
            "UPDATE flowing_contribution_basis SET atoms_json = '[]' WHERE unit_id = 'unit'",
            1,
            "source lineage is unknown or ineligible",
        ),
        (
            "UPDATE flowing_contributions SET scope_digest = 'changed' WHERE unit_id = 'unit'",
            2,
            "source-admission premises changed during derivation",
        ),
    ] {
        let native = NativeFixture::new();
        let runtime = SqliteStore::open_in_memory().unwrap();
        let (store, record) = f::fixture(Some(f::template()), true);
        let configuration = configuration(&store, &record);
        let policy = policy();
        let verify = |_: &PythonRuntime| Ok(());
        let host = AdmissionHost {
            now: None,
            verifier: &Boundary,
            configuration: &configuration,
            runtime: &runtime,
            policy: &policy,
            verify_runtime: &verify,
        };
        let ledger = ChangingLedger {
            store,
            branches: rusqlite::Connection::open(native.root.join("branches.db")).unwrap(),
            mutation,
            reads: Cell::new(0),
            mutate_at,
        };
        let before = ledger.store.export_events().unwrap();
        assert!(
            plan_native(&native.vcs, &ledger, host, &native.witness, "attempt")
                .unwrap_err()
                .contains(reason),
            "{reason}"
        );
        assert_eq!(ledger.store.export_events().unwrap(), before);
        assert!(runtime.list_instances().unwrap().is_empty());
        assert!(native
            .branches
            .flowing_admission_receipt("attempt")
            .unwrap()
            .is_none());
    }
}

#[test]
fn deleting_the_subject_at_a_native_candidate_keeps_the_prior_duty() {
    let native = NativeFixture::with_change("main.py", true);
    let runtime = SqliteStore::open_in_memory().unwrap();
    let (store, record) = f::fixture(Some(f::template()), true);
    let configuration = configuration(&store, &record);
    let policy = policy();
    let verify = |_: &PythonRuntime| Ok(());
    let plan = plan_native(
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
    )
    .unwrap();
    assert_eq!(
        plan.judgment()
            .subject
            .witness
            .expected_trunk_cut_id
            .as_deref(),
        Some("base")
    );
    let obligations: Vec<_> = plan
        .judgment()
        .obligations
        .values()
        .filter(|obligation| obligation.record == record)
        .collect();
    assert!(!obligations.is_empty());
    assert!(obligations
        .iter()
        .any(|obligation| obligation.bases.contains(&ImpactBasis::Before)));
    assert!(obligations.iter().any(|obligation| obligation
        .applicability
        .values()
        .any(|binding| !binding.subject_present)));
    assert!(plan
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope == "norm/admission"));
}

#[test]
fn equal_content_in_another_review_has_distinct_plan_and_obligations() {
    let mut native = NativeFixture::new();
    let runtime = SqliteStore::open_in_memory().unwrap();
    let (store, record) = f::fixture(Some(f::template()), true);
    let configuration = configuration(&store, &record);
    let policy = policy();
    let verify = |_: &PythonRuntime| Ok(());
    let host = AdmissionHost {
        now: None,
        verifier: &Boundary,
        configuration: &configuration,
        runtime: &runtime,
        policy: &policy,
        verify_runtime: &verify,
    };
    let first = plan_native(&native.vcs, &store, host, &native.witness, "attempt").unwrap();
    let other = native.review("other-review", "other-candidate", "other-attempt");
    let second = plan_native(&native.vcs, &store, host, &other, "other-attempt").unwrap();
    assert_eq!(
        first.judgment().subject.witness.candidate_manifest_hash,
        second.judgment().subject.witness.candidate_manifest_hash
    );
    assert_ne!(first.identity(), second.identity());
    assert!(first
        .judgment()
        .obligations
        .keys()
        .all(|key| !second.judgment().obligations.contains_key(key)));
    assert!(
        plan_native(&native.vcs, &store, host, &native.witness, "other-attempt")
            .unwrap_err()
            .contains("pin differs")
    );
}

#[test]
fn interpretation_identity_is_semantic_and_rejects_ambiguous_roles() {
    let one = serde_json::json!({"vocabulary": {"name":"one","version":"1","digest":"one"}, "interpretation":"context"});
    let two = serde_json::json!({"vocabulary": {"name":"two","version":"1","digest":"two"}, "interpretation":"context"});
    let parse = |roles| {
        PlanningConfiguration::parse(
            &serde_json::json!({"capability":"observer","roles":roles}).to_string(),
        )
    };
    let left = parse(vec![one.clone(), two.clone()]).unwrap();
    let right = parse(vec![two, one.clone()]).unwrap();
    assert_eq!(left.identity(), right.identity());
    assert!(parse(vec![one.clone(), one]).is_err());
}

#[test]
fn an_absent_subject_does_not_remove_the_admitted_duty() {
    let native = NativeFixture::with_path("other.py");
    let runtime = SqliteStore::open_in_memory().unwrap();
    let (store, record) = f::fixture(Some(f::template()), true);
    let configuration = configuration(&store, &record);
    let policy = policy();
    let verify = |_: &PythonRuntime| Ok(());
    let host = AdmissionHost {
        now: None,
        verifier: &Boundary,
        configuration: &configuration,
        runtime: &runtime,
        policy: &policy,
        verify_runtime: &verify,
    };
    let planned = plan_native(&native.vcs, &store, host, &native.witness, "attempt").unwrap();
    let duty = planned
        .judgment()
        .obligations
        .values()
        .find(|obligation| obligation.record == record)
        .unwrap();
    assert_eq!(duty.work, ImpactWork::ResourceGap);
    assert!(planned
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope == "norm/admission"));
}

#[test]
fn policy_changes_during_derivation_refuse_the_result() {
    use std::cell::{Cell, RefCell};
    use whipplescript_store::items::TrackerEvent;
    use whipplescript_store::norm::{NormAct, NormVerifier, NormView};
    use whipplescript_store::vcs::GateCommit;
    use whipplescript_store::StoreResult;
    struct ChangingLedger {
        store: RefCell<WorkItemStore>,
        record: String,
        reads: Cell<usize>,
    }
    impl AdmissionLedger for ChangingLedger {
        fn bootstrapped(&self) -> StoreResult<bool> {
            Ok(self.store.borrow().norm_checkpoint()?.is_some())
        }
        fn capture(
            &self,
            verifier: &dyn NormVerifier,
        ) -> StoreResult<(NormView, Vec<TrackerEvent>)> {
            self.reads.set(self.reads.get() + 1);
            let mut store = self.store.borrow_mut();
            if self.reads.get() == 2 {
                let view = store.norm_view(&Boundary)?;
                let current = &view.records[&self.record];
                store.append_norm_event(
                    &f::sign(
                        "accept",
                        NormAct::Transition {
                            ledger: view.ledger.clone(),
                            authority: None,
                            vocabulary: current.vocabulary.clone(),
                            record: self.record.clone(),
                            previous: current.head.clone(),
                            status: "accepted".into(),
                        },
                    ),
                    &Boundary,
                )?;
            }
            store.norm_admission_capture(verifier)
        }
        fn exclusively(
            &self,
            f: &mut dyn FnMut() -> StoreResult<GateCommit>,
        ) -> StoreResult<GateCommit> {
            f()
        }
    }
    let native = NativeFixture::new();
    let runtime = SqliteStore::open_in_memory().unwrap();
    let (store, record) = f::fixture(Some(f::template()), false);
    let configuration = configuration(&store, &record);
    let ledger = ChangingLedger {
        store: RefCell::new(store),
        record,
        reads: Cell::new(0),
    };
    let policy = policy();
    let verify = |_: &PythonRuntime| Ok(());
    let host = AdmissionHost {
        now: None,
        verifier: &Boundary,
        configuration: &configuration,
        runtime: &runtime,
        policy: &policy,
        verify_runtime: &verify,
    };
    assert!(
        plan_native(&native.vcs, &ledger, host, &native.witness, "attempt")
            .unwrap_err()
            .contains("premises changed")
    );
}

#[test]
fn an_unclassified_reference_field_is_required_even_without_an_observed_edge() {
    use whipplescript_core::vocabulary::{FieldDefinition, ReferenceForm, ValueType};
    let native = NativeFixture::new();
    let runtime = SqliteStore::open_in_memory().unwrap();
    let mut vocabulary = f::observation_vocabulary();
    vocabulary.definition.fields.push(FieldDefinition {
        name: "provider".into(),
        required: false,
        value_type: ValueType::Reference {
            form: ReferenceForm::Identity,
        },
        editorial: false,
    });
    let (store, record) =
        f::fixture_with_custom_observation(Some(f::template()), true, Some(vocabulary));
    let configuration = configuration(&store, &record);
    let policy = policy();
    let verify = |_: &PythonRuntime| Ok(());
    let host = AdmissionHost {
        now: None,
        verifier: &Boundary,
        configuration: &configuration,
        runtime: &runtime,
        policy: &policy,
        verify_runtime: &verify,
    };
    let plan = plan_native(&native.vcs, &store, host, &native.witness, "attempt").unwrap();
    assert!(plan
        .judgment()
        .references
        .required_classes
        .iter()
        .any(|class| class.vocabulary == "local-observation"
            && class.field == "provider"
            && class.meaning.is_none()));
    assert!(!plan
        .judgment()
        .references
        .edges
        .iter()
        .any(|edge| edge.vocabulary == "local-observation"));
    assert!(plan
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope.ends_with("/local-observation/1/provider")));
}

#[test]
fn a_workspace_without_admitted_policy_cannot_produce_an_empty_success() {
    let native = NativeFixture::new();
    let runtime = SqliteStore::open_in_memory().unwrap();
    let (configured, record) = f::fixture(Some(f::template()), true);
    let configuration = configuration(&configured, &record);
    let empty = WorkItemStore::open_in_memory().unwrap();
    let policy = policy();
    let verify = |_: &PythonRuntime| Ok(());
    let host = AdmissionHost {
        now: None,
        verifier: &Boundary,
        configuration: &configuration,
        runtime: &runtime,
        policy: &policy,
        verify_runtime: &verify,
    };
    assert!(
        plan_native(&native.vcs, &empty, host, &native.witness, "attempt")
            .unwrap_err()
            .contains("no admitted norm policy")
    );
}

#[test]
fn a_home_capture_cannot_omit_the_norm_readers_required_reference_classes() {
    use crate::source_process::*;
    struct EmptyHome {
        basis: ProcessBasis,
        reads: std::cell::Cell<usize>,
        change_on: usize,
        norm_binding: bool,
        installed_process: Option<EvidenceVersion>,
        process_reads: std::cell::Cell<usize>,
        uninstall_on: usize,
        validation: Option<OwnerValidation>,
    }
    impl ProcessCaptureAuthority for EmptyHome {
        fn verify_process_basis(
            &self,
            _: &ProcessBasis,
            process: &EvidenceVersion,
        ) -> Result<(), String> {
            self.process_reads.set(self.process_reads.get() + 1);
            if self.process_reads.get() < self.uninstall_on
                && self.installed_process.as_ref() == Some(process)
            {
                Ok(())
            } else {
                Err("derivation implementation has no exact admitted process installation".into())
            }
        }
        fn basis(&self, _: &str) -> Result<ProcessBasis, String> {
            self.reads.set(self.reads.get() + 1);
            let mut basis = self.basis.clone();
            if self.reads.get() >= self.change_on {
                basis.policy.version = "changed".into();
            }
            Ok(basis)
        }
        fn observe(
            &self,
            _: &ProcessBasis,
            _: CutSide,
            _: &ReferenceScope,
        ) -> Result<ScopeObservation, String> {
            Err("no captured scope".into())
        }
        fn verify_boundary(
            &self,
            _: &ProcessBasis,
            _: CutSide,
            _: &ReferenceScope,
            _: &ScopeObservation,
        ) -> Result<VerifiedScopeBoundary, String> {
            Err("no installed boundary".into())
        }
        fn verify_norm_basis(
            &self,
            _: &ProcessBasis,
            _: &whipplescript_store::norm_history::NormReadAnchor,
            _: &EvidenceVersion,
        ) -> Result<(), String> {
            if self.norm_binding {
                Ok(())
            } else {
                Err("norm policy binding is stale".into())
            }
        }
        fn owner_validation(
            &self,
            _: &ProcessBasis,
            _: CutSide,
            _: &ReferenceScope,
            _: &DependencyIdentity,
        ) -> Result<Option<OwnerValidation>, String> {
            Ok(self.validation.clone())
        }
    }
    let native = NativeFixture::new();
    let runtime = SqliteStore::open_in_memory().unwrap();
    let (store, record) = f::fixture(Some(f::template()), true);
    let configuration = configuration(&store, &record);
    let policy = policy();
    let verify = |_: &PythonRuntime| Ok(());
    let host = AdmissionHost {
        now: None,
        verifier: &Boundary,
        configuration: &configuration,
        runtime: &runtime,
        policy: &policy,
        verify_runtime: &verify,
    };
    let version = |name: &str| EvidenceVersion {
        name: name.into(),
        version: "1".into(),
        digest: name.into(),
    };
    let cut = |name: &str| StructuralCut {
        cut: name.into(),
        registry: version("registry"),
        population: version("roster"),
        resolutions: BTreeMap::new(),
        scopes: BTreeMap::new(),
    };
    let mut authority = EmptyHome {
        basis: ProcessBasis {
            home: "home".into(),
            candidate_witness_digest: native.witness.clone(),
            native_base_cut: None,
            native_candidate_cut: "candidate".into(),
            seal: version("seal"),
            policy: version("policy"),
            before: cut("before"),
            after: cut("after"),
        },
        reads: std::cell::Cell::new(0),
        change_on: usize::MAX,
        norm_binding: true,
        installed_process: None,
        process_reads: std::cell::Cell::new(0),
        uninstall_on: usize::MAX,
        validation: None,
    };
    let plan = plan_native_with_authority(
        &native.vcs,
        &store,
        host,
        &native.witness,
        "attempt",
        &authority,
    )
    .unwrap();
    assert!(!plan.judgment().references.required_classes.is_empty());
    assert!(plan.judgment().blockers.iter().any(|gap| gap
        .reason
        .contains("omits a locally required reference scope")));
    assert!(plan.judgment().dependencies.is_some());
    assert!(plan
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope == "home/process-installation"));
    authority.installed_process = Some(plan.judgment().process.clone());
    let installed = plan_native_with_authority(
        &native.vcs,
        &store,
        host,
        &native.witness,
        "attempt",
        &authority,
    )
    .unwrap();
    assert!(!installed
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope == "home/process-installation"));
    // A different implementation cannot inherit the same admitted methodology.
    authority.installed_process.as_mut().unwrap().digest = "another-implementation".into();
    let substituted = plan_native_with_authority(
        &native.vcs,
        &store,
        host,
        &native.witness,
        "attempt",
        &authority,
    )
    .unwrap();
    assert!(substituted
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope == "home/process-installation"));
    assert_ne!(installed.identity(), substituted.identity());
    authority.installed_process = Some(plan.judgment().process.clone());
    authority.process_reads.set(0);
    authority.uninstall_on = 2;
    assert!(plan_native_with_authority(
        &native.vcs,
        &store,
        host,
        &native.witness,
        "attempt",
        &authority,
    )
    .unwrap_err()
    .contains("Home process installation changed during derivation"));
    authority.uninstall_on = usize::MAX;
    assert!(plan.to_json()["judgment"]["dependencies"]["coverage"].is_array());
    authority.basis.native_candidate_cut = "another-candidate".into();
    let wrong_native = plan_native_with_authority(
        &native.vcs,
        &store,
        host,
        &native.witness,
        "attempt",
        &authority,
    )
    .unwrap();
    assert!(wrong_native
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope == "home/structural-cut"));
    authority.basis.native_candidate_cut = "candidate".into();
    authority.norm_binding = false;
    let wrong_norm = plan_native_with_authority(
        &native.vcs,
        &store,
        host,
        &native.witness,
        "attempt",
        &authority,
    )
    .unwrap();
    assert!(wrong_norm
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope == "home/norm-basis"));
    authority.norm_binding = true;
    let consumer = DependencyIdentity {
        authority: "fixture-home".into(),
        identity: "program".into(),
    };
    let scope = ReferenceScope {
        class: version("fixture-imports"),
        consumer_scope: "programs".into(),
    };
    authority
        .basis
        .after
        .scopes
        .insert(scope, BTreeSet::from([consumer.clone()]));
    authority
        .basis
        .after
        .resolutions
        .insert(consumer, "p1".into());
    authority.validation = Some(OwnerValidation {
        owner: "program-owner".into(),
        candidate_cut: "after".into(),
        method: version("program-check"),
    });
    let work_only = plan_native_with_authority(
        &native.vcs,
        &store,
        host,
        &native.witness,
        "attempt",
        &authority,
    )
    .unwrap();
    assert_eq!(work_only.judgment().dependency_work.len(), 1);
    assert!(work_only.judgment().blockers.iter().any(|gap| gap
        .scope
        .starts_with("dependency-validation/")
        && gap
            .reason
            .contains("no independently verified execution evidence")));
    authority.basis.after.scopes.clear();
    authority.basis.after.resolutions.clear();
    authority.validation = None;
    authority.reads.set(0);
    // Dependency capture's two reads agree. Only the final joined source/norm
    // recheck sees a relevant policy movement; no changed plan may escape.
    authority.change_on = 3;
    assert!(plan_native_with_authority(
        &native.vcs,
        &store,
        host,
        &native.witness,
        "attempt",
        &authority
    )
    .unwrap_err()
    .contains("Home source-admission basis changed during derivation"));
}
