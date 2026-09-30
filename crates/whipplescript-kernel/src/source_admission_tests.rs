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

struct NativeFixture {
    root: std::path::PathBuf,
    vcs: NativeWorkspaceVcs,
    branches: BranchStore,
    reviews: ReviewStore,
    witness: String,
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
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "whip-source-plan-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let mut vcs =
            NativeWorkspaceVcs::open(root.join("branches.db"), root.join("content.db")).unwrap();
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        let mut branches = BranchStore::open(root.join("branches.db")).unwrap();
        branches
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "twig".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Twig,
                owner: "coordinator".into(),
                opened_at: "t1".into(),
            })
            .unwrap();
        vcs.write(
            "twig",
            path,
            Some("def allow(value):\n    return False\n"),
            "source",
            "t2",
        )
        .unwrap();
        let cut = branches.get_cut("source").unwrap().unwrap();
        branches
            .pin_private_cut(PinPrivateCut {
                pin_id: "pin",
                twig_branch_id: "twig",
                cut_id: "source",
                manifest_hash: &cut.manifest_hash,
                principal: "author",
                retained_at: "t3",
            })
            .unwrap();
        branches
            .declare_contribution(DeclareContribution {
                unit_id: "unit",
                pin_id: "pin",
                principal: "author",
                intent: "change",
                read_basis_digest: &native_read_basis_digest(None, None),
                dependency_basis_digest: &native_dependency_basis_digest(&[]),
                scope_digest: "scope",
                declared_at: "t3",
            })
            .unwrap();
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                "pin",
                &whipplescript_store::selection::parse(&format!("path({path})")).unwrap(),
            )
            .unwrap()
        else {
            panic!("valid source selection")
        };
        vcs.bind_private_selection("unit", &selection, "t3")
            .unwrap();
        let mut fixture = Self {
            root,
            vcs,
            branches,
            reviews: ReviewStore::open(":memory:").unwrap(),
            witness: String::new(),
        };
        fixture.witness = fixture.review("review", "candidate", "attempt");
        fixture
    }
    fn review(&mut self, review: &str, candidate: &str, attempt: &str) -> String {
        self.reviews
            .create_native_contribution(review, "author", "change", MAINLINE_BRANCH_ID, &[])
            .unwrap();
        self.reviews
            .upload_native_revision(
                &self.branches,
                NativeUpload {
                    contribution_id: review,
                    upload_id: review,
                    actor: "author",
                    source_branch_id: "twig",
                    source_cut_id: "source",
                    unit_ids: &["unit"],
                },
            )
            .unwrap();
        let NativeCandidateOutcome::Prepared(prepared) = self
            .reviews
            .prepare_native_candidate(
                &mut self.vcs,
                NativeCandidateRequest {
                    contribution_id: review,
                    sequence: 1,
                    expected_trunk_cut_id: None,
                    candidate_cut_id: candidate,
                    actor: "coordinator",
                    recorded_at: "t4",
                },
            )
            .unwrap()
        else {
            panic!("valid candidate")
        };
        assert!(matches!(
            self.vcs
                .retain_review_attempt(attempt, &prepared.candidate_witness_digest, "t4")
                .unwrap(),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        prepared.candidate_witness_digest
    }
}

fn configuration(store: &WorkItemStore, record: &str) -> PlanningConfiguration {
    let vocabulary = store.norm_view(&Boundary).unwrap().records[record]
        .vocabulary
        .clone();
    PlanningConfiguration::parse(&serde_json::json!({
        "capability": "observer", "roles": [{"vocabulary": vocabulary, "interpretation": "context"}]
    }).to_string()).unwrap()
}
fn policy() -> ProtectedPythonPolicy {
    let mut runtime = f::method().runtime;
    runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/opt/reactor.wasm".into(),
        artifact_sha256: "a".repeat(64),
    };
    runtime.executable = "/usr/local/bin/whip".into();
    ProtectedPythonPolicy::new(&serde_json::to_string(&runtime).unwrap(), "t9").unwrap()
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
    native
        .vcs
        .write("twig", "later.txt", Some("tail"), "tail", "t5")
        .unwrap();
    let second = plan_native(&native.vcs, &store, host, &native.witness, "attempt").unwrap();
    assert_eq!(first.identity(), second.identity());
    assert_eq!(store.export_events().unwrap(), before);
    assert!(runtime.list_instances().unwrap().is_empty());
    let judgment = first.judgment();
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
    }
    impl ProcessCaptureAuthority for EmptyHome {
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
            Ok(None)
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
