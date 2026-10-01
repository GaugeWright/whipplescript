//! Qualification of the owning-route/norm join. Authentication, publication
//! and run recovery use the real codecs; execution uses the existing transport
//! fixture, whose observer implementation is qualified separately.
use super::*;
use crate::norm_execution::{PreparedNormExecution, PythonCallSupport};
use crate::norm_publication::{ObservationSigning, PreparedObservationPublication};
use crate::source_process::*;
use whipplescript_core::vocabulary::Vocabulary;

type NormRead = Box<dyn Fn(usize) -> Result<(), String>>;

struct Home {
    basis: ProcessBasis,
    validation: OwnerValidation,
    binding: Option<NormValidationBinding>,
    reads: std::cell::Cell<usize>,
    change_on: usize,
    norm_reads: std::cell::Cell<usize>,
    norm_read: Option<NormRead>,
}
impl ProcessCaptureAuthority for Home {
    fn basis(&self, _: &str) -> Result<ProcessBasis, String> {
        Ok(self.basis.clone())
    }
    fn verify_process_basis(&self, _: &ProcessBasis, _: &EvidenceVersion) -> Result<(), String> {
        Ok(())
    }
    fn observe(
        &self,
        basis: &ProcessBasis,
        side: CutSide,
        _: &ReferenceScope,
    ) -> Result<ScopeObservation, String> {
        let cut = match side {
            CutSide::Before => &basis.before,
            CutSide::After => &basis.after,
        };
        Ok(ScopeObservation {
            cut: cut.cut.clone(),
            registry: cut.registry.clone(),
            population: cut.population.clone(),
            extractor: EvidenceVersion {
                name: "fixture-extractor".into(),
                version: "1".into(),
                digest: "fixture-extractor".into(),
            },
            examined: cut.resolutions.clone(),
            live: BTreeSet::new(),
        })
    }
    fn verify_boundary(
        &self,
        _: &ProcessBasis,
        _: CutSide,
        _: &ReferenceScope,
        _: &ScopeObservation,
    ) -> Result<VerifiedScopeBoundary, String> {
        Ok(VerifiedScopeBoundary::Unknown {
            reason: "fixture extraction is unknown".into(),
        })
    }
    fn verify_norm_basis(
        &self,
        _: &ProcessBasis,
        _: &whipplescript_store::norm_history::NormReadAnchor,
        _: &EvidenceVersion,
    ) -> Result<(), String> {
        self.norm_reads.set(self.norm_reads.get() + 1);
        match &self.norm_read {
            Some(read) => read(self.norm_reads.get()),
            None => Ok(()),
        }
    }
    fn owner_validation(
        &self,
        _: &ProcessBasis,
        _: CutSide,
        _: &ReferenceScope,
        _: &DependencyIdentity,
    ) -> Result<Option<OwnerValidation>, String> {
        Ok(Some(self.validation.clone()))
    }
    fn validation_requirement(
        &self,
        _: &ProcessBasis,
        _: &DependencyIdentity,
        _: &OwnerValidation,
    ) -> Result<Option<NormValidationBinding>, String> {
        self.reads.set(self.reads.get() + 1);
        if self.reads.get() >= self.change_on {
            Ok(None)
        } else {
            Ok(self.binding.clone())
        }
    }
}

struct Fixture {
    native: NativeFixture,
    ledger: WorkItemStore,
    runtime: SqliteStore,
    configuration: PlanningConfiguration,
    policy: ProtectedPythonPolicy,
    home: Home,
}
impl Fixture {
    fn new() -> Self {
        let native = NativeFixture::new();
        let policy = policy();
        let mut method = f::method();
        method.runtime.engine = PythonEngine::Cpython3147Wasi {
            artifact_path: "/opt/reactor.wasm".into(),
            artifact_sha256: "a".repeat(64),
        };
        method.runtime.executable = "/usr/local/bin/whip".into();
        let mut support: PythonCallSupport =
            serde_json::from_value(f::template()).expect("fixture support");
        let PythonCallSupport::V1 {
            method: installed, ..
        } = &mut support;
        *installed = method.clone();
        let (ledger, record) = f::fixture_with_observation(
            Some(serde_json::to_value(support).expect("fixture support JSON")),
            true,
            true,
        );
        let runtime = SqliteStore::open(native.root.join("runtime.db")).expect("fixture runtime");
        let mut script = f::script();
        script.body = method.adapter().into();
        script.sha256 = crate::exec_http::sha256_hex(script.body.as_bytes());
        script.argv_json = serde_json::json!([
            "/usr/local/bin/whip",
            "executor",
            "observe-norm",
            "{script}"
        ])
        .to_string();
        runtime
            .register_script_capability(whipplescript_store::ScriptCapabilityRegistration {
                name: &script.name,
                argv_json: &script.argv_json,
                sha256: &script.sha256,
                env_json: &script.env_json,
                hermetic: script.hermetic,
                body: &script.body,
            })
            .expect("install fixture observer");
        let view = ledger.norm_view(&Boundary).expect("fixture norm view");
        let requirement = view
            .requirement_inventory()
            .expect("fixture requirements")
            .requirements[&record]
            .requirement
            .clone()
            .expect("fixture exact requirement");
        let vocabulary = Vocabulary::new(f::observation_vocabulary().definition)
            .expect("fixture observation vocabulary")
            .reference()
            .clone();
        let configuration = PlanningConfiguration::parse(
            &serde_json::json!({
                "capability": "observer", "roles": [
                    {"vocabulary":view.records[&record].vocabulary,"interpretation":"context"},
                    {"vocabulary":vocabulary,"interpretation":"published_execution"}
                ]
            })
            .to_string(),
        )
        .expect("fixture planning configuration");
        let version = |name: &str| EvidenceVersion {
            name: name.into(),
            version: "1".into(),
            digest: name.into(),
        };
        let cut = |name: &str| StructuralCut {
            cut: name.into(),
            registry: version("registry"),
            population: version("population"),
            resolutions: BTreeMap::new(),
            scopes: BTreeMap::new(),
        };
        let consumer = DependencyIdentity {
            authority: "program-store".into(),
            identity: "program".into(),
        };
        let mut after = cut("after");
        after
            .resolutions
            .insert(consumer.clone(), "program-1".into());
        after.scopes.insert(
            ReferenceScope {
                class: version("imports"),
                consumer_scope: "programs".into(),
            },
            BTreeSet::from([consumer]),
        );
        let home = Home {
            basis: ProcessBasis {
                home: "home".into(),
                candidate_witness_digest: native.witness.clone(),
                native_base_cut: None,
                native_candidate_cut: "candidate".into(),
                seal: version("seal"),
                policy: version("process-policy"),
                before: cut("before"),
                after,
            },
            validation: OwnerValidation {
                owner: "program-owner".into(),
                candidate_cut: "after".into(),
                method: method.reference(),
            },
            binding: Some(NormValidationBinding {
                contract: version("program-validation-correspondence"),
                ledger: view.ledger,
                record,
                requirement,
            }),
            reads: std::cell::Cell::new(0),
            change_on: usize::MAX,
            norm_reads: std::cell::Cell::new(0),
            norm_read: None,
        };
        Self {
            native,
            ledger,
            runtime,
            configuration,
            policy,
            home,
        }
    }
    fn plan(&self) -> Result<SourceAdmissionPlan, String> {
        self.plan_verifying(&|_: &PythonRuntime| Ok(()))
    }
    fn plan_verifying(
        &self,
        verify_runtime: &dyn Fn(&PythonRuntime) -> Result<(), String>,
    ) -> Result<SourceAdmissionPlan, String> {
        plan_native_with_authority(
            &self.native.vcs,
            &self.ledger,
            AdmissionHost {
                now: None,
                verifier: &Boundary,
                configuration: &self.configuration,
                runtime: &self.runtime,
                policy: &self.policy,
                verify_runtime,
            },
            &self.native.witness,
            "attempt",
            &self.home,
        )
    }
    fn publish(&mut self, cut: &str, actual: bool, timeout: bool) {
        self.publish_named(cut, actual, timeout, "observation");
    }
    fn publish_named(&mut self, cut: &str, actual: bool, timeout: bool, name: &str) {
        let binding = self.home.binding.as_ref().expect("fixture binding");
        let history = f::history(&self.ledger);
        let artifact = self
            .native
            .vcs
            .capture_norm_artifact(cut, ArtifactLimits::default())
            .expect("fixture artifact");
        let script = self
            .runtime
            .get_script_capability("observer")
            .expect("read fixture observer")
            .expect("fixture observer exists");
        let mut selection = f::selection(&binding.ledger, &binding.record);
        selection.effect_id = name;
        let prepared =
            PreparedNormExecution::prepare(&history, &Boundary, &artifact, &script, selection)
                .expect("prepare actual fixture contract");
        let runtime = std::mem::replace(
            &mut self.runtime,
            SqliteStore::open_in_memory().expect("temporary journal"),
        );
        let kernel = f::journal_execution_as(
            runtime,
            &prepared,
            &f::receipt(&prepared, actual, timeout),
            actual || timeout,
            &format!("instance-{name}"),
            &format!("run-{name}"),
        );
        self.runtime = kernel.into_store();
        let execution = PreparedNormExecution::recover_with_artifacts(
            &history,
            &Boundary,
            &|cut: &str| {
                self.native
                    .vcs
                    .capture_norm_artifact(cut, ArtifactLimits::default())
            },
            &self.runtime,
            &format!("instance-{name}"),
            &format!("run-{name}"),
        )
        .expect("recover independently bound fixture run");
        let vocabulary = Vocabulary::new(f::observation_vocabulary().definition)
            .expect("fixture observation vocabulary")
            .reference()
            .clone();
        let publication = PreparedObservationPublication::prepare(
            &execution,
            &history,
            &self.runtime,
            &Boundary,
            ObservationSigning {
                vocabulary: &vocabulary,
                authority: None,
                actor: &f::actor(),
                created_at: "t9",
            },
            |statement| {
                Ok(crate::exec_http::sha256_hex(
                    &statement.signing_bytes().expect("fixture signing bytes"),
                ))
            },
        )
        .expect("prepare authenticated observation");
        publication
            .submit(&mut self.ledger, &Boundary)
            .expect("publish fixture observation")
            .acknowledge(&self.runtime)
            .expect("acknowledge fixture publication");
    }
}

fn judgment(plan: &SourceAdmissionPlan) -> &DependencyValidationJudgment {
    assert_eq!(plan.judgment().dependency_judgments.len(), 1);
    plan.judgment()
        .dependency_judgments
        .values()
        .next()
        .expect("owning validation judgment")
}

#[test]
fn owning_validation_uses_published_exercise_and_retains_failed_and_unrun_states() {
    let mut fixture = Fixture::new();
    let before = fixture.plan().unwrap();
    assert!(matches!(judgment(&before).work, ImpactWork::Check { .. }));
    for (actual, timeout, expected) in [
        (false, false, ImpactWork::Supported),
        (true, false, ImpactWork::Repair),
        (true, true, ImpactWork::Repair),
        (
            false,
            true,
            ImpactWork::Check {
                method: fixture.home.validation.method.clone(),
            },
        ),
    ] {
        let mut fixture = Fixture::new();
        fixture.publish("candidate", actual, timeout);
        let events = fixture.ledger.export_events().unwrap();
        let plan = fixture.plan().unwrap();
        assert_eq!(
            judgment(&plan).work,
            expected,
            "actual={actual}, timeout={timeout}"
        );
        let obligation = &plan.judgment().obligations[judgment(&plan).obligation.as_ref().unwrap()];
        assert!(!obligation.support.as_ref().unwrap().judgments.is_empty());
        assert_eq!(fixture.ledger.export_events().unwrap(), events);
        assert_eq!(
            plan.judgment()
                .blockers
                .iter()
                .any(|gap| gap.scope.starts_with("dependency-validation/")),
            expected != ImpactWork::Supported
        );
        // Closing this work is neither support nor an admission receipt. Other
        // deliberately unclosed Home scopes remain explicit even after Pass.
        assert!(plan
            .judgment()
            .blockers
            .iter()
            .any(|gap| gap.scope.starts_with("home/norm/")));
    }
    let item = fixture
        .ledger
        .file_item(
            "checks",
            "validator passed",
            "",
            &[],
            &serde_json::json!({}),
            None,
            None,
        )
        .unwrap();
    fixture
        .ledger
        .finish_item(&item.id, Some("pass"), None)
        .unwrap();
    let closed = fixture.plan().unwrap();
    assert_eq!(judgment(&closed).work, judgment(&before).work);
}

#[test]
fn an_owning_route_cannot_borrow_an_unrelated_or_stale_norm_success() {
    for fault in [
        "missing",
        "ledger",
        "record",
        "requirement",
        "contract",
        "method",
    ] {
        let mut fixture = Fixture::new();
        fixture.publish("candidate", false, false);
        assert_eq!(
            judgment(&fixture.plan().unwrap()).work,
            ImpactWork::Supported
        );
        if fault == "missing" {
            fixture.home.binding = None;
        } else if fault == "method" {
            fixture.home.validation.method.digest.push('x');
        } else {
            let binding = fixture.home.binding.as_mut().unwrap();
            match fault {
                "ledger" => binding.ledger.push('x'),
                "record" => binding.record.push('x'),
                "requirement" => binding.requirement.digest.push('x'),
                _ => binding.contract.digest.clear(),
            }
        }
        let plan = fixture.plan().unwrap();
        assert_eq!(judgment(&plan).work, ImpactWork::ObservationGap, "{fault}");
        assert!(
            plan.judgment()
                .blockers
                .iter()
                .any(|gap| gap.scope.starts_with("dependency-validation/")),
            "{fault}"
        );
    }
    let mut fixture = Fixture::new();
    // A real published success on another captured artifact remains stale.
    fixture
        .native
        .vcs
        .write(
            "twig",
            "main.py",
            Some("def allow(value): return True\n"),
            "other-cut",
            "t8",
        )
        .unwrap();
    fixture.publish("other-cut", false, false);
    let plan = fixture.plan().unwrap();
    assert!(matches!(judgment(&plan).work, ImpactWork::Check { .. }));
    let obligation = &plan.judgment().obligations[judgment(&plan).obligation.as_ref().unwrap()];
    assert!(!obligation.support.as_ref().unwrap().stale.is_empty());
}

#[test]
fn owning_correspondence_is_recaptured_before_returning_the_plan() {
    let mut fixture = Fixture::new();
    fixture.publish("candidate", false, false);
    assert_eq!(
        judgment(&fixture.plan().unwrap()).work,
        ImpactWork::Supported
    );
    fixture.home.reads.set(0);
    fixture.home.change_on = 2;
    assert!(fixture
        .plan()
        .unwrap_err()
        .contains("owning validation correspondence changed"));
}

#[test]
fn conflicting_or_unrecoverable_execution_cannot_clear_owning_work() {
    let mut fixture = Fixture::new();
    fixture.publish_named("candidate", false, false, "passed");
    fixture.publish_named("candidate", true, false, "failed");
    let plan = fixture.plan().unwrap();
    assert_eq!(judgment(&plan).work, ImpactWork::ResolveEvidence);
    let obligation = &plan.judgment().obligations[judgment(&plan).obligation.as_ref().unwrap()];
    let selection = obligation.support.as_ref().unwrap();
    assert!(!selection.positive.is_empty());
    assert!(!selection.counterevidence.is_empty());
    assert!(plan
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope.starts_with("dependency-validation/")));

    let mut fixture = Fixture::new();
    fixture.publish("candidate", false, false);
    fixture.runtime = SqliteStore::open_in_memory().unwrap();
    let plan = fixture.plan().unwrap();
    assert_eq!(judgment(&plan).work, ImpactWork::VerifyEvidence);
    assert!(plan
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope.starts_with("dependency-validation/")));
}

fn register_observer(store: &SqliteStore, script: &whipplescript_store::ScriptCapabilityRecord) {
    store
        .register_script_capability(whipplescript_store::ScriptCapabilityRegistration {
            name: &script.name,
            argv_json: &script.argv_json,
            sha256: &script.sha256,
            env_json: &script.env_json,
            hermetic: script.hermetic,
            body: &script.body,
        })
        .expect("replace fixture observer registration");
}

#[test]
fn discovery_installation_is_bound_without_exposing_private_registration() {
    let fixture = Fixture::new();
    let first = fixture.plan().unwrap();
    assert!(matches!(judgment(&first).work, ImpactWork::Check { .. }));
    assert_eq!(first.identity(), fixture.plan().unwrap().identity());
    let reads = first.judgment().norm["method_installation"]["reads"]
        .as_array()
        .unwrap();
    assert_eq!(reads.len(), 2);
    assert!(reads.iter().all(|read| read["available"] == true));
    let mut script = fixture
        .runtime
        .get_script_capability("observer")
        .unwrap()
        .unwrap();
    script.env_json = serde_json::json!({"TOKEN":"planner-private-fixture-value"}).to_string();
    script.body.push_str("\n# planner-private-fixture-body");
    register_observer(&fixture.runtime, &script);
    let changed = fixture.plan().unwrap();
    assert_ne!(first.identity(), changed.identity());
    assert_ne!(
        first.judgment().norm["method_installation"],
        changed.judgment().norm["method_installation"]
    );
    let wire = changed.to_json().to_string();
    assert!(!wire.contains("planner-private-fixture-value"));
    assert!(!wire.contains("planner-private-fixture-body"));
}

#[test]
fn observer_repin_after_norm_planning_refuses_the_source_judgment() {
    for field in ["body", "digest", "argv", "environment", "reuse"] {
        let mut fixture = Fixture::new();
        let mut script = fixture
            .runtime
            .get_script_capability("observer")
            .unwrap()
            .unwrap();
        match field {
            "body" => script.body.push_str("\n# changed"),
            "digest" => script.sha256 = "b".repeat(64),
            "argv" => script.argv_json = "[]".into(),
            "environment" => script.env_json = "{\"TOKEN\":\"changed\"}".into(),
            _ => script.hermetic = !script.hermetic,
        }
        // A separate connection mutates the real registry after the generic
        // norm query returned, while source, ledger and Home basis stay fixed.
        let writer = SqliteStore::open(fixture.native.root.join("runtime.db")).unwrap();
        fixture.home.norm_read = Some(Box::new(move |read| {
            if read == 1 {
                register_observer(&writer, &script);
            }
            Ok(())
        }));
        assert!(
            fixture
                .plan()
                .unwrap_err()
                .contains("observer installation changed"),
            "{field}"
        );
    }
}

#[test]
fn observer_repin_during_discovery_refuses_the_norm_query() {
    let fixture = Fixture::new();
    let mut script = fixture
        .runtime
        .get_script_capability("observer")
        .unwrap()
        .unwrap();
    script.body.push_str("\n# concurrent registration");
    let writer = SqliteStore::open(fixture.native.root.join("runtime.db")).unwrap();
    let result = fixture.plan_verifying(&|_| {
        register_observer(&writer, &script);
        Ok(())
    });
    assert!(result
        .unwrap_err()
        .contains("observer installation changed"));
    assert_eq!(
        fixture.home.norm_reads.get(),
        0,
        "generic norm query must refuse first"
    );
}

#[test]
fn missing_observer_is_a_bound_gap_and_late_installation_is_stale() {
    let mut fixture = Fixture::new();
    let script = fixture
        .runtime
        .get_script_capability("observer")
        .unwrap()
        .unwrap();
    let path = fixture.native.root.join("empty-runtime.db");
    fixture.runtime = SqliteStore::open(&path).unwrap();
    let gap = fixture.plan().unwrap();
    let reads = gap.judgment().norm["method_installation"]["reads"]
        .as_array()
        .unwrap();
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0]["available"], false);
    assert!(gap.judgment().norm["method_gaps"]
        .to_string()
        .contains("not registered"));
    let writer = SqliteStore::open(path).unwrap();
    fixture.home.norm_read = Some(Box::new(move |_| {
        register_observer(&writer, &script);
        Ok(())
    }));
    assert!(fixture
        .plan()
        .unwrap_err()
        .contains("observer installation changed"));
}

#[test]
fn used_runtime_verification_is_recaptured_by_norm_and_source_planners() {
    for change_on in [2, 3] {
        let fixture = Fixture::new();
        let reads = std::cell::Cell::new(0);
        let result = fixture.plan_verifying(&|_| {
            reads.set(reads.get() + 1);
            if reads.get() >= change_on {
                Err("host installation unavailable".into())
            } else {
                Ok(())
            }
        });
        assert!(
            result.unwrap_err().contains("runtime installation changed"),
            "{change_on}"
        );
        assert_eq!(reads.get(), change_on);
    }
    let fixture = Fixture::new();
    let stable = fixture
        .plan_verifying(&|_| Err("host installation unavailable".into()))
        .unwrap();
    assert!(stable.judgment().norm["method_gaps"]
        .to_string()
        .contains("host installation unavailable"));
    assert!(stable.judgment().norm["method_installation"]["reads"]
        .as_array()
        .unwrap()
        .iter()
        .any(|read| read["kind"] == "runtime" && read["available"] == false));
}

#[test]
fn historical_support_does_not_read_unrelated_current_installations() {
    let mut fixture = Fixture::new();
    fixture.publish("candidate", false, false);
    let initial = fixture
        .plan_verifying(&|_| panic!("supported evidence needs no discovery"))
        .unwrap();
    assert_eq!(judgment(&initial).work, ImpactWork::Supported);
    assert!(initial.judgment().norm["method_installation"]["reads"]
        .as_array()
        .unwrap()
        .is_empty());
    let mut script = fixture
        .runtime
        .get_script_capability("observer")
        .unwrap()
        .unwrap();
    script.body.push_str("\n# unrelated current installation");
    let writer = SqliteStore::open(fixture.native.root.join("runtime.db")).unwrap();
    fixture.home.norm_read = Some(Box::new(move |_| {
        register_observer(&writer, &script);
        Ok(())
    }));
    let plan = fixture
        .plan_verifying(&|_| panic!("irrelevant runtime must not be read"))
        .unwrap();
    assert_eq!(judgment(&plan).work, ImpactWork::Supported);
    assert_eq!(initial.identity(), plan.identity());
}

#[test]
fn home_norm_authority_binding_is_recaptured_including_refusals() {
    for (before, after) in [
        (Ok(()), Err("binding withdrawn".to_owned())),
        (Err("binding absent".to_owned()), Ok(())),
        (
            Err("binding absent".to_owned()),
            Err("binding changed".to_owned()),
        ),
    ] {
        let mut fixture = Fixture::new();
        fixture.home.norm_read = Some(Box::new(move |read| {
            if read == 1 {
                before.clone()
            } else {
                after.clone()
            }
        }));
        assert!(fixture
            .plan()
            .unwrap_err()
            .contains("Home norm authority binding changed"));
    }
    let mut fixture = Fixture::new();
    fixture.home.norm_read = Some(Box::new(|_| Err("stable missing binding".into())));
    let plan = fixture.plan().unwrap();
    assert!(plan
        .judgment()
        .blockers
        .iter()
        .any(|gap| gap.scope == "home/norm-basis" && gap.reason == "stable missing binding"));
}
