use super::*;
use crate::norm_execution::fixtures::{self as f, Boundary};
use serde_json::json;
use whipplescript_core::norm_evidence::*;
use whipplescript_core::norm_preservation::*;
use whipplescript_core::norm_selection::SelectionPayload;
use whipplescript_store::branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID};
use whipplescript_store::content::ContentBlobs;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm::NormAct;
use whipplescript_store::norm_artifact::{capture_cut, ArtifactLimits};

// Typed evidence verification is a separate trusted fixture boundary here;
// this suite does not stand in for a production ledger-to-evidence projection.
struct Host {
    events: Vec<SelectionEvent>,
    automatic: Option<EvidenceVersion>,
}
impl ReportVerifier for Host {
    fn verify_report_binding(&self, report: &TestReport) -> bool {
        self.events.iter().any(|e| matches!(&e.payload, SelectionPayload::Observation {report: r,..} if r.as_ref()==report))
    }
    fn verify_assertion_exercise(
        &self,
        _: &TestReport,
        observation: &AssertionObservation,
    ) -> bool {
        observation.witness == "call"
    }
}
impl PreservationVerifier for Host {
    fn verify_preservation_basis(&self, witness: &PreservationWitness) -> bool {
        self.events.iter().any(|e| matches!(&e.payload, SelectionPayload::Preservation {witness:w,..} if w.as_ref()==witness))
    }
}
impl SelectionVerifier for Host {
    fn verify_event(&self, event: &SelectionEvent) -> bool {
        self.events.contains(event)
    }
    fn accepts_contract(&self, _: &SelectionQuery, contract: &ReportContract) -> bool {
        contract.subject.method == version("method")
    }
    fn authorize_resolution(&self, _: &SelectionQuery, _: &SelectionEvent) -> bool {
        false
    }
    fn accepts_preservation(&self, query: &SelectionQuery, witness: &PreservationWitness) -> bool {
        witness.context.policy == query.policy && witness.context.boundary == version("boundary")
    }
}
impl ImpactVerifier for Host {
    fn automatic_method(
        &self,
        _: &InventoryRequirement,
        _: &CapturedArtifact,
    ) -> Option<EvidenceVersion> {
        self.automatic.clone()
    }
}
fn version(name: &str) -> EvidenceVersion {
    EvidenceVersion {
        name: name.into(),
        version: "1".into(),
        digest: name.into(),
    }
}
fn artifact(files: &[(&str, &str)]) -> CapturedArtifact {
    let blobs = f::Blobs::default();
    let manifest: BTreeMap<_, _> = files
        .iter()
        .map(|(path, body)| (*path, blobs.put(body.as_bytes()).unwrap()))
        .collect();
    let root = blobs.put(json!(manifest).to_string().as_bytes()).unwrap();
    let mut branches = BranchStore::open(":memory:").unwrap();
    branches.ensure_mainline("t0").unwrap();
    branches
        .record_cut(CutRecord {
            cut_id: "candidate",
            change_id: "change",
            branch_id: MAINLINE_BRANCH_ID,
            manifest_hash: &root,
            parent_cut_id: None,
            origin: None,
            actor: None,
            intent: None,
            recorded_at: "t1",
        })
        .unwrap();
    capture_cut(&branches, &blobs, "candidate", ArtifactLimits::default()).unwrap()
}
fn events(store: &WorkItemStore) -> Vec<SelectionEvent> {
    store
        .export_events()
        .unwrap()
        .into_iter()
        .map(|e| SelectionEvent {
            id: e.event_id,
            parents: e.parents.into_iter().collect(),
            payload: SelectionPayload::Context,
        })
        .collect()
}
fn evaluate(
    before: &NormView,
    a: &CapturedArtifact,
    after: &NormView,
    b: &CapturedArtifact,
    host: &Host,
) -> ImpactPlan {
    plan(
        ImpactInput {
            before,
            before_artifact: a,
            after,
            candidate: b,
            policy: &version("policy"),
            time_basis: "captured",
            evidence: &host.events,
        },
        host,
        ImpactLimits::default(),
    )
    .unwrap()
}
fn observation(requirement: EvidenceVersion, artifact: String, passed: bool) -> SelectionPayload {
    let subject = EvidenceSubject {
        requirement,
        method: version("method"),
        artifact: artifact.clone(),
    };
    SelectionPayload::Observation {
        contract: ReportContract {
            subject: subject.clone(),
            cases: vec![RequiredCase {
                id: "case".into(),
                assertion: "property".into(),
                expected: json!(true),
            }],
        },
        report: Box::new(TestReport {
            subject,
            provenance: Some(ArtifactProvenance::Interpreted {
                source_frontier: artifact,
                interpreter: "observer".into(),
                environment: "epoch".into(),
            }),
            completion: ReportCompletion::Complete,
            termination: if passed {
                ProcessTermination::Success
            } else {
                ProcessTermination::Failure
            },
            observations: vec![AssertionObservation {
                case: "case".into(),
                assertion: "property".into(),
                actual: json!(passed),
                witness: "call".into(),
            }],
        }),
    }
}
#[test]
fn impact_keeps_new_and_retired_duties_and_repairs_at_the_candidate() {
    let (mut store, id) = f::fixture(Some(f::template()), true);
    let before = store.norm_view(&Boundary).unwrap();
    let current = &before.records[&id];
    let active = &before.effective_records[&id];
    store
        .append_norm_event(
            &f::sign(
                "retire",
                NormAct::Retire {
                    ledger: before.ledger.clone(),
                    authority: Some(before.authority_head.clone()),
                    vocabulary: current.vocabulary.clone(),
                    record: id.clone(),
                    previous: current.head.clone(),
                    revision: active.content_head.clone(),
                    activation: active.head.clone(),
                    status: "retired".into(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let after = store.norm_view(&Boundary).unwrap();
    let missing = artifact(&[]);
    let repaired = artifact(&[("main.py", "property")]);
    let host = Host {
        events: events(&store),
        automatic: Some(version("method")),
    };
    let plan = evaluate(&before, &missing, &after, &repaired, &host);
    assert_eq!(plan.requirements.len(), 1);
    assert_eq!(
        plan.requirements[&id][0].bases,
        [ImpactBasis::Before].into()
    );
    assert!(matches!(
        plan.requirements[&id][0].work,
        ImpactWork::Check { .. }
    ));
    assert!(plan
        .authority_actions
        .contains(&ImpactAuthorityAction::RequirementChanged(id.clone())));
    assert!(!plan.resources.before.binding_complete);
    assert!(plan.prior_at_candidate.binding_complete);
    let deleted = evaluate(&before, &repaired, &after, &missing, &host);
    assert_eq!(deleted.requirements[&id][0].work, ImpactWork::ResourceGap);
    assert!(!deleted.prior_at_candidate.binding_complete);
    // A newly effective requirement needs work even without any changed file.
    let (mut new_store, new_id) = f::fixture(Some(f::template()), false);
    let prior = new_store.norm_view(&Boundary).unwrap();
    let record = &prior.records[&new_id];
    new_store
        .append_norm_event(
            &f::sign(
                "activate",
                NormAct::Transition {
                    ledger: prior.ledger.clone(),
                    authority: None,
                    vocabulary: record.vocabulary.clone(),
                    record: new_id.clone(),
                    previous: record.head.clone(),
                    status: "accepted".into(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let after = new_store.norm_view(&Boundary).unwrap();
    let host = Host {
        events: events(&new_store),
        automatic: Some(version("method")),
    };
    let new = evaluate(&prior, &repaired, &after, &repaired, &host);
    assert!(new.resources.changes.is_empty());
    assert!(matches!(
        new.requirements[&new_id][0].work,
        ImpactWork::Check { .. }
    ));
}
#[test]
fn impact_rechecks_support_without_subject_shortcuts_or_retry_washing() {
    let (store, id) = f::fixture(Some(f::template()), true);
    let view = store.norm_view(&Boundary).unwrap();
    let requirement = view.requirement_inventory().unwrap().requirements[&id]
        .requirement
        .clone()
        .unwrap();
    let before = artifact(&[("main.py", "same subject"), ("parser.py", "old")]);
    let candidate = artifact(&[("main.py", "same subject"), ("parser.py", "changed")]);
    for (mode, expected) in [
        ("exact", ImpactWork::Supported),
        ("failure", ImpactWork::Repair),
        ("conflict", ImpactWork::ResolveEvidence),
        (
            "stale",
            ImpactWork::Check {
                method: version("method"),
            },
        ),
    ] {
        let mut host = Host {
            events: events(&store),
            automatic: Some(version("method")),
        };
        host.events[0].payload = observation(
            requirement.clone(),
            candidate_identity(if mode == "stale" {
                before.files()
            } else {
                candidate.files()
            }),
            mode != "failure" && mode != "conflict",
        );
        if mode == "conflict" {
            host.events[1].payload = observation(
                requirement.clone(),
                candidate_identity(candidate.files()),
                true,
            );
        }
        let plan = evaluate(&view, &before, &view, &candidate, &host);
        let result = &plan.requirements[&id];
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].bases,
            [ImpactBasis::Before, ImpactBasis::After].into()
        );
        assert_eq!(result[0].work, expected, "{mode}");
        // Independent typed-evidence fixture: a verification gap must retain
        // already established repair/conflict work, but block support/rechecks.
        let gap_plan = plan_with_selection(
            ImpactInput {
                before: &view,
                before_artifact: &before,
                after: &view,
                candidate: &candidate,
                policy: &version("policy"),
                time_basis: "captured",
                evidence: &host.events,
            },
            ImpactLimits::default(),
            [("unverified".into(), ProjectionGap::MalformedPublication)].into(),
            |query, events| select_evidence(query, events, &host),
            |_, _| panic!("gap must not request an automatic replacement"),
        )
        .unwrap();
        assert_eq!(gap_plan.evidence_gaps.len(), 1);
        assert_eq!(
            gap_plan.requirements[&id][0].work,
            match mode {
                "failure" => ImpactWork::Repair,
                "conflict" => ImpactWork::ResolveEvidence,
                _ => ImpactWork::VerifyEvidence,
            }
        );

        assert_eq!(
            result[0].selection.as_ref().unwrap().query.artifact,
            candidate_identity(candidate.files())
        );
    }
    let host = Host {
        events: events(&store),
        automatic: None,
    };
    assert_eq!(
        evaluate(&view, &before, &view, &candidate, &host).requirements[&id][0].work,
        ImpactWork::ObservationGap
    );
}
#[test]
fn impact_only_preserves_with_complete_unchanged_verified_dependencies() {
    let (store, id) = f::fixture(Some(f::template()), true);
    let view = store.norm_view(&Boundary).unwrap();
    let requirement = view.requirement_inventory().unwrap().requirements[&id]
        .requirement
        .clone()
        .unwrap();
    let before = artifact(&[("main.py", "same"), ("readme.md", "old")]);
    let candidate = artifact(&[("main.py", "same"), ("readme.md", "new")]);
    for fault in ["exact", "partial", "creation", "metadata", "membership"] {
        let mut host = Host {
            events: events(&store),
            automatic: Some(version("method")),
        };
        host.events[0].payload = observation(
            requirement.clone(),
            candidate_identity(before.files()),
            true,
        );
        let key = ObservationKey {
            resource: "optional.config".into(),
            aspect: match fault {
                "metadata" => ObservationAspect::Metadata,
                "membership" => ObservationAspect::Membership,
                _ => ObservationAspect::Presence,
            },
        };
        let source = DependencyObservation {
            key: key.clone(),
            value: ObservationValue::Absent,
        };
        let target = DependencyObservation {
            key,
            value: if matches!(fault, "creation" | "metadata" | "membership") {
                ObservationValue::Present("changed".into())
            } else {
                ObservationValue::Absent
            },
        };
        host.events[1].payload = SelectionPayload::Preservation {
            observation: host.events[0].id.clone(),
            witness: Box::new(PreservationWitness {
                id: host.events[1].id.clone(),
                context: PreservationContext {
                    requirement: requirement.clone(),
                    method: version("method"),
                    policy: version("policy"),
                    source_artifact: candidate_identity(before.files()),
                    target_artifact: candidate_identity(candidate.files()),
                    boundary: version("boundary"),
                },
                basis: if fault == "partial" {
                    PreservationBasis::PartialTrace
                } else {
                    PreservationBasis::CompleteExact
                },
                mode: PreservationMode::Deterministic,
                source: vec![source],
                target: vec![target],
                gaps: BTreeSet::new(),
            }),
        };
        let result = evaluate(&view, &before, &view, &candidate, &host);
        assert_eq!(
            result.requirements[&id][0].work,
            if fault == "exact" {
                ImpactWork::Supported
            } else {
                ImpactWork::Check {
                    method: version("method"),
                }
            },
            "{fault}"
        );
    }
}
#[test]
fn impact_refuses_unverifiable_history_and_partial_budget_results() {
    let (store, _) = f::fixture(Some(f::template()), true);
    let view = store.norm_view(&Boundary).unwrap();
    let candidate = artifact(&[("main.py", "same")]);
    let host = Host {
        events: events(&store),
        automatic: Some(version("method")),
    };
    for fault in ["policy", "time", "events", "evaluations", "history"] {
        let mut policy = version("policy");
        if fault == "policy" {
            policy.digest.clear();
        }
        let mut limits = ImpactLimits::default();
        if fault == "events" {
            limits.max_events = 0;
        }
        if fault == "evaluations" {
            limits.max_evaluations = 0;
        }
        let mut evidence = host.events.clone();
        if fault == "history" {
            evidence[0].parents.insert("absent".into());
        }
        assert!(
            plan(
                ImpactInput {
                    before: &view,
                    before_artifact: &candidate,
                    after: &view,
                    candidate: &candidate,
                    policy: &policy,
                    time_basis: if fault == "time" { "" } else { "captured" },
                    evidence: &evidence
                },
                &host,
                limits
            )
            .is_err(),
            "{fault}"
        );
    }
}

#[test]
fn impact_keeps_both_meanings_when_a_requirement_changes() {
    let (mut store, id) = f::fixture(Some(f::template()), true);
    let before = store.norm_view(&Boundary).unwrap();
    let old = &before.records[&id];
    let mut fields = old.fields.clone();
    fields["proposition"] = json!("a different property");
    let edited = store
        .append_norm_event(
            &f::sign(
                "edit",
                NormAct::Edit {
                    ledger: before.ledger.clone(),
                    authority: None,
                    vocabulary: old.vocabulary.clone(),
                    record: id.clone(),
                    previous: old.head.clone(),
                    fields_json: fields.to_string(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    store
        .append_norm_event(
            &f::sign(
                "reaccept",
                NormAct::Transition {
                    ledger: before.ledger.clone(),
                    authority: None,
                    vocabulary: old.vocabulary.clone(),
                    record: id.clone(),
                    previous: edited,
                    status: "accepted".into(),
                },
            ),
            &Boundary,
        )
        .unwrap();
    let after = store.norm_view(&Boundary).unwrap();
    let candidate = artifact(&[("main.py", "same")]);
    let prior = before.requirement_inventory().unwrap().requirements[&id]
        .requirement
        .clone()
        .unwrap();
    let mut host = Host {
        events: events(&store),
        automatic: Some(version("method")),
    };
    host.events[0].payload = observation(prior, candidate_identity(candidate.files()), true);
    let result = evaluate(&before, &candidate, &after, &candidate, &host);
    assert_eq!(result.requirements[&id].len(), 2);
    assert_eq!(result.requirements[&id][0].work, ImpactWork::Supported);
    assert!(matches!(
        result.requirements[&id][1].work,
        ImpactWork::Check { .. }
    ));
    assert!(result
        .authority_actions
        .contains(&ImpactAuthorityAction::RequirementChanged(id.clone())));
    host.automatic = Some(version(""));
    assert_eq!(
        evaluate(&before, &candidate, &after, &candidate, &host).requirements[&id][1].work,
        ImpactWork::ObservationGap
    );

    let current = after.requirement_inventory().unwrap().requirements[&id]
        .requirement
        .clone()
        .unwrap();
    host.events.last_mut().unwrap().payload =
        observation(current, candidate_identity(candidate.files()), true);
    let supported = evaluate(&before, &candidate, &after, &candidate, &host);
    assert!(supported.requirements[&id]
        .iter()
        .all(|entry| entry.work == ImpactWork::Supported));
}

#[test]
fn impact_empty_inventory_still_requires_policy_and_time_and_keeps_coverage_gaps() {
    let (store, _) = f::fixture(None, false);
    let view = store.norm_view(&Boundary).unwrap();
    let candidate = artifact(&[("main.py", "uncovered")]);
    let host = Host {
        events: events(&store),
        automatic: None,
    };
    let valid = evaluate(&view, &candidate, &view, &candidate, &host);
    assert!(valid.requirements.is_empty());
    assert_eq!(valid.resources.after.uncovered, ["main.py".into()].into());
    assert_eq!(valid.policy, version("policy"));
    assert_eq!(valid.time_basis, "captured");
    for fault in ["policy", "time"] {
        let mut policy = version("policy");
        if fault == "policy" {
            policy.digest.clear();
        }
        assert!(
            plan(
                ImpactInput {
                    before: &view,
                    before_artifact: &candidate,
                    after: &view,
                    candidate: &candidate,
                    policy: &policy,
                    time_basis: if fault == "time" { "" } else { "captured" },
                    evidence: &host.events
                },
                &host,
                ImpactLimits::default()
            )
            .is_err(),
            "{fault}"
        );
    }
}

#[test]
fn impact_retains_authority_rotation_as_a_distinct_action() {
    use whipplescript_store::norm::{NormActor, NormVerifier};
    struct RotationBoundary;
    let successor = NormActor {
        key_id: "successor".into(),
        ..f::actor()
    };
    impl NormVerifier for RotationBoundary {
        fn verify(&self, actor: &NormActor, bytes: &[u8], signature: &str) -> Result<(), String> {
            let successor = NormActor {
                key_id: "successor".into(),
                ..f::actor()
            };
            if (actor == &f::actor() || actor == &successor)
                && signature == crate::exec_http::sha256_hex(bytes)
            {
                Ok(())
            } else {
                Err("fixture signature mismatch".into())
            }
        }
        fn authorize_creation(&self, creator: &str, owner: &NormActor) -> Result<(), String> {
            Boundary.authorize_creation(creator, owner)
        }
    }
    let (mut store, id) = f::fixture(Some(f::template()), true);
    let before = store.norm_view(&Boundary).unwrap();
    let mut rotation = f::sign(
        "rotate",
        NormAct::Rotate {
            ledger: before.ledger.clone(),
            previous: before.authority_head.clone(),
            successor,
            frontier: before.frontier.iter().cloned().collect(),
        },
    );
    rotation.successor_signature = Some(rotation.signature.clone());
    store
        .append_norm_event(&rotation, &RotationBoundary)
        .unwrap();
    let after = store.norm_view(&RotationBoundary).unwrap();
    let candidate = artifact(&[("main.py", "same")]);
    let host = Host {
        events: events(&store),
        automatic: Some(version("method")),
    };
    let result = evaluate(&before, &candidate, &after, &candidate, &host);
    assert_eq!(
        result.authority_actions,
        [ImpactAuthorityAction::AuthorityChanged].into()
    );
    assert_eq!(result.requirements[&id].len(), 1);
}
