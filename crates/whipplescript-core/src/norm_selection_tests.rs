use super::*;
use crate::norm_evidence::*;
use serde_json::json;

struct Host {
    events: Vec<SelectionEvent>,
    authorized: BTreeSet<String>,
    contracts: bool,
    preservation_allowed: bool,
}
impl ReportVerifier for Host {
    fn verify_report_binding(&self, report: &TestReport) -> bool {
        self.events.iter().any(|e| matches!(&e.payload, SelectionPayload::Observation { report: r, .. } if r.as_ref() == report))
    }
    fn verify_assertion_exercise(
        &self,
        _: &TestReport,
        observation: &AssertionObservation,
    ) -> bool {
        observation.witness == "observed-call"
    }
}
impl PreservationVerifier for Host {
    fn verify_preservation_basis(&self, witness: &PreservationWitness) -> bool {
        self.events.iter().any(|e| matches!(&e.payload, SelectionPayload::Preservation { witness: w, .. } if w.as_ref() == witness))
    }
}
impl SelectionVerifier for Host {
    fn accepts_preservation(&self, query: &SelectionQuery, witness: &PreservationWitness) -> bool {
        self.preservation_allowed
            && query.time_basis == "captured-cut"
            && witness.context.boundary == version("closed-boundary")
    }
    fn verify_event(&self, e: &SelectionEvent) -> bool {
        self.events.contains(e)
    }
    fn accepts_contract(&self, _: &SelectionQuery, _: &ReportContract) -> bool {
        self.contracts
    }
    fn authorize_resolution(&self, _: &SelectionQuery, e: &SelectionEvent) -> bool {
        self.authorized.contains(&e.id)
    }
}
fn version(name: &str) -> EvidenceVersion {
    EvidenceVersion {
        name: name.into(),
        version: "1".into(),
        digest: name.into(),
    }
}
fn query(frontier: &[&str]) -> SelectionQuery {
    SelectionQuery {
        requirement: version("auth"),
        artifact: "candidate".into(),
        policy: version("policy"),
        time_basis: "captured-cut".into(),
        frontier: frontier.iter().map(|s| (*s).into()).collect(),
    }
}
fn observation(id: &str, passed: bool) -> SelectionEvent {
    let subject = EvidenceSubject {
        requirement: version("auth"),
        method: version("calls"),
        artifact: "candidate".into(),
    };
    SelectionEvent {
        id: id.into(),
        parents: BTreeSet::new(),
        payload: SelectionPayload::Observation {
            contract: ReportContract {
                subject: subject.clone(),
                cases: vec![RequiredCase {
                    id: "case".into(),
                    assertion: "authorize".into(),
                    expected: json!(true),
                }],
            },
            report: Box::new(TestReport {
                subject,
                provenance: Some(ArtifactProvenance::Interpreted {
                    source_frontier: "candidate".into(),
                    interpreter: "python".into(),
                    environment: "host".into(),
                }),
                completion: ReportCompletion::Complete,
                termination: if passed {
                    ProcessTermination::Success
                } else {
                    ProcessTermination::Failure
                },
                observations: vec![AssertionObservation {
                    case: "case".into(),
                    assertion: "authorize".into(),
                    actual: json!(passed),
                    witness: "observed-call".into(),
                }],
            }),
        },
    }
}
fn resolution(id: &str, old: &str, new: &str) -> SelectionEvent {
    SelectionEvent {
        id: id.into(),
        parents: BTreeSet::from([old.into(), new.into()]),
        payload: SelectionPayload::Resolution(EvidenceResolution {
            predecessor: old.into(),
            replacement: new.into(),
            requirement: version("auth"),
            artifact: "candidate".into(),
            reason: "authorized adjudication".into(),
        }),
    }
}
fn host(events: &[SelectionEvent], authorized: &[&str]) -> Host {
    Host {
        events: events.to_vec(),
        authorized: authorized.iter().map(|s| (*s).into()).collect(),
        contracts: true,
        preservation_allowed: true,
    }
}
#[test]
fn norm_selection_retains_concurrent_failure_and_passing_retries_in_every_order() {
    let mut events = vec![
        observation("fail", false),
        observation("pass", true),
        observation("retry", true),
    ];
    let q = query(&["fail", "pass", "retry"]);
    let h = host(&events, &[]);
    let original = select_evidence(&q, &events, &h).unwrap();
    assert_eq!(original.conformance, Conformance::Conflicted);
    assert_eq!(original.counterevidence, BTreeSet::from(["fail".into()]));
    events.reverse();
    assert_eq!(select_evidence(&q, &events, &h).unwrap(), original);
    if let SelectionPayload::Observation { report, .. } = &mut events[2].payload {
        report.termination = ProcessTermination::Success;
    }
    let h = host(&events, &[]);
    let view = select_evidence(&q, &events, &h).unwrap();
    assert_eq!(view.conformance, Conformance::Conflicted);
    assert!(view.unresolved.contains("fail"));
}
#[test]
fn norm_selection_resolves_only_visible_scoped_authorized_causal_acts_and_keeps_history() {
    let events = vec![
        observation("fail", false),
        observation("pass", true),
        resolution("resolve", "fail", "pass"),
    ];
    let h = host(&events, &["resolve"]);
    let q = query(&["resolve"]);
    let view = select_evidence(&q, &events, &h).unwrap();
    assert_eq!(view.conformance, Conformance::Satisfied);
    assert_eq!(view.history.len(), 3);
    assert_eq!(view.judgments["fail"].counterexamples.len(), 1);
    assert!(view.retired_by.contains_key("fail"));
    assert_eq!(
        select_evidence(&query(&["fail", "pass"]), &events, &h)
            .unwrap()
            .conformance,
        Conformance::Conflicted
    );
    for change in 0..6 {
        let mut altered = events.clone();
        let mut allowed = vec!["resolve"];
        if change == 0 {
            allowed.clear();
        }
        if change == 1 {
            altered[2].parents.remove("fail");
        }
        if change == 2 {
            altered[2].parents.remove("pass");
        }
        if let SelectionPayload::Resolution(r) = &mut altered[2].payload {
            if change == 3 {
                r.requirement = version("other");
            }
            if change == 4 {
                r.artifact = "other".into();
            }
            if change == 5 {
                r.reason.clear();
            }
        }
        let h = host(&altered, &allowed);
        let v = select_evidence(&query(&["fail", "pass", "resolve"]), &altered, &h).unwrap();
        assert_eq!(v.conformance, Conformance::Conflicted, "control {change}");
        assert!(v.resolution_diagnostics.contains_key("resolve"));
    }
}
#[test]
fn norm_selection_checks_graph_completeness_identity_and_authentication() {
    let events = vec![observation("pass", true)];
    let h = host(&events, &[]);
    assert!(select_evidence(&query(&["missing"]), &events, &h).is_err());
    assert!(select_evidence(
        &query(&["pass"]),
        &[events[0].clone(), events[0].clone()],
        &h
    )
    .is_err());
    let mut tampered = events.clone();
    if let SelectionPayload::Observation { report, .. } = &mut tampered[0].payload {
        report.termination = ProcessTermination::Unknown;
    }
    assert!(select_evidence(&query(&["pass"]), &tampered, &h).is_err());
    let mut bad = events.clone();
    bad[0].parents.insert("pass".into());
    assert!(select_evidence(&query(&["pass"]), &bad, &h).is_err());
    assert!(select_evidence(&query(&["pass"]), &bad, &host(&bad, &[])).is_err());
    bad[0].parents = BTreeSet::from(["missing".into()]);
    assert!(select_evidence(&query(&["pass"]), &bad, &host(&bad, &[])).is_err());
    let mut q = query(&["pass"]);
    q.policy.digest.clear();
    assert!(select_evidence(&q, &events, &h).is_err());
}
#[test]
fn norm_selection_separates_stale_unresolved_and_excluded_evidence() {
    let mut events = vec![observation("pass", true)];
    let mut q = query(&["pass"]);
    q.artifact = "new".into();
    assert_eq!(
        select_evidence(&q, &events, &host(&events, &[]))
            .unwrap()
            .conformance,
        Conformance::Stale
    );
    let mut h = host(&events, &[]);
    h.contracts = false;
    assert_eq!(
        select_evidence(&q, &events, &h).unwrap().conformance,
        Conformance::Unresolved
    );
    q.requirement = version("other");
    assert!(select_evidence(&q, &events, &h)
        .unwrap()
        .excluded
        .contains("pass"));
    if let SelectionPayload::Observation { report, .. } = &mut events[0].payload {
        report.observations.clear();
    }
    assert_eq!(
        select_evidence(&query(&["pass"]), &events, &host(&events, &[]))
            .unwrap()
            .conformance,
        Conformance::Unresolved
    );
    assert_eq!(
        select_evidence(&query(&[]), &[], &host(&[], &[]))
            .unwrap()
            .conformance,
        Conformance::Unresolved
    );
}
#[test]
fn norm_selection_chained_retirement_is_order_independent() {
    let mut events = vec![
        observation("a", false),
        observation("b", true),
        observation("c", false),
        resolution("r1", "a", "b"),
        resolution("r2", "b", "c"),
    ];
    events[4].parents.insert("r1".into());
    let h = host(&events, &["r1", "r2"]);
    let q = query(&["r2"]);
    let expected = select_evidence(&q, &events, &h).unwrap();
    assert_eq!(expected.conformance, Conformance::Violated);
    assert_eq!(expected.retired_by.len(), 2);
    events.reverse();
    assert_eq!(select_evidence(&q, &events, &h).unwrap(), expected);
}

fn reuse_event(id: &str, observation: &str) -> SelectionEvent {
    use crate::norm_preservation::*;
    let observations = vec![DependencyObservation {
        key: ObservationKey {
            resource: "src/auth.py".into(),
            aspect: ObservationAspect::Content,
        },
        value: ObservationValue::Present("unchanged-source".into()),
    }];
    SelectionEvent {
        id: id.into(),
        parents: BTreeSet::from([observation.into()]),
        payload: SelectionPayload::Preservation {
            observation: observation.into(),
            witness: Box::new(PreservationWitness {
                id: id.into(),
                context: PreservationContext {
                    requirement: version("auth"),
                    method: version("calls"),
                    policy: version("policy"),
                    source_artifact: "candidate".into(),
                    target_artifact: "candidate-new".into(),
                    boundary: version("closed-boundary"),
                },
                basis: PreservationBasis::CompleteExact,
                mode: PreservationMode::Deterministic,
                source: observations.clone(),
                target: observations,
                gaps: BTreeSet::new(),
            }),
        },
    }
}
fn reuse_query(frontier: &[&str]) -> SelectionQuery {
    let mut q = query(frontier);
    q.artifact = "candidate-new".into();
    q
}
fn retarget(event: &mut SelectionEvent) {
    if let SelectionPayload::Observation { contract, report } = &mut event.payload {
        contract.subject.artifact = "candidate-new".into();
        report.subject.artifact = "candidate-new".into();
    }
}
#[test]
fn norm_reuse_transports_positive_and_counterevidence_without_relabelling_history() {
    for passed in [false, true] {
        let events = vec![observation("old", passed), reuse_event("witness", "old")];
        let view =
            select_evidence(&reuse_query(&["witness"]), &events, &host(&events, &[])).unwrap();
        assert_eq!(
            view.conformance,
            if passed {
                Conformance::Satisfied
            } else {
                Conformance::Violated
            }
        );
        assert!(view.stale.is_empty());
        assert!(view.reuse_evaluations["witness"].applied);
        assert_eq!(view.reused_by["old"], BTreeSet::from(["witness".into()]));
        assert_eq!(view.judgments["old"].reported_subject.artifact, "candidate");
        assert_eq!(view.judgments["old"].subject.artifact, "candidate");
        assert_eq!(view.history["old"], events[0]);
    }
    let mut events = vec![observation("old", false), reuse_event("witness", "old")];
    if let SelectionPayload::Observation { report, .. } = &mut events[0].payload {
        report.termination = ProcessTermination::Success;
    }
    let view = select_evidence(&reuse_query(&["witness"]), &events, &host(&events, &[])).unwrap();
    assert_eq!(view.conformance, Conformance::Violated);
    assert!(view.unresolved.contains("old"));
}
#[test]
fn norm_reuse_cannot_manufacture_support_or_bypass_requirement_policy() {
    let mut events = vec![observation("old", true), reuse_event("witness", "old")];
    let mut h = host(&events, &[]);
    h.contracts = false;
    let view = select_evidence(&reuse_query(&["witness"]), &events, &h).unwrap();
    assert_eq!(view.conformance, Conformance::Unresolved);
    assert!(view.reuse_evaluations["witness"]
        .diagnostics
        .contains(&ReuseDiagnostic::UnsupportedObservation));
    if let SelectionPayload::Observation { report, .. } = &mut events[0].payload {
        report.observations.clear();
    }
    let view = select_evidence(&reuse_query(&["witness"]), &events, &host(&events, &[])).unwrap();
    assert_eq!(view.conformance, Conformance::Unresolved);
    assert!(!view.reuse_evaluations["witness"].applied);
}
#[test]
fn norm_reuse_requires_captured_linked_identity_and_live_policy() {
    let events = vec![observation("old", true), reuse_event("witness", "old")];
    let q = reuse_query(&["old", "witness"]);
    let view = select_evidence(&reuse_query(&["old"]), &events, &host(&events, &[])).unwrap();
    assert_eq!(view.conformance, Conformance::Stale);
    assert!(view.reuse_evaluations.is_empty());
    for change in 0..5 {
        let mut altered = events.clone();
        let mut current = q.clone();
        if change == 0 {
            altered[1].parents.clear();
        }
        if change == 1 {
            if let SelectionPayload::Preservation { witness, .. } = &mut altered[1].payload {
                witness.id = "other".into();
            }
        }
        if change == 2 {
            current.time_basis = "later-expired-cut".into();
        }
        let mut h = host(&altered, &[]);
        if change == 3 {
            h.preservation_allowed = false;
        }
        if change == 4 {
            h.events.pop(); /* actual event authentication cannot be bypassed */
        }
        let result = select_evidence(&current, &altered, &h);
        if change == 4 {
            assert!(result.is_err());
            continue;
        }
        let view = result.unwrap();
        assert_eq!(view.conformance, Conformance::Stale, "control {change}");
        assert!(!view.reuse_evaluations["witness"].applied);
    }
}
#[test]
fn norm_reuse_refuses_mismatched_or_incomplete_witnesses_and_reports_dangling_links() {
    use crate::norm_preservation::*;
    let original = vec![observation("old", true), reuse_event("witness", "old")];
    for change in 0..11 {
        let mut events = original.clone();
        if let SelectionPayload::Preservation {
            observation,
            witness,
        } = &mut events[1].payload
        {
            match change {
                0 => witness.context.requirement = version("other"),
                1 => witness.context.method = version("other"),
                2 => witness.context.policy = version("other"),
                3 => witness.context.source_artifact = "other".into(),
                4 => witness.context.target_artifact = "other".into(),
                5 => witness.context.boundary = version("other"),
                6 => witness.basis = PreservationBasis::PartialTrace,
                7 => witness.mode = PreservationMode::Sampled,
                8 => witness.target[0].value = ObservationValue::Present("changed".into()),
                9 => {
                    witness.gaps.insert("escaped read".into());
                }
                _ => *observation = "missing".into(),
            }
        }
        let view =
            select_evidence(&reuse_query(&["witness"]), &events, &host(&events, &[])).unwrap();
        assert_eq!(view.conformance, Conformance::Stale, "control {change}");
        assert!(!view.reuse_evaluations["witness"].applied);
        if change == 10 {
            assert!(view.reuse_evaluations["witness"]
                .diagnostics
                .contains(&ReuseDiagnostic::UnknownObservation));
        }
    }
}
#[test]
fn norm_reuse_preserves_conflict_and_requires_resolutions_to_know_the_witness() {
    let mut events = vec![
        observation("old", false),
        reuse_event("witness", "old"),
        observation("fresh", true),
        resolution("resolve", "old", "fresh"),
    ];
    retarget(&mut events[2]);
    if let SelectionPayload::Resolution(r) = &mut events[3].payload {
        r.artifact = "candidate-new".into();
    }
    let q = reuse_query(&["witness", "resolve"]);
    let h = host(&events, &["resolve"]);
    let view = select_evidence(&q, &events, &h).unwrap();
    assert_eq!(view.conformance, Conformance::Conflicted);
    assert!(view.resolution_diagnostics.contains_key("resolve"));
    events[3].parents.insert("witness".into());
    let h = host(&events, &["resolve"]);
    let view = select_evidence(&q, &events, &h).unwrap();
    assert_eq!(view.conformance, Conformance::Satisfied);
    assert_eq!(view.judgments["old"].counterexamples.len(), 1);
    events.reverse();
    assert_eq!(select_evidence(&q, &events, &h).unwrap(), view);
}
