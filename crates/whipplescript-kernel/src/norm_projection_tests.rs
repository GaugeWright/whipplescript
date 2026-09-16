use super::*;
use crate::norm_impact::{plan_projected, ImpactLimits, ImpactWork, ProjectedImpactInput};
fn impact<'a>(
    before: &'a whipplescript_store::norm::NormView,
    after: &'a whipplescript_store::norm::NormView,
    artifact: &'a whipplescript_store::norm_artifact::CapturedArtifact,
    policy: &'a EvidenceVersion,
) -> ProjectedImpactInput<'a> {
    ProjectedImpactInput {
        before,
        before_artifact: artifact,
        after,
        candidate: artifact,
        policy,
        time_basis: "captured",
    }
}
use crate::norm_execution::{fixtures::*, PreparedNormExecution};
use crate::norm_publication::{ObservationSigning, PreparedObservationPublication};
use crate::norm_runner::ObserverIntegrity;
use whipplescript_core::norm_evidence::EvidenceVersion;
use whipplescript_core::norm_selection::Conformance;
use whipplescript_core::vocabulary::Vocabulary;
use whipplescript_store::norm::NormAct;

struct Policy {
    protected_only: bool,
}
impl ExecutionSelectionPolicy for Policy {
    fn accepts(&self, query: &SelectionQuery, execution: &VerifiedNormExecution) -> bool {
        query.policy == policy_version()
            && query.time_basis == "captured"
            && (!self.protected_only
                || execution.observation().observation_integrity
                    == ObserverIntegrity::ProtectedInterpreter {})
    }
}
fn policy_version() -> EvidenceVersion {
    EvidenceVersion {
        name: "fixture-policy".into(),
        version: "1".into(),
        digest: "installed".into(),
    }
}
#[test]
fn projection_recovers_published_evidence_and_preserves_causal_gaps() {
    for (actual, timeout) in [(false, false), (true, false), (true, true)] {
        let mut vocabulary_definition = observation_vocabulary();
        vocabulary_definition.editing = Some(vocabulary_definition.creation.clone());
        let (mut ledger, requirement) =
            fixture_with_custom_observation(Some(template()), true, Some(vocabulary_definition));
        let before = history(&ledger);
        let artifact = artifact("def allow(user): return False");
        let prepared = PreparedNormExecution::prepare(
            &before,
            &Boundary,
            &artifact,
            &script(),
            selection(&before.anchor().checkpoint.ledger, &requirement),
        )
        .unwrap();
        let kernel = journal_execution(
            whipplescript_store::SqliteStore::open_in_memory().unwrap(),
            &prepared,
            &receipt(&prepared, actual, timeout),
            actual || timeout,
        );
        let verified = prepared
            .verify_settled(kernel.store(), "instance", "run")
            .unwrap();
        let vocabulary = Vocabulary::new(observation_vocabulary().definition)
            .unwrap()
            .reference()
            .clone();
        let publication = PreparedObservationPublication::prepare(
            &verified,
            &before,
            kernel.store(),
            &Boundary,
            ObservationSigning {
                vocabulary: &vocabulary,
                authority: None,
                actor: &actor(),
                created_at: "t1",
            },
            |s| Ok(crate::exec_http::sha256_hex(&s.signing_bytes().unwrap())),
        )
        .unwrap();
        let published = publication.submit(&mut ledger, &Boundary).unwrap();
        let current = history(&ledger);
        let mut roles = BTreeMap::from([
            (
                ledger.norm_view(&Boundary).unwrap().records[&requirement]
                    .vocabulary
                    .clone(),
                ProjectionRole::Context,
            ),
            (vocabulary.clone(), ProjectionRole::PublishedExecution),
        ]);
        let recover = |instance: &str, run: &str| {
            PreparedNormExecution::recover_settled(
                &current,
                &Boundary,
                &artifact,
                kernel.store(),
                instance,
                run,
            )
        };
        let projected = EvidenceProjection::capture(&current, &roles, 100, recover).unwrap();
        let query = SelectionQuery {
            requirement: verified.contract().subject.requirement.clone(),
            artifact: verified.contract().subject.artifact.clone(),
            policy: policy_version(),
            time_basis: "captured".into(),
            frontier: current.anchor().frontier,
        };
        let policy = Policy {
            protected_only: false,
        };
        let result = projected.select(&query, &policy).unwrap();
        assert!(result.gaps.is_empty());
        let before_view = before.project(None, &Boundary).unwrap();
        let current_view = current.project(None, &Boundary).unwrap();
        let version = policy_version();
        let plan = plan_projected(
            impact(&before_view, &current_view, &artifact, &version),
            &projected,
            &policy,
            |_, _| None,
            ImpactLimits::default(),
        )
        .unwrap();
        assert!(plan.evidence_gaps.is_empty());
        assert_eq!(
            plan.requirements[&requirement][0].work,
            if actual {
                ImpactWork::Repair
            } else {
                ImpactWork::Supported
            }
        );

        assert_eq!(
            result.selection.conformance,
            if actual {
                Conformance::Violated
            } else {
                Conformance::Satisfied
            }
        );
        assert!(result.selection.history.contains_key(published.event_id()));
        assert_eq!(projected.events().len(), current.events().count());
        let old = SelectionQuery {
            frontier: before.anchor().frontier,
            ..query.clone()
        };
        let result = projected.select(&old, &policy).unwrap();
        assert!(!result.selection.history.contains_key(published.event_id()));
        assert_eq!(result.selection.conformance, Conformance::Unresolved);
        assert_eq!(
            projected
                .select(
                    &query,
                    &Policy {
                        protected_only: true
                    }
                )
                .unwrap()
                .selection
                .conformance,
            Conformance::Unresolved
        );
        let protected = Policy {
            protected_only: true,
        };
        let verifier = ProjectionVerifier {
            projection: &projected,
            policy: &protected,
            query: &query,
        };
        assert!(!verifier.verify_report_binding(&verified.observation().report));
        assert!(!verifier.verify_assertion_exercise(
            &verified.observation().report,
            &verified.observation().report.observations[0]
        ));
        assert!(!verifier.accepts_contract(&query, verified.contract()));
        let missing =
            EvidenceProjection::capture(
                &current,
                &roles,
                100,
                |_, _| Err("missing receipt".into()),
            )
            .unwrap();
        assert!(matches!(
            missing.gaps()[published.event_id()],
            ProjectionGap::ExecutionUnavailable { .. }
        ));
        assert_eq!(missing.select(&query, &policy).unwrap().gaps.len(), 1);
        assert!(missing.select(&old, &policy).unwrap().gaps.is_empty());
        let gap_plan = plan_projected(
            impact(&before_view, &current_view, &artifact, &version),
            &missing,
            &policy,
            |_, _| panic!("verification gaps must not schedule replacement checks"),
            ImpactLimits::default(),
        )
        .unwrap();
        assert_eq!(gap_plan.evidence_gaps.len(), 1);
        assert_eq!(
            gap_plan.requirements[&requirement][0].work,
            ImpactWork::VerifyEvidence
        );
        let historical = plan_projected(
            impact(&before_view, &before_view, &artifact, &version),
            &missing,
            &policy,
            |_, _| Some(verified.contract().subject.method.clone()),
            ImpactLimits::default(),
        )
        .unwrap();
        assert!(historical.evidence_gaps.is_empty());
        assert!(matches!(
            historical.requirements[&requirement][0].work,
            ImpactWork::Check { .. }
        ));
        for fault in ["ledger", "closure", "unknown"] {
            let mut changed = current_view.clone();
            match fault {
                "ledger" => changed.ledger.push_str("-other"),
                "closure" => changed.frontier = before_view.frontier.clone(),
                _ => changed.frontier = ["unknown".into()].into(),
            }
            assert!(
                plan_projected(
                    impact(&before_view, &changed, &artifact, &version),
                    &projected,
                    &policy,
                    |_, _| None,
                    ImpactLimits::default()
                )
                .is_err(),
                "{fault}"
            );
        }

        assert!(
            EvidenceProjection::capture(&current, &roles, 0, |_, _| panic!(
                "budget before recovery"
            ))
            .is_err()
        );
        roles.remove(&vocabulary);
        let unsupported = EvidenceProjection::capture(&current, &roles, 100, |_, _| {
            panic!("unknown vocabulary cannot recover")
        })
        .unwrap();
        assert!(matches!(
            unsupported.gaps()[published.event_id()],
            ProjectionGap::UnknownVocabulary { .. }
        ));
        roles.insert(vocabulary.clone(), ProjectionRole::PublishedExecution);
        // A newly admitted signed claim with altered effect is not the verified run.
        let mut fields = crate::norm_publication::fields(&verified).unwrap();
        fields["effect"] = serde_json::json!("invented-effect");
        let forged = ledger
            .append_norm_event(
                &sign(
                    "altered-publication",
                    NormAct::Create {
                        ledger: current.anchor().checkpoint.ledger,
                        authority: None,
                        vocabulary: vocabulary.clone(),
                        fields_json: fields.to_string(),
                    },
                ),
                &Boundary,
            )
            .unwrap();
        // Editing the materialized record must not rewrite the earlier event.
        ledger
            .append_norm_event(
                &sign(
                    "edit-publication",
                    NormAct::Edit {
                        ledger: current.anchor().checkpoint.ledger,
                        authority: None,
                        vocabulary,
                        record: published.event_id().into(),
                        previous: published.event_id().into(),
                        fields_json: fields.to_string(),
                    },
                ),
                &Boundary,
            )
            .unwrap();
        let after = history(&ledger);
        let projected = EvidenceProjection::capture(&after, &roles, 100, |instance, run| {
            PreparedNormExecution::recover_settled(
                &after,
                &Boundary,
                &artifact,
                kernel.store(),
                instance,
                run,
            )
        })
        .unwrap();
        let after_query = SelectionQuery {
            frontier: after.anchor().frontier,
            ..query.clone()
        };
        let selected = projected.select(&after_query, &policy).unwrap();
        assert!(
            selected
                .selection
                .history
                .contains_key(published.event_id()),
            "edited frontier must retain its original observation ancestor"
        );
        assert_eq!(
            selected.selection.conformance,
            if actual {
                Conformance::Violated
            } else {
                Conformance::Satisfied
            }
        );
        assert_eq!(selected.gaps.len(), 1);
        let after_view = after.project(None, &Boundary).unwrap();
        let plan = plan_projected(
            impact(&before_view, &after_view, &artifact, &version),
            &projected,
            &policy,
            |_, _| None,
            ImpactLimits::default(),
        )
        .unwrap();
        assert_eq!(plan.evidence_gaps.len(), 1);
        assert_eq!(
            plan.requirements[&requirement][0].work,
            if actual {
                ImpactWork::Repair
            } else {
                ImpactWork::VerifyEvidence
            }
        );

        assert_eq!(
            projected.gaps()[&forged],
            ProjectionGap::PublicationMismatch
        );
        assert!(matches!(
            projected
                .events()
                .iter()
                .find(|e| e.id == published.event_id())
                .unwrap()
                .payload,
            SelectionPayload::Observation { .. }
        ));
    }
}

#[test]
fn projected_impact_keeps_gaps_and_history_checks_with_no_active_requirements() {
    let (mut ledger, requirement) = fixture_with_observation(None, false, true);
    let before = ledger.norm_view(&Boundary).unwrap();
    let vocabulary = Vocabulary::new(observation_vocabulary().definition)
        .unwrap()
        .reference()
        .clone();
    let malformed = ledger.append_norm_event(&sign("empty-publication", NormAct::Create {
        ledger: before.ledger.clone(), authority: None, vocabulary: vocabulary.clone(),
        fields_json: serde_json::json!({"instance":"instance","run":"","effect":"observe","invocation_json":"","observation_json":""}).to_string(),
    }), &Boundary).unwrap();
    let captured = history(&ledger);
    let after = captured.project(None, &Boundary).unwrap();
    let roles = [
        (
            before.records[&requirement].vocabulary.clone(),
            ProjectionRole::Context,
        ),
        (vocabulary, ProjectionRole::PublishedExecution),
    ]
    .into();
    let projection = EvidenceProjection::capture(&captured, &roles, 100, |_, _| {
        panic!("malformed coordinates cannot recover")
    })
    .unwrap();
    let artifact = artifact("uncovered");
    let version = policy_version();
    let policy = Policy {
        protected_only: false,
    };
    let plan = plan_projected(
        impact(&before, &after, &artifact, &version),
        &projection,
        &policy,
        |_, _| panic!("no active requirements"),
        ImpactLimits::default(),
    )
    .unwrap();
    assert!(plan.requirements.is_empty());
    assert_eq!(
        plan.evidence_gaps[&malformed],
        ProjectionGap::MalformedPublication
    );
    let mut unknown = after.clone();
    unknown.frontier = ["unknown".into()].into();
    let budget_error = plan_projected(
        impact(&before, &unknown, &artifact, &version),
        &projection,
        &policy,
        |_, _| None,
        ImpactLimits {
            max_events: 0,
            ..ImpactLimits::default()
        },
    )
    .unwrap_err();
    assert!(format!("{budget_error:?}").contains("event budget"));
    for fault in [
        "empty-frontier",
        "unknown",
        "closure",
        "ledger",
        "budget",
        "policy",
    ] {
        let mut view = after.clone();
        let mut limits = ImpactLimits::default();
        let mut policy_id = version.clone();
        match fault {
            "empty-frontier" => view.frontier.clear(),
            "unknown" => view.frontier = ["unknown".into()].into(),
            "closure" => view.frontier = before.frontier.clone(),
            "ledger" => view.ledger.push_str("-other"),
            "budget" => limits.max_events = 0,
            _ => policy_id.digest.clear(),
        }
        let mut before_view = before.clone();
        if fault == "ledger" {
            before_view.ledger = view.ledger.clone();
        }
        assert!(
            plan_projected(
                impact(&before_view, &view, &artifact, &policy_id),
                &projection,
                &policy,
                |_, _| None,
                limits
            )
            .is_err(),
            "{fault}"
        );
    }
}
