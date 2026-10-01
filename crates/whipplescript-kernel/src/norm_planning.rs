//! Host-owned impact query composition shared by native and hosted embeddings.
use crate::norm_buck2_execution::{is_run_instance, VerifiedBuck2Execution, BUCK2_UNAVAILABLE};
use crate::norm_execution::{PreparedNormExecution, SupportTemplate};
use crate::norm_execution_policy::EvidencePolicy;
use crate::norm_impact::{plan_projected, ImpactLimits, ProjectedImpactInput};
use crate::norm_projection::VerifiedExecution;
use crate::norm_projection::{EvidenceProjection, ProjectionRole};
use crate::norm_runner::PythonRuntime;
use serde::Deserialize;
use std::collections::BTreeMap;
use whipplescript_core::norm_evidence::EvidenceVersion;
use whipplescript_core::vocabulary::VocabularyRef;
use whipplescript_store::norm::NormVerifier;
use whipplescript_store::norm_commands::NormArtifactCapture;
use whipplescript_store::norm_history::CapturedNormHistory;
use whipplescript_store::RuntimeStore;

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationWire {
    capability: String,
    roles: Vec<Role>,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Role {
    vocabulary: VocabularyRef,
    interpretation: Interpretation,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Interpretation {
    Context,
    PublishedExecution,
    /// Claims over regions (norm-plane §7): context to evidence projection,
    /// and the reservations a gated ref's admission fences.
    Reservation,
    /// Methods whose positive support is insufficient for gated admission
    /// while their reliability is unresolved (norm-plane §3.5, N1).
    Quarantine,
    /// Fixed-budget statistical policies that can recover a quarantined
    /// method (norm-plane §3.5).
    SamplingPolicy,
    /// Scoped, expiring, authorized exceptions to a gated requirement
    /// (norm-plane §5).
    Exception,
}
/// A requirement the host could discover no installed method for.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MethodGap {
    pub requirement: Option<EvidenceVersion>,
    pub reason: String,
}

/// A plan and the exact ledger state it was computed at: the read anchor the
/// history was captured under, and the two frontiers it projected.
pub struct Planned {
    pub anchor: whipplescript_store::norm_history::NormReadAnchor,
    pub before_frontier: std::collections::BTreeSet<String>,
    pub after_frontier: std::collections::BTreeSet<String>,
    pub plan: crate::norm_impact::ImpactPlan,
    pub method_gaps: BTreeMap<String, Vec<MethodGap>>,
    /// Fingerprints of the installations actually read for automatic discovery,
    /// with private capture retained for an embedding's final recapture.
    pub method_installation: crate::norm_discovery::MethodInstallationCapture,
    /// Each witnessed record's derived current conformance at the candidate.
    pub conformance: Vec<Conformance>,
    /// Conflicts among live claims at the after frontier (norm-plane §7).
    pub reservation_conflicts: Vec<whipplescript_store::norm_reservations::ReservationConflict>,
    /// Methods whose runs call for an investigation, each with the nonce that
    /// files it once (norm-plane §3.5).
    pub investigations: Vec<crate::norm_reliability::Investigation>,
}

/// A witnessed record's derived current conformance (norm-plane §6, D1): the
/// status its history reached, whether the witness that admitted it holds at
/// the after frontier, and the work each requirement it relies on needs at the
/// candidate. `current` is `holds` only when the witness holds and every one of
/// them is supported, `contradicted` when any needs repair, and otherwise
/// `stale`. The history is never revised by it.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Conformance {
    pub record: String,
    pub status: String,
    pub family: String,
    pub holds: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub requirements: BTreeMap<String, Vec<String>>,
    pub current: &'static str,
}

/// Derive the conformance of every witnessed record in `view` from a plan of
/// the candidate.
pub fn conformance(
    view: &whipplescript_store::norm::NormView,
    plan: &crate::norm_impact::ImpactPlan,
) -> Vec<Conformance> {
    view.witnessed_records()
        .into_iter()
        .map(|witnessed| {
            let requirements: BTreeMap<String, Vec<String>> = witnessed
                .relied
                .iter()
                .map(|requirement| {
                    let work = plan
                        .requirements
                        .get(requirement)
                        .map(|impacts| {
                            impacts
                                .iter()
                                .map(|impact| {
                                    serde_json::to_value(&impact.work)
                                        .ok()
                                        .and_then(|work| {
                                            work.get("kind")
                                                .and_then(|kind| kind.as_str())
                                                .map(str::to_owned)
                                        })
                                        .unwrap_or_default()
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    (requirement.clone(), work)
                })
                .collect();
            let needs = |kind: &str| requirements.values().flatten().any(|work| work == kind);
            let supported = requirements
                .values()
                .all(|work| !work.is_empty() && work.iter().all(|kind| kind == "supported"));
            let current = if needs("repair") {
                "contradicted"
            } else if witnessed.holds && supported {
                "holds"
            } else {
                "stale"
            };
            Conformance {
                record: witnessed.record,
                status: witnessed.status,
                family: witnessed.family,
                holds: witnessed.holds,
                reason: witnessed.reason,
                requirements,
                current,
            }
        })
        .collect()
}

impl Planned {
    /// The query's answer, as `norm impact` has always returned it.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "anchor": self.anchor,
            "before_frontier": self.before_frontier,
            "after_frontier": self.after_frontier,
            "plan": self.plan,
            "method_gaps": self.method_gaps,
            "method_installation": self.method_installation,
            "conformance": self.conformance,
            "reservation_conflicts": self.reservation_conflicts,
            "investigations": self.investigations,
        })
    }
}

/// Validated embedding configuration, never part of a query request.
pub struct PlanningConfiguration {
    identity: EvidenceVersion,
    capability: String,
    roles: BTreeMap<VocabularyRef, ProjectionRole>,
    reservations: std::collections::BTreeSet<VocabularyRef>,
    reliability: crate::norm_reliability::ReliabilityVocabularies,
}
impl PlanningConfiguration {
    pub fn parse(configured: &str) -> Result<Self, String> {
        let mut configuration: ConfigurationWire =
            serde_json::from_str(configured).map_err(|error| error.to_string())?;
        if configuration.capability.trim().is_empty() {
            return Err("norm planning requires a named installed capability".into());
        }
        configuration
            .roles
            .sort_by(|left, right| left.vocabulary.cmp(&right.vocabulary));
        let identity = EvidenceVersion {
            name: "whipplescript.norm.planning".into(),
            version: "1".into(),
            digest: format!(
                "sha256:{}",
                crate::exec_http::sha256_hex(
                    &serde_json::to_vec(&configuration).map_err(|error| error.to_string())?
                )
            ),
        };
        let mut roles = BTreeMap::new();
        let mut reservations = std::collections::BTreeSet::new();
        let mut reliability = crate::norm_reliability::ReliabilityVocabularies::default();
        for role in configuration.roles {
            if [
                &role.vocabulary.name,
                &role.vocabulary.version,
                &role.vocabulary.digest,
            ]
            .iter()
            .any(|part| part.trim().is_empty())
            {
                return Err("norm planning vocabulary identities must be complete".into());
            }
            let interpretation = match role.interpretation {
                Interpretation::Context => ProjectionRole::Context,
                Interpretation::PublishedExecution => ProjectionRole::PublishedExecution,
                Interpretation::Reservation => {
                    reservations.insert(role.vocabulary.clone());
                    ProjectionRole::Context
                }
                Interpretation::Quarantine => {
                    reliability.quarantines.insert(role.vocabulary.clone());
                    ProjectionRole::Context
                }
                Interpretation::SamplingPolicy => {
                    reliability.policies.insert(role.vocabulary.clone());
                    ProjectionRole::Context
                }
                Interpretation::Exception => {
                    reliability.exceptions.insert(role.vocabulary.clone());
                    ProjectionRole::Context
                }
            };
            if roles.insert(role.vocabulary, interpretation).is_some() {
                return Err("norm planning vocabulary interpretations must be unique".into());
            }
        }
        Ok(Self {
            identity,
            capability: configuration.capability,
            roles,
            reservations,
            reliability,
        })
    }

    /// The vocabularies the host interprets as quarantines, sampling
    /// policies and exceptions (norm-plane §3.5, §5).
    pub fn reliability_vocabularies(&self) -> &crate::norm_reliability::ReliabilityVocabularies {
        &self.reliability
    }

    /// The vocabularies the host interprets as reservations.
    pub fn reservation_vocabularies(&self) -> &std::collections::BTreeSet<VocabularyRef> {
        &self.reservations
    }

    /// Exact host interpretation, independent of configuration role order.
    pub fn identity(&self) -> &EvidenceVersion {
        &self.identity
    }
}

/// All authority-bearing inputs come from the embedding. Cut and frontier
/// coordinates select data through these readers; they confer no authority.
pub struct ImpactQuery<'a, S: RuntimeStore> {
    pub configuration: &'a PlanningConfiguration,
    pub history: &'a CapturedNormHistory,
    pub verifier: &'a dyn NormVerifier,
    pub runtime: &'a S,
    pub artifacts: &'a NormArtifactCapture<'a>,
    pub before_cut: &'a str,
    pub after_cut: &'a str,
    pub before_frontier: Option<&'a [String]>,
    pub after_frontier: Option<&'a [String]>,
    /// The host's installed evidence policy: the protected interpreter's
    /// alone, or on a native host, beside Buck2 test runs.
    pub policy: &'a dyn EvidencePolicy,
}

/// Read-only composition: no enqueue, publication, or ref-movement capability.
/// The verifier checks an actual host installation binding, not just the policy.
pub fn execute<S: RuntimeStore>(
    input: ImpactQuery<'_, S>,
    verify_runtime: impl Fn(&PythonRuntime) -> Result<(), String>,
) -> Result<serde_json::Value, String> {
    plan(input, verify_runtime).map(|planned| planned.to_json())
}

/// The same composition, typed, for a door that must act on its answer.
pub fn plan<S: RuntimeStore>(
    input: ImpactQuery<'_, S>,
    verify_runtime: impl Fn(&PythonRuntime) -> Result<(), String>,
) -> Result<Planned, String> {
    let ImpactQuery {
        configuration,
        history,
        verifier,
        runtime,
        artifacts,
        before_cut,
        after_cut,
        before_frontier,
        after_frontier,
        policy,
    } = input;
    let before = history
        .project(before_frontier, verifier)
        .map_err(|error| format!("{error:?}"))?;
    let after = history
        .project(after_frontier, verifier)
        .map_err(|error| format!("{error:?}"))?;
    let before_artifact = artifacts(before_cut).map_err(|error| format!("{error:?}"))?;
    let candidate = artifacts(after_cut).map_err(|error| format!("{error:?}"))?;
    let projection = EvidenceProjection::capture(
        history,
        &configuration.roles,
        ImpactLimits::default().max_events,
        |instance, run| -> Result<VerifiedExecution, String> {
            if is_run_instance(instance) {
                // A host that runs no Buck2 recovers no Buck2 run: its
                // publication is an explicit gap, never support.
                if !policy.runs_buck2_tests() {
                    return Err(BUCK2_UNAVAILABLE.into());
                }
                return VerifiedBuck2Execution::recover(
                    history, verifier, artifacts, runtime, instance, run,
                )
                .map(Into::into);
            }
            PreparedNormExecution::recover_with_artifacts(
                history, verifier, artifacts, runtime, instance, run,
            )
            .map(Into::into)
        },
    )?;
    let method_gaps = std::cell::RefCell::new(BTreeMap::<String, Vec<MethodGap>>::new());
    let discovery = crate::norm_discovery::DiscoveryReads::default();
    let runs_buck2 = policy.runs_buck2_tests();
    let plan = plan_projected(
        ProjectedImpactInput {
            before: &before,
            before_artifact: &before_artifact,
            after: &after,
            candidate: &candidate,
            policy: policy.identity(),
            time_basis: policy.time_basis(),
        },
        &projection,
        policy,
        |requirement, artifact| {
            let found = match crate::norm_execution::support_template(requirement) {
                // A Buck2 template is its own method; only a host that runs
                // Buck2 can schedule it.
                // MUTATION-SUCCESS-EXPR: crate::norm_buck2_execution::requirement_support(requirement).map(|support| support.method())
                Ok(SupportTemplate::Buck2Tests(_)) if !runs_buck2 => Err(BUCK2_UNAVAILABLE.into()),
                Ok(SupportTemplate::Buck2Tests(_)) => {
                    crate::norm_buck2_execution::requirement_support(requirement)
                        .map(|support| support.method())
                }
                _ => discovery.discover(
                    runtime,
                    &configuration.capability,
                    requirement,
                    artifact,
                    &verify_runtime,
                ),
            };
            match found {
                Ok(method) => Some(method),
                Err(reason) => {
                    method_gaps
                        .borrow_mut()
                        .entry(requirement.source.id.clone())
                        .or_default()
                        .push(MethodGap {
                            requirement: requirement.requirement.clone(),
                            reason,
                        });
                    None
                }
            }
        },
        ImpactLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let mut plan = plan;
    // Whether an observation's run was prepared against a frontier that held
    // an act: the causal past of the frontier its intent recorded.
    let parents: BTreeMap<&str, &[String]> = history
        .events()
        .map(|event| (event.event_id.as_str(), event.parents.as_slice()))
        .collect();
    let prepared_after = |observation: &str, act: &str| {
        let Some(execution) = projection.execution(observation) else {
            return false;
        };
        let mut pending: Vec<&str> = execution
            .anchor()
            .frontier
            .iter()
            .map(String::as_str)
            .collect();
        let mut seen = std::collections::BTreeSet::new();
        while let Some(event) = pending.pop() {
            if event == act {
                return true;
            }
            if seen.insert(event) {
                pending.extend(
                    parents
                        .get(event)
                        .into_iter()
                        .flat_map(|up| up.iter().map(String::as_str)),
                );
            }
        }
        false
    };
    crate::norm_reliability::apply(
        &mut plan,
        &after,
        &configuration.reliability,
        &prepared_after,
    );
    let conformance = conformance(&after, &plan);
    let reservation_conflicts = after.reservation_conflicts();
    let mut observed = BTreeMap::new();
    for impact in plan.requirements.values().flatten() {
        let Some(selection) = &impact.selection else {
            continue;
        };
        for (event, judgment) in &selection.judgments {
            observed.insert(event.clone(), judgment.clone());
        }
    }
    let investigations =
        crate::norm_reliability::investigations(observed.iter().map(|(event, judgment)| {
            crate::norm_reliability::Observed {
                event,
                method: &judgment.subject.method,
                artifact: &judgment.subject.artifact,
                outcome: &judgment.outcome,
                counterexample: !judgment.counterexamples.is_empty(),
                diagnosed: !judgment.diagnostics.is_empty(),
            }
        }));
    let method_installation = discovery.finish()?;
    method_installation.revalidate(runtime, &verify_runtime)?;
    Ok(Planned {
        anchor: history.anchor(),
        before_frontier: before.frontier,
        after_frontier: after.frontier,
        plan,
        method_gaps: method_gaps.into_inner(),
        method_installation,
        conformance,
        reservation_conflicts,
        investigations,
    })
}

#[cfg(test)]
mod configuration_tests {
    use super::PlanningConfiguration;
    use serde_json::json;

    fn vocabulary(name: &str) -> serde_json::Value {
        json!({"name": name, "version": "1", "digest": format!("sha256:{name}")})
    }

    /// The host's planning configuration refuses what would let a query or a
    /// door read the ledger ambiguously, and records which vocabularies it
    /// interprets as reservations (norm-plane §7).
    #[test]
    fn planning_configuration_refuses_ambiguity_and_names_its_reservations() {
        let parse = |configured: serde_json::Value| {
            PlanningConfiguration::parse(&configured.to_string()).map(|parsed| {
                parsed
                    .reservation_vocabularies()
                    .iter()
                    .map(|reference| reference.name.clone())
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(
            parse(json!({"capability": " ", "roles": []})),
            Err("norm planning requires a named installed capability".into())
        );
        assert_eq!(
            parse(json!({"capability": "observer", "roles": [
                {"vocabulary": {"name": "claim", "version": "1", "digest": " "}, "interpretation": "context"}
            ]})),
            Err("norm planning vocabulary identities must be complete".into())
        );
        assert_eq!(
            parse(json!({"capability": "observer", "roles": [
                {"vocabulary": vocabulary("claim"), "interpretation": "context"},
                {"vocabulary": vocabulary("claim"), "interpretation": "reservation"}
            ]})),
            Err("norm planning vocabulary interpretations must be unique".into())
        );
        assert_eq!(
            parse(json!({"capability": "observer", "roles": [
                {"vocabulary": vocabulary("requirement"), "interpretation": "context"},
                {"vocabulary": vocabulary("claim"), "interpretation": "reservation"}
            ]})),
            Ok(vec!["claim".to_owned()])
        );
    }
}
