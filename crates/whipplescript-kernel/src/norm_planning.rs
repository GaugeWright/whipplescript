//! Host-owned impact query composition shared by native and hosted embeddings.
use crate::norm_execution::PreparedNormExecution;
use crate::norm_execution_policy::ProtectedPythonPolicy;
use crate::norm_impact::{plan_projected, ImpactLimits, ProjectedImpactInput};
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationWire {
    capability: String,
    roles: Vec<Role>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Role {
    vocabulary: VocabularyRef,
    interpretation: Interpretation,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Interpretation {
    Context,
    PublishedExecution,
}
#[derive(serde::Serialize)]
struct MethodGap {
    requirement: Option<EvidenceVersion>,
    reason: String,
}

/// Validated embedding configuration, never part of a query request.
pub struct PlanningConfiguration {
    capability: String,
    roles: BTreeMap<VocabularyRef, ProjectionRole>,
}
impl PlanningConfiguration {
    pub fn parse(configured: &str) -> Result<Self, String> {
        let configuration: ConfigurationWire =
            serde_json::from_str(configured).map_err(|error| error.to_string())?;
        if configuration.capability.trim().is_empty() {
            return Err("norm planning requires a named installed capability".into());
        }
        let mut roles = BTreeMap::new();
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
            };
            if roles.insert(role.vocabulary, interpretation).is_some() {
                return Err("norm planning vocabulary interpretations must be unique".into());
            }
        }
        Ok(Self {
            capability: configuration.capability,
            roles,
        })
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
    pub policy: &'a ProtectedPythonPolicy,
}

/// Read-only composition: no enqueue, publication, or ref-movement capability.
/// The verifier checks an actual host installation binding, not just the policy.
pub fn execute<S: RuntimeStore>(
    input: ImpactQuery<'_, S>,
    verify_runtime: impl Fn(&PythonRuntime) -> Result<(), String>,
) -> Result<serde_json::Value, String> {
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
    let installed = runtime
        .get_script_capability(&configuration.capability)
        .map_err(|error| format!("{error:?}"))?;
    let projection = EvidenceProjection::capture(
        history,
        &configuration.roles,
        ImpactLimits::default().max_events,
        |instance, run| {
            PreparedNormExecution::recover_with_artifacts(
                history, verifier, artifacts, runtime, instance, run,
            )
        },
    )?;
    let method_gaps = std::cell::RefCell::new(BTreeMap::<String, Vec<MethodGap>>::new());
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
            let found = installed
                .as_ref()
                .ok_or_else(|| "norm observer capability is not registered".to_owned())
                .and_then(|installed| {
                    crate::norm_discovery::discover(
                        requirement,
                        artifact,
                        installed,
                        &verify_runtime,
                    )
                });
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
    Ok(serde_json::json!({
        "anchor": history.anchor(),
        "before_frontier": before.frontier,
        "after_frontier": after.frontier,
        "plan": plan,
        "method_gaps": method_gaps.into_inner(),
    }))
}
