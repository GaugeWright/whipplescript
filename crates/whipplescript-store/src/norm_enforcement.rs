//! Enforcement (norm-plane §4): which admission phase evaluates each
//! requirement through a governed door, and which phases are not wired at all.
//!
//! Coverage says which resources have requirements and conformance says what
//! the evidence supports; this says where a requirement actually blocks. A
//! phase is wired when a door evaluates requirements there: every gated ref
//! is one, since each door onto it judges the proposed result against every
//! effective requirement. Deployment is wired where the charter declares a
//! deployment vocabulary, whose admission a host judges against every
//! effective requirement at the cuts it deploys (§10); without one it is
//! reported as an unwired phase rather than left out.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::branches::MAINLINE_BRANCH_ID;
use crate::norm::NormView;
use crate::StoreResult;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseKind {
    /// A gated ref: the mainline, or a line the charter declares gated.
    GatedRef,
    Deployment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdmissionPhase {
    pub phase: String,
    pub kind: PhaseKind,
    pub wired: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnforcementView {
    pub phases: Vec<AdmissionPhase>,
    /// Each effective requirement, by its creation id, and the wired phases
    /// that evaluate it.
    pub requirements: BTreeMap<String, Vec<String>>,
}

impl NormView {
    /// Every admission phase and whether a door evaluates requirements there,
    /// with the phases that evaluate each effective requirement.
    pub fn enforcement(&self) -> StoreResult<EnforcementView> {
        let mut phases: Vec<AdmissionPhase> = std::iter::once(MAINLINE_BRANCH_ID)
            .chain(self.charter.gated_refs.iter().map(String::as_str))
            .map(|line| AdmissionPhase {
                phase: format!("ref:{line}"),
                kind: PhaseKind::GatedRef,
                wired: true,
                reason: format!(
                    "every door onto `{line}` judges its proposed result against every effective requirement"
                ),
            })
            .collect();
        let deployments: Vec<String> = self
            .charter
            .vocabularies
            .iter()
            .filter(|entry| entry.deployment.is_some())
            .map(|entry| format!("{}@{}", entry.definition.name, entry.definition.version))
            .collect();
        phases.push(if deployments.is_empty() {
            AdmissionPhase {
                phase: "deployment".into(),
                kind: PhaseKind::Deployment,
                wired: false,
                reason: "the charter declares no deployment, so none evaluates a requirement"
                    .into(),
            }
        } else {
            AdmissionPhase {
                phase: "deployment".into(),
                kind: PhaseKind::Deployment,
                wired: true,
                reason: format!(
                    "admitting a deployment of {} judges every effective requirement at each cut it deploys",
                    deployments.join(", ")
                ),
            }
        });
        let wired: Vec<String> = phases
            .iter()
            .filter(|phase| phase.wired)
            .map(|phase| phase.phase.clone())
            .collect();
        let requirements = self
            .requirement_inventory()?
            .requirements
            .into_keys()
            .map(|requirement| (requirement, wired.clone()))
            .collect();
        Ok(EnforcementView {
            phases,
            requirements,
        })
    }
}
