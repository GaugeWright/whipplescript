//! Source policy shared by legacy and managed effect lowering. This contract
//! does not invent execution identity, control edges or resource authority.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Resource {
    None,
    Named(String),
    Binding(String),
}
impl Resource {
    pub(crate) fn legacy_name(&self, bindings: &BTreeMap<String, String>) -> Option<String> {
        match self {
            Self::None => None,
            Self::Named(name) => Some(name.clone()),
            Self::Binding(name) => bindings.get(name).cloned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Source kind. The legacy owner still disambiguates tracker/lease renew
    /// using its actual binding map; managed resource analysis must do likewise.
    pub kind: IrEffectKind,
    pub required_capabilities: Vec<String>,
    /// The type a `prompt` names for its answer (DR-0120). A derived field of
    /// the effect like every other one here.
    pub prompt_result_type: Option<String>,
    pub timeout_seconds: Option<u64>,
    pub access_grants: Vec<IrAccessGrant>,
    pub turn_skills: Vec<String>,
    pub on_stream: Option<String>,
    pub selection_source: Option<String>,
    pub transport_onto: Option<String>,
    pub resource: Resource,
    /// Source expression, resolved against a lexical environment by managed typing.
    pub agent: Option<String>,
    pub coerce_target: Option<String>,
    pub workflow_target: Option<String>,
    pub endorsed: bool,
    pub declassified: bool,
    pub construct_use: Option<IrConstructUse>,
    pub exec_target: Option<IrExecTarget>,
    pub http_request: Option<IrHttpRequest>,
    pub mint_credential: Option<IrMintCredential>,
    /// The prompt endpoint an inline prompt names, judged where it is written
    /// rather than inferred later.
    pub prompt_provider: Option<String>,
    /// Analysis metadata for an ordinary package call. Derived here with every
    /// other field an effect carries: computing two of them beside a contract
    /// that computes the rest is how the two stop agreeing.
    pub package_call: Option<crate::IrPackageCall>,
}
impl Contract {
    pub fn from_statement(effect: &body::EffectStmt) -> Self {
        let mut required_capabilities = effect.requires.clone();
        match &effect.kind {
            body::BodyEffectKind::Call { capability, .. } => {
                required_capabilities.push(capability.clone())
            }
            body::BodyEffectKind::ConstructCapabilityCall {
                target_capability, ..
            } => required_capabilities.push(target_capability.clone()),
            // A prompt that names a MEDIA result asks the provider to generate
            // it, which is its own capability (`image.generate`). Derived here
            // with the rest of the contract rather than beside it, for the
            // reason `package_call` gives.
            body::BodyEffectKind::Prompt {
                result_type: Some(result_type),
                ..
            } => {
                if let Some(capability) = media_generate_capability(result_type) {
                    required_capabilities.push(capability);
                }
            }
            _ => {}
        }
        required_capabilities.sort();
        required_capabilities.dedup();
        let resource = match &effect.kind {
            body::BodyEffectKind::TrackerClaim { item, .. }
            | body::BodyEffectKind::TrackerRelease { item }
            | body::BodyEffectKind::TrackerFinish { item, .. } => Resource::Binding(item.clone()),
            body::BodyEffectKind::LeaseRenew {
                acquire_binding, ..
            } => Resource::Binding(acquire_binding.clone()),
            other => {
                resource_for_body(other, &BTreeMap::new()).map_or(Resource::None, Resource::Named)
            }
        };
        let (selection_source, transport_onto) = vcs_selective_for_body(&effect.kind);
        Self {
            kind: ir_effect_kind_for_body(&effect.kind),
            required_capabilities,
            prompt_result_type: prompt_result_type_for_body(&effect.kind),
            timeout_seconds: effect.timeout_seconds,
            access_grants: ir_access_grants_for_body(&effect.kind),
            turn_skills: turn_skills_for_body(&effect.kind),
            on_stream: on_stream_for_body(&effect.kind),
            selection_source,
            transport_onto,
            resource,
            agent: agent_for_body(&effect.kind),
            coerce_target: coerce_target_for_body(&effect.kind),
            workflow_target: workflow_target_for_body(&effect.kind),
            endorsed: endorsed_for_body(&effect.kind),
            declassified: declassified_for_body(&effect.kind),
            construct_use: construct_use_for_body(&effect.kind),
            exec_target: exec_target_for_body(&effect.kind),
            http_request: http_request_for_body(&effect.kind),
            mint_credential: mint_credential_for_body(&effect.kind),
            prompt_provider: prompt_provider_for_body(&effect.kind),
            package_call: match &effect.kind {
                body::BodyEffectKind::Call {
                    capability,
                    argument,
                } => Some(crate::IrPackageCall {
                    target: capability.clone(),
                    argument: argument.clone(),
                    tracker_resources: Vec::new(),
                }),
                body::BodyEffectKind::ConstructCapabilityCall {
                    target_capability, ..
                } => Some(crate::IrPackageCall {
                    target: target_capability.clone(),
                    argument: None,
                    tracker_resources: Vec::new(),
                }),
                _ => None,
            },
        }
    }
}

#[cfg(test)]
mod tests;
