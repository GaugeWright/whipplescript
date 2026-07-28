//! Typed governance-envelope construction for embedding product authorities.
//!
//! WhippleScript owns this schema and its enforcement meaning. A host such as
//! GaugeDesk supplies product facts through these types, serializes the unsigned
//! document, and signs WhippleScript's canonical bytes. Keeping the builder here
//! prevents each host from inventing a parallel JSON policy language.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Reader/writer labels for one canonical resource identity.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourcePolicy {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub reader: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub writer: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub principal: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub internal: bool,
}

/// The non-secret identity of one provider binding admitted by an epoch.
///
/// `credential_ref` names host-custodied material. The secret bytes are resolved
/// only after this exact tuple has been admitted and are never serialized here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderBindingPolicy {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub credential_ref: String,
}

/// Placement constraints that sit below the WhippleScript policy envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlacementPolicy {
    /// Stable placement class (`local`, `durable_object`, `wasm`, …).
    pub kind: String,
    /// Provider binding handles this placement may realize.
    pub provider_bindings: BTreeSet<String>,
    /// Whether commands realized by this placement may receive ambient network.
    /// Provider HTTP uses its exact provider binding and is a separate capability.
    #[serde(default, skip_serializing_if = "is_false")]
    pub command_network: bool,
}

/// WhippleScript's complete host-authored governance document.
///
/// The IFC fields are the established envelope. The runtime fields close the
/// product-host seam: a package capability, provider binding, credential ref, or
/// placement is executable only when this signed document admits it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostGovernancePolicy {
    #[serde(default)]
    pub resources: BTreeMap<String, ResourcePolicy>,
    #[serde(default)]
    pub bindings: BTreeMap<String, String>,
    #[serde(default)]
    pub parties: BTreeMap<String, String>,
    #[serde(default)]
    pub delegations: Vec<[String; 2]>,
    #[serde(default)]
    pub declassifications: Vec<[String; 2]>,
    #[serde(default)]
    pub endorsements: Vec<[String; 2]>,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default)]
    pub provider_bindings: BTreeMap<String, ProviderBindingPolicy>,
    #[serde(default)]
    pub placements: BTreeMap<String, PlacementPolicy>,
}

impl HostGovernancePolicy {
    /// Validate the referential shape and render deterministic unsigned JSON.
    /// `gov::canonicalize` remains the canonical signing boundary.
    pub fn to_json(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string(self).map_err(|error| error.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        for (handle, address) in &self.bindings {
            nonempty("resource handle", handle)?;
            nonempty("resource address", address)?;
            if !self.resources.contains_key(address) {
                return Err(format!(
                    "resource binding `{handle}` names undeclared address `{address}`"
                ));
            }
        }
        for capability in &self.capabilities {
            nonempty("capability", capability)?;
        }
        for (handle, binding) in &self.provider_bindings {
            nonempty("provider binding handle", handle)?;
            nonempty("provider", &binding.provider)?;
            nonempty("provider model", &binding.model)?;
            nonempty("provider base URL", &binding.base_url)?;
            nonempty("credential reference", &binding.credential_ref)?;
            require_principal_binding(self, handle, "provider")?;
        }
        for (handle, placement) in &self.placements {
            nonempty("placement handle", handle)?;
            nonempty("placement kind", &placement.kind)?;
            require_principal_binding(self, handle, "placement")?;
            if placement.provider_bindings.is_empty() {
                return Err(format!("placement `{handle}` admits no provider binding"));
            }
            for binding in &placement.provider_bindings {
                if !self.provider_bindings.contains_key(binding) {
                    return Err(format!(
                        "placement `{handle}` names undeclared provider binding `{binding}`"
                    ));
                }
            }
        }
        for (identity, role) in &self.parties {
            nonempty("party identity", identity)?;
            nonempty("party role", role)?;
        }
        validate_pairs("delegation", &self.delegations)?;
        validate_pairs("declassification", &self.declassifications)?;
        validate_pairs("endorsement", &self.endorsements)?;
        Ok(())
    }
}

fn validate_pairs(what: &str, pairs: &[[String; 2]]) -> Result<(), String> {
    for [left, right] in pairs {
        nonempty(&format!("{what} source"), left)?;
        nonempty(&format!("{what} target"), right)?;
    }
    Ok(())
}

fn require_principal_binding(
    policy: &HostGovernancePolicy,
    handle: &str,
    expected_kind: &str,
) -> Result<(), String> {
    let address = policy
        .bindings
        .get(handle)
        .ok_or_else(|| format!("{expected_kind} `{handle}` has no resource binding"))?;
    let resource = policy
        .resources
        .get(address)
        .ok_or_else(|| format!("{expected_kind} `{handle}` has no governed resource"))?;
    if !resource.principal || !address.starts_with(&format!("{expected_kind}:")) {
        return Err(format!(
            "{expected_kind} `{handle}` must bind to a principal `{expected_kind}:…` resource"
        ));
    }
    Ok(())
}

fn nonempty(what: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{what} must not be empty"))
    } else {
        Ok(())
    }
}

const fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_policy() -> HostGovernancePolicy {
        HostGovernancePolicy {
            resources: BTreeMap::from([
                (
                    "provider:openai".to_owned(),
                    ResourcePolicy {
                        principal: true,
                        ..ResourcePolicy::default()
                    },
                ),
                (
                    "placement:local".to_owned(),
                    ResourcePolicy {
                        principal: true,
                        ..ResourcePolicy::default()
                    },
                ),
            ]),
            bindings: BTreeMap::from([
                ("model".to_owned(), "provider:openai".to_owned()),
                ("local".to_owned(), "placement:local".to_owned()),
            ]),
            capabilities: BTreeSet::from(["workspace.read".to_owned()]),
            provider_bindings: BTreeMap::from([(
                "model".to_owned(),
                ProviderBindingPolicy {
                    provider: "openai".to_owned(),
                    model: "gpt-5".to_owned(),
                    base_url: "https://api.openai.com/v1/responses".to_owned(),
                    credential_ref: "credential:account:openai".to_owned(),
                },
            )]),
            placements: BTreeMap::from([(
                "local".to_owned(),
                PlacementPolicy {
                    kind: "local".to_owned(),
                    provider_bindings: BTreeSet::from(["model".to_owned()]),
                    command_network: false,
                },
            )]),
            ..HostGovernancePolicy::default()
        }
    }

    #[test]
    fn validates_and_serializes_a_complete_host_policy() {
        let json = complete_policy().to_json().expect("policy");
        assert!(json.contains("credential:account:openai"));
        assert!(json.contains("workspace.read"));
    }

    #[test]
    fn rejects_a_placement_that_widens_to_an_unknown_provider() {
        let mut policy = complete_policy();
        policy
            .placements
            .get_mut("local")
            .expect("fixture has local placement")
            .provider_bindings
            .insert("other".to_owned());
        assert!(policy
            .validate()
            .expect_err("unknown provider must fail")
            .contains("undeclared provider"));
    }

    #[test]
    fn rejects_empty_trusted_crossing_and_delegation_terms() {
        let mut policy = complete_policy();
        policy
            .delegations
            .push(["Operator".to_owned(), String::new()]);
        assert!(policy
            .validate()
            .expect_err("empty delegation role must fail")
            .contains("delegation target"));
    }
}
