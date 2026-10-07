//! Request-scoped offered skills from the authenticated owning host (DR-0192).
//! Source witnesses use the existing transient model provenance contract;
//! identity agreement does not independently certify repository origin.
use serde::{Deserialize, Serialize};
use whipplescript_kernel::sansio::ModelContentProvenance;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostedSkillCatalogue {
    pub instance_id: String,
    pub command_id: String,
    pub actor_ref: String,
    pub entries: Vec<HostedSkillEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostedSkillEntry {
    /// The retained file path, before any presented-root rename.
    pub path: String,
    pub body_sha256: String,
    pub name: String,
    pub description: String,
    /// The owning host verifies its asset before supplying this exact witness.
    /// These labels certify only the entry above in this admitted request.
    pub source: ModelContentProvenance,
}

/// Parse the same authenticated config on native fixtures and Wasm attachment.
/// The Worker strips this field from public requests before config creation.
pub fn from_agent_config(json: &str) -> Result<Option<HostedSkillCatalogue>, String> {
    let config: serde_json::Value =
        serde_json::from_str(json).map_err(|error| format!("invalid agent config: {error}"))?;
    config
        .get("skill_catalogue")
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|error| format!("invalid hosted skill catalogue: {error}"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hosted_selection_wire_is_exact_and_never_accepts_a_trust_boolean() {
        assert!(from_agent_config("{}").expect("legacy config").is_none());
        let empty = serde_json::json!({"skill_catalogue":{"instance_id":"instance","command_id":"command","actor_ref":"actor","entries":[]}});
        assert!(from_agent_config(&empty.to_string())
            .expect("empty selection")
            .expect("selected")
            .entries
            .is_empty());
        for field in ["trust", "origin_url", "unknown"] {
            let mut malformed = empty.clone();
            malformed["skill_catalogue"][field] = serde_json::json!(true);
            assert!(
                from_agent_config(&malformed.to_string()).is_err(),
                "{field}"
            );
        }
        assert!(from_agent_config(r#"{"skill_catalogue":null}"#).is_err());
        assert!(from_agent_config(
            r#"{"skill_catalogue":{"instance_id":"instance","entries":[]}}"#
        )
        .is_err());
    }
}
