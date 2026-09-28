//! Deployment as a gated admission (norm-plane §10, slice W1).
//!
//! A vocabulary that declares a `deployment` role names the field of its
//! records that lists the cuts they deploy, and the status that deploys
//! them. Moving a record into that status is a deployment. A host admits it
//! only when every gated requirement is supported at each cut it deploys,
//! judged at the ledger's current frontier. The act binds that frontier as its
//! premise, so every replay applies it after exactly the ledger it was judged
//! against. The ledger cannot run the planner itself; the judgment is the
//! host's, at its command door, as the mainline gate's is at a ref door.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use whipplescript_core::vocabulary::{ValueType, VocabularyRef};

use crate::norm::{NormView, NormVocabulary};
use crate::{StoreError, StoreResult};

/// The fields of a deployment record, by role.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentDeclaration {
    /// A required list of text naming the cuts a record deploys.
    pub cuts: String,
    /// The status whose entry deploys them.
    pub status: String,
}

fn refused(message: impl Into<String>) -> StoreError {
    StoreError::Conflict(message.into())
}

pub(crate) fn validate_deployment_declaration(entry: &NormVocabulary) -> StoreResult<()> {
    let Some(declaration) = &entry.deployment else {
        return Ok(());
    };
    let cuts = entry
        .definition
        .fields
        .iter()
        .find(|field| field.name == declaration.cuts && field.required);
    let listed = cuts.is_some_and(|field| {
        matches!(&field.value_type, ValueType::List { item } if matches!(**item, ValueType::Text {}))
    });
    if !listed {
        return Err(refused(
            "a deployment role names a required list of text for the cuts it deploys",
        ));
    }
    let status = &entry.definition.status;
    // A record created in the deploying status would deploy with no act a
    // host could judge, so the status is reached only by a transition.
    if status.initial == declaration.status
        || !status
            .transitions
            .iter()
            .any(|transition| transition.to == declaration.status)
    {
        return Err(refused(
            "a deployment role names a status that only a transition reaches",
        ));
    }
    Ok(())
}

impl NormView {
    /// The cuts an act moving `record` into `status` deploys, when that is a
    /// deployment; `None` when it is not one.
    pub fn deployed_cuts(
        &self,
        vocabulary: &VocabularyRef,
        record: &str,
        status: &str,
    ) -> Option<Vec<String>> {
        let declaration = self.interpretation(vocabulary)?.deployment.as_ref()?;
        if declaration.status != status {
            return None;
        }
        let cuts = self
            .records
            .get(record)
            .and_then(|current| current.fields.get(&declaration.cuts))
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        Some(cuts)
    }
}

/// The ledger premise a deployment binds: the exact frontier it was judged
/// at, which a host requires to be its current one.
pub fn judged_at_current(view: &NormView, frontier: &[String]) -> StoreResult<()> {
    let bound: BTreeSet<&String> = frontier.iter().collect();
    let current: BTreeSet<&String> = view.frontier.iter().collect();
    if bound != current {
        return Err(refused(
            "a deployment is judged at the ledger's current frontier, and this one binds another; judge it again",
        ));
    }
    Ok(())
}
