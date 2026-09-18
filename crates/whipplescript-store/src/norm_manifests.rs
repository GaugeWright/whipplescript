//! Manifests (DR-0122, norm-plane §13.1).
//!
//! A manifest is a record of a vocabulary whose charter entry names the field
//! carrying its members, exact revision references, and the field carrying
//! its completeness claim. Structural validity is the door's: every member is
//! bound as a premise and resolves to a revision this ledger admitted, or the
//! act is refused. Completeness is a separate judgment, never inferred from
//! structure: an exhaustive claim binds the ledger frontier it was judged
//! against, as causal parents, and the judgment is derived by projecting the
//! history at that frontier and comparing the members with the applicable
//! inventory there. It is the same in every replay, and it is a historical
//! judgment: a requirement admitted afterwards does not rewrite it. A bounded
//! claim names its scope and is never total. Modeled in
//! `models/maude/manifest-completeness.maude`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use whipplescript_core::vocabulary::{ReferenceForm, ValueType};

use crate::norm::NormVocabulary;
use crate::norm_inventory::RequirementInventory;
use crate::{StoreError, StoreResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestDeclaration {
    /// The required list field of revision references carrying the members.
    pub members: String,
    /// The required enum field carrying the completeness claim.
    pub claim: String,
    /// The claim literal that asserts exhaustiveness over the inventory.
    pub exhaustive: String,
    /// An optional text field naming a bounded claim's scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// The derived completeness judgment of one admitted manifest revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestJudgment {
    pub revision: String,
    pub claim: String,
    pub completeness: ManifestCompleteness,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManifestCompleteness {
    /// Every applicable requirement revision at the basis is a member.
    Complete { basis: Vec<String> },
    /// Applicable revisions at the basis that are not members.
    Incomplete {
        basis: Vec<String>,
        missing: Vec<String>,
    },
    /// The inventory at the basis is not completely classified, or the basis
    /// is not a frontier of this history, so no total judgment exists.
    Unresolved { basis: Vec<String>, reason: String },
    /// A bounded claim: judged within its declared scope, never total.
    Bounded { scope: Option<String> },
}

fn conflict(message: &str) -> StoreError {
    StoreError::Conflict(message.into())
}

pub(crate) fn validate_manifest_declaration(entry: &NormVocabulary) -> StoreResult<()> {
    let Some(manifest) = &entry.manifest else {
        return Ok(());
    };
    let field = |name: &str| {
        entry
            .definition
            .fields
            .iter()
            .find(|field| field.name == name)
    };
    let members_ok = field(&manifest.members).is_some_and(|field| {
        field.required
            && matches!(
                &field.value_type,
                ValueType::List { item } if matches!(**item, ValueType::Reference { form: ReferenceForm::Revision })
            )
    });
    if !members_ok {
        return Err(conflict(
            "manifest members must be a required list of revision references",
        ));
    }
    let claim_ok = field(&manifest.claim).is_some_and(|field| {
        field.required
            && matches!(&field.value_type, ValueType::Enum { values } if values.contains(&manifest.exhaustive))
    });
    if !claim_ok {
        return Err(conflict(
            "manifest claim must be a required enum field containing the exhaustive literal",
        ));
    }
    if let Some(scope) = &manifest.scope {
        let scope_ok =
            field(scope).is_some_and(|field| matches!(field.value_type, ValueType::Text {}));
        if !scope_ok {
            return Err(conflict("manifest scope must name a text field"));
        }
    }
    Ok(())
}

/// Compare a manifest's members with the applicable inventory at its basis.
pub fn judge(
    members: &[String],
    inventory: &RequirementInventory,
    basis: Vec<String>,
) -> ManifestCompleteness {
    if !inventory.classification_complete {
        return ManifestCompleteness::Unresolved {
            basis,
            reason: format!(
                "the inventory at the basis is not completely classified: {} gap(s)",
                inventory.gaps.len()
            ),
        };
    }
    let members: BTreeSet<&str> = members.iter().map(String::as_str).collect();
    let missing: Vec<String> = inventory
        .requirements
        .values()
        .map(|requirement| requirement.source.content_head.clone())
        .filter(|revision| !members.contains(revision.as_str()))
        .collect();
    if missing.is_empty() {
        ManifestCompleteness::Complete { basis }
    } else {
        ManifestCompleteness::Incomplete { basis, missing }
    }
}
