//! Correspondence (DR-0122, norm-plane §13.3).
//!
//! A correspondence is a record of a vocabulary whose charter entry names the
//! fields carrying its sources and targets, exact revision references, and
//! the field carrying its claim from a closed set. It binds both sides as
//! premises, so the revisions it relates precede it in every replay, and it
//! changes nothing about them: activation of a successor is an admitted act
//! on that successor, never an effect of a correspondence. What a consumer
//! may rely on through it, and under which authority, is the record's own
//! content; reuse of support across it is a later slice's rule. Modeled in
//! `models/maude/correspondence-reuse.maude`.

use serde::{Deserialize, Serialize};
use whipplescript_core::vocabulary::{ReferenceForm, ValueType};

use crate::norm::NormVocabulary;
use crate::{StoreError, StoreResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrespondenceDeclaration {
    /// The required list fields of revision references on each side.
    pub sources: String,
    pub targets: String,
    /// The required enum field carrying the claimed relationship.
    pub claim: String,
}

fn conflict(message: &str) -> StoreError {
    StoreError::Conflict(message.into())
}

pub(crate) fn validate_correspondence_declaration(entry: &NormVocabulary) -> StoreResult<()> {
    let Some(correspondence) = &entry.correspondence else {
        return Ok(());
    };
    let field = |name: &str| {
        entry
            .definition
            .fields
            .iter()
            .find(|field| field.name == name)
    };
    for (role, name) in [
        ("sources", &correspondence.sources),
        ("targets", &correspondence.targets),
    ] {
        let ok = field(name).is_some_and(|field| {
            field.required
                && matches!(
                    &field.value_type,
                    ValueType::List { item } if matches!(**item, ValueType::Reference { form: ReferenceForm::Revision })
                )
        });
        if !ok {
            return Err(conflict(&format!(
                "correspondence {role} must be a required list of revision references"
            )));
        }
    }
    if correspondence.sources == correspondence.targets {
        return Err(conflict(
            "correspondence sources and targets must be distinct fields",
        ));
    }
    let claim_ok = field(&correspondence.claim).is_some_and(|field| {
        field.required
            && matches!(&field.value_type, ValueType::Enum { values } if !values.is_empty())
    });
    if !claim_ok {
        return Err(conflict(
            "correspondence claim must be a required enum field",
        ));
    }
    Ok(())
}
