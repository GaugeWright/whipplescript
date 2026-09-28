//! Reference-capable norm fields at one admitted charter cut (DR-0131, RC-1).
//!
//! The charter's field types, not a scan of record prose, determine this
//! inventory. Roles name structural interpretation only. In particular, a
//! relation family is not a live update dependency without a separate
//! propagation declaration. An unfamiliar reference field stays unclassified
//! instead of disappearing from a future coverage witness. The caller must
//! bind this projection to the exact admitted charter revision; this module
//! does not certify a Home-wide consumer population or authorize routing.

use whipplescript_core::vocabulary::{ReferenceForm, ValueType};

use crate::norm::{NormCharter, NormView, NormVocabulary};
use crate::{stable_hash_hex, StoreResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormReferenceRole {
    RelationEndpoint {
        family: String,
    },
    ManifestMember,
    CorrespondenceSide,
    /// The requirement a typed constraint constrains (norm-plane §11.1).
    ConstraintSubject,
    Unclassified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormReferenceField {
    pub vocabulary: String,
    pub vocabulary_version: String,
    pub path: String,
    pub form: ReferenceForm,
    pub role: NormReferenceRole,
}

/// The field inventory from a replayed, authenticated norm cut. `frontier`
/// changes whenever an admitted act moves the ledger, even when the charter
/// stays the same. A consumer must compare this basis to the cut it will use;
/// a field list alone is not evidence about the current Home.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormReferenceInventory {
    pub ledger: String,
    pub authority_head: String,
    pub frontier: Vec<String>,
    pub charter_digest: String,
    pub fields: Vec<NormReferenceField>,
    pub has_unclassified: bool,
}

pub fn inventory_at(view: &NormView) -> StoreResult<NormReferenceInventory> {
    let fields = inventory(&view.charter);
    let charter_digest = stable_hash_hex(&serde_json::to_string(&view.charter)?);
    Ok(NormReferenceInventory {
        ledger: view.ledger.clone(),
        authority_head: view.authority_head.clone(),
        frontier: view.frontier.iter().cloned().collect(),
        charter_digest,
        has_unclassified: fields
            .iter()
            .any(|field| field.role == NormReferenceRole::Unclassified),
        fields,
    })
}

/// Enumerate every typed reference, including nested object/list fields.
/// A newly added reference always appears, even if no existing X1 construct
/// names its role. Completeness remains unknown while any role is unclassified.
pub fn inventory(charter: &NormCharter) -> Vec<NormReferenceField> {
    let mut fields = Vec::new();
    for vocabulary in &charter.vocabularies {
        for field in &vocabulary.definition.fields {
            visit_field(vocabulary, &field.name, &field.value_type, &mut fields);
        }
    }
    fields.sort_by(|left, right| {
        (&left.vocabulary, &left.vocabulary_version, &left.path).cmp(&(
            &right.vocabulary,
            &right.vocabulary_version,
            &right.path,
        ))
    });
    fields
}

fn visit_field(
    vocabulary: &NormVocabulary,
    path: &str,
    value_type: &ValueType,
    fields: &mut Vec<NormReferenceField>,
) {
    match value_type {
        ValueType::Reference { form } => fields.push(NormReferenceField {
            vocabulary: vocabulary.definition.name.clone(),
            vocabulary_version: vocabulary.definition.version.clone(),
            path: path.to_owned(),
            form: *form,
            role: role(vocabulary, path),
        }),
        ValueType::List { item } => visit_field(vocabulary, &format!("{path}[]"), item, fields),
        ValueType::Object { fields: nested } => {
            for field in nested {
                visit_field(
                    vocabulary,
                    &format!("{path}.{}", field.name),
                    &field.value_type,
                    fields,
                );
            }
        }
        ValueType::Text { .. }
        | ValueType::Boolean { .. }
        | ValueType::Integer { .. }
        | ValueType::Enum { .. } => {}
    }
}

fn role(vocabulary: &NormVocabulary, path: &str) -> NormReferenceRole {
    if let Some(relation) = &vocabulary.relation {
        if path == relation.source || path == relation.target {
            return NormReferenceRole::RelationEndpoint {
                family: relation.family.clone(),
            };
        }
    }
    if vocabulary
        .manifest
        .as_ref()
        .is_some_and(|manifest| path == format!("{}[]", manifest.members))
    {
        return NormReferenceRole::ManifestMember;
    }
    if vocabulary
        .correspondence
        .as_ref()
        .is_some_and(|correspondence| {
            path == format!("{}[]", correspondence.sources)
                || path == format!("{}[]", correspondence.targets)
        })
    {
        return NormReferenceRole::CorrespondenceSide;
    }
    if vocabulary
        .constraint
        .as_ref()
        .is_some_and(|constraint| path == constraint.requirement)
    {
        return NormReferenceRole::ConstraintSubject;
    }
    NormReferenceRole::Unclassified
}

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_core::vocabulary::FieldDefinition;

    #[test]
    fn bundled_charter_exposes_every_typed_reference_without_live_routing_claim() {
        let charter = NormCharter::bundled().expect("bundled charter");
        let fields = inventory(&charter);
        assert_eq!(fields.len(), 13);
        assert_eq!(
            fields
                .iter()
                .filter(|field| matches!(field.role, NormReferenceRole::RelationEndpoint { .. }))
                .count(),
            8
        );
        assert_eq!(
            fields
                .iter()
                .filter(|field| field.role == NormReferenceRole::ManifestMember)
                .count(),
            1
        );
        assert_eq!(
            fields
                .iter()
                .filter(|field| field.role == NormReferenceRole::CorrespondenceSide)
                .count(),
            2
        );
        // A constraint declares which field names the requirement it types.
        assert_eq!(
            fields
                .iter()
                .filter(|field| field.role == NormReferenceRole::ConstraintSubject)
                .map(|field| (field.vocabulary.as_str(), field.path.as_str()))
                .collect::<Vec<_>>(),
            [("constraint", "requirement")]
        );
        // An exception's requirement is read by the planner's interpretation
        // (norm-plane §3.5), not declared by the charter, so the charter
        // alone leaves it unclassified, and says so.
        assert_eq!(
            fields
                .iter()
                .filter(|field| field.role == NormReferenceRole::Unclassified)
                .map(|field| (field.vocabulary.as_str(), field.path.as_str()))
                .collect::<Vec<_>>(),
            [("exception", "requirement")]
        );
    }

    #[test]
    fn new_nested_reference_is_visible_and_unclassified() {
        let mut charter = NormCharter::bundled().expect("bundled charter");
        let issue = charter
            .vocabularies
            .iter_mut()
            .find(|entry| entry.definition.name == "issue")
            .expect("issue vocabulary");
        issue.definition.fields.push(FieldDefinition {
            name: "metadata".into(),
            required: false,
            value_type: ValueType::Object {
                fields: vec![FieldDefinition {
                    name: "new_links".into(),
                    required: false,
                    value_type: ValueType::List {
                        item: Box::new(ValueType::Reference {
                            form: ReferenceForm::Identity,
                        }),
                    },
                    editorial: false,
                }],
            },
            editorial: false,
        });
        let fields = inventory(&charter);
        assert_eq!(fields.len(), 14);
        assert!(fields.iter().any(|field| {
            field.vocabulary == "issue"
                && field.path == "metadata.new_links[]"
                && field.form == ReferenceForm::Identity
                && field.role == NormReferenceRole::Unclassified
        }));
    }
}
