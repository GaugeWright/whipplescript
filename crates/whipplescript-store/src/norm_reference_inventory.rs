//! Reference-capable norm fields at one admitted charter cut (DR-0131, RC-1).
//!
//! The charter's field types, not a scan of record prose, determine this
//! inventory. Roles name structural interpretation only. In particular, a
//! relation family is not a live update dependency without a separate
//! propagation declaration. An unfamiliar reference field stays unclassified
//! instead of disappearing from a future coverage witness. The caller must
//! bind this projection to the exact admitted charter revision; this module
//! does not certify a Home-wide consumer population or authorize routing.

use whipplescript_core::vocabulary::{ReferenceForm, ValueType, VocabularyRef};

use crate::norm::{NormCharter, NormView, NormVocabulary};
use crate::{stable_hash_hex, StoreError, StoreResult};

/// Meaning is declared at charter admission, never inferred from the
/// reference's content-id shape or structural role. A missing declaration is
/// unknown and cannot support a complete dependency-coverage claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormReferenceMeaning {
    LiveDependency,
    HistoricalPin,
    Provenance,
    Authority,
    ContentInput,
}

/// One versioned classification of a typed norm reference field. The charter
/// and its exact vocabulary declaration supply the ledger authority, the
/// population of admitted records, and identity/revision provider resolution;
/// this entry supplies the otherwise unknowable edge meaning.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormReferenceClass {
    pub vocabulary: String,
    pub vocabulary_version: String,
    pub path: String,
    pub meaning: NormReferenceMeaning,
}

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
    pub meaning: Option<NormReferenceMeaning>,
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
    /// The exact signed acts that installed each charter, from genesis through
    /// the current one. This field inventory describes only the last charter.
    pub charter_events: Vec<String>,
    /// Earlier admissions cannot be certified by the current charter's field
    /// declarations alone, even if every current field has a meaning.
    pub historical_population_unknown: bool,
    pub fields: Vec<NormReferenceField>,
    pub has_unclassified: bool,
}

/// One record act observed in replay, including lifecycle and activation acts
/// that reinterpret an unchanged content revision. It is a population member,
/// not an extracted dependency edge or proof that the Home roster is closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormReferenceAdmission {
    pub event: String,
    pub record: String,
    pub content_head: String,
    pub charter_event: String,
    pub vocabulary: VocabularyRef,
    pub status: String,
}

/// The record acts one authenticated local replay observed at its frontier.
/// A Home-wide coverage witness still needs an authoritative operation roster
/// and a closed cut; this projection supplies neither by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormObservedReferenceActs {
    pub ledger: String,
    pub authority_head: String,
    pub frontier: Vec<String>,
    pub charter_events: Vec<String>,
    pub admissions: Vec<NormReferenceAdmission>,
}

pub fn observed_acts_at(view: &NormView) -> NormObservedReferenceActs {
    NormObservedReferenceActs {
        ledger: view.ledger.clone(),
        authority_head: view.authority_head.clone(),
        frontier: view.frontier.iter().cloned().collect(),
        charter_events: view.charter_events.clone(),
        admissions: view.observed_reference_admissions(),
    }
}

pub fn inventory_at(view: &NormView) -> StoreResult<NormReferenceInventory> {
    let fields = inventory(&view.charter);
    let charter_digest = stable_hash_hex(&serde_json::to_string(&view.charter)?);
    Ok(NormReferenceInventory {
        ledger: view.ledger.clone(),
        authority_head: view.authority_head.clone(),
        frontier: view.frontier.iter().cloned().collect(),
        charter_digest,
        charter_events: view.charter_events.clone(),
        historical_population_unknown: view.charter_events.len() > 1,
        has_unclassified: fields.iter().any(|field| field.meaning.is_none()),
        fields,
    })
}

/// Enumerate every typed reference, including nested object/list fields.
/// A newly added reference always appears, even if no existing X1 construct
/// names its role. Completeness remains unknown while any meaning is absent.
pub fn inventory(charter: &NormCharter) -> Vec<NormReferenceField> {
    let mut fields = Vec::new();
    for vocabulary in &charter.vocabularies {
        for field in &vocabulary.definition.fields {
            visit_field(vocabulary, &field.name, &field.value_type, &mut fields);
        }
    }
    for field in &mut fields {
        field.meaning = charter
            .reference_classes
            .iter()
            .find(|class| {
                class.vocabulary == field.vocabulary
                    && class.vocabulary_version == field.vocabulary_version
                    && class.path == field.path
            })
            .map(|class| class.meaning);
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
            meaning: None,
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

/// A charter may leave a class unclassified (coverage then stays unknown),
/// but it may not assert a class for a nonexistent field or use one key twice.
/// The current norm charter has no propagation declaration, so claiming a
/// live update edge here would be unsound until RC-3 adds that contract.
pub(crate) fn validate_classes(charter: &NormCharter) -> StoreResult<()> {
    let fields = inventory(charter);
    let mut seen: std::collections::BTreeSet<(&str, &str, &str)> =
        std::collections::BTreeSet::new();
    for class in &charter.reference_classes {
        let key = (
            class.vocabulary.as_str(),
            class.vocabulary_version.as_str(),
            class.path.as_str(),
        );
        if !seen.insert(key) {
            return Err(StoreError::Conflict(
                "reference class must name one distinct typed field of this charter".into(),
            ));
        }
        if let Some(field) = fields.iter().find(|field| {
            field.vocabulary == class.vocabulary
                && field.vocabulary_version == class.vocabulary_version
                && field.path == class.path
        }) {
            if matches!(
                class.meaning,
                NormReferenceMeaning::HistoricalPin | NormReferenceMeaning::ContentInput
            ) && field.form != ReferenceForm::Revision
            {
                return Err(StoreError::Conflict(
                    "historical pins and content inputs require exact revision references".into(),
                ));
            }
        } else {
            return Err(StoreError::Conflict(
                "reference class must name one distinct typed field of this charter".into(),
            ));
        }
        if class.meaning == NormReferenceMeaning::LiveDependency {
            return Err(StoreError::Conflict(
                "a live dependency class requires a declared propagation rule".into(),
            ));
        }
    }
    Ok(())
}

/// The meaning contract for one exact vocabulary version, including the empty
/// contract. Activation may not change it for a version already admitted.
pub(crate) fn classes_for(
    charter: &NormCharter,
    vocabulary: &NormVocabulary,
) -> std::collections::BTreeMap<String, NormReferenceMeaning> {
    charter
        .reference_classes
        .iter()
        .filter(|class| {
            class.vocabulary == vocabulary.definition.name
                && class.vocabulary_version == vocabulary.definition.version
        })
        .map(|class| (class.path.clone(), class.meaning))
        .collect()
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
        assert!(fields.iter().all(|field| field.meaning.is_none()));
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
                && field.meaning.is_none()
        }));
        charter.reference_classes.push(NormReferenceClass {
            vocabulary: "issue".into(),
            vocabulary_version: "1".into(),
            path: "metadata.new_links[]".into(),
            meaning: NormReferenceMeaning::Authority,
        });
        crate::norm::registry_for(&charter).expect("exact nested class admission");
        assert!(inventory(&charter).iter().any(|field| {
            field.path == "metadata.new_links[]"
                && field.meaning == Some(NormReferenceMeaning::Authority)
        }));
    }

    #[test]
    fn charter_classifies_only_the_exact_declared_reference_field() {
        let mut charter = NormCharter::bundled().expect("bundled charter");
        let member = inventory(&charter)
            .into_iter()
            .find(|field| field.role == NormReferenceRole::ManifestMember)
            .expect("manifest member field");
        charter.reference_classes.push(NormReferenceClass {
            vocabulary: member.vocabulary.clone(),
            vocabulary_version: member.vocabulary_version.clone(),
            path: member.path.clone(),
            meaning: NormReferenceMeaning::HistoricalPin,
        });
        crate::norm::registry_for(&charter).expect("exact class admission");
        let fields = inventory(&charter);
        assert_eq!(
            fields
                .iter()
                .find(|field| field.path == member.path && field.vocabulary == member.vocabulary)
                .expect("classified member")
                .meaning,
            Some(NormReferenceMeaning::HistoricalPin)
        );
        assert_eq!(
            fields
                .iter()
                .filter(|field| field.meaning.is_some())
                .count(),
            1
        );

        let mut changed_version = charter.clone();
        changed_version.reference_classes[0].vocabulary_version = "later".into();
        assert!(matches!(
            crate::norm::registry_for(&changed_version),
            Err(StoreError::Conflict(reason))
                if reason == "reference class must name one distinct typed field of this charter"
        ));
        let mut duplicate = charter.clone();
        duplicate
            .reference_classes
            .push(charter.reference_classes[0].clone());
        assert!(matches!(
            crate::norm::registry_for(&duplicate),
            Err(StoreError::Conflict(reason))
                if reason == "reference class must name one distinct typed field of this charter"
        ));
        let mut unsupported_live = charter;
        unsupported_live.reference_classes[0].meaning = NormReferenceMeaning::LiveDependency;
        assert!(matches!(
            crate::norm::registry_for(&unsupported_live),
            Err(StoreError::Conflict(reason))
                if reason == "a live dependency class requires a declared propagation rule"
        ));

        let mut false_pin = NormCharter::bundled().expect("bundled charter");
        let identity = inventory(&false_pin)
            .into_iter()
            .find(|field| field.form == ReferenceForm::Identity)
            .expect("identity reference");
        false_pin.reference_classes.push(NormReferenceClass {
            vocabulary: identity.vocabulary,
            vocabulary_version: identity.vocabulary_version,
            path: identity.path,
            meaning: NormReferenceMeaning::HistoricalPin,
        });
        assert!(matches!(
            crate::norm::registry_for(&false_pin),
            Err(StoreError::Conflict(reason))
                if reason == "historical pins and content inputs require exact revision references"
        ));
    }
}
