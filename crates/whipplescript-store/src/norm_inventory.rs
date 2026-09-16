//! Full-ledger requirement classification from a captured authenticated view.
//! This is not resource applicability, evidence adequacy, or gate admission.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use whipplescript_core::norm_evidence::EvidenceVersion;
use whipplescript_core::vocabulary::{ValueType, Vocabulary, VocabularyRef};

use crate::norm::{
    EffectiveLifecycle, EffectiveRevision, NormCheckpoint, NormRecord, NormView, NormVocabulary,
};
use crate::{StoreError, StoreResult};

/// Omission on a historical charter is unknown, not an exclusion. The role is
/// C0 data, never guessed from a vocabulary name or a record's status spelling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InventoryRole {
    NonRequirement {},
    Requirement { fields: RequirementFields },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementFields {
    pub name: String,
    pub proposition: String,
    pub domain: String,
    pub subject: String,
    pub support_contract: Option<String>,
}

pub(crate) fn validate_inventory_role(entry: &NormVocabulary) -> StoreResult<()> {
    let Some(InventoryRole::Requirement { fields }) = &entry.inventory_role else {
        return Ok(());
    };
    let mut mapped = BTreeSet::new();
    for (name, required) in [
        (&fields.name, true),
        (&fields.proposition, true),
        (&fields.domain, true),
        (&fields.subject, true),
    ]
    .into_iter()
    .chain(fields.support_contract.iter().map(|name| (name, false)))
    {
        let unique = mapped.insert(name);
        if !unique {
            return Err(StoreError::Conflict(
                "requirement role maps the same field twice".into(),
            ));
        }
        let valid = entry.definition.fields.iter().any(|field| {
            &field.name == name
                && matches!(
                    field.value_type,
                    ValueType::Text {} | ValueType::Enum { .. }
                )
                && (!required || field.required)
        });
        if !valid {
            return Err(StoreError::Conflict(
                "requirement role needs declared text fields with required meaning".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementDeclaration {
    pub name: String,
    pub proposition: String,
    /// Declared text, not an evaluated resource selector or coverage claim.
    pub domain: String,
    pub subject: String,
    /// No declaration is distinct from a verified or installed support method.
    pub support_contract: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryRequirement {
    pub source: NormRecord,
    pub lifecycle: EffectiveLifecycle,
    /// Malformed meaning retains its active source, but cannot mint a usable
    /// requirement identity. Located gaps explain the failed interpretation.
    pub declaration: Option<RequirementDeclaration>,
    pub requirement: Option<EvidenceVersion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InventoryGapKind {
    UnspecifiedRole,
    UnspecifiedEffectiveness,
    InvalidText { field: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryGap {
    pub vocabulary: VocabularyRef,
    pub record: Option<String>,
    pub reason: InventoryGapKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementInventory {
    pub checkpoint: NormCheckpoint,
    pub frontier: BTreeSet<String>,
    /// Complete only as a classification of this full authenticated ledger.
    /// It says nothing about undeclared duties, resource coverage or enforcement.
    pub classification_complete: bool,
    /// Keys are immutable creation ids; aliases and duplicate display names do
    /// not select, collapse, or relabel requirements.
    pub requirements: BTreeMap<String, InventoryRequirement>,
    pub inactive: BTreeSet<String>,
    pub non_requirements: BTreeSet<String>,
    pub unclassified: BTreeSet<String>,
    pub gaps: Vec<InventoryGap>,
}

fn text_field(record: &NormRecord, field: &str, gaps: &mut Vec<InventoryGap>) -> Option<String> {
    let value = record
        .fields
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty());
    if value.is_none() {
        gaps.push(InventoryGap {
            vocabulary: record.vocabulary.clone(),
            record: Some(record.id.clone()),
            reason: InventoryGapKind::InvalidText {
                field: field.into(),
            },
        });
    }
    value.map(str::to_owned)
}

fn declaration(
    record: &NormRecord,
    fields: &RequirementFields,
    gaps: &mut Vec<InventoryGap>,
) -> Option<RequirementDeclaration> {
    let before = gaps.len();
    let name = text_field(record, &fields.name, gaps);
    let proposition = text_field(record, &fields.proposition, gaps);
    let domain = text_field(record, &fields.domain, gaps);
    let subject = text_field(record, &fields.subject, gaps);
    let support_contract = fields
        .support_contract
        .as_ref()
        .filter(|field| record.fields.get(*field).is_some())
        .and_then(|field| text_field(record, field, gaps));
    if gaps.len() != before {
        return None;
    }
    Some(RequirementDeclaration {
        name: name?,
        proposition: proposition?,
        domain: domain?,
        subject: subject?,
        support_contract,
    })
}

impl NormView {
    /// The same pure derivation serves native/hosted full-ledger commands. An
    /// IFC-filtered view must not call this and claim full-ledger completeness.
    pub fn requirement_inventory(&self) -> StoreResult<RequirementInventory> {
        let mut result = RequirementInventory {
            checkpoint: self.checkpoint(),
            frontier: self.frontier.clone(),
            classification_complete: false,
            requirements: BTreeMap::new(),
            inactive: BTreeSet::new(),
            non_requirements: BTreeSet::new(),
            unclassified: BTreeSet::new(),
            gaps: Vec::new(),
        };
        for entry in &self.charter.vocabularies {
            let vocabulary = Vocabulary::new(entry.definition.clone())
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            let reference = vocabulary.reference();
            // Even an empty vocabulary needs an explicit interpretation before
            // an empty record inventory can count as completely classified.
            let gap = match &entry.inventory_role {
                None => Some(InventoryGapKind::UnspecifiedRole),
                Some(InventoryRole::Requirement { .. }) if entry.effectiveness.is_none() => {
                    Some(InventoryGapKind::UnspecifiedEffectiveness)
                }
                _ => None,
            };
            if let Some(reason) = gap {
                result.gaps.push(InventoryGap {
                    vocabulary: reference.clone(),
                    record: None,
                    reason,
                });
            }
            for current in self
                .records
                .values()
                .filter(|record| &record.vocabulary == reference)
            {
                match &entry.inventory_role {
                    None => {
                        result.unclassified.insert(current.id.clone());
                    }
                    Some(InventoryRole::NonRequirement {}) => {
                        result.non_requirements.insert(current.id.clone());
                    }
                    Some(InventoryRole::Requirement { fields }) => {
                        match self.effective_revision(current) {
                            EffectiveRevision::Unspecified => {
                                result.unclassified.insert(current.id.clone());
                            }
                            EffectiveRevision::Inactive => {
                                result.inactive.insert(current.id.clone());
                            }
                            EffectiveRevision::Active { record, lifecycle } => {
                                let declaration = declaration(&record, fields, &mut result.gaps);
                                let requirement = declaration
                                    .as_ref()
                                    .map(|meaning| -> StoreResult<_> {
                                        let mut hasher = Sha256::new();
                                        hasher.update(b"whipplescript.norm.requirement/v1\0");
                                        hasher.update(serde_json::to_vec(&(
                                            &self.ledger,
                                            &record.vocabulary,
                                            &record.content_head,
                                            meaning,
                                        ))?);
                                        Ok(EvidenceVersion {
                                            name: record.id.clone(),
                                            version: record.content_head.clone(),
                                            digest: hasher
                                                .finalize()
                                                .iter()
                                                .map(|byte| format!("{byte:02x}"))
                                                .collect(),
                                        })
                                    })
                                    .transpose()?;
                                result.requirements.insert(
                                    current.id.clone(),
                                    InventoryRequirement {
                                        source: *record,
                                        lifecycle,
                                        declaration,
                                        requirement,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
        result.classification_complete = result.gaps.is_empty();
        Ok(result)
    }
}
