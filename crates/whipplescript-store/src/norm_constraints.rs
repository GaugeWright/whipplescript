//! Typed constraints on requirements (norm-plane §11.1, slice U1).
//!
//! A vocabulary that declares a `constraint` role names the fields of its
//! records that carry a requirement reference, variable declarations and a
//! formula. An effective constraint on an effective requirement gives that
//! requirement a typed part, and the ledger's compatibility view checks the
//! typed parts of requirements whose domains overlap jointly, within a bound.
//! Requirements with no typed part are listed, never assumed compatible, and
//! a constraint that does not parse is listed with why.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use whipplescript_core::norm_compatibility::{self, Component, TypedNorm};
use whipplescript_core::vocabulary::{ReferenceForm, ValueType};

use crate::norm::{EffectiveRevision, NormView, NormVocabulary};
use crate::{StoreError, StoreResult};

/// The fields of a constraint record, by role.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintDeclaration {
    /// A required identity reference to the constrained requirement.
    pub requirement: String,
    /// A required list of text variable declarations.
    pub declarations: String,
    /// A required text formula.
    pub formula: String,
}

/// The assignments a bounded check may enumerate for one component.
pub const COMPATIBILITY_BUDGET: u128 = 1 << 20;

pub(crate) fn validate_constraint_declaration(entry: &NormVocabulary) -> StoreResult<()> {
    let Some(declaration) = &entry.constraint else {
        return Ok(());
    };
    let refused = || {
        StoreError::Conflict(
            "a constraint role names a required identity reference, a required text list and a required text field"
                .into(),
        )
    };
    let field = |name: &str| {
        entry
            .definition
            .fields
            .iter()
            .find(|field| field.name == name && field.required)
    };
    let requirement = field(&declaration.requirement).ok_or_else(refused)?;
    let declarations = field(&declaration.declarations).ok_or_else(refused)?;
    let formula = field(&declaration.formula).ok_or_else(refused)?;
    let text = |value: &ValueType| matches!(value, ValueType::Text {});
    let typed = matches!(
        requirement.value_type,
        ValueType::Reference {
            form: ReferenceForm::Identity
        }
    ) && matches!(&declarations.value_type, ValueType::List { item } if text(item))
        && text(&formula.value_type);
    if !typed {
        return Err(refused());
    }
    Ok(())
}

/// The ledger's compatibility answer at one frontier.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityView {
    /// Components of typed requirements checked jointly.
    pub components: Vec<Component>,
    /// Effective requirements with no effective typed part: prose only,
    /// neither compatible nor incompatible.
    pub untyped: BTreeSet<String>,
    /// Effective constraints that do not parse, with why.
    pub malformed: BTreeMap<String, String>,
}

impl NormView {
    /// Check the typed parts of effective requirements jointly, comparing
    /// requirements only where their domains overlap (norm-plane §11.1).
    pub fn compatibility(&self) -> StoreResult<CompatibilityView> {
        let inventory = self.requirement_inventory()?;
        let domains: BTreeMap<&String, String> = inventory
            .requirements
            .iter()
            .map(|(id, requirement)| {
                let domain = requirement
                    .declaration
                    .as_ref()
                    .map(|declaration| declaration.domain.clone())
                    .unwrap_or_default();
                (id, domain)
            })
            .collect();
        let mut view = CompatibilityView::default();
        let mut typed: BTreeMap<String, TypedNorm> = BTreeMap::new();
        for record in self.records.values() {
            let Some(declaration) = self
                .interpretation(&record.vocabulary)
                .and_then(|entry| entry.constraint.as_ref())
            else {
                continue;
            };
            if !matches!(
                self.effective_revision(record),
                EffectiveRevision::Active { .. }
            ) {
                continue;
            }
            let Some(requirement) = record.fields[&declaration.requirement].as_str() else {
                continue;
            };
            if !inventory.requirements.contains_key(requirement) {
                continue;
            }
            let declarations: Vec<String> = record.fields[&declaration.declarations]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let formula = record.fields[&declaration.formula]
                .as_str()
                .unwrap_or_default();
            match norm_compatibility::parse(&declarations, formula) {
                Ok(norm) => {
                    // Several constraints on one requirement are one
                    // conjunction, over one declaration of each variable.
                    let entry = typed.entry(requirement.to_owned()).or_default();
                    let clash = norm.variables.iter().find(|(name, domain)| {
                        entry
                            .variables
                            .get(*name)
                            .is_some_and(|known| known != *domain)
                    });
                    if let Some((name, _)) = clash {
                        view.malformed.insert(
                            record.id.clone(),
                            format!("`{name}` is declared differently by another constraint on this requirement"),
                        );
                        continue;
                    }
                    entry.variables.extend(norm.variables);
                    entry.atoms.extend(norm.atoms);
                }
                Err(reason) => {
                    view.malformed.insert(record.id.clone(), reason);
                }
            }
        }
        view.untyped = inventory
            .requirements
            .keys()
            .filter(|id| !typed.contains_key(*id))
            .cloned()
            .collect();
        let overlap = |a: &str, b: &str| {
            let (a, b) = (&domains[&a.to_owned()], &domains[&b.to_owned()]);
            let region = |domain: &str| {
                let trimmed = domain.trim_end_matches('/');
                if trimmed.is_empty() {
                    "**".to_owned()
                } else if domain.ends_with('/') {
                    format!("{trimmed}/**")
                } else {
                    trimmed.to_owned()
                }
            };
            crate::norm_reservations::selectors_overlap(&region(a), &region(b))
        };
        view.components = norm_compatibility::check_with(&typed, COMPATIBILITY_BUDGET, &overlap);
        Ok(view)
    }
}
