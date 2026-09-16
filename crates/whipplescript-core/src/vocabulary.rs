//! Immutable vocabulary declarations (DR-0098).
//!
//! This is shared schema interpretation, not an authority oracle or a ledger.
//! A caller gets the explicit predicate for a transition and must satisfy it
//! at the admitting door. Parsing/validating a declaration grants no permission
//! to install it. Historical lookup is exact; there is no "latest" fallback.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VocabularyRef {
    pub name: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VocabularyDefinition {
    pub name: String,
    pub version: String,
    pub fields: Vec<FieldDefinition>,
    /// The declaration is the sole owner of this version's status literals.
    pub status: StatusDomain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDefinition {
    pub name: String,
    pub required: bool,
    pub value_type: ValueType,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueType {
    Text {},
    Boolean {},
    Integer {},
    /// A closed finite domain owned by this field's declaration.
    Enum {
        values: Vec<String>,
    },
    List {
        item: Box<ValueType>,
    },
    Object {
        fields: Vec<FieldDefinition>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusDomain {
    pub values: Vec<String>,
    pub initial: String,
    pub transitions: Vec<TransitionRule>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionRule {
    pub from: String,
    pub to: String,
    pub admission: AdmissionPredicate,
}

/// Data returned to a governed door, never a boolean derived from an actor name.
/// Further predicate primitives require their own implementation and model.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "requires", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdmissionPredicate {
    Public {},
    Authority { scope: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VocabularyError {
    InvalidDefinition { path: String, reason: String },
    InvalidRecord { path: String, reason: String },
    UnknownVocabulary(VocabularyRef),
    ConflictingVersion { name: String, version: String },
    InvalidStatus(String),
    MissingTransition { from: String, to: String },
    Serialization(String),
}

impl std::fmt::Display for VocabularyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDefinition { path, reason } => write!(f, "vocabulary {path}: {reason}"),
            Self::InvalidRecord { path, reason } => write!(f, "record {path}: {reason}"),
            Self::UnknownVocabulary(reference) => write!(
                f,
                "unknown vocabulary {}@{} ({})",
                reference.name, reference.version, reference.digest
            ),
            Self::ConflictingVersion { name, version } => write!(
                f,
                "vocabulary {name}@{version} already has another definition"
            ),
            Self::InvalidStatus(status) => {
                write!(f, "status {status:?} is outside the pinned vocabulary")
            }
            Self::MissingTransition { from, to } => {
                write!(f, "no admission rule for {from:?} -> {to:?}")
            }
            Self::Serialization(reason) => write!(f, "vocabulary serialization: {reason}"),
        }
    }
}
impl std::error::Error for VocabularyError {}

/// Only validated declarations can be interpreted. No Deserialize implementation
/// can bypass construction; references are computed from the complete definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vocabulary {
    definition: VocabularyDefinition,
    reference: VocabularyRef,
}

impl Vocabulary {
    pub fn new(definition: VocabularyDefinition) -> Result<Self, VocabularyError> {
        nonempty(&definition.name, "name")?;
        nonempty(&definition.version, "version")?;
        validate_fields(&definition.fields, "fields")?;
        validate_domain(&definition.status.values, "status.values")?;
        let statuses = &definition.status.values;
        if !statuses.contains(&definition.status.initial) {
            return Err(invalid(
                "status.initial",
                "must belong to the declared status domain",
            ));
        }
        let mut edges: BTreeSet<(&String, &String)> = BTreeSet::new();
        for (index, transition) in definition.status.transitions.iter().enumerate() {
            let path = format!("status.transitions[{index}]");
            if !statuses.contains(&transition.from) || !statuses.contains(&transition.to) {
                return Err(invalid(
                    &path,
                    "both endpoints must belong to the declared status domain",
                ));
            }
            if !edges.insert((&transition.from, &transition.to)) {
                return Err(invalid(
                    &path,
                    "duplicate transition; admission must be unambiguous",
                ));
            }
            if let AdmissionPredicate::Authority { scope } = &transition.admission {
                nonempty(scope, &format!("{path}.admission.scope"))?;
            }
        }
        // Definitions contain only structs, vectors and scalar strings/bools.
        // Their serde field order is fixed, independent of a JSON map backend.
        // Order is part of the declaration's identity, not normalized away.
        let bytes = serde_json::to_vec(&definition)
            .map_err(|error| VocabularyError::Serialization(error.to_string()))?;
        let mut hash = Sha256::new();
        hash.update(b"whipplescript.vocabulary.v1\0");
        hash.update(bytes);
        let reference = VocabularyRef {
            name: definition.name.clone(),
            version: definition.version.clone(),
            digest: hash
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        };
        Ok(Self {
            definition,
            reference,
        })
    }

    pub fn reference(&self) -> &VocabularyRef {
        &self.reference
    }
    pub fn definition(&self) -> &VocabularyDefinition {
        &self.definition
    }

    /// Validate the complete record body, not an unchecked patch. Optional
    /// means absent is allowed; present null still has to satisfy its type.
    pub fn validate_record(&self, fields: &Value, status: &str) -> Result<(), VocabularyError> {
        self.validate_status(status)?;
        validate_object(&self.definition.fields, fields, "fields")
    }

    /// Parse an untrusted JSON body without silently resolving duplicate field
    /// names. Use this at raw ingress before interpreting or signing a record.
    pub fn parse_record_json(&self, json: &str, status: &str) -> Result<Value, VocabularyError> {
        let value = serde_json::from_str::<UniqueValue>(json)
            .map_err(|error| record_error("fields", &error.to_string()))?
            .0;
        self.validate_record(&value, status)?;
        Ok(value)
    }

    pub fn validate_status(&self, status: &str) -> Result<(), VocabularyError> {
        if !self
            .definition
            .status
            .values
            .iter()
            .any(|value| value == status)
        {
            return Err(VocabularyError::InvalidStatus(status.to_owned()));
        }
        Ok(())
    }

    /// Missing rules deny, including an apparent no-op. This method does not
    /// evaluate authority, change record state or select a newer vocabulary.
    pub fn transition(&self, from: &str, to: &str) -> Result<&AdmissionPredicate, VocabularyError> {
        self.validate_status(from)?;
        self.validate_status(to)?;
        let Some(rule) = self
            .definition
            .status
            .transitions
            .iter()
            .find(|rule| rule.from == from && rule.to == to)
        else {
            let from = from.to_owned();
            let to = to.to_owned();
            // A missing rule must not default to public admission.
            // MUTATION-SUCCESS-EXPR: Ok(&AdmissionPredicate::Public {})
            return Err(VocabularyError::MissingTransition { from, to });
        };
        Ok(&rule.admission)
    }
}

/// The admitting ledger supplies the declarations authorized at its selected
/// charter/frontier. This registry prevents redefining a version in that set;
/// it is not a global package registry or a grant to install a declaration.
#[derive(Clone, Debug, Default)]
pub struct VocabularyRegistry {
    entries: BTreeMap<(String, String), Vocabulary>,
}
impl VocabularyRegistry {
    pub fn register(&mut self, vocabulary: Vocabulary) -> Result<VocabularyRef, VocabularyError> {
        let reference = vocabulary.reference().clone();
        let key = (reference.name.clone(), reference.version.clone());
        if let Some(existing) = self.entries.get(&key) {
            if existing != &vocabulary {
                return Err(VocabularyError::ConflictingVersion {
                    name: reference.name,
                    version: reference.version,
                });
            }
        } else {
            self.entries.insert(key, vocabulary);
        }
        Ok(reference)
    }

    pub fn get(&self, reference: &VocabularyRef) -> Result<&Vocabulary, VocabularyError> {
        let Some(vocabulary) = self
            .entries
            .get(&(reference.name.clone(), reference.version.clone()))
            .filter(|vocabulary| vocabulary.reference() == reference)
        else {
            // The historical-lookup fixture supplies an alternative version;
            // using it would be the forbidden fallback, not a valid recovery.
            // MUTATION-SUCCESS-EXPR: Ok(self.entries.values().next().expect("mutation fixture supplies an alternative vocabulary"))
            return Err(VocabularyError::UnknownVocabulary(reference.clone()));
        };
        Ok(vocabulary)
    }
}

fn invalid(path: &str, reason: &str) -> VocabularyError {
    VocabularyError::InvalidDefinition {
        path: path.to_owned(),
        reason: reason.to_owned(),
    }
}
fn nonempty(value: &str, path: &str) -> Result<(), VocabularyError> {
    if value.trim().is_empty() {
        Err(invalid(path, "must not be empty"))
    } else {
        Ok(())
    }
}
fn validate_domain(values: &[String], path: &str) -> Result<(), VocabularyError> {
    if values.is_empty() {
        return Err(invalid(path, "finite domain must not be empty"));
    }
    let mut seen: BTreeSet<&String> = BTreeSet::new();
    for value in values {
        nonempty(value, path)?;
        if !seen.insert(value) {
            return Err(invalid(path, "duplicate literal"));
        }
    }
    Ok(())
}
fn validate_fields(fields: &[FieldDefinition], path: &str) -> Result<(), VocabularyError> {
    let mut seen: BTreeSet<&String> = BTreeSet::new();
    for field in fields {
        nonempty(&field.name, path)?;
        if !seen.insert(&field.name) {
            return Err(invalid(path, "duplicate field name"));
        }
        validate_type(&field.value_type, &format!("{path}.{}", field.name))?;
    }
    Ok(())
}
fn validate_type(value_type: &ValueType, path: &str) -> Result<(), VocabularyError> {
    match value_type {
        ValueType::Enum { values } => validate_domain(values, path),
        ValueType::List { item } => validate_type(item, path),
        ValueType::Object { fields } => validate_fields(fields, path),
        _ => Ok(()),
    }
}
fn record_error(path: &str, reason: &str) -> VocabularyError {
    VocabularyError::InvalidRecord {
        path: path.to_owned(),
        reason: reason.to_owned(),
    }
}
fn validate_object(
    fields: &[FieldDefinition],
    value: &Value,
    path: &str,
) -> Result<(), VocabularyError> {
    let object = value
        .as_object()
        .ok_or_else(|| record_error(path, "expected object"))?;
    for name in object.keys() {
        if !fields.iter().any(|field| &field.name == name) {
            return Err(record_error(&format!("{path}.{name}"), "unknown field"));
        }
    }
    for field in fields {
        let path = format!("{path}.{}", field.name);
        match object.get(&field.name) {
            None if field.required => return Err(record_error(&path, "required field missing")),
            Some(value) => validate_value(&field.value_type, value, &path)?,
            None => (),
        }
    }
    Ok(())
}
fn validate_value(
    value_type: &ValueType,
    value: &Value,
    path: &str,
) -> Result<(), VocabularyError> {
    let valid = match value_type {
        ValueType::Text {} => value.is_string(),
        ValueType::Boolean {} => value.is_boolean(),
        ValueType::Integer {} => value.is_i64() || value.is_u64(),
        ValueType::Enum { values } => value
            .as_str()
            .is_some_and(|value| values.iter().any(|literal| literal == value)),
        ValueType::List { item } => {
            let items = value
                .as_array()
                .ok_or_else(|| record_error(path, "expected list"))?;
            for (index, value) in items.iter().enumerate() {
                validate_value(item, value, &format!("{path}[{index}]"))?;
            }
            true
        }
        ValueType::Object { fields } => {
            validate_object(fields, value, path)?;
            true
        }
    };
    if valid {
        Ok(())
    } else {
        let expected = match value_type {
            ValueType::Text {} => "Text",
            ValueType::Boolean {} => "Boolean",
            ValueType::Integer {} => "Integer",
            ValueType::Enum { .. } => "a declared enum literal",
            ValueType::List { .. } => "List",
            ValueType::Object { .. } => "Object",
        };
        Err(record_error(path, &format!("expected {expected}")))
    }
}

// serde_json::Value intentionally accepts duplicate object keys. At a signed
// record boundary, first/last-wins ambiguity must be rejected before it is lost.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON with unique object field names")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<UniqueValue, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<UniqueValue, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<UniqueValue, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<UniqueValue, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| UniqueValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<UniqueValue, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<UniqueValue, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<UniqueValue, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<UniqueValue, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<UniqueValue, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(name) = map.next_key::<String>()? {
                    if values.contains_key(&name) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate field {name:?}"
                        )));
                    }
                    let value = map.next_value::<UniqueValue>()?;
                    values.insert(name, value.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
