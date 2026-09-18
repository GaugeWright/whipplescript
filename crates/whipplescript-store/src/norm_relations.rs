//! Typed relations (DR-0122, norm-plane §13.2 and §13.4).
//!
//! A relation is a record of a vocabulary whose charter entry declares which
//! two reference fields carry its endpoints, which record kinds those may
//! name, the family its live edges belong to, and the structural properties
//! the family keeps: acyclicity and cardinality. The kernel enforces exactly
//! those properties over the family's live edges at the captured frontier and
//! gives an edge no meaning beyond its declaration.
//!
//! A local mutation is not a local validation basis: one added edge can close
//! a cycle through an arbitrarily long existing path, and two candidates that
//! each add one edge of a two-cycle are each acyclic against the same family.
//! So an act that makes an edge live binds the family basis it was validated
//! against, the family's head event, and the references it names; both are
//! causal parents of the act, so a replay applies it after them and
//! reproduces the admission, and the door refuses an act whose family has
//! moved since. The re-evaluation is the caller's: capture the family again,
//! validate again. Modeled in `models/maude/relation-validation-scope.maude`.

use std::collections::{BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use whipplescript_core::vocabulary::ValueType;

use crate::norm::{NormCharter, NormVocabulary};
use crate::{StoreError, StoreResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationDeclaration {
    /// The required reference fields carrying the endpoints.
    pub source: String,
    pub target: String,
    /// Vocabulary names an endpoint may belong to; empty means any record.
    #[serde(default)]
    pub source_kinds: Vec<String>,
    #[serde(default)]
    pub target_kinds: Vec<String>,
    /// The family whose live edges this relation joins for structural checks.
    /// Several vocabularies may share one family.
    pub family: String,
    /// No live path in the family may run from the target back to the source.
    pub acyclic: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardinality: Option<RelationCardinality>,
    /// The statuses in which the record's edge is live in its family.
    pub live_statuses: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationCardinality {
    AtMostOneLivePerTarget,
}

/// One live edge of a family, with both endpoints resolved to record identities.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationEdge {
    pub record: String,
    pub revision: String,
    pub relation: String,
    pub source: String,
    pub target: String,
}

/// A family's live edges at a frontier and the basis an act binds: the event
/// id of the family's last admitted act, which every act on the family moves.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationFamilyView {
    pub basis: String,
    pub edges: Vec<RelationEdge>,
}

impl RelationFamilyView {
    pub fn new(basis: String, mut edges: Vec<RelationEdge>) -> Self {
        edges.sort();
        Self { basis, edges }
    }

    /// Whether a live path runs from `from` to `to`, ignoring the edge of the
    /// record being acted on, whose new endpoints are the candidate's.
    pub fn reaches(&self, from: &str, to: &str, ignoring: Option<&str>) -> bool {
        let mut seen: BTreeSet<&str> = BTreeSet::from([from]);
        let mut queue = VecDeque::from([from]);
        while let Some(node) = queue.pop_front() {
            for edge in &self.edges {
                if Some(edge.record.as_str()) == ignoring || edge.source != node {
                    continue;
                }
                if edge.target == to {
                    return true;
                }
                if seen.insert(edge.target.as_str()) {
                    queue.push_back(edge.target.as_str());
                }
            }
        }
        false
    }
}

fn conflict(message: &str) -> StoreError {
    StoreError::Conflict(message.into())
}

/// A relation declaration is validated with its charter: the endpoint fields
/// are required references of its own vocabulary, the family is named, the
/// live statuses come from its status domain, and the endpoint kinds name
/// vocabularies the charter declares.
pub(crate) fn validate_relation_declaration(
    entry: &NormVocabulary,
    charter: &NormCharter,
) -> StoreResult<()> {
    let Some(relation) = &entry.relation else {
        return Ok(());
    };
    for (role, name) in [("source", &relation.source), ("target", &relation.target)] {
        let declared = entry.definition.fields.iter().any(|field| {
            &field.name == name
                && field.required
                && matches!(field.value_type, ValueType::Reference { .. })
        });
        if !declared {
            return Err(conflict(&format!(
                "relation {role} must name a required reference field of its vocabulary"
            )));
        }
    }
    if relation.source == relation.target {
        return Err(conflict(
            "relation source and target must be distinct fields",
        ));
    }
    if relation.family.trim().is_empty() {
        return Err(conflict("relation family must be named"));
    }
    let statuses = &entry.definition.status.values;
    if relation.live_statuses.is_empty()
        || relation
            .live_statuses
            .iter()
            .any(|status| !statuses.contains(status))
    {
        return Err(conflict(
            "relation live statuses must be nonempty and from the vocabulary's status domain",
        ));
    }
    for kind in relation.source_kinds.iter().chain(&relation.target_kinds) {
        if !charter
            .vocabularies
            .iter()
            .any(|vocabulary| &vocabulary.definition.name == kind)
        {
            return Err(conflict(
                "relation endpoint kinds must name vocabularies the charter declares",
            ));
        }
    }
    Ok(())
}
